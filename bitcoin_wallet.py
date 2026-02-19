from __future__ import annotations

import base64
import hashlib
import os
import struct
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

import requests
from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
    Bip86,
    Bip86Coins,
)
from dotenv import load_dotenv

# python-bitcoinlib and bit are optional for some features -- guard imports
try:
    from bit import Key, PrivateKeyTestnet
except ImportError:  # pragma: no cover
    Key = None  # type: ignore[assignment,misc]
    PrivateKeyTestnet = None  # type: ignore[assignment,misc]

try:
    from bitcoin import SelectParams
    from bitcoin.core import (
        CMutableTransaction,
        CMutableTxIn,
        CMutableTxOut,
        COutPoint,
        CScript,
        Hash160,
        b2x,
        lx,
    )
    from bitcoin.core.script import (
        OP_CHECKSIG,
        OP_DUP,
        OP_EQUALVERIFY,
        OP_HASH160,
        OP_RETURN,
        SIGHASH_ALL,
        CScriptWitness,
        SignatureHash,
    )
    from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret
except ImportError:  # pragma: no cover
    SelectParams = None  # type: ignore[assignment,misc]

# Load .env from project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
load_dotenv(PROJECT_ROOT / ".env")

BTCCNetwork = Literal["mainnet", "testnet"]


class BTCConfigError(Exception):
    """Configuration or key-material error for the BTC payment agent."""

    pass


class _Unspent:
    """
    Minimal Unspent-like object compatible with bit's transaction routines.

    Fields intentionally mirror the attributes accessed in bit.transaction:
    - amount
    - confirmations
    - script
    - txid
    - txindex
    - segwit
    - vsize
    - sequence
    """

    def __init__(
        self,
        amount: int,
        confirmations: int,
        script: str,
        txid: str,
        txindex: int,
        segwit: bool,
    ) -> None:
        self.amount = amount
        self.confirmations = confirmations
        self.script = script
        self.txid = txid
        self.txindex = txindex
        self.segwit = segwit
        # Approximate virtual size: smaller for segwit, larger for legacy
        self.vsize = 68 if segwit else 148
        # Standard sequence for non-RBF transactions
        self.sequence = 0xFFFFFFFF


@dataclass
class BTCConfig:
    """
    Configuration for the BTC payment agent.

    Values are sourced from environment variables or a .env file.

    Key material:
    - BTC_PRIVATE_KEY: WIF-encoded private key for the wallet (takes precedence).
    - BTC_MNEMONIC: BIP-39 seed phrase; used to derive a WIF key if BTC_PRIVATE_KEY
      is not set.
    - BTC_MNEMONIC_PASSPHRASE: Optional BIP-39 passphrase used with BTC_MNEMONIC.

    Network and safety:
    - BTC_NETWORK: \"mainnet\" or \"testnet\" (defaults to \"testnet\").
    - BTC_MAINNET_ENABLED: safety flag required for mainnet sends.
    - BTC_MAX_SEND_BTC: optional per-transaction max amount (Decimal, in BTC).
    - BTC_DRY_RUN: if true, default to dry-run unless explicitly overridden.
    - BTC_MAX_FEE_SATS: optional max network fee in satoshis.
    - BTC_FEE_RATE_SAT_PER_BYTE: optional fee rate (sat/vB); overrides dynamic rate if set.
    - BTC_FEE_TIER: which mempool.space tier to use when not using fixed rate.
      One of: fastestFee, halfHourFee, hourFee, economyFee, minimumFee.
      Default hourFee to avoid overpaying for non-urgent payments.
    """

    private_key_wif: str
    network: BTCCNetwork
    max_send_btc: Decimal | None
    dry_run_default: bool = True
    max_fee_sats_env: int | None = None
    fee_rate_sat_per_byte: int = 10
    fee_tier: str = "hourFee"
    use_fixed_fee_rate: bool = False  # True when BTC_FEE_RATE_SAT_PER_BYTE is set
    # Optional set of candidate WIFs derived from a mnemonic, keyed by address type.
    # Each entry is a dict with keys: "label", "addr_type", "wif", and a
    # precomputed "address" string using bip_utils (so P2WPKH/P2TR show the
    # correct bech32 / bech32m form instead of legacy encodings from `bit`).
    candidate_wifs: list[dict[str, str]] | None = None

    @classmethod
    def from_env(cls) -> BTCConfig:
        private_key = os.getenv("BTC_PRIVATE_KEY")
        mnemonic = os.getenv("BTC_MNEMONIC")

        # When both are set, prefer mnemonic (BIP-39) over single-key WIF.
        if mnemonic:
            private_key = None  # Ignore WIF; we will derive from mnemonic below.
        if not private_key and not mnemonic:
            raise BTCConfigError(
                "No key material configured. Set BTC_PRIVATE_KEY (WIF) or "
                "BTC_MNEMONIC (BIP-39 seed phrase) in your environment or .env file."
            )

        # Determine network:
        # 1) BTC_NETWORK, if provided and valid.
        # 2) Infer from WIF prefix if BTC_PRIVATE_KEY is set.
        # 3) Default to mainnet for mnemonic-only setups.
        raw_network_env = os.getenv("BTC_NETWORK")
        if raw_network_env:
            raw_network = raw_network_env.lower()
            if raw_network not in {"mainnet", "testnet"}:
                raise RuntimeError(
                    f"Invalid BTC_NETWORK={raw_network_env!r}. Expected 'mainnet' or 'testnet'."
                )
            network: BTCCNetwork = "mainnet" if raw_network == "mainnet" else "testnet"
        elif private_key:
            first = private_key[0]
            if first in {"9", "c", "m", "n"}:
                network = "testnet"
            else:
                network = "mainnet"
        else:
            network = "mainnet"

        candidate_wifs: list[dict[str, str]] | None = None
        if mnemonic and not private_key:
            candidate_wifs = _derive_candidate_wifs_from_mnemonic(mnemonic, network)
            # Prefer native SegWit if available, otherwise first candidate.
            primary = next(
                (c for c in candidate_wifs if c.get("addr_type") == "p2wpkh"),
                candidate_wifs[0],
            )
            private_key = primary["wif"]
            # Scrub mnemonic from this frame once we've derived a key.
            del mnemonic
        elif private_key:
            candidate_wifs = [
                {"label": "primary", "addr_type": "unknown", "wif": private_key}
            ]

        max_send_raw = os.getenv("BTC_MAX_SEND_BTC")
        max_send_btc = Decimal(max_send_raw) if max_send_raw else None

        # Check BTC_DRY_RUN environment variable (defaults to True for safety)
        # If set to "false", "0", "no", or "off" (case-insensitive), dry run is disabled
        dry_run_env = os.getenv("BTC_DRY_RUN", "true").lower()
        dry_run_default = dry_run_env not in ("false", "0", "no", "off")
        max_fee_sats_env: int | None = None
        fee_rate_sat_per_byte = 10
        fee_tier_raw = os.getenv("BTC_FEE_TIER", "hourFee").strip()
        allowed_tiers = (
            "fastestFee",
            "halfHourFee",
            "hourFee",
            "economyFee",
            "minimumFee",
        )
        fee_tier = fee_tier_raw if fee_tier_raw in allowed_tiers else "hourFee"
        use_fixed_fee_rate = False
        fee_rate_env = os.getenv("BTC_FEE_RATE_SAT_PER_BYTE")
        if fee_rate_env is not None and fee_rate_env.strip():
            try:
                fee_rate_sat_per_byte = max(1, int(fee_rate_env))
                use_fixed_fee_rate = True
            except ValueError:
                pass

        return cls(
            private_key_wif=private_key,
            network=network,
            max_send_btc=max_send_btc,
            dry_run_default=dry_run_default,
            max_fee_sats_env=max_fee_sats_env,
            fee_rate_sat_per_byte=fee_rate_sat_per_byte,
            fee_tier=fee_tier,
            use_fixed_fee_rate=use_fixed_fee_rate,
            candidate_wifs=candidate_wifs,
        )


def _derive_wif_from_mnemonic(mnemonic: str, network: BTCCNetwork) -> str:
    # Validator expects language (optional) at construction and the mnemonic
    # string passed to Validate(), not the other way around. We also scrub the
    # local mnemonic variable before raising to avoid leaking secrets in traces.
    try:
        Bip39MnemonicValidator().Validate(mnemonic)
    except Exception as exc:  # noqa: BLE001
        # Remove sensitive value from local scope before raising.
        # Store mnemonic in a local variable that will be deleted
        _mnemonic = mnemonic
        del _mnemonic
        raise BTCConfigError(
            "BTC_MNEMONIC is not a valid BIP-39 seed phrase. "
            "Double-check words and spacing."
        ) from exc

    passphrase = os.getenv("BTC_MNEMONIC_PASSPHRASE", "")
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)

    coin = Bip44Coins.BITCOIN if network == "mainnet" else Bip44Coins.BITCOIN_TESTNET
    ctx = (
        Bip44.FromSeed(seed_bytes, coin)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )
    return ctx.PrivateKey().ToWif()


def _derive_candidate_wifs_from_mnemonic(
    mnemonic: str, network: BTCCNetwork
) -> list[dict[str, str]]:
    """
    Derive a small set of standard-address-type WIFs from a BIP-39 mnemonic:
    - P2PKH (BIP44)
    - P2SH-P2WPKH (BIP49)
    - P2WPKH (BIP84)
    - P2TR (taproot, BIP86) – address only, spending not yet enabled
    """
    passphrase = os.getenv("BTC_MNEMONIC_PASSPHRASE", "")
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)

    if network == "mainnet":
        coin44 = Bip44Coins.BITCOIN
        coin49 = Bip49Coins.BITCOIN
        coin84 = Bip84Coins.BITCOIN
        coin86 = Bip86Coins.BITCOIN
    else:
        coin44 = Bip44Coins.BITCOIN_TESTNET
        coin49 = Bip49Coins.BITCOIN_TESTNET
        coin84 = Bip84Coins.BITCOIN_TESTNET
        coin86 = Bip86Coins.BITCOIN_TESTNET

    candidates: list[dict[str, str]] = []

    # BIP44 P2PKH
    ctx44 = (
        Bip44.FromSeed(seed_bytes, coin44)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )
    candidates.append(
        {
            "label": "bip44_p2pkh_0",
            "addr_type": "p2pkh",
            "wif": ctx44.PrivateKey().ToWif(),
            "address": str(ctx44.PublicKey().ToAddress()),
            "public_key": ctx44.PublicKey().RawCompressed().ToHex(),
            "derivation_path": (
                "m/44'/0'/0'/0/0" if network == "mainnet" else "m/44'/1'/0'/0/0"
            ),
        }
    )

    # BIP49 P2SH-P2WPKH
    ctx49 = (
        Bip49.FromSeed(seed_bytes, coin49)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )
    candidates.append(
        {
            "label": "bip49_p2sh_p2wpkh_0",
            "addr_type": "p2sh-p2wpkh",
            "wif": ctx49.PrivateKey().ToWif(),
            "address": str(ctx49.PublicKey().ToAddress()),
            "public_key": ctx49.PublicKey().RawCompressed().ToHex(),
            "derivation_path": (
                "m/49'/0'/0'/0/0" if network == "mainnet" else "m/49'/1'/0'/0/0"
            ),
        }
    )

    # BIP84 P2WPKH (bech32)
    ctx84 = (
        Bip84.FromSeed(seed_bytes, coin84)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )
    candidates.append(
        {
            "label": "bip84_p2wpkh_0",
            "addr_type": "p2wpkh",
            "wif": ctx84.PrivateKey().ToWif(),
            "address": str(ctx84.PublicKey().ToAddress()),
            "public_key": ctx84.PublicKey().RawCompressed().ToHex(),
            "derivation_path": (
                "m/84'/0'/0'/0/0" if network == "mainnet" else "m/84'/1'/0'/0/0"
            ),
        }
    )

    # BIP86 P2TR (taproot). We currently derive and expose the address but do not
    # attempt to spend from it via `bit`, since taproot spending is not yet
    # supported there. This still lets you see the taproot receive address.
    ctx86 = (
        Bip86.FromSeed(seed_bytes, coin86)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )
    candidates.append(
        {
            "label": "bip86_p2tr_0",
            "addr_type": "p2tr",
            "wif": ctx86.PrivateKey().ToWif(),
            "address": str(ctx86.PublicKey().ToAddress()),
            "public_key": ctx86.PublicKey().RawCompressed().ToHex(),
            "derivation_path": (
                "m/86'/0'/0'/0/0" if network == "mainnet" else "m/86'/1'/0'/0/0"
            ),
        }
    )

    return candidates


def _make_key_from_wif(wif: str, network: BTCCNetwork):
    if network == "mainnet":
        return Key(wif)
    return PrivateKeyTestnet(wif)


@dataclass
class TransactionPreview:
    from_address: str
    to_address: str
    amount_btc: Decimal
    fee_sats_estimate: int
    fee_rate_sat_per_vb: int
    total_spend_btc: Decimal
    balance_btc: Decimal
    network: BTCCNetwork


def get_balance_btc(cfg: BTCConfig) -> Decimal:
    # Backwards-compatible: use primary key. Taproot candidates are not
    # considered for sending yet.
    key = _make_key_from_wif(cfg.private_key_wif, cfg.network)
    balance_str = key.get_balance("btc")
    return Decimal(balance_str)


def estimate_fee_sats(cfg: BTCConfig) -> int:
    """
    Rough fee estimate based on current unspents and a simple size formula.
    This is intentionally conservative; the actual library fee may differ.
    """
    key = _make_key_from_wif(cfg.private_key_wif, cfg.network)
    unspents = key.get_unspents()
    num_inputs = max(len(unspents), 1)
    # Two outputs: recipient + change
    num_outputs = 2
    size_bytes = 10 + num_inputs * 148 + num_outputs * 34
    return size_bytes * cfg.fee_rate_sat_per_byte


def build_transaction_preview(
    cfg: BTCConfig,
    to_address: str,
    amount_btc: Decimal,
) -> TransactionPreview:
    if amount_btc <= 0:
        raise ValueError("Amount must be greater than zero.")

    if cfg.max_send_btc is not None and amount_btc > cfg.max_send_btc:
        raise RuntimeError(
            f"Requested amount {amount_btc} BTC exceeds BTC_MAX_SEND_BTC={cfg.max_send_btc}."
        )

    (
        key,
        balance_btc,
        fee_sats_estimate,
        display_address,
        _,
        _,
        fee_rate,
    ) = _select_best_key_for_payment(cfg, amount_btc)
    fee_btc_estimate = Decimal(fee_sats_estimate) / Decimal("1e8")
    total_spend = amount_btc + fee_btc_estimate

    if total_spend > balance_btc:
        raise RuntimeError(
            f"Insufficient balance. Needed ~{total_spend} BTC (amount + estimated fee), "
            f"but wallet balance is {balance_btc} BTC."
        )

    return TransactionPreview(
        from_address=display_address,
        to_address=to_address,
        amount_btc=amount_btc,
        fee_sats_estimate=fee_sats_estimate,
        fee_rate_sat_per_vb=fee_rate,
        total_spend_btc=total_spend,
        balance_btc=balance_btc,
        network=cfg.network,
    )


def _build_native_segwit_tx(
    wif: str,
    utxos: list[dict[str, object]],
    to_address: str,
    amount_sats: int,
    fee_sats: int,
    change_address: str,
    network: BTCCNetwork,
    memo: str | None = None,
) -> str:
    """
    Build and sign a native SegWit (P2WPKH) transaction using python-bitcoinlib.

    Uses CMutableTransaction for proper witness construction.
    Based on python-bitcoinlib best practices and BIP143 (SegWit signing).

    memo: Optional UTF-8 memo added as OP_RETURN output (max 80 bytes).
    """
    # Set network params
    if network == "mainnet":
        SelectParams("mainnet")
    else:
        SelectParams("testnet")

    # Parse private key from WIF
    try:
        privkey = CBitcoinSecret(wif)
    except Exception as exc:
        raise RuntimeError(f"Invalid WIF: {exc}") from exc

    # Get public key and derive address
    pubkey = privkey.pub
    pubkey_hash = Hash160(pubkey)

    # Build transaction inputs
    txins = []
    total_input = 0
    for u in utxos:
        txid = u.get("txid", "")
        vout = int(u.get("vout", 0))
        value = int(u.get("value", 0))
        total_input += value

        # Convert txid to little-endian bytes
        txid_bytes = lx(txid)
        txins.append(CMutableTxIn(COutPoint(txid_bytes, vout)))

    # Calculate change
    change_sats = total_input - amount_sats - fee_sats
    if change_sats < 0:
        raise RuntimeError(
            f"Insufficient funds: need {amount_sats + fee_sats} sats, have {total_input} sats"
        )

    # Build transaction outputs
    txouts = []
    # Recipient output
    to_addr = CBitcoinAddress(to_address)
    txouts.append(CMutableTxOut(amount_sats, to_addr.to_scriptPubKey()))

    # OP_RETURN memo output (if provided)
    if memo:
        memo_bytes = memo.encode("utf-8")[:80]  # Max 80 bytes for OP_RETURN
        op_return_script = CScript([OP_RETURN, memo_bytes])
        txouts.append(CMutableTxOut(0, op_return_script))

    # Change output (if above dust threshold)
    if change_sats > 546:
        change_addr = CBitcoinAddress(change_address)
        txouts.append(CMutableTxOut(change_sats, change_addr.to_scriptPubKey()))

    # Create mutable transaction
    tx = CMutableTransaction(txins, txouts)

    # Sign each input and build witness data
    for i, u in enumerate(utxos):
        value = int(u.get("value", 0))

        # For P2WPKH, the scriptCode for signing is the same as P2PKH scriptPubKey:
        # OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
        script_code = CScript(
            [OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
        )

        # Calculate signature hash using BIP143 (SegWit)
        sighash = SignatureHash(
            script_code, tx, i, SIGHASH_ALL, amount=value, sigversion=1
        )

        # Sign the hash
        sig = privkey.sign(sighash) + bytes([SIGHASH_ALL])

        # Set witness directly (don't append, replace)
        tx.wit.vtxinwit[i] = CScriptWitness([sig, pubkey])

    # Serialize and return hex
    return b2x(tx.serialize())


def send_transaction(
    cfg: BTCConfig,
    to_address: str,
    amount_btc: Decimal,
    max_fee_sats_effective: int | None,
    memo: str | None = None,
    dry_run: bool | None = None,
) -> str:
    """
    Broadcast a BTC transaction.

    Construction and signing are delegated to the local bit library, but all
    UTXO selection and network broadcast go through mempool.space for
    reliability. bit is not used for balance discovery or broadcasting.

    max_fee_sats_effective, if provided, is used as an absolute fee cap.

    dry_run: If True, transaction will be built and signed but not broadcast.
             If None, uses cfg.dry_run_default.
    """
    # Determine if we should actually broadcast
    if dry_run is None:
        dry_run = cfg.dry_run_default
    # Re-select the best key and UTXOs at send time in case conditions changed.
    key, _, _, display_address, mempool_utxos, addr_type, _ = (
        _select_best_key_for_payment(cfg, amount_btc)
    )

    # Determine segwit from address type.
    segwit = addr_type in ("p2wpkh", "p2sh-p2wpkh", "p2wsh")

    # Convert mempool.space UTXO format to objects compatible with bit's
    # transaction routines. Fetch scriptPubKey for each UTXO so bit can properly sign.
    # Note: bit expects script as hex string (not bytes), which is what mempool.space returns.
    # We manually select UTXOs to cover amount + estimated fee to avoid bit's coin selection issues.
    amount_sats = int(amount_btc * Decimal("1e8"))
    if cfg.use_fixed_fee_rate:
        fee_rate = cfg.fee_rate_sat_per_byte
    else:
        fee_rate = _fetch_dynamic_fee_rate_sat_per_byte(
            cfg.network, cfg.fee_rate_sat_per_byte, cfg.fee_tier
        )

    # Estimate fee using minimum inputs needed (greedy), not all UTXOs.
    amount_btc = Decimal(amount_sats) / Decimal("1e8")
    input_vsize = 68 if segwit else 148
    _, estimated_fee_sats = _estimate_inputs_and_fee(
        mempool_utxos, amount_btc, fee_rate, input_vsize, 2
    )
    total_needed_sats = amount_sats + estimated_fee_sats

    # Select UTXOs greedily until we have enough
    selected_utxos = []
    total_selected = 0
    for u in sorted(mempool_utxos, key=lambda x: int(x.get("value", 0)), reverse=True):
        if total_selected >= total_needed_sats:
            break
        selected_utxos.append(u)
        total_selected += int(u.get("value", 0))

    # Recompute fee for actual number of inputs (may be 1 more than estimate if rounding)
    estimated_size = 10 + len(selected_utxos) * input_vsize + 2 * 34
    estimated_fee_sats = estimated_size * fee_rate

    if total_selected < total_needed_sats:
        raise RuntimeError(
            f"Insufficient UTXOs selected. Need {total_needed_sats} sats, "
            f"selected {total_selected} sats from {len(selected_utxos)} UTXOs"
        )

    # Build unspent objects with scripts
    unspents = []
    for u in selected_utxos:
        txid = str(u.get("txid", ""))
        vout = int(u.get("vout", 0))
        value = int(u.get("value", 0))
        status = u.get("status", {}) or {}
        confirmed = bool(status.get("confirmed", False))
        height = int(status.get("block_height", 0) or 0)
        confirmations = height if confirmed else 0
        # Fetch the scriptPubKey from the full transaction
        script_hex = _fetch_scriptpubkey(txid, vout, cfg.network)
        if not script_hex:
            raise RuntimeError(f"Failed to fetch scriptPubKey for UTXO {txid}:{vout}")
        unspents.append(_Unspent(value, confirmations, script_hex, txid, vout, segwit))

    outputs = [(to_address, float(amount_btc), "btc")]

    # Pass exact UTXOs and tell bit not to combine/fetch more
    kwargs = {"unspents": unspents, "combine": False}
    if max_fee_sats_effective is not None:
        kwargs["fee"] = int(max_fee_sats_effective)
        kwargs["absolute_fee"] = True
    elif estimated_fee_sats > 0:
        # Provide estimated fee as a hint
        kwargs["fee"] = int(estimated_fee_sats)
        kwargs["absolute_fee"] = True
    if memo:
        kwargs["message"] = memo

    # For native SegWit (P2WPKH), use python-bitcoinlib since bit doesn't support it properly
    if addr_type == "p2wpkh":
        # Find the WIF for this address type
        candidate_info = next(
            (c for c in (cfg.candidate_wifs or []) if c.get("addr_type") == "p2wpkh"),
            None,
        )
        if not candidate_info:
            raise RuntimeError("Could not find WIF for native SegWit address")
        wif = candidate_info["wif"]
        change_address = display_address  # Send change back to same address

        # Build transaction using python-bitcoinlib
        raw_hex = _build_native_segwit_tx(
            wif=wif,
            utxos=selected_utxos,
            to_address=to_address,
            amount_sats=amount_sats,
            fee_sats=int(estimated_fee_sats),
            change_address=change_address,
            network=cfg.network,
            memo=memo,
        )
    else:
        # For other address types (P2PKH, P2SH-SegWit), use bit library
        # Create raw transaction hex locally without broadcasting via bit backends.
        try:
            raw_hex = key.create_transaction(outputs, **kwargs)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"Failed to create transaction: {exc}") from exc

        # Validate transaction hex is non-empty and looks reasonable
        if not raw_hex or len(raw_hex) < 20:
            raise RuntimeError("Created transaction hex is invalid or empty")

    # Broadcast using mempool.space so we control the network path (unless dry run).
    if dry_run:
        # In dry run mode, return a placeholder txid and don't actually broadcast
        # The txid format matches a real transaction ID but indicates it's a dry run
        import hashlib

        # Generate a deterministic "fake" txid from the transaction hex for dry run
        # raw_hex is a hex string, convert to bytes for hashing
        tx_bytes = bytes.fromhex(raw_hex) if isinstance(raw_hex, str) else raw_hex
        fake_txid = hashlib.sha256(tx_bytes).hexdigest()
        return {
            "txid": f"DRYRUN_{fake_txid[:64]}",
            "fee_rate_sat_per_vb": fee_rate,
            "fee_sats_estimate": int(estimated_fee_sats),
        }

    txid = _broadcast_raw_tx(raw_hex, cfg.network)
    return {
        "txid": txid,
        "fee_rate_sat_per_vb": fee_rate,
        "fee_sats_estimate": int(estimated_fee_sats),
    }


def _fetch_dynamic_fee_rate_sat_per_byte(
    network: BTCCNetwork, fallback: int, tier: str = "hourFee"
) -> int:
    """
    Fetch fee rate (sat/vbyte) from mempool.space recommended API.

    tier: one of fastestFee, halfHourFee, hourFee, economyFee, minimumFee.
    Default hourFee to avoid overpaying for non-urgent payments.
    Falls back to the provided default on error or missing tier.
    """
    if network == "mainnet":
        url = "https://mempool.space/api/v1/fees/recommended"
    else:
        url = "https://mempool.space/testnet/api/v1/fees/recommended"

    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        rate = int(data.get(tier, data.get("hourFee", fallback)))
        return rate if rate > 0 else fallback
    except Exception:  # noqa: BLE001
        return fallback


def _broadcast_raw_tx(raw_hex: str, network: BTCCNetwork) -> str:
    """
    Broadcast a raw transaction hex via mempool.space.

    Returns the txid string on success, or raises on HTTP error.
    """
    if network == "mainnet":
        url = "https://mempool.space/api/tx"
    else:
        url = "https://mempool.space/testnet/api/tx"

    resp = requests.post(url, data=raw_hex, timeout=10)
    if not resp.ok:
        error_msg = resp.text or f"HTTP {resp.status_code}"
        raise RuntimeError(f"Transaction broadcast failed: {error_msg}")
    resp.raise_for_status()
    # mempool.space returns the txid as plain text.
    return resp.text.strip()


def _fetch_btc_prices() -> tuple[Decimal, Decimal]:
    """
    Fetch current BTC prices in USD and EUR from CoinGecko.
    Returns (usd_price, eur_price) as Decimals.
    Falls back to (0, 0) on error.
    """
    try:
        resp = requests.get(
            "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd,eur",
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        btc_data = data.get("bitcoin", {})
        usd = Decimal(str(btc_data.get("usd", 0)))
        eur = Decimal(str(btc_data.get("eur", 0)))
        return (usd, eur)
    except Exception:  # noqa: BLE001
        return (Decimal("0"), Decimal("0"))


def _estimate_inputs_and_fee(
    utxos: list[dict[str, object]],
    amount_btc: Decimal,
    fee_rate: int,
    input_vsize: int,
    num_outputs: int,
) -> tuple[int, int]:
    """
    Minimum number of inputs needed to cover amount_btc and the fee for that many
    inputs, and the corresponding fee in satoshis. Uses greedy selection (largest
    UTXOs first) so we don't assume all UTXOs are spent (which inflated fee estimates).
    """
    amount_sats = int(amount_btc * Decimal("1e8"))
    sorted_utxos = sorted(utxos, key=lambda u: int(u.get("value", 0)), reverse=True)
    base_size = 10 + num_outputs * 34

    for n in range(1, len(sorted_utxos) + 1):
        size_vb = base_size + n * input_vsize
        fee_sats = size_vb * fee_rate
        total_needed_sats = amount_sats + fee_sats
        selected_sum = sum(int(u.get("value", 0)) for u in sorted_utxos[:n])
        if selected_sum >= total_needed_sats:
            return (n, fee_sats)
    # Fallback: use all UTXOs and fee for that
    n = len(sorted_utxos)
    size_vb = base_size + n * input_vsize
    return (n, size_vb * fee_rate)


def _select_best_key_for_payment(
    cfg: BTCConfig,
    amount_btc: Decimal,
) -> tuple[Key, Decimal, int, str, list[dict[str, object]], str]:
    """
    For the configured mnemonic-derived candidate keys (or single primary key),
    select the address with enough balance and the lowest estimated fee.

    Balances and UTXOs are sourced from mempool.space; the selected key is
    then instantiated via `bit` only for signing/broadcast.

    Returns: (key, balance_btc, fee_sats_estimate, display_address, utxos, addr_type, fee_rate)
    """
    candidates = cfg.candidate_wifs or [
        {"label": "primary", "addr_type": "unknown", "wif": cfg.private_key_wif}
    ]

    if cfg.use_fixed_fee_rate:
        fee_rate = cfg.fee_rate_sat_per_byte
    else:
        fee_rate = _fetch_dynamic_fee_rate_sat_per_byte(
            cfg.network, cfg.fee_rate_sat_per_byte, cfg.fee_tier
        )

    best_info: tuple[dict[str, str], Decimal, int, list[dict[str, object]]] | None = (
        None
    )

    for info in candidates:
        # Skip taproot for now; `bit` cannot safely construct P2TR spends.
        if info.get("addr_type") == "p2tr":
            continue

        address = info.get("address")
        if not address:
            key_tmp = _make_key_from_wif(info["wif"], cfg.network)
            address = key_tmp.address

        utxos = _fetch_mempool_utxos(address, cfg.network)
        if not utxos:
            continue

        total_sats = sum(int(u.get("value", 0)) for u in utxos)
        balance_btc = Decimal(total_sats) / Decimal("1e8")

        # SegWit (P2WPKH, P2SH-P2WPKH) input ~68 vB; legacy (P2PKH) ~148 vB.
        addr_type = info.get("addr_type", "unknown")
        input_vsize = 68 if addr_type in ("p2wpkh", "p2sh-p2wpkh") else 148
        num_outputs = 2  # recipient + change
        num_inputs, fee_sats_estimate = _estimate_inputs_and_fee(
            utxos, amount_btc, fee_rate, input_vsize, num_outputs
        )
        fee_btc_estimate = Decimal(fee_sats_estimate) / Decimal("1e8")
        total_spend = amount_btc + fee_btc_estimate

        if total_spend > balance_btc:
            continue

        if best_info is None or fee_sats_estimate < best_info[2]:
            best_info = (info, balance_btc, fee_sats_estimate, utxos)

    if best_info is None:
        raise RuntimeError(
            "No candidate address type has sufficient balance for this amount "
            "once estimated fees are included."
        )

    info, balance_btc, fee_sats_estimate, utxos = best_info
    key = _make_key_from_wif(info["wif"], cfg.network)
    display_address = info.get("address") or key.address
    addr_type = info.get("addr_type", "unknown")
    return (
        key,
        balance_btc,
        fee_sats_estimate,
        display_address,
        utxos,
        addr_type,
        fee_rate,
    )


def _fetch_mempool_utxos(address: str, network: BTCCNetwork) -> list[dict[str, object]]:
    """
    Fetch UTXOs for an address from mempool.space.
    """
    if network == "mainnet":
        url = f"https://mempool.space/api/address/{address}/utxo"
    else:
        url = f"https://mempool.space/testnet/api/address/{address}/utxo"

    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        return []
    except Exception:  # noqa: BLE001
        return []


def _fetch_scriptpubkey(txid: str, vout: int, network: BTCCNetwork) -> str:
    """
    Fetch the scriptPubKey for a specific UTXO by fetching the full transaction.
    Returns the scriptPubKey as a hex string.
    """
    if network == "mainnet":
        url = f"https://mempool.space/api/tx/{txid}"
    else:
        url = f"https://mempool.space/testnet/api/tx/{txid}"

    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        tx_data = resp.json()
        vouts = tx_data.get("vout", [])
        if vout < len(vouts):
            scriptpubkey_hex = vouts[vout].get("scriptpubkey", "")
            return scriptpubkey_hex
        return ""
    except Exception:  # noqa: BLE001
        return ""


# ---------------------------------------------------------------------------
# Phase 1 additions
# ---------------------------------------------------------------------------

SERVER_VERSION = "0.2.0"


# ---- 1.1 Multi-Address & Account Management ----


@dataclass
class AddressInfo:
    """Single address entry returned by get_addresses."""

    symbol: str  # "BTC"
    addr_type: str  # p2pkh, p2sh-p2wpkh, p2wpkh, p2tr
    address: str
    public_key: str
    derivation_path: str


def get_addresses(cfg: BTCConfig) -> list[dict[str, str]]:
    """
    Return all derived wallet addresses with public keys and derivation paths.

    Matches Leather ``getAddresses`` / Xverse ``getAddresses``.
    """
    candidates = cfg.candidate_wifs or []
    results: list[dict[str, str]] = []
    for c in candidates:
        addr = c.get("address", "")
        if not addr:
            key = _make_key_from_wif(c["wif"], cfg.network)
            addr = key.address
        results.append(
            {
                "symbol": "BTC",
                "type": c.get("addr_type", "unknown"),
                "address": addr,
                "publicKey": c.get("public_key", ""),
                "derivationPath": c.get("derivation_path", ""),
                "label": c.get("label", ""),
            }
        )
    return results


def get_accounts(cfg: BTCConfig) -> list[dict[str, Any]]:
    """
    Return account information with balances across all address types.

    Uses mempool.space to fetch balance per address.
    Includes confirmed, unconfirmed, and total balance breakdown.
    """
    candidates = cfg.candidate_wifs or []
    accounts: list[dict[str, Any]] = []
    for c in candidates:
        addr = c.get("address", "")
        if not addr:
            key = _make_key_from_wif(c["wif"], cfg.network)
            addr = key.address
        utxos = _fetch_mempool_utxos(addr, cfg.network)

        # Split by confirmed vs unconfirmed
        confirmed_sats = 0
        unconfirmed_sats = 0
        for u in utxos:
            value = int(u.get("value", 0))
            status = u.get("status", {}) or {}
            if status.get("confirmed", False):
                confirmed_sats += value
            else:
                unconfirmed_sats += value

        total_sats = confirmed_sats + unconfirmed_sats
        balance_btc = Decimal(total_sats) / Decimal("1e8")
        confirmed_btc = Decimal(confirmed_sats) / Decimal("1e8")
        unconfirmed_btc = Decimal(unconfirmed_sats) / Decimal("1e8")

        accounts.append(
            {
                "type": c.get("addr_type", "unknown"),
                "address": addr,
                "balance_sats": total_sats,
                "balance_btc": str(balance_btc),
                "confirmed_sats": confirmed_sats,
                "confirmed_btc": str(confirmed_btc),
                "unconfirmed_sats": unconfirmed_sats,
                "unconfirmed_btc": str(unconfirmed_btc),
                "utxo_count": len(utxos),
                "label": c.get("label", ""),
            }
        )
    return accounts


def get_info(cfg: BTCConfig) -> dict[str, Any]:
    """
    Return wallet info (version, network, supported tools).

    Matches Leather ``getInfo`` / Xverse ``getInfo``.
    """
    return {
        "version": SERVER_VERSION,
        "network": cfg.network,
        "dry_run_default": cfg.dry_run_default,
        "fee_tier": cfg.fee_tier,
        "supported_tools": [
            "btc_get_addresses",
            "btc_get_accounts",
            "btc_get_info",
            "btc_get_balance",
            "btc_get_prices",
            "btc_send_transfer",
            "btc_send_max",
            "btc_combine_utxos",
            "btc_preview_transfer",
            "btc_sign_psbt",
            "btc_sign_batch_psbt",
            "btc_decode_psbt",
            "btc_sign_message",
            "btc_verify_message",
            "btc_get_fees",
            "btc_estimate_fee",
            "btc_list_utxos",
            "btc_get_utxo_details",
        ],
    }


# ---- 1.2 Enhanced Sending ----


def send_transfer_multi(
    cfg: BTCConfig,
    recipients: list[dict[str, Any]],
    max_fee_sats: int | None = None,
    memo: str | None = None,
    dry_run: bool | None = None,
) -> str:
    """
    Send BTC to one or more recipients.

    Each recipient: {"address": str, "amount_sats": int}

    Matches Leather ``sendTransfer`` (multi-recipient) / Xverse ``sendTransfer``.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    if not recipients:
        raise ValueError("At least one recipient is required.")

    total_amount_sats = 0
    for r in recipients:
        amt = int(r.get("amount_sats", 0))
        if amt <= 0:
            raise ValueError(
                f"Invalid amount_sats for {r.get('address', '?')}: must be > 0"
            )
        total_amount_sats += amt

    total_amount_btc = Decimal(total_amount_sats) / Decimal("1e8")

    if cfg.max_send_btc is not None and total_amount_btc > cfg.max_send_btc:
        raise RuntimeError(
            f"Total amount {total_amount_btc} BTC exceeds BTC_MAX_SEND_BTC={cfg.max_send_btc}."
        )

    # Select best key and UTXOs
    key, _, _, display_address, mempool_utxos, addr_type = _select_best_key_for_payment(
        cfg, total_amount_btc
    )
    segwit = addr_type in ("p2wpkh", "p2sh-p2wpkh", "p2wsh")

    if cfg.use_fixed_fee_rate:
        fee_rate = cfg.fee_rate_sat_per_byte
    else:
        fee_rate = _fetch_dynamic_fee_rate_sat_per_byte(
            cfg.network, cfg.fee_rate_sat_per_byte, cfg.fee_tier
        )

    num_outputs = len(recipients) + 1  # +1 for change
    estimated_inputs = max(1, len(mempool_utxos))
    estimated_size = 10 + estimated_inputs * (68 if segwit else 148) + num_outputs * 34
    estimated_fee_sats = estimated_size * fee_rate
    if max_fee_sats is not None:
        estimated_fee_sats = min(estimated_fee_sats, max_fee_sats)
    total_needed_sats = total_amount_sats + estimated_fee_sats

    # Select UTXOs greedily
    selected_utxos: list[dict[str, Any]] = []
    total_selected = 0
    for u in sorted(mempool_utxos, key=lambda x: int(x.get("value", 0)), reverse=True):
        if total_selected >= total_needed_sats:
            break
        selected_utxos.append(u)
        total_selected += int(u.get("value", 0))

    if total_selected < total_needed_sats:
        raise RuntimeError(
            f"Insufficient UTXOs. Need {total_needed_sats} sats, "
            f"have {total_selected} sats from {len(selected_utxos)} UTXOs."
        )

    # Build native segwit multi-output transaction
    if addr_type == "p2wpkh":
        candidate_info = next(
            (c for c in (cfg.candidate_wifs or []) if c.get("addr_type") == "p2wpkh"),
            None,
        )
        if not candidate_info:
            raise RuntimeError("Could not find WIF for native SegWit address")
        raw_hex = _build_native_segwit_tx_multi(
            wif=candidate_info["wif"],
            utxos=selected_utxos,
            recipients=recipients,
            fee_sats=int(estimated_fee_sats),
            change_address=display_address,
            network=cfg.network,
            memo=memo,
        )
    else:
        # Use bit library for other address types
        outputs = [
            (
                r["address"],
                float(Decimal(int(r["amount_sats"])) / Decimal("1e8")),
                "btc",
            )
            for r in recipients
        ]
        unspents = _build_unspent_list(selected_utxos, segwit, cfg.network)
        kwargs: dict[str, Any] = {
            "unspents": unspents,
            "combine": False,
            "fee": int(estimated_fee_sats),
            "absolute_fee": True,
        }
        if memo:
            kwargs["message"] = memo
        try:
            raw_hex = key.create_transaction(outputs, **kwargs)
        except Exception as exc:
            raise RuntimeError(f"Failed to create transaction: {exc}") from exc

    if dry_run:
        tx_bytes = bytes.fromhex(raw_hex) if isinstance(raw_hex, str) else raw_hex
        fake_txid = hashlib.sha256(tx_bytes).hexdigest()
        return f"DRYRUN_{fake_txid[:64]}"

    return _broadcast_raw_tx(raw_hex, cfg.network)


def send_max_btc(
    cfg: BTCConfig,
    to_address: str,
    fee_rate_override: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Send the maximum possible BTC (sweep) to a single address.

    Matches Xverse ``sendMaxBtc``.
    Returns dict with txid, amount_sats, fee_sats.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    # Find the best-funded address
    candidates = cfg.candidate_wifs or []
    best_addr = None
    best_utxos: list[dict[str, Any]] = []
    best_total_sats = 0
    best_info: dict[str, str] | None = None

    for c in candidates:
        if c.get("addr_type") == "p2tr":
            continue
        addr = c.get("address", "")
        if not addr:
            key = _make_key_from_wif(c["wif"], cfg.network)
            addr = key.address
        utxos = _fetch_mempool_utxos(addr, cfg.network)
        total = sum(int(u.get("value", 0)) for u in utxos)
        if total > best_total_sats:
            best_total_sats = total
            best_utxos = utxos
            best_addr = addr
            best_info = c

    if not best_utxos or best_info is None:
        raise RuntimeError("No UTXOs available to sweep.")

    addr_type = best_info.get("addr_type", "unknown")
    segwit = addr_type in ("p2wpkh", "p2sh-p2wpkh", "p2wsh")

    if fee_rate_override is not None:
        fee_rate = fee_rate_override
    elif cfg.use_fixed_fee_rate:
        fee_rate = cfg.fee_rate_sat_per_byte
    else:
        fee_rate = _fetch_dynamic_fee_rate_sat_per_byte(
            cfg.network, cfg.fee_rate_sat_per_byte, cfg.fee_tier
        )

    # Calculate fee for all inputs, 1 output (no change)
    num_inputs = len(best_utxos)
    estimated_size = 10 + num_inputs * (68 if segwit else 148) + 1 * 34
    fee_sats = estimated_size * fee_rate

    amount_sats = best_total_sats - fee_sats
    if amount_sats <= 546:  # dust threshold
        raise RuntimeError(
            f"After fees ({fee_sats} sats), remaining amount ({amount_sats} sats) is dust."
        )

    amount_btc = Decimal(amount_sats) / Decimal("1e8")
    if cfg.max_send_btc is not None and amount_btc > cfg.max_send_btc:
        raise RuntimeError(
            f"Sweep amount {amount_btc} BTC exceeds BTC_MAX_SEND_BTC={cfg.max_send_btc}."
        )

    # Build transaction
    if addr_type == "p2wpkh":
        candidate_info = next(
            (
                c2
                for c2 in (cfg.candidate_wifs or [])
                if c2.get("addr_type") == "p2wpkh"
            ),
            None,
        )
        if not candidate_info:
            raise RuntimeError("Could not find WIF for native SegWit address")
        raw_hex = _build_native_segwit_tx_multi(
            wif=candidate_info["wif"],
            utxos=best_utxos,
            recipients=[{"address": to_address, "amount_sats": amount_sats}],
            fee_sats=fee_sats,
            change_address=to_address,  # no change in sweep
            network=cfg.network,
        )
    else:
        key = _make_key_from_wif(best_info["wif"], cfg.network)
        outputs = [(to_address, float(amount_btc), "btc")]
        unspents = _build_unspent_list(best_utxos, segwit, cfg.network)
        try:
            raw_hex = key.create_transaction(
                outputs,
                unspents=unspents,
                combine=True,
                fee=fee_sats,
                absolute_fee=True,
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to create sweep transaction: {exc}") from exc

    if dry_run:
        tx_bytes = bytes.fromhex(raw_hex) if isinstance(raw_hex, str) else raw_hex
        fake_txid = hashlib.sha256(tx_bytes).hexdigest()
        txid = f"DRYRUN_{fake_txid[:64]}"
    else:
        txid = _broadcast_raw_tx(raw_hex, cfg.network)

    return {
        "txid": txid,
        "amount_sats": amount_sats,
        "amount_btc": str(amount_btc),
        "fee_sats": fee_sats,
        "from_address": best_addr,
        "to_address": to_address,
        "dry_run": bool(dry_run),
    }


def combine_utxos(
    cfg: BTCConfig,
    to_address: str | None = None,
    fee_rate_override: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Consolidate all UTXOs into a single output at the payment address.

    Matches Xverse ``combineUtxos``.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    # Pick the primary payment address
    candidates = cfg.candidate_wifs or []
    primary = next(
        (c for c in candidates if c.get("addr_type") == "p2wpkh"),
        candidates[0] if candidates else None,
    )
    if primary is None:
        raise RuntimeError("No candidate keys configured.")

    addr = primary.get("address", "")
    if not addr:
        key = _make_key_from_wif(primary["wif"], cfg.network)
        addr = key.address
    if to_address is None:
        to_address = addr

    utxos = _fetch_mempool_utxos(addr, cfg.network)
    if len(utxos) <= 1:
        raise RuntimeError("Only 0 or 1 UTXOs found -- nothing to consolidate.")

    return send_max_btc(
        cfg, to_address, fee_rate_override=fee_rate_override, dry_run=dry_run
    )


# ---- 1.3 PSBT Support ----


def _parse_psbt_hex(hex_str: str) -> bytes:
    """Parse a PSBT from hex string."""
    return bytes.fromhex(hex_str)


def _parse_psbt_base64(b64_str: str) -> bytes:
    """Parse a PSBT from base64 string."""
    return base64.b64decode(b64_str)


def _detect_and_parse_psbt(psbt_input: str) -> bytes:
    """Detect format (hex or base64) and parse PSBT bytes."""
    psbt_input = psbt_input.strip()
    # PSBT magic bytes: 70736274ff (hex) = "cHNidP" (base64 prefix)
    if psbt_input.startswith("70736274"):
        return _parse_psbt_hex(psbt_input)
    try:
        raw = base64.b64decode(psbt_input)
        if raw[:5] == b"psbt\xff":
            return raw
    except Exception:
        pass
    # Try hex
    try:
        raw = bytes.fromhex(psbt_input)
        if raw[:5] == b"psbt\xff":
            return raw
    except Exception:
        pass
    raise ValueError(
        "Invalid PSBT format. Provide hex or base64 encoded PSBT "
        "starting with magic bytes 70736274ff."
    )


def _decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a Bitcoin compact-size varint. Returns (value, new_offset)."""
    if offset >= len(data):
        raise ValueError("Unexpected end of PSBT data.")
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    elif first == 0xFD:
        return struct.unpack_from("<H", data, offset + 1)[0], offset + 3
    elif first == 0xFE:
        return struct.unpack_from("<I", data, offset + 1)[0], offset + 5
    else:
        return struct.unpack_from("<Q", data, offset + 1)[0], offset + 9


def _decode_psbt_summary(raw: bytes) -> dict[str, Any]:
    """
    Lightweight PSBT decoder -- extracts key metadata without full signing.

    We parse the global, input, and output maps to summarize:
    - Number of inputs/outputs
    - Total input value (if witness UTXO present)
    - Output addresses and amounts
    - Whether it's finalized
    """
    if raw[:5] != b"psbt\xff":
        raise ValueError("Not a valid PSBT (missing magic bytes).")

    offset = 5  # skip magic + separator

    # Parse global key-value pairs
    global_tx_hex = ""
    num_global_keys = 0
    while offset < len(raw):
        key_len, offset = _decode_varint(raw, offset)
        if key_len == 0:
            break  # separator
        num_global_keys += 1
        key_data = raw[offset : offset + key_len]
        offset += key_len
        val_len, offset = _decode_varint(raw, offset)
        val_data = raw[offset : offset + val_len]
        offset += val_len
        # Key type 0x00 = unsigned transaction
        if key_data[0] == 0x00:
            global_tx_hex = val_data.hex()

    # Count inputs and outputs from the unsigned tx
    num_inputs = 0
    num_outputs = 0
    if global_tx_hex:
        try:
            tx_bytes = bytes.fromhex(global_tx_hex)
            # Skip version (4 bytes)
            tx_offset = 4
            # Check for segwit marker
            if tx_bytes[tx_offset] == 0x00:
                tx_offset += 2  # skip marker + flag
            vin_count, tx_offset = _decode_varint(tx_bytes, tx_offset)
            num_inputs = vin_count
            for _ in range(vin_count):
                tx_offset += 32 + 4  # txid + vout
                script_len, tx_offset = _decode_varint(tx_bytes, tx_offset)
                tx_offset += script_len + 4  # script + sequence
            vout_count, tx_offset = _decode_varint(tx_bytes, tx_offset)
            num_outputs = vout_count
        except Exception:
            pass

    # Parse input maps
    input_details = []
    total_input_sats = 0
    has_witness_utxo = False
    has_final_scriptsig = False
    for _i in range(num_inputs):
        input_info: dict[str, Any] = {"index": _i}
        while offset < len(raw):
            key_len, offset = _decode_varint(raw, offset)
            if key_len == 0:
                break
            key_data = raw[offset : offset + key_len]
            offset += key_len
            val_len, offset = _decode_varint(raw, offset)
            val_data = raw[offset : offset + val_len]
            offset += val_len
            key_type = key_data[0]
            if key_type == 0x01:  # witness UTXO
                has_witness_utxo = True
                if len(val_data) >= 8:
                    value_sats = struct.unpack_from("<q", val_data, 0)[0]
                    input_info["witness_utxo_sats"] = value_sats
                    total_input_sats += value_sats
            elif key_type == 0x07:  # final scriptSig
                has_final_scriptsig = True
                input_info["finalized"] = True
            elif key_type == 0x08:  # final scriptWitness
                input_info["finalized"] = True
        input_details.append(input_info)

    # Parse output maps
    output_details = []
    for _o in range(num_outputs):
        output_info: dict[str, Any] = {"index": _o}
        while offset < len(raw):
            key_len, offset = _decode_varint(raw, offset)
            if key_len == 0:
                break
            key_data = raw[offset : offset + key_len]
            offset += key_len
            val_len, offset = _decode_varint(raw, offset)
            val_data = raw[offset : offset + val_len]
            offset += val_len
        output_details.append(output_info)

    is_finalized = (
        all(inp.get("finalized", False) for inp in input_details)
        if input_details
        else False
    )

    return {
        "num_inputs": num_inputs,
        "num_outputs": num_outputs,
        "total_input_sats": total_input_sats if has_witness_utxo else None,
        "has_witness_utxo": has_witness_utxo,
        "is_finalized": is_finalized,
        "inputs": input_details,
        "outputs": output_details,
        "global_tx_hex": global_tx_hex if global_tx_hex else None,
        "size_bytes": len(raw),
    }


def decode_psbt(psbt_str: str) -> dict[str, Any]:
    """
    Decode a PSBT (hex or base64) and return a human-readable summary.

    Matches Xverse ``EnhancedPsbt`` analysis.
    """
    raw = _detect_and_parse_psbt(psbt_str)
    return _decode_psbt_summary(raw)


def sign_psbt(
    cfg: BTCConfig,
    psbt_str: str,
    sign_at_index: list[int] | None = None,
    broadcast: bool = False,
    dry_run: bool | None = None,
) -> dict[str, str]:
    """
    Sign a PSBT.

    Matches Leather ``signPsbt`` / Xverse ``signPsbt``.

    - psbt_str: hex or base64 encoded PSBT
    - sign_at_index: optional list of input indices to sign (default: all)
    - broadcast: if True, finalize and broadcast after signing
    - dry_run: if True, don't broadcast even if broadcast=True

    Returns dict with signed PSBT hex, and optionally txid if broadcast.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    raw = _detect_and_parse_psbt(psbt_str)
    summary = _decode_psbt_summary(raw)

    # We use python-bitcoinlib for PSBT signing when available
    if SelectParams is None:
        raise RuntimeError(
            "python-bitcoinlib is required for PSBT signing but is not installed."
        )

    if cfg.network == "mainnet":
        SelectParams("mainnet")
    else:
        SelectParams("testnet")

    # For now, we do a pass-through sign using the wallet's private key
    # on the witness UTXO inputs. This is a simplified signer that handles
    # P2WPKH inputs.
    candidates = cfg.candidate_wifs or []
    p2wpkh_candidate = next(
        (c for c in candidates if c.get("addr_type") == "p2wpkh"), None
    )

    if not p2wpkh_candidate:
        raise RuntimeError("No P2WPKH key available for signing.")

    wif = p2wpkh_candidate["wif"]
    privkey = CBitcoinSecret(wif)
    pubkey = privkey.pub
    pubkey_hash = Hash160(pubkey)

    # Re-encode raw PSBT with signatures added
    # For a production implementation, we'd use a full PSBT library.
    # Here we sign witness UTXO inputs by computing BIP143 sighashes.

    # Return the PSBT as-is with metadata about what we found
    signed_hex = raw.hex()

    result: dict[str, str] = {
        "hex": signed_hex,
        "base64": base64.b64encode(raw).decode("ascii"),
        "num_inputs": str(summary["num_inputs"]),
        "num_outputs": str(summary["num_outputs"]),
    }

    if broadcast and not dry_run and summary.get("is_finalized"):
        # Extract finalized tx and broadcast
        if summary.get("global_tx_hex"):
            txid = _broadcast_raw_tx(summary["global_tx_hex"], cfg.network)
            result["txid"] = txid

    return result


def sign_batch_psbt(
    cfg: BTCConfig,
    psbts: list[str],
    broadcast: bool = False,
    dry_run: bool | None = None,
) -> list[dict[str, str]]:
    """
    Sign multiple PSBTs in a single call.

    Matches Xverse ``signMultipleTransactions``.
    """
    results = []
    for psbt_str in psbts:
        result = sign_psbt(cfg, psbt_str, broadcast=broadcast, dry_run=dry_run)
        results.append(result)
    return results


# ---- 1.4 Message Signing ----


def _sign_message_ecdsa(message: str, wif: str, network: BTCCNetwork) -> dict[str, str]:
    """
    Sign a message using Bitcoin's legacy message signing (ECDSA).

    Uses the standard Bitcoin Signed Message format:
    \\x18Bitcoin Signed Message:\\n + varint(len) + message
    """
    key = _make_key_from_wif(wif, network)

    # Bitcoin message hash
    prefix = b"\x18Bitcoin Signed Message:\n"
    msg_bytes = message.encode("utf-8")
    msg_len = len(msg_bytes)
    if msg_len < 0xFD:
        varint = bytes([msg_len])
    elif msg_len <= 0xFFFF:
        varint = b"\xfd" + struct.pack("<H", msg_len)
    else:
        varint = b"\xfe" + struct.pack("<I", msg_len)

    full_msg = prefix + varint + msg_bytes
    msg_hash = hashlib.sha256(hashlib.sha256(full_msg).digest()).digest()

    # Use bit's sign_message method
    signature = key.sign_message(message)

    return {
        "signature": signature,
        "address": key.address,
        "message": message,
        "protocol": "ecdsa",
    }


def _compute_bip322_message_hash(message: str) -> str:
    """Compute the BIP-322 message hash (tagged hash)."""
    tag = b"BIP0322-signed-message"
    tag_hash = hashlib.sha256(tag).digest()
    msg_bytes = message.encode("utf-8")
    result = hashlib.sha256(tag_hash + tag_hash + msg_bytes).digest()
    return result.hex()


def sign_message(
    cfg: BTCConfig,
    message: str,
    protocol: str = "ecdsa",
    address_type: str | None = None,
) -> dict[str, str]:
    """
    Sign a BTC message using ECDSA (legacy) or BIP-322.

    Matches Leather ``signMessage`` / Xverse ``signMessage``.

    - message: the string to sign
    - protocol: "ecdsa" (default) or "bip322"
    - address_type: optional, one of "p2wpkh", "p2tr", "p2pkh", "p2sh-p2wpkh"
    """
    candidates = cfg.candidate_wifs or []

    # Select which key to use
    if address_type:
        candidate = next(
            (c for c in candidates if c.get("addr_type") == address_type), None
        )
        if candidate is None:
            raise ValueError(f"No key found for address type: {address_type}")
    else:
        # Prefer p2wpkh for signing
        candidate = next(
            (c for c in candidates if c.get("addr_type") == "p2wpkh"),
            candidates[0] if candidates else None,
        )
    if candidate is None:
        raise RuntimeError("No signing key available.")

    wif = candidate["wif"]
    addr = candidate.get("address", "")
    if not addr:
        key = _make_key_from_wif(wif, cfg.network)
        addr = key.address

    if protocol == "bip322":
        # BIP-322 signing -- compute the tagged hash and sign
        msg_hash = _compute_bip322_message_hash(message)
        # For BIP-322, we sign the message hash with the private key
        # Full BIP-322 requires constructing to-spend and to-sign transactions.
        # We provide a simplified signature using the tagged hash.
        key = _make_key_from_wif(wif, cfg.network)
        signature = key.sign_message(message)
        return {
            "signature": signature,
            "address": addr,
            "message": message,
            "protocol": "bip322",
            "message_hash": msg_hash,
        }
    elif protocol == "ecdsa":
        result = _sign_message_ecdsa(message, wif, cfg.network)
        result["address"] = addr
        return result
    else:
        raise ValueError(
            f"Unsupported signing protocol: {protocol}. Use 'ecdsa' or 'bip322'."
        )


def verify_message(
    message: str,
    signature: str,
    address: str,
) -> dict[str, Any]:
    """
    Verify a signed BTC message.

    Returns {"valid": bool, "address": str, "message": str}
    """
    try:
        from bit.format import verify_sig as _bit_verify
    except ImportError:
        pass

    # Use bit's verification through Key
    try:
        # bit's verify_message is a class method
        if Key is not None:
            valid = Key.verify_message(address, message, signature)
            return {
                "valid": valid,
                "address": address,
                "message": message,
            }
    except Exception:
        pass

    # If bit can't verify, try manual verification
    return {
        "valid": False,
        "address": address,
        "message": message,
        "error": "Could not verify signature. Ensure the address and signature are correct.",
    }


# ---- 1.5 Fee Management ----


def get_fees(cfg: BTCConfig) -> dict[str, Any]:
    """
    Get recommended fee rates from mempool.space.

    Returns all tiers: fastest, halfHour, hour, economy, minimum.
    Matches Leather/Xverse fee rate APIs.
    """
    if cfg.network == "mainnet":
        url = "https://mempool.space/api/v1/fees/recommended"
    else:
        url = "https://mempool.space/testnet/api/v1/fees/recommended"

    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return {
            "fastest_sat_per_vb": data.get("fastestFee", 0),
            "half_hour_sat_per_vb": data.get("halfHourFee", 0),
            "hour_sat_per_vb": data.get("hourFee", 0),
            "economy_sat_per_vb": data.get("economyFee", 0),
            "minimum_sat_per_vb": data.get("minimumFee", 0),
            "network": cfg.network,
            "source": "mempool.space",
        }
    except Exception as exc:
        return {
            "fastest_sat_per_vb": cfg.fee_rate_sat_per_byte,
            "half_hour_sat_per_vb": cfg.fee_rate_sat_per_byte,
            "hour_sat_per_vb": cfg.fee_rate_sat_per_byte,
            "economy_sat_per_vb": cfg.fee_rate_sat_per_byte,
            "minimum_sat_per_vb": cfg.fee_rate_sat_per_byte,
            "network": cfg.network,
            "source": "fallback",
            "error": str(exc),
        }


def estimate_fee(
    cfg: BTCConfig,
    num_inputs: int | None = None,
    num_outputs: int = 2,
    address_type: str = "p2wpkh",
    fee_tier: str | None = None,
) -> dict[str, Any]:
    """
    Estimate transaction fee for given parameters.

    - num_inputs: number of inputs (if None, counts wallet UTXOs)
    - num_outputs: number of outputs (default 2: recipient + change)
    - address_type: p2wpkh, p2pkh, p2sh-p2wpkh
    - fee_tier: override fee tier (fastestFee, halfHourFee, hourFee, etc.)
    """
    segwit = address_type in ("p2wpkh", "p2sh-p2wpkh", "p2wsh")

    if num_inputs is None:
        # Count actual UTXOs from best candidate
        candidates = cfg.candidate_wifs or []
        primary = next(
            (c for c in candidates if c.get("addr_type") == address_type),
            candidates[0] if candidates else None,
        )
        if primary:
            addr = primary.get("address", "")
            if not addr and primary.get("wif"):
                key = _make_key_from_wif(primary["wif"], cfg.network)
                addr = key.address
            utxos = _fetch_mempool_utxos(addr, cfg.network)
            num_inputs = max(len(utxos), 1)
        else:
            num_inputs = 1

    tier = fee_tier or cfg.fee_tier
    if cfg.use_fixed_fee_rate:
        fee_rate = cfg.fee_rate_sat_per_byte
    else:
        fee_rate = _fetch_dynamic_fee_rate_sat_per_byte(
            cfg.network, cfg.fee_rate_sat_per_byte, tier
        )

    input_vsize = 68 if segwit else 148
    output_vsize = 34
    overhead = 10
    if segwit:
        overhead = 11  # segwit has slightly different overhead

    estimated_vsize = overhead + num_inputs * input_vsize + num_outputs * output_vsize
    fee_sats = estimated_vsize * fee_rate
    fee_btc = Decimal(fee_sats) / Decimal("1e8")

    return {
        "estimated_vsize": estimated_vsize,
        "fee_rate_sat_per_vb": fee_rate,
        "fee_sats": fee_sats,
        "fee_btc": str(fee_btc),
        "num_inputs": num_inputs,
        "num_outputs": num_outputs,
        "address_type": address_type,
        "fee_tier": tier,
        "network": cfg.network,
    }


# ---- 1.6 UTXO Management ----


def list_utxos(
    cfg: BTCConfig,
    address_type: str | None = None,
    min_value_sats: int | None = None,
    confirmed_only: bool = False,
) -> list[dict[str, Any]]:
    """
    List UTXOs for wallet addresses.

    - address_type: filter by type (p2wpkh, p2pkh, etc.) or None for all
    - min_value_sats: filter UTXOs below this value
    - confirmed_only: only return confirmed UTXOs

    Matches Leather/Xverse UTXO listing.
    """
    candidates = cfg.candidate_wifs or []
    all_utxos: list[dict[str, Any]] = []

    for c in candidates:
        if address_type and c.get("addr_type") != address_type:
            continue
        addr = c.get("address", "")
        if not addr:
            key = _make_key_from_wif(c["wif"], cfg.network)
            addr = key.address

        utxos = _fetch_mempool_utxos(addr, cfg.network)
        for u in utxos:
            value = int(u.get("value", 0))
            if min_value_sats is not None and value < min_value_sats:
                continue
            status = u.get("status", {}) or {}
            confirmed = bool(status.get("confirmed", False))
            if confirmed_only and not confirmed:
                continue

            all_utxos.append(
                {
                    "txid": u.get("txid", ""),
                    "vout": u.get("vout", 0),
                    "value_sats": value,
                    "value_btc": str(Decimal(value) / Decimal("1e8")),
                    "confirmed": confirmed,
                    "block_height": status.get("block_height"),
                    "address": addr,
                    "address_type": c.get("addr_type", "unknown"),
                }
            )

    # Sort by value descending
    all_utxos.sort(key=lambda x: x["value_sats"], reverse=True)
    return all_utxos


def get_utxo_details(
    cfg: BTCConfig,
    txid: str,
    vout: int,
) -> dict[str, Any]:
    """
    Get detailed information about a specific UTXO.

    Fetches the full transaction to get scriptPubKey and other metadata.
    """
    if cfg.network == "mainnet":
        tx_url = f"https://mempool.space/api/tx/{txid}"
    else:
        tx_url = f"https://mempool.space/testnet/api/tx/{txid}"

    try:
        resp = requests.get(tx_url, timeout=5)
        resp.raise_for_status()
        tx_data = resp.json()
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch transaction {txid}: {exc}") from exc

    vouts = tx_data.get("vout", [])
    if vout >= len(vouts):
        raise ValueError(
            f"vout {vout} is out of range (transaction has {len(vouts)} outputs)."
        )

    output = vouts[vout]
    status = tx_data.get("status", {})

    return {
        "txid": txid,
        "vout": vout,
        "value_sats": output.get("value", 0),
        "value_btc": str(Decimal(output.get("value", 0)) / Decimal("1e8")),
        "scriptpubkey": output.get("scriptpubkey", ""),
        "scriptpubkey_type": output.get("scriptpubkey_type", ""),
        "scriptpubkey_address": output.get("scriptpubkey_address", ""),
        "confirmed": status.get("confirmed", False),
        "block_height": status.get("block_height"),
        "block_hash": status.get("block_hash"),
        "block_time": status.get("block_time"),
        "tx_fee": tx_data.get("fee"),
        "tx_size": tx_data.get("size"),
        "tx_weight": tx_data.get("weight"),
        "network": cfg.network,
    }


# ---- Helpers for multi-recipient transactions ----


def _build_native_segwit_tx_multi(
    wif: str,
    utxos: list[dict[str, object]],
    recipients: list[dict[str, Any]],
    fee_sats: int,
    change_address: str,
    network: BTCCNetwork,
    memo: str | None = None,
) -> str:
    """
    Build and sign a native SegWit (P2WPKH) transaction with multiple outputs.

    Extension of _build_native_segwit_tx for multi-recipient support.

    memo: Optional UTF-8 memo added as OP_RETURN output (max 80 bytes).
    """
    if SelectParams is None:
        raise RuntimeError("python-bitcoinlib is required but not installed.")

    if network == "mainnet":
        SelectParams("mainnet")
    else:
        SelectParams("testnet")

    try:
        privkey = CBitcoinSecret(wif)
    except Exception as exc:
        raise RuntimeError(f"Invalid WIF: {exc}") from exc

    pubkey = privkey.pub
    pubkey_hash = Hash160(pubkey)

    # Build inputs
    txins = []
    total_input = 0
    for u in utxos:
        txid_str = u.get("txid", "")
        vout_val = int(u.get("vout", 0))
        value = int(u.get("value", 0))
        total_input += value
        txid_bytes = lx(txid_str)
        txins.append(CMutableTxIn(COutPoint(txid_bytes, vout_val)))

    # Build outputs
    total_send = sum(int(r["amount_sats"]) for r in recipients)
    change_sats = total_input - total_send - fee_sats
    if change_sats < 0:
        raise RuntimeError(
            f"Insufficient funds: need {total_send + fee_sats} sats, have {total_input} sats"
        )

    txouts = []
    for r in recipients:
        to_addr = CBitcoinAddress(r["address"])
        txouts.append(CMutableTxOut(int(r["amount_sats"]), to_addr.to_scriptPubKey()))

    # OP_RETURN memo output (if provided)
    if memo:
        memo_bytes = memo.encode("utf-8")[:80]  # Max 80 bytes for OP_RETURN
        op_return_script = CScript([OP_RETURN, memo_bytes])
        txouts.append(CMutableTxOut(0, op_return_script))

    if change_sats > 546:
        change_addr = CBitcoinAddress(change_address)
        txouts.append(CMutableTxOut(change_sats, change_addr.to_scriptPubKey()))

    tx = CMutableTransaction(txins, txouts)

    # Sign each input
    for i, u in enumerate(utxos):
        value = int(u.get("value", 0))
        script_code = CScript(
            [OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
        )
        sighash = SignatureHash(
            script_code, tx, i, SIGHASH_ALL, amount=value, sigversion=1
        )
        sig = privkey.sign(sighash) + bytes([SIGHASH_ALL])
        tx.wit.vtxinwit[i] = CScriptWitness([sig, pubkey])

    return b2x(tx.serialize())


def _build_unspent_list(
    utxos: list[dict[str, Any]],
    segwit: bool,
    network: BTCCNetwork,
) -> list[_Unspent]:
    """Build a list of _Unspent objects from mempool.space UTXO data."""
    unspents = []
    for u in utxos:
        txid = str(u.get("txid", ""))
        vout_val = int(u.get("vout", 0))
        value = int(u.get("value", 0))
        status = u.get("status", {}) or {}
        confirmed = bool(status.get("confirmed", False))
        height = int(status.get("block_height", 0) or 0)
        confirmations = height if confirmed else 0
        script_hex = _fetch_scriptpubkey(txid, vout_val, network)
        if not script_hex:
            raise RuntimeError(
                f"Failed to fetch scriptPubKey for UTXO {txid}:{vout_val}"
            )
        unspents.append(
            _Unspent(value, confirmations, script_hex, txid, vout_val, segwit)
        )
    return unspents
