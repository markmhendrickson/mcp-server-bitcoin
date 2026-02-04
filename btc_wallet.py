from __future__ import annotations

import os
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Literal

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
from bit import Key, PrivateKeyTestnet
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
    SIGHASH_ALL,
    CScriptWitness,
    SignatureHash,
)
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret
from dotenv import load_dotenv

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
        allowed_tiers = ("fastestFee", "halfHourFee", "hourFee", "economyFee", "minimumFee")
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
) -> str:
    """
    Build and sign a native SegWit (P2WPKH) transaction using python-bitcoinlib.

    Uses CMutableTransaction for proper witness construction.
    Based on python-bitcoinlib best practices and BIP143 (SegWit signing).
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
    key, _, _, display_address, mempool_utxos, addr_type = _select_best_key_for_payment(
        cfg, amount_btc
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

    # Estimate fee: rough size estimate (10 base + inputs * vsize + outputs * 34)
    # Start with a conservative estimate, then refine
    estimated_inputs = max(1, len(mempool_utxos))
    estimated_size = 10 + estimated_inputs * (68 if segwit else 148) + 2 * 34
    estimated_fee_sats = estimated_size * fee_rate
    total_needed_sats = amount_sats + estimated_fee_sats

    # Select UTXOs greedily until we have enough
    selected_utxos = []
    total_selected = 0
    for u in sorted(mempool_utxos, key=lambda x: int(x.get("value", 0)), reverse=True):
        if total_selected >= total_needed_sats:
            break
        selected_utxos.append(u)
        total_selected += int(u.get("value", 0))

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
        return f"DRYRUN_{fake_txid[:64]}"
    
    txid = _broadcast_raw_tx(raw_hex, cfg.network)
    return txid


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


def _select_best_key_for_payment(
    cfg: BTCConfig,
    amount_btc: Decimal,
) -> tuple[Key, Decimal, int, str, list[dict[str, object]], str]:
    """
    For the configured mnemonic-derived candidate keys (or single primary key),
    select the address with enough balance and the lowest estimated fee.

    Balances and UTXOs are sourced from mempool.space; the selected key is
    then instantiated via `bit` only for signing/broadcast.

    Returns: (key, balance_btc, fee_sats_estimate, display_address, utxos, addr_type)
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

    best_info: tuple[
        dict[str, str], Decimal, int, list[dict[str, object]]
    ] | None = None

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

        num_inputs = max(len(utxos), 1)
        num_outputs = 2  # recipient + change
        size_bytes = 10 + num_inputs * 148 + num_outputs * 34
        fee_sats_estimate = size_bytes * fee_rate
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
    return key, balance_btc, fee_sats_estimate, display_address, utxos, addr_type


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
