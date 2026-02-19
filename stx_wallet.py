"""
Stacks (STX) wallet operations for Phase 2 MCP support.

Implements:
- c32check address encoding/decoding
- STX key derivation from BIP-39 mnemonic (m/44'/5757'/0'/0/0)
- Hiro Stacks API client for balance, nonce, fees, contract reads
- Stacks transaction building, signing, and broadcasting
- Message signing (SIP-018 structured data)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal

import requests
from bip_utils import Bip39SeedGenerator
from dotenv import load_dotenv

# coincurve for secp256k1 signing (installed with bip-utils)
import coincurve

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HIRO_MAINNET = "https://api.hiro.so"
HIRO_TESTNET = "https://api.testnet.hiro.so"

STX_DERIVATION_PATH = "m/44'/5757'/0'/0"

# Stacks address versions
ADDRESS_VERSION_MAINNET_SINGLE_SIG = 22  # 'SP'
ADDRESS_VERSION_TESTNET_SINGLE_SIG = 26  # 'ST'
ADDRESS_VERSION_MAINNET_MULTI_SIG = 20  # 'SM'
ADDRESS_VERSION_TESTNET_MULTI_SIG = 21  # 'SN'

# Stacks transaction versions
TX_VERSION_MAINNET = 0x00
TX_VERSION_TESTNET = 0x80

# Chain IDs
CHAIN_ID_MAINNET = 0x00000001
CHAIN_ID_TESTNET = 0x80000000

# Transaction types
PAYLOAD_TOKEN_TRANSFER = 0x00
PAYLOAD_CONTRACT_CALL = 0x02
PAYLOAD_SMART_CONTRACT = 0x01

# Auth types
AUTH_STANDARD = 0x04
SPENDING_CONDITION_SINGLESIG_P2PKH = 0x00

# Anchor modes
ANCHOR_MODE_ANY = 0x03

# Post-condition mode
POST_CONDITION_MODE_DENY = 0x02
POST_CONDITION_MODE_ALLOW = 0x01

STXNetwork = Literal["mainnet", "testnet"]

# c32 alphabet (Crockford base32 variant)
C32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


# ---------------------------------------------------------------------------
# c32check address encoding
# ---------------------------------------------------------------------------


def _c32_encode(data: bytes) -> str:
    """Encode bytes to c32 string."""
    if not data:
        return ""
    # Convert bytes to integer
    num = int.from_bytes(data, "big")
    if num == 0:
        # Count leading zero bytes
        leading_zeros = 0
        for b in data:
            if b == 0:
                leading_zeros += 1
            else:
                break
        return C32_ALPHABET[0] * leading_zeros

    result = []
    while num > 0:
        num, remainder = divmod(num, 32)
        result.append(C32_ALPHABET[remainder])
    # Add leading zeros
    for b in data:
        if b == 0:
            result.append(C32_ALPHABET[0])
        else:
            break
    return "".join(reversed(result))


def _c32_checksum(version: int, data: bytes) -> bytes:
    """Compute c32check checksum (double SHA256 of version + data)."""
    payload = bytes([version]) + data
    h1 = hashlib.sha256(payload).digest()
    h2 = hashlib.sha256(h1).digest()
    return h2[:4]


def c32_address(version: int, hash160_bytes: bytes) -> str:
    """
    Encode a Stacks address from version byte and hash160.

    Returns a c32check-encoded address string like 'SP...' or 'ST...'.
    """
    checksum = _c32_checksum(version, hash160_bytes)
    c32_str = _c32_encode(hash160_bytes + checksum)
    # Version character
    version_char = C32_ALPHABET[version]
    return "S" + version_char + c32_str


def _hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))"""
    sha = hashlib.sha256(data).digest()
    ripemd = hashlib.new("ripemd160", sha).digest()
    return ripemd


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def _derive_stx_key_from_seed(
    seed: bytes, account_index: int = 0
) -> tuple[bytes, bytes]:
    """
    Derive a Stacks private/public key pair from a BIP-39 seed.

    Uses BIP-32 hardened derivation at m/44'/5757'/0'/0/{account_index}.
    Returns (private_key_bytes_32, compressed_public_key_bytes_33).
    """
    # BIP-32 master key derivation
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_key = I[:32]
    master_chain = I[32:]

    # Derive path: m/44'/5757'/0'/0
    path_components = [
        44 + 0x80000000,  # 44'
        5757 + 0x80000000,  # 5757'
        0 + 0x80000000,  # 0'
        0,  # 0 (external chain)
    ]

    key = master_key
    chain = master_chain

    for child_index in path_components:
        key, chain = _derive_child(key, chain, child_index)

    # Finally derive the account index (non-hardened)
    key, chain = _derive_child(key, chain, account_index)

    # Get compressed public key
    privkey_obj = coincurve.PrivateKey(key)
    pubkey = privkey_obj.public_key.format(compressed=True)

    return key, pubkey


def _derive_child(
    parent_key: bytes, parent_chain: bytes, index: int
) -> tuple[bytes, bytes]:
    """BIP-32 child key derivation."""
    if index >= 0x80000000:
        # Hardened child
        data = b"\x00" + parent_key + struct.pack(">I", index)
    else:
        # Normal child
        privkey_obj = coincurve.PrivateKey(parent_key)
        pubkey = privkey_obj.public_key.format(compressed=True)
        data = pubkey + struct.pack(">I", index)

    I = hmac.new(parent_chain, data, hashlib.sha512).digest()
    child_key_int = (
        int.from_bytes(I[:32], "big") + int.from_bytes(parent_key, "big")
    ) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    child_key = child_key_int.to_bytes(32, "big")
    child_chain = I[32:]

    return child_key, child_chain


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class STXConfig:
    """Configuration for Stacks wallet operations."""

    private_key: bytes  # 32-byte private key
    public_key: bytes  # 33-byte compressed public key
    stx_address: str  # c32check encoded address
    network: STXNetwork
    hiro_api_url: str
    dry_run_default: bool = True
    derivation_path: str = ""

    @classmethod
    def from_env(cls) -> STXConfig:
        """Build STXConfig from environment variables."""
        mnemonic = os.getenv("BTC_MNEMONIC")
        if not mnemonic:
            raise RuntimeError(
                "BTC_MNEMONIC is required for Stacks operations. "
                "Set it in your environment or .env file."
            )

        passphrase = os.getenv("BTC_MNEMONIC_PASSPHRASE", "")
        seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
        # Convert seed to bytes if needed
        seed_bytes = bytes(seed) if not isinstance(seed, bytes) else seed

        account_index = int(os.getenv("STX_ACCOUNT_INDEX", "0"))
        private_key, public_key = _derive_stx_key_from_seed(seed_bytes, account_index)

        # Determine network
        raw_network = os.getenv("BTC_NETWORK", "testnet").lower()
        network: STXNetwork = "mainnet" if raw_network == "mainnet" else "testnet"

        # Derive address
        hash160_bytes = _hash160(public_key)
        if network == "mainnet":
            version = ADDRESS_VERSION_MAINNET_SINGLE_SIG
            hiro_url = os.getenv("STX_API_URL", HIRO_MAINNET)
        else:
            version = ADDRESS_VERSION_TESTNET_SINGLE_SIG
            hiro_url = os.getenv("STX_API_URL", HIRO_TESTNET)

        stx_address = c32_address(version, hash160_bytes)
        derivation_path = f"{STX_DERIVATION_PATH}/{account_index}"

        dry_run_env = os.getenv("BTC_DRY_RUN", "true").lower()
        dry_run_default = dry_run_env not in ("false", "0", "no", "off")

        return cls(
            private_key=private_key,
            public_key=public_key,
            stx_address=stx_address,
            network=network,
            hiro_api_url=hiro_url,
            dry_run_default=dry_run_default,
            derivation_path=derivation_path,
        )


# ---------------------------------------------------------------------------
# Hiro API helpers
# ---------------------------------------------------------------------------


def _hiro_get(cfg: STXConfig, path: str, params: dict | None = None) -> Any:
    """GET request to Hiro Stacks API."""
    url = f"{cfg.hiro_api_url}{path}"
    resp = requests.get(url, params=params, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _hiro_post(cfg: STXConfig, path: str, data: Any = None, raw: bool = False) -> Any:
    """POST request to Hiro Stacks API."""
    url = f"{cfg.hiro_api_url}{path}"
    if raw:
        resp = requests.post(
            url,
            data=data,
            headers={"Content-Type": "application/octet-stream"},
            timeout=10,
        )
    else:
        resp = requests.post(url, json=data, timeout=10)
    resp.raise_for_status()
    return resp.json() if not raw else resp.text


# ---------------------------------------------------------------------------
# 2.1 Address & Account Management
# ---------------------------------------------------------------------------


def stx_get_addresses(cfg: STXConfig) -> list[dict[str, str]]:
    """Return Stacks addresses with public keys and derivation paths."""
    return [
        {
            "symbol": "STX",
            "address": cfg.stx_address,
            "publicKey": cfg.public_key.hex(),
            "derivationPath": cfg.derivation_path,
        }
    ]


def stx_get_accounts(cfg: STXConfig) -> list[dict[str, Any]]:
    """Get Stacks accounts with balances and nonces."""
    try:
        data = _hiro_get(cfg, f"/v2/accounts/{cfg.stx_address}")
        balance_raw = (
            int(data.get("balance", "0x0"), 16)
            if isinstance(data.get("balance"), str)
            else int(data.get("balance", 0))
        )
        locked_raw = (
            int(data.get("locked", "0x0"), 16)
            if isinstance(data.get("locked"), str)
            else int(data.get("locked", 0))
        )
        nonce = int(data.get("nonce", 0))
    except Exception:
        balance_raw = 0
        locked_raw = 0
        nonce = 0

    balance_stx = Decimal(balance_raw) / Decimal("1000000")
    locked_stx = Decimal(locked_raw) / Decimal("1000000")

    return [
        {
            "address": cfg.stx_address,
            "balance_ustx": balance_raw,
            "balance_stx": str(balance_stx),
            "locked_ustx": locked_raw,
            "locked_stx": str(locked_stx),
            "nonce": nonce,
            "derivationPath": cfg.derivation_path,
            "publicKey": cfg.public_key.hex(),
        }
    ]


def stx_get_balance(cfg: STXConfig, address: str | None = None) -> dict[str, Any]:
    """Get STX balance and fungible/non-fungible token balances."""
    addr = address or cfg.stx_address
    try:
        data = _hiro_get(cfg, f"/extended/v1/address/{addr}/balances")
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch balance for {addr}: {exc}") from exc

    stx_data = data.get("stx", {})
    balance_ustx = int(stx_data.get("balance", 0))
    locked_ustx = int(stx_data.get("locked", 0))
    balance_stx = Decimal(balance_ustx) / Decimal("1000000")

    # Fungible tokens
    ft_data = data.get("fungible_tokens", {})
    fungible_tokens = []
    for token_id, token_info in ft_data.items():
        fungible_tokens.append(
            {
                "token_id": token_id,
                "balance": token_info.get("balance", "0"),
            }
        )

    # Non-fungible tokens
    nft_data = data.get("non_fungible_tokens", {})
    nfts = []
    for token_id, token_info in nft_data.items():
        nfts.append(
            {
                "token_id": token_id,
                "count": token_info.get("count", 0),
            }
        )

    return {
        "address": addr,
        "balance_ustx": balance_ustx,
        "balance_stx": str(balance_stx),
        "locked_ustx": locked_ustx,
        "fungible_tokens": fungible_tokens,
        "non_fungible_tokens": nfts,
    }


def stx_get_networks(cfg: STXConfig) -> dict[str, Any]:
    """List available Stacks networks."""
    networks = [
        {
            "id": "mainnet",
            "name": "Stacks Mainnet",
            "chainId": hex(CHAIN_ID_MAINNET),
            "transactionVersion": hex(TX_VERSION_MAINNET),
            "apiUrl": HIRO_MAINNET,
        },
        {
            "id": "testnet",
            "name": "Stacks Testnet",
            "chainId": hex(CHAIN_ID_TESTNET),
            "transactionVersion": hex(TX_VERSION_TESTNET),
            "apiUrl": HIRO_TESTNET,
        },
    ]
    return {
        "active": cfg.network,
        "networks": networks,
    }


# ---------------------------------------------------------------------------
# 2.2 STX Transfers
# ---------------------------------------------------------------------------


def stx_get_nonce(cfg: STXConfig, address: str | None = None) -> int:
    """Get the current nonce for an address."""
    addr = address or cfg.stx_address
    try:
        data = _hiro_get(cfg, f"/v2/accounts/{addr}")
        return int(data.get("nonce", 0))
    except Exception:
        return 0


def stx_estimate_fee(cfg: STXConfig, tx_bytes_len: int = 180) -> int:
    """
    Estimate Stacks transaction fee in micro-STX.

    Uses the Hiro fee estimation endpoint.
    """
    try:
        # Hiro v2 fee estimation
        data = _hiro_get(cfg, "/v2/fees/transfer")
        # Returns a list of fee estimates; use the middle one
        if isinstance(data, list) and len(data) > 0:
            return int(data[0].get("fee", 200))
        if isinstance(data, dict):
            return int(data.get("estimated_cost", {}).get("write_length", 200))
        return 200  # fallback: 200 micro-STX
    except Exception:
        return 200


def stx_preview_transfer(
    cfg: STXConfig,
    recipient: str,
    amount_ustx: int,
    memo: str = "",
) -> dict[str, Any]:
    """Preview an STX transfer with fee estimation."""
    balance_data = stx_get_balance(cfg)
    balance_ustx = balance_data["balance_ustx"]
    fee_ustx = stx_estimate_fee(cfg)
    nonce = stx_get_nonce(cfg)

    total_ustx = amount_ustx + fee_ustx
    sufficient = balance_ustx >= total_ustx

    return {
        "from_address": cfg.stx_address,
        "recipient": recipient,
        "amount_ustx": amount_ustx,
        "amount_stx": str(Decimal(amount_ustx) / Decimal("1000000")),
        "fee_ustx": fee_ustx,
        "fee_stx": str(Decimal(fee_ustx) / Decimal("1000000")),
        "total_ustx": total_ustx,
        "total_stx": str(Decimal(total_ustx) / Decimal("1000000")),
        "balance_ustx": balance_ustx,
        "balance_stx": str(Decimal(balance_ustx) / Decimal("1000000")),
        "nonce": nonce,
        "sufficient_balance": sufficient,
        "memo": memo,
        "network": cfg.network,
    }


def _serialize_lp_string(s: str) -> bytes:
    """Serialize a length-prefixed string (1-byte length + UTF-8 bytes)."""
    encoded = s.encode("utf-8")
    if len(encoded) > 34:
        encoded = encoded[:34]
    return struct.pack("B", len(encoded)) + encoded


def _build_stx_transfer_payload(
    recipient_address: str,
    amount_ustx: int,
    memo: str = "",
) -> bytes:
    """Build the payload for an STX token transfer."""
    payload = struct.pack("B", PAYLOAD_TOKEN_TRANSFER)

    # Recipient: Stacks principal (standard)
    # Type: 0x05 = standard principal
    payload += b"\x05"
    # Parse c32 address to get version and hash160
    version, hash160_bytes = _decode_c32_address(recipient_address)
    payload += struct.pack("B", version)
    payload += hash160_bytes

    # Amount: 8 bytes big-endian
    payload += struct.pack(">Q", amount_ustx)

    # Memo: 34 bytes (1-byte type + content padded to 34 bytes)
    if memo:
        payload += b"\x01"  # memo type: CodeBody
        memo_bytes = memo.encode("utf-8")[:34]
        payload += memo_bytes.ljust(34, b"\x00")
    else:
        payload += b"\x03"  # memo type: empty
        payload += b"\x00" * 34

    return payload


def _decode_c32_address(address: str) -> tuple[int, bytes]:
    """Decode a c32check address into version byte and hash160 bytes."""
    if not address or len(address) < 5 or address[0] != "S":
        raise ValueError(f"Invalid Stacks address: {address}")

    version_char = address[1]
    version = C32_ALPHABET.index(version_char.upper())
    c32_data = address[2:]

    # Decode c32 string to bytes
    decoded = _c32_decode(c32_data)

    # Last 4 bytes are checksum
    if len(decoded) < 4:
        raise ValueError(f"Invalid Stacks address (too short): {address}")

    hash160_bytes = decoded[:-4]
    checksum = decoded[-4:]

    # Verify checksum
    expected_checksum = _c32_checksum(version, hash160_bytes)
    if checksum != expected_checksum:
        raise ValueError(f"Invalid Stacks address checksum: {address}")

    # hash160 should be 20 bytes
    if len(hash160_bytes) < 20:
        hash160_bytes = b"\x00" * (20 - len(hash160_bytes)) + hash160_bytes
    elif len(hash160_bytes) > 20:
        hash160_bytes = hash160_bytes[-20:]

    return version, hash160_bytes


def _c32_decode(c32_str: str) -> bytes:
    """Decode a c32 string to bytes."""
    c32_str = c32_str.upper()
    # Count leading zeros
    leading_zeros = 0
    for ch in c32_str:
        if ch == C32_ALPHABET[0]:
            leading_zeros += 1
        else:
            break

    num = 0
    for ch in c32_str:
        idx = C32_ALPHABET.index(ch)
        num = num * 32 + idx

    if num == 0:
        return b"\x00" * max(leading_zeros, 1)

    result = []
    while num > 0:
        result.append(num & 0xFF)
        num >>= 8
    result.reverse()

    return b"\x00" * leading_zeros + bytes(result)


def _build_authorization(
    cfg: STXConfig,
    fee: int,
    nonce: int,
) -> tuple[bytes, int]:
    """
    Build a standard single-sig authorization for a Stacks transaction.

    Returns (auth_bytes, offset_of_signature_placeholder).
    """
    auth = struct.pack("B", AUTH_STANDARD)
    # Spending condition: single-sig P2PKH
    auth += struct.pack("B", SPENDING_CONDITION_SINGLESIG_P2PKH)
    # Signer (hash160 of public key)
    signer_hash = _hash160(cfg.public_key)
    auth += signer_hash
    # Nonce (8 bytes big-endian)
    auth += struct.pack(">Q", nonce)
    # Fee (8 bytes big-endian)
    auth += struct.pack(">Q", fee)

    sig_offset = len(auth)
    # Key encoding: compressed = 0x00
    auth += struct.pack("B", 0x00)
    # Signature placeholder: 65 bytes of zeros (recoverable ECDSA)
    auth += b"\x00" * 65

    return auth, sig_offset


def _build_stx_transaction(
    cfg: STXConfig,
    payload: bytes,
    fee: int,
    nonce: int,
) -> bytes:
    """Build a complete unsigned Stacks transaction."""
    tx_version = TX_VERSION_MAINNET if cfg.network == "mainnet" else TX_VERSION_TESTNET
    chain_id = CHAIN_ID_MAINNET if cfg.network == "mainnet" else CHAIN_ID_TESTNET

    # Version
    tx = struct.pack("B", tx_version)
    # Chain ID
    tx += struct.pack(">I", chain_id)
    # Authorization
    auth, sig_offset = _build_authorization(cfg, fee, nonce)
    auth_start = len(tx)
    tx += auth
    # Anchor mode
    tx += struct.pack("B", ANCHOR_MODE_ANY)
    # Post-condition mode
    tx += struct.pack("B", POST_CONDITION_MODE_ALLOW)
    # Post-conditions length: 0
    tx += struct.pack(">I", 0)
    # Payload
    tx += payload

    return tx, auth_start + sig_offset


def _sign_stx_transaction(cfg: STXConfig, tx_bytes: bytes, sig_offset: int) -> bytes:
    """
    Sign a Stacks transaction.

    Computes Stacks-specific sighash and produces a recoverable ECDSA signature.
    """
    # The initial sighash is the transaction with empty signature
    # Then apply presign-sighash (just the tx hash for single-sig)
    tx_hash = hashlib.sha512_256(tx_bytes).digest()

    # Stacks uses secp256k1 recoverable signatures
    privkey = coincurve.PrivateKey(cfg.private_key)
    sig = privkey.sign_recoverable(tx_hash, hasher=None)
    # coincurve returns 65 bytes: [r(32) || s(32) || recovery_id(1)]
    # Stacks format: [recovery_id(1) || r(32) || s(32)]
    recovery_id = sig[64]
    stacks_sig = bytes([recovery_id]) + sig[:64]

    # Insert signature into transaction
    signed_tx = bytearray(tx_bytes)
    # Skip key_encoding byte (+1), then write 65-byte signature
    signed_tx[sig_offset + 1 : sig_offset + 1 + 65] = stacks_sig

    return bytes(signed_tx)


def stx_transfer_stx(
    cfg: STXConfig,
    recipient: str,
    amount_ustx: int,
    memo: str = "",
    fee: int | None = None,
    nonce: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Transfer STX to a recipient.

    Matches Leather stx_transferStx / Xverse stx_transferStx.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    if amount_ustx <= 0:
        raise ValueError("Amount must be greater than zero.")

    if nonce is None:
        nonce = stx_get_nonce(cfg)
    if fee is None:
        fee = stx_estimate_fee(cfg)

    # Build payload
    payload = _build_stx_transfer_payload(recipient, amount_ustx, memo)

    # Build transaction
    tx_bytes, sig_offset = _build_stx_transaction(cfg, payload, fee, nonce)

    # Sign
    signed_tx = _sign_stx_transaction(cfg, tx_bytes, sig_offset)
    tx_hex = signed_tx.hex()

    if dry_run:
        tx_hash = hashlib.sha256(signed_tx).hexdigest()
        return {
            "txid": f"DRYRUN_{tx_hash[:64]}",
            "tx_hex": tx_hex,
            "dry_run": True,
            "from_address": cfg.stx_address,
            "recipient": recipient,
            "amount_ustx": amount_ustx,
            "amount_stx": str(Decimal(amount_ustx) / Decimal("1000000")),
            "fee_ustx": fee,
            "nonce": nonce,
            "network": cfg.network,
        }

    # Broadcast
    txid = _broadcast_stx_tx(cfg, tx_hex)
    return {
        "txid": txid,
        "tx_hex": tx_hex,
        "dry_run": False,
        "from_address": cfg.stx_address,
        "recipient": recipient,
        "amount_ustx": amount_ustx,
        "amount_stx": str(Decimal(amount_ustx) / Decimal("1000000")),
        "fee_ustx": fee,
        "nonce": nonce,
        "network": cfg.network,
    }


def stx_transfer_sip10_ft(
    cfg: STXConfig,
    recipient: str,
    asset: str,
    amount: int,
    fee: int | None = None,
    nonce: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Transfer a SIP-10 fungible token.

    asset: fully qualified contract identifier, e.g. 'SP...::token-name'
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    # Parse asset identifier: "contract_address.contract_name::function_name"
    # SIP-10 transfer function is always 'transfer'
    parts = asset.split("::")
    if len(parts) != 2:
        raise ValueError(
            "Asset must be in format 'contract_address.contract_name::token_name'"
        )

    contract_id = parts[0]  # SP...xxx.contract-name
    token_name = parts[1]

    contract_parts = contract_id.split(".")
    if len(contract_parts) != 2:
        raise ValueError("Contract ID must be in format 'address.contract-name'")

    contract_address = contract_parts[0]
    contract_name = contract_parts[1]

    # Build a contract call to the 'transfer' function
    # SIP-10 transfer signature: (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))
    result = stx_call_contract(
        cfg,
        contract_address=contract_address,
        contract_name=contract_name,
        function_name="transfer",
        function_args=[
            f"u{amount}",
            f"'{cfg.stx_address}",
            f"'{recipient}",
            "none",
        ],
        fee=fee,
        nonce=nonce,
        dry_run=dry_run,
    )
    result["asset"] = asset
    result["token_name"] = token_name
    result["transfer_amount"] = amount
    return result


def stx_transfer_sip9_nft(
    cfg: STXConfig,
    recipient: str,
    asset: str,
    asset_id: str,
    fee: int | None = None,
    nonce: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Transfer a SIP-9 NFT.

    asset: fully qualified contract identifier
    asset_id: the NFT identifier (uint)
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    parts = asset.split("::")
    if len(parts) != 2:
        raise ValueError(
            "Asset must be in format 'contract_address.contract_name::nft_name'"
        )

    contract_id = parts[0]
    nft_name = parts[1]

    contract_parts = contract_id.split(".")
    if len(contract_parts) != 2:
        raise ValueError("Contract ID must be in format 'address.contract-name'")

    contract_address = contract_parts[0]
    contract_name = contract_parts[1]

    # SIP-9 transfer signature: (transfer (token-id uint) (sender principal) (recipient principal))
    result = stx_call_contract(
        cfg,
        contract_address=contract_address,
        contract_name=contract_name,
        function_name="transfer",
        function_args=[
            f"u{asset_id}",
            f"'{cfg.stx_address}",
            f"'{recipient}",
        ],
        fee=fee,
        nonce=nonce,
        dry_run=dry_run,
    )
    result["asset"] = asset
    result["nft_name"] = nft_name
    result["asset_id"] = asset_id
    return result


# ---------------------------------------------------------------------------
# 2.3 Smart Contract Interaction
# ---------------------------------------------------------------------------


def _serialize_clarity_value(val_str: str) -> bytes:
    """
    Serialize a Clarity value from string representation.

    Supported:
    - uNNN -> uint
    - iNNN -> int
    - 'SPADDR... -> principal
    - true/false -> bool
    - none -> none
    - 0x... -> buffer
    - "text" -> string-ascii
    """
    val_str = val_str.strip()

    # uint
    if val_str.startswith("u") and val_str[1:].isdigit():
        return b"\x01" + struct.pack(
            ">QQ", 0, int(val_str[1:])
        )  # 128-bit uint as two u64

    # int
    if val_str.startswith("i") and (
        val_str[1:].isdigit() or (val_str[1] == "-" and val_str[2:].isdigit())
    ):
        v = int(val_str[1:])
        if v < 0:
            v = (1 << 128) + v
        return b"\x00" + struct.pack(">QQ", v >> 64, v & ((1 << 64) - 1))

    # bool
    if val_str == "true":
        return b"\x03"
    if val_str == "false":
        return b"\x04"

    # none
    if val_str == "none":
        return b"\x09"

    # principal (standard)
    if val_str.startswith("'") and val_str[1] == "S":
        addr = val_str[1:]
        version, hash160 = _decode_c32_address(addr)
        return b"\x05" + struct.pack("B", version) + hash160

    # buffer
    if val_str.startswith("0x"):
        buf = bytes.fromhex(val_str[2:])
        return b"\x02" + struct.pack(">I", len(buf)) + buf

    # string-ascii
    if val_str.startswith('"') and val_str.endswith('"'):
        s = val_str[1:-1].encode("ascii")
        return b"\x0d" + struct.pack(">I", len(s)) + s

    # Default: treat as string-utf8
    s = val_str.encode("utf-8")
    return b"\x0e" + struct.pack(">I", len(s)) + s


def _build_contract_call_payload(
    contract_address: str,
    contract_name: str,
    function_name: str,
    function_args: list[str],
) -> bytes:
    """Build payload for a contract call."""
    payload = struct.pack("B", PAYLOAD_CONTRACT_CALL)

    # Contract address (principal)
    version, hash160 = _decode_c32_address(contract_address)
    payload += struct.pack("B", version)
    payload += hash160

    # Contract name (clarity name: 1-byte len + string)
    cn = contract_name.encode("ascii")
    payload += struct.pack("B", len(cn))
    payload += cn

    # Function name
    fn = function_name.encode("ascii")
    payload += struct.pack("B", len(fn))
    payload += fn

    # Function args
    payload += struct.pack(">I", len(function_args))
    for arg_str in function_args:
        payload += _serialize_clarity_value(arg_str)

    return payload


def stx_call_contract(
    cfg: STXConfig,
    contract_address: str,
    contract_name: str,
    function_name: str,
    function_args: list[str] | None = None,
    fee: int | None = None,
    nonce: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Call a public Clarity smart contract function.

    function_args: list of Clarity value strings (e.g., ["u100", "'SP...", "true"])
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default
    if function_args is None:
        function_args = []

    if nonce is None:
        nonce = stx_get_nonce(cfg)
    if fee is None:
        fee = stx_estimate_fee(cfg)

    payload = _build_contract_call_payload(
        contract_address, contract_name, function_name, function_args
    )

    tx_bytes, sig_offset = _build_stx_transaction(cfg, payload, fee, nonce)
    signed_tx = _sign_stx_transaction(cfg, tx_bytes, sig_offset)
    tx_hex = signed_tx.hex()

    base_result = {
        "from_address": cfg.stx_address,
        "contract": f"{contract_address}.{contract_name}",
        "function_name": function_name,
        "function_args": function_args,
        "fee_ustx": fee,
        "nonce": nonce,
        "network": cfg.network,
    }

    if dry_run:
        tx_hash = hashlib.sha256(signed_tx).hexdigest()
        return {
            **base_result,
            "txid": f"DRYRUN_{tx_hash[:64]}",
            "tx_hex": tx_hex,
            "dry_run": True,
        }

    txid = _broadcast_stx_tx(cfg, tx_hex)
    return {
        **base_result,
        "txid": txid,
        "tx_hex": tx_hex,
        "dry_run": False,
    }


def _build_smart_contract_payload(
    contract_name: str,
    clarity_code: str,
    clarity_version: int = 2,
) -> bytes:
    """Build payload for smart contract deployment."""
    payload = struct.pack("B", PAYLOAD_SMART_CONTRACT)

    # Contract name
    cn = contract_name.encode("ascii")
    payload += struct.pack("B", len(cn))
    payload += cn

    # Code body (4-byte length + UTF-8)
    code_bytes = clarity_code.encode("utf-8")
    payload += struct.pack(">I", len(code_bytes))
    payload += code_bytes

    return payload


def stx_deploy_contract(
    cfg: STXConfig,
    contract_name: str,
    clarity_code: str,
    clarity_version: int = 2,
    fee: int | None = None,
    nonce: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """Deploy a Clarity smart contract."""
    if dry_run is None:
        dry_run = cfg.dry_run_default

    if nonce is None:
        nonce = stx_get_nonce(cfg)
    if fee is None:
        fee = stx_estimate_fee(cfg)

    payload = _build_smart_contract_payload(
        contract_name, clarity_code, clarity_version
    )
    tx_bytes, sig_offset = _build_stx_transaction(cfg, payload, fee, nonce)
    signed_tx = _sign_stx_transaction(cfg, tx_bytes, sig_offset)
    tx_hex = signed_tx.hex()

    base_result = {
        "from_address": cfg.stx_address,
        "contract_name": contract_name,
        "contract_id": f"{cfg.stx_address}.{contract_name}",
        "code_length": len(clarity_code),
        "fee_ustx": fee,
        "nonce": nonce,
        "network": cfg.network,
    }

    if dry_run:
        tx_hash = hashlib.sha256(signed_tx).hexdigest()
        return {
            **base_result,
            "txid": f"DRYRUN_{tx_hash[:64]}",
            "tx_hex": tx_hex,
            "dry_run": True,
        }

    txid = _broadcast_stx_tx(cfg, tx_hex)
    return {**base_result, "txid": txid, "tx_hex": tx_hex, "dry_run": False}


def stx_read_contract(
    cfg: STXConfig,
    contract_address: str,
    contract_name: str,
    function_name: str,
    function_args: list[str] | None = None,
    sender: str | None = None,
) -> dict[str, Any]:
    """
    Read-only call to a Clarity contract function (no transaction needed).

    Uses the Hiro API /v2/contracts/call-read endpoint.
    """
    if function_args is None:
        function_args = []

    # Serialize arguments to hex for the API
    serialized_args = []
    for arg_str in function_args:
        serialized_args.append(_serialize_clarity_value(arg_str).hex())

    sender_addr = sender or cfg.stx_address

    try:
        data = _hiro_post(
            cfg,
            f"/v2/contracts/call-read/{contract_address}/{contract_name}/{function_name}",
            data={
                "sender": sender_addr,
                "arguments": serialized_args,
            },
        )
    except Exception as exc:
        raise RuntimeError(
            f"Read-only call failed: {contract_address}.{contract_name}::{function_name}: {exc}"
        ) from exc

    return {
        "contract": f"{contract_address}.{contract_name}",
        "function_name": function_name,
        "result": data.get("result"),
        "okay": data.get("okay", False),
        "cause": data.get("cause"),
    }


# ---------------------------------------------------------------------------
# 2.4 Transaction Signing
# ---------------------------------------------------------------------------


def stx_sign_transaction(
    cfg: STXConfig,
    tx_hex: str,
) -> dict[str, str]:
    """
    Sign a serialized Stacks transaction (SIP-30 compatible).

    Takes a hex-encoded unsigned transaction, signs it, and returns
    the signed transaction hex.
    """
    tx_bytes = bytes.fromhex(tx_hex)

    # The signature placeholder is at a fixed offset in the authorization
    # For standard single-sig: version(1) + chain_id(4) + auth_type(1) + hash_mode(1) + signer(20) + nonce(8) + fee(8) + key_encoding(1)
    # = 1 + 4 + 1 + 1 + 20 + 8 + 8 + 1 = 44
    sig_offset = 44  # offset to key_encoding byte (signature starts at +1)

    signed_tx = _sign_stx_transaction(cfg, tx_bytes, sig_offset)

    return {
        "transaction": signed_tx.hex(),
        "txHex": signed_tx.hex(),
    }


def stx_sign_transactions(
    cfg: STXConfig,
    tx_hexes: list[str],
) -> list[dict[str, str]]:
    """Sign multiple Stacks transactions in batch."""
    results = []
    for tx_hex in tx_hexes:
        result = stx_sign_transaction(cfg, tx_hex)
        results.append(result)
    return results


# ---------------------------------------------------------------------------
# 2.5 Message Signing
# ---------------------------------------------------------------------------


def _stx_message_hash(message: str) -> bytes:
    """
    Compute the Stacks message hash for signing.

    Prefix: "\\x17Stacks Signed Message:\\n" + length + message
    Then SHA256.
    """
    prefix = b"\x17Stacks Signed Message:\n"
    msg_bytes = message.encode("utf-8")
    length_bytes = str(len(msg_bytes)).encode("ascii")
    full = prefix + length_bytes + msg_bytes
    return hashlib.sha256(full).digest()


def stx_sign_message(
    cfg: STXConfig,
    message: str,
) -> dict[str, str]:
    """
    Sign a UTF-8 message on Stacks.

    Returns signature and public key.
    """
    msg_hash = _stx_message_hash(message)

    privkey = coincurve.PrivateKey(cfg.private_key)
    sig = privkey.sign_recoverable(msg_hash, hasher=None)
    # Convert to Stacks format: [recovery_id(1) || r(32) || s(32)]
    recovery_id = sig[64]
    stacks_sig = bytes([recovery_id]) + sig[:64]

    return {
        "signature": stacks_sig.hex(),
        "publicKey": cfg.public_key.hex(),
        "message": message,
    }


def _stx_structured_message_hash(domain: str, message: str) -> bytes:
    """
    Compute hash for SIP-018 structured data signing.

    Hash: SHA256(0x534950303138 || domain_hash || message_hash)
    """
    prefix = bytes.fromhex("534950303138")  # "SIP018" in hex
    domain_hash = hashlib.sha256(domain.encode("utf-8")).digest()
    message_hash = hashlib.sha256(message.encode("utf-8")).digest()
    return hashlib.sha256(prefix + domain_hash + message_hash).digest()


def stx_sign_structured_message(
    cfg: STXConfig,
    domain: str,
    message: str,
) -> dict[str, str]:
    """
    Sign SIP-018 structured data.

    Returns signature and public key.
    """
    msg_hash = _stx_structured_message_hash(domain, message)

    privkey = coincurve.PrivateKey(cfg.private_key)
    sig = privkey.sign_recoverable(msg_hash, hasher=None)
    recovery_id = sig[64]
    stacks_sig = bytes([recovery_id]) + sig[:64]

    return {
        "signature": stacks_sig.hex(),
        "publicKey": cfg.public_key.hex(),
        "domain": domain,
        "message": message,
    }


# ---------------------------------------------------------------------------
# 2.6 Utilities
# ---------------------------------------------------------------------------


def stx_update_profile(
    cfg: STXConfig,
    person: dict[str, Any],
    fee: int | None = None,
    nonce: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Update an on-chain profile (schema.org/Person).

    This is a contract call to the BNS or profile contract.
    For now, returns the profile data that would be submitted.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    # Profile updates are typically done via Gaia storage + zone file updates
    # For the MCP tool, we provide the mechanism but note it requires BNS name ownership
    return {
        "from_address": cfg.stx_address,
        "person": person,
        "dry_run": dry_run,
        "network": cfg.network,
        "note": "Profile update requires a registered BNS name. "
        "Use stx_call_contract with the BNS contract for zone file updates.",
    }


# ---------------------------------------------------------------------------
# Broadcasting
# ---------------------------------------------------------------------------


def _broadcast_stx_tx(cfg: STXConfig, tx_hex: str) -> str:
    """Broadcast a signed Stacks transaction via Hiro API."""
    url = f"{cfg.hiro_api_url}/v2/transactions"
    tx_bytes = bytes.fromhex(tx_hex)
    resp = requests.post(
        url,
        data=tx_bytes,
        headers={"Content-Type": "application/octet-stream"},
        timeout=10,
    )
    if not resp.ok:
        try:
            err = resp.json()
            error_msg = err.get("error", err.get("reason", resp.text))
        except Exception:
            error_msg = resp.text or f"HTTP {resp.status_code}"
        raise RuntimeError(f"Stacks transaction broadcast failed: {error_msg}")

    data = resp.json()
    if isinstance(data, str):
        return data.strip().strip('"')
    return data.get("txid", data.get("tx_id", str(data)))
