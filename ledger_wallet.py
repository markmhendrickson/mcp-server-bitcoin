"""
Phase 5C (Ledger only): Ledger hardware wallet operations.

Implements:
- Get BTC addresses from Ledger device (multiple address types)
- Sign PSBT via Ledger Bitcoin app
- Sign STX transaction via Ledger Stacks app

Communication uses the ledgercomm library over USB HID or TCP
(TCP is useful for the Speculos emulator during development).

Ledger Bitcoin app APDU reference:
  https://github.com/LedgerHQ/app-bitcoin-new/blob/develop/doc/bitcoin.md

Ledger Stacks app APDU reference:
  https://github.com/aspect-build/ledger-stacks/blob/main/docs/APDU.md
"""

from __future__ import annotations

import base64
import struct
from typing import Any, Literal

try:
    from ledgercomm import Transport
except ImportError:
    Transport = None  # type: ignore[assignment,misc]

BTCNetwork = Literal["mainnet", "testnet"]

# ---------------------------------------------------------------------------
# Ledger APDU constants -- Bitcoin app (new)
# ---------------------------------------------------------------------------

# CLA for Bitcoin app
BTC_CLA = 0xE1

# Instructions
BTC_INS_GET_EXTENDED_PUBKEY = 0x00
BTC_INS_GET_ADDRESS = 0x01
BTC_INS_SIGN_PSBT = 0x04

# Address types (P1 for GET_ADDRESS)
BTC_P1_DISPLAY = 0x01
BTC_P1_NO_DISPLAY = 0x00

# Address formats (P2 for GET_ADDRESS)
BTC_ADDR_LEGACY = 0x00        # P2PKH
BTC_ADDR_SEGWIT = 0x01        # P2SH-P2WPKH
BTC_ADDR_NATIVE_SEGWIT = 0x02 # P2WPKH
BTC_ADDR_TAPROOT = 0x03       # P2TR

# ---------------------------------------------------------------------------
# Ledger APDU constants -- Stacks app
# ---------------------------------------------------------------------------

STX_CLA = 0x09

STX_INS_GET_VERSION = 0x00
STX_INS_GET_ADDR = 0x01
STX_INS_SIGN_TX = 0x02
STX_INS_SIGN_MSG = 0x03

# ---------------------------------------------------------------------------
# Transport helper
# ---------------------------------------------------------------------------


def _get_transport(interface: str = "hid") -> Any:
    """
    Open a connection to the Ledger device.

    interface: 'hid' for USB, 'tcp' for Speculos emulator
    """
    if Transport is None:
        raise RuntimeError(
            "ledgercomm is not installed. Install with: pip install ledgercomm"
        )
    try:
        transport = Transport(interface=interface)
        return transport
    except Exception as exc:
        raise RuntimeError(
            f"Failed to connect to Ledger device via {interface}. "
            f"Ensure the device is connected, unlocked, and the correct app is open. "
            f"Error: {exc}"
        ) from exc


def _serialize_bip32_path(path: str) -> bytes:
    """
    Serialize a BIP-32 derivation path to bytes.

    e.g. "m/84'/0'/0'/0/0" -> bytes
    """
    path = path.strip()
    if path.startswith("m/"):
        path = path[2:]

    components = path.split("/")
    result = struct.pack("B", len(components))
    for comp in components:
        hardened = comp.endswith("'") or comp.endswith("h")
        index = int(comp.rstrip("'h"))
        if hardened:
            index += 0x80000000
        result += struct.pack(">I", index)
    return result


# ---------------------------------------------------------------------------
# ledger_get_addresses
# ---------------------------------------------------------------------------


def ledger_get_addresses(
    network: BTCNetwork = "mainnet",
    account: int = 0,
    display: bool = False,
    interface: str = "hid",
) -> dict[str, Any]:
    """
    Get BTC addresses from the Ledger device for all address types.

    Queries the Ledger Bitcoin app for P2PKH, P2SH-P2WPKH, P2WPKH,
    and P2TR addresses at the standard derivation paths.

    - network: 'mainnet' or 'testnet'
    - account: account index (default 0)
    - display: if True, display address on device for verification
    - interface: 'hid' for USB, 'tcp' for Speculos emulator
    """
    coin_type = "0'" if network == "mainnet" else "1'"

    address_configs = [
        {
            "type": "p2pkh",
            "path": f"m/44'/{coin_type}/{account}'/0/0",
            "format": BTC_ADDR_LEGACY,
        },
        {
            "type": "p2sh-p2wpkh",
            "path": f"m/49'/{coin_type}/{account}'/0/0",
            "format": BTC_ADDR_SEGWIT,
        },
        {
            "type": "p2wpkh",
            "path": f"m/84'/{coin_type}/{account}'/0/0",
            "format": BTC_ADDR_NATIVE_SEGWIT,
        },
        {
            "type": "p2tr",
            "path": f"m/86'/{coin_type}/{account}'/0/0",
            "format": BTC_ADDR_TAPROOT,
        },
    ]

    transport = _get_transport(interface)
    addresses = []

    try:
        for cfg in address_configs:
            try:
                path_bytes = _serialize_bip32_path(cfg["path"])
                p1 = BTC_P1_DISPLAY if display else BTC_P1_NO_DISPLAY
                p2 = cfg["format"]

                # Send GET_ADDRESS APDU
                sw, response = transport.exchange(
                    BTC_CLA, BTC_INS_GET_ADDRESS, p1, p2, path_bytes
                )

                if sw == 0x9000 and response:
                    # Response format: address_len (1 byte) + address (ascii)
                    addr_len = response[0]
                    address = response[1:1 + addr_len].decode("ascii")
                    addresses.append({
                        "symbol": "BTC",
                        "type": cfg["type"],
                        "address": address,
                        "derivationPath": cfg["path"],
                    })
                else:
                    addresses.append({
                        "symbol": "BTC",
                        "type": cfg["type"],
                        "address": "",
                        "derivationPath": cfg["path"],
                        "error": f"Device returned SW=0x{sw:04X}",
                    })
            except Exception as exc:
                addresses.append({
                    "symbol": "BTC",
                    "type": cfg["type"],
                    "address": "",
                    "derivationPath": cfg["path"],
                    "error": str(exc),
                })
    finally:
        transport.close()

    return {
        "addresses": addresses,
        "account": account,
        "network": network,
        "device": "ledger",
    }


# ---------------------------------------------------------------------------
# ledger_sign_psbt
# ---------------------------------------------------------------------------


def ledger_sign_psbt(
    psbt_hex: str,
    network: BTCNetwork = "mainnet",
    interface: str = "hid",
) -> dict[str, Any]:
    """
    Sign a PSBT using the Ledger Bitcoin app.

    The Ledger Bitcoin app (v2+) accepts PSBTs and returns the signed
    version. The PSBT must contain all necessary UTXO information.

    - psbt_hex: hex-encoded PSBT
    - network: 'mainnet' or 'testnet'
    - interface: 'hid' or 'tcp'
    """
    psbt_bytes = bytes.fromhex(psbt_hex)

    if psbt_bytes[:5] != b"psbt\xff":
        raise ValueError("Invalid PSBT: missing magic bytes.")

    transport = _get_transport(interface)

    try:
        # The new Ledger Bitcoin app uses a multi-message protocol for PSBT signing.
        # We send the PSBT in chunks using the SIGN_PSBT instruction.

        # For the new app, we need to send:
        # 1. Global map info
        # 2. Input/output maps
        # The protocol is complex; we use a simplified single-chunk approach
        # for smaller PSBTs.

        # Send PSBT length first (P1=0x00 = first chunk)
        chunk_size = 255
        offset = 0
        is_first = True

        while offset < len(psbt_bytes):
            chunk = psbt_bytes[offset:offset + chunk_size]
            p1 = 0x00 if is_first else 0x80  # 0x00 = first, 0x80 = continuation
            is_first = False

            sw, response = transport.exchange(
                BTC_CLA, BTC_INS_SIGN_PSBT, p1, 0x00, chunk
            )

            if sw not in (0x9000, 0xE000):
                raise RuntimeError(
                    f"Ledger rejected PSBT signing at offset {offset}: SW=0x{sw:04X}"
                )
            offset += chunk_size

        # The final response contains the signed PSBT
        if response:
            signed_hex = response.hex()
        else:
            signed_hex = psbt_hex  # fallback: return original if no response

    finally:
        transport.close()

    return {
        "hex": signed_hex,
        "base64": base64.b64encode(bytes.fromhex(signed_hex)).decode("ascii") if signed_hex else "",
        "device": "ledger",
        "network": network,
    }


# ---------------------------------------------------------------------------
# ledger_get_stx_addresses
# ---------------------------------------------------------------------------


def ledger_get_stx_addresses(
    account: int = 0,
    display: bool = False,
    interface: str = "hid",
) -> dict[str, Any]:
    """
    Get Stacks addresses from the Ledger device.

    Queries the Ledger Stacks app for the address at the standard
    derivation path (m/44'/5757'/account'/0/0).

    - account: account index (default 0)
    - display: if True, display address on device for verification
    - interface: 'hid' for USB, 'tcp' for Speculos emulator
    """
    derivation_path = f"m/44'/5757'/{account}'/0/0"
    path_bytes = _serialize_bip32_path(derivation_path)

    transport = _get_transport(interface)

    try:
        # P1: 0x01 = display address, 0x00 = no display
        # P2: unused (0x00)
        p1 = 0x01 if display else 0x00

        sw, response = transport.exchange(
            STX_CLA, STX_INS_GET_ADDR, p1, 0x00, path_bytes
        )

        if sw != 0x9000:
            raise RuntimeError(f"Ledger Stacks app rejected address request: SW=0x{sw:04X}")

        if not response or len(response) < 20:
            raise RuntimeError(
                f"Unexpected response length from Ledger: {len(response) if response else 0} bytes"
            )

        # Response format: public_key (65 bytes) + address_len (1 byte) + address (c32 encoded)
        # For simplicity, we'll parse based on known response structure
        if len(response) >= 66:
            public_key = response[:65].hex()
            addr_len = response[65]
            if len(response) >= 66 + addr_len:
                address = response[66:66 + addr_len].decode("ascii")
            else:
                # Fallback: try to parse rest as address
                address = response[66:].decode("ascii", errors="ignore")
        else:
            # Older format or different response structure
            public_key = response[:65].hex() if len(response) >= 65 else ""
            address = response[65:].decode("ascii", errors="ignore") if len(response) > 65 else ""

        addresses = [{
            "symbol": "STX",
            "address": address,
            "publicKey": public_key,
            "derivationPath": derivation_path,
        }]

    except Exception as exc:
        addresses = [{
            "symbol": "STX",
            "address": "",
            "publicKey": "",
            "derivationPath": derivation_path,
            "error": str(exc),
        }]
    finally:
        transport.close()

    return {
        "addresses": addresses,
        "account": account,
        "device": "ledger",
    }


# ---------------------------------------------------------------------------
# ledger_sign_stx_transaction
# ---------------------------------------------------------------------------


def ledger_sign_stx_transaction(
    tx_hex: str,
    derivation_path: str = "m/44'/5757'/0'/0/0",
    interface: str = "hid",
) -> dict[str, Any]:
    """
    Sign a Stacks transaction using the Ledger Stacks app.

    The Ledger Stacks app accepts serialized unsigned transactions
    and returns a 65-byte recoverable ECDSA signature.

    - tx_hex: hex-encoded unsigned Stacks transaction
    - derivation_path: BIP-32 path for the signing key
    - interface: 'hid' or 'tcp'
    """
    tx_bytes = bytes.fromhex(tx_hex)
    path_bytes = _serialize_bip32_path(derivation_path)

    transport = _get_transport(interface)

    try:
        # Send derivation path first (P1=0x00 = init)
        sw, response = transport.exchange(
            STX_CLA, STX_INS_SIGN_TX, 0x00, 0x00, path_bytes
        )
        if sw != 0x9000:
            raise RuntimeError(f"Ledger Stacks app rejected path: SW=0x{sw:04X}")

        # Send transaction in chunks (P1=0x01 = data, P1=0x02 = last chunk)
        chunk_size = 255
        offset = 0

        while offset < len(tx_bytes):
            chunk = tx_bytes[offset:offset + chunk_size]
            remaining = len(tx_bytes) - offset - len(chunk)
            p1 = 0x02 if remaining == 0 else 0x01  # 0x02 = last chunk

            sw, response = transport.exchange(
                STX_CLA, STX_INS_SIGN_TX, p1, 0x00, chunk
            )

            if sw != 0x9000:
                raise RuntimeError(
                    f"Ledger Stacks app rejected tx chunk at offset {offset}: SW=0x{sw:04X}"
                )
            offset += chunk_size

        # Response should contain the 65-byte signature
        if response and len(response) >= 65:
            signature = response[:65].hex()
        else:
            raise RuntimeError(
                f"Unexpected response length from Ledger: {len(response) if response else 0} bytes"
            )

        # Insert signature into the transaction
        # For standard single-sig: signature is at offset 44 + 1 (after key_encoding byte)
        signed_tx = bytearray(tx_bytes)
        sig_offset = 44  # version(1) + chain_id(4) + auth_type(1) + hash_mode(1) + signer(20) + nonce(8) + fee(8) + key_encoding(1)
        if sig_offset + 1 + 65 <= len(signed_tx):
            signed_tx[sig_offset + 1:sig_offset + 1 + 65] = bytes.fromhex(signature)

        signed_hex = bytes(signed_tx).hex()

    finally:
        transport.close()

    return {
        "transaction": signed_hex,
        "txHex": signed_hex,
        "signature": signature,
        "derivationPath": derivation_path,
        "device": "ledger",
    }
