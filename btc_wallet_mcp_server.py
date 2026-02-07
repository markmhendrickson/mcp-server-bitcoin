#!/usr/bin/env python3
"""
MCP server for Bitcoin and Stacks wallet operations.

Phase 1: Core Bitcoin Enhancement -- 19 tools covering addresses, accounts,
sending (multi-recipient, sweep, consolidate), PSBT, message signing,
fee management, and UTXO management.

Phase 2: Stacks (STX) Support -- 17 tools covering STX addresses, balances,
transfers (STX, SIP-10 FT, SIP-9 NFT), contract calls/deploys, read-only
contract queries, transaction signing, message signing, and utilities.

Wraps btc_wallet.py and stx_wallet.py as MCP tools.
"""

from __future__ import annotations

import asyncio
import json
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, List

from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# Load .env from current directory or parent directories
SERVER_DIR = Path(__file__).resolve().parent
load_dotenv(SERVER_DIR / ".env")
load_dotenv(SERVER_DIR.parent / ".env")

from btc_wallet import (
    BTCConfig,
    _fetch_btc_prices,
    build_transaction_preview,
    combine_utxos,
    decode_psbt,
    estimate_fee,
    get_accounts,
    get_addresses,
    get_balance_btc,
    get_fees,
    get_info,
    get_utxo_details,
    list_utxos,
    send_max_btc,
    send_transaction,
    send_transfer_multi,
    sign_batch_psbt,
    sign_message,
    sign_psbt,
    verify_message,
)

from stx_wallet import (
    STXConfig,
    stx_call_contract,
    stx_deploy_contract,
    stx_estimate_fee,
    stx_get_accounts,
    stx_get_addresses,
    stx_get_balance,
    stx_get_networks,
    stx_get_nonce,
    stx_preview_transfer,
    stx_read_contract,
    stx_sign_message,
    stx_sign_structured_message,
    stx_sign_transaction,
    stx_sign_transactions,
    stx_transfer_sip9_nft,
    stx_transfer_sip10_ft,
    stx_transfer_stx,
    stx_update_profile,
)

app = Server("btc_wallet")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok_response(data: dict[str, Any]) -> List[TextContent]:
    data["success"] = True
    return [TextContent(type="text", text=json.dumps(data, default=str))]


def _error_response(message: str) -> List[TextContent]:
    return [TextContent(type="text", text=json.dumps({"success": False, "error": message}))]


def _parse_decimal(value: Any, field_name: str) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError(f"Invalid {field_name}. Must be a number.") from exc
    if parsed <= 0:
        raise ValueError(f"Invalid {field_name}. Must be greater than zero.")
    return parsed


async def _resolve_amount_btc(arguments: dict[str, Any]) -> Decimal:
    amount_btc = arguments.get("amount_btc")
    amount_eur = arguments.get("amount_eur")

    if amount_btc is not None and amount_eur is not None:
        raise ValueError("Provide exactly one of amount_btc or amount_eur, not both.")
    if amount_btc is None and amount_eur is None:
        raise ValueError("Missing amount. Provide amount_btc or amount_eur.")

    if amount_btc is not None:
        return _parse_decimal(amount_btc, "amount_btc")

    amount_eur_decimal = _parse_decimal(amount_eur, "amount_eur")
    usd_price, eur_price = await asyncio.to_thread(_fetch_btc_prices)
    if eur_price <= 0:
        raise RuntimeError("BTC price lookup failed. Cannot convert EUR to BTC.")
    return amount_eur_decimal / eur_price


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


@app.list_tools()
async def list_tools() -> List[Tool]:
    return [
        # -- 1.1 Multi-Address & Account Management --
        Tool(
            name="btc_get_addresses",
            description=(
                "Return all derived wallet addresses (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR) "
                "with public keys and derivation paths."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="btc_get_accounts",
            description=(
                "List accounts with balances across all address types. "
                "Queries mempool.space for live UTXO data."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="btc_get_info",
            description="Return wallet version, network, supported tools, and configuration.",
            inputSchema={"type": "object", "properties": {}},
        ),
        # -- Original tools (kept for backward compatibility) --
        Tool(
            name="btc_wallet_get_balance",
            description="Return the current wallet balance in BTC.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="btc_wallet_get_prices",
            description="Return current BTC prices in USD and EUR.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="btc_wallet_preview_transfer",
            description=(
                "Preview a BTC transfer with estimated fees. "
                "Provide amount_btc or amount_eur."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "to_address": {"type": "string", "description": "Recipient address"},
                    "amount_btc": {"type": "number", "description": "Amount to send in BTC"},
                    "amount_eur": {"type": "number", "description": "Amount to send in EUR"},
                },
                "required": ["to_address"],
            },
        ),
        Tool(
            name="btc_wallet_send_transfer",
            description=(
                "Send a BTC transfer. Requires explicit user confirmation. "
                "Call btc_wallet_preview_transfer first and confirm before sending."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "to_address": {"type": "string", "description": "Recipient address"},
                    "amount_btc": {"type": "number", "description": "Amount to send in BTC"},
                    "amount_eur": {"type": "number", "description": "Amount to send in EUR"},
                    "max_fee_sats": {
                        "type": "integer",
                        "description": "Optional max fee in satoshis",
                    },
                    "memo": {"type": "string", "description": "Optional transaction memo"},
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, build but do not broadcast",
                    },
                },
                "required": ["to_address"],
            },
        ),
        # -- 1.2 Enhanced Sending --
        Tool(
            name="btc_send_transfer",
            description=(
                "Send BTC to one or more recipients with sat-denominated amounts. "
                "Supports multi-recipient transfers. Call btc_wallet_preview_transfer "
                "first for single transfers, or use this directly for multi-output. "
                "Requires explicit user confirmation."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "recipients": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "address": {"type": "string", "description": "Recipient BTC address"},
                                "amount_sats": {"type": "integer", "description": "Amount in satoshis"},
                            },
                            "required": ["address", "amount_sats"],
                        },
                        "description": "List of recipients with addresses and amounts in satoshis",
                    },
                    "max_fee_sats": {
                        "type": "integer",
                        "description": "Optional maximum fee in satoshis",
                    },
                    "memo": {"type": "string", "description": "Optional memo"},
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, build but do not broadcast (default: true)",
                    },
                },
                "required": ["recipients"],
            },
        ),
        Tool(
            name="btc_send_max",
            description=(
                "Send maximum possible BTC (sweep) to a single address. "
                "Automatically calculates amount after fees. "
                "Requires explicit user confirmation."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "to_address": {"type": "string", "description": "Recipient address"},
                    "fee_rate": {
                        "type": "integer",
                        "description": "Optional fee rate in sat/vB (uses wallet default if omitted)",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, build but do not broadcast (default: true)",
                    },
                },
                "required": ["to_address"],
            },
        ),
        Tool(
            name="btc_combine_utxos",
            description=(
                "Consolidate all UTXOs into a single output. "
                "Reduces future transaction fees by combining many small UTXOs."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "to_address": {
                        "type": "string",
                        "description": "Target address (defaults to wallet's payment address)",
                    },
                    "fee_rate": {
                        "type": "integer",
                        "description": "Optional fee rate in sat/vB",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, build but do not broadcast (default: true)",
                    },
                },
            },
        ),
        # -- 1.3 PSBT Support --
        Tool(
            name="btc_sign_psbt",
            description=(
                "Sign a PSBT (Partially Signed Bitcoin Transaction). "
                "Accepts hex or base64 encoded PSBT. "
                "Optionally broadcast after signing."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "psbt": {
                        "type": "string",
                        "description": "PSBT in hex or base64 format",
                    },
                    "sign_at_index": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Optional list of input indices to sign (default: all)",
                    },
                    "broadcast": {
                        "type": "boolean",
                        "description": "If true, finalize and broadcast after signing",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, don't broadcast even if broadcast=true",
                    },
                },
                "required": ["psbt"],
            },
        ),
        Tool(
            name="btc_sign_batch_psbt",
            description="Sign multiple PSBTs in a single call.",
            inputSchema={
                "type": "object",
                "properties": {
                    "psbts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of PSBTs in hex or base64 format",
                    },
                    "broadcast": {
                        "type": "boolean",
                        "description": "If true, finalize and broadcast each after signing",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, don't broadcast",
                    },
                },
                "required": ["psbts"],
            },
        ),
        Tool(
            name="btc_decode_psbt",
            description=(
                "Decode a PSBT and return a human-readable summary including "
                "inputs, outputs, total value, and finalization status."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "psbt": {
                        "type": "string",
                        "description": "PSBT in hex or base64 format",
                    },
                },
                "required": ["psbt"],
            },
        ),
        # -- 1.4 Message Signing --
        Tool(
            name="btc_sign_message",
            description=(
                "Sign a message using the wallet's private key. "
                "Supports ECDSA (legacy Bitcoin Signed Message) and BIP-322."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Message to sign"},
                    "protocol": {
                        "type": "string",
                        "enum": ["ecdsa", "bip322"],
                        "description": "Signing protocol (default: ecdsa)",
                    },
                    "address_type": {
                        "type": "string",
                        "enum": ["p2wpkh", "p2tr", "p2pkh", "p2sh-p2wpkh"],
                        "description": "Address type to use for signing (default: p2wpkh)",
                    },
                },
                "required": ["message"],
            },
        ),
        Tool(
            name="btc_verify_message",
            description="Verify a signed Bitcoin message.",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Original message"},
                    "signature": {"type": "string", "description": "Base64 encoded signature"},
                    "address": {"type": "string", "description": "Signer's BTC address"},
                },
                "required": ["message", "signature", "address"],
            },
        ),
        # -- 1.5 Fee Management --
        Tool(
            name="btc_get_fees",
            description=(
                "Get recommended fee rates from mempool.space for all tiers: "
                "fastest, halfHour, hour, economy, minimum."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="btc_estimate_fee",
            description=(
                "Estimate transaction fee for given parameters. "
                "Calculates vsize and fee based on input/output counts and address type."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "num_inputs": {
                        "type": "integer",
                        "description": "Number of inputs (auto-detected if omitted)",
                    },
                    "num_outputs": {
                        "type": "integer",
                        "description": "Number of outputs (default: 2)",
                    },
                    "address_type": {
                        "type": "string",
                        "enum": ["p2wpkh", "p2pkh", "p2sh-p2wpkh"],
                        "description": "Address type (default: p2wpkh)",
                    },
                    "fee_tier": {
                        "type": "string",
                        "enum": ["fastestFee", "halfHourFee", "hourFee", "economyFee", "minimumFee"],
                        "description": "Fee tier (default: wallet config)",
                    },
                },
            },
        ),
        # -- 1.6 UTXO Management --
        Tool(
            name="btc_list_utxos",
            description=(
                "List UTXOs across all wallet address types. "
                "Supports filtering by address type, minimum value, and confirmation status."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address_type": {
                        "type": "string",
                        "enum": ["p2wpkh", "p2pkh", "p2sh-p2wpkh", "p2tr"],
                        "description": "Filter by address type",
                    },
                    "min_value_sats": {
                        "type": "integer",
                        "description": "Minimum UTXO value in satoshis",
                    },
                    "confirmed_only": {
                        "type": "boolean",
                        "description": "Only return confirmed UTXOs",
                    },
                },
            },
        ),
        Tool(
            name="btc_get_utxo_details",
            description=(
                "Get detailed information about a specific UTXO including "
                "scriptPubKey, confirmation status, and transaction metadata."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "txid": {"type": "string", "description": "Transaction ID"},
                    "vout": {"type": "integer", "description": "Output index"},
                },
                "required": ["txid", "vout"],
            },
        ),
        # ===================================================================
        # Phase 2: Stacks (STX) Support
        # ===================================================================
        # -- 2.1 Stacks Address & Account Management --
        Tool(
            name="stx_get_addresses",
            description="Get Stacks addresses with public keys and derivation paths.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="stx_get_accounts",
            description=(
                "Get Stacks accounts with balances (STX), locked amounts, and nonces. "
                "Queries the Hiro Stacks API."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="stx_get_balance",
            description=(
                "Get STX balance and all fungible/non-fungible token balances for an address."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Stacks address (default: wallet address)",
                    },
                },
            },
        ),
        Tool(
            name="stx_get_networks",
            description="List available Stacks networks (mainnet, testnet) with chain IDs.",
            inputSchema={"type": "object", "properties": {}},
        ),
        # -- 2.2 STX Transfers --
        Tool(
            name="stx_transfer_stx",
            description=(
                "Transfer STX to a recipient. Amount in micro-STX (1 STX = 1,000,000 uSTX). "
                "Supports optional memo. Requires explicit user confirmation."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "recipient": {"type": "string", "description": "Recipient Stacks address"},
                    "amount_ustx": {
                        "type": "integer",
                        "description": "Amount in micro-STX (1 STX = 1000000 uSTX)",
                    },
                    "memo": {"type": "string", "description": "Optional memo (max 34 bytes)"},
                    "fee": {"type": "integer", "description": "Optional fee in micro-STX"},
                    "nonce": {"type": "integer", "description": "Optional nonce override"},
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, build and sign but do not broadcast (default: true)",
                    },
                },
                "required": ["recipient", "amount_ustx"],
            },
        ),
        Tool(
            name="stx_preview_transfer",
            description=(
                "Preview an STX transfer with fee estimation and balance check. "
                "Call before stx_transfer_stx to verify details."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "recipient": {"type": "string", "description": "Recipient Stacks address"},
                    "amount_ustx": {
                        "type": "integer",
                        "description": "Amount in micro-STX",
                    },
                    "memo": {"type": "string", "description": "Optional memo"},
                },
                "required": ["recipient", "amount_ustx"],
            },
        ),
        Tool(
            name="stx_transfer_sip10_ft",
            description=(
                "Transfer a SIP-10 fungible token. Calls the token contract's "
                "'transfer' function."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "recipient": {"type": "string", "description": "Recipient Stacks address"},
                    "asset": {
                        "type": "string",
                        "description": "Fully qualified asset: 'address.contract-name::token-name'",
                    },
                    "amount": {"type": "integer", "description": "Amount to transfer"},
                    "fee": {"type": "integer", "description": "Optional fee in micro-STX"},
                    "nonce": {"type": "integer", "description": "Optional nonce override"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["recipient", "asset", "amount"],
            },
        ),
        Tool(
            name="stx_transfer_sip9_nft",
            description=(
                "Transfer a SIP-9 non-fungible token. Calls the NFT contract's "
                "'transfer' function."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "recipient": {"type": "string", "description": "Recipient Stacks address"},
                    "asset": {
                        "type": "string",
                        "description": "Fully qualified asset: 'address.contract-name::nft-name'",
                    },
                    "asset_id": {"type": "string", "description": "NFT identifier (uint)"},
                    "fee": {"type": "integer", "description": "Optional fee in micro-STX"},
                    "nonce": {"type": "integer", "description": "Optional nonce override"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["recipient", "asset", "asset_id"],
            },
        ),
        # -- 2.3 Smart Contract Interaction --
        Tool(
            name="stx_call_contract",
            description=(
                "Call a public Clarity smart contract function. "
                "Args use Clarity notation: u100 (uint), 'SPaddr (principal), true/false (bool)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "contract_address": {"type": "string", "description": "Contract deployer address"},
                    "contract_name": {"type": "string", "description": "Contract name"},
                    "function_name": {"type": "string", "description": "Function to call"},
                    "function_args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Clarity-encoded arguments: u100, 'SPaddr, true, none, 0xBEEF, \"text\"",
                    },
                    "fee": {"type": "integer", "description": "Optional fee in micro-STX"},
                    "nonce": {"type": "integer", "description": "Optional nonce override"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["contract_address", "contract_name", "function_name"],
            },
        ),
        Tool(
            name="stx_deploy_contract",
            description="Deploy a Clarity smart contract to the Stacks blockchain.",
            inputSchema={
                "type": "object",
                "properties": {
                    "contract_name": {"type": "string", "description": "Name for the contract"},
                    "clarity_code": {"type": "string", "description": "Clarity source code"},
                    "clarity_version": {
                        "type": "integer",
                        "description": "Clarity version (default: 2)",
                    },
                    "fee": {"type": "integer", "description": "Optional fee in micro-STX"},
                    "nonce": {"type": "integer", "description": "Optional nonce override"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["contract_name", "clarity_code"],
            },
        ),
        Tool(
            name="stx_read_contract",
            description=(
                "Read-only call to a Clarity contract function (no transaction needed). "
                "Returns the function result without modifying state."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "contract_address": {"type": "string", "description": "Contract deployer address"},
                    "contract_name": {"type": "string", "description": "Contract name"},
                    "function_name": {"type": "string", "description": "Function to call"},
                    "function_args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Clarity-encoded arguments",
                    },
                    "sender": {
                        "type": "string",
                        "description": "Optional sender address for the read call",
                    },
                },
                "required": ["contract_address", "contract_name", "function_name"],
            },
        ),
        # -- 2.4 Stacks Transaction Signing --
        Tool(
            name="stx_sign_transaction",
            description=(
                "Sign a serialized Stacks transaction (SIP-30 compatible). "
                "Takes hex-encoded unsigned transaction, returns signed hex."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tx_hex": {"type": "string", "description": "Hex-encoded unsigned transaction"},
                },
                "required": ["tx_hex"],
            },
        ),
        Tool(
            name="stx_sign_transactions",
            description="Sign multiple Stacks transactions in batch.",
            inputSchema={
                "type": "object",
                "properties": {
                    "tx_hexes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of hex-encoded unsigned transactions",
                    },
                },
                "required": ["tx_hexes"],
            },
        ),
        # -- 2.5 Stacks Message Signing --
        Tool(
            name="stx_sign_message",
            description=(
                "Sign a UTF-8 message on Stacks. Returns recoverable ECDSA signature "
                "and public key."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Message to sign"},
                },
                "required": ["message"],
            },
        ),
        Tool(
            name="stx_sign_structured_message",
            description=(
                "Sign SIP-018 structured data. Takes a domain and message, "
                "returns signature and public key."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "SIP-018 domain string"},
                    "message": {"type": "string", "description": "SIP-018 message string"},
                },
                "required": ["domain", "message"],
            },
        ),
        # -- 2.6 Stacks Utilities --
        Tool(
            name="stx_get_nonce",
            description="Get the current nonce for a Stacks address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Stacks address (default: wallet address)",
                    },
                },
            },
        ),
        Tool(
            name="stx_estimate_fee",
            description="Estimate Stacks transaction fee in micro-STX.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="stx_update_profile",
            description=(
                "Update an on-chain profile (schema.org/Person). "
                "Requires a registered BNS name."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "person": {
                        "type": "object",
                        "description": "schema.org/Person object with profile fields",
                    },
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["person"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> List[TextContent]:
    if not isinstance(arguments, dict):
        return _error_response("Invalid arguments. Expected an object.")

    try:
        # 1.1 Multi-Address & Account Management
        if name == "btc_get_addresses":
            return await _handle_get_addresses()
        if name == "btc_get_accounts":
            return await _handle_get_accounts()
        if name == "btc_get_info":
            return await _handle_get_info()

        # Original tools (backward compatible)
        if name == "btc_wallet_get_balance":
            return await _handle_get_balance()
        if name == "btc_wallet_get_prices":
            return await _handle_get_prices()
        if name == "btc_wallet_preview_transfer":
            return await _handle_preview_transfer(arguments)
        if name == "btc_wallet_send_transfer":
            return await _handle_send_transfer(arguments)

        # 1.2 Enhanced Sending
        if name == "btc_send_transfer":
            return await _handle_send_transfer_multi(arguments)
        if name == "btc_send_max":
            return await _handle_send_max(arguments)
        if name == "btc_combine_utxos":
            return await _handle_combine_utxos(arguments)

        # 1.3 PSBT Support
        if name == "btc_sign_psbt":
            return await _handle_sign_psbt(arguments)
        if name == "btc_sign_batch_psbt":
            return await _handle_sign_batch_psbt(arguments)
        if name == "btc_decode_psbt":
            return await _handle_decode_psbt(arguments)

        # 1.4 Message Signing
        if name == "btc_sign_message":
            return await _handle_sign_message(arguments)
        if name == "btc_verify_message":
            return await _handle_verify_message(arguments)

        # 1.5 Fee Management
        if name == "btc_get_fees":
            return await _handle_get_fees()
        if name == "btc_estimate_fee":
            return await _handle_estimate_fee(arguments)

        # 1.6 UTXO Management
        if name == "btc_list_utxos":
            return await _handle_list_utxos(arguments)
        if name == "btc_get_utxo_details":
            return await _handle_get_utxo_details(arguments)

        # =================================================================
        # Phase 2: Stacks (STX) Support
        # =================================================================

        # 2.1 Stacks Address & Account Management
        if name == "stx_get_addresses":
            return await _handle_stx_get_addresses()
        if name == "stx_get_accounts":
            return await _handle_stx_get_accounts()
        if name == "stx_get_balance":
            return await _handle_stx_get_balance(arguments)
        if name == "stx_get_networks":
            return await _handle_stx_get_networks()

        # 2.2 STX Transfers
        if name == "stx_transfer_stx":
            return await _handle_stx_transfer_stx(arguments)
        if name == "stx_preview_transfer":
            return await _handle_stx_preview_transfer(arguments)
        if name == "stx_transfer_sip10_ft":
            return await _handle_stx_transfer_sip10_ft(arguments)
        if name == "stx_transfer_sip9_nft":
            return await _handle_stx_transfer_sip9_nft(arguments)

        # 2.3 Smart Contract Interaction
        if name == "stx_call_contract":
            return await _handle_stx_call_contract(arguments)
        if name == "stx_deploy_contract":
            return await _handle_stx_deploy_contract(arguments)
        if name == "stx_read_contract":
            return await _handle_stx_read_contract(arguments)

        # 2.4 Stacks Transaction Signing
        if name == "stx_sign_transaction":
            return await _handle_stx_sign_transaction(arguments)
        if name == "stx_sign_transactions":
            return await _handle_stx_sign_transactions(arguments)

        # 2.5 Stacks Message Signing
        if name == "stx_sign_message":
            return await _handle_stx_sign_message(arguments)
        if name == "stx_sign_structured_message":
            return await _handle_stx_sign_structured_message(arguments)

        # 2.6 Stacks Utilities
        if name == "stx_get_nonce":
            return await _handle_stx_get_nonce(arguments)
        if name == "stx_estimate_fee":
            return await _handle_stx_estimate_fee()
        if name == "stx_update_profile":
            return await _handle_stx_update_profile(arguments)

    except Exception as exc:  # noqa: BLE001
        return _error_response(str(exc))

    return _error_response(f"Unknown tool: {name}")


# ---------------------------------------------------------------------------
# Handlers -- 1.1 Multi-Address & Account Management
# ---------------------------------------------------------------------------


async def _handle_get_addresses() -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    addresses = await asyncio.to_thread(get_addresses, cfg)
    return _ok_response({"addresses": addresses, "network": cfg.network})


async def _handle_get_accounts() -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    accounts = await asyncio.to_thread(get_accounts, cfg)
    total_sats = sum(a["balance_sats"] for a in accounts)
    total_btc = Decimal(total_sats) / Decimal("1e8")
    return _ok_response({
        "accounts": accounts,
        "total_balance_sats": total_sats,
        "total_balance_btc": str(total_btc),
        "network": cfg.network,
    })


async def _handle_get_info() -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    info = await asyncio.to_thread(get_info, cfg)
    return _ok_response(info)


# ---------------------------------------------------------------------------
# Handlers -- Original (backward compatible)
# ---------------------------------------------------------------------------


async def _handle_get_balance() -> List[TextContent]:
    try:
        cfg = await asyncio.to_thread(BTCConfig.from_env)
        balance = await asyncio.to_thread(get_balance_btc, cfg)
        result = {
            "success": True,
            "balance_btc": str(balance),
            "network": cfg.network,
        }
        return [TextContent(type="text", text=json.dumps(result))]
    except Exception as exc:  # noqa: BLE001
        return _error_response(str(exc))


async def _handle_get_prices() -> List[TextContent]:
    try:
        usd_price, eur_price = await asyncio.to_thread(_fetch_btc_prices)
        result = {
            "success": True,
            "usd": str(usd_price),
            "eur": str(eur_price),
        }
        return [TextContent(type="text", text=json.dumps(result))]
    except Exception as exc:  # noqa: BLE001
        return _error_response(str(exc))


async def _handle_preview_transfer(arguments: dict[str, Any]) -> List[TextContent]:
    to_address = (arguments.get("to_address") or "").strip()
    if not to_address:
        return _error_response("Missing to_address.")

    try:
        amount_btc = await _resolve_amount_btc(arguments)
        cfg = await asyncio.to_thread(BTCConfig.from_env)
        preview = await asyncio.to_thread(
            build_transaction_preview, cfg, to_address, amount_btc
        )
        result = {
            "success": True,
            "from_address": preview.from_address,
            "to_address": preview.to_address,
            "amount_btc": str(preview.amount_btc),
            "fee_sats_estimate": preview.fee_sats_estimate,
            "total_spend_btc": str(preview.total_spend_btc),
            "balance_btc": str(preview.balance_btc),
            "network": preview.network,
        }
        return [TextContent(type="text", text=json.dumps(result))]
    except Exception as exc:  # noqa: BLE001
        return _error_response(str(exc))


async def _handle_send_transfer(arguments: dict[str, Any]) -> List[TextContent]:
    to_address = (arguments.get("to_address") or "").strip()
    if not to_address:
        return _error_response("Missing to_address.")

    try:
        amount_btc = await _resolve_amount_btc(arguments)
        cfg = await asyncio.to_thread(BTCConfig.from_env)

        max_fee_sats = arguments.get("max_fee_sats")
        if max_fee_sats is not None:
            max_fee_sats = int(max_fee_sats)

        memo = arguments.get("memo")
        dry_run = arguments.get("dry_run")
        if dry_run is None:
            dry_run = cfg.dry_run_default

        txid = await asyncio.to_thread(
            send_transaction,
            cfg,
            to_address,
            amount_btc,
            max_fee_sats,
            memo,
            dry_run,
        )
        result = {
            "success": True,
            "txid": txid,
            "dry_run": bool(dry_run),
            "network": cfg.network,
        }
        return [TextContent(type="text", text=json.dumps(result))]
    except Exception as exc:  # noqa: BLE001
        return _error_response(str(exc))


# ---------------------------------------------------------------------------
# Handlers -- 1.2 Enhanced Sending
# ---------------------------------------------------------------------------


async def _handle_send_transfer_multi(arguments: dict[str, Any]) -> List[TextContent]:
    recipients = arguments.get("recipients")
    if not recipients or not isinstance(recipients, list):
        return _error_response("Missing or invalid 'recipients' array.")

    cfg = await asyncio.to_thread(BTCConfig.from_env)
    max_fee_sats = arguments.get("max_fee_sats")
    if max_fee_sats is not None:
        max_fee_sats = int(max_fee_sats)
    memo = arguments.get("memo")
    dry_run = arguments.get("dry_run")

    txid = await asyncio.to_thread(
        send_transfer_multi, cfg, recipients, max_fee_sats, memo, dry_run
    )
    return _ok_response({
        "txid": txid,
        "num_recipients": len(recipients),
        "dry_run": bool(dry_run if dry_run is not None else cfg.dry_run_default),
        "network": cfg.network,
    })


async def _handle_send_max(arguments: dict[str, Any]) -> List[TextContent]:
    to_address = (arguments.get("to_address") or "").strip()
    if not to_address:
        return _error_response("Missing to_address.")

    cfg = await asyncio.to_thread(BTCConfig.from_env)
    fee_rate = arguments.get("fee_rate")
    dry_run = arguments.get("dry_run")

    result = await asyncio.to_thread(
        send_max_btc, cfg, to_address, fee_rate, dry_run
    )
    result["network"] = cfg.network
    return _ok_response(result)


async def _handle_combine_utxos(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    to_address = (arguments.get("to_address") or "").strip() or None
    fee_rate = arguments.get("fee_rate")
    dry_run = arguments.get("dry_run")

    result = await asyncio.to_thread(
        combine_utxos, cfg, to_address, fee_rate, dry_run
    )
    result["network"] = cfg.network
    return _ok_response(result)


# ---------------------------------------------------------------------------
# Handlers -- 1.3 PSBT Support
# ---------------------------------------------------------------------------


async def _handle_sign_psbt(arguments: dict[str, Any]) -> List[TextContent]:
    psbt_str = (arguments.get("psbt") or "").strip()
    if not psbt_str:
        return _error_response("Missing 'psbt' parameter.")

    cfg = await asyncio.to_thread(BTCConfig.from_env)
    sign_at_index = arguments.get("sign_at_index")
    broadcast = arguments.get("broadcast", False)
    dry_run = arguments.get("dry_run")

    result = await asyncio.to_thread(
        sign_psbt, cfg, psbt_str, sign_at_index, broadcast, dry_run
    )
    result["network"] = cfg.network
    return _ok_response(result)


async def _handle_sign_batch_psbt(arguments: dict[str, Any]) -> List[TextContent]:
    psbts = arguments.get("psbts")
    if not psbts or not isinstance(psbts, list):
        return _error_response("Missing or invalid 'psbts' array.")

    cfg = await asyncio.to_thread(BTCConfig.from_env)
    broadcast = arguments.get("broadcast", False)
    dry_run = arguments.get("dry_run")

    results = await asyncio.to_thread(
        sign_batch_psbt, cfg, psbts, broadcast, dry_run
    )
    return _ok_response({
        "results": results,
        "count": len(results),
        "network": cfg.network,
    })


async def _handle_decode_psbt(arguments: dict[str, Any]) -> List[TextContent]:
    psbt_str = (arguments.get("psbt") or "").strip()
    if not psbt_str:
        return _error_response("Missing 'psbt' parameter.")

    result = await asyncio.to_thread(decode_psbt, psbt_str)
    return _ok_response(result)


# ---------------------------------------------------------------------------
# Handlers -- 1.4 Message Signing
# ---------------------------------------------------------------------------


async def _handle_sign_message(arguments: dict[str, Any]) -> List[TextContent]:
    message = arguments.get("message", "")
    if not message:
        return _error_response("Missing 'message' parameter.")

    cfg = await asyncio.to_thread(BTCConfig.from_env)
    protocol = arguments.get("protocol", "ecdsa")
    address_type = arguments.get("address_type")

    result = await asyncio.to_thread(
        sign_message, cfg, message, protocol, address_type
    )
    return _ok_response(result)


async def _handle_verify_message(arguments: dict[str, Any]) -> List[TextContent]:
    message = arguments.get("message", "")
    signature = arguments.get("signature", "")
    address = arguments.get("address", "")
    if not all([message, signature, address]):
        return _error_response("Missing required parameters: message, signature, address.")

    result = await asyncio.to_thread(verify_message, message, signature, address)
    return _ok_response(result)


# ---------------------------------------------------------------------------
# Handlers -- 1.5 Fee Management
# ---------------------------------------------------------------------------


async def _handle_get_fees() -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    result = await asyncio.to_thread(get_fees, cfg)
    return _ok_response(result)


async def _handle_estimate_fee(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    num_inputs = arguments.get("num_inputs")
    num_outputs = arguments.get("num_outputs", 2)
    address_type = arguments.get("address_type", "p2wpkh")
    fee_tier = arguments.get("fee_tier")

    result = await asyncio.to_thread(
        estimate_fee, cfg, num_inputs, num_outputs, address_type, fee_tier
    )
    return _ok_response(result)


# ---------------------------------------------------------------------------
# Handlers -- 1.6 UTXO Management
# ---------------------------------------------------------------------------


async def _handle_list_utxos(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    address_type = arguments.get("address_type")
    min_value_sats = arguments.get("min_value_sats")
    confirmed_only = arguments.get("confirmed_only", False)

    utxos = await asyncio.to_thread(
        list_utxos, cfg, address_type, min_value_sats, confirmed_only
    )
    total_sats = sum(u["value_sats"] for u in utxos)
    return _ok_response({
        "utxos": utxos,
        "count": len(utxos),
        "total_sats": total_sats,
        "total_btc": str(Decimal(total_sats) / Decimal("1e8")),
        "network": cfg.network,
    })


async def _handle_get_utxo_details(arguments: dict[str, Any]) -> List[TextContent]:
    txid = (arguments.get("txid") or "").strip()
    vout = arguments.get("vout")
    if not txid:
        return _error_response("Missing 'txid' parameter.")
    if vout is None:
        return _error_response("Missing 'vout' parameter.")

    cfg = await asyncio.to_thread(BTCConfig.from_env)
    result = await asyncio.to_thread(get_utxo_details, cfg, txid, int(vout))
    return _ok_response(result)


# ===========================================================================
# Phase 2 Handlers -- Stacks (STX)
# ===========================================================================


# ---------------------------------------------------------------------------
# 2.1 Stacks Address & Account Management
# ---------------------------------------------------------------------------


async def _handle_stx_get_addresses() -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    addresses = await asyncio.to_thread(stx_get_addresses, cfg)
    return _ok_response({"addresses": addresses, "network": cfg.network})


async def _handle_stx_get_accounts() -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    accounts = await asyncio.to_thread(stx_get_accounts, cfg)
    return _ok_response({"accounts": accounts, "network": cfg.network})


async def _handle_stx_get_balance(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    address = (arguments.get("address") or "").strip() or None
    result = await asyncio.to_thread(stx_get_balance, cfg, address)
    result["network"] = cfg.network
    return _ok_response(result)


async def _handle_stx_get_networks() -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(stx_get_networks, cfg)
    return _ok_response(result)


# ---------------------------------------------------------------------------
# 2.2 STX Transfers
# ---------------------------------------------------------------------------


async def _handle_stx_transfer_stx(arguments: dict[str, Any]) -> List[TextContent]:
    recipient = (arguments.get("recipient") or "").strip()
    if not recipient:
        return _error_response("Missing 'recipient' parameter.")
    amount_ustx = arguments.get("amount_ustx")
    if amount_ustx is None:
        return _error_response("Missing 'amount_ustx' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_transfer_stx,
        cfg,
        recipient,
        int(amount_ustx),
        arguments.get("memo", ""),
        arguments.get("fee"),
        arguments.get("nonce"),
        arguments.get("dry_run"),
    )
    return _ok_response(result)


async def _handle_stx_preview_transfer(arguments: dict[str, Any]) -> List[TextContent]:
    recipient = (arguments.get("recipient") or "").strip()
    if not recipient:
        return _error_response("Missing 'recipient' parameter.")
    amount_ustx = arguments.get("amount_ustx")
    if amount_ustx is None:
        return _error_response("Missing 'amount_ustx' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_preview_transfer, cfg, recipient, int(amount_ustx), arguments.get("memo", "")
    )
    return _ok_response(result)


async def _handle_stx_transfer_sip10_ft(arguments: dict[str, Any]) -> List[TextContent]:
    recipient = (arguments.get("recipient") or "").strip()
    asset = (arguments.get("asset") or "").strip()
    amount = arguments.get("amount")
    if not recipient:
        return _error_response("Missing 'recipient' parameter.")
    if not asset:
        return _error_response("Missing 'asset' parameter.")
    if amount is None:
        return _error_response("Missing 'amount' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_transfer_sip10_ft,
        cfg, recipient, asset, int(amount),
        arguments.get("fee"), arguments.get("nonce"), arguments.get("dry_run"),
    )
    return _ok_response(result)


async def _handle_stx_transfer_sip9_nft(arguments: dict[str, Any]) -> List[TextContent]:
    recipient = (arguments.get("recipient") or "").strip()
    asset = (arguments.get("asset") or "").strip()
    asset_id = (arguments.get("asset_id") or "").strip()
    if not recipient:
        return _error_response("Missing 'recipient' parameter.")
    if not asset:
        return _error_response("Missing 'asset' parameter.")
    if not asset_id:
        return _error_response("Missing 'asset_id' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_transfer_sip9_nft,
        cfg, recipient, asset, asset_id,
        arguments.get("fee"), arguments.get("nonce"), arguments.get("dry_run"),
    )
    return _ok_response(result)


# ---------------------------------------------------------------------------
# 2.3 Smart Contract Interaction
# ---------------------------------------------------------------------------


async def _handle_stx_call_contract(arguments: dict[str, Any]) -> List[TextContent]:
    contract_address = (arguments.get("contract_address") or "").strip()
    contract_name = (arguments.get("contract_name") or "").strip()
    function_name = (arguments.get("function_name") or "").strip()
    if not contract_address:
        return _error_response("Missing 'contract_address' parameter.")
    if not contract_name:
        return _error_response("Missing 'contract_name' parameter.")
    if not function_name:
        return _error_response("Missing 'function_name' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_call_contract,
        cfg, contract_address, contract_name, function_name,
        arguments.get("function_args"),
        arguments.get("fee"), arguments.get("nonce"), arguments.get("dry_run"),
    )
    return _ok_response(result)


async def _handle_stx_deploy_contract(arguments: dict[str, Any]) -> List[TextContent]:
    contract_name = (arguments.get("contract_name") or "").strip()
    clarity_code = arguments.get("clarity_code", "")
    if not contract_name:
        return _error_response("Missing 'contract_name' parameter.")
    if not clarity_code:
        return _error_response("Missing 'clarity_code' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_deploy_contract,
        cfg, contract_name, clarity_code,
        arguments.get("clarity_version", 2),
        arguments.get("fee"), arguments.get("nonce"), arguments.get("dry_run"),
    )
    return _ok_response(result)


async def _handle_stx_read_contract(arguments: dict[str, Any]) -> List[TextContent]:
    contract_address = (arguments.get("contract_address") or "").strip()
    contract_name = (arguments.get("contract_name") or "").strip()
    function_name = (arguments.get("function_name") or "").strip()
    if not contract_address:
        return _error_response("Missing 'contract_address' parameter.")
    if not contract_name:
        return _error_response("Missing 'contract_name' parameter.")
    if not function_name:
        return _error_response("Missing 'function_name' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_read_contract,
        cfg, contract_address, contract_name, function_name,
        arguments.get("function_args"), arguments.get("sender"),
    )
    return _ok_response(result)


# ---------------------------------------------------------------------------
# 2.4 Stacks Transaction Signing
# ---------------------------------------------------------------------------


async def _handle_stx_sign_transaction(arguments: dict[str, Any]) -> List[TextContent]:
    tx_hex = (arguments.get("tx_hex") or "").strip()
    if not tx_hex:
        return _error_response("Missing 'tx_hex' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(stx_sign_transaction, cfg, tx_hex)
    result["network"] = cfg.network
    return _ok_response(result)


async def _handle_stx_sign_transactions(arguments: dict[str, Any]) -> List[TextContent]:
    tx_hexes = arguments.get("tx_hexes")
    if not tx_hexes or not isinstance(tx_hexes, list):
        return _error_response("Missing or invalid 'tx_hexes' array.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    results = await asyncio.to_thread(stx_sign_transactions, cfg, tx_hexes)
    return _ok_response({"results": results, "count": len(results), "network": cfg.network})


# ---------------------------------------------------------------------------
# 2.5 Stacks Message Signing
# ---------------------------------------------------------------------------


async def _handle_stx_sign_message(arguments: dict[str, Any]) -> List[TextContent]:
    message = arguments.get("message", "")
    if not message:
        return _error_response("Missing 'message' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(stx_sign_message, cfg, message)
    result["network"] = cfg.network
    return _ok_response(result)


async def _handle_stx_sign_structured_message(arguments: dict[str, Any]) -> List[TextContent]:
    domain = arguments.get("domain", "")
    message = arguments.get("message", "")
    if not domain:
        return _error_response("Missing 'domain' parameter.")
    if not message:
        return _error_response("Missing 'message' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(stx_sign_structured_message, cfg, domain, message)
    result["network"] = cfg.network
    return _ok_response(result)


# ---------------------------------------------------------------------------
# 2.6 Stacks Utilities
# ---------------------------------------------------------------------------


async def _handle_stx_get_nonce(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    address = (arguments.get("address") or "").strip() or None
    nonce = await asyncio.to_thread(stx_get_nonce, cfg, address)
    return _ok_response({
        "address": address or cfg.stx_address,
        "nonce": nonce,
        "network": cfg.network,
    })


async def _handle_stx_estimate_fee() -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    fee = await asyncio.to_thread(stx_estimate_fee, cfg)
    return _ok_response({
        "fee_ustx": fee,
        "fee_stx": str(Decimal(fee) / Decimal("1000000")),
        "network": cfg.network,
    })


async def _handle_stx_update_profile(arguments: dict[str, Any]) -> List[TextContent]:
    person = arguments.get("person")
    if not person:
        return _error_response("Missing 'person' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_update_profile, cfg, person,
        arguments.get("fee"), arguments.get("nonce"), arguments.get("dry_run"),
    )
    return _ok_response(result)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
