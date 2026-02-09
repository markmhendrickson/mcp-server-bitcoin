#!/usr/bin/env python3
"""
MCP server for Bitcoin and Stacks wallet operations.

Phase 1: Core Bitcoin Enhancement -- 19 tools covering addresses, accounts,
sending (multi-recipient, sweep, consolidate), PSBT, message signing,
fee management, and UTXO management.

Phase 2: Stacks (STX) Support -- 18 tools covering STX addresses, balances,
transfers (STX, SIP-10 FT, SIP-9 NFT), contract calls/deploys, read-only
contract queries, transaction signing, message signing, and utilities.

Phase 3: Ordinals & Inscriptions -- 7 tools covering inscription queries,
sending (full UTXO and split), extraction, and recovery operations.

Wraps bitcoin_wallet.py, stx_wallet.py, and ord_wallet.py as MCP tools.
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

from bitcoin_wallet import (
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

from inscribe_onramp_wallet import (
    buy_get_providers,
    buy_get_quote,
    ord_create_inscription,
    ord_create_repeat_inscriptions,
)

from ledger_wallet import (
    ledger_get_addresses,
    ledger_get_stx_addresses,
    ledger_sign_psbt,
    ledger_sign_stx_transaction,
)

from advanced_wallet import (
    stx_get_network_info,
    stx_get_network_status,
    stx_query_transactions,
    stx_query_transactions_by_contract,
    tx_cancel,
    tx_get_history,
    tx_get_status,
    tx_speed_up,
    wallet_add_network,
    wallet_get_network,
    wallet_get_supported_methods,
    wallet_switch_network,
)

from stx_mempool import (
    stx_mempool_get_dropped,
    stx_mempool_get_stats,
    stx_mempool_list_pending,
)

from stx_explorer import (
    stx_get_block_by_hash,
    stx_get_block_by_height,
    stx_get_recent_blocks,
    stx_get_stacks_blocks_for_bitcoin_block,
)

from stx_events import (
    stx_get_address_asset_events,
    stx_get_contract_events,
)

from stx_token_metadata import (
    stx_get_token_holders,
    stx_get_token_metadata,
)

from bns_market_wallet import (
    bns_get_names,
    bns_lookup,
    bns_register,
    market_get_history,
    market_get_prices,
    portfolio_get_assets,
    portfolio_get_collectibles,
    portfolio_get_summary,
)

from defi_wallet import (
    sbtc_bridge_deposit,
    sbtc_bridge_withdraw,
    sbtc_get_balance,
    stx_get_stacking_info,
    stx_revoke_delegation,
    stx_stack,
    swap_execute,
    swap_get_history,
    swap_get_quote,
    swap_get_supported_pairs,
)

from ord_wallet import (
    ord_extract_from_utxo,
    ord_get_inscription_details,
    ord_get_inscriptions,
    ord_recover_bitcoin,
    ord_recover_ordinals,
    ord_send_inscriptions,
    ord_send_inscriptions_split,
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

app = Server("bitcoin_wallet")


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
        # ===================================================================
        # Phase 3: Ordinals & Inscriptions
        # ===================================================================
        Tool(
            name="ord_get_inscriptions",
            description=(
                "List inscriptions owned by the wallet (or a specific address) "
                "with pagination. Returns inscription IDs, content types, "
                "locations, and sat rarity."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "offset": {"type": "integer", "description": "Pagination offset (default: 0)"},
                    "limit": {"type": "integer", "description": "Page size, max 60 (default: 20)"},
                    "address": {
                        "type": "string",
                        "description": "Address to query (default: wallet's taproot address)",
                    },
                },
            },
        ),
        Tool(
            name="ord_get_inscription_details",
            description=(
                "Get detailed information for a specific inscription by ID, "
                "including genesis info, content type, sat ordinal, rarity, "
                "current location, and value."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "inscription_id": {
                        "type": "string",
                        "description": "Inscription ID (e.g. 'txid...i0')",
                    },
                },
                "required": ["inscription_id"],
            },
        ),
        Tool(
            name="ord_send_inscriptions",
            description=(
                "Send inscriptions to recipients. Transfers the full UTXO "
                "containing each inscription. Uses a separate payment UTXO for fees."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "transfers": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "address": {"type": "string", "description": "Recipient BTC address"},
                                "inscriptionId": {"type": "string", "description": "Inscription ID"},
                            },
                            "required": ["address", "inscriptionId"],
                        },
                        "description": "List of inscription transfers",
                    },
                    "fee_rate": {"type": "integer", "description": "Fee rate in sat/vB"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["transfers"],
            },
        ),
        Tool(
            name="ord_send_inscriptions_split",
            description=(
                "Send inscriptions with UTXO splitting. When an inscription "
                "sits in a large UTXO, splits it so only the inscription's "
                "sat range goes to the recipient and the remainder returns."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "transfers": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "address": {"type": "string", "description": "Recipient BTC address"},
                                "inscriptionId": {"type": "string", "description": "Inscription ID"},
                            },
                            "required": ["address", "inscriptionId"],
                        },
                        "description": "List of inscription transfers",
                    },
                    "fee_rate": {"type": "integer", "description": "Fee rate in sat/vB"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["transfers"],
            },
        ),
        Tool(
            name="ord_extract_from_utxo",
            description=(
                "Extract ordinals/inscriptions from a mixed UTXO into "
                "individual outputs at the ordinals address."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "outpoint": {
                        "type": "string",
                        "description": "UTXO outpoint in 'txid:vout' format",
                    },
                    "fee_rate": {"type": "integer", "description": "Fee rate in sat/vB"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["outpoint"],
            },
        ),
        Tool(
            name="ord_recover_bitcoin",
            description=(
                "Recover BTC trapped in the ordinals (taproot) address. "
                "Finds UTXOs without inscriptions and sweeps them to "
                "the payment address."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "outpoint": {
                        "type": "string",
                        "description": "Optional: recover a specific UTXO ('txid:vout')",
                    },
                    "fee_rate": {"type": "integer", "description": "Fee rate in sat/vB"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
            },
        ),
        Tool(
            name="ord_recover_ordinals",
            description=(
                "Recover ordinals/inscriptions that ended up on the payment "
                "address. Moves inscription-bearing UTXOs to the ordinals address."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "outpoint": {
                        "type": "string",
                        "description": "Optional: recover from a specific UTXO ('txid:vout')",
                    },
                    "fee_rate": {"type": "integer", "description": "Fee rate in sat/vB"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
            },
        ),
        # ===================================================================
        # Phase 4: Swaps, DeFi & Bridge
        # ===================================================================
        # -- 4.1 Swap Operations --
        Tool(
            name="swap_get_supported_pairs",
            description="List supported swap pairs and protocols (Alex DEX pools and Bitflow ticker).",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="swap_get_quote",
            description=(
                "Get a swap quote with estimated output, exchange rate, and fees. "
                "Protocol: alex (default), bitflow, or velar. Alex and Velar use Alex token prices; Bitflow uses Bitflow ticker."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "token_in": {
                        "type": "string",
                        "description": "Input token contract ID (or 'STX' for native STX)",
                    },
                    "token_out": {
                        "type": "string",
                        "description": "Output token contract ID (or 'STX')",
                    },
                    "amount": {
                        "type": "integer",
                        "description": "Amount of token_in in smallest unit",
                    },
                    "protocol": {
                        "type": "string",
                        "description": "DEX protocol: alex (default), bitflow, or velar",
                    },
                },
                "required": ["token_in", "token_out", "amount"],
            },
        ),
        Tool(
            name="swap_execute",
            description=(
                "Execute a token swap via DEX smart contract call. "
                "Supported for protocol=alex (default). Bitflow and Velar are supported for quotes and pair discovery; "
                "execution for them could be added via protocol SDKs (e.g. Velar SDK returns contract-call params)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "token_in": {"type": "string", "description": "Input token contract ID or 'STX'"},
                    "token_out": {"type": "string", "description": "Output token contract ID or 'STX'"},
                    "amount": {"type": "integer", "description": "Amount of token_in"},
                    "min_output": {
                        "type": "integer",
                        "description": "Minimum acceptable output (slippage protection)",
                    },
                    "protocol": {"type": "string", "description": "Must be alex for execution (default: alex)"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["token_in", "token_out", "amount"],
            },
        ),
        Tool(
            name="swap_get_history",
            description="Get swap transaction history from on-chain activity.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Page size (default: 20)"},
                    "offset": {"type": "integer", "description": "Pagination offset (default: 0)"},
                },
            },
        ),
        # -- 4.2 sBTC Bridge --
        Tool(
            name="sbtc_get_balance",
            description="Get sBTC token balance for the wallet.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="sbtc_bridge_deposit",
            description=(
                "Get deposit information for bridging BTC to sBTC. "
                "Returns the deposit intent details."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "amount_sats": {
                        "type": "integer",
                        "description": "Amount in satoshis to bridge to sBTC",
                    },
                    "dry_run": {"type": "boolean", "description": "If true, info only"},
                },
                "required": ["amount_sats"],
            },
        ),
        Tool(
            name="sbtc_bridge_withdraw",
            description=(
                "Get withdrawal information for converting sBTC back to BTC."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "amount_sats": {
                        "type": "integer",
                        "description": "Amount in satoshis to withdraw",
                    },
                    "btc_address": {
                        "type": "string",
                        "description": "BTC address to receive the withdrawn BTC",
                    },
                    "dry_run": {"type": "boolean", "description": "If true, info only"},
                },
                "required": ["amount_sats", "btc_address"],
            },
        ),
        # -- 4.3 Yield / Stacking --
        Tool(
            name="stx_get_stacking_info",
            description=(
                "Get current PoX stacking status, cycle info, thresholds, "
                "and wallet stacking state."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="stx_stack",
            description=(
                "Initiate STX stacking (solo). Locks STX for reward cycles "
                "and earns BTC rewards at the specified pox_address."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "amount_ustx": {
                        "type": "integer",
                        "description": "Amount to stack in micro-STX",
                    },
                    "pox_address": {
                        "type": "string",
                        "description": "BTC address for reward payouts",
                    },
                    "num_cycles": {
                        "type": "integer",
                        "description": "Number of cycles to stack (1-12, default: 1)",
                    },
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["amount_ustx", "pox_address"],
            },
        ),
        Tool(
            name="stx_revoke_delegation",
            description="Revoke stacking delegation via the PoX contract.",
            inputSchema={
                "type": "object",
                "properties": {
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
            },
        ),
        # ===================================================================
        # Phase 5A: Transaction Management & Wallet
        # ===================================================================
        Tool(
            name="tx_get_history",
            description="Get transaction history for BTC and/or STX with filtering.",
            inputSchema={
                "type": "object",
                "properties": {
                    "chain": {"type": "string", "enum": ["btc", "stx", "both"], "description": "Which chain (default: both)"},
                    "limit": {"type": "integer", "description": "Page size (default: 20)"},
                    "offset": {"type": "integer", "description": "Pagination offset"},
                },
            },
        ),
        Tool(
            name="tx_get_status",
            description="Get the status of a specific BTC or STX transaction.",
            inputSchema={
                "type": "object",
                "properties": {
                    "txid": {"type": "string", "description": "Transaction ID"},
                    "chain": {"type": "string", "enum": ["btc", "stx"], "description": "Chain (default: btc)"},
                },
                "required": ["txid"],
            },
        ),
        Tool(
            name="tx_speed_up",
            description="Speed up a pending BTC transaction using Replace-By-Fee (RBF).",
            inputSchema={
                "type": "object",
                "properties": {
                    "txid": {"type": "string", "description": "Transaction ID to speed up"},
                    "new_fee_rate": {"type": "integer", "description": "New fee rate in sat/vB"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["txid"],
            },
        ),
        Tool(
            name="tx_cancel",
            description="Cancel a pending BTC transaction via RBF (sends funds back to self).",
            inputSchema={
                "type": "object",
                "properties": {
                    "txid": {"type": "string", "description": "Transaction ID to cancel"},
                    "fee_rate": {"type": "integer", "description": "Fee rate for cancel tx in sat/vB"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["txid"],
            },
        ),
        Tool(
            name="wallet_get_network",
            description="Get current wallet network configuration and API endpoints.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="wallet_switch_network",
            description="Switch between mainnet and testnet.",
            inputSchema={
                "type": "object",
                "properties": {
                    "network": {"type": "string", "enum": ["mainnet", "testnet"], "description": "Target network"},
                },
                "required": ["network"],
            },
        ),
        Tool(
            name="wallet_add_network",
            description="Add a custom network with custom API URLs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Network name"},
                    "btc_api_url": {"type": "string", "description": "Custom mempool.space URL"},
                    "stx_api_url": {"type": "string", "description": "Custom Hiro API URL"},
                },
                "required": ["name"],
            },
        ),
        Tool(
            name="wallet_get_supported_methods",
            description="List all available MCP tools with their names and descriptions.",
            inputSchema={"type": "object", "properties": {}},
        ),
        # ===================================================================
        # Phase 5B: BNS & Market Data
        # ===================================================================
        Tool(
            name="bns_lookup",
            description="Look up a BNS name to resolve its Stacks address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "BNS name, e.g. 'alice.btc'"},
                },
                "required": ["name"],
            },
        ),
        Tool(
            name="bns_get_names",
            description="Get BNS names owned by a Stacks address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Stacks address (default: wallet)"},
                },
            },
        ),
        Tool(
            name="bns_register",
            description="Register a BNS name via Stacks contract call.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name to register (without namespace)"},
                    "namespace": {"type": "string", "description": "Namespace (default: btc)"},
                    "fee": {"type": "integer", "description": "Optional fee in micro-STX"},
                    "dry_run": {"type": "boolean", "description": "If true, don't broadcast"},
                },
                "required": ["name"],
            },
        ),
        Tool(
            name="market_get_prices",
            description="Get multi-asset prices (BTC, STX, tokens) from CoinGecko.",
            inputSchema={
                "type": "object",
                "properties": {
                    "coins": {
                        "type": "array", "items": {"type": "string"},
                        "description": "CoinGecko coin IDs (default: bitcoin, blockstack)",
                    },
                    "vs_currencies": {
                        "type": "array", "items": {"type": "string"},
                        "description": "Fiat currencies (default: usd, eur)",
                    },
                },
            },
        ),
        Tool(
            name="market_get_history",
            description="Get price history for a coin (for charting).",
            inputSchema={
                "type": "object",
                "properties": {
                    "coin": {"type": "string", "description": "CoinGecko coin ID (default: bitcoin)"},
                    "vs_currency": {"type": "string", "description": "Fiat currency (default: usd)"},
                    "days": {"type": "integer", "description": "Number of days (default: 7)"},
                    "interval": {"type": "string", "description": "Interval: daily, hourly (default: daily)"},
                },
            },
        ),
        Tool(
            name="portfolio_get_summary",
            description="Full portfolio summary across BTC and STX with USD valuations.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="portfolio_get_assets",
            description="List all assets (BTC, STX, tokens) with current balances.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="portfolio_get_collectibles",
            description="List all collectibles: Bitcoin inscriptions and Stacks NFTs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max items per chain (default: 20)"},
                },
            },
        ),
        # ===================================================================
        # Phase 5C: Ledger Hardware Wallet
        # ===================================================================
        Tool(
            name="ledger_get_addresses",
            description=(
                "Get BTC addresses from a connected Ledger device for all address "
                "types (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR). Requires Ledger "
                "connected via USB with the Bitcoin app open."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "account": {"type": "integer", "description": "Account index (default: 0)"},
                    "display": {
                        "type": "boolean",
                        "description": "If true, display address on device for verification",
                    },
                    "interface": {
                        "type": "string",
                        "enum": ["hid", "tcp"],
                        "description": "Connection: 'hid' for USB, 'tcp' for Speculos emulator (default: hid)",
                    },
                },
            },
        ),
        Tool(
            name="ledger_sign_psbt",
            description=(
                "Sign a PSBT using the Ledger Bitcoin app. Requires Ledger "
                "connected via USB with the Bitcoin app open. The PSBT must "
                "contain all necessary UTXO information."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "psbt": {"type": "string", "description": "Hex-encoded PSBT"},
                    "interface": {
                        "type": "string",
                        "enum": ["hid", "tcp"],
                        "description": "Connection type (default: hid)",
                    },
                },
                "required": ["psbt"],
            },
        ),
        Tool(
            name="ledger_get_stx_addresses",
            description=(
                "Get Stacks addresses from a connected Ledger device. "
                "Requires Ledger connected via USB with the Stacks app open."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "account": {"type": "integer", "description": "Account index (default: 0)"},
                    "display": {
                        "type": "boolean",
                        "description": "If true, display address on device for verification",
                    },
                    "interface": {
                        "type": "string",
                        "enum": ["hid", "tcp"],
                        "description": "Connection: 'hid' for USB, 'tcp' for Speculos emulator (default: hid)",
                    },
                },
            },
        ),
        Tool(
            name="ledger_sign_stx_transaction",
            description=(
                "Sign a Stacks transaction using the Ledger Stacks app. "
                "Requires Ledger connected via USB with the Stacks app open."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tx_hex": {"type": "string", "description": "Hex-encoded unsigned STX transaction"},
                    "derivation_path": {
                        "type": "string",
                        "description": "BIP-32 derivation path (default: m/44'/5757'/0'/0/0)",
                    },
                    "interface": {
                        "type": "string",
                        "enum": ["hid", "tcp"],
                        "description": "Connection type (default: hid)",
                    },
                },
                "required": ["tx_hex"],
            },
        ),
        # ===================================================================
        # Phase 5D: Inscription Creation & Onramp
        # ===================================================================
        Tool(
            name="ord_create_inscription",
            description=(
                "Create a new Bitcoin inscription. Builds the Ordinals envelope "
                "with content type and data, estimates commit/reveal fees. "
                "Supports text, JSON, images (hex-encoded), and any MIME type."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "content_type": {
                        "type": "string",
                        "description": "MIME type: text/plain, image/png, application/json, etc.",
                    },
                    "content": {
                        "type": "string",
                        "description": "Inscription content (text or hex for binary)",
                    },
                    "content_encoding": {
                        "type": "string",
                        "enum": ["utf-8", "hex"],
                        "description": "Content encoding: utf-8 for text, hex for binary (default: utf-8)",
                    },
                    "recipient": {
                        "type": "string",
                        "description": "Address to receive inscription (default: wallet taproot)",
                    },
                    "fee_rate": {"type": "integer", "description": "Fee rate in sat/vB"},
                    "dry_run": {"type": "boolean", "description": "If true, estimate only"},
                },
                "required": ["content_type", "content"],
            },
        ),
        Tool(
            name="ord_create_repeat_inscriptions",
            description=(
                "Create multiple inscriptions in batch. Each content item becomes "
                "a separate inscription. Returns envelopes and total fee estimates."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "content_type": {
                        "type": "string",
                        "description": "MIME type for all inscriptions",
                    },
                    "contents": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of content items (text or hex)",
                    },
                    "content_encoding": {
                        "type": "string",
                        "enum": ["utf-8", "hex"],
                        "description": "Content encoding (default: utf-8)",
                    },
                    "recipient": {"type": "string", "description": "Recipient address"},
                    "fee_rate": {"type": "integer", "description": "Fee rate in sat/vB"},
                    "dry_run": {"type": "boolean", "description": "If true, estimate only"},
                },
                "required": ["content_type", "contents"],
            },
        ),
        Tool(
            name="buy_get_providers",
            description="List available fiat-to-crypto onramp providers with supported currencies.",
            inputSchema={
                "type": "object",
                "properties": {
                    "crypto": {"type": "string", "description": "Filter by crypto (BTC, STX, ETH)"},
                    "fiat": {"type": "string", "description": "Filter by fiat (USD, EUR, GBP)"},
                },
            },
        ),
        Tool(
            name="buy_get_quote",
            description=(
                "Get a fiat-to-crypto buy quote with estimated amount and fees. "
                "Uses live market prices from CoinGecko."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "crypto": {"type": "string", "description": "Cryptocurrency: BTC, STX, ETH (default: BTC)"},
                    "fiat": {"type": "string", "description": "Fiat currency: USD, EUR (default: USD)"},
                    "fiat_amount": {"type": "number", "description": "Fiat amount to spend (default: 100)"},
                },
            },
        ),
        # ===================================================================
        # Phase 6: Hiro API Enhanced Integration
        # ===================================================================
        # -- 6.1 Enhanced Transaction Queries --
        Tool(
            name="stx_query_transactions",
            description=(
                "Query Stacks transactions for an address with advanced filtering. "
                "Filter by transaction type and include mempool transactions."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Stacks address (default: wallet address)"},
                    "limit": {"type": "integer", "description": "Max results (default: 50)"},
                    "offset": {"type": "integer", "description": "Pagination offset (default: 0)"},
                    "tx_type": {
                        "type": "string",
                        "enum": ["token_transfer", "contract_call", "smart_contract", "coinbase", "poison_microblock"],
                        "description": "Filter by transaction type",
                    },
                    "unanchored": {"type": "boolean", "description": "Include mempool/unconfirmed transactions (default: false)"},
                },
            },
        ),
        Tool(
            name="stx_query_transactions_by_contract",
            description=(
                "Query transactions that interacted with a specific smart contract. "
                "Optionally filter by called function name."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "contract_id": {"type": "string", "description": "Contract ID (e.g. SP...address.contract-name)"},
                    "function_name": {"type": "string", "description": "Filter by function name (optional)"},
                    "limit": {"type": "integer", "description": "Max results (default: 50)"},
                    "offset": {"type": "integer", "description": "Pagination offset (default: 0)"},
                },
                "required": ["contract_id"],
            },
        ),
        # -- 6.2 Mempool Operations --
        Tool(
            name="stx_mempool_list_pending",
            description=(
                "List pending mempool transactions. "
                "Optionally filter by address for address-specific pending txs."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Stacks address to filter by (optional, omit for global mempool)"},
                    "limit": {"type": "integer", "description": "Max results (default: 50)"},
                    "offset": {"type": "integer", "description": "Pagination offset (default: 0)"},
                },
            },
        ),
        Tool(
            name="stx_mempool_get_stats",
            description=(
                "Get Stacks mempool statistics including transaction counts by type, "
                "fee averages, ages, and byte sizes."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="stx_mempool_get_dropped",
            description=(
                "Get recently dropped mempool transactions. "
                "These were in the mempool but removed without being mined."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max results (default: 50)"},
                    "offset": {"type": "integer", "description": "Pagination offset (default: 0)"},
                },
            },
        ),
        # -- 6.3 Block Explorer --
        Tool(
            name="stx_get_recent_blocks",
            description="Get recent Stacks blocks with metadata.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Number of blocks (default: 20)"},
                    "offset": {"type": "integer", "description": "Pagination offset (default: 0)"},
                },
            },
        ),
        Tool(
            name="stx_get_block_by_height",
            description="Get a specific Stacks block by its height.",
            inputSchema={
                "type": "object",
                "properties": {
                    "height": {"type": "integer", "description": "Block height"},
                },
                "required": ["height"],
            },
        ),
        Tool(
            name="stx_get_block_by_hash",
            description="Get a specific Stacks block by its hash.",
            inputSchema={
                "type": "object",
                "properties": {
                    "block_hash": {"type": "string", "description": "Block hash (with or without 0x prefix)"},
                },
                "required": ["block_hash"],
            },
        ),
        Tool(
            name="stx_get_stacks_blocks_for_bitcoin_block",
            description=(
                "Get all Stacks blocks produced during a specific Bitcoin block. "
                "Maps Bitcoin block height to corresponding Stacks blocks."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "bitcoin_height": {"type": "integer", "description": "Bitcoin block height"},
                    "limit": {"type": "integer", "description": "Max results (default: 20)"},
                    "offset": {"type": "integer", "description": "Pagination offset (default: 0)"},
                },
                "required": ["bitcoin_height"],
            },
        ),
        # -- 6.4 Contract Event Monitoring --
        Tool(
            name="stx_get_contract_events",
            description=(
                "Get event history for a smart contract. "
                "Returns print events, FT/NFT events, and STX events."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "contract_id": {"type": "string", "description": "Contract ID (e.g. SP...address.contract-name)"},
                    "limit": {"type": "integer", "description": "Max results (default: 50)"},
                    "offset": {"type": "integer", "description": "Pagination offset (default: 0)"},
                },
                "required": ["contract_id"],
            },
        ),
        Tool(
            name="stx_get_address_asset_events",
            description=(
                "Get asset events for an address. "
                "Returns FT transfers, NFT transfers, and STX transfers."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Stacks address (default: wallet address)"},
                    "limit": {"type": "integer", "description": "Max results (default: 50)"},
                    "offset": {"type": "integer", "description": "Pagination offset (default: 0)"},
                },
            },
        ),
        # -- 6.5 Token Metadata --
        Tool(
            name="stx_get_token_metadata",
            description=(
                "Get metadata for a SIP-10 fungible or SIP-9 non-fungible token. "
                "Returns name, symbol, decimals, total supply, description, and image."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "contract_id": {"type": "string", "description": "Token contract ID (e.g. SP...address.contract-name)"},
                    "token_type": {
                        "type": "string",
                        "enum": ["ft", "nft"],
                        "description": "Token type: ft (fungible) or nft (non-fungible). Default: ft",
                    },
                },
                "required": ["contract_id"],
            },
        ),
        Tool(
            name="stx_get_token_holders",
            description="Get holder addresses and balances for a fungible token.",
            inputSchema={
                "type": "object",
                "properties": {
                    "contract_id": {"type": "string", "description": "Token contract ID (e.g. SP...address.contract-name)"},
                    "limit": {"type": "integer", "description": "Max results (default: 50)"},
                    "offset": {"type": "integer", "description": "Pagination offset (default: 0)"},
                },
                "required": ["contract_id"],
            },
        ),
        # -- 6.6 Network Statistics & Health --
        Tool(
            name="stx_get_network_info",
            description=(
                "Get core Stacks network information including peer version, "
                "burn block height, server version, and chain tip."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="stx_get_network_status",
            description="Get Stacks blockchain sync status and chain tip details.",
            inputSchema={"type": "object", "properties": {}},
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

        # =================================================================
        # Phase 3: Ordinals & Inscriptions
        # =================================================================
        if name == "ord_get_inscriptions":
            return await _handle_ord_get_inscriptions(arguments)
        if name == "ord_get_inscription_details":
            return await _handle_ord_get_inscription_details(arguments)
        if name == "ord_send_inscriptions":
            return await _handle_ord_send_inscriptions(arguments)
        if name == "ord_send_inscriptions_split":
            return await _handle_ord_send_inscriptions_split(arguments)
        if name == "ord_extract_from_utxo":
            return await _handle_ord_extract_from_utxo(arguments)
        if name == "ord_recover_bitcoin":
            return await _handle_ord_recover_bitcoin(arguments)
        if name == "ord_recover_ordinals":
            return await _handle_ord_recover_ordinals(arguments)

        # =================================================================
        # Phase 4: Swaps, DeFi & Bridge
        # =================================================================
        if name == "swap_get_supported_pairs":
            return await _handle_swap_get_supported_pairs()
        if name == "swap_get_quote":
            return await _handle_swap_get_quote(arguments)
        if name == "swap_execute":
            return await _handle_swap_execute(arguments)
        if name == "swap_get_history":
            return await _handle_swap_get_history(arguments)
        if name == "sbtc_get_balance":
            return await _handle_sbtc_get_balance()
        if name == "sbtc_bridge_deposit":
            return await _handle_sbtc_bridge_deposit(arguments)
        if name == "sbtc_bridge_withdraw":
            return await _handle_sbtc_bridge_withdraw(arguments)
        if name == "stx_get_stacking_info":
            return await _handle_stx_get_stacking_info()
        if name == "stx_stack":
            return await _handle_stx_stack(arguments)
        if name == "stx_revoke_delegation":
            return await _handle_stx_revoke_delegation(arguments)

        # =================================================================
        # Phase 5A: Transaction Management & Wallet
        # =================================================================
        if name == "tx_get_history":
            return await _handle_tx_get_history(arguments)
        if name == "tx_get_status":
            return await _handle_tx_get_status(arguments)
        if name == "tx_speed_up":
            return await _handle_tx_speed_up(arguments)
        if name == "tx_cancel":
            return await _handle_tx_cancel(arguments)
        if name == "wallet_get_network":
            return await _handle_wallet_get_network()
        if name == "wallet_switch_network":
            return await _handle_wallet_switch_network(arguments)
        if name == "wallet_add_network":
            return await _handle_wallet_add_network(arguments)
        if name == "wallet_get_supported_methods":
            return await _handle_wallet_get_supported_methods()

        # =================================================================
        # Phase 5B: BNS & Market Data
        # =================================================================
        if name == "bns_lookup":
            return await _handle_bns_lookup(arguments)
        if name == "bns_get_names":
            return await _handle_bns_get_names(arguments)
        if name == "bns_register":
            return await _handle_bns_register(arguments)
        if name == "market_get_prices":
            return await _handle_market_get_prices(arguments)
        if name == "market_get_history":
            return await _handle_market_get_history(arguments)
        if name == "portfolio_get_summary":
            return await _handle_portfolio_get_summary()
        if name == "portfolio_get_assets":
            return await _handle_portfolio_get_assets()
        if name == "portfolio_get_collectibles":
            return await _handle_portfolio_get_collectibles(arguments)

        # =================================================================
        # Phase 5C: Ledger Hardware Wallet
        # =================================================================
        if name == "ledger_get_addresses":
            return await _handle_ledger_get_addresses(arguments)
        if name == "ledger_sign_psbt":
            return await _handle_ledger_sign_psbt(arguments)
        if name == "ledger_get_stx_addresses":
            return await _handle_ledger_get_stx_addresses(arguments)
        if name == "ledger_sign_stx_transaction":
            return await _handle_ledger_sign_stx_transaction(arguments)

        # =================================================================
        # Phase 5D: Inscription Creation & Onramp
        # =================================================================
        if name == "ord_create_inscription":
            return await _handle_ord_create_inscription(arguments)
        if name == "ord_create_repeat_inscriptions":
            return await _handle_ord_create_repeat_inscriptions(arguments)
        if name == "buy_get_providers":
            return await _handle_buy_get_providers(arguments)
        if name == "buy_get_quote":
            return await _handle_buy_get_quote(arguments)

        # =================================================================
        # Phase 6: Hiro API Enhanced Integration
        # =================================================================

        # 6.1 Enhanced Transaction Queries
        if name == "stx_query_transactions":
            return await _handle_stx_query_transactions(arguments)
        if name == "stx_query_transactions_by_contract":
            return await _handle_stx_query_transactions_by_contract(arguments)

        # 6.2 Mempool Operations
        if name == "stx_mempool_list_pending":
            return await _handle_stx_mempool_list_pending(arguments)
        if name == "stx_mempool_get_stats":
            return await _handle_stx_mempool_get_stats()
        if name == "stx_mempool_get_dropped":
            return await _handle_stx_mempool_get_dropped(arguments)

        # 6.3 Block Explorer
        if name == "stx_get_recent_blocks":
            return await _handle_stx_get_recent_blocks(arguments)
        if name == "stx_get_block_by_height":
            return await _handle_stx_get_block_by_height(arguments)
        if name == "stx_get_block_by_hash":
            return await _handle_stx_get_block_by_hash(arguments)
        if name == "stx_get_stacks_blocks_for_bitcoin_block":
            return await _handle_stx_get_stacks_blocks_for_bitcoin_block(arguments)

        # 6.4 Contract Event Monitoring
        if name == "stx_get_contract_events":
            return await _handle_stx_get_contract_events(arguments)
        if name == "stx_get_address_asset_events":
            return await _handle_stx_get_address_asset_events(arguments)

        # 6.5 Token Metadata
        if name == "stx_get_token_metadata":
            return await _handle_stx_get_token_metadata(arguments)
        if name == "stx_get_token_holders":
            return await _handle_stx_get_token_holders(arguments)

        # 6.6 Network Statistics & Health
        if name == "stx_get_network_info":
            return await _handle_stx_get_network_info()
        if name == "stx_get_network_status":
            return await _handle_stx_get_network_status()

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
        accounts = await asyncio.to_thread(get_accounts, cfg)
        
        # Aggregate wallet-wide balance from all accounts
        total_confirmed_sats = sum(acc.get("confirmed_sats", 0) for acc in accounts)
        total_unconfirmed_sats = sum(acc.get("unconfirmed_sats", 0) for acc in accounts)
        total_sats = total_confirmed_sats + total_unconfirmed_sats
        
        balance_btc = Decimal(total_sats) / Decimal("1e8")
        confirmed_btc = Decimal(total_confirmed_sats) / Decimal("1e8")
        unconfirmed_btc = Decimal(total_unconfirmed_sats) / Decimal("1e8")
        
        result = {
            "success": True,
            "balance_btc": str(balance_btc),
            "confirmed_btc": str(confirmed_btc),
            "unconfirmed_btc": str(unconfirmed_btc),
            "balance_sats": total_sats,
            "confirmed_sats": total_confirmed_sats,
            "unconfirmed_sats": total_unconfirmed_sats,
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
        usd_price, eur_price = await asyncio.to_thread(_fetch_btc_prices)
        fee_btc = Decimal(preview.fee_sats_estimate) / Decimal("1e8")
        result = {
            "success": True,
            "from_address": preview.from_address,
            "to_address": preview.to_address,
            "amount_btc": str(preview.amount_btc),
            "amount_usd": float(preview.amount_btc * usd_price),
            "amount_eur": float(preview.amount_btc * eur_price),
            "fee_sats_estimate": preview.fee_sats_estimate,
            "fee_rate_sat_per_vb": preview.fee_rate_sat_per_vb,
            "fee_usd": float(fee_btc * usd_price),
            "fee_eur": float(fee_btc * eur_price),
            "total_spend_btc": str(preview.total_spend_btc),
            "total_spend_usd": float(preview.total_spend_btc * usd_price),
            "total_spend_eur": float(preview.total_spend_btc * eur_price),
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

        send_result = await asyncio.to_thread(
            send_transaction,
            cfg,
            to_address,
            amount_btc,
            max_fee_sats,
            memo,
            dry_run,
        )
        usd_price, eur_price = await asyncio.to_thread(_fetch_btc_prices)
        fee_btc = Decimal(send_result["fee_sats_estimate"]) / Decimal("1e8")
        result = {
            "success": True,
            "txid": send_result["txid"],
            "amount_btc": str(amount_btc),
            "amount_usd": float(amount_btc * usd_price),
            "amount_eur": float(amount_btc * eur_price),
            "fee_rate_sat_per_vb": send_result["fee_rate_sat_per_vb"],
            "fee_sats_estimate": send_result["fee_sats_estimate"],
            "fee_usd": float(fee_btc * usd_price),
            "fee_eur": float(fee_btc * eur_price),
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


# ===========================================================================
# Phase 3 Handlers -- Ordinals & Inscriptions
# ===========================================================================


async def _handle_ord_get_inscriptions(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    offset = arguments.get("offset", 0)
    limit = arguments.get("limit", 20)
    address = (arguments.get("address") or "").strip() or None
    result = await asyncio.to_thread(ord_get_inscriptions, cfg, offset, limit, address)
    return _ok_response(result)


async def _handle_ord_get_inscription_details(arguments: dict[str, Any]) -> List[TextContent]:
    inscription_id = (arguments.get("inscription_id") or "").strip()
    if not inscription_id:
        return _error_response("Missing 'inscription_id' parameter.")
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    result = await asyncio.to_thread(ord_get_inscription_details, cfg, inscription_id)
    return _ok_response(result)


async def _handle_ord_send_inscriptions(arguments: dict[str, Any]) -> List[TextContent]:
    transfers = arguments.get("transfers")
    if not transfers or not isinstance(transfers, list):
        return _error_response("Missing or invalid 'transfers' array.")
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    fee_rate = arguments.get("fee_rate")
    dry_run = arguments.get("dry_run")
    result = await asyncio.to_thread(ord_send_inscriptions, cfg, transfers, fee_rate, dry_run)
    return _ok_response(result)


async def _handle_ord_send_inscriptions_split(arguments: dict[str, Any]) -> List[TextContent]:
    transfers = arguments.get("transfers")
    if not transfers or not isinstance(transfers, list):
        return _error_response("Missing or invalid 'transfers' array.")
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    fee_rate = arguments.get("fee_rate")
    dry_run = arguments.get("dry_run")
    result = await asyncio.to_thread(ord_send_inscriptions_split, cfg, transfers, fee_rate, dry_run)
    return _ok_response(result)


async def _handle_ord_extract_from_utxo(arguments: dict[str, Any]) -> List[TextContent]:
    outpoint = (arguments.get("outpoint") or "").strip()
    if not outpoint:
        return _error_response("Missing 'outpoint' parameter.")
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    fee_rate = arguments.get("fee_rate")
    dry_run = arguments.get("dry_run")
    result = await asyncio.to_thread(ord_extract_from_utxo, cfg, outpoint, fee_rate, dry_run)
    return _ok_response(result)


async def _handle_ord_recover_bitcoin(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    outpoint = (arguments.get("outpoint") or "").strip() or None
    fee_rate = arguments.get("fee_rate")
    dry_run = arguments.get("dry_run")
    result = await asyncio.to_thread(ord_recover_bitcoin, cfg, outpoint, fee_rate, dry_run)
    return _ok_response(result)


async def _handle_ord_recover_ordinals(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    outpoint = (arguments.get("outpoint") or "").strip() or None
    fee_rate = arguments.get("fee_rate")
    dry_run = arguments.get("dry_run")
    result = await asyncio.to_thread(ord_recover_ordinals, cfg, outpoint, fee_rate, dry_run)
    return _ok_response(result)


# ===========================================================================
# Phase 4 Handlers -- Swaps, DeFi & Bridge
# ===========================================================================


async def _handle_swap_get_supported_pairs() -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(swap_get_supported_pairs, cfg)
    return _ok_response(result)


async def _handle_swap_get_quote(arguments: dict[str, Any]) -> List[TextContent]:
    token_in = (arguments.get("token_in") or "").strip()
    token_out = (arguments.get("token_out") or "").strip()
    amount = arguments.get("amount")
    if not token_in:
        return _error_response("Missing 'token_in' parameter.")
    if not token_out:
        return _error_response("Missing 'token_out' parameter.")
    if amount is None:
        return _error_response("Missing 'amount' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    protocol = arguments.get("protocol", "alex")
    result = await asyncio.to_thread(swap_get_quote, cfg, token_in, token_out, int(amount), protocol)
    return _ok_response(result)


async def _handle_swap_execute(arguments: dict[str, Any]) -> List[TextContent]:
    token_in = (arguments.get("token_in") or "").strip()
    token_out = (arguments.get("token_out") or "").strip()
    amount = arguments.get("amount")
    if not token_in:
        return _error_response("Missing 'token_in' parameter.")
    if not token_out:
        return _error_response("Missing 'token_out' parameter.")
    if amount is None:
        return _error_response("Missing 'amount' parameter.")

    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        swap_execute, cfg, token_in, token_out, int(amount),
        arguments.get("min_output"), arguments.get("protocol", "alex"),
        arguments.get("dry_run"),
    )
    if isinstance(result, dict) and result.get("ok") is False:
        return _error_response(result.get("error", "Swap execution failed."))
    return _ok_response(result)


async def _handle_swap_get_history(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    limit = arguments.get("limit", 20)
    offset = arguments.get("offset", 0)
    result = await asyncio.to_thread(swap_get_history, cfg, limit, offset)
    return _ok_response(result)


async def _handle_sbtc_get_balance() -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(sbtc_get_balance, cfg)
    return _ok_response(result)


async def _handle_sbtc_bridge_deposit(arguments: dict[str, Any]) -> List[TextContent]:
    amount_sats = arguments.get("amount_sats")
    if amount_sats is None:
        return _error_response("Missing 'amount_sats' parameter.")
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(sbtc_bridge_deposit, cfg, int(amount_sats), arguments.get("dry_run"))
    return _ok_response(result)


async def _handle_sbtc_bridge_withdraw(arguments: dict[str, Any]) -> List[TextContent]:
    amount_sats = arguments.get("amount_sats")
    btc_address = (arguments.get("btc_address") or "").strip()
    if amount_sats is None:
        return _error_response("Missing 'amount_sats' parameter.")
    if not btc_address:
        return _error_response("Missing 'btc_address' parameter.")
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(sbtc_bridge_withdraw, cfg, int(amount_sats), btc_address, arguments.get("dry_run"))
    return _ok_response(result)


async def _handle_stx_get_stacking_info() -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(stx_get_stacking_info, cfg)
    return _ok_response(result)


async def _handle_stx_stack(arguments: dict[str, Any]) -> List[TextContent]:
    amount_ustx = arguments.get("amount_ustx")
    pox_address = (arguments.get("pox_address") or "").strip()
    if amount_ustx is None:
        return _error_response("Missing 'amount_ustx' parameter.")
    if not pox_address:
        return _error_response("Missing 'pox_address' parameter.")
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_stack, cfg, int(amount_ustx), pox_address,
        arguments.get("num_cycles", 1), arguments.get("dry_run"),
    )
    return _ok_response(result)


async def _handle_stx_revoke_delegation(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(stx_revoke_delegation, cfg, arguments.get("dry_run"))
    return _ok_response(result)


# ===========================================================================
# Phase 5A Handlers -- Transaction Management & Wallet
# ===========================================================================


async def _handle_tx_get_history(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    chain = arguments.get("chain", "both")
    limit = arguments.get("limit", 20)
    offset = arguments.get("offset", 0)
    result = await asyncio.to_thread(tx_get_history, cfg, chain, limit, offset)
    return _ok_response(result)


async def _handle_tx_get_status(arguments: dict[str, Any]) -> List[TextContent]:
    txid = (arguments.get("txid") or "").strip()
    if not txid:
        return _error_response("Missing 'txid' parameter.")
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    chain = arguments.get("chain", "btc")
    result = await asyncio.to_thread(tx_get_status, cfg, txid, chain)
    return _ok_response(result)


async def _handle_tx_speed_up(arguments: dict[str, Any]) -> List[TextContent]:
    txid = (arguments.get("txid") or "").strip()
    if not txid:
        return _error_response("Missing 'txid' parameter.")
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    result = await asyncio.to_thread(
        tx_speed_up, cfg, txid, arguments.get("new_fee_rate"), arguments.get("dry_run")
    )
    return _ok_response(result)


async def _handle_tx_cancel(arguments: dict[str, Any]) -> List[TextContent]:
    txid = (arguments.get("txid") or "").strip()
    if not txid:
        return _error_response("Missing 'txid' parameter.")
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    result = await asyncio.to_thread(
        tx_cancel, cfg, txid, arguments.get("fee_rate"), arguments.get("dry_run")
    )
    return _ok_response(result)


async def _handle_wallet_get_network() -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    result = await asyncio.to_thread(wallet_get_network, cfg)
    return _ok_response(result)


async def _handle_wallet_switch_network(arguments: dict[str, Any]) -> List[TextContent]:
    network = (arguments.get("network") or "").strip()
    if not network:
        return _error_response("Missing 'network' parameter.")
    result = await asyncio.to_thread(wallet_switch_network, network)
    return _ok_response(result)


async def _handle_wallet_add_network(arguments: dict[str, Any]) -> List[TextContent]:
    name = (arguments.get("name") or "").strip()
    if not name:
        return _error_response("Missing 'name' parameter.")
    result = await asyncio.to_thread(
        wallet_add_network, name, arguments.get("btc_api_url"), arguments.get("stx_api_url")
    )
    return _ok_response(result)


async def _handle_wallet_get_supported_methods() -> List[TextContent]:
    # Introspect the tool list
    tools = await list_tools()
    methods = [{"name": t.name, "description": t.description} for t in tools]
    return _ok_response({"methods": methods, "count": len(methods)})


# ===========================================================================
# Phase 5B Handlers -- BNS & Market Data
# ===========================================================================


async def _handle_bns_lookup(arguments: dict[str, Any]) -> List[TextContent]:
    name = (arguments.get("name") or "").strip()
    if not name:
        return _error_response("Missing 'name' parameter.")
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(bns_lookup, cfg, name)
    return _ok_response(result)


async def _handle_bns_get_names(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    address = (arguments.get("address") or "").strip() or None
    result = await asyncio.to_thread(bns_get_names, cfg, address)
    return _ok_response(result)


async def _handle_bns_register(arguments: dict[str, Any]) -> List[TextContent]:
    name = (arguments.get("name") or "").strip()
    if not name:
        return _error_response("Missing 'name' parameter.")
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        bns_register, cfg, name, arguments.get("namespace", "btc"),
        arguments.get("fee"), arguments.get("dry_run"),
    )
    return _ok_response(result)


async def _handle_market_get_prices(arguments: dict[str, Any]) -> List[TextContent]:
    coins = arguments.get("coins")
    vs_currencies = arguments.get("vs_currencies")
    result = await asyncio.to_thread(market_get_prices, coins, vs_currencies)
    return _ok_response(result)


async def _handle_market_get_history(arguments: dict[str, Any]) -> List[TextContent]:
    result = await asyncio.to_thread(
        market_get_history,
        arguments.get("coin", "bitcoin"),
        arguments.get("vs_currency", "usd"),
        arguments.get("days", 7),
        arguments.get("interval", "daily"),
    )
    return _ok_response(result)


async def _handle_portfolio_get_summary() -> List[TextContent]:
    btc_cfg = await asyncio.to_thread(BTCConfig.from_env)
    stx_cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(portfolio_get_summary, btc_cfg, stx_cfg)
    return _ok_response(result)


async def _handle_portfolio_get_assets() -> List[TextContent]:
    btc_cfg = await asyncio.to_thread(BTCConfig.from_env)
    stx_cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(portfolio_get_assets, btc_cfg, stx_cfg)
    return _ok_response(result)


async def _handle_portfolio_get_collectibles(arguments: dict[str, Any]) -> List[TextContent]:
    btc_cfg = await asyncio.to_thread(BTCConfig.from_env)
    stx_cfg = await asyncio.to_thread(STXConfig.from_env)
    limit = arguments.get("limit", 20)
    result = await asyncio.to_thread(portfolio_get_collectibles, btc_cfg, stx_cfg, limit)
    return _ok_response(result)


# ===========================================================================
# Phase 5C Handlers -- Ledger Hardware Wallet
# ===========================================================================


async def _handle_ledger_get_addresses(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    account = arguments.get("account", 0)
    display = arguments.get("display", False)
    interface = arguments.get("interface", "hid")
    result = await asyncio.to_thread(
        ledger_get_addresses, cfg.network, account, display, interface
    )
    return _ok_response(result)


async def _handle_ledger_sign_psbt(arguments: dict[str, Any]) -> List[TextContent]:
    psbt = (arguments.get("psbt") or "").strip()
    if not psbt:
        return _error_response("Missing 'psbt' parameter.")
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    interface = arguments.get("interface", "hid")
    result = await asyncio.to_thread(ledger_sign_psbt, psbt, cfg.network, interface)
    return _ok_response(result)


async def _handle_ledger_get_stx_addresses(arguments: dict[str, Any]) -> List[TextContent]:
    account = arguments.get("account", 0)
    display = arguments.get("display", False)
    interface = arguments.get("interface", "hid")
    result = await asyncio.to_thread(
        ledger_get_stx_addresses, account, display, interface
    )
    return _ok_response(result)


async def _handle_ledger_sign_stx_transaction(arguments: dict[str, Any]) -> List[TextContent]:
    tx_hex = (arguments.get("tx_hex") or "").strip()
    if not tx_hex:
        return _error_response("Missing 'tx_hex' parameter.")
    derivation_path = arguments.get("derivation_path", "m/44'/5757'/0'/0/0")
    interface = arguments.get("interface", "hid")
    result = await asyncio.to_thread(
        ledger_sign_stx_transaction, tx_hex, derivation_path, interface
    )
    return _ok_response(result)


# ===========================================================================
# Phase 5D Handlers -- Inscription Creation & Onramp
# ===========================================================================


async def _handle_ord_create_inscription(arguments: dict[str, Any]) -> List[TextContent]:
    content_type = (arguments.get("content_type") or "").strip()
    content = arguments.get("content", "")
    if not content_type:
        return _error_response("Missing 'content_type' parameter.")
    if not content:
        return _error_response("Missing 'content' parameter.")

    cfg = await asyncio.to_thread(BTCConfig.from_env)
    result = await asyncio.to_thread(
        ord_create_inscription, cfg,
        content_type, content,
        arguments.get("content_encoding", "utf-8"),
        (arguments.get("recipient") or "").strip() or None,
        arguments.get("fee_rate"),
        arguments.get("dry_run"),
    )
    return _ok_response(result)


async def _handle_ord_create_repeat_inscriptions(arguments: dict[str, Any]) -> List[TextContent]:
    content_type = (arguments.get("content_type") or "").strip()
    contents = arguments.get("contents")
    if not content_type:
        return _error_response("Missing 'content_type' parameter.")
    if not contents or not isinstance(contents, list):
        return _error_response("Missing or invalid 'contents' array.")

    cfg = await asyncio.to_thread(BTCConfig.from_env)
    result = await asyncio.to_thread(
        ord_create_repeat_inscriptions, cfg,
        content_type, contents,
        arguments.get("content_encoding", "utf-8"),
        (arguments.get("recipient") or "").strip() or None,
        arguments.get("fee_rate"),
        arguments.get("dry_run"),
    )
    return _ok_response(result)


async def _handle_buy_get_providers(arguments: dict[str, Any]) -> List[TextContent]:
    crypto = (arguments.get("crypto") or "").strip() or None
    fiat = (arguments.get("fiat") or "").strip() or None
    result = await asyncio.to_thread(buy_get_providers, crypto, fiat)
    return _ok_response(result)


async def _handle_buy_get_quote(arguments: dict[str, Any]) -> List[TextContent]:
    crypto = arguments.get("crypto", "BTC")
    fiat = arguments.get("fiat", "USD")
    fiat_amount = arguments.get("fiat_amount", 100.0)
    result = await asyncio.to_thread(buy_get_quote, crypto, fiat, float(fiat_amount))
    return _ok_response(result)


# ===========================================================================
# Phase 6 Handlers -- Hiro API Enhanced Integration
# ===========================================================================


# -- 6.1 Enhanced Transaction Queries --


async def _handle_stx_query_transactions(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    result = await asyncio.to_thread(
        stx_query_transactions,
        cfg,
        address=(arguments.get("address") or "").strip() or None,
        limit=arguments.get("limit", 50),
        offset=arguments.get("offset", 0),
        tx_type=(arguments.get("tx_type") or "").strip() or None,
        unanchored=arguments.get("unanchored", False),
    )
    return _ok_response(result)


async def _handle_stx_query_transactions_by_contract(arguments: dict[str, Any]) -> List[TextContent]:
    contract_id = (arguments.get("contract_id") or "").strip()
    if not contract_id:
        return _error_response("Missing 'contract_id' parameter.")
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    result = await asyncio.to_thread(
        stx_query_transactions_by_contract,
        cfg,
        contract_id=contract_id,
        function_name=(arguments.get("function_name") or "").strip() or None,
        limit=arguments.get("limit", 50),
        offset=arguments.get("offset", 0),
    )
    return _ok_response(result)


# -- 6.2 Mempool Operations --


async def _handle_stx_mempool_list_pending(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_mempool_list_pending,
        cfg,
        address=(arguments.get("address") or "").strip() or None,
        limit=arguments.get("limit", 50),
        offset=arguments.get("offset", 0),
    )
    return _ok_response(result)


async def _handle_stx_mempool_get_stats() -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(stx_mempool_get_stats, cfg)
    return _ok_response(result)


async def _handle_stx_mempool_get_dropped(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_mempool_get_dropped,
        cfg,
        limit=arguments.get("limit", 50),
        offset=arguments.get("offset", 0),
    )
    return _ok_response(result)


# -- 6.3 Block Explorer --


async def _handle_stx_get_recent_blocks(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_get_recent_blocks,
        cfg,
        limit=arguments.get("limit", 20),
        offset=arguments.get("offset", 0),
    )
    return _ok_response(result)


async def _handle_stx_get_block_by_height(arguments: dict[str, Any]) -> List[TextContent]:
    height = arguments.get("height")
    if height is None:
        return _error_response("Missing 'height' parameter.")
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(stx_get_block_by_height, cfg, int(height))
    return _ok_response(result)


async def _handle_stx_get_block_by_hash(arguments: dict[str, Any]) -> List[TextContent]:
    block_hash = (arguments.get("block_hash") or "").strip()
    if not block_hash:
        return _error_response("Missing 'block_hash' parameter.")
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(stx_get_block_by_hash, cfg, block_hash)
    return _ok_response(result)


async def _handle_stx_get_stacks_blocks_for_bitcoin_block(arguments: dict[str, Any]) -> List[TextContent]:
    bitcoin_height = arguments.get("bitcoin_height")
    if bitcoin_height is None:
        return _error_response("Missing 'bitcoin_height' parameter.")
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_get_stacks_blocks_for_bitcoin_block,
        cfg,
        int(bitcoin_height),
        limit=arguments.get("limit", 20),
        offset=arguments.get("offset", 0),
    )
    return _ok_response(result)


# -- 6.4 Contract Event Monitoring --


async def _handle_stx_get_contract_events(arguments: dict[str, Any]) -> List[TextContent]:
    contract_id = (arguments.get("contract_id") or "").strip()
    if not contract_id:
        return _error_response("Missing 'contract_id' parameter.")
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_get_contract_events,
        cfg,
        contract_id=contract_id,
        limit=arguments.get("limit", 50),
        offset=arguments.get("offset", 0),
    )
    return _ok_response(result)


async def _handle_stx_get_address_asset_events(arguments: dict[str, Any]) -> List[TextContent]:
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_get_address_asset_events,
        cfg,
        address=(arguments.get("address") or "").strip() or None,
        limit=arguments.get("limit", 50),
        offset=arguments.get("offset", 0),
    )
    return _ok_response(result)


# -- 6.5 Token Metadata --


async def _handle_stx_get_token_metadata(arguments: dict[str, Any]) -> List[TextContent]:
    contract_id = (arguments.get("contract_id") or "").strip()
    if not contract_id:
        return _error_response("Missing 'contract_id' parameter.")
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_get_token_metadata,
        cfg,
        contract_id=contract_id,
        token_type=arguments.get("token_type", "ft"),
    )
    return _ok_response(result)


async def _handle_stx_get_token_holders(arguments: dict[str, Any]) -> List[TextContent]:
    contract_id = (arguments.get("contract_id") or "").strip()
    if not contract_id:
        return _error_response("Missing 'contract_id' parameter.")
    cfg = await asyncio.to_thread(STXConfig.from_env)
    result = await asyncio.to_thread(
        stx_get_token_holders,
        cfg,
        contract_id=contract_id,
        limit=arguments.get("limit", 50),
        offset=arguments.get("offset", 0),
    )
    return _ok_response(result)


# -- 6.6 Network Statistics & Health --


async def _handle_stx_get_network_info() -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    result = await asyncio.to_thread(stx_get_network_info, cfg)
    return _ok_response(result)


async def _handle_stx_get_network_status() -> List[TextContent]:
    cfg = await asyncio.to_thread(BTCConfig.from_env)
    result = await asyncio.to_thread(stx_get_network_status, cfg)
    return _ok_response(result)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
