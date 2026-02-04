#!/usr/bin/env python3
"""
MCP server for Bitcoin wallet operations.

Wraps execution/scripts/btc_wallet.py as MCP tools.
"""

from __future__ import annotations

import asyncio
import json
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, List

from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "execution" / "scripts"))
load_dotenv(REPO_ROOT / ".env")

from btc_wallet import (  # noqa: E402
    BTCConfig,
    _fetch_btc_prices,
    build_transaction_preview,
    get_balance_btc,
    send_transaction,
)

app = Server("btc_wallet")


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


@app.list_tools()
async def list_tools() -> List[Tool]:
    return [
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
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> List[TextContent]:
    if not isinstance(arguments, dict):
        return _error_response("Invalid arguments. Expected an object.")

    if name == "btc_wallet_get_balance":
        return await _handle_get_balance()
    if name == "btc_wallet_get_prices":
        return await _handle_get_prices()
    if name == "btc_wallet_preview_transfer":
        return await _handle_preview_transfer(arguments)
    if name == "btc_wallet_send_transfer":
        return await _handle_send_transfer(arguments)

    return _error_response(f"Unknown tool: {name}")


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


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
