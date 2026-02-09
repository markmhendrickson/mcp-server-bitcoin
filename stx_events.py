"""
Stacks contract event monitoring for Hiro API integration.

Implements:
- Contract event history (print events, FT/NFT events)
- Address asset events (FT/NFT transfers)
"""

from __future__ import annotations

from typing import Any

import requests

from stx_wallet import STXConfig


# ---------------------------------------------------------------------------
# Hiro API helpers
# ---------------------------------------------------------------------------


def _hiro_get(cfg: STXConfig, path: str, params: dict | None = None) -> Any:
    """GET request to Hiro Stacks API."""
    url = f"{cfg.hiro_api_url}{path}"
    resp = requests.get(url, params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Contract events
# ---------------------------------------------------------------------------


def stx_get_contract_events(
    cfg: STXConfig,
    contract_id: str,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Get event history for a specific smart contract.

    Returns print events, fungible token events, non-fungible token events,
    and STX lock events emitted by the contract.
    """
    try:
        data = _hiro_get(
            cfg,
            f"/extended/v1/contract/{contract_id}/events",
            params={"limit": limit, "offset": offset},
        )
    except Exception as exc:
        raise RuntimeError(
            f"Failed to fetch events for {contract_id}: {exc}"
        ) from exc

    events = []
    for event in data.get("results", []):
        parsed = {
            "event_index": event.get("event_index"),
            "event_type": event.get("event_type", ""),
            "tx_id": event.get("tx_id", ""),
        }

        # Parse type-specific data
        event_type = event.get("event_type", "")
        if event_type == "smart_contract_log":
            log = event.get("contract_log", {})
            parsed["contract_id"] = log.get("contract_id", "")
            parsed["topic"] = log.get("topic", "")
            parsed["value"] = log.get("value", {}).get("repr", "")
        elif event_type == "fungible_token_asset":
            asset = event.get("asset", {})
            parsed["asset_event_type"] = asset.get("asset_event_type", "")
            parsed["asset_id"] = asset.get("asset_id", "")
            parsed["sender"] = asset.get("sender", "")
            parsed["recipient"] = asset.get("recipient", "")
            parsed["amount"] = asset.get("amount", "0")
        elif event_type == "non_fungible_token_asset":
            asset = event.get("asset", {})
            parsed["asset_event_type"] = asset.get("asset_event_type", "")
            parsed["asset_id"] = asset.get("asset_id", "")
            parsed["sender"] = asset.get("sender", "")
            parsed["recipient"] = asset.get("recipient", "")
            parsed["value"] = asset.get("value", {}).get("repr", "")
        elif event_type == "stx_asset":
            asset = event.get("asset", {})
            parsed["asset_event_type"] = asset.get("asset_event_type", "")
            parsed["sender"] = asset.get("sender", "")
            parsed["recipient"] = asset.get("recipient", "")
            parsed["amount"] = asset.get("amount", "0")

        events.append(parsed)

    return {
        "contract_id": contract_id,
        "events": events,
        "total": data.get("total", len(events)),
        "limit": limit,
        "offset": offset,
        "network": cfg.network,
    }


# ---------------------------------------------------------------------------
# Address asset events
# ---------------------------------------------------------------------------


def stx_get_address_asset_events(
    cfg: STXConfig,
    address: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Get asset events for an address.

    Returns FT transfers, NFT transfers, and STX transfers involving the address.
    """
    addr = address or cfg.stx_address

    try:
        data = _hiro_get(
            cfg,
            f"/extended/v1/address/{addr}/assets",
            params={"limit": limit, "offset": offset},
        )
    except Exception as exc:
        raise RuntimeError(
            f"Failed to fetch asset events for {addr}: {exc}"
        ) from exc

    events = []
    for event in data.get("results", []):
        parsed = {
            "event_index": event.get("event_index"),
            "event_type": event.get("event_type", ""),
            "tx_id": event.get("tx_id", ""),
            "block_height": event.get("block_height"),
        }

        asset = event.get("asset", {})
        if asset:
            parsed["asset_event_type"] = asset.get("asset_event_type", "")
            parsed["asset_id"] = asset.get("asset_id", "")
            parsed["sender"] = asset.get("sender", "")
            parsed["recipient"] = asset.get("recipient", "")
            parsed["amount"] = asset.get("amount", asset.get("value", {}).get("repr", ""))

        events.append(parsed)

    return {
        "address": addr,
        "events": events,
        "total": data.get("total", len(events)),
        "limit": limit,
        "offset": offset,
        "network": cfg.network,
    }
