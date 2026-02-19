"""
Stacks mempool operations for Hiro API integration.

Implements:
- List pending mempool transactions (global or per address)
- Mempool statistics
- Dropped/replaced mempool transaction status
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
# Mempool: list pending transactions
# ---------------------------------------------------------------------------


def stx_mempool_list_pending(
    cfg: STXConfig,
    address: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """
    List pending mempool transactions.

    If address is provided, returns only mempool transactions for that address.
    Otherwise returns global mempool transactions.
    """
    if address:
        # Address-specific pending transactions
        try:
            data = _hiro_get(
                cfg,
                f"/extended/v1/address/{address}/mempool",
                params={"limit": limit, "offset": offset},
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch mempool for {address}: {exc}") from exc
    else:
        # Global mempool
        try:
            data = _hiro_get(
                cfg,
                "/extended/v1/tx/mempool",
                params={"limit": limit, "offset": offset},
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch mempool: {exc}") from exc

    results = []
    for tx in data.get("results", []):
        results.append(
            {
                "txid": tx.get("tx_id", ""),
                "tx_type": tx.get("tx_type", ""),
                "tx_status": tx.get("tx_status", ""),
                "receipt_time": tx.get("receipt_time"),
                "receipt_time_iso": tx.get("receipt_time_iso"),
                "fee_rate": tx.get("fee_rate", "0"),
                "sender_address": tx.get("sender_address", ""),
                "nonce": tx.get("nonce"),
                "sponsor_address": tx.get("sponsor_address"),
            }
        )

    return {
        "transactions": results,
        "total": data.get("total", len(results)),
        "limit": limit,
        "offset": offset,
        "address": address,
        "network": cfg.network,
    }


# ---------------------------------------------------------------------------
# Mempool: statistics
# ---------------------------------------------------------------------------


def stx_mempool_get_stats(cfg: STXConfig) -> dict[str, Any]:
    """
    Get mempool statistics including transaction counts by type
    and byte sizes.
    """
    try:
        data = _hiro_get(cfg, "/extended/v1/tx/mempool/stats")
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch mempool stats: {exc}") from exc

    return {
        "tx_type_counts": data.get("tx_type_counts", {}),
        "tx_simple_fee_averages": data.get("tx_simple_fee_averages", {}),
        "tx_ages": data.get("tx_ages", {}),
        "tx_byte_sizes": data.get("tx_byte_sizes", {}),
        "network": cfg.network,
    }


# ---------------------------------------------------------------------------
# Mempool: dropped transactions
# ---------------------------------------------------------------------------


def stx_mempool_get_dropped(
    cfg: STXConfig,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Get recently dropped mempool transactions.

    These are transactions that were in the mempool but were removed
    without being included in a block (replaced, expired, etc.).
    """
    try:
        data = _hiro_get(
            cfg,
            "/extended/v1/tx/mempool/dropped",
            params={"limit": limit, "offset": offset},
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch dropped mempool txs: {exc}") from exc

    results = []
    for tx in data.get("results", []):
        results.append(
            {
                "txid": tx.get("tx_id", ""),
                "tx_type": tx.get("tx_type", ""),
                "tx_status": tx.get("tx_status", ""),
                "receipt_time": tx.get("receipt_time"),
                "receipt_time_iso": tx.get("receipt_time_iso"),
                "fee_rate": tx.get("fee_rate", "0"),
                "sender_address": tx.get("sender_address", ""),
                "reason": tx.get("tx_status", ""),
            }
        )

    return {
        "dropped_transactions": results,
        "total": data.get("total", len(results)),
        "limit": limit,
        "offset": offset,
        "network": cfg.network,
    }
