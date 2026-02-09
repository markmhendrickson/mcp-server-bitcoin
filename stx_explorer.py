"""
Stacks block explorer operations for Hiro API integration.

Implements:
- List recent Stacks blocks
- Get block by height or hash
- List Stacks blocks for a given Bitcoin block
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


def _format_block(block: dict) -> dict[str, Any]:
    """Extract key fields from a Stacks block object."""
    return {
        "height": block.get("height"),
        "hash": block.get("hash", ""),
        "index_block_hash": block.get("index_block_hash", ""),
        "parent_block_hash": block.get("parent_block_hash", ""),
        "burn_block_height": block.get("burn_block_height"),
        "burn_block_hash": block.get("burn_block_hash", ""),
        "burn_block_time": block.get("burn_block_time"),
        "burn_block_time_iso": block.get("burn_block_time_iso", ""),
        "miner_txid": block.get("miner_txid", ""),
        "canonical": block.get("canonical", True),
        "execution_cost_read_count": block.get("execution_cost_read_count"),
        "execution_cost_read_length": block.get("execution_cost_read_length"),
        "execution_cost_runtime": block.get("execution_cost_runtime"),
        "execution_cost_write_count": block.get("execution_cost_write_count"),
        "execution_cost_write_length": block.get("execution_cost_write_length"),
        "tx_count": block.get("tx_count", block.get("txs", []).__len__() if isinstance(block.get("txs"), list) else 0),
    }


# ---------------------------------------------------------------------------
# Block queries
# ---------------------------------------------------------------------------


def stx_get_recent_blocks(
    cfg: STXConfig,
    limit: int = 20,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Get recent Stacks blocks.

    Returns a paginated list of blocks from newest to oldest.
    """
    try:
        data = _hiro_get(
            cfg,
            "/extended/v2/blocks",
            params={"limit": limit, "offset": offset},
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch recent blocks: {exc}") from exc

    blocks = []
    for block in data.get("results", []):
        blocks.append(_format_block(block))

    return {
        "blocks": blocks,
        "total": data.get("total", len(blocks)),
        "limit": limit,
        "offset": offset,
        "network": cfg.network,
    }


def stx_get_block_by_height(
    cfg: STXConfig,
    height: int,
) -> dict[str, Any]:
    """
    Get a specific Stacks block by its height.
    """
    try:
        data = _hiro_get(cfg, f"/extended/v2/blocks/by-height/{height}")
    except Exception as exc:
        raise RuntimeError(
            f"Failed to fetch block at height {height}: {exc}"
        ) from exc

    result = _format_block(data)
    # Include transaction IDs if available
    txs = data.get("txs", [])
    if txs:
        result["transaction_ids"] = txs

    result["network"] = cfg.network
    return result


def stx_get_block_by_hash(
    cfg: STXConfig,
    block_hash: str,
) -> dict[str, Any]:
    """
    Get a specific Stacks block by its hash.
    """
    # Ensure 0x prefix
    if not block_hash.startswith("0x"):
        block_hash = f"0x{block_hash}"

    try:
        data = _hiro_get(cfg, f"/extended/v2/blocks/{block_hash}")
    except Exception as exc:
        raise RuntimeError(
            f"Failed to fetch block {block_hash}: {exc}"
        ) from exc

    result = _format_block(data)
    txs = data.get("txs", [])
    if txs:
        result["transaction_ids"] = txs

    result["network"] = cfg.network
    return result


def stx_get_stacks_blocks_for_bitcoin_block(
    cfg: STXConfig,
    bitcoin_height: int,
    limit: int = 20,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Get Stacks blocks that were mined during a specific Bitcoin block.

    This maps a Bitcoin block height to all corresponding Stacks blocks.
    """
    try:
        data = _hiro_get(
            cfg,
            f"/extended/v2/burn-blocks/{bitcoin_height}/blocks",
            params={"limit": limit, "offset": offset},
        )
    except Exception as exc:
        raise RuntimeError(
            f"Failed to fetch Stacks blocks for BTC block {bitcoin_height}: {exc}"
        ) from exc

    blocks = []
    for block in data.get("results", []):
        blocks.append(_format_block(block))

    return {
        "bitcoin_block_height": bitcoin_height,
        "stacks_blocks": blocks,
        "total": data.get("total", len(blocks)),
        "limit": limit,
        "offset": offset,
        "network": cfg.network,
    }
