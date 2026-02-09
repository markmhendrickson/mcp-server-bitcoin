"""
Stacks token metadata operations using Hiro Token Metadata API.

Implements:
- Get fungible token metadata (name, symbol, decimals, supply)
- Get non-fungible token metadata (name, description, image)
- Get token holders (top holders of a fungible token)
"""

from __future__ import annotations

from typing import Any

import requests

from stx_wallet import STXConfig

# Token Metadata API base URL (separate from Blockchain API)
TOKEN_METADATA_MAINNET = "https://api.hiro.so/metadata/v1"
TOKEN_METADATA_TESTNET = "https://api.testnet.hiro.so/metadata/v1"


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------


def _metadata_base(network: str) -> str:
    return TOKEN_METADATA_MAINNET if network == "mainnet" else TOKEN_METADATA_TESTNET


def _metadata_get(cfg: STXConfig, path: str, params: dict | None = None) -> Any:
    """GET request to Hiro Token Metadata API."""
    url = f"{_metadata_base(cfg.network)}{path}"
    resp = requests.get(url, params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Fungible token metadata
# ---------------------------------------------------------------------------


def stx_get_ft_metadata(
    cfg: STXConfig,
    contract_id: str,
) -> dict[str, Any]:
    """
    Get metadata for a SIP-10 fungible token.

    Returns: name, symbol, decimals, total supply, description,
    image URI, and contract principal.

    contract_id format: SP...address.contract-name
    """
    try:
        data = _metadata_get(cfg, f"/ft/{contract_id}")
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            raise RuntimeError(
                f"Token metadata not found for {contract_id}. "
                "The token may not be indexed yet."
            ) from exc
        raise RuntimeError(
            f"Failed to fetch FT metadata for {contract_id}: {exc}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"Failed to fetch FT metadata for {contract_id}: {exc}"
        ) from exc

    return {
        "contract_id": contract_id,
        "name": data.get("name", ""),
        "symbol": data.get("symbol", ""),
        "decimals": data.get("decimals"),
        "total_supply": data.get("total_supply", ""),
        "description": data.get("description", ""),
        "image_uri": data.get("image_uri", ""),
        "image_canonical_uri": data.get("image_canonical_uri", ""),
        "token_uri": data.get("token_uri", ""),
        "sender_address": data.get("sender_address", ""),
        "network": cfg.network,
    }


# ---------------------------------------------------------------------------
# Non-fungible token metadata
# ---------------------------------------------------------------------------


def stx_get_nft_metadata(
    cfg: STXConfig,
    contract_id: str,
) -> dict[str, Any]:
    """
    Get metadata for a SIP-9 non-fungible token collection.

    Returns: name, description, image URI, and contract principal.

    contract_id format: SP...address.contract-name
    """
    try:
        data = _metadata_get(cfg, f"/nft/{contract_id}")
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            raise RuntimeError(
                f"NFT metadata not found for {contract_id}. "
                "The token may not be indexed yet."
            ) from exc
        raise RuntimeError(
            f"Failed to fetch NFT metadata for {contract_id}: {exc}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"Failed to fetch NFT metadata for {contract_id}: {exc}"
        ) from exc

    return {
        "contract_id": contract_id,
        "name": data.get("name", ""),
        "description": data.get("description", ""),
        "image_uri": data.get("image_uri", ""),
        "image_canonical_uri": data.get("image_canonical_uri", ""),
        "token_uri": data.get("token_uri", ""),
        "sender_address": data.get("sender_address", ""),
        "network": cfg.network,
    }


# ---------------------------------------------------------------------------
# Combined token metadata (auto-detect FT or NFT)
# ---------------------------------------------------------------------------


def stx_get_token_metadata(
    cfg: STXConfig,
    contract_id: str,
    token_type: str = "ft",
) -> dict[str, Any]:
    """
    Get token metadata for a fungible or non-fungible token.

    token_type: "ft" for fungible (SIP-10) or "nft" for non-fungible (SIP-9).
    """
    if token_type == "nft":
        return stx_get_nft_metadata(cfg, contract_id)
    return stx_get_ft_metadata(cfg, contract_id)


# ---------------------------------------------------------------------------
# Token holders
# ---------------------------------------------------------------------------


def stx_get_token_holders(
    cfg: STXConfig,
    contract_id: str,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Get holder information for a fungible token.

    Returns addresses holding the token with their balances.
    """
    try:
        data = _metadata_get(
            cfg,
            f"/ft/{contract_id}/holders",
            params={"limit": limit, "offset": offset},
        )
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            raise RuntimeError(
                f"Token holders not found for {contract_id}. "
                "The token may not be indexed yet."
            ) from exc
        raise RuntimeError(
            f"Failed to fetch token holders for {contract_id}: {exc}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"Failed to fetch token holders for {contract_id}: {exc}"
        ) from exc

    holders = []
    for holder in data.get("results", []):
        holders.append({
            "address": holder.get("address", ""),
            "balance": holder.get("balance", "0"),
        })

    return {
        "contract_id": contract_id,
        "holders": holders,
        "total": data.get("total", len(holders)),
        "limit": limit,
        "offset": offset,
        "network": cfg.network,
    }
