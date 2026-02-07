"""
Phase 5B: BNS Name Systems, Market Data, and Portfolio operations.

Implements:
- BNS name lookup and resolution via Hiro BNS API
- BNS name listing for an address
- BNS name registration via contract call
- Multi-asset price data from CoinGecko
- Price history for charting
- Portfolio summary aggregation across BTC + STX
- Asset listing with current values
- Collectibles/NFT listing
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Literal

import requests

from btc_wallet import BTCConfig, _fetch_mempool_utxos
from stx_wallet import STXConfig, stx_call_contract, stx_get_balance, _hiro_get

BTCNetwork = Literal["mainnet", "testnet"]

COINGECKO_API = "https://api.coingecko.com/api/v3"

# BNS contract
BNS_CONTRACT_V2 = "SP000000000000000000002Q6VF78.bns"


# ---------------------------------------------------------------------------
# 5B.1 BNS Name Systems
# ---------------------------------------------------------------------------


def bns_lookup(
    cfg: STXConfig,
    name: str,
) -> dict[str, Any]:
    """
    Look up a BNS name to resolve its address.

    name: fully qualified BNS name, e.g. "muneeb.btc"
    """
    if not name:
        raise ValueError("BNS name is required.")

    # Parse name and namespace
    parts = name.split(".")
    if len(parts) < 2:
        raise ValueError("BNS name must include namespace, e.g. 'alice.btc'")

    try:
        data = _hiro_get(cfg, f"/v1/names/{name}")
    except Exception as exc:
        raise RuntimeError(f"BNS lookup failed for '{name}': {exc}") from exc

    return {
        "name": name,
        "address": data.get("address", ""),
        "blockchain": data.get("blockchain", "stacks"),
        "status": data.get("status", ""),
        "last_txid": data.get("last_txid", ""),
        "expire_block": data.get("expire_block", 0),
        "zonefile_hash": data.get("zonefile_hash", ""),
        "network": cfg.network,
    }


def bns_get_names(
    cfg: STXConfig,
    address: str | None = None,
) -> dict[str, Any]:
    """
    Get BNS names owned by an address.

    Defaults to the wallet's STX address.
    """
    addr = address or cfg.stx_address

    try:
        data = _hiro_get(cfg, f"/v1/addresses/stacks/{addr}")
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch BNS names for {addr}: {exc}") from exc

    names = data.get("names", [])
    return {
        "address": addr,
        "names": names,
        "count": len(names),
        "network": cfg.network,
    }


def bns_register(
    cfg: STXConfig,
    name: str,
    namespace: str = "btc",
    fee: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Register a BNS name via contract call.

    This calls the BNS contract's name-register function.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    if not name:
        raise ValueError("Name is required.")

    bns_parts = BNS_CONTRACT_V2.split(".")
    bns_addr = bns_parts[0]
    bns_name = bns_parts[1]

    # BNS name-register expects: (namespace (buff 20)) (name (buff 48)) (salt (buff 20)) (zonefile-hash (buff 20))
    name_hex = name.encode("ascii").hex()
    namespace_hex = namespace.encode("ascii").hex()

    result = stx_call_contract(
        cfg,
        contract_address=bns_addr,
        contract_name=bns_name,
        function_name="name-register",
        function_args=[
            f"0x{namespace_hex}",
            f"0x{name_hex}",
            f"0x{'00' * 20}",  # salt placeholder
            f"0x{'00' * 20}",  # zonefile-hash placeholder
        ],
        fee=fee,
        dry_run=dry_run,
    )
    result["bns_name"] = f"{name}.{namespace}"
    return result


# ---------------------------------------------------------------------------
# 5B.2 Market Data
# ---------------------------------------------------------------------------


def market_get_prices(
    coins: list[str] | None = None,
    vs_currencies: list[str] | None = None,
) -> dict[str, Any]:
    """
    Get multi-asset prices from CoinGecko.

    coins: list of CoinGecko IDs (default: bitcoin, blockstack)
    vs_currencies: list of fiat currencies (default: usd, eur)
    """
    if coins is None:
        coins = ["bitcoin", "blockstack"]
    if vs_currencies is None:
        vs_currencies = ["usd", "eur"]

    ids_str = ",".join(coins)
    vs_str = ",".join(vs_currencies)

    try:
        resp = requests.get(
            f"{COINGECKO_API}/simple/price",
            params={"ids": ids_str, "vs_currencies": vs_str},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch prices: {exc}") from exc

    return {
        "prices": data,
        "coins": coins,
        "vs_currencies": vs_currencies,
    }


def market_get_history(
    coin: str = "bitcoin",
    vs_currency: str = "usd",
    days: int = 7,
    interval: str = "daily",
) -> dict[str, Any]:
    """
    Get price history for a coin from CoinGecko.

    Returns price, market_cap, and volume data points.
    """
    try:
        resp = requests.get(
            f"{COINGECKO_API}/coins/{coin}/market_chart",
            params={"vs_currency": vs_currency, "days": days, "interval": interval},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch price history: {exc}") from exc

    prices = data.get("prices", [])
    return {
        "coin": coin,
        "vs_currency": vs_currency,
        "days": days,
        "interval": interval,
        "data_points": len(prices),
        "prices": [{"timestamp": p[0], "price": p[1]} for p in prices],
        "latest_price": prices[-1][1] if prices else None,
    }


# ---------------------------------------------------------------------------
# 5B.3 Portfolio
# ---------------------------------------------------------------------------


def portfolio_get_summary(
    btc_cfg: BTCConfig,
    stx_cfg: STXConfig,
) -> dict[str, Any]:
    """
    Full portfolio summary across BTC and STX.

    Aggregates balances from all address types and fetches current prices.
    """
    # BTC balances
    btc_candidates = btc_cfg.candidate_wifs or []
    total_btc_sats = 0
    btc_accounts = []
    for c in btc_candidates:
        addr = c.get("address", "")
        if not addr:
            continue
        utxos = _fetch_mempool_utxos(addr, btc_cfg.network)
        sats = sum(int(u.get("value", 0)) for u in utxos)
        total_btc_sats += sats
        if sats > 0:
            btc_accounts.append({
                "type": c.get("addr_type", "unknown"),
                "address": addr,
                "balance_sats": sats,
            })

    total_btc = Decimal(total_btc_sats) / Decimal("1e8")

    # STX balance
    try:
        stx_balance = stx_get_balance(stx_cfg)
        stx_ustx = stx_balance.get("balance_ustx", 0)
        stx_amount = Decimal(stx_ustx) / Decimal("1000000")
        ft_count = len(stx_balance.get("fungible_tokens", []))
        nft_count = len(stx_balance.get("non_fungible_tokens", []))
    except Exception:
        stx_ustx = 0
        stx_amount = Decimal("0")
        ft_count = 0
        nft_count = 0

    # Prices
    try:
        price_data = market_get_prices(["bitcoin", "blockstack"], ["usd"])
        btc_usd = price_data["prices"].get("bitcoin", {}).get("usd", 0)
        stx_usd = price_data["prices"].get("blockstack", {}).get("usd", 0)
    except Exception:
        btc_usd = 0
        stx_usd = 0

    btc_value_usd = float(total_btc) * btc_usd
    stx_value_usd = float(stx_amount) * stx_usd
    total_value_usd = btc_value_usd + stx_value_usd

    return {
        "total_value_usd": round(total_value_usd, 2),
        "btc": {
            "balance_btc": str(total_btc),
            "balance_sats": total_btc_sats,
            "price_usd": btc_usd,
            "value_usd": round(btc_value_usd, 2),
            "accounts": btc_accounts,
        },
        "stx": {
            "balance_stx": str(stx_amount),
            "balance_ustx": stx_ustx,
            "price_usd": stx_usd,
            "value_usd": round(stx_value_usd, 2),
            "fungible_token_count": ft_count,
            "nft_count": nft_count,
        },
        "network": btc_cfg.network,
    }


def portfolio_get_assets(
    btc_cfg: BTCConfig,
    stx_cfg: STXConfig,
) -> dict[str, Any]:
    """List all assets with current values."""
    assets = []

    # BTC
    btc_candidates = btc_cfg.candidate_wifs or []
    total_btc_sats = 0
    for c in btc_candidates:
        addr = c.get("address", "")
        if not addr:
            continue
        utxos = _fetch_mempool_utxos(addr, btc_cfg.network)
        sats = sum(int(u.get("value", 0)) for u in utxos)
        total_btc_sats += sats

    if total_btc_sats > 0:
        assets.append({
            "symbol": "BTC",
            "name": "Bitcoin",
            "balance": str(Decimal(total_btc_sats) / Decimal("1e8")),
            "balance_raw": total_btc_sats,
            "chain": "bitcoin",
        })

    # STX and tokens
    try:
        stx_balance = stx_get_balance(stx_cfg)
        stx_ustx = stx_balance.get("balance_ustx", 0)
        if stx_ustx > 0:
            assets.append({
                "symbol": "STX",
                "name": "Stacks",
                "balance": str(Decimal(stx_ustx) / Decimal("1000000")),
                "balance_raw": stx_ustx,
                "chain": "stacks",
            })
        for ft in stx_balance.get("fungible_tokens", []):
            if int(ft.get("balance", 0)) > 0:
                assets.append({
                    "symbol": ft.get("token_id", "").split("::")[-1] if "::" in ft.get("token_id", "") else ft.get("token_id", ""),
                    "name": ft.get("token_id", ""),
                    "balance": ft.get("balance", "0"),
                    "balance_raw": int(ft.get("balance", 0)),
                    "chain": "stacks",
                })
    except Exception:
        pass

    return {
        "assets": assets,
        "count": len(assets),
        "network": btc_cfg.network,
    }


def portfolio_get_collectibles(
    btc_cfg: BTCConfig,
    stx_cfg: STXConfig,
    limit: int = 20,
) -> dict[str, Any]:
    """List all collectibles/NFTs across BTC (inscriptions) and STX."""
    collectibles = []

    # Bitcoin inscriptions (ordinals)
    btc_candidates = btc_cfg.candidate_wifs or []
    taproot = next((c for c in btc_candidates if c.get("addr_type") == "p2tr"), None)
    if taproot and taproot.get("address"):
        ord_api = "https://api.hiro.so" if btc_cfg.network == "mainnet" else "https://api.testnet.hiro.so"
        try:
            resp = requests.get(
                f"{ord_api}/ordinals/v1/inscriptions",
                params={"address": taproot["address"], "limit": limit},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            for r in data.get("results", []):
                collectibles.append({
                    "type": "inscription",
                    "chain": "bitcoin",
                    "id": r.get("id", ""),
                    "number": r.get("number"),
                    "content_type": r.get("content_type", ""),
                    "address": r.get("address", ""),
                    "value": r.get("value", "0"),
                })
        except Exception:
            pass

    # Stacks NFTs
    try:
        stx_balance = stx_get_balance(stx_cfg)
        for nft in stx_balance.get("non_fungible_tokens", []):
            count = nft.get("count", 0)
            if count > 0:
                collectibles.append({
                    "type": "nft",
                    "chain": "stacks",
                    "id": nft.get("token_id", ""),
                    "count": count,
                })
    except Exception:
        pass

    return {
        "collectibles": collectibles,
        "count": len(collectibles),
        "network": btc_cfg.network,
    }
