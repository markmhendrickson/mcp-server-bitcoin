"""
Phase 5A: Transaction Management & Wallet operations.

Implements:
- Transaction history (BTC via mempool.space, STX via Hiro)
- Transaction status lookup
- RBF speed-up and cancel for pending BTC transactions
- Wallet network configuration management
- Supported methods introspection
"""

from __future__ import annotations

import hashlib
import os
from decimal import Decimal
from typing import Any, Literal

import requests

from btc_wallet import (
    BTCConfig,
    _broadcast_raw_tx,
    _build_native_segwit_tx_multi,
    _fetch_dynamic_fee_rate_sat_per_byte,
    _fetch_mempool_utxos,
    _make_key_from_wif,
)

BTCNetwork = Literal["mainnet", "testnet"]


# ---------------------------------------------------------------------------
# Mempool / Hiro API helpers
# ---------------------------------------------------------------------------


def _mempool_base(network: BTCNetwork) -> str:
    return "https://mempool.space" if network == "mainnet" else "https://mempool.space/testnet"


def _hiro_base(network: BTCNetwork) -> str:
    return "https://api.hiro.so" if network == "mainnet" else "https://api.testnet.hiro.so"


# ---------------------------------------------------------------------------
# 5A.1 Transaction History
# ---------------------------------------------------------------------------


def tx_get_history(
    cfg: BTCConfig,
    chain: str = "both",
    limit: int = 20,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Get transaction history for BTC and/or STX.

    chain: "btc", "stx", or "both"
    """
    results: dict[str, Any] = {"network": cfg.network, "chain": chain}

    if chain in ("btc", "both"):
        # Get BTC transactions from mempool.space
        btc_txs = _get_btc_tx_history(cfg, limit)
        results["btc_transactions"] = btc_txs
        results["btc_count"] = len(btc_txs)

    if chain in ("stx", "both"):
        # Get STX transactions from Hiro
        stx_txs = _get_stx_tx_history(cfg, limit, offset)
        results["stx_transactions"] = stx_txs
        results["stx_count"] = len(stx_txs)

    return results


def _get_btc_tx_history(cfg: BTCConfig, limit: int = 20) -> list[dict[str, Any]]:
    """Fetch BTC transaction history from mempool.space."""
    candidates = cfg.candidate_wifs or []
    p2wpkh = next((c for c in candidates if c.get("addr_type") == "p2wpkh"), None)
    if not p2wpkh:
        return []
    addr = p2wpkh.get("address", "")
    if not addr:
        return []

    url = f"{_mempool_base(cfg.network)}/api/address/{addr}/txs"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        txs = resp.json()
    except Exception:
        return []

    results = []
    for tx in txs[:limit]:
        status = tx.get("status", {})
        results.append({
            "txid": tx.get("txid", ""),
            "confirmed": status.get("confirmed", False),
            "block_height": status.get("block_height"),
            "block_time": status.get("block_time"),
            "fee": tx.get("fee", 0),
            "size": tx.get("size", 0),
            "value_in": sum(v.get("prevout", {}).get("value", 0) for v in tx.get("vin", [])),
            "value_out": sum(v.get("value", 0) for v in tx.get("vout", [])),
            "chain": "btc",
        })
    return results


def _get_stx_tx_history(
    cfg: BTCConfig, limit: int = 20, offset: int = 0
) -> list[dict[str, Any]]:
    """Fetch STX transaction history from Hiro API."""
    # Derive STX address from mnemonic if available
    stx_address = os.getenv("STX_ADDRESS", "")
    if not stx_address:
        try:
            from stx_wallet import STXConfig
            stx_cfg = STXConfig.from_env()
            stx_address = stx_cfg.stx_address
        except Exception:
            return []

    url = f"{_hiro_base(cfg.network)}/extended/v1/address/{stx_address}/transactions"
    try:
        resp = requests.get(url, params={"limit": limit, "offset": offset}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    results = []
    for tx in data.get("results", []):
        results.append({
            "txid": tx.get("tx_id", ""),
            "tx_type": tx.get("tx_type", ""),
            "status": tx.get("tx_status", ""),
            "block_height": tx.get("block_height"),
            "burn_block_time": tx.get("burn_block_time"),
            "fee_ustx": tx.get("fee_rate", 0),
            "sender": tx.get("sender_address", ""),
            "chain": "stx",
        })
    return results


# ---------------------------------------------------------------------------
# 5A.2 Transaction Status
# ---------------------------------------------------------------------------


def tx_get_status(
    cfg: BTCConfig,
    txid: str,
    chain: str = "btc",
) -> dict[str, Any]:
    """
    Get the status of a specific transaction.

    chain: "btc" or "stx"
    """
    if chain == "btc":
        return _get_btc_tx_status(cfg, txid)
    elif chain == "stx":
        return _get_stx_tx_status(cfg, txid)
    else:
        raise ValueError(f"Unknown chain: {chain}. Use 'btc' or 'stx'.")


def _get_btc_tx_status(cfg: BTCConfig, txid: str) -> dict[str, Any]:
    url = f"{_mempool_base(cfg.network)}/api/tx/{txid}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        tx = resp.json()
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch BTC transaction {txid}: {exc}") from exc

    status = tx.get("status", {})
    return {
        "txid": txid,
        "chain": "btc",
        "confirmed": status.get("confirmed", False),
        "block_height": status.get("block_height"),
        "block_hash": status.get("block_hash"),
        "block_time": status.get("block_time"),
        "fee": tx.get("fee", 0),
        "size": tx.get("size", 0),
        "weight": tx.get("weight", 0),
        "rbf": any(vin.get("sequence", 0xFFFFFFFF) < 0xFFFFFFFE for vin in tx.get("vin", [])),
        "network": cfg.network,
    }


def _get_stx_tx_status(cfg: BTCConfig, txid: str) -> dict[str, Any]:
    # Ensure txid has 0x prefix for Hiro
    if not txid.startswith("0x"):
        txid = f"0x{txid}"
    url = f"{_hiro_base(cfg.network)}/extended/v1/tx/{txid}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        tx = resp.json()
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch STX transaction {txid}: {exc}") from exc

    return {
        "txid": txid,
        "chain": "stx",
        "tx_type": tx.get("tx_type", ""),
        "status": tx.get("tx_status", ""),
        "block_height": tx.get("block_height"),
        "burn_block_time": tx.get("burn_block_time"),
        "fee_ustx": tx.get("fee_rate", 0),
        "sender": tx.get("sender_address", ""),
        "nonce": tx.get("nonce"),
        "network": cfg.network,
    }


# ---------------------------------------------------------------------------
# 5A.3 RBF Speed-up / Cancel
# ---------------------------------------------------------------------------


def tx_speed_up(
    cfg: BTCConfig,
    txid: str,
    new_fee_rate: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Speed up a pending BTC transaction using Replace-By-Fee (RBF).

    Fetches the original transaction, rebuilds it with a higher fee rate,
    and broadcasts the replacement.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    # Fetch original transaction
    orig = _get_btc_tx_status(cfg, txid)
    if orig.get("confirmed"):
        raise RuntimeError("Transaction is already confirmed. Cannot RBF.")
    if not orig.get("rbf"):
        raise RuntimeError("Transaction does not signal RBF (sequence >= 0xFFFFFFFE).")

    # Fetch full transaction details
    url = f"{_mempool_base(cfg.network)}/api/tx/{txid}"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    tx_data = resp.json()

    # Determine new fee rate
    if new_fee_rate is None:
        # Use fastest fee rate
        new_fee_rate = _fetch_dynamic_fee_rate_sat_per_byte(
            cfg.network, cfg.fee_rate_sat_per_byte, "fastestFee"
        )

    old_fee = tx_data.get("fee", 0)
    weight = tx_data.get("weight", 0)
    old_vsize = weight / 4 if weight else tx_data.get("size", 200)
    min_new_fee = old_fee + int(old_vsize)  # BIP125: at least 1 sat/vB increase

    new_fee = max(int(old_vsize * new_fee_rate), min_new_fee)

    # Reconstruct: same inputs, same outputs but reduce change by fee increase
    vins = tx_data.get("vin", [])
    vouts = tx_data.get("vout", [])

    total_in = sum(v.get("prevout", {}).get("value", 0) for v in vins)
    total_out_original = sum(v.get("value", 0) for v in vouts)
    fee_increase = new_fee - old_fee

    if fee_increase <= 0:
        raise RuntimeError(f"New fee ({new_fee}) must exceed old fee ({old_fee}).")

    # Find the change output (largest output going back to our addresses)
    payment_addr = None
    candidates = cfg.candidate_wifs or []
    our_addrs = set()
    for c in candidates:
        a = c.get("address", "")
        if a:
            our_addrs.add(a)

    change_idx = None
    for i, vout in enumerate(vouts):
        addr = vout.get("scriptpubkey_address", "")
        if addr in our_addrs:
            if change_idx is None or vout.get("value", 0) > vouts[change_idx].get("value", 0):
                change_idx = i

    if change_idx is None:
        raise RuntimeError("Cannot identify change output for RBF adjustment.")

    if vouts[change_idx].get("value", 0) < fee_increase + 546:
        raise RuntimeError("Change output too small to absorb fee increase.")

    # Build replacement recipients
    recipients = []
    for i, vout in enumerate(vouts):
        val = vout.get("value", 0)
        if i == change_idx:
            val -= fee_increase
        if val > 0:
            recipients.append({
                "address": vout.get("scriptpubkey_address", ""),
                "amount_sats": val,
            })

    # Build input UTXOs from original transaction
    input_utxos = []
    for vin in vins:
        input_utxos.append({
            "txid": vin.get("txid", ""),
            "vout": vin.get("vout", 0),
            "value": vin.get("prevout", {}).get("value", 0),
        })

    p2wpkh = next((c for c in candidates if c.get("addr_type") == "p2wpkh"), None)
    if not p2wpkh:
        raise RuntimeError("No P2WPKH key for signing replacement transaction.")

    raw_hex = _build_native_segwit_tx_multi(
        wif=p2wpkh["wif"],
        utxos=input_utxos,
        recipients=recipients,
        fee_sats=0,
        change_address=p2wpkh.get("address", ""),
        network=cfg.network,
    )

    if dry_run:
        tx_bytes = bytes.fromhex(raw_hex)
        fake = hashlib.sha256(tx_bytes).hexdigest()
        new_txid = f"DRYRUN_{fake[:64]}"
    else:
        new_txid = _broadcast_raw_tx(raw_hex, cfg.network)

    return {
        "original_txid": txid,
        "new_txid": new_txid,
        "old_fee": old_fee,
        "new_fee": new_fee,
        "fee_rate_sat_per_vb": new_fee_rate,
        "dry_run": bool(dry_run),
        "network": cfg.network,
    }


def tx_cancel(
    cfg: BTCConfig,
    txid: str,
    fee_rate: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Cancel a pending BTC transaction via RBF.

    Sends all funds back to the wallet's own address with a higher fee.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    orig = _get_btc_tx_status(cfg, txid)
    if orig.get("confirmed"):
        raise RuntimeError("Transaction is already confirmed. Cannot cancel.")
    if not orig.get("rbf"):
        raise RuntimeError("Transaction does not signal RBF.")

    url = f"{_mempool_base(cfg.network)}/api/tx/{txid}"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    tx_data = resp.json()

    if fee_rate is None:
        fee_rate = _fetch_dynamic_fee_rate_sat_per_byte(
            cfg.network, cfg.fee_rate_sat_per_byte, "fastestFee"
        )

    vins = tx_data.get("vin", [])
    total_in = sum(v.get("prevout", {}).get("value", 0) for v in vins)

    weight = tx_data.get("weight", 0)
    vsize = weight / 4 if weight else tx_data.get("size", 200)
    cancel_fee = max(int(vsize * fee_rate), tx_data.get("fee", 0) + int(vsize))

    send_back = total_in - cancel_fee
    if send_back <= 546:
        raise RuntimeError("Not enough value to create a cancel transaction after fees.")

    candidates = cfg.candidate_wifs or []
    p2wpkh = next((c for c in candidates if c.get("addr_type") == "p2wpkh"), None)
    if not p2wpkh:
        raise RuntimeError("No P2WPKH key for signing cancel transaction.")
    our_addr = p2wpkh.get("address", "")

    input_utxos = [{
        "txid": vin.get("txid", ""),
        "vout": vin.get("vout", 0),
        "value": vin.get("prevout", {}).get("value", 0),
    } for vin in vins]

    raw_hex = _build_native_segwit_tx_multi(
        wif=p2wpkh["wif"],
        utxos=input_utxos,
        recipients=[{"address": our_addr, "amount_sats": send_back}],
        fee_sats=0,
        change_address=our_addr,
        network=cfg.network,
    )

    if dry_run:
        tx_bytes = bytes.fromhex(raw_hex)
        fake = hashlib.sha256(tx_bytes).hexdigest()
        new_txid = f"DRYRUN_{fake[:64]}"
    else:
        new_txid = _broadcast_raw_tx(raw_hex, cfg.network)

    return {
        "action": "cancel",
        "original_txid": txid,
        "cancel_txid": new_txid,
        "returned_sats": send_back,
        "cancel_fee": cancel_fee,
        "to_address": our_addr,
        "dry_run": bool(dry_run),
        "network": cfg.network,
    }


# ---------------------------------------------------------------------------
# 5A.4 Wallet Management
# ---------------------------------------------------------------------------


def wallet_get_network(cfg: BTCConfig) -> dict[str, Any]:
    """Get current wallet network configuration."""
    return {
        "network": cfg.network,
        "fee_tier": cfg.fee_tier,
        "fee_rate_sat_per_byte": cfg.fee_rate_sat_per_byte,
        "use_fixed_fee_rate": cfg.use_fixed_fee_rate,
        "dry_run_default": cfg.dry_run_default,
        "max_send_btc": str(cfg.max_send_btc) if cfg.max_send_btc else None,
        "btc_api": _mempool_base(cfg.network),
        "stx_api": _hiro_base(cfg.network),
    }


def wallet_switch_network(network: str) -> dict[str, Any]:
    """
    Switch network. Sets the BTC_NETWORK environment variable.

    Note: Takes effect on next BTCConfig.from_env() / STXConfig.from_env() call.
    """
    network = network.lower()
    if network not in ("mainnet", "testnet"):
        raise ValueError(f"Invalid network: {network}. Use 'mainnet' or 'testnet'.")
    os.environ["BTC_NETWORK"] = network
    return {
        "network": network,
        "message": f"Network switched to {network}. New operations will use this network.",
    }


def wallet_add_network(
    name: str,
    btc_api_url: str | None = None,
    stx_api_url: str | None = None,
) -> dict[str, Any]:
    """
    Add a custom network configuration.

    Sets custom API URLs via environment variables.
    """
    if btc_api_url:
        os.environ["BTC_API_URL"] = btc_api_url
    if stx_api_url:
        os.environ["STX_API_URL"] = stx_api_url

    return {
        "name": name,
        "btc_api_url": btc_api_url,
        "stx_api_url": stx_api_url,
        "message": f"Custom network '{name}' configured.",
    }


def wallet_get_supported_methods() -> dict[str, Any]:
    """List all available MCP tools with descriptions."""
    # This will be populated by the MCP server from its tool list
    return {"note": "Use the MCP list_tools protocol to get full tool metadata."}
