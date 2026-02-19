"""
DeFi, Swaps, sBTC Bridge, and Stacking operations for Phase 4 MCP support.

Implements:
- Swap quotes and execution via Alex, Bitflow, and Velar DEX
- Supported swap pairs listing (Alex pools, Bitflow ticker)
- Swap history from Hiro activity API
- sBTC bridge deposit/withdraw information
- sBTC balance queries
- Stacks stacking info, delegation, and revocation

Quote and pairs: Alex, Bitflow, and Velar. Execution: Alex only (Bitflow/Velar
execute require protocol-specific contract calls not yet implemented).
"""

from __future__ import annotations

import hashlib
from decimal import Decimal
from typing import Any, Literal

import requests

from stx_wallet import (
    STXConfig,
    stx_call_contract,
    stx_get_balance,
    stx_get_nonce,
    _hiro_get,
)

STXNetwork = Literal["mainnet", "testnet"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALEX_API = "https://api.alexlab.co"
BITFLOW_API = "https://bitflow-sdk-api-gateway-7owjsmt8.uc.gateway.dev"
# Velar: no public REST pools/prices; we use Alex token prices for Velar quotes
SUPPORTED_SWAP_PROTOCOLS = ["alex", "bitflow", "velar"]

# Known sBTC contract (mainnet)
SBTC_CONTRACT_MAINNET = "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token"
SBTC_CONTRACT_TESTNET = "ST1F8Z1TGQ5MCHKZ1GQHRNF2SA3C3QZZMQNPBWES.sbtc-token"

# PoX stacking contract
POX_CONTRACT = "SP000000000000000000002Q6VF78.pox-4"


# ---------------------------------------------------------------------------
# 4.1 Swap Operations
# ---------------------------------------------------------------------------


def _alex_pairs() -> list[dict[str, Any]]:
    """Fetch Alex DEX pools and return list of pair dicts with protocol='alex'."""
    try:
        resp = requests.get(f"{ALEX_API}/v2/public/pools", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        pools = data.get("data", data) if isinstance(data, dict) else data
    except Exception:
        return []
    pairs = []
    if isinstance(pools, list):
        for p in pools:
            token_x = p.get("token_x", "")
            token_y = p.get("token_y", "")
            if token_x and token_y:
                pairs.append(
                    {
                        "pool_id": p.get("pool_id"),
                        "token_x": token_x,
                        "token_y": token_y,
                        "protocol": "alex",
                        "apr_7d": p.get("apr_7d", 0),
                    }
                )
    return pairs


def _bitflow_pairs() -> list[dict[str, Any]]:
    """Fetch Bitflow ticker and return list of pair dicts with protocol='bitflow'."""
    try:
        resp = requests.get(f"{BITFLOW_API}/ticker", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        tickers = data if isinstance(data, list) else data.get("data", data) or []
    except Exception:
        return []
    pairs = []
    if isinstance(tickers, list):
        for t in tickers:
            base = t.get("base_currency") or t.get("base")
            target = t.get("target_currency") or t.get("target")
            if base and target:
                pairs.append(
                    {
                        "pool_id": t.get("ticker_id") or f"{base}_{target}",
                        "token_x": base,
                        "token_y": target,
                        "protocol": "bitflow",
                        "last_price": t.get("last_price"),
                    }
                )
    return pairs


def swap_get_supported_pairs(cfg: STXConfig) -> dict[str, Any]:
    """
    List supported swap pairs and protocols.

    Fetches pools from Alex DEX and Bitflow ticker. Velar has no public REST
    pool list; use alex or bitflow for pair discovery.
    """
    alex_pairs = _alex_pairs()
    bitflow_pairs = _bitflow_pairs()
    all_pairs = alex_pairs + bitflow_pairs

    return {
        "protocols": SUPPORTED_SWAP_PROTOCOLS,
        "pair_count": len(all_pairs),
        "pairs": all_pairs[:150],
        "network": cfg.network,
    }


WSTX_CONTRACT = "SP102V8P0F7JX67ARQ77WEA3D3CFB5XW39REDT0AM.token-wstx"


def _normalize_token_for_bitflow(token: str) -> str:
    """Map STX / wstx to a form Bitflow ticker may use (e.g. 'STX')."""
    if not token:
        return token
    if token.upper() == "STX" or token == WSTX_CONTRACT:
        return "STX"
    return token


def swap_get_quote(
    cfg: STXConfig,
    token_in: str,
    token_out: str,
    amount: int,
    protocol: str = "alex",
) -> dict[str, Any]:
    """
    Get a swap quote.

    - token_in: contract ID of the input token (or "STX" for native STX)
    - token_out: contract ID of the output token
    - amount: amount of token_in in smallest unit
    - protocol: "alex" | "bitflow" | "velar"

    Alex and Velar use Alex token prices; Bitflow uses Bitflow ticker last_price.
    """
    protocol = (protocol or "alex").lower()
    if protocol not in SUPPORTED_SWAP_PROTOCOLS:
        raise ValueError(
            f"Unsupported protocol: {protocol}. Use one of: {SUPPORTED_SWAP_PROTOCOLS}"
        )

    if protocol == "bitflow":
        return _swap_get_quote_bitflow(cfg, token_in, token_out, amount)
    # alex and velar: use Alex token prices (Velar shares same Stacks tokens)
    return _swap_get_quote_alex_velar(cfg, token_in, token_out, amount, protocol)


def _swap_get_quote_alex_velar(
    cfg: STXConfig, token_in: str, token_out: str, amount: int, protocol: str
) -> dict[str, Any]:
    """Quote using Alex token prices (used for alex and velar)."""
    try:
        resp = requests.get(f"{ALEX_API}/v2/public/token-prices", timeout=10)
        resp.raise_for_status()
        price_data = resp.json().get("data", [])
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch token prices: {exc}") from exc

    prices: dict[str, float] = {}
    for item in price_data:
        cid = item.get("contract_id", "")
        price = item.get("last_price_usd", 0)
        if cid and price:
            prices[cid] = float(price)

    wstx = "SP102V8P0F7JX67ARQ77WEA3D3CFB5XW39REDT0AM.token-wstx"
    if token_in.upper() == "STX":
        token_in_price = prices.get(wstx, 0)
    else:
        token_in_price = prices.get(token_in, 0)
    if token_out.upper() == "STX":
        token_out_price = prices.get(wstx, 0)
    else:
        token_out_price = prices.get(token_out, 0)

    if token_in_price <= 0:
        raise RuntimeError(f"No price data available for input token: {token_in}")
    if token_out_price <= 0:
        raise RuntimeError(f"No price data available for output token: {token_out}")

    value_usd = amount * token_in_price
    estimated_output = value_usd / token_out_price
    fee_pct = 0.003
    slippage_pct = 0.01
    estimated_output_after_fees = estimated_output * (1 - fee_pct - slippage_pct)

    return {
        "token_in": token_in,
        "token_out": token_out,
        "amount_in": amount,
        "token_in_price_usd": token_in_price,
        "token_out_price_usd": token_out_price,
        "estimated_output": int(estimated_output_after_fees),
        "estimated_output_before_fees": int(estimated_output),
        "exchange_rate": token_in_price / token_out_price,
        "fee_pct": fee_pct,
        "slippage_pct": slippage_pct,
        "protocol": protocol,
        "network": cfg.network,
    }


def _swap_get_quote_bitflow(
    cfg: STXConfig, token_in: str, token_out: str, amount: int
) -> dict[str, Any]:
    """Quote using Bitflow ticker (last_price is target per base)."""
    try:
        resp = requests.get(f"{BITFLOW_API}/ticker", timeout=10)
        resp.raise_for_status()
        tickers = resp.json()
        if not isinstance(tickers, list):
            tickers = tickers.get("data", tickers) or []
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch Bitflow ticker: {exc}") from exc

    a_in = _normalize_token_for_bitflow(token_in)
    a_out = _normalize_token_for_bitflow(token_out)

    for t in tickers:
        base = (t.get("base_currency") or t.get("base") or "").strip()
        target = (t.get("target_currency") or t.get("target") or "").strip()
        if not base or not target:
            continue
        last = t.get("last_price")
        if last is None:
            continue
        try:
            rate = float(last)
        except (TypeError, ValueError):
            continue
        # Match (token_in, token_out) to (base, target) or (target, base)
        if (base == a_in and target == a_out) or (
            base == token_in and target == token_out
        ):
            estimated_output = amount * rate
        elif (base == a_out and target == a_in) or (
            base == token_out and target == token_in
        ):
            estimated_output = amount / rate if rate else 0
        else:
            continue
        fee_pct = 0.003
        slippage_pct = 0.01
        estimated_output_after_fees = int(
            estimated_output * (1 - fee_pct - slippage_pct)
        )
        return {
            "token_in": token_in,
            "token_out": token_out,
            "amount_in": amount,
            "token_in_price_usd": None,
            "token_out_price_usd": None,
            "estimated_output": estimated_output_after_fees,
            "estimated_output_before_fees": int(estimated_output),
            "exchange_rate": rate if (base == a_in or base == token_in) else 1.0 / rate,
            "fee_pct": fee_pct,
            "slippage_pct": slippage_pct,
            "protocol": "bitflow",
            "network": cfg.network,
        }
    raise RuntimeError(
        f"No Bitflow ticker found for pair {token_in} / {token_out}. Try protocol=alex or protocol=velar."
    )


def swap_execute(
    cfg: STXConfig,
    token_in: str,
    token_out: str,
    amount: int,
    min_output: int | None = None,
    protocol: str = "alex",
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Execute a swap via DEX smart contract call.

    Only protocol=alex is supported for execution. Bitflow and Velar are
    supported for quotes and pair listing only; use protocol=alex to execute.

    Future execution support: Velar exposes contract-call params via
    @velarprotocol/velar-sdk (swap() returns contract, function, args); Bitflow
    has no public swap-build API (only ticker); contact Bitflow for SDK/API.
    """
    protocol = (protocol or "alex").lower()
    if protocol not in ("alex",):
        return {
            "ok": False,
            "error": f"Execution is only supported for protocol=alex. Got protocol={protocol}. Use swap_get_quote with protocol={protocol} for a quote, then execute with protocol=alex.",
            "protocol": protocol,
            "network": cfg.network,
        }
    if dry_run is None:
        dry_run = cfg.dry_run_default

    quote = swap_get_quote(cfg, token_in, token_out, amount, "alex")
    estimated_output = quote["estimated_output"]
    if min_output is None:
        min_output = int(estimated_output * 0.95)

    alex_router = "SP102V8P0F7JX67ARQ77WEA3D3CFB5XW39REDT0AM"
    alex_contract = "amm-pool-v2-01"
    in_asset = (
        f"'{alex_router}.token-wstx" if token_in.upper() == "STX" else f"'{token_in}"
    )
    out_asset = (
        f"'{alex_router}.token-wstx" if token_out.upper() == "STX" else f"'{token_out}"
    )

    result = stx_call_contract(
        cfg,
        contract_address=alex_router,
        contract_name=alex_contract,
        function_name="swap-helper",
        function_args=[in_asset, out_asset, f"u{amount}", f"u{min_output}"],
        dry_run=dry_run,
    )

    result["swap_details"] = {
        "token_in": token_in,
        "token_out": token_out,
        "amount_in": amount,
        "estimated_output": estimated_output,
        "min_output": min_output,
        "protocol": "alex",
    }
    return result


def swap_get_history(
    cfg: STXConfig,
    limit: int = 20,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Get swap transaction history from the Hiro activity API.

    Filters for contract-call transactions that look like swaps.
    """
    try:
        data = _hiro_get(
            cfg,
            f"/extended/v1/address/{cfg.stx_address}/transactions",
            params={"limit": limit, "offset": offset, "type": "contract_call"},
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch transaction history: {exc}") from exc

    results = data.get("results", [])
    swap_txs = []
    swap_keywords = ["swap", "amm", "exchange", "trade"]

    for tx in results:
        contract_call = tx.get("contract_call", {})
        fn_name = contract_call.get("function_name", "")
        contract_id = contract_call.get("contract_id", "")

        # Filter for swap-like transactions
        is_swap = any(kw in fn_name.lower() for kw in swap_keywords) or any(
            kw in contract_id.lower() for kw in swap_keywords
        )

        if is_swap:
            swap_txs.append(
                {
                    "txid": tx.get("tx_id", ""),
                    "contract_id": contract_id,
                    "function_name": fn_name,
                    "status": tx.get("tx_status", ""),
                    "block_height": tx.get("block_height"),
                    "burn_block_time": tx.get("burn_block_time"),
                    "fee_ustx": tx.get("fee_rate", 0),
                }
            )

    return {
        "swaps": swap_txs,
        "count": len(swap_txs),
        "total_queried": len(results),
        "address": cfg.stx_address,
        "network": cfg.network,
    }


# ---------------------------------------------------------------------------
# 4.2 sBTC Bridge
# ---------------------------------------------------------------------------


def _sbtc_contract(network: STXNetwork) -> str:
    return SBTC_CONTRACT_MAINNET if network == "mainnet" else SBTC_CONTRACT_TESTNET


def sbtc_get_balance(cfg: STXConfig) -> dict[str, Any]:
    """Get sBTC balance for the wallet."""
    balance_data = stx_get_balance(cfg)
    ft_list = balance_data.get("fungible_tokens", [])
    sbtc_contract = _sbtc_contract(cfg.network)

    sbtc_balance = 0
    for ft in ft_list:
        token_id = ft.get("token_id", "")
        if sbtc_contract in token_id or "sbtc" in token_id.lower():
            sbtc_balance = int(ft.get("balance", 0))
            break

    return {
        "address": cfg.stx_address,
        "sbtc_balance": sbtc_balance,
        "sbtc_balance_btc": str(Decimal(sbtc_balance) / Decimal("1e8")),
        "sbtc_contract": sbtc_contract,
        "network": cfg.network,
    }


def sbtc_bridge_deposit(
    cfg: STXConfig,
    amount_sats: int,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Bridge BTC to sBTC (deposit).

    sBTC bridging is orchestrated through the sBTC protocol contracts.
    This provides the deposit intent and transaction info.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    if amount_sats <= 0:
        raise ValueError("Amount must be greater than zero.")

    sbtc_contract = _sbtc_contract(cfg.network)
    parts = sbtc_contract.split(".")
    contract_address = parts[0]
    contract_name = parts[1] if len(parts) > 1 else "sbtc-token"

    return {
        "action": "deposit",
        "from_address": cfg.stx_address,
        "amount_sats": amount_sats,
        "amount_btc": str(Decimal(amount_sats) / Decimal("1e8")),
        "sbtc_contract": sbtc_contract,
        "dry_run": bool(dry_run),
        "network": cfg.network,
        "note": (
            "sBTC deposits require a Bitcoin transaction to the sBTC peg address "
            "followed by a Stacks mint confirmation. Use the sBTC bridge UI or "
            "the official sBTC SDK for the full deposit flow."
        ),
    }


def sbtc_bridge_withdraw(
    cfg: STXConfig,
    amount_sats: int,
    btc_address: str,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Withdraw sBTC back to BTC.

    sBTC withdrawal burns sBTC on Stacks and releases BTC.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    if amount_sats <= 0:
        raise ValueError("Amount must be greater than zero.")
    if not btc_address:
        raise ValueError("btc_address is required for withdrawal.")

    sbtc_contract = _sbtc_contract(cfg.network)

    return {
        "action": "withdraw",
        "from_address": cfg.stx_address,
        "btc_address": btc_address,
        "amount_sats": amount_sats,
        "amount_btc": str(Decimal(amount_sats) / Decimal("1e8")),
        "sbtc_contract": sbtc_contract,
        "dry_run": bool(dry_run),
        "network": cfg.network,
        "note": (
            "sBTC withdrawals burn sBTC tokens and release BTC to the specified "
            "address. Use the sBTC bridge UI or the official sBTC SDK for the "
            "full withdrawal flow."
        ),
    }


# ---------------------------------------------------------------------------
# 4.3 Yield / Stacking
# ---------------------------------------------------------------------------


def stx_get_stacking_info(cfg: STXConfig) -> dict[str, Any]:
    """
    Get current stacking status and PoX cycle information.

    Queries the Hiro PoX endpoint and the wallet's stacking state.
    Enhanced with cycle progress, estimated end date, participation rate,
    and recent cycle history.
    """
    # Global PoX info
    try:
        pox_data = _hiro_get(cfg, "/v2/pox")
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch PoX info: {exc}") from exc

    current_cycle = pox_data.get("current_cycle", {})
    next_cycle = pox_data.get("next_cycle", {})

    # Check if the wallet is stacking
    try:
        stacker_info = _hiro_get(
            cfg, f"/extended/v2/addresses/{cfg.stx_address}/stacking"
        )
    except Exception:
        stacker_info = {}

    # Calculate enhanced cycle metrics
    reward_phase_length = pox_data.get("reward_phase_block_length", 0)
    prepare_phase_length = pox_data.get("prepare_phase_block_length", 0)
    total_cycle_length = reward_phase_length + prepare_phase_length

    current_burn_height = pox_data.get("current_burnchain_block_height", 0)
    first_burnchain_block_height = pox_data.get("first_burnchain_block_height", 0)

    # Calculate blocks into current cycle and progress
    blocks_into_cycle = 0
    percent_complete = 0.0
    blocks_remaining = 0
    estimated_minutes_remaining = 0

    if (
        total_cycle_length > 0
        and current_burn_height > 0
        and first_burnchain_block_height > 0
    ):
        blocks_since_start = current_burn_height - first_burnchain_block_height
        blocks_into_cycle = blocks_since_start % total_cycle_length
        percent_complete = round((blocks_into_cycle / total_cycle_length) * 100, 2)
        blocks_remaining = total_cycle_length - blocks_into_cycle
        # Bitcoin averages ~10 minutes per block
        estimated_minutes_remaining = blocks_remaining * 10

    # Participation rate
    total_liquid_supply = pox_data.get("total_liquid_supply_ustx", 0)
    stacked_ustx = current_cycle.get("stacked_ustx", 0)
    participation_rate = 0.0
    if total_liquid_supply > 0:
        participation_rate = round((stacked_ustx / total_liquid_supply) * 100, 2)

    return {
        "pox_contract": pox_data.get("contract_id", ""),
        "current_cycle": {
            "id": current_cycle.get("id"),
            "min_threshold_ustx": current_cycle.get("min_threshold_ustx", 0),
            "stacked_ustx": stacked_ustx,
            "is_pox_active": current_cycle.get("is_pox_active", False),
            "blocks_into_cycle": blocks_into_cycle,
            "blocks_remaining": blocks_remaining,
            "percent_complete": percent_complete,
            "estimated_minutes_remaining": estimated_minutes_remaining,
        },
        "next_cycle": {
            "id": next_cycle.get("id"),
            "min_threshold_ustx": next_cycle.get("min_threshold_ustx", 0),
            "stacked_ustx": next_cycle.get("stacked_ustx", 0),
            "blocks_until_prepare_phase": next_cycle.get("blocks_until_prepare_phase"),
        },
        "reward_phase_block_length": reward_phase_length,
        "prepare_phase_block_length": prepare_phase_length,
        "total_cycle_length": total_cycle_length,
        "current_burnchain_block_height": current_burn_height,
        "total_liquid_supply_ustx": total_liquid_supply,
        "participation_rate_percent": participation_rate,
        "wallet_stacking": stacker_info if stacker_info else None,
        "address": cfg.stx_address,
        "network": cfg.network,
    }


def stx_stack(
    cfg: STXConfig,
    amount_ustx: int,
    pox_address: str,
    num_cycles: int = 1,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Initiate STX stacking (solo stacking).

    Calls the PoX contract's stack-stx function.

    - amount_ustx: amount to stack in micro-STX
    - pox_address: BTC address for reward payouts
    - num_cycles: number of cycles to stack (1-12)
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    if amount_ustx <= 0:
        raise ValueError("Amount must be greater than zero.")
    if num_cycles < 1 or num_cycles > 12:
        raise ValueError("num_cycles must be between 1 and 12.")
    if not pox_address:
        raise ValueError("pox_address (BTC reward address) is required.")

    # PoX contract is at SP000000000000000000002Q6VF78.pox-4
    pox_parts = POX_CONTRACT.split(".")
    pox_addr = pox_parts[0]
    pox_name = pox_parts[1]

    # Get current burn block height for start-burn-ht
    try:
        pox_data = _hiro_get(cfg, "/v2/pox")
        burn_height = pox_data.get("current_burnchain_block_height", 0)
    except Exception:
        burn_height = 0

    result = stx_call_contract(
        cfg,
        contract_address=pox_addr,
        contract_name=pox_name,
        function_name="stack-stx",
        function_args=[
            f"u{amount_ustx}",
            # pox-addr is a tuple; simplified as buffer for the BTC address hash
            f"0x{pox_address.encode('utf-8').hex()}",
            f"u{burn_height}",
            f"u{num_cycles}",
        ],
        dry_run=dry_run,
    )

    result["stacking_details"] = {
        "amount_ustx": amount_ustx,
        "amount_stx": str(Decimal(amount_ustx) / Decimal("1000000")),
        "pox_address": pox_address,
        "num_cycles": num_cycles,
        "start_burn_height": burn_height,
    }
    return result


def stx_revoke_delegation(
    cfg: STXConfig,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Revoke stacking delegation.

    Calls the PoX contract's revoke-delegate-stx function.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    pox_parts = POX_CONTRACT.split(".")
    pox_addr = pox_parts[0]
    pox_name = pox_parts[1]

    result = stx_call_contract(
        cfg,
        contract_address=pox_addr,
        contract_name=pox_name,
        function_name="revoke-delegate-stx",
        function_args=[],
        dry_run=dry_run,
    )

    result["action"] = "revoke_delegation"
    return result
