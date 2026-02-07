"""Unit tests for Phase 4: Swaps, DeFi & Bridge MCP tools."""

import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import btc_wallet_mcp_server as server  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(response):
    return json.loads(response[0].text)


class DummySTXCfg:
    private_key = bytes.fromhex("0" * 64)
    public_key = bytes.fromhex("02" + "ab" * 32)
    stx_address = "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG"
    network = "testnet"
    hiro_api_url = "https://api.testnet.hiro.so"
    dry_run_default = True
    derivation_path = "m/44'/5757'/0'/0/0"


def _make_dummy_stx_cfg(*_args, **_kwargs):
    return DummySTXCfg()


# ---------------------------------------------------------------------------
# Tool list tests
# ---------------------------------------------------------------------------


def test_phase4_tools_in_tool_list():
    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}
    expected = {
        "swap_get_supported_pairs", "swap_get_quote", "swap_execute", "swap_get_history",
        "sbtc_get_balance", "sbtc_bridge_deposit", "sbtc_bridge_withdraw",
        "stx_get_stacking_info", "stx_stack", "stx_revoke_delegation",
    }
    assert expected.issubset(names), f"Missing: {expected - names}"


def test_total_tool_count():
    """Phase 1 (19) + Phase 2 (18) + Phase 3 (7) + Phase 4 (10) = 54."""
    tools = asyncio.run(server.list_tools())
    assert len(tools) == 54


# ---------------------------------------------------------------------------
# 4.1 Swap Operations
# ---------------------------------------------------------------------------


def test_swap_get_supported_pairs(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_pairs(cfg):
        return {
            "protocols": ["alex"],
            "pair_count": 2,
            "pairs": [
                {"pool_id": 1, "token_x": "STX", "token_y": "ALEX", "apr_7d": 5.2},
                {"pool_id": 2, "token_x": "STX", "token_y": "sBTC", "apr_7d": 3.1},
            ],
            "network": "testnet",
        }

    monkeypatch.setattr(server, "swap_get_supported_pairs", mock_pairs)
    response = asyncio.run(server._handle_swap_get_supported_pairs())
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["pair_count"] == 2


def test_swap_get_quote_missing_params():
    response = asyncio.run(server.call_tool("swap_get_quote", {"token_in": "STX"}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "token_out" in payload["error"]


def test_swap_get_quote(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_quote(cfg, token_in, token_out, amount, protocol):
        return {
            "token_in": token_in,
            "token_out": token_out,
            "amount_in": amount,
            "estimated_output": 95000,
            "exchange_rate": 0.95,
            "fee_pct": 0.003,
            "protocol": protocol,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "swap_get_quote", mock_quote)
    response = asyncio.run(server._handle_swap_get_quote({
        "token_in": "STX", "token_out": "ALEX", "amount": 100000,
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["estimated_output"] == 95000


def test_swap_execute_missing_params():
    response = asyncio.run(server.call_tool("swap_execute", {"token_in": "STX"}))
    payload = _parse(response)
    assert payload["success"] is False


def test_swap_execute(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_exec(cfg, ti, to, amt, mo, proto, dr):
        return {
            "txid": "DRYRUN_swap123",
            "dry_run": True,
            "swap_details": {"token_in": ti, "token_out": to, "amount_in": amt},
            "network": "testnet",
        }

    monkeypatch.setattr(server, "swap_execute", mock_exec)
    response = asyncio.run(server._handle_swap_execute({
        "token_in": "STX", "token_out": "ALEX", "amount": 100000,
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["txid"].startswith("DRYRUN_")


def test_swap_get_history(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_history(cfg, limit, offset):
        return {
            "swaps": [{"txid": "tx1", "function_name": "swap-helper"}],
            "count": 1,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "swap_get_history", mock_history)
    response = asyncio.run(server._handle_swap_get_history({}))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["count"] == 1


# ---------------------------------------------------------------------------
# 4.2 sBTC Bridge
# ---------------------------------------------------------------------------


def test_sbtc_get_balance(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_balance(cfg):
        return {
            "address": cfg.stx_address,
            "sbtc_balance": 50000,
            "sbtc_balance_btc": "0.00050000",
            "network": "testnet",
        }

    monkeypatch.setattr(server, "sbtc_get_balance", mock_balance)
    response = asyncio.run(server._handle_sbtc_get_balance())
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["sbtc_balance"] == 50000


def test_sbtc_bridge_deposit_missing_amount():
    response = asyncio.run(server.call_tool("sbtc_bridge_deposit", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "amount_sats" in payload["error"]


def test_sbtc_bridge_deposit(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_deposit(cfg, amount, dr):
        return {
            "action": "deposit",
            "amount_sats": amount,
            "dry_run": True,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "sbtc_bridge_deposit", mock_deposit)
    response = asyncio.run(server._handle_sbtc_bridge_deposit({"amount_sats": 100000}))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["action"] == "deposit"


def test_sbtc_bridge_withdraw_missing_address():
    response = asyncio.run(server.call_tool("sbtc_bridge_withdraw", {"amount_sats": 100}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "btc_address" in payload["error"]


def test_sbtc_bridge_withdraw(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_withdraw(cfg, amount, addr, dr):
        return {
            "action": "withdraw",
            "amount_sats": amount,
            "btc_address": addr,
            "dry_run": True,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "sbtc_bridge_withdraw", mock_withdraw)
    response = asyncio.run(server._handle_sbtc_bridge_withdraw({
        "amount_sats": 50000, "btc_address": "bc1qtest",
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["action"] == "withdraw"


# ---------------------------------------------------------------------------
# 4.3 Yield / Stacking
# ---------------------------------------------------------------------------


def test_stx_get_stacking_info(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_info(cfg):
        return {
            "pox_contract": "SP000000000000000000002Q6VF78.pox-4",
            "current_cycle": {"id": 100, "is_pox_active": True},
            "next_cycle": {"id": 101},
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_stacking_info", mock_info)
    response = asyncio.run(server._handle_stx_get_stacking_info())
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["current_cycle"]["is_pox_active"] is True


def test_stx_stack_missing_params():
    response = asyncio.run(server.call_tool("stx_stack", {"amount_ustx": 1000}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "pox_address" in payload["error"]


def test_stx_stack(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_stack(cfg, amount, pox_addr, cycles, dr):
        return {
            "txid": "DRYRUN_stack123",
            "dry_run": True,
            "stacking_details": {"amount_ustx": amount, "num_cycles": cycles},
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_stack", mock_stack)
    response = asyncio.run(server._handle_stx_stack({
        "amount_ustx": 100000000, "pox_address": "bc1qtest",
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["txid"].startswith("DRYRUN_")


def test_stx_revoke_delegation(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_revoke(cfg, dr):
        return {
            "txid": "DRYRUN_revoke123",
            "action": "revoke_delegation",
            "dry_run": True,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_revoke_delegation", mock_revoke)
    response = asyncio.run(server._handle_stx_revoke_delegation({}))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["action"] == "revoke_delegation"
