"""Unit tests for Phase 5A (Tx Management & Wallet) and 5B (BNS & Market Data)."""

import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import bitcoin_wallet_mcp_server as server  # noqa: E402


def _parse(response):
    return json.loads(response[0].text)


class DummyBTCCfg:
    network = "testnet"
    dry_run_default = True
    fee_tier = "hourFee"
    fee_rate_sat_per_byte = 10
    use_fixed_fee_rate = True
    max_send_btc = None
    max_fee_sats_env = None
    private_key_wif = "ctest"
    candidate_wifs = [{"label": "p2wpkh", "addr_type": "p2wpkh", "wif": "ctest",
                        "address": "tb1qtest", "public_key": "02ab", "derivation_path": "m/84'/1'/0'/0/0"}]


class DummySTXCfg:
    private_key = bytes(32)
    public_key = bytes.fromhex("02" + "ab" * 32)
    stx_address = "STtest"
    network = "testnet"
    hiro_api_url = "https://api.testnet.hiro.so"
    dry_run_default = True
    derivation_path = "m/44'/5757'/0'/0/0"


def _mk_btc(*a, **k):
    return DummyBTCCfg()


def _mk_stx(*a, **k):
    return DummySTXCfg()


# ---------------------------------------------------------------------------
# Tool list
# ---------------------------------------------------------------------------


def test_phase5a_tools_present():
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    expected = {"tx_get_history", "tx_get_status", "tx_speed_up", "tx_cancel",
                "wallet_get_network", "wallet_switch_network", "wallet_add_network",
                "wallet_get_supported_methods"}
    assert expected.issubset(names), f"Missing: {expected - names}"


def test_phase5b_tools_present():
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    expected = {"bns_lookup", "bns_get_names", "bns_register",
                "market_get_prices", "market_get_history",
                "portfolio_get_summary", "portfolio_get_assets", "portfolio_get_collectibles"}
    assert expected.issubset(names), f"Missing: {expected - names}"


def test_total_tool_count():
    tools = asyncio.run(server.list_tools())
    assert len(tools) == 93


# ---------------------------------------------------------------------------
# 5A: Transaction Management
# ---------------------------------------------------------------------------


def test_tx_get_history(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("C", (), {"from_env": classmethod(_mk_btc)}))

    def mock(cfg, chain, limit, offset):
        return {"btc_transactions": [{"txid": "tx1"}], "btc_count": 1, "network": "testnet", "chain": chain}

    monkeypatch.setattr(server, "tx_get_history", mock)
    r = asyncio.run(server._handle_tx_get_history({"chain": "btc"}))
    p = _parse(r)
    assert p["success"] is True
    assert p["btc_count"] == 1


def test_tx_get_status_missing_txid():
    r = asyncio.run(server.call_tool("tx_get_status", {}))
    p = _parse(r)
    assert p["success"] is False
    assert "txid" in p["error"]


def test_tx_get_status(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("C", (), {"from_env": classmethod(_mk_btc)}))

    def mock(cfg, txid, chain):
        return {"txid": txid, "chain": chain, "confirmed": True, "network": "testnet"}

    monkeypatch.setattr(server, "tx_get_status", mock)
    r = asyncio.run(server._handle_tx_get_status({"txid": "abc123"}))
    p = _parse(r)
    assert p["success"] is True
    assert p["confirmed"] is True


def test_tx_speed_up_missing_txid():
    r = asyncio.run(server.call_tool("tx_speed_up", {}))
    p = _parse(r)
    assert p["success"] is False
    assert "txid" in p["error"]


def test_tx_cancel_missing_txid():
    r = asyncio.run(server.call_tool("tx_cancel", {}))
    p = _parse(r)
    assert p["success"] is False
    assert "txid" in p["error"]


# ---------------------------------------------------------------------------
# 5A: Wallet Management
# ---------------------------------------------------------------------------


def test_wallet_get_network(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("C", (), {"from_env": classmethod(_mk_btc)}))

    def mock(cfg):
        return {"network": "testnet", "fee_tier": "hourFee"}

    monkeypatch.setattr(server, "wallet_get_network", mock)
    r = asyncio.run(server._handle_wallet_get_network())
    p = _parse(r)
    assert p["success"] is True
    assert p["network"] == "testnet"


def test_wallet_switch_network_missing():
    r = asyncio.run(server.call_tool("wallet_switch_network", {}))
    p = _parse(r)
    assert p["success"] is False
    assert "network" in p["error"]


def test_wallet_switch_network(monkeypatch):
    def mock(net):
        return {"network": net, "message": f"Switched to {net}"}

    monkeypatch.setattr(server, "wallet_switch_network", mock)
    r = asyncio.run(server._handle_wallet_switch_network({"network": "mainnet"}))
    p = _parse(r)
    assert p["success"] is True
    assert p["network"] == "mainnet"


def test_wallet_add_network(monkeypatch):
    def mock(name, btc, stx):
        return {"name": name, "btc_api_url": btc, "stx_api_url": stx}

    monkeypatch.setattr(server, "wallet_add_network", mock)
    r = asyncio.run(server._handle_wallet_add_network({"name": "custom", "btc_api_url": "http://x"}))
    p = _parse(r)
    assert p["success"] is True
    assert p["name"] == "custom"


def test_wallet_get_supported_methods():
    r = asyncio.run(server._handle_wallet_get_supported_methods())
    p = _parse(r)
    assert p["success"] is True
    assert p["count"] == 93
    assert any(m["name"] == "btc_get_addresses" for m in p["methods"])
    assert any(m["name"] == "bns_lookup" for m in p["methods"])


# ---------------------------------------------------------------------------
# 5B: BNS
# ---------------------------------------------------------------------------


def test_bns_lookup_missing_name():
    r = asyncio.run(server.call_tool("bns_lookup", {}))
    p = _parse(r)
    assert p["success"] is False
    assert "name" in p["error"]


def test_bns_lookup(monkeypatch):
    monkeypatch.setattr(server, "STXConfig", type("C", (), {"from_env": classmethod(_mk_stx)}))

    def mock(cfg, name):
        return {"name": name, "address": "SPabc123", "status": "registered", "network": "testnet"}

    monkeypatch.setattr(server, "bns_lookup", mock)
    r = asyncio.run(server._handle_bns_lookup({"name": "alice.btc"}))
    p = _parse(r)
    assert p["success"] is True
    assert p["address"] == "SPabc123"


def test_bns_get_names(monkeypatch):
    monkeypatch.setattr(server, "STXConfig", type("C", (), {"from_env": classmethod(_mk_stx)}))

    def mock(cfg, addr):
        return {"address": cfg.stx_address, "names": ["alice.btc"], "count": 1, "network": "testnet"}

    monkeypatch.setattr(server, "bns_get_names", mock)
    r = asyncio.run(server._handle_bns_get_names({}))
    p = _parse(r)
    assert p["success"] is True
    assert p["count"] == 1


def test_bns_register_missing_name():
    r = asyncio.run(server.call_tool("bns_register", {}))
    p = _parse(r)
    assert p["success"] is False
    assert "name" in p["error"]


# ---------------------------------------------------------------------------
# 5B: Market Data
# ---------------------------------------------------------------------------


def test_market_get_prices(monkeypatch):
    def mock(coins, vs):
        return {"prices": {"bitcoin": {"usd": 68000}}, "coins": coins or ["bitcoin"], "vs_currencies": vs or ["usd"]}

    monkeypatch.setattr(server, "market_get_prices", mock)
    r = asyncio.run(server._handle_market_get_prices({}))
    p = _parse(r)
    assert p["success"] is True
    assert p["prices"]["bitcoin"]["usd"] == 68000


def test_market_get_history(monkeypatch):
    def mock(coin, vs, days, interval):
        return {"coin": coin, "data_points": 7, "prices": [{"timestamp": 1, "price": 68000}], "latest_price": 68000}

    monkeypatch.setattr(server, "market_get_history", mock)
    r = asyncio.run(server._handle_market_get_history({}))
    p = _parse(r)
    assert p["success"] is True
    assert p["data_points"] == 7


# ---------------------------------------------------------------------------
# 5B: Portfolio
# ---------------------------------------------------------------------------


def test_portfolio_get_summary(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("C", (), {"from_env": classmethod(_mk_btc)}))
    monkeypatch.setattr(server, "STXConfig", type("C", (), {"from_env": classmethod(_mk_stx)}))

    def mock(btc_cfg, stx_cfg):
        return {"total_value_usd": 1234.56, "btc": {"balance_btc": "0.01"}, "stx": {"balance_stx": "100"}, "network": "testnet"}

    monkeypatch.setattr(server, "portfolio_get_summary", mock)
    r = asyncio.run(server._handle_portfolio_get_summary())
    p = _parse(r)
    assert p["success"] is True
    assert p["total_value_usd"] == 1234.56


def test_portfolio_get_assets(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("C", (), {"from_env": classmethod(_mk_btc)}))
    monkeypatch.setattr(server, "STXConfig", type("C", (), {"from_env": classmethod(_mk_stx)}))

    def mock(btc_cfg, stx_cfg):
        return {"assets": [{"symbol": "BTC"}, {"symbol": "STX"}], "count": 2, "network": "testnet"}

    monkeypatch.setattr(server, "portfolio_get_assets", mock)
    r = asyncio.run(server._handle_portfolio_get_assets())
    p = _parse(r)
    assert p["success"] is True
    assert p["count"] == 2


def test_portfolio_get_collectibles(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("C", (), {"from_env": classmethod(_mk_btc)}))
    monkeypatch.setattr(server, "STXConfig", type("C", (), {"from_env": classmethod(_mk_stx)}))

    def mock(btc_cfg, stx_cfg, limit):
        return {"collectibles": [{"type": "inscription", "id": "abc"}], "count": 1, "network": "testnet"}

    monkeypatch.setattr(server, "portfolio_get_collectibles", mock)
    r = asyncio.run(server._handle_portfolio_get_collectibles({}))
    p = _parse(r)
    assert p["success"] is True
    assert p["count"] == 1
