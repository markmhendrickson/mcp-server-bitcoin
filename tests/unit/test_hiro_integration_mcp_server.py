"""
Unit tests for Phase 6: Hiro API Enhanced Integration MCP tools.

Tests cover:
- Enhanced transaction queries (stx_query_transactions, stx_query_transactions_by_contract)
- Mempool operations (stx_mempool_list_pending, stx_mempool_get_stats, stx_mempool_get_dropped)
- Block explorer (stx_get_recent_blocks, stx_get_block_by_height, stx_get_block_by_hash, stx_get_stacks_blocks_for_bitcoin_block)
- Contract events (stx_get_contract_events, stx_get_address_asset_events)
- Token metadata (stx_get_token_metadata, stx_get_token_holders)
- Network stats (stx_get_network_info, stx_get_network_status)
- Enhanced stacking info
"""

import asyncio
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import bitcoin_wallet_mcp_server as server  # noqa: E402


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


class DummyBTCCfg:
    network = "testnet"
    fee_tier = "halfHourFee"
    fee_rate_sat_per_byte = None
    use_fixed_fee_rate = False
    dry_run_default = True
    max_send_btc = None
    candidate_wifs = [
        {"addr_type": "p2wpkh", "address": "tb1qtest", "wif": "cTest..."}
    ]


def _make_dummy_stx_cfg(*_a, **_kw):
    return DummySTXCfg()


def _make_dummy_btc_cfg(*_a, **_kw):
    return DummyBTCCfg()


# ---------------------------------------------------------------------------
# Tool list: Phase 6 tools are registered
# ---------------------------------------------------------------------------


def test_phase6_tools_in_tool_list():
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    expected = {
        # 6.1 Enhanced tx queries
        "stx_query_transactions",
        "stx_query_transactions_by_contract",
        # 6.2 Mempool
        "stx_mempool_list_pending",
        "stx_mempool_get_stats",
        "stx_mempool_get_dropped",
        # 6.3 Block explorer
        "stx_get_recent_blocks",
        "stx_get_block_by_height",
        "stx_get_block_by_hash",
        "stx_get_stacks_blocks_for_bitcoin_block",
        # 6.4 Events
        "stx_get_contract_events",
        "stx_get_address_asset_events",
        # 6.5 Token metadata
        "stx_get_token_metadata",
        "stx_get_token_holders",
        # 6.6 Network stats
        "stx_get_network_info",
        "stx_get_network_status",
    }
    assert expected.issubset(names), f"Missing: {expected - names}"


def test_phase6_adds_16_tools():
    """Phase 6 adds 16 new tools on top of previous 77."""
    tools = asyncio.run(server.list_tools())
    assert len(tools) == 93


# ---------------------------------------------------------------------------
# 6.1 Enhanced Transaction Queries
# ---------------------------------------------------------------------------


def test_stx_query_transactions(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_btc_cfg)}),
    )
    monkeypatch.setenv("STX_ADDRESS", "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG")

    def mock_query(cfg, address=None, limit=50, offset=0, tx_type=None, unanchored=False):
        return {
            "address": address or "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG",
            "transactions": [
                {"txid": "0xabc", "tx_type": "token_transfer", "status": "success"},
                {"txid": "0xdef", "tx_type": "contract_call", "status": "success"},
            ],
            "total": 2,
            "limit": limit,
            "offset": offset,
            "tx_type_filter": tx_type,
            "unanchored": unanchored,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_query_transactions", mock_query)
    response = asyncio.run(server._handle_stx_query_transactions({"limit": 10}))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["total"] == 2
    assert len(payload["transactions"]) == 2


def test_stx_query_transactions_with_type_filter(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_btc_cfg)}),
    )

    def mock_query(cfg, address=None, limit=50, offset=0, tx_type=None, unanchored=False):
        return {
            "address": "ST2CY5...",
            "transactions": [{"txid": "0xabc", "tx_type": "contract_call"}],
            "total": 1,
            "limit": limit,
            "offset": offset,
            "tx_type_filter": tx_type,
            "unanchored": unanchored,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_query_transactions", mock_query)
    response = asyncio.run(server._handle_stx_query_transactions({
        "tx_type": "contract_call", "unanchored": True,
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["tx_type_filter"] == "contract_call"


def test_stx_query_transactions_by_contract(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_btc_cfg)}),
    )

    def mock_query(cfg, contract_id=None, function_name=None, limit=50, offset=0):
        return {
            "contract_id": contract_id,
            "function_name_filter": function_name,
            "transactions": [
                {"txid": "0xabc", "tx_type": "contract_call", "status": "success"},
            ],
            "total": 1,
            "limit": limit,
            "offset": offset,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_query_transactions_by_contract", mock_query)
    response = asyncio.run(server._handle_stx_query_transactions_by_contract({
        "contract_id": "SP000.my-contract",
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["contract_id"] == "SP000.my-contract"
    assert payload["total"] == 1


def test_stx_query_transactions_by_contract_missing_id():
    response = asyncio.run(server.call_tool("stx_query_transactions_by_contract", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "contract_id" in payload["error"]


# ---------------------------------------------------------------------------
# 6.2 Mempool Operations
# ---------------------------------------------------------------------------


def test_stx_mempool_list_pending(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_pending(cfg, address=None, limit=50, offset=0):
        return {
            "transactions": [
                {"txid": "0x111", "tx_type": "token_transfer", "tx_status": "pending"},
            ],
            "total": 1,
            "limit": limit,
            "offset": offset,
            "address": address,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_mempool_list_pending", mock_pending)
    response = asyncio.run(server._handle_stx_mempool_list_pending({}))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["total"] == 1
    assert payload["transactions"][0]["txid"] == "0x111"


def test_stx_mempool_list_pending_with_address(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_pending(cfg, address=None, limit=50, offset=0):
        return {
            "transactions": [],
            "total": 0,
            "limit": limit,
            "offset": offset,
            "address": address,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_mempool_list_pending", mock_pending)
    response = asyncio.run(server._handle_stx_mempool_list_pending({
        "address": "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG",
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["address"] == "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG"


def test_stx_mempool_get_stats(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_stats(cfg):
        return {
            "tx_type_counts": {"token_transfer": 42, "contract_call": 18},
            "tx_simple_fee_averages": {"token_transfer": {"p50": 200}},
            "tx_ages": {},
            "tx_byte_sizes": {},
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_mempool_get_stats", mock_stats)
    response = asyncio.run(server._handle_stx_mempool_get_stats())
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["tx_type_counts"]["token_transfer"] == 42


def test_stx_mempool_get_dropped(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_dropped(cfg, limit=50, offset=0):
        return {
            "dropped_transactions": [
                {"txid": "0xdead", "tx_type": "token_transfer", "reason": "replaced"},
            ],
            "total": 1,
            "limit": limit,
            "offset": offset,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_mempool_get_dropped", mock_dropped)
    response = asyncio.run(server._handle_stx_mempool_get_dropped({}))
    payload = _parse(response)
    assert payload["success"] is True
    assert len(payload["dropped_transactions"]) == 1


# ---------------------------------------------------------------------------
# 6.3 Block Explorer
# ---------------------------------------------------------------------------


def test_stx_get_recent_blocks(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_blocks(cfg, limit=20, offset=0):
        return {
            "blocks": [
                {"height": 100, "hash": "0xabc", "tx_count": 5},
                {"height": 99, "hash": "0xdef", "tx_count": 3},
            ],
            "total": 100,
            "limit": limit,
            "offset": offset,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_recent_blocks", mock_blocks)
    response = asyncio.run(server._handle_stx_get_recent_blocks({"limit": 2}))
    payload = _parse(response)
    assert payload["success"] is True
    assert len(payload["blocks"]) == 2
    assert payload["blocks"][0]["height"] == 100


def test_stx_get_block_by_height(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_block(cfg, height):
        return {
            "height": height,
            "hash": "0xabc123",
            "tx_count": 10,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_block_by_height", mock_block)
    response = asyncio.run(server._handle_stx_get_block_by_height({"height": 100}))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["height"] == 100


def test_stx_get_block_by_height_missing_param():
    response = asyncio.run(server.call_tool("stx_get_block_by_height", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "height" in payload["error"]


def test_stx_get_block_by_hash(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_block(cfg, block_hash):
        return {
            "height": 100,
            "hash": block_hash,
            "tx_count": 10,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_block_by_hash", mock_block)
    response = asyncio.run(server._handle_stx_get_block_by_hash({"block_hash": "0xabc123"}))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["hash"] == "0xabc123"


def test_stx_get_block_by_hash_missing_param():
    response = asyncio.run(server.call_tool("stx_get_block_by_hash", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "block_hash" in payload["error"]


def test_stx_get_stacks_blocks_for_bitcoin_block(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_blocks(cfg, bitcoin_height, limit=20, offset=0):
        return {
            "bitcoin_block_height": bitcoin_height,
            "stacks_blocks": [
                {"height": 500, "hash": "0xstx1"},
                {"height": 501, "hash": "0xstx2"},
            ],
            "total": 2,
            "limit": limit,
            "offset": offset,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_stacks_blocks_for_bitcoin_block", mock_blocks)
    response = asyncio.run(server._handle_stx_get_stacks_blocks_for_bitcoin_block({
        "bitcoin_height": 935748,
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["bitcoin_block_height"] == 935748
    assert len(payload["stacks_blocks"]) == 2


def test_stx_get_stacks_blocks_for_bitcoin_block_missing_param():
    response = asyncio.run(server.call_tool("stx_get_stacks_blocks_for_bitcoin_block", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "bitcoin_height" in payload["error"]


# ---------------------------------------------------------------------------
# 6.4 Contract Event Monitoring
# ---------------------------------------------------------------------------


def test_stx_get_contract_events(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_events(cfg, contract_id, limit=50, offset=0):
        return {
            "contract_id": contract_id,
            "events": [
                {"event_type": "smart_contract_log", "tx_id": "0xabc", "topic": "print"},
                {"event_type": "fungible_token_asset", "tx_id": "0xdef", "amount": "100"},
            ],
            "total": 2,
            "limit": limit,
            "offset": offset,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_contract_events", mock_events)
    response = asyncio.run(server._handle_stx_get_contract_events({
        "contract_id": "SP000.my-contract",
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["contract_id"] == "SP000.my-contract"
    assert len(payload["events"]) == 2


def test_stx_get_contract_events_missing_id():
    response = asyncio.run(server.call_tool("stx_get_contract_events", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "contract_id" in payload["error"]


def test_stx_get_address_asset_events(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_events(cfg, address=None, limit=50, offset=0):
        return {
            "address": address or "ST2CY5...",
            "events": [
                {"event_type": "fungible_token_asset", "tx_id": "0xabc"},
            ],
            "total": 1,
            "limit": limit,
            "offset": offset,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_address_asset_events", mock_events)
    response = asyncio.run(server._handle_stx_get_address_asset_events({}))
    payload = _parse(response)
    assert payload["success"] is True
    assert len(payload["events"]) == 1


# ---------------------------------------------------------------------------
# 6.5 Token Metadata
# ---------------------------------------------------------------------------


def test_stx_get_token_metadata_ft(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_metadata(cfg, contract_id, token_type="ft"):
        return {
            "contract_id": contract_id,
            "name": "Alex Token",
            "symbol": "ALEX",
            "decimals": 8,
            "total_supply": "1000000000000",
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_token_metadata", mock_metadata)
    response = asyncio.run(server._handle_stx_get_token_metadata({
        "contract_id": "SP000.alex-token",
        "token_type": "ft",
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["name"] == "Alex Token"
    assert payload["symbol"] == "ALEX"


def test_stx_get_token_metadata_nft(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_metadata(cfg, contract_id, token_type="ft"):
        return {
            "contract_id": contract_id,
            "name": "My NFT Collection",
            "description": "A test NFT",
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_token_metadata", mock_metadata)
    response = asyncio.run(server._handle_stx_get_token_metadata({
        "contract_id": "SP000.my-nft",
        "token_type": "nft",
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["name"] == "My NFT Collection"


def test_stx_get_token_metadata_missing_id():
    response = asyncio.run(server.call_tool("stx_get_token_metadata", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "contract_id" in payload["error"]


def test_stx_get_token_holders(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_holders(cfg, contract_id, limit=50, offset=0):
        return {
            "contract_id": contract_id,
            "holders": [
                {"address": "SP111...", "balance": "500000"},
                {"address": "SP222...", "balance": "300000"},
            ],
            "total": 2,
            "limit": limit,
            "offset": offset,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_token_holders", mock_holders)
    response = asyncio.run(server._handle_stx_get_token_holders({
        "contract_id": "SP000.alex-token",
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert len(payload["holders"]) == 2


def test_stx_get_token_holders_missing_id():
    response = asyncio.run(server.call_tool("stx_get_token_holders", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "contract_id" in payload["error"]


# ---------------------------------------------------------------------------
# 6.6 Network Statistics & Health
# ---------------------------------------------------------------------------


def test_stx_get_network_info(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_btc_cfg)}),
    )

    def mock_info(cfg):
        return {
            "peer_version": 402653189,
            "burn_block_height": 935748,
            "server_version": "stacks-node 2.5.0",
            "stacks_tip_height": 150000,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_network_info", mock_info)
    response = asyncio.run(server._handle_stx_get_network_info())
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["burn_block_height"] == 935748
    assert payload["stacks_tip_height"] == 150000


def test_stx_get_network_status(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_btc_cfg)}),
    )

    def mock_status(cfg):
        return {
            "server_version": "stacks-node 2.5.0",
            "status": "ready",
            "chain_tip": {
                "block_height": 150000,
                "block_hash": "0xabc",
                "burn_block_height": 935748,
            },
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_network_status", mock_status)
    response = asyncio.run(server._handle_stx_get_network_status())
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["status"] == "ready"
    assert payload["chain_tip"]["block_height"] == 150000


# ---------------------------------------------------------------------------
# Enhanced Stacking Info (Phase 1.3)
# ---------------------------------------------------------------------------


def test_enhanced_stacking_info(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_stacking(cfg):
        return {
            "pox_contract": "SP000.pox-4",
            "current_cycle": {
                "id": 128,
                "min_threshold_ustx": 100000000,
                "stacked_ustx": 588800000000000,
                "is_pox_active": True,
                "blocks_into_cycle": 500,
                "blocks_remaining": 1600,
                "percent_complete": 23.81,
                "estimated_minutes_remaining": 16000,
            },
            "next_cycle": {"id": 129},
            "total_cycle_length": 2100,
            "participation_rate_percent": 45.5,
            "wallet_stacking": None,
            "address": "ST2CY5...",
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_stacking_info", mock_stacking)
    response = asyncio.run(server._handle_stx_get_stacking_info())
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["current_cycle"]["percent_complete"] == 23.81
    assert payload["current_cycle"]["blocks_remaining"] == 1600
    assert payload["participation_rate_percent"] == 45.5
    assert payload["total_cycle_length"] == 2100


# ---------------------------------------------------------------------------
# Edge cases and error handling
# ---------------------------------------------------------------------------


def test_unknown_tool_returns_error():
    response = asyncio.run(server.call_tool("nonexistent_tool", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "Unknown tool" in payload["error"]


def test_stx_query_transactions_empty_result(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_btc_cfg)}),
    )

    def mock_query(cfg, address=None, limit=50, offset=0, tx_type=None, unanchored=False):
        return {
            "address": "ST2CY5...",
            "transactions": [],
            "total": 0,
            "limit": limit,
            "offset": offset,
            "tx_type_filter": tx_type,
            "unanchored": unanchored,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_query_transactions", mock_query)
    response = asyncio.run(server._handle_stx_query_transactions({}))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["total"] == 0
    assert payload["transactions"] == []


def test_stx_mempool_empty_stats(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_stats(cfg):
        return {
            "tx_type_counts": {},
            "tx_simple_fee_averages": {},
            "tx_ages": {},
            "tx_byte_sizes": {},
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_mempool_get_stats", mock_stats)
    response = asyncio.run(server._handle_stx_mempool_get_stats())
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["tx_type_counts"] == {}


def test_stx_get_recent_blocks_empty(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_blocks(cfg, limit=20, offset=0):
        return {
            "blocks": [],
            "total": 0,
            "limit": limit,
            "offset": offset,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_recent_blocks", mock_blocks)
    response = asyncio.run(server._handle_stx_get_recent_blocks({}))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["blocks"] == []


def test_stx_get_contract_events_empty(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_events(cfg, contract_id, limit=50, offset=0):
        return {
            "contract_id": contract_id,
            "events": [],
            "total": 0,
            "limit": limit,
            "offset": offset,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_contract_events", mock_events)
    response = asyncio.run(server._handle_stx_get_contract_events({
        "contract_id": "SP000.empty-contract",
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["events"] == []


def test_stx_get_address_asset_events_with_address(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_events(cfg, address=None, limit=50, offset=0):
        return {
            "address": address or cfg.stx_address,
            "events": [
                {"event_type": "stx_asset", "tx_id": "0x123", "amount": "1000000"},
            ],
            "total": 1,
            "limit": limit,
            "offset": offset,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_get_address_asset_events", mock_events)
    response = asyncio.run(server._handle_stx_get_address_asset_events({
        "address": "SP111TESTADDR",
    }))
    payload = _parse(response)
    assert payload["success"] is True
    assert payload["address"] == "SP111TESTADDR"
    assert payload["events"][0]["amount"] == "1000000"
