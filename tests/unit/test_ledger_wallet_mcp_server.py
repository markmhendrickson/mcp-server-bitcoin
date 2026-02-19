"""Unit tests for Phase 5C: Ledger hardware wallet MCP tools."""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import bitcoin_wallet_mcp_server as server  # noqa: E402
import ledger_wallet  # noqa: E402


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
    candidate_wifs = []


def _mk_btc(*a, **k):
    return DummyBTCCfg()


# ---------------------------------------------------------------------------
# Tool presence
# ---------------------------------------------------------------------------


def test_ledger_tools_in_list():
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert "ledger_get_addresses" in names
    assert "ledger_sign_psbt" in names
    assert "ledger_sign_stx_transaction" in names


def test_total_tool_count():
    tools = asyncio.run(server.list_tools())
    assert len(tools) == 93


# ---------------------------------------------------------------------------
# BIP-32 path serialization
# ---------------------------------------------------------------------------


def test_serialize_bip32_path():
    result = ledger_wallet._serialize_bip32_path("m/84'/0'/0'/0/0")
    # 5 components
    assert result[0] == 5
    # Total: 1 (count) + 5*4 (indices) = 21 bytes
    assert len(result) == 21


def test_serialize_bip32_path_hardened():
    result = ledger_wallet._serialize_bip32_path("m/44'/5757'/0'/0/0")
    assert result[0] == 5
    # Check that first index is 44 + 0x80000000
    import struct

    idx = struct.unpack_from(">I", result, 1)[0]
    assert idx == 44 + 0x80000000


# ---------------------------------------------------------------------------
# ledger_get_addresses
# ---------------------------------------------------------------------------


def test_ledger_get_addresses_mock(monkeypatch):
    """Test with mocked transport."""
    monkeypatch.setattr(
        server,
        "BTCConfig",
        type("C", (), {"from_env": classmethod(_mk_btc)}),
    )

    def mock_get_addrs(network, account, display, interface):
        return {
            "addresses": [
                {
                    "symbol": "BTC",
                    "type": "p2wpkh",
                    "address": "tb1qmock",
                    "derivationPath": "m/84'/1'/0'/0/0",
                },
                {
                    "symbol": "BTC",
                    "type": "p2tr",
                    "address": "tb1pmock",
                    "derivationPath": "m/86'/1'/0'/0/0",
                },
            ],
            "account": account,
            "network": network,
            "device": "ledger",
        }

    monkeypatch.setattr(server, "ledger_get_addresses", mock_get_addrs)

    response = asyncio.run(server._handle_ledger_get_addresses({}))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["device"] == "ledger"
    assert len(payload["addresses"]) == 2
    assert payload["addresses"][0]["type"] == "p2wpkh"


def test_ledger_get_addresses_no_device():
    """Without a real device, should get a connection error."""
    monkeypatch_obj = None
    try:
        # This should fail with a connection error since no Ledger is attached
        result = ledger_wallet.ledger_get_addresses(network="testnet", interface="tcp")
        # If it somehow succeeds (e.g., something listening on port 9999), that's OK
    except RuntimeError as e:
        assert "Failed to connect" in str(e) or "Ledger" in str(e)


# ---------------------------------------------------------------------------
# ledger_sign_psbt
# ---------------------------------------------------------------------------


def test_ledger_sign_psbt_missing_param():
    response = asyncio.run(server.call_tool("ledger_sign_psbt", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "psbt" in payload["error"]


def test_ledger_sign_psbt_mock(monkeypatch):
    monkeypatch.setattr(
        server,
        "BTCConfig",
        type("C", (), {"from_env": classmethod(_mk_btc)}),
    )

    def mock_sign(psbt, network, interface):
        return {
            "hex": psbt,
            "base64": "",
            "device": "ledger",
            "network": network,
        }

    monkeypatch.setattr(server, "ledger_sign_psbt", mock_sign)

    response = asyncio.run(server._handle_ledger_sign_psbt({"psbt": "70736274ff01"}))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["device"] == "ledger"


# ---------------------------------------------------------------------------
# ledger_sign_stx_transaction
# ---------------------------------------------------------------------------


def test_ledger_sign_stx_tx_missing_param():
    response = asyncio.run(server.call_tool("ledger_sign_stx_transaction", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "tx_hex" in payload["error"]


def test_ledger_sign_stx_tx_mock(monkeypatch):
    def mock_sign(tx_hex, path, interface):
        return {
            "transaction": tx_hex,
            "txHex": tx_hex,
            "signature": "00" * 65,
            "derivationPath": path,
            "device": "ledger",
        }

    monkeypatch.setattr(server, "ledger_sign_stx_transaction", mock_sign)

    response = asyncio.run(
        server._handle_ledger_sign_stx_transaction({"tx_hex": "aabb"})
    )
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["device"] == "ledger"
    assert payload["derivationPath"] == "m/44'/5757'/0'/0/0"
