import asyncio
import json
import sys
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import btc_wallet_mcp_server as server  # noqa: E402
import btc_wallet  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class DummyCfg:
    network = "testnet"
    dry_run_default = True
    fee_tier = "hourFee"
    fee_rate_sat_per_byte = 10
    use_fixed_fee_rate = False
    max_send_btc = None
    max_fee_sats_env = None
    private_key_wif = "cNYfRxoekiij3wxrMFCJMhCkVizeRaFcDMS72k1MFBBJFqJCD4ZN"
    candidate_wifs = [
        {
            "label": "bip44_p2pkh_0",
            "addr_type": "p2pkh",
            "wif": "cNYfRxoekiij3wxrMFCJMhCkVizeRaFcDMS72k1MFBBJFqJCD4ZN",
            "address": "mxVFsFW5N4mu1HPkxhmZQEsNZXeFbmPGt1",
            "public_key": "02abc123",
            "derivation_path": "m/44'/1'/0'/0/0",
        },
        {
            "label": "bip84_p2wpkh_0",
            "addr_type": "p2wpkh",
            "wif": "cNYfRxoekiij3wxrMFCJMhCkVizeRaFcDMS72k1MFBBJFqJCD4ZN",
            "address": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            "public_key": "02def456",
            "derivation_path": "m/84'/1'/0'/0/0",
        },
        {
            "label": "bip86_p2tr_0",
            "addr_type": "p2tr",
            "wif": "cNYfRxoekiij3wxrMFCJMhCkVizeRaFcDMS72k1MFBBJFqJCD4ZN",
            "address": "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            "public_key": "02789abc",
            "derivation_path": "m/86'/1'/0'/0/0",
        },
    ]


def _make_dummy_cfg(*_args, **_kwargs):
    return DummyCfg()


def _parse(response):
    return json.loads(response[0].text)


# ---------------------------------------------------------------------------
# 1.1 Tests: Multi-Address & Account Management
# ---------------------------------------------------------------------------


def test_list_tools_includes_all_phase1_tools():
    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}

    # Original tools
    assert "btc_wallet_get_balance" in names
    assert "btc_wallet_get_prices" in names
    assert "btc_wallet_preview_transfer" in names
    assert "btc_wallet_send_transfer" in names

    # Phase 1 new tools
    assert "btc_get_addresses" in names
    assert "btc_get_accounts" in names
    assert "btc_get_info" in names
    assert "btc_send_transfer" in names
    assert "btc_send_max" in names
    assert "btc_combine_utxos" in names
    assert "btc_sign_psbt" in names
    assert "btc_sign_batch_psbt" in names
    assert "btc_decode_psbt" in names
    assert "btc_sign_message" in names
    assert "btc_verify_message" in names
    assert "btc_get_fees" in names
    assert "btc_estimate_fee" in names
    assert "btc_list_utxos" in names
    assert "btc_get_utxo_details" in names


def test_list_tools_count():
    """All phases: 19 BTC + 21 STX (incl stacking) + 7 ORD + 4 SWAP + 3 SBTC = 54."""
    tools = asyncio.run(server.list_tools())
    btc_count = sum(1 for t in tools if t.name.startswith("btc_"))
    stx_count = sum(1 for t in tools if t.name.startswith("stx_"))
    ord_count = sum(1 for t in tools if t.name.startswith("ord_"))
    swap_count = sum(1 for t in tools if t.name.startswith("swap_"))
    sbtc_count = sum(1 for t in tools if t.name.startswith("sbtc_"))
    assert btc_count == 19
    assert stx_count == 21  # 18 original + 3 stacking
    assert ord_count == 7
    assert swap_count == 4
    assert sbtc_count == 3
    assert len(tools) == 73


def test_get_addresses_returns_all_types(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}))
    monkeypatch.setattr(btc_wallet, "_make_key_from_wif", lambda *a: type("K", (), {"address": "test"})())

    response = asyncio.run(server._handle_get_addresses())
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["network"] == "testnet"
    assert len(payload["addresses"]) == 3
    types = {a["type"] for a in payload["addresses"]}
    assert "p2pkh" in types
    assert "p2wpkh" in types
    assert "p2tr" in types


def test_get_accounts_returns_balances(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}))
    monkeypatch.setattr(
        btc_wallet, "_fetch_mempool_utxos",
        lambda addr, net: [{"value": 50000}] if "p2wpkh" in addr or "tb1q" in addr else [],
    )
    monkeypatch.setattr(btc_wallet, "_make_key_from_wif", lambda *a: type("K", (), {"address": "test"})())

    response = asyncio.run(server._handle_get_accounts())
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["total_balance_sats"] >= 0
    assert len(payload["accounts"]) == 3


def test_get_info(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}))

    response = asyncio.run(server._handle_get_info())
    payload = _parse(response)

    assert payload["success"] is True
    assert "version" in payload
    assert payload["network"] == "testnet"
    assert "btc_get_addresses" in payload["supported_tools"]
    assert "btc_sign_psbt" in payload["supported_tools"]


# ---------------------------------------------------------------------------
# Original tools (backward compat)
# ---------------------------------------------------------------------------


def test_get_balance_returns_json(monkeypatch):
    monkeypatch.setattr(
        server.BTCConfig, "from_env", classmethod(lambda cls: DummyCfg())
    )
    monkeypatch.setattr(server, "get_balance_btc", lambda cfg: Decimal("1.2345"))

    response = asyncio.run(server._handle_get_balance())
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["balance_btc"] == "1.2345"
    assert payload["network"] == "testnet"


def test_get_prices_returns_json(monkeypatch):
    monkeypatch.setattr(
        server, "_fetch_btc_prices", lambda: (Decimal("91000"), Decimal("84000"))
    )

    response = asyncio.run(server._handle_get_prices())
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["usd"] == "91000"
    assert payload["eur"] == "84000"


# ---------------------------------------------------------------------------
# 1.2 Tests: Enhanced Sending
# ---------------------------------------------------------------------------


def test_send_transfer_multi_missing_recipients():
    response = asyncio.run(server.call_tool("btc_send_transfer", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "recipients" in payload["error"]


def test_send_max_missing_address():
    response = asyncio.run(server.call_tool("btc_send_max", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "to_address" in payload["error"]


def test_send_transfer_multi_calls_backend(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}))
    monkeypatch.setattr(
        server, "send_transfer_multi",
        lambda cfg, recipients, max_fee, memo, dry_run: "DRYRUN_abc123",
    )

    response = asyncio.run(server._handle_send_transfer_multi({
        "recipients": [{"address": "tb1qtest", "amount_sats": 10000}],
    }))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["txid"] == "DRYRUN_abc123"
    assert payload["num_recipients"] == 1


# ---------------------------------------------------------------------------
# 1.3 Tests: PSBT Support
# ---------------------------------------------------------------------------


def test_decode_psbt_missing_param():
    response = asyncio.run(server.call_tool("btc_decode_psbt", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "psbt" in payload["error"]


def test_decode_psbt_invalid():
    response = asyncio.run(server.call_tool("btc_decode_psbt", {"psbt": "not_a_psbt"}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "Invalid PSBT" in payload["error"] or "valid" in payload["error"].lower()


def test_sign_psbt_missing_param():
    response = asyncio.run(server.call_tool("btc_sign_psbt", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "psbt" in payload["error"]


# ---------------------------------------------------------------------------
# 1.4 Tests: Message Signing
# ---------------------------------------------------------------------------


def test_sign_message_missing_message():
    response = asyncio.run(server.call_tool("btc_sign_message", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "message" in payload["error"]


def test_verify_message_missing_params():
    response = asyncio.run(server.call_tool("btc_verify_message", {"message": "hello"}))
    payload = _parse(response)
    assert payload["success"] is False


# ---------------------------------------------------------------------------
# 1.5 Tests: Fee Management
# ---------------------------------------------------------------------------


def test_get_fees(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}))
    monkeypatch.setattr(
        btc_wallet, "_fetch_dynamic_fee_rate_sat_per_byte", lambda *a: 5
    )

    # Mock requests to avoid network calls
    def mock_get_fees(cfg):
        return {
            "fastest_sat_per_vb": 20,
            "half_hour_sat_per_vb": 15,
            "hour_sat_per_vb": 10,
            "economy_sat_per_vb": 5,
            "minimum_sat_per_vb": 1,
            "network": "testnet",
            "source": "mock",
        }

    monkeypatch.setattr(server, "get_fees", mock_get_fees)

    response = asyncio.run(server._handle_get_fees())
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["fastest_sat_per_vb"] == 20
    assert payload["minimum_sat_per_vb"] == 1


def test_estimate_fee(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}))

    def mock_estimate(cfg, num_inputs, num_outputs, addr_type, fee_tier):
        return {
            "estimated_vsize": 141,
            "fee_rate_sat_per_vb": 10,
            "fee_sats": 1410,
            "fee_btc": "0.00001410",
            "num_inputs": num_inputs or 1,
            "num_outputs": num_outputs,
            "address_type": addr_type,
            "fee_tier": fee_tier or "hourFee",
            "network": "testnet",
        }

    monkeypatch.setattr(server, "estimate_fee", mock_estimate)

    response = asyncio.run(server._handle_estimate_fee({
        "num_inputs": 2,
        "num_outputs": 3,
        "address_type": "p2wpkh",
    }))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["fee_sats"] == 1410
    assert payload["num_inputs"] == 2


# ---------------------------------------------------------------------------
# 1.6 Tests: UTXO Management
# ---------------------------------------------------------------------------


def test_list_utxos(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}))

    def mock_list_utxos(cfg, addr_type, min_val, confirmed):
        return [
            {
                "txid": "abc123",
                "vout": 0,
                "value_sats": 50000,
                "value_btc": "0.00050000",
                "confirmed": True,
                "block_height": 100000,
                "address": "tb1qtest",
                "address_type": "p2wpkh",
            }
        ]

    monkeypatch.setattr(server, "list_utxos", mock_list_utxos)

    response = asyncio.run(server._handle_list_utxos({}))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["count"] == 1
    assert payload["total_sats"] == 50000
    assert payload["utxos"][0]["txid"] == "abc123"


def test_get_utxo_details_missing_params():
    response = asyncio.run(server.call_tool("btc_get_utxo_details", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "txid" in payload["error"]


def test_get_utxo_details_missing_vout():
    response = asyncio.run(server.call_tool("btc_get_utxo_details", {"txid": "abc"}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "vout" in payload["error"]


# ---------------------------------------------------------------------------
# Dispatch tests
# ---------------------------------------------------------------------------


def test_unknown_tool():
    response = asyncio.run(server.call_tool("nonexistent_tool", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "Unknown tool" in payload["error"]


def test_invalid_arguments():
    response = asyncio.run(server.call_tool("btc_get_info", "not_a_dict"))
    payload = _parse(response)
    assert payload["success"] is False
    assert "Invalid arguments" in payload["error"]
