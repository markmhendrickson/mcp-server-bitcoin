"""Unit tests for Phase 3: Ordinals & Inscriptions MCP tools."""

import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import bitcoin_wallet_mcp_server as server  # noqa: E402
import ord_wallet  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    private_key_wif = "cNYfRxoekiij3wxrMFCJMhCkVizeRaFcDMS72k1MFBBJFqJCD4ZN"
    candidate_wifs = [
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
    return DummyBTCCfg()


# ---------------------------------------------------------------------------
# Tool list tests
# ---------------------------------------------------------------------------


def test_ord_tools_in_tool_list():
    """All Phase 3 tools should appear in the tool list."""
    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}

    ord_expected = {
        "ord_get_inscriptions",
        "ord_get_inscription_details",
        "ord_send_inscriptions",
        "ord_send_inscriptions_split",
        "ord_extract_from_utxo",
        "ord_recover_bitcoin",
        "ord_recover_ordinals",
    }
    assert ord_expected.issubset(names), f"Missing: {ord_expected - names}"


def test_total_tool_count():
    """All phases = 54 tools."""
    tools = asyncio.run(server.list_tools())
    assert len(tools) == 93


# ---------------------------------------------------------------------------
# Address helper tests
# ---------------------------------------------------------------------------


def test_get_ordinals_address_prefers_taproot():
    cfg = DummyBTCCfg()
    addr = ord_wallet._get_ordinals_address(cfg)
    assert "tb1p" in addr  # taproot address


def test_get_payment_address_prefers_p2wpkh():
    cfg = DummyBTCCfg()
    addr = ord_wallet._get_payment_address(cfg)
    assert "tb1q" in addr  # native segwit


# ---------------------------------------------------------------------------
# Inscription query tests
# ---------------------------------------------------------------------------


def test_ord_get_inscriptions(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}),
    )

    def mock_get_inscriptions(cfg, offset, limit, address):
        return {
            "total": 2,
            "limit": limit,
            "offset": offset,
            "inscriptions": [
                {
                    "inscriptionId": "abc123i0",
                    "inscriptionNumber": "100",
                    "address": "tb1p...",
                    "contentType": "image/png",
                    "contentLength": 5000,
                    "mimeType": "image/png",
                    "genesisTransaction": "abc123",
                    "location": "abc123:0:0",
                    "output": "abc123:0",
                    "offset": "0",
                    "value": "546",
                    "satOrdinal": "12345",
                    "satRarity": "common",
                    "timestamp": 1700000000,
                },
            ],
            "address": "tb1p...",
            "network": "testnet",
        }

    monkeypatch.setattr(server, "ord_get_inscriptions", mock_get_inscriptions)

    response = asyncio.run(server._handle_ord_get_inscriptions({}))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["total"] == 2
    assert len(payload["inscriptions"]) == 1
    assert payload["inscriptions"][0]["inscriptionId"] == "abc123i0"


def test_ord_get_inscription_details_missing_id():
    response = asyncio.run(server.call_tool("ord_get_inscription_details", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "inscription_id" in payload["error"]


def test_ord_get_inscription_details(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}),
    )

    def mock_details(cfg, iid):
        return {
            "inscriptionId": iid,
            "inscriptionNumber": 42,
            "address": "tb1p...",
            "mimeType": "text/plain",
            "contentType": "text/plain;charset=utf-8",
            "contentLength": 100,
            "satRarity": "uncommon",
            "network": "testnet",
        }

    monkeypatch.setattr(server, "ord_get_inscription_details", mock_details)

    response = asyncio.run(server._handle_ord_get_inscription_details({
        "inscription_id": "abc123i0",
    }))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["inscriptionId"] == "abc123i0"
    assert payload["satRarity"] == "uncommon"


# ---------------------------------------------------------------------------
# Send inscription tests
# ---------------------------------------------------------------------------


def test_ord_send_inscriptions_missing_transfers():
    response = asyncio.run(server.call_tool("ord_send_inscriptions", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "transfers" in payload["error"]


def test_ord_send_inscriptions(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}),
    )

    def mock_send(cfg, transfers, fee_rate, dry_run):
        return {
            "txid": "DRYRUN_abc123",
            "transfers": [{"inscriptionId": t["inscriptionId"], "toAddress": t["address"]} for t in transfers],
            "fee_sats": 1500,
            "dry_run": True,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "ord_send_inscriptions", mock_send)

    response = asyncio.run(server._handle_ord_send_inscriptions({
        "transfers": [{"address": "tb1qtest", "inscriptionId": "abc123i0"}],
    }))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["txid"].startswith("DRYRUN_")
    assert len(payload["transfers"]) == 1


def test_ord_send_inscriptions_split_missing_transfers():
    response = asyncio.run(server.call_tool("ord_send_inscriptions_split", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "transfers" in payload["error"]


def test_ord_send_inscriptions_split(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}),
    )

    def mock_split(cfg, transfers, fee_rate, dry_run):
        return {
            "txid": "DRYRUN_def456",
            "splits": [{"inscriptionId": "abc123i0", "split": True, "sentValue": 546}],
            "fee_sats": 2000,
            "dry_run": True,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "ord_send_inscriptions_split", mock_split)

    response = asyncio.run(server._handle_ord_send_inscriptions_split({
        "transfers": [{"address": "tb1qtest", "inscriptionId": "abc123i0"}],
    }))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["splits"][0]["split"] is True


# ---------------------------------------------------------------------------
# Extract & Recover tests
# ---------------------------------------------------------------------------


def test_ord_extract_from_utxo_missing_outpoint():
    response = asyncio.run(server.call_tool("ord_extract_from_utxo", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "outpoint" in payload["error"]


def test_ord_extract_from_utxo(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}),
    )

    def mock_extract(cfg, outpoint, fee_rate, dry_run):
        return {
            "txid": "DRYRUN_extract",
            "extracted_count": 2,
            "outpoint": outpoint,
            "dry_run": True,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "ord_extract_from_utxo", mock_extract)

    response = asyncio.run(server._handle_ord_extract_from_utxo({
        "outpoint": "abc123:0",
    }))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["extracted_count"] == 2


def test_ord_recover_bitcoin(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}),
    )

    def mock_recover_btc(cfg, outpoint, fee_rate, dry_run):
        return {
            "txid": "DRYRUN_recover_btc",
            "recovered_sats": 50000,
            "recovered_btc": "0.00050000",
            "fee_sats": 1000,
            "utxo_count": 3,
            "dry_run": True,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "ord_recover_bitcoin", mock_recover_btc)

    response = asyncio.run(server._handle_ord_recover_bitcoin({}))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["recovered_sats"] == 50000


def test_ord_recover_ordinals(monkeypatch):
    monkeypatch.setattr(
        server, "BTCConfig",
        type("BTCConfig", (), {"from_env": classmethod(_make_dummy_cfg)}),
    )

    def mock_recover_ord(cfg, outpoint, fee_rate, dry_run):
        return {
            "txid": "DRYRUN_recover_ord",
            "recovered_count": 1,
            "dry_run": True,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "ord_recover_ordinals", mock_recover_ord)

    response = asyncio.run(server._handle_ord_recover_ordinals({}))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["recovered_count"] == 1
