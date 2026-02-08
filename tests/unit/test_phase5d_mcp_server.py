"""Unit tests for Phase 5D: Inscription Creation & Fiat Onramp."""

import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import bitcoin_wallet_mcp_server as server  # noqa: E402
import inscribe_onramp_wallet as iow  # noqa: E402


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
    candidate_wifs = [
        {"label": "p2wpkh", "addr_type": "p2wpkh", "wif": "ctest",
         "address": "tb1qtest", "public_key": "02ab", "derivation_path": "m/84'/1'/0'/0/0"},
        {"label": "p2tr", "addr_type": "p2tr", "wif": "ctest",
         "address": "tb1ptest", "public_key": "02cd", "derivation_path": "m/86'/1'/0'/0/0"},
    ]


def _mk_btc(*a, **k):
    return DummyBTCCfg()


# ---------------------------------------------------------------------------
# Tool presence
# ---------------------------------------------------------------------------


def test_5d_tools_present():
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert "ord_create_inscription" in names
    assert "ord_create_repeat_inscriptions" in names
    assert "buy_get_providers" in names
    assert "buy_get_quote" in names


def test_total_tool_count():
    tools = asyncio.run(server.list_tools())
    assert len(tools) == 77


# ---------------------------------------------------------------------------
# Inscription envelope
# ---------------------------------------------------------------------------


def test_build_envelope_text():
    envelope = iow._build_inscription_envelope("text/plain", b"Hello, World!")
    # Should start with OP_FALSE OP_IF
    assert envelope[:2] == b"\x00\x63"
    # Should end with OP_ENDIF
    assert envelope[-1:] == b"\x68"
    # Should contain "ord"
    assert b"ord" in envelope
    # Should contain the content
    assert b"Hello, World!" in envelope


def test_build_envelope_large_content():
    """Content > 520 bytes should be chunked."""
    big = b"X" * 1000
    envelope = iow._build_inscription_envelope("application/octet-stream", big)
    assert b"X" * 520 in envelope
    assert len(envelope) > 1000


def test_estimate_fees():
    est = iow._estimate_inscription_fees(100, 10, 1)
    assert est["commit_fee"] > 0
    assert est["reveal_fee"] > 0
    assert est["total_cost"] > 0
    assert est["fee_rate"] == 10


def test_estimate_fees_batch():
    single = iow._estimate_inscription_fees(100, 10, 1)
    batch = iow._estimate_inscription_fees(100, 10, 5)
    assert batch["total_cost"] > single["total_cost"]


# ---------------------------------------------------------------------------
# ord_create_inscription
# ---------------------------------------------------------------------------


def test_create_inscription_missing_type():
    r = asyncio.run(server.call_tool("ord_create_inscription", {"content": "hi"}))
    p = _parse(r)
    assert p["success"] is False
    assert "content_type" in p["error"]


def test_create_inscription_missing_content():
    r = asyncio.run(server.call_tool("ord_create_inscription", {"content_type": "text/plain"}))
    p = _parse(r)
    assert p["success"] is False
    assert "content" in p["error"]


def test_create_inscription(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("C", (), {"from_env": classmethod(_mk_btc)}))

    def mock(cfg, ct, content, enc, recip, fr, dr):
        return {
            "content_type": ct,
            "content_size": len(content),
            "content_hash": "abc123",
            "recipient": "tb1ptest",
            "envelope_hex": "00636f7264...",
            "fee_estimate": {"total_cost": 5000},
            "total_cost_sats": 5000,
            "dry_run": True,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "ord_create_inscription", mock)

    r = asyncio.run(server._handle_ord_create_inscription({
        "content_type": "text/plain",
        "content": "Hello Ordinals!",
    }))
    p = _parse(r)
    assert p["success"] is True
    assert p["content_type"] == "text/plain"
    assert p["total_cost_sats"] == 5000


# ---------------------------------------------------------------------------
# ord_create_repeat_inscriptions
# ---------------------------------------------------------------------------


def test_repeat_inscriptions_missing_contents():
    r = asyncio.run(server.call_tool("ord_create_repeat_inscriptions", {"content_type": "text/plain"}))
    p = _parse(r)
    assert p["success"] is False
    assert "contents" in p["error"]


def test_repeat_inscriptions(monkeypatch):
    monkeypatch.setattr(server, "BTCConfig", type("C", (), {"from_env": classmethod(_mk_btc)}))

    def mock(cfg, ct, contents, enc, recip, fr, dr):
        return {
            "content_type": ct,
            "count": len(contents),
            "inscriptions": [{"index": i} for i in range(len(contents))],
            "total_cost_sats": 15000,
            "dry_run": True,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "ord_create_repeat_inscriptions", mock)

    r = asyncio.run(server._handle_ord_create_repeat_inscriptions({
        "content_type": "text/plain",
        "contents": ["one", "two", "three"],
    }))
    p = _parse(r)
    assert p["success"] is True
    assert p["count"] == 3


# ---------------------------------------------------------------------------
# buy_get_providers
# ---------------------------------------------------------------------------


def test_buy_get_providers():
    r = asyncio.run(server._handle_buy_get_providers({}))
    p = _parse(r)
    assert p["success"] is True
    assert p["count"] >= 1
    assert any(prov["name"] == "MoonPay" for prov in p["providers"])


def test_buy_get_providers_filter():
    r = asyncio.run(server._handle_buy_get_providers({"crypto": "BTC", "fiat": "USD"}))
    p = _parse(r)
    assert p["success"] is True
    for prov in p["providers"]:
        assert "BTC" in prov["supported_crypto"]
        assert "USD" in prov["supported_fiat"]


# ---------------------------------------------------------------------------
# buy_get_quote
# ---------------------------------------------------------------------------


def test_buy_get_quote(monkeypatch):
    def mock(crypto, fiat, amount):
        return {
            "crypto": crypto,
            "fiat": fiat,
            "fiat_amount": amount,
            "crypto_price": 68000,
            "estimated_crypto_amount": 0.00141912,
            "estimated_fee_fiat": 3.5,
            "estimated_fee_pct": 0.035,
        }

    monkeypatch.setattr(server, "buy_get_quote", mock)

    r = asyncio.run(server._handle_buy_get_quote({"fiat_amount": 100}))
    p = _parse(r)
    assert p["success"] is True
    assert p["crypto_price"] == 68000
    assert p["estimated_crypto_amount"] > 0
