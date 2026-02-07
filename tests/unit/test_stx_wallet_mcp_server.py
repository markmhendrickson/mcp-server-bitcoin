"""Unit tests for Phase 2: Stacks (STX) MCP tools."""

import asyncio
import json
import sys
from decimal import Decimal
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import btc_wallet_mcp_server as server  # noqa: E402
import stx_wallet  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class DummySTXCfg:
    private_key = bytes.fromhex("0" * 64)  # dummy 32-byte key
    public_key = bytes.fromhex("02" + "ab" * 32)  # dummy compressed pubkey
    stx_address = "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG"
    network = "testnet"
    hiro_api_url = "https://api.testnet.hiro.so"
    dry_run_default = True
    derivation_path = "m/44'/5757'/0'/0/0"


def _make_dummy_stx_cfg(*_args, **_kwargs):
    return DummySTXCfg()


def _parse(response):
    return json.loads(response[0].text)


# ---------------------------------------------------------------------------
# c32check encoding tests
# ---------------------------------------------------------------------------


def test_c32_encode_decode_roundtrip():
    """Test c32 encode/decode roundtrip."""
    original = bytes(range(20))
    encoded = stx_wallet._c32_encode(original + stx_wallet._c32_checksum(22, original))
    decoded = stx_wallet._c32_decode(encoded)
    assert decoded[:20] == original


def test_c32_address_starts_with_s():
    """c32 addresses must start with 'S'."""
    hash160 = bytes(20)
    addr = stx_wallet.c32_address(22, hash160)
    assert addr.startswith("S")
    assert len(addr) > 5


def test_decode_c32_address_roundtrip():
    """Encode then decode an address."""
    hash160 = b"\x01\x02\x03" + b"\x00" * 17
    version = 26  # testnet
    addr = stx_wallet.c32_address(version, hash160)
    decoded_version, decoded_hash = stx_wallet._decode_c32_address(addr)
    assert decoded_version == version
    assert decoded_hash == hash160


# ---------------------------------------------------------------------------
# Key derivation tests
# ---------------------------------------------------------------------------


def test_derive_stx_key_returns_correct_lengths():
    """Key derivation should return 32-byte privkey and 33-byte pubkey."""
    seed = bytes(64)  # dummy seed
    priv, pub = stx_wallet._derive_stx_key_from_seed(seed, 0)
    assert len(priv) == 32
    assert len(pub) == 33
    assert pub[0] in (0x02, 0x03)  # compressed pubkey prefix


# ---------------------------------------------------------------------------
# Clarity value serialization tests
# ---------------------------------------------------------------------------


def test_serialize_uint():
    data = stx_wallet._serialize_clarity_value("u42")
    assert data[0] == 0x01  # uint type


def test_serialize_bool_true():
    data = stx_wallet._serialize_clarity_value("true")
    assert data == b"\x03"


def test_serialize_bool_false():
    data = stx_wallet._serialize_clarity_value("false")
    assert data == b"\x04"


def test_serialize_none():
    data = stx_wallet._serialize_clarity_value("none")
    assert data == b"\x09"


def test_serialize_principal():
    addr = DummySTXCfg.stx_address
    data = stx_wallet._serialize_clarity_value(f"'{addr}")
    assert data[0] == 0x05  # standard principal type


def test_serialize_buffer():
    data = stx_wallet._serialize_clarity_value("0xDEADBEEF")
    assert data[0] == 0x02  # buffer type
    assert b"\xde\xad\xbe\xef" in data


def test_serialize_string_ascii():
    data = stx_wallet._serialize_clarity_value('"hello"')
    assert data[0] == 0x0D  # string-ascii type
    assert b"hello" in data


# ---------------------------------------------------------------------------
# 2.1 Tests: Stacks Address & Account Management
# ---------------------------------------------------------------------------


def test_stx_tools_in_tool_list():
    """All Phase 2 tools should appear in the tool list."""
    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}

    stx_expected = {
        "stx_get_addresses", "stx_get_accounts", "stx_get_balance", "stx_get_networks",
        "stx_transfer_stx", "stx_preview_transfer", "stx_transfer_sip10_ft",
        "stx_transfer_sip9_nft", "stx_call_contract", "stx_deploy_contract",
        "stx_read_contract", "stx_sign_transaction", "stx_sign_transactions",
        "stx_sign_message", "stx_sign_structured_message", "stx_get_nonce",
        "stx_estimate_fee", "stx_update_profile",
    }
    assert stx_expected.issubset(names), f"Missing: {stx_expected - names}"


def test_stx_get_addresses(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    response = asyncio.run(server._handle_stx_get_addresses())
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["network"] == "testnet"
    assert len(payload["addresses"]) == 1
    assert payload["addresses"][0]["symbol"] == "STX"
    assert payload["addresses"][0]["address"] == DummySTXCfg.stx_address


def test_stx_get_accounts(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_get_accounts(cfg):
        return [{
            "address": cfg.stx_address,
            "balance_ustx": 5000000,
            "balance_stx": "5.000000",
            "locked_ustx": 0,
            "locked_stx": "0",
            "nonce": 3,
            "derivationPath": cfg.derivation_path,
            "publicKey": cfg.public_key.hex(),
        }]

    monkeypatch.setattr(server, "stx_get_accounts", mock_get_accounts)

    response = asyncio.run(server._handle_stx_get_accounts())
    payload = _parse(response)

    assert payload["success"] is True
    assert len(payload["accounts"]) == 1
    assert payload["accounts"][0]["balance_ustx"] == 5000000


def test_stx_get_networks(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    response = asyncio.run(server._handle_stx_get_networks())
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["active"] == "testnet"
    assert len(payload["networks"]) == 2


# ---------------------------------------------------------------------------
# 2.2 Tests: STX Transfers
# ---------------------------------------------------------------------------


def test_stx_transfer_stx_missing_recipient():
    response = asyncio.run(server.call_tool("stx_transfer_stx", {"amount_ustx": 1000}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "recipient" in payload["error"]


def test_stx_transfer_stx_missing_amount():
    response = asyncio.run(server.call_tool("stx_transfer_stx", {"recipient": "STxxx"}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "amount_ustx" in payload["error"]


def test_stx_preview_transfer(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_preview(cfg, recipient, amount_ustx, memo):
        return {
            "from_address": cfg.stx_address,
            "recipient": recipient,
            "amount_ustx": amount_ustx,
            "amount_stx": str(Decimal(amount_ustx) / Decimal("1000000")),
            "fee_ustx": 200,
            "fee_stx": "0.000200",
            "total_ustx": amount_ustx + 200,
            "total_stx": str(Decimal(amount_ustx + 200) / Decimal("1000000")),
            "balance_ustx": 10000000,
            "balance_stx": "10.000000",
            "nonce": 5,
            "sufficient_balance": True,
            "memo": memo,
            "network": "testnet",
        }

    monkeypatch.setattr(server, "stx_preview_transfer", mock_preview)

    response = asyncio.run(server._handle_stx_preview_transfer({
        "recipient": "STxxx",
        "amount_ustx": 1000000,
    }))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["amount_ustx"] == 1000000
    assert payload["sufficient_balance"] is True


def test_stx_transfer_sip10_missing_asset():
    response = asyncio.run(server.call_tool("stx_transfer_sip10_ft", {
        "recipient": "STxxx", "amount": 100,
    }))
    payload = _parse(response)
    assert payload["success"] is False
    assert "asset" in payload["error"]


def test_stx_transfer_sip9_missing_asset_id():
    response = asyncio.run(server.call_tool("stx_transfer_sip9_nft", {
        "recipient": "STxxx", "asset": "SPxxx.contract::nft",
    }))
    payload = _parse(response)
    assert payload["success"] is False
    assert "asset_id" in payload["error"]


# ---------------------------------------------------------------------------
# 2.3 Tests: Smart Contract Interaction
# ---------------------------------------------------------------------------


def test_stx_call_contract_missing_address():
    response = asyncio.run(server.call_tool("stx_call_contract", {
        "contract_name": "test", "function_name": "fn",
    }))
    payload = _parse(response)
    assert payload["success"] is False
    assert "contract_address" in payload["error"]


def test_stx_deploy_contract_missing_code():
    response = asyncio.run(server.call_tool("stx_deploy_contract", {
        "contract_name": "test",
    }))
    payload = _parse(response)
    assert payload["success"] is False
    assert "clarity_code" in payload["error"]


def test_stx_read_contract_missing_function():
    response = asyncio.run(server.call_tool("stx_read_contract", {
        "contract_address": "SPxxx", "contract_name": "test",
    }))
    payload = _parse(response)
    assert payload["success"] is False
    assert "function_name" in payload["error"]


# ---------------------------------------------------------------------------
# 2.4-2.5 Tests: Transaction & Message Signing
# ---------------------------------------------------------------------------


def test_stx_sign_transaction_missing_hex():
    response = asyncio.run(server.call_tool("stx_sign_transaction", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "tx_hex" in payload["error"]


def test_stx_sign_transactions_missing_array():
    response = asyncio.run(server.call_tool("stx_sign_transactions", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "tx_hexes" in payload["error"]


def test_stx_sign_message_missing():
    response = asyncio.run(server.call_tool("stx_sign_message", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "message" in payload["error"]


def test_stx_sign_message(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    def mock_sign(cfg, message):
        return {
            "signature": "00" * 65,
            "publicKey": cfg.public_key.hex(),
            "message": message,
        }

    monkeypatch.setattr(server, "stx_sign_message", mock_sign)

    response = asyncio.run(server._handle_stx_sign_message({"message": "Hello Stacks"}))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["message"] == "Hello Stacks"
    assert "signature" in payload


def test_stx_sign_structured_message_missing_domain():
    response = asyncio.run(server.call_tool("stx_sign_structured_message", {"message": "hi"}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "domain" in payload["error"]


# ---------------------------------------------------------------------------
# 2.6 Tests: Stacks Utilities
# ---------------------------------------------------------------------------


def test_stx_get_nonce(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )
    monkeypatch.setattr(server, "stx_get_nonce", lambda cfg, addr: 42)

    response = asyncio.run(server._handle_stx_get_nonce({}))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["nonce"] == 42


def test_stx_estimate_fee(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )
    monkeypatch.setattr(server, "stx_estimate_fee", lambda cfg: 500)

    response = asyncio.run(server._handle_stx_estimate_fee())
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["fee_ustx"] == 500


def test_stx_update_profile_missing_person():
    response = asyncio.run(server.call_tool("stx_update_profile", {}))
    payload = _parse(response)
    assert payload["success"] is False
    assert "person" in payload["error"]


def test_stx_update_profile(monkeypatch):
    monkeypatch.setattr(
        server, "STXConfig",
        type("STXConfig", (), {"from_env": classmethod(_make_dummy_stx_cfg)}),
    )

    response = asyncio.run(server._handle_stx_update_profile({
        "person": {"name": "Satoshi"},
    }))
    payload = _parse(response)

    assert payload["success"] is True
    assert payload["person"]["name"] == "Satoshi"


# ---------------------------------------------------------------------------
# Total tool count
# ---------------------------------------------------------------------------


def test_total_tool_count():
    """Phase 1 + Phase 2 = 37 tools."""
    tools = asyncio.run(server.list_tools())
    assert len(tools) == 37
