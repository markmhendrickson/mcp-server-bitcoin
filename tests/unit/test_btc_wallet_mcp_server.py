import asyncio
import json
import sys
from decimal import Decimal
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_DIR = REPO_ROOT / "mcp" / "btc_wallet"
sys.path.insert(0, str(MODULE_DIR))

import btc_wallet_mcp_server as server  # noqa: E402


def test_list_tools_includes_wallet_tools():
    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}
    assert "btc_wallet_get_balance" in names
    assert "btc_wallet_get_prices" in names
    assert "btc_wallet_preview_transfer" in names
    assert "btc_wallet_send_transfer" in names


def test_get_balance_returns_json(monkeypatch):
    class DummyCfg:
        network = "testnet"

    monkeypatch.setattr(
        server.BTCConfig, "from_env", classmethod(lambda cls: DummyCfg())
    )
    monkeypatch.setattr(server, "get_balance_btc", lambda cfg: Decimal("1.2345"))

    response = asyncio.run(server._handle_get_balance())
    payload = json.loads(response[0].text)

    assert payload["success"] is True
    assert payload["balance_btc"] == "1.2345"
    assert payload["network"] == "testnet"
