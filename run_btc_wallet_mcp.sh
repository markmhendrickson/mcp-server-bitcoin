#!/bin/bash
# Wrapper script for BTC Wallet MCP server
# Loads environment variables from .env file

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load .env file if it exists
if [ -f "$REPO_ROOT/.env" ]; then
    set -a
    source "$REPO_ROOT/.env"
    set +a
fi

# Use venv Python if available, otherwise system Python
if [ -f "$REPO_ROOT/execution/venv/bin/python3" ]; then
    exec "$REPO_ROOT/execution/venv/bin/python3" "$SCRIPT_DIR/btc_wallet_mcp_server.py"
else
    exec python3 "$SCRIPT_DIR/btc_wallet_mcp_server.py"
fi
