# BTC wallet MCP server

This standalone MCP server wraps `btc_wallet.py` and exposes safe wallet
operations as tools.

## Tools

### `btc_wallet_get_balance`

Returns the current wallet balance in BTC.

Example request:

```json
{}
```

Example response:

```json
{
  "success": true,
  "balance_btc": "0.12345678",
  "network": "testnet"
}
```

### `btc_wallet_get_prices`

Returns current BTC prices in USD and EUR.

Example response:

```json
{
  "success": true,
  "usd": "91000.12",
  "eur": "84000.34"
}
```

### `btc_wallet_preview_transfer`

Previews a transfer and returns estimated fees. Provide either `amount_btc` or
`amount_eur`.

Example request:

```json
{
  "to_address": "bc1q...",
  "amount_eur": 50
}
```

Example response:

```json
{
  "success": true,
  "from_address": "bc1q...",
  "to_address": "bc1q...",
  "amount_btc": "0.00059523",
  "fee_sats_estimate": 1140,
  "total_spend_btc": "0.00060663",
  "balance_btc": "0.02345678",
  "network": "mainnet"
}
```

### `btc_wallet_send_transfer`

Sends a transfer. Requires explicit user confirmation. Call
`btc_wallet_preview_transfer` first and confirm before sending.

Example request:

```json
{
  "to_address": "bc1q...",
  "amount_btc": 0.0006,
  "max_fee_sats": 2000,
  "memo": "Example payment",
  "dry_run": true
}
```

Example response:

```json
{
  "success": true,
  "txid": "DRYRUN_...",
  "dry_run": true,
  "network": "testnet"
}
```

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Create a `.env` file in this directory (or parent directory) with your wallet configuration.

## Configuration

The server reads configuration from environment variables or a `.env` file. Provide
key material in one of these forms:

- `BTC_PRIVATE_KEY` for a WIF private key
- `BTC_MNEMONIC` for a BIP-39 seed phrase
- `BTC_MNEMONIC_PASSPHRASE` optional passphrase

Additional settings:

- `BTC_NETWORK` set to `mainnet` or `testnet` (default: testnet)
- `BTC_DRY_RUN` set to `true` or `false` (default: true)
- `BTC_MAX_SEND_BTC` optional per transfer limit
- `BTC_MAX_FEE_SATS` optional max fee cap
- `BTC_FEE_RATE_SAT_PER_BYTE` optional fixed fee rate
- `BTC_FEE_TIER` choose fee tier from mempool space (hourFee, halfHourFee, fastestFee)

## Security

- No secrets are returned in tool responses.
- Use preview and user confirmation before sending.
- Use `dry_run` for safety in automated workflows.

## Cursor MCP config example

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "btc-wallet": {
      "command": "mcp/btc_wallet/run_btc_wallet_mcp.sh"
    }
  }
}
```
