# BTC wallet MCP server

This standalone MCP server wraps `btc_wallet.py` and exposes safe wallet
operations as tools. **Phase 1** provides 19 tools covering addresses, accounts,
transfers (including multi-recipient and sweep), PSBT operations, message
signing, fee management, and UTXO management.

## Tools

### Address & Account Management

#### `btc_get_addresses`

Return all derived wallet addresses (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR)
with public keys and derivation paths.

Example response:

```json
{
  "success": true,
  "addresses": [
    {
      "symbol": "BTC",
      "type": "p2wpkh",
      "address": "bc1q...",
      "publicKey": "02abc...",
      "derivationPath": "m/84'/0'/0'/0/0",
      "label": "bip84_p2wpkh_0"
    }
  ],
  "network": "mainnet"
}
```

#### `btc_get_accounts`

List accounts with balances across all address types. Queries mempool.space
for live UTXO data.

Example response:

```json
{
  "success": true,
  "accounts": [
    {
      "type": "p2wpkh",
      "address": "bc1q...",
      "balance_sats": 123456,
      "balance_btc": "0.00123456",
      "utxo_count": 3,
      "label": "bip84_p2wpkh_0"
    }
  ],
  "total_balance_sats": 123456,
  "total_balance_btc": "0.00123456",
  "network": "mainnet"
}
```

#### `btc_get_info`

Return wallet version, network, supported tools, and configuration.

Example response:

```json
{
  "success": true,
  "version": "0.2.0",
  "network": "testnet",
  "dry_run_default": true,
  "fee_tier": "hourFee",
  "supported_tools": ["btc_get_addresses", "btc_send_transfer", "..."]
}
```

### Balance & Prices

#### `btc_wallet_get_balance`

Returns the current wallet balance in BTC.

```json
{
  "success": true,
  "balance_btc": "0.12345678",
  "network": "testnet"
}
```

#### `btc_wallet_get_prices`

Returns current BTC prices in USD and EUR.

```json
{
  "success": true,
  "usd": "91000.12",
  "eur": "84000.34"
}
```

### Transfers

#### `btc_wallet_preview_transfer`

Previews a transfer and returns estimated fees. Provide either `amount_btc` or
`amount_eur`.

Example request:

```json
{
  "to_address": "bc1q...",
  "amount_eur": 50
}
```

#### `btc_wallet_send_transfer`

Sends a BTC transfer (single recipient). Requires explicit user confirmation.
Call `btc_wallet_preview_transfer` first.

#### `btc_send_transfer`

Send BTC to one or more recipients with sat-denominated amounts. Supports
multi-output transactions (matching Leather/Xverse `sendTransfer`).

Example request:

```json
{
  "recipients": [
    {"address": "bc1q...", "amount_sats": 50000},
    {"address": "bc1q...", "amount_sats": 30000}
  ],
  "dry_run": true
}
```

Example response:

```json
{
  "success": true,
  "txid": "DRYRUN_abc...",
  "num_recipients": 2,
  "dry_run": true,
  "network": "testnet"
}
```

#### `btc_send_max`

Send maximum possible BTC (sweep) to a single address. Automatically calculates
the amount after fees.

Example request:

```json
{
  "to_address": "bc1q...",
  "dry_run": true
}
```

#### `btc_combine_utxos`

Consolidate all UTXOs into a single output. Reduces future transaction fees by
combining many small UTXOs.

```json
{
  "to_address": "bc1q...",
  "dry_run": true
}
```

### PSBT Support

#### `btc_sign_psbt`

Sign a PSBT (Partially Signed Bitcoin Transaction). Accepts hex or base64
encoded PSBT. Optionally broadcast after signing.

```json
{
  "psbt": "70736274ff...",
  "sign_at_index": [0, 1],
  "broadcast": false,
  "dry_run": true
}
```

#### `btc_sign_batch_psbt`

Sign multiple PSBTs in a single call.

```json
{
  "psbts": ["70736274ff...", "70736274ff..."],
  "broadcast": false
}
```

#### `btc_decode_psbt`

Decode a PSBT and return a human-readable summary including inputs, outputs,
total value, and finalization status.

```json
{
  "psbt": "70736274ff..."
}
```

Example response:

```json
{
  "success": true,
  "num_inputs": 2,
  "num_outputs": 3,
  "total_input_sats": 150000,
  "has_witness_utxo": true,
  "is_finalized": false,
  "size_bytes": 512
}
```

### Message Signing

#### `btc_sign_message`

Sign a message using the wallet's private key. Supports ECDSA (legacy Bitcoin
Signed Message) and BIP-322.

```json
{
  "message": "Hello, world!",
  "protocol": "ecdsa",
  "address_type": "p2wpkh"
}
```

Example response:

```json
{
  "success": true,
  "signature": "H...",
  "address": "bc1q...",
  "message": "Hello, world!",
  "protocol": "ecdsa"
}
```

#### `btc_verify_message`

Verify a signed Bitcoin message.

```json
{
  "message": "Hello, world!",
  "signature": "H...",
  "address": "bc1q..."
}
```

### Fee Management

#### `btc_get_fees`

Get recommended fee rates from mempool.space for all tiers.

```json
{
  "success": true,
  "fastest_sat_per_vb": 25,
  "half_hour_sat_per_vb": 18,
  "hour_sat_per_vb": 12,
  "economy_sat_per_vb": 5,
  "minimum_sat_per_vb": 1,
  "network": "mainnet",
  "source": "mempool.space"
}
```

#### `btc_estimate_fee`

Estimate transaction fee for given parameters.

```json
{
  "num_inputs": 3,
  "num_outputs": 2,
  "address_type": "p2wpkh",
  "fee_tier": "halfHourFee"
}
```

Example response:

```json
{
  "success": true,
  "estimated_vsize": 283,
  "fee_rate_sat_per_vb": 15,
  "fee_sats": 4245,
  "fee_btc": "0.00004245",
  "network": "mainnet"
}
```

### UTXO Management

#### `btc_list_utxos`

List UTXOs across all wallet address types. Supports filtering by address type,
minimum value, and confirmation status.

```json
{
  "address_type": "p2wpkh",
  "min_value_sats": 1000,
  "confirmed_only": true
}
```

Example response:

```json
{
  "success": true,
  "utxos": [
    {
      "txid": "abc...",
      "vout": 0,
      "value_sats": 50000,
      "value_btc": "0.00050000",
      "confirmed": true,
      "address": "bc1q...",
      "address_type": "p2wpkh"
    }
  ],
  "count": 1,
  "total_sats": 50000,
  "total_btc": "0.00050000"
}
```

#### `btc_get_utxo_details`

Get detailed information about a specific UTXO including scriptPubKey,
confirmation status, and transaction metadata.

```json
{
  "txid": "abc...",
  "vout": 0
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

## Roadmap

See [LEATHER_XVERSE_MCP_PLAN.md](LEATHER_XVERSE_MCP_PLAN.md) for the full 6-phase
roadmap covering Stacks, Ordinals, Runes, Swaps, Spark/Lightning, and more.
