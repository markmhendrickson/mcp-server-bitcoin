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

---

## Phase 2: Stacks (STX) Tools

All STX tools derive keys from the same `BTC_MNEMONIC` using the Stacks
derivation path (`m/44'/5757'/0'/0/0`). The Hiro Stacks API is used for
on-chain queries and broadcasting.

### Stacks Address & Account Management

#### `stx_get_addresses`

Get Stacks addresses with public keys and derivation paths.

```json
{
  "success": true,
  "addresses": [{"symbol": "STX", "address": "SP...", "publicKey": "02...", "derivationPath": "m/44'/5757'/0'/0/0"}],
  "network": "mainnet"
}
```

#### `stx_get_accounts`

Get Stacks accounts with STX balances, locked amounts, and nonces.

#### `stx_get_balance`

Get STX balance and all fungible/non-fungible token balances for an address.

```json
{
  "success": true,
  "address": "SP...",
  "balance_ustx": 5000000,
  "balance_stx": "5.000000",
  "fungible_tokens": [{"token_id": "SP...::token", "balance": "1000"}],
  "non_fungible_tokens": [{"token_id": "SP...::nft", "count": 3}]
}
```

#### `stx_get_networks`

List available Stacks networks (mainnet, testnet) with chain IDs and API URLs.

### STX Transfers

#### `stx_transfer_stx`

Transfer STX to a recipient. Amount in micro-STX (1 STX = 1,000,000 uSTX).

```json
{"recipient": "SP...", "amount_ustx": 1000000, "memo": "payment", "dry_run": true}
```

#### `stx_preview_transfer`

Preview an STX transfer with fee estimation and balance check.

#### `stx_transfer_sip10_ft`

Transfer a SIP-10 fungible token via contract call.

```json
{"recipient": "SP...", "asset": "SP....contract-name::token-name", "amount": 100, "dry_run": true}
```

#### `stx_transfer_sip9_nft`

Transfer a SIP-9 non-fungible token via contract call.

```json
{"recipient": "SP...", "asset": "SP....contract-name::nft-name", "asset_id": "1", "dry_run": true}
```

### Smart Contract Interaction

#### `stx_call_contract`

Call a public Clarity smart contract function. Arguments use Clarity notation.

```json
{
  "contract_address": "SP...",
  "contract_name": "my-contract",
  "function_name": "transfer",
  "function_args": ["u100", "'SP...", "true"],
  "dry_run": true
}
```

Supported argument types:
- `u100` -- uint
- `i-5` -- int
- `true` / `false` -- bool
- `none` -- optional none
- `'SPaddr...` -- standard principal
- `0xDEADBEEF` -- buffer
- `"hello"` -- string-ascii

#### `stx_deploy_contract`

Deploy a Clarity smart contract.

```json
{"contract_name": "my-counter", "clarity_code": "(define-data-var counter uint u0)...", "dry_run": true}
```

#### `stx_read_contract`

Read-only call to a Clarity contract function (no transaction needed).

```json
{"contract_address": "SP...", "contract_name": "my-contract", "function_name": "get-balance", "function_args": ["'SP..."]}
```

### Stacks Transaction Signing

#### `stx_sign_transaction`

Sign a serialized Stacks transaction (SIP-30 compatible). Takes hex-encoded
unsigned transaction, returns signed hex.

#### `stx_sign_transactions`

Sign multiple Stacks transactions in batch.

### Stacks Message Signing

#### `stx_sign_message`

Sign a UTF-8 message on Stacks. Returns recoverable ECDSA signature.

```json
{"message": "Hello Stacks!"}
```

#### `stx_sign_structured_message`

Sign SIP-018 structured data with domain and message.

```json
{"domain": "my-app", "message": "{\"action\":\"login\"}"}
```

### Stacks Utilities

#### `stx_get_nonce`

Get the current nonce for a Stacks address.

#### `stx_estimate_fee`

Estimate Stacks transaction fee in micro-STX.

#### `stx_update_profile`

Update an on-chain profile (schema.org/Person). Requires a registered BNS name.

---

---

## Phase 3: Ordinals & Inscriptions Tools

Ordinals tools use the Hiro Ordinals API for inscription discovery and the
wallet's taproot (P2TR) address for ordinals storage. Inscription transfers
use the P2WPKH payment address for fee funding.

### Inscription Queries

#### `ord_get_inscriptions`

List inscriptions owned by the wallet with pagination.

```json
{"offset": 0, "limit": 20}
```

Returns inscription IDs, content types, sat rarity, locations, and values.

#### `ord_get_inscription_details`

Get detailed info for a specific inscription including genesis data, content
type, sat ordinal, rarity, and current UTXO location.

```json
{"inscription_id": "abc123...i0"}
```

### Sending Inscriptions

#### `ord_send_inscriptions`

Send inscriptions to recipients. Transfers the full UTXO containing each
inscription, using a separate payment UTXO for fees.

```json
{
  "transfers": [
    {"address": "bc1p...", "inscriptionId": "abc123...i0"}
  ],
  "dry_run": true
}
```

#### `ord_send_inscriptions_split`

Send inscriptions with UTXO splitting. When an inscription sits in a large
UTXO at a specific offset, splits it so only the inscription's sat range
goes to the recipient and the remainder returns to the sender.

```json
{
  "transfers": [
    {"address": "bc1p...", "inscriptionId": "abc123...i0"}
  ],
  "dry_run": true
}
```

### Extract & Recover

#### `ord_extract_from_utxo`

Extract ordinals from a mixed UTXO into individual outputs.

```json
{"outpoint": "txid:vout", "dry_run": true}
```

#### `ord_recover_bitcoin`

Recover BTC trapped in the ordinals (taproot) address. Finds UTXOs without
inscriptions and sweeps them to the payment address.

```json
{"dry_run": true}
```

#### `ord_recover_ordinals`

Recover ordinals that ended up on the payment address. Moves
inscription-bearing UTXOs to the ordinals (taproot) address.

```json
{"dry_run": true}
```

---

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

See [LEATHER_XVERSE_MCP_PLAN.md](LEATHER_XVERSE_MCP_PLAN.md) for the remaining phases
covering Swaps/DeFi, sBTC Bridge, Stacking, and advanced ecosystem features.
