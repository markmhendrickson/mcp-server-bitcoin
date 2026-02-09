# Bitcoin wallet MCP server

> **⚠️ Warning:** Experimental. Not yet safe for meaningful funds. Use only with wallets you are prepared to lose. The code is not battle-tested, audited, or hardened. This doc covers setup, configuration, running, and the full tool reference.

## Intro

This repo is a single [MCP](https://modelcontextprotocol.io) server that exposes Bitcoin (Layer 1) and Stacks (Layer 2) wallet operations as tools. Agents or other MCP clients connect over stdio, pass tool names and arguments as JSON, and get back structured results. The server wraps local Python wallet code and external APIs (mempool.space, Hiro, CoinGecko, etc.). Destructive actions (send, sign-and-broadcast, deploy) support `dry_run` and do not broadcast by default. No keys or mnemonics are ever returned.

**What it exposes:** 93 tools in two groups. 
1. **Layer 1 (Bitcoin):** addresses, balance (confirmed and unconfirmed), UTXOs, fee estimation, single and multi-recipient sends, sweep, PSBT sign/decode, message sign/verify, Ordinals / inscriptions, inscription creation, transaction history and RBF, Ledger (Bitcoin app). 
2. **Layer 2 (Stacks):** STX addresses and balances, nonce, STX and token transfers, Clarity call/deploy/read, signing, swaps (Alex, Bitflow, Velar), sBTC bridge, stacking, BNS, market and portfolio data, Ledger (Stacks app), enhanced transaction queries with filtering, mempool monitoring, block explorer, contract event monitoring, token metadata (SIP-10/SIP-9), and network statistics. One mnemonic or WIF key drives both layers; Stacks keys are derived from the same seed.



---

## Table of contents

- [Intro](#intro)
- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the server](#running-the-server)
- [Architecture](#architecture)
- [Tools reference](#tools-reference)
  - [Layer 1 (Bitcoin)](#layer-1-bitcoin)
    - [Core Bitcoin](#core-bitcoin)
    - [Ordinals & inscriptions](#ordinals--inscriptions)
    - [Inscription creation & onramp](#inscription-creation--onramp)
    - [Transaction & wallet management](#transaction--wallet-management)
    - [Ledger hardware wallet (Bitcoin)](#ledger-hardware-wallet-bitcoin)
  - [Layer 2 (Stacks)](#layer-2-stacks)
    - [Stacks (STX)](#stacks-stx)
    - [Swaps, DeFi & bridge](#swaps-defi--bridge)
    - [BNS & market data](#bns--market-data)
    - [Ledger hardware wallet (Stacks)](#ledger-hardware-wallet-stacks)
    - [Enhanced transaction queries](#enhanced-transaction-queries)
    - [Mempool operations](#mempool-operations)
    - [Block explorer](#block-explorer)
    - [Contract event monitoring](#contract-event-monitoring)
    - [Token metadata](#token-metadata)
    - [Network statistics & health](#network-statistics--health)
- [Security](#security)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Reference](#reference)
- [Related documents](#related-documents)

---

## Overview

- **Purpose:** Layer 1 (Bitcoin) and Layer 2 (Stacks) wallet operations as MCP tools with a single, safe interface.
- **Design:** Destructive operations support `dry_run` (default `true`). Responses: `{ "success": true, ... }` or `{ "success": false, "error": "..." }`. No keys or mnemonics in responses.

---

## Requirements

- **Python**: 3.10 or later (for type hints and runtime).
- **OS**: Any platform supported by Python and the dependencies (Linux, macOS, Windows). Ledger tools require a Ledger device and USB (or Speculos with `interface: "tcp"`).
- **Dependencies**: Listed in `requirements.txt`; install with `pip install -r requirements.txt` (see [Installation](#installation)).

| Package | Purpose |
|--------|---------|
| `mcp` | MCP server and stdio transport |
| `python-dotenv` | Load `.env` configuration |
| `bip-utils` | BIP-39/44/84 derivation |
| `bit` | Bitcoin transaction building (legacy paths) |
| `python-bitcoinlib` | PSBT, keys, addresses, raw tx |
| `requests` | HTTP for mempool.space, Hiro, CoinGecko, etc. |
| `coincurve` | ECDSA and key operations |
| `ledgercomm` | Ledger device communication (optional for Ledger tools) |

---

## Installation

1. **Clone** the repo. If you did not use `--recurse-submodules`, run `git submodule update --init foundation`.

2. **Create a virtual environment** (recommended):
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**: Copy `.env.example` to `.env` and set at least one key source and network (see [Configuration](#configuration)).

5. **Optional**: If you use the repo’s `run_btc_wallet_mcp.sh`, it will prefer `../../execution/venv` when present; otherwise it uses `python3` from `PATH`.

---

## Configuration

Configuration comes from **environment variables**. The runner script loads `.env` from the **repository root** (two levels above this directory). You can also set variables in the shell or in your MCP host.

### Key material (choose one)

| Variable | Description |
|----------|-------------|
| `BTC_PRIVATE_KEY` | WIF private key for the wallet. |
| `BTC_MNEMONIC` | BIP-39 mnemonic (12 or 24 words). |
| `BTC_MNEMONIC_PASSPHRASE` | Optional BIP-39 passphrase when using `BTC_MNEMONIC`. |

Stacks (STX) keys are derived from the same mnemonic using the Stacks path `m/44'/5757'/0'/0/0`.

### Network and safety

| Variable | Description | Default |
|----------|-------------|--------|
| `BTC_NETWORK` | `mainnet` or `testnet`. | `testnet` |
| `BTC_DRY_RUN` | If `true`, send/sign tools do not broadcast by default. | `true` |

### Limits (optional)

| Variable | Description |
|----------|-------------|
| `BTC_MAX_SEND_BTC` | Maximum BTC per transfer (decimal string or number). |
| `BTC_MAX_FEE_SATS` | Maximum fee in satoshis per transaction. |

### Fee behavior

| Variable | Description |
|----------|-------------|
| `BTC_FEE_RATE_SAT_PER_BYTE` | Fixed fee rate (sat/vB). If set, overrides tier. |
| `BTC_FEE_TIER` | mempool.space tier: `hourFee`, `halfHourFee`, `fastestFee`. Used when no fixed rate is set. |

---

## Running the server

- **Wrapper script** (recommended): `run_btc_wallet_mcp.sh` loads `.env` from repo root, uses `execution/venv/bin/python3` if present else `python3`, runs the server over stdio.
- **Direct:** Set env from `.env`, then run `python3 bitcoin_wallet_mcp_server.py` from this directory.

### Cursor MCP config

Add to `.cursor/mcp.json` (or your Cursor MCP config file):

```json
{
  "mcpServers": {
    "bitcoin-wallet": {
      "command": "/absolute/path/to/repo/mcp/btc_wallet/run_btc_wallet_mcp.sh"
    }
  }
}
```

Use an absolute path to your repo. The server lives in `mcp/btc_wallet/`. Put `.env` at repo root if you use the script’s env loading.

---

## Architecture

- **Entrypoint**: `bitcoin_wallet_mcp_server.py`. Single MCP server; registers all tools and delegates to wallet modules.
- **Layer 1 (Bitcoin) modules**: `bitcoin_wallet.py` (addresses, accounts, balance, sends, PSBT, message signing, fees, UTXOs); `ord_wallet.py` (ordinals and inscriptions); `inscribe_onramp_wallet.py` (inscription creation, buy quotes); `advanced_wallet.py` (transaction history, RBF, wallet network, enhanced STX transaction queries, network statistics); `ledger_wallet.py` (Ledger Bitcoin app).
- **Layer 2 (Stacks) modules**: `stx_wallet.py` (addresses, accounts, balance, STX/token transfers, contracts, signing); `defi_wallet.py` (swaps via Alex, Bitflow, Velar; sBTC bridge; stacking with enhanced cycle metrics); `bns_market_wallet.py` (BNS, market, portfolio); `stx_mempool.py` (mempool monitoring and statistics); `stx_explorer.py` (block explorer queries); `stx_events.py` (contract event monitoring); `stx_token_metadata.py` (SIP-10/SIP-9 token metadata); `ledger_wallet.py` (Ledger Stacks app).

**Responses:** JSON with `"success": true` and data, or `"success": false` and `"error"`. Keys and mnemonics are never returned.

---

## Tools reference

**93 tools**, grouped by Layer 1 (Bitcoin) and Layer 2 (Stacks). Parameters and response shape are below; optional args can be omitted. `dry_run` defaults to `BTC_DRY_RUN` (usually `true`).

---

### Layer 1 (Bitcoin)

Tools for the Bitcoin chain: addresses, balance, transfers, PSBT, message signing, fees, UTXOs, ordinals, inscription creation, transaction management, and Ledger (Bitcoin app).

#### Core Bitcoin

Address and account management, balance, prices, transfers, PSBT, message signing, fees, UTXOs.

| Tool | Description |
|------|-------------|
| `btc_get_addresses` | All derived addresses (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR) with public keys and derivation paths. |
| `btc_get_accounts` | Accounts with balances per address type; uses mempool.space for UTXO data. |
| `btc_get_info` | Wallet version, network, supported tools, and configuration (e.g. dry_run_default, fee_tier). |

**Parameters**: None.

**Example response** (`btc_get_addresses`):

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

---

| Tool | Description |
|------|-------------|
| `btc_wallet_get_balance` | Current wallet balance in BTC. |
| `btc_wallet_get_prices` | Current BTC prices in USD and EUR. |

**Parameters**: None.

**Example response** (`btc_wallet_get_balance`): `{ "success": true, "balance_btc": "0.12345678", "network": "testnet" }`  
**Example response** (`btc_wallet_get_prices`): `{ "success": true, "usd": "91000.12", "eur": "84000.34" }`

---

| Tool | Description |
|------|-------------|
| `btc_wallet_preview_transfer` | Preview a transfer and estimated fees. Provide either `amount_btc` or `amount_eur`. |
| `btc_wallet_send_transfer` | Send BTC to a single recipient (BTC or EUR amount). Prefer calling the preview tool first and require explicit user confirmation. |

**Parameters** (preview): `to_address` (required), `amount_btc` or `amount_eur` (one required).  
**Parameters** (send): `to_address` (required), `amount_btc` or `amount_eur` (one required), optional `max_fee_sats`, `memo`, `dry_run`.

---

| Tool | Description |
|------|-------------|
| `btc_send_transfer` | Send BTC to one or more recipients with amounts in sats; multi-output. |
| `btc_send_max` | Sweep: send maximum spendable BTC to one address (amount after fees). |
| `btc_combine_utxos` | Consolidate UTXOs into one output (optionally to a given address). |

**Parameters** (`btc_send_transfer`): `recipients` (array of `{ "address", "amount_sats" }`), optional `max_fee_sats`, `memo`, `dry_run`.  
**Parameters** (`btc_send_max`): `to_address` (required), optional `fee_rate`, `dry_run`.  
**Parameters** (`btc_combine_utxos`): optional `to_address`, `fee_rate`, `dry_run`.

**Example request** (`btc_send_transfer`):

```json
{
  "recipients": [
    { "address": "bc1q...", "amount_sats": 50000 },
    { "address": "bc1q...", "amount_sats": 30000 }
  ],
  "dry_run": true
}
```

**Example response**: `{ "success": true, "txid": "DRYRUN_...", "num_recipients": 2, "dry_run": true, "network": "testnet" }`

---

| Tool | Description |
|------|-------------|
| `btc_sign_psbt` | Sign a PSBT (hex or base64). Optional `sign_at_index`, `broadcast`, `dry_run`. |
| `btc_sign_batch_psbt` | Sign multiple PSBTs in one call. |
| `btc_decode_psbt` | Decode a PSBT and return a human-readable summary (inputs, outputs, total value, finalization). |

**Parameters** (`btc_sign_psbt`): `psbt` (hex or base64), optional `sign_at_index` (array of input indices), `broadcast`, `dry_run`.  
**Parameters** (`btc_sign_batch_psbt`): `psbts` (array of PSBT strings), optional `broadcast`.  
**Parameters** (`btc_decode_psbt`): `psbt`.

**Example response** (`btc_decode_psbt`): `{ "success": true, "num_inputs": 2, "num_outputs": 3, "total_input_sats": 150000, "has_witness_utxo": true, "is_finalized": false, "size_bytes": 512 }`

---

| Tool | Description |
|------|-------------|
| `btc_sign_message` | Sign a message (ECDSA legacy Bitcoin Signed Message or BIP-322). |
| `btc_verify_message` | Verify a signed Bitcoin message. |

**Parameters** (sign): `message`, optional `protocol` (`ecdsa` | BIP-322), `address_type` (e.g. `p2wpkh`).  
**Parameters** (verify): `message`, `signature`, `address`.

**Example response** (sign): `{ "success": true, "signature": "H...", "address": "bc1q...", "message": "Hello, world!", "protocol": "ecdsa" }`

---

| Tool | Description |
|------|-------------|
| `btc_get_fees` | Recommended fee rates from mempool.space (all tiers). |
| `btc_estimate_fee` | Estimate fee for given input/output count and address type. |

**Parameters** (`btc_estimate_fee`): `num_inputs`, `num_outputs`, `address_type` (e.g. `p2wpkh`), optional `fee_tier`.

**Example response** (`btc_get_fees`): `{ "success": true, "fastest_sat_per_vb": 25, "half_hour_sat_per_vb": 18, "hour_sat_per_vb": 12, "economy_sat_per_vb": 5, "minimum_sat_per_vb": 1, "network": "mainnet", "source": "mempool.space" }`

---

| Tool | Description |
|------|-------------|
| `btc_list_utxos` | List UTXOs with optional filters: address type, min value, confirmed only. |
| `btc_get_utxo_details` | Detailed info for one UTXO (scriptPubKey, confirmation, tx metadata). |

**Parameters** (`btc_list_utxos`): optional `address_type`, `min_value_sats`, `confirmed_only`.  
**Parameters** (`btc_get_utxo_details`): `txid`, `vout`.

**Example response** (`btc_list_utxos`): `{ "success": true, "utxos": [{ "txid": "...", "vout": 0, "value_sats": 50000, "value_btc": "0.00050000", "confirmed": true, "address": "bc1q...", "address_type": "p2wpkh" }], "count": 1, "total_sats": 50000, "total_btc": "0.00050000" }`

---

#### Ordinals & inscriptions

Uses Hiro Ordinals API for inscription data; taproot (P2TR) for ordinals storage; P2WPKH for fee funding.

| Tool | Description |
|------|-------------|
| `ord_get_inscriptions` | List inscriptions owned by the wallet; pagination via `offset`, `limit`. |
| `ord_get_inscription_details` | Detailed inscription info (genesis, content type, sat ordinal, rarity, UTXO location). |

**Parameters** (`ord_get_inscriptions`): optional `offset`, `limit`.  
**Parameters** (`ord_get_inscription_details`): `inscription_id`.

---

| Tool | Description |
|------|-------------|
| `ord_send_inscriptions` | Send inscriptions to recipients; full UTXO transfer; separate payment UTXO for fees. |
| `ord_send_inscriptions_split` | Send inscriptions with UTXO splitting (only the inscription's sat range to recipient, rest to sender). |
| `ord_extract_from_utxo` | Extract ordinals from a mixed UTXO into separate outputs. |
| `ord_recover_bitcoin` | Recover BTC from ordinals address (sweep non-inscription UTXOs to payment address). |
| `ord_recover_ordinals` | Move inscription-bearing UTXOs from payment address to ordinals (taproot) address. |

**Parameters** (send tools): `transfers` (array of `{ "address", "inscriptionId" }`), optional `dry_run`.  
**Parameters** (`ord_extract_from_utxo`): `outpoint` (`txid:vout`), optional `dry_run`.  
**Parameters** (recover tools): optional `dry_run`.

---

#### Inscription creation & onramp

| Tool | Description |
|------|-------------|
| `ord_create_inscription` | Create a single inscription; content type and body; estimates commit/reveal fees. |
| `ord_create_repeat_inscriptions` | Create multiple inscriptions in batch with shared fee estimation. |
| `buy_get_providers` | List fiat-to-crypto onramp providers and supported currencies. |
| `buy_get_quote` | Fiat-to-crypto quote (e.g. price and fees). |

**Parameters** (`ord_create_inscription`): `content_type`, `content` (text or hex if `content_encoding`: `hex`), optional `content_encoding`, `dry_run`.  
**Parameters** (`ord_create_repeat_inscriptions`): `content_type`, `contents` (array), optional `dry_run`.  
**Parameters** (`buy_get_providers`): optional `crypto`, `fiat`.  
**Parameters** (`buy_get_quote`): `crypto`, `fiat`, `fiat_amount` (or equivalent).

---

#### Transaction & wallet management

| Tool | Description |
|------|-------------|
| `tx_get_history` | Transaction history for BTC and/or STX. |
| `tx_get_status` | Status of a single transaction (BTC or STX). |
| `tx_speed_up` | Speed up pending BTC tx via RBF. |
| `tx_cancel` | Cancel pending BTC tx (RBF send-to-self). |
| `wallet_get_network` | Current network config, API endpoints, fee settings. |
| `wallet_switch_network` | Switch between mainnet and testnet. |
| `wallet_add_network` | Add custom network (name, BTC API URL, etc.). |
| `wallet_get_supported_methods` | List all MCP tool names and descriptions. |

**Parameters** (`tx_get_history`): optional `chain` (`btc` | `stx` | `both`), `limit`.  
**Parameters** (`tx_get_status`): `txid`, `chain` (`btc` | `stx`).  
**Parameters** (`tx_speed_up`, `tx_cancel`): `txid`, optional `dry_run`.  
**Parameters** (`wallet_switch_network`): `network` (`mainnet` | `testnet`).  
**Parameters** (`wallet_add_network`): `name`, `btc_api_url`, and other endpoint fields as needed.

---

#### Ledger hardware wallet (Bitcoin)

Requires a Ledger device connected via USB with the Bitcoin app open. Use `interface: "tcp"` for Speculos.

| Tool | Description |
|------|-------------|
| `ledger_get_addresses` | Get BTC addresses (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR) from Ledger. |
| `ledger_sign_psbt` | Sign a PSBT with Ledger Bitcoin app. |

**Parameters**: `account` (optional), `display` (optional, show on device), `interface` (`hid` or `tcp` for Speculos).  
**Parameters** (sign PSBT): `psbt`, `interface`.

---

### Layer 2 (Stacks)

Tools for the Stacks chain: STX addresses, balance, transfers, contracts, swaps, sBTC bridge, stacking, BNS, market/portfolio data, and Ledger (Stacks app).

#### Stacks (STX)

Keys are derived from `BTC_MNEMONIC` using path `m/44'/5757'/0'/0/0`. Hiro Stacks API is used for chain data and broadcasting.

| Tool | Description |
|------|-------------|
| `stx_get_addresses` | Stacks addresses with public keys and derivation paths. |
| `stx_get_accounts` | Accounts with STX balance, locked amounts, nonces. |
| `stx_get_balance` | STX balance plus fungible and non-fungible token balances for an address. |
| `stx_get_networks` | Available Stacks networks (mainnet, testnet) with chain IDs and API URLs. |

**Parameters** (`stx_get_balance`): optional `address`.

**Example response** (`stx_get_balance`): `{ "success": true, "address": "SP...", "balance_ustx": 5000000, "balance_stx": "5.000000", "fungible_tokens": [...], "non_fungible_tokens": [...] }`

---

| Tool | Description |
|------|-------------|
| `stx_transfer_stx` | Transfer STX; amount in micro-STX (1 STX = 1_000_000 uSTX). |
| `stx_preview_transfer` | Preview STX transfer with fee and balance check. |
| `stx_transfer_sip10_ft` | Transfer a SIP-10 fungible token via contract call. |
| `stx_transfer_sip9_nft` | Transfer a SIP-9 NFT via contract call. |

**Parameters** (`stx_transfer_stx`): `recipient`, `amount_ustx`, optional `memo`, `dry_run`.  
**Parameters** (`stx_transfer_sip10_ft`): `recipient`, `asset` (e.g. `SP...contract::token`), `amount`, optional `dry_run`.  
**Parameters** (`stx_transfer_sip9_nft`): `recipient`, `asset`, `asset_id`, optional `dry_run`.

---

| Tool | Description |
|------|-------------|
| `stx_call_contract` | Call a public Clarity function; args in Clarity notation. |
| `stx_deploy_contract` | Deploy a Clarity contract. |
| `stx_read_contract` | Read-only contract call (no transaction). |

**Parameters** (`stx_call_contract`): `contract_address`, `contract_name`, `function_name`, `function_args` (array of Clarity literals), optional `dry_run`.  
**Parameters** (`stx_deploy_contract`): `contract_name`, `clarity_code`, optional `dry_run`.  
**Parameters** (`stx_read_contract`): `contract_address`, `contract_name`, `function_name`, optional `function_args`.

Clarity argument examples: `u100`, `i-5`, `true`/`false`, `none`, `'SP...` (principal), `0xDEADBEEF` (buffer), `"hello"` (string-ascii).

---

| Tool | Description |
|------|-------------|
| `stx_sign_transaction` | Sign a serialized Stacks transaction (SIP-30); hex in, signed hex out. |
| `stx_sign_transactions` | Sign multiple Stacks transactions. |
| `stx_sign_message` | Sign a UTF-8 message (recoverable ECDSA). |
| `stx_sign_structured_message` | Sign SIP-018 structured data (domain + message). |
| `stx_get_nonce` | Current nonce for a Stacks address. |
| `stx_estimate_fee` | Estimate Stacks transaction fee in micro-STX. |
| `stx_update_profile` | Update on-chain profile (schema.org/Person); requires BNS name. |

**Parameters** (`stx_sign_message`): `message`.  
**Parameters** (`stx_sign_structured_message`): `domain`, `message` (JSON string).  
**Parameters** (`stx_get_nonce`): optional `address`.

---

#### Swaps, DeFi & bridge

**Swap protocols:** Alex, Bitflow, and Velar. Use `protocol` for quotes and pair listing: **alex** (pools and token prices), **bitflow** (ticker API), **velar** (Alex token prices). **Execution:** `swap_execute` supports `protocol=alex` only (default). For bitflow or velar you get a quote only; to execute, use protocol alex. Execution for Bitflow and Velar could be added via protocol SDKs (e.g. Velar’s @velarprotocol/velar-sdk returns contract-call params; Bitflow requires their SDK or API).

| Tool | Description |
|------|-------------|
| `swap_get_supported_pairs` | List supported swap pairs and protocols (Alex pools, Bitflow ticker). |
| `swap_get_quote` | Get swap quote: estimated output, rate, fees. Protocol: alex (default), bitflow, or velar. |
| `swap_execute` | Execute swap via Alex DEX contract call (protocol=alex). Bitflow/Velar execution could be added via protocol SDKs. |
| `swap_get_history` | Swap transaction history from on-chain activity. |
| `sbtc_get_balance` | sBTC token balance for the wallet. |
| `sbtc_bridge_deposit` | Deposit info for bridging BTC → sBTC. |
| `sbtc_bridge_withdraw` | Withdrawal info for sBTC → BTC. |
| `stx_get_stacking_info` | PoX stacking status, cycle info, thresholds, wallet stacking state. |
| `stx_stack` | Initiate STX solo stacking (lock STX for reward cycles). |
| `stx_revoke_delegation` | Revoke stacking delegation via PoX contract. |

**Parameters** (`swap_get_quote`): `token_in`, `token_out`, `amount`, optional `protocol` (`alex` \| `bitflow` \| `velar`, default `alex`).  
**Parameters** (`swap_execute`): `token_in`, `token_out`, `amount`, optional `min_output`, `protocol` (must be `alex` for execution), `dry_run`.  
**Parameters** (`sbtc_bridge_deposit`): `amount_sats`, optional `dry_run`.  
**Parameters** (`sbtc_bridge_withdraw`): `amount_sats`, `btc_address`, optional `dry_run`.  
**Parameters** (`stx_stack`): `amount_ustx`, `pox_address`, `num_cycles`, optional `dry_run`.

---

#### BNS & market data

| Tool | Description |
|------|-------------|
| `bns_lookup` | Resolve BNS name to Stacks address. |
| `bns_get_names` | BNS names owned by an address. |
| `bns_register` | Register a BNS name (contract call). |
| `market_get_prices` | Multi-asset prices (e.g. CoinGecko). |
| `market_get_history` | Price history for charting. |
| `portfolio_get_summary` | Portfolio summary with USD valuations (BTC + STX). |
| `portfolio_get_assets` | All assets (BTC, STX, fungible tokens) with balances. |
| `portfolio_get_collectibles` | Collectibles: Bitcoin inscriptions and Stacks NFTs. |

**Parameters** (`bns_lookup`): `name` (e.g. `alice.btc`).  
**Parameters** (`bns_get_names`): `address`.  
**Parameters** (`bns_register`): `name`, `namespace` (e.g. `btc`), optional `dry_run`.  
**Parameters** (`market_get_prices`): `coins` (e.g. `["bitcoin", "blockstack"]`).  
**Parameters** (`market_get_history`): `coin`, `days`, optional `interval` (e.g. `daily`).  
**Parameters** (`portfolio_get_collectibles`): optional `limit`.

---

#### Ledger hardware wallet (Stacks)

Requires a Ledger device connected via USB with the Stacks app open. Use `interface: "tcp"` for Speculos.

| Tool | Description |
|------|-------------|
| `ledger_get_stx_addresses` | Get Stacks addresses from Ledger device with public keys and derivation paths. |
| `ledger_sign_stx_transaction` | Sign a Stacks transaction with Ledger Stacks app. |

**Parameters** (`ledger_get_stx_addresses`): optional `account`, `display`, `interface`.  
**Parameters** (`ledger_sign_stx_transaction`): `tx_hex`, optional `derivation_path`, `interface`.

---

#### Enhanced transaction queries

Advanced Stacks transaction queries with filtering, contract-specific queries, and mempool inclusion. Uses Hiro `/extended/v2/addresses/` and `/extended/v1/address/` endpoints.

| Tool | Description |
|------|-------------|
| `stx_query_transactions` | Query Stacks transactions for an address with filtering by type and mempool inclusion. |
| `stx_query_transactions_by_contract` | Query transactions that called a specific contract, optionally filtered by function name. |

**Parameters** (`stx_query_transactions`): optional `address`, `limit`, `offset`, `tx_type` (`token_transfer`, `contract_call`, `smart_contract`, `coinbase`, `poison_microblock`), `unanchored` (include mempool).  
**Parameters** (`stx_query_transactions_by_contract`): `contract_id` (required), optional `function_name`, `limit`, `offset`.

**Example response** (`stx_query_transactions`): `{ "success": true, "address": "SP...", "transactions": [{ "txid": "0x...", "tx_type": "token_transfer", "status": "success", "block_height": 150000 }], "total": 42, "tx_type_filter": null, "unanchored": false }`

---

#### Mempool operations

Monitor pending Stacks transactions, view mempool statistics, and track dropped transactions. Uses Hiro `/extended/v1/tx/mempool/` endpoints.

| Tool | Description |
|------|-------------|
| `stx_mempool_list_pending` | List pending mempool transactions, optionally filtered by address. |
| `stx_mempool_get_stats` | Get mempool statistics: transaction counts by type, fee averages, ages, byte sizes. |
| `stx_mempool_get_dropped` | Get recently dropped mempool transactions (removed without being mined). |

**Parameters** (`stx_mempool_list_pending`): optional `address`, `limit`, `offset`.  
**Parameters** (`stx_mempool_get_dropped`): optional `limit`, `offset`.

**Example response** (`stx_mempool_get_stats`): `{ "success": true, "tx_type_counts": { "token_transfer": 42, "contract_call": 18 }, "tx_simple_fee_averages": { "token_transfer": { "p50": 200 } } }`

---

#### Block explorer

Query Stacks blocks by height, hash, or Bitcoin block association. Uses Hiro `/extended/v2/blocks/` and `/extended/v2/burn-blocks/` endpoints.

| Tool | Description |
|------|-------------|
| `stx_get_recent_blocks` | Get recent Stacks blocks with metadata (height, hash, tx count, burn block info). |
| `stx_get_block_by_height` | Get a specific Stacks block by its height, including transaction IDs. |
| `stx_get_block_by_hash` | Get a specific Stacks block by its hash. |
| `stx_get_stacks_blocks_for_bitcoin_block` | Get all Stacks blocks produced during a specific Bitcoin block. |

**Parameters** (`stx_get_recent_blocks`): optional `limit`, `offset`.  
**Parameters** (`stx_get_block_by_height`): `height` (required).  
**Parameters** (`stx_get_block_by_hash`): `block_hash` (required, with or without `0x` prefix).  
**Parameters** (`stx_get_stacks_blocks_for_bitcoin_block`): `bitcoin_height` (required), optional `limit`, `offset`.

**Example response** (`stx_get_block_by_height`): `{ "success": true, "height": 150000, "hash": "0x...", "burn_block_height": 935748, "tx_count": 12, "transaction_ids": ["0x..."] }`

---

#### Contract event monitoring

Track events emitted by smart contracts and asset transfers for addresses. Uses Hiro `/extended/v1/contract/` and `/extended/v1/address/` endpoints.

| Tool | Description |
|------|-------------|
| `stx_get_contract_events` | Get event history for a contract (print events, FT/NFT events, STX events). |
| `stx_get_address_asset_events` | Get asset events (FT, NFT, STX transfers) for an address. |

**Parameters** (`stx_get_contract_events`): `contract_id` (required), optional `limit`, `offset`.  
**Parameters** (`stx_get_address_asset_events`): optional `address` (default: wallet), `limit`, `offset`.

**Example response** (`stx_get_contract_events`): `{ "success": true, "contract_id": "SP...contract", "events": [{ "event_type": "fungible_token_asset", "tx_id": "0x...", "asset_id": "SP...::token", "amount": "1000" }], "total": 5 }`

---

#### Token metadata

Query SIP-10 fungible and SIP-9 non-fungible token metadata and holder information. Uses Hiro Token Metadata API (`/metadata/v1/`).

| Tool | Description |
|------|-------------|
| `stx_get_token_metadata` | Get metadata for a fungible (SIP-10) or non-fungible (SIP-9) token: name, symbol, decimals, supply. |
| `stx_get_token_holders` | Get holder addresses and balances for a fungible token. |

**Parameters** (`stx_get_token_metadata`): `contract_id` (required), optional `token_type` (`ft` or `nft`, default: `ft`).  
**Parameters** (`stx_get_token_holders`): `contract_id` (required), optional `limit`, `offset`.

**Example response** (`stx_get_token_metadata`): `{ "success": true, "contract_id": "SP...::alex-token", "name": "Alex Token", "symbol": "ALEX", "decimals": 8, "total_supply": "1000000000000" }`

---

#### Network statistics & health

Query Stacks network status, peer info, and chain tip details. Uses Hiro `/v2/info` and `/extended/v1/status` endpoints.

| Tool | Description |
|------|-------------|
| `stx_get_network_info` | Core network info: peer version, burn block height, server version, chain tip. |
| `stx_get_network_status` | Blockchain sync status and chain tip details. |

**Parameters**: None.

**Example response** (`stx_get_network_info`): `{ "success": true, "peer_version": 402653189, "burn_block_height": 935748, "stacks_tip_height": 150000, "server_version": "stacks-node 2.5.0" }`

---

## Security

- **Secrets:** MUST NOT be returned in tool responses (keys, mnemonics, passphrases).
- **Destructive ops:** Send, sign-and-broadcast, and deploy tools support `dry_run`. Keep `BTC_DRY_RUN=true` unless you intend to broadcast. Require explicit confirmation before `dry_run=false`.
- **Preview first:** Use preview/estimate tools before sending (e.g. `btc_wallet_preview_transfer`, `btc_estimate_fee`, `stx_preview_transfer`).
- **Limits:** Optional `BTC_MAX_SEND_BTC` and `BTC_MAX_FEE_SATS` cap amount and fees.
- **Env:** Keep `.env` out of version control and restrict permissions. Run script loads it from repo root.

---

## Testing

Unit tests live under `tests/unit/` and target MCP server behavior and wallet modules:

```bash
# From mcp/btc_wallet (this directory) or repo root
python -m pytest mcp/btc_wallet/tests/unit -v
```

Test modules include: `test_bitcoin_wallet_mcp_server.py`, `test_stx_wallet_mcp_server.py`, `test_ord_wallet_mcp_server.py`, `test_defi_wallet_mcp_server.py`, `test_phase5ab_mcp_server.py`, `test_phase5d_mcp_server.py`, `test_ledger_wallet_mcp_server.py`, `test_hiro_integration_mcp_server.py`. Ledger tests require a device or Speculos.

---

## Troubleshooting

| Issue | What to check |
|-------|----------------|
| Server fails to start | Python 3.10+, `pip install -r requirements.txt`, and correct `PATH`. |
| "Missing key" or "No mnemonic" | Set exactly one of `BTC_PRIVATE_KEY` or `BTC_MNEMONIC` in `.env` (and ensure the run script loads it from repo root). |
| Wrong network | Set `BTC_NETWORK=mainnet` or `testnet`; some tools also accept an explicit `network` argument. |
| Transfers not broadcasting | Confirm `BTC_DRY_RUN` and/or the tool’s `dry_run` are `false` when you intend to broadcast. |
| Ledger "No device" | Device connected, Bitcoin/Stacks app open, no other app holding the device; try `interface: "tcp"` with Speculos for dev. |
| Fee or balance errors | Check mempool.space (or configured API) is reachable; for Stacks, check Hiro API and network. |
| Import errors | Run from repo root or from `mcp/btc_wallet` so that `bitcoin_wallet`, `stx_wallet`, etc. are importable; or install the package if you use a package layout. |

---

## Reference

- **MCP**: [Model Context Protocol](https://modelcontextprotocol.io). Protocol and tool contract used by this server.
- **Foundation**: [markmhendrickson/foundation](https://github.com/markmhendrickson/foundation). Shared development processes and documentation conventions. After cloning, run `git submodule update --init foundation` if the `foundation/` directory is empty.

