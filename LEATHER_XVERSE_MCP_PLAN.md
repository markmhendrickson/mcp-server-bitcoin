# Leather & Xverse MCP Support Plan

## Comprehensive Phased Roadmap for Full Wallet Functionality via MCP

---

## Executive Summary

This document provides a prioritized, phased plan to expose all functionality from the
**Leather** (leather-io) and **Xverse** (secretkeylabs) Bitcoin/Stacks wallet ecosystems
through MCP (Model Context Protocol) server tools. The plan is organized into 6 phases,
moving from foundational BTC operations through advanced multi-chain features.

---

## Current State Assessment

### Existing MCP Server (`btc_wallet_mcp_server.py`)

The current server provides 4 basic tools:

| Tool | Description |
|------|-------------|
| `btc_wallet_get_balance` | Get wallet balance in BTC |
| `btc_wallet_get_prices` | Get BTC prices (USD/EUR) |
| `btc_wallet_preview_transfer` | Preview a BTC transfer with fee estimation |
| `btc_wallet_send_transfer` | Send BTC (with dry-run support) |

**Capabilities**: BIP44/49/84/86 key derivation, native SegWit (P2WPKH) signing via
python-bitcoinlib, mempool.space UTXO/fee/broadcast APIs, multi-address-type candidate
selection, dry-run mode, CoinGecko price feeds.

**Gaps**: No Stacks support, no PSBT signing, no message signing, no Ordinals/BRC-20/Runes,
no multi-account, no hardware wallet, no Starknet/Spark, no swap/DeFi, no NFT support.

---

## Repository Analysis

### Leather Ecosystem (leather-io)

**Primary repos**: `leather-io/mono` (monorepo with all packages), `leather-io/extension`

**RPC Methods** (from `@leather.io/rpc`):

#### Bitcoin Methods
| Method | Description |
|--------|-------------|
| `sendTransfer` | Send BTC to one or more recipients (sat-denominated amounts) |
| `signMessage` | Sign a message (BIP-322, legacy) with p2tr or p2wpkh |
| `signPsbt` | Sign a PSBT (partial, full, with sighash options + broadcast) |

#### Stacks Methods
| Method | Description |
|--------|-------------|
| `stx_callContract` | Call a Clarity smart contract function |
| `stx_deployContract` | Deploy a Clarity smart contract |
| `stx_getAddresses` | Get Stacks addresses for the wallet |
| `stx_getNetworks` | Get available Stacks networks |
| `stx_signMessage` | Sign a UTF-8 or structured message |
| `stx_signStructuredMessage` | Sign a SIP-018 structured data message |
| `stx_signTransaction` | Sign a Stacks transaction (SIP-30 compatible) |
| `stx_transferSip10Ft` | Transfer a SIP-10 fungible token |
| `stx_transferSip9Nft` | Transfer a SIP-9 NFT |
| `stx_transferStx` | Transfer STX tokens |
| `stx_updateProfile` | Update a user's on-chain profile (schema.org/Person) |

#### General Methods
| Method | Description |
|--------|-------------|
| `getAddresses` | Get all wallet addresses (BTC + STX) |
| `getInfo` | Get wallet version, platform, supported methods |
| `open` | Open the wallet UI (popup or fullpage) |
| `openSwap` | Open the swap interface with base/quote pair |
| `supportedMethods` | List all supported RPC methods with docs |

**Key Packages** (from `leather-io/mono`):
- `@leather.io/bitcoin` -- BIP-21, BIP-322, coin selection, fees, PSBT, payments, signing, transactions
- `@leather.io/stacks` -- Addresses, Clarity, message signing, signing, transactions
- `@leather.io/services` -- Swap (Alex, Bitflow, Velar, sBTC Bridge), yield, fees, balances, UTXOs, activity, BNS, collectibles, market data, notifications
- `@leather.io/queries` -- Activity, assets, balances, BNS, collectibles, market data/history, transactions, UTXOs
- `@leather.io/models` -- Account, activity, assets, balance, Bitcoin, BNS, currencies, fees, market, money, network, swap, transactions, UTXO, yield
- `@leather.io/sdk` -- Client library for wallet integration

**Extension Features**: Send (BTC, STX, tokens, NFTs), receive, swap, PSBT signing (batch), message signing (BIP-322), Stacks contract calls/deploys, Ledger support, address monitoring, fee editing, nonce editing, speed-up transactions, collectibles/Ordinals, BNS (Bitcoin Name System), stacking

### Xverse Ecosystem (secretkeylabs)

**Primary repos**: `secretkeylabs/xverse-core`, `secretkeylabs/xverse-web-extension`, `secretkeylabs/sats-connect-core`

**RPC Methods** (from `@sats-connect/core`):

#### BTC Methods
| Method | Description |
|--------|-------------|
| `getInfo` | Get wallet info |
| `getAddresses` | Get BTC addresses |
| `getAccounts` | Get BTC accounts |
| `getBalance` | Get BTC balance |
| `signMessage` | Sign a BTC message (ECDSA/BIP-322) |
| `signMultipleMessages` | Sign multiple messages in batch |
| `sendTransfer` | Send BTC transfer |
| `signPsbt` | Sign a PSBT |

#### Stacks Methods
| Method | Description |
|--------|-------------|
| `stx_callContract` | Call a Clarity contract |
| `stx_deployContract` | Deploy a Clarity contract |
| `stx_getAccounts` | Get Stacks accounts |
| `stx_getAddresses` | Get Stacks addresses |
| `stx_signMessage` | Sign a Stacks message |
| `stx_signStructuredMessage` | Sign structured data |
| `stx_signTransaction` | Sign a Stacks transaction |
| `stx_signTransactions` | Sign multiple Stacks transactions |
| `stx_transferStx` | Transfer STX |

#### Runes Methods
| Method | Description |
|--------|-------------|
| `runes_estimateEtch` | Estimate cost to etch (create) a rune |
| `runes_estimateMint` | Estimate cost to mint runes |
| `runes_estimateRbfOrder` | Estimate RBF cost for rune order |
| `runes_etch` | Etch (create) a new rune |
| `runes_getBalance` | Get rune balances |
| `runes_getOrder` | Get rune order status |
| `runes_mint` | Mint runes |
| `runes_rbfOrder` | RBF (Replace-By-Fee) a rune order |
| `runes_transfer` | Transfer runes |

#### Ordinals Methods
| Method | Description |
|--------|-------------|
| `ord_getInscriptions` | List inscriptions with pagination |
| `ord_sendInscriptions` | Send inscriptions to addresses |

#### Spark Methods (Lightning/L2)
| Method | Description |
|--------|-------------|
| `spark_getAddresses` | Get Spark addresses |
| `spark_getBalance` | Get Spark balance |
| `spark_transfer` | Transfer on Spark |
| `spark_transferToken` | Transfer tokens on Spark |
| `spark_signMessage` | Sign a Spark message |
| `spark_flashnet_getJwt` | Get Flashnet JWT |
| `spark_flashnet_signIntent` | Sign a Flashnet intent |
| `spark_flashnet_signStructuredMessage` | Sign structured Flashnet message |
| `spark_flashnet_executeSwap` | Execute a Flashnet swap |
| `spark_flashnet_executeRouteSwap` | Execute a routed Flashnet swap |
| `spark_flashnet_clawbackFunds` | Clawback funds from Flashnet |
| `spark_getClawbackEligibleTransfers` | Get clawback-eligible transfers |

#### Wallet Methods
| Method | Description |
|--------|-------------|
| `wallet_connect` | Connect to wallet |
| `wallet_disconnect` | Disconnect wallet |
| `wallet_getAccount` | Get current account info |
| `wallet_getNetwork` | Get current network |
| `wallet_addNetwork` | Add a custom network |
| `wallet_changeNetwork` | Change active network |
| `wallet_changeNetworkById` | Change network by ID |
| `wallet_getWalletType` | Get wallet type |
| `wallet_requestPermissions` | Request permissions |
| `wallet_getCurrentPermissions` | Get current permissions |
| `wallet_renouncePermissions` | Renounce permissions |
| `wallet_openReceive` | Open receive UI |
| `wallet_openBridge` | Open bridge UI |
| `wallet_openBuy` | Open buy/onramp UI |

**Xverse Core Modules**:
- `transactions/bitcoin` -- Enhanced PSBT, transaction context, coin selection, send BTC, send ordinals (with split), send max, combine UTXOs, recover BTC/ordinals, extract ordinals
- `transactions/stacks` -- Builders, fees, nonce helpers, stacking, transaction requests
- `transactions/runes` -- Send runes (multi-recipient)
- `transactions/brc20` -- BRC-20 operations (estimate, execute, transfer)
- `transactions/rbf` -- Replace-By-Fee for pending transactions
- `connect` -- Auth, message signing (ECDSA + BIP-322), Stacks message signing
- `wallet` -- Mnemonic generation, HD key derivation, address validation (BTC + STX + Starknet), balance discovery
- `api` -- Esplora, mempool, Hiro Stacks API, ordinals, runes, Xverse API, AVNU (Starknet), onramper
- `vaults` -- Seed vault, encryption vault, key-value vault, master vault
- `starknet` -- Address validation, contracts, paymaster
- `portfolio` -- Portfolio management
- `stacking` -- Stacking state management
- `swaps` -- Multi-protocol swaps (BTC, STX, Runes, SIP-10, Starknet, BRC-20)
- `ledger` -- Ledger hardware wallet (BTC + STX)
- `keystone` -- Keystone hardware wallet

---

## Phased Implementation Plan

### Phase 1: Core Bitcoin Enhancement (Priority: CRITICAL)
**Goal**: Bring existing BTC tools to parity with Leather/Xverse BTC RPC methods.
**Estimated effort**: 2-3 weeks

#### 1.1 Multi-Address & Account Management
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `btc_get_addresses` | Return all derived addresses (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR) with public keys and derivation paths | Leather `getAddresses`, Xverse `getAddresses` |
| `btc_get_accounts` | List accounts with balances across all address types | Xverse `getAccounts` |
| `btc_get_info` | Return wallet version, supported tools, network | Leather `getInfo` |

#### 1.2 Enhanced Sending
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `btc_send_transfer` | **Upgrade existing**: Support multiple recipients, sat-denominated amounts, account selection | Leather `sendTransfer` (multi-recipient), Xverse `sendTransfer` |
| `btc_send_max` | Send maximum BTC (sweep) with dust filtering | Xverse `sendMaxBtc` |
| `btc_combine_utxos` | Consolidate UTXOs to a single address | Xverse `combineUtxos` |

#### 1.3 PSBT Support
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `btc_sign_psbt` | Sign a PSBT (hex input), with signAtIndex, sighash options, optional broadcast | Leather `signPsbt`, Xverse `signPsbt` |
| `btc_sign_batch_psbt` | Sign multiple PSBTs in a single call | Xverse `signMultipleTransactions` |
| `btc_decode_psbt` | Decode and summarize a PSBT for human review | Xverse `EnhancedPsbt` |

#### 1.4 Message Signing
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `btc_sign_message` | Sign a message (BIP-322 or ECDSA/legacy) for any address type | Leather `signMessage`, Xverse `signMessage` |
| `btc_verify_message` | Verify a signed BTC message | Derived from signing libraries |

#### 1.5 Fee Management
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `btc_get_fees` | Get recommended fee rates (fastest, half-hour, hour, economy) | mempool.space API, Leather/Xverse fee services |
| `btc_estimate_fee` | Estimate fee for a specific transaction (vsize-aware) | Xverse `estimateVSize`, Leather `@leather.io/bitcoin/fees` |

#### 1.6 UTXO Management
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `btc_list_utxos` | List UTXOs for all address types with optional filtering | Leather `@leather.io/queries/utxos`, Xverse `ExtendedUtxo` |
| `btc_get_utxo_details` | Get detailed UTXO info (inscriptions, runes, sat ranges) | Xverse `getBundleData` |

---

### Phase 2: Stacks (STX) Support (Priority: HIGH)
**Goal**: Full Stacks blockchain support matching Leather/Xverse Stacks RPC methods.
**Estimated effort**: 3-4 weeks

#### 2.1 Stacks Address & Account Management
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `stx_get_addresses` | Get Stacks addresses with public keys and derivation paths | Leather `stx_getAddresses`, Xverse `stx_getAddresses` |
| `stx_get_accounts` | Get Stacks accounts with balances and nonces | Xverse `stx_getAccounts` |
| `stx_get_balance` | Get STX balance and token balances for an address | Leather `@leather.io/queries/balances` |
| `stx_get_networks` | List available Stacks networks | Leather `stx_getNetworks` |

#### 2.2 STX Transfers
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `stx_transfer_stx` | Transfer STX to a recipient (with memo support) | Leather `stx_transferStx`, Xverse `stx_transferStx` |
| `stx_preview_transfer` | Preview an STX transfer with fee estimation | Derived from Stacks transaction builders |
| `stx_transfer_sip10_ft` | Transfer a SIP-10 fungible token | Leather `stx_transferSip10Ft` |
| `stx_transfer_sip9_nft` | Transfer a SIP-9 NFT | Leather `stx_transferSip9Nft` |

#### 2.3 Smart Contract Interaction
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `stx_call_contract` | Call a read-only or public Clarity contract function | Leather `stx_callContract`, Xverse `stx_callContract` |
| `stx_deploy_contract` | Deploy a Clarity smart contract | Leather `stx_deployContract`, Xverse `stx_deployContract` |
| `stx_read_contract` | Read-only call to a contract (no transaction needed) | Stacks API |

#### 2.4 Stacks Transaction Signing
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `stx_sign_transaction` | Sign a serialized Stacks transaction (SIP-30 compatible) | Leather `stx_signTransaction`, Xverse `stx_signTransaction` |
| `stx_sign_transactions` | Sign multiple Stacks transactions in batch | Xverse `stx_signTransactions` |

#### 2.5 Stacks Message Signing
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `stx_sign_message` | Sign a UTF-8 message on Stacks | Leather `stx_signMessage`, Xverse `stx_signMessage` |
| `stx_sign_structured_message` | Sign SIP-018 structured data | Leather `stx_signStructuredMessage`, Xverse `stx_signStructuredMessage` |

#### 2.6 Stacks Utilities
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `stx_get_nonce` | Get current nonce for an address | Xverse `nonceHelpers` |
| `stx_estimate_fee` | Estimate Stacks transaction fee | Xverse `transactions/stacks/fees` |
| `stx_update_profile` | Update on-chain profile | Leather `stx_updateProfile` |

---

### Phase 3: Ordinals, Inscriptions & BRC-20 (Priority: HIGH)
**Goal**: Full support for Bitcoin Ordinals, inscriptions, and BRC-20 tokens.
**Estimated effort**: 3-4 weeks

#### 3.1 Ordinals / Inscriptions
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `ord_get_inscriptions` | List inscriptions with pagination (ID, number, content type, address) | Xverse `ord_getInscriptions`, Leather collectibles |
| `ord_get_inscription_details` | Get detailed info for a specific inscription | Ordinals API |
| `ord_send_inscriptions` | Send inscriptions to recipient(s) | Xverse `ord_sendInscriptions`, `sendOrdinals` |
| `ord_send_inscriptions_split` | Send inscriptions with UTXO splitting (preserve sat ranges) | Xverse `sendOrdinalsWithSplit` |
| `ord_extract_from_utxo` | Extract ordinals from a mixed UTXO | Xverse `extractOrdinalsFromUtxo` |
| `ord_recover_bitcoin` | Recover BTC trapped in ordinals address | Xverse `recoverBitcoin` |
| `ord_recover_ordinals` | Recover ordinals from payment address | Xverse `recoverOrdinal` |

#### 3.2 BRC-20 Tokens
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `brc20_estimate_transfer` | Estimate cost for BRC-20 transfer (inscribe + transfer) | Xverse `brc20.ts` |
| `brc20_execute_transfer` | Execute a BRC-20 transfer | Xverse BRC-20 flow |
| `brc20_get_balances` | Get BRC-20 token balances | Xverse/Hiro APIs |

#### 3.3 Rare Sats
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `sats_get_rare` | List rare/exotic sats in wallet | Xverse `rareSatsBundle`, `rareSatsDetail` |
| `sats_get_bundle` | Get sat range bundle data for a UTXO | Xverse `getBundleData` |

---

### Phase 4: Runes Support (Priority: MEDIUM-HIGH)
**Goal**: Complete Runes token lifecycle support.
**Estimated effort**: 2-3 weeks

| MCP Tool | Description | Source |
|----------|-------------|--------|
| `runes_get_balance` | Get rune balances for wallet | Xverse `runes_getBalance` |
| `runes_transfer` | Transfer runes to recipients | Xverse `runes_transfer`, `sendManyRunes` |
| `runes_estimate_etch` | Estimate cost to create a new rune | Xverse `runes_estimateEtch` |
| `runes_etch` | Etch (create) a new rune | Xverse `runes_etch` |
| `runes_estimate_mint` | Estimate cost to mint runes | Xverse `runes_estimateMint` |
| `runes_mint` | Mint runes | Xverse `runes_mint` |
| `runes_get_order` | Get rune order status | Xverse `runes_getOrder` |
| `runes_estimate_rbf` | Estimate RBF cost for a rune order | Xverse `runes_estimateRbfOrder` |
| `runes_rbf_order` | RBF a pending rune order | Xverse `runes_rbfOrder` |
| `runes_list` | List available runes (search/browse) | Xverse runes API |

---

### Phase 5: Swaps, DeFi & Cross-Chain (Priority: MEDIUM)
**Goal**: Swap, bridge, yield, and cross-chain functionality.
**Estimated effort**: 4-5 weeks

#### 5.1 Swap Operations
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `swap_get_quote` | Get a swap quote (BTC, STX, Runes, SIP-10, BRC-20) | Leather swap services (Alex, Bitflow, Velar), Xverse swap module |
| `swap_execute` | Execute a swap | Leather `openSwap`, swap providers |
| `swap_get_supported_pairs` | List supported swap pairs and protocols | Derived from both ecosystems |
| `swap_get_history` | Get swap transaction history | Activity/transaction history APIs |

#### 5.2 sBTC Bridge
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `sbtc_bridge_deposit` | Bridge BTC to sBTC (Stacks L2) | Leather `sbtc-bridge-swap-provider` |
| `sbtc_bridge_withdraw` | Withdraw sBTC back to BTC | Leather sBTC bridge service |
| `sbtc_get_balance` | Get sBTC balance | Derived from Stacks token balance |

#### 5.3 Yield / Stacking
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `stx_get_stacking_info` | Get current stacking status and rewards | Xverse `stacking`, Leather yield service |
| `stx_stack` | Initiate STX stacking (delegate or solo) | Xverse `transactions/stacks/stacking` |
| `stx_revoke_delegation` | Revoke stacking delegation | Stacks stacking contract |

#### 5.4 Spark (Lightning/L2)
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `spark_get_addresses` | Get Spark addresses | Xverse `spark_getAddresses` |
| `spark_get_balance` | Get Spark balance | Xverse `spark_getBalance` |
| `spark_transfer` | Transfer on Spark network | Xverse `spark_transfer` |
| `spark_transfer_token` | Transfer tokens on Spark | Xverse `spark_transferToken` |
| `spark_sign_message` | Sign a message for Spark | Xverse `spark_signMessage` |

#### 5.5 Flashnet (Advanced Lightning)
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `flashnet_get_jwt` | Get Flashnet authentication token | Xverse `spark_flashnet_getJwt` |
| `flashnet_sign_intent` | Sign a Flashnet intent | Xverse `spark_flashnet_signIntent` |
| `flashnet_execute_swap` | Execute a swap via Flashnet | Xverse `spark_flashnet_executeSwap` |
| `flashnet_execute_route_swap` | Execute a routed swap | Xverse `spark_flashnet_executeRouteSwap` |
| `flashnet_clawback` | Clawback funds from Flashnet | Xverse `spark_flashnet_clawbackFunds` |

---

### Phase 6: Advanced Features & Ecosystem (Priority: LOWER)
**Goal**: Full ecosystem parity including advanced wallet management, hardware wallets,
name systems, market data, and Starknet.
**Estimated effort**: 5-6 weeks

#### 6.1 Transaction Management
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `tx_get_history` | Get transaction history (BTC + STX) with filtering | Leather activity, Xverse transaction history |
| `tx_get_status` | Get status of a specific transaction | mempool.space / Stacks API |
| `tx_speed_up` | Speed up (RBF) a pending BTC transaction | Xverse `rbf.ts`, Leather speed-up feature |
| `tx_cancel` | Cancel a pending transaction via RBF | Derived from RBF |

#### 6.2 Wallet Management
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `wallet_get_network` | Get current network configuration | Xverse `wallet_getNetwork`, Leather networks |
| `wallet_switch_network` | Switch between mainnet/testnet/signet/regtest | Xverse `wallet_changeNetwork` |
| `wallet_add_network` | Add a custom network | Xverse `wallet_addNetwork` |
| `wallet_get_supported_methods` | List all available MCP tools | Leather `supportedMethods` |

#### 6.3 Name Systems
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `bns_lookup` | Look up a BNS name to resolve address | Leather `@leather.io/queries/bns` |
| `bns_get_names` | Get BNS names owned by an address | Leather BNS queries |
| `bns_register` | Register a BNS name | Stacks BNS contract |

#### 6.4 Market Data & Portfolio
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `market_get_prices` | **Upgrade existing**: Multi-asset price data (BTC, STX, tokens) | Leather market data service, CoinGecko |
| `market_get_history` | Price history for charting | Leather `@leather.io/queries/market-history` |
| `portfolio_get_summary` | Full portfolio summary (all assets, all chains) | Xverse `portfolio`, Leather `@leather.io/queries/balances` |
| `portfolio_get_assets` | List all assets with current values | Leather `@leather.io/queries/assets` |
| `portfolio_get_collectibles` | List all collectibles/NFTs | Leather `@leather.io/queries/collectibles` |

#### 6.5 Starknet (Xverse)
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `starknet_get_address` | Get Starknet address | Xverse `starknet` module |
| `starknet_validate_address` | Validate a Starknet address | Xverse `address-validation.ts` |
| `starknet_transfer` | Transfer on Starknet | Xverse Starknet contracts |

#### 6.6 Hardware Wallet Support
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `ledger_get_addresses` | Get addresses from Ledger device | Xverse `ledger`, Leather Ledger feature |
| `ledger_sign_psbt` | Sign PSBT via Ledger | Xverse `ledger/btc.ts` |
| `ledger_sign_stx_transaction` | Sign STX transaction via Ledger | Xverse `ledger/stx.ts` |
| `keystone_get_addresses` | Get addresses from Keystone device | Xverse `keystone` |
| `keystone_sign_psbt` | Sign PSBT via Keystone | Xverse `keystone/btc.ts` |

#### 6.7 Inscription Creation
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `ord_create_inscription` | Create a new inscription | Xverse `createInscription`, inscription mint |
| `ord_create_repeat_inscriptions` | Create multiple inscriptions | Xverse `createRepeatInscriptions` |

#### 6.8 Address Book & Permissions
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `addressbook_list` | List address book entries | Xverse `addressBook` |
| `addressbook_add` | Add an address book entry | Xverse `addressBook` |
| `permissions_get` | Get current permissions state | Xverse `wallet_getCurrentPermissions` |
| `permissions_request` | Request specific permissions | Xverse `wallet_requestPermissions` |

#### 6.9 Buy/Onramp
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `buy_get_providers` | List available onramp providers | Xverse `onramper`, Leather fund page |
| `buy_get_quote` | Get a buy quote | Onramper API |

---

## Architecture Recommendations

### MCP Server Structure

```
mcp/
  btc_wallet/                     # Phase 1 -- existing, enhanced
    btc_wallet_mcp_server.py
    btc_wallet.py
  stx_wallet/                     # Phase 2
    stx_wallet_mcp_server.py
    stx_wallet.py
  ordinals/                       # Phase 3
    ordinals_mcp_server.py
  runes/                          # Phase 4
    runes_mcp_server.py
  defi/                           # Phase 5
    swap_mcp_server.py
    bridge_mcp_server.py
    spark_mcp_server.py
  advanced/                       # Phase 6
    portfolio_mcp_server.py
    market_mcp_server.py
```

**Alternative (Recommended)**: Single unified MCP server with namespaced tools:

```
wallet_mcp_server.py              # All tools in one server
  ├── btc_*       tools           # Phase 1
  ├── stx_*       tools           # Phase 2
  ├── ord_*       tools           # Phase 3
  ├── runes_*     tools           # Phase 4
  ├── swap_*      tools           # Phase 5
  ├── spark_*     tools           # Phase 5
  └── wallet_*    tools           # Phase 6
```

### Key Design Principles

1. **Safety First**: All destructive operations (send, sign, deploy) require explicit
   confirmation via `dry_run` parameter defaulting to `true`. Preview tools should
   always be called before execution tools.

2. **Consistent Interface**: Every tool returns `{ success: bool, ...data }` or
   `{ success: false, error: string }`. No secrets in responses.

3. **Network Awareness**: All tools accept optional `network` parameter
   (mainnet/testnet/signet/regtest). Default from env config.

4. **Account Selection**: Multi-account tools accept optional `account` index.
   Default to account 0.

5. **Composability**: Tools should be composable -- preview before send, decode PSBT
   before sign, estimate before execute.

6. **MCP Resources**: Use MCP resources (not just tools) for read-only data:
   - `wallet://addresses` -- current addresses
   - `wallet://balances` -- current balances
   - `wallet://network` -- current network config
   - `wallet://utxos` -- current UTXOs

### API Dependencies

| Phase | External APIs | Libraries Needed |
|-------|--------------|------------------|
| 1 | mempool.space, CoinGecko | python-bitcoinlib, bip-utils, bit |
| 2 | Hiro Stacks API, mempool.space | stacks.py (or HTTP calls to Hiro API) |
| 3 | Ordinals API (ord, Hiro), mempool.space | python-bitcoinlib, requests |
| 4 | Runes API (ord), mempool.space | python-bitcoinlib, requests |
| 5 | Alex SDK, Bitflow, Velar, sBTC, Spark | Protocol-specific SDKs/APIs |
| 6 | BNS API, CoinGecko, Onramper, Ledger/Keystone | ledgercomm, various |

---

## Priority Matrix

| Phase | Priority | Business Value | Technical Complexity | Dependencies |
|-------|----------|---------------|---------------------|--------------|
| 1 | CRITICAL | High -- Core BTC operations used by all users | Medium -- Extends existing code | None |
| 2 | HIGH | High -- Stacks is core to both ecosystems | Medium-High -- New chain integration | Phase 1 |
| 3 | HIGH | High -- Ordinals/inscriptions are key Bitcoin NFT use case | Medium -- New APIs and UTXO handling | Phase 1 |
| 4 | MEDIUM-HIGH | Medium -- Runes is growing token standard | Medium -- Similar patterns to Phase 3 | Phase 1, 3 |
| 5 | MEDIUM | Medium-High -- DeFi/swap is key user workflow | High -- Multiple protocol integrations | Phase 1, 2, 4 |
| 6 | LOWER | Medium -- Advanced features for power users | High -- Many diverse integrations | Phase 1-5 |

---

## Tool Count Summary

| Phase | Category | Tool Count |
|-------|----------|------------|
| 1 | Core Bitcoin | 16 |
| 2 | Stacks (STX) | 14 |
| 3 | Ordinals & BRC-20 | 10 |
| 4 | Runes | 10 |
| 5 | Swaps, DeFi, Spark, Flashnet | 16 |
| 6 | Advanced & Ecosystem | 19 |
| **Total** | | **85** |

---

## Appendix: Feature Mapping (Current vs Target)

| Feature | Current MCP | Leather | Xverse | Target Phase |
|---------|------------|---------|--------|-------------|
| BTC Balance | Yes | Yes | Yes | 1 (enhance) |
| BTC Send | Yes (basic) | Yes (multi-recipient) | Yes (multi-recipient) | 1 (enhance) |
| BTC Receive Addresses | Partial | Yes (all types) | Yes (all types) | 1 |
| PSBT Signing | No | Yes | Yes (batch) | 1 |
| BTC Message Signing | No | Yes (BIP-322) | Yes (ECDSA + BIP-322) | 1 |
| Fee Estimation | Basic | Yes (dynamic) | Yes (dynamic) | 1 |
| UTXO Management | No | Yes | Yes (extended) | 1 |
| STX Balance | No | Yes | Yes | 2 |
| STX Transfer | No | Yes | Yes | 2 |
| STX Token Transfer | No | Yes (SIP-10, SIP-9) | Yes | 2 |
| Stacks Contracts | No | Yes (call + deploy) | Yes (call + deploy) | 2 |
| Stacks Message Signing | No | Yes (UTF-8 + structured) | Yes (UTF-8 + structured) | 2 |
| Ordinals/Inscriptions | No | Yes (view) | Yes (view + send + split) | 3 |
| BRC-20 Tokens | No | No | Yes | 3 |
| Runes | No | No | Yes (full lifecycle) | 4 |
| Swaps | No | Yes (Alex, Bitflow, Velar) | Yes (multi-protocol) | 5 |
| sBTC Bridge | No | Yes | No | 5 |
| Spark/Lightning | No | No | Yes | 5 |
| Stacking/Yield | No | Yes | Yes | 5 |
| RBF/Speed-up | No | No | Yes | 6 |
| Hardware Wallets | No | Yes (Ledger) | Yes (Ledger + Keystone) | 6 |
| BNS Names | No | Yes | No | 6 |
| Portfolio | No | Yes | Yes | 6 |
| Starknet | No | No | Yes | 6 |
| Inscription Creation | No | No | Yes | 6 |
