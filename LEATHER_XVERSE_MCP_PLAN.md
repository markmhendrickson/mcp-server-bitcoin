# Leather & Xverse MCP Support Plan

## Comprehensive Phased Roadmap for Full Wallet Functionality via MCP

---

## Executive Summary

This document provides a prioritized, phased plan to expose functionality from the
**Leather** (leather-io) and **Xverse** (secretkeylabs) Bitcoin/Stacks wallet ecosystems
through MCP (Model Context Protocol) server tools. The plan is organized into 5 phases,
moving from foundational BTC operations through advanced ecosystem features.

**Scope exclusions**: BRC-20 tokens, Runes, rare sats, Spark (Lightning/L2), and Flashnet
are out of scope for this plan.

---

## Current State (Implemented)

### Phase 1: Core Bitcoin -- COMPLETE (19 tools)

| Tool | Description | Status |
|------|-------------|--------|
| `btc_get_addresses` | All derived addresses (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR) with pubkeys | Done |
| `btc_get_accounts` | Account balances across all address types via mempool.space | Done |
| `btc_get_info` | Wallet version, network, supported tools | Done |
| `btc_wallet_get_balance` | Wallet balance in BTC | Done |
| `btc_wallet_get_prices` | BTC prices in USD and EUR | Done |
| `btc_wallet_preview_transfer` | Preview transfer with fee estimation | Done |
| `btc_wallet_send_transfer` | Send BTC (single recipient, BTC/EUR amounts) | Done |
| `btc_send_transfer` | Multi-recipient sat-denominated transfers | Done |
| `btc_send_max` | Sweep/send-max with automatic fee calculation | Done |
| `btc_combine_utxos` | UTXO consolidation | Done |
| `btc_sign_psbt` | PSBT signing (hex/base64, optional broadcast) | Done |
| `btc_sign_batch_psbt` | Batch PSBT signing | Done |
| `btc_decode_psbt` | PSBT decoder with human-readable summary | Done |
| `btc_sign_message` | Message signing (ECDSA + BIP-322) | Done |
| `btc_verify_message` | Signature verification | Done |
| `btc_get_fees` | All fee tiers from mempool.space | Done |
| `btc_estimate_fee` | vsize-aware fee estimation | Done |
| `btc_list_utxos` | UTXO listing with filtering | Done |
| `btc_get_utxo_details` | Detailed UTXO info with scriptPubKey | Done |

### Phase 2: Stacks (STX) -- COMPLETE (18 tools)

| Tool | Description | Status |
|------|-------------|--------|
| `stx_get_addresses` | STX addresses with pubkeys and derivation paths | Done |
| `stx_get_accounts` | Balances, locked amounts, nonces via Hiro API | Done |
| `stx_get_balance` | STX + fungible + NFT token balances | Done |
| `stx_get_networks` | Available networks with chain IDs | Done |
| `stx_transfer_stx` | STX transfer with memo | Done |
| `stx_preview_transfer` | Transfer preview with fee estimation | Done |
| `stx_transfer_sip10_ft` | SIP-10 fungible token transfer | Done |
| `stx_transfer_sip9_nft` | SIP-9 NFT transfer | Done |
| `stx_call_contract` | Public Clarity contract function calls | Done |
| `stx_deploy_contract` | Smart contract deployment | Done |
| `stx_read_contract` | Read-only contract calls via Hiro API | Done |
| `stx_sign_transaction` | SIP-30 compatible transaction signing | Done |
| `stx_sign_transactions` | Batch transaction signing | Done |
| `stx_sign_message` | UTF-8 message signing | Done |
| `stx_sign_structured_message` | SIP-018 structured data signing | Done |
| `stx_get_nonce` | Address nonce lookup | Done |
| `stx_estimate_fee` | Transaction fee estimation | Done |
| `stx_update_profile` | On-chain profile update (BNS) | Done |

---

## Remaining Phases

### Phase 3: Ordinals & Inscriptions (Priority: HIGH)
**Goal**: Support for Bitcoin Ordinals inscriptions -- viewing, sending, and splitting.
**Estimated effort**: 2-3 weeks

| MCP Tool | Description | Source |
|----------|-------------|--------|
| `ord_get_inscriptions` | List inscriptions with pagination (ID, number, content type, address) | Xverse `ord_getInscriptions`, Leather collectibles |
| `ord_get_inscription_details` | Get detailed info for a specific inscription | Ordinals API |
| `ord_send_inscriptions` | Send inscriptions to recipient(s) | Xverse `ord_sendInscriptions`, `sendOrdinals` |
| `ord_send_inscriptions_split` | Send inscriptions with UTXO splitting (preserve sat ranges) | Xverse `sendOrdinalsWithSplit` |
| `ord_extract_from_utxo` | Extract ordinals from a mixed UTXO | Xverse `extractOrdinalsFromUtxo` |
| `ord_recover_bitcoin` | Recover BTC trapped in ordinals address | Xverse `recoverBitcoin` |
| `ord_recover_ordinals` | Recover ordinals from payment address | Xverse `recoverOrdinal` |

**Tool count**: 7

---

### Phase 4: Swaps, DeFi & Bridge (Priority: MEDIUM)
**Goal**: Swap, sBTC bridge, and stacking/yield functionality.
**Estimated effort**: 3-4 weeks

#### 4.1 Swap Operations
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `swap_get_quote` | Get a swap quote (BTC, STX, SIP-10) | Leather swap services (Alex, Bitflow, Velar), Xverse swap module |
| `swap_execute` | Execute a swap | Leather `openSwap`, swap providers |
| `swap_get_supported_pairs` | List supported swap pairs and protocols | Derived from both ecosystems |
| `swap_get_history` | Get swap transaction history | Activity/transaction history APIs |

#### 4.2 sBTC Bridge
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `sbtc_bridge_deposit` | Bridge BTC to sBTC (Stacks L2) | Leather `sbtc-bridge-swap-provider` |
| `sbtc_bridge_withdraw` | Withdraw sBTC back to BTC | Leather sBTC bridge service |
| `sbtc_get_balance` | Get sBTC balance | Derived from Stacks token balance |

#### 4.3 Yield / Stacking
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `stx_get_stacking_info` | Get current stacking status and rewards | Xverse `stacking`, Leather yield service |
| `stx_stack` | Initiate STX stacking (delegate or solo) | Xverse `transactions/stacks/stacking` |
| `stx_revoke_delegation` | Revoke stacking delegation | Stacks stacking contract |

**Tool count**: 10

---

### Phase 5: Advanced Features & Ecosystem (Priority: LOWER)
**Goal**: Full ecosystem parity including transaction management, wallet management,
name systems, market data, hardware wallets, and inscription creation.
**Estimated effort**: 4-5 weeks

#### 5.1 Transaction Management
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `tx_get_history` | Get transaction history (BTC + STX) with filtering | Leather activity, Xverse transaction history |
| `tx_get_status` | Get status of a specific transaction | mempool.space / Stacks API |
| `tx_speed_up` | Speed up (RBF) a pending BTC transaction | Xverse `rbf.ts`, Leather speed-up feature |
| `tx_cancel` | Cancel a pending transaction via RBF | Derived from RBF |

#### 5.2 Wallet Management
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `wallet_get_network` | Get current network configuration | Xverse `wallet_getNetwork`, Leather networks |
| `wallet_switch_network` | Switch between mainnet/testnet/signet/regtest | Xverse `wallet_changeNetwork` |
| `wallet_add_network` | Add a custom network | Xverse `wallet_addNetwork` |
| `wallet_get_supported_methods` | List all available MCP tools | Leather `supportedMethods` |

#### 5.3 Name Systems
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `bns_lookup` | Look up a BNS name to resolve address | Leather `@leather.io/queries/bns` |
| `bns_get_names` | Get BNS names owned by an address | Leather BNS queries |
| `bns_register` | Register a BNS name | Stacks BNS contract |

#### 5.4 Market Data & Portfolio
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `market_get_prices` | Multi-asset price data (BTC, STX, tokens) | Leather market data service, CoinGecko |
| `market_get_history` | Price history for charting | Leather `@leather.io/queries/market-history` |
| `portfolio_get_summary` | Full portfolio summary (all assets, all chains) | Xverse `portfolio`, Leather `@leather.io/queries/balances` |
| `portfolio_get_assets` | List all assets with current values | Leather `@leather.io/queries/assets` |
| `portfolio_get_collectibles` | List all collectibles/NFTs | Leather `@leather.io/queries/collectibles` |

#### 5.5 Hardware Wallet Support
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `ledger_get_addresses` | Get addresses from Ledger device | Xverse `ledger`, Leather Ledger feature |
| `ledger_sign_psbt` | Sign PSBT via Ledger | Xverse `ledger/btc.ts` |
| `ledger_sign_stx_transaction` | Sign STX transaction via Ledger | Xverse `ledger/stx.ts` |
| `keystone_get_addresses` | Get addresses from Keystone device | Xverse `keystone` |
| `keystone_sign_psbt` | Sign PSBT via Keystone | Xverse `keystone/btc.ts` |

#### 5.6 Inscription Creation
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `ord_create_inscription` | Create a new inscription | Xverse `createInscription`, inscription mint |
| `ord_create_repeat_inscriptions` | Create multiple inscriptions | Xverse `createRepeatInscriptions` |

#### 5.7 Buy/Onramp
| MCP Tool | Description | Source |
|----------|-------------|--------|
| `buy_get_providers` | List available onramp providers | Xverse `onramper`, Leather fund page |
| `buy_get_quote` | Get a buy quote | Onramper API |

**Tool count**: 25

---

## Architecture

### Implemented Structure (Unified Server)

```
btc_wallet_mcp_server.py          # Single MCP server with all tools
  ├── btc_*       tools           # Phase 1 (19 tools) -- DONE
  ├── stx_*       tools           # Phase 2 (18 tools) -- DONE
  ├── ord_*       tools           # Phase 3 (7 tools)
  ├── swap_*/sbtc_* tools         # Phase 4 (10 tools)
  └── tx_*/wallet_*/bns_* tools   # Phase 5 (25 tools)

btc_wallet.py                     # BTC wallet operations
stx_wallet.py                     # STX wallet operations
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

### API Dependencies

| Phase | External APIs | Libraries Needed |
|-------|--------------|------------------|
| 1 | mempool.space, CoinGecko | python-bitcoinlib, bip-utils, bit, coincurve |
| 2 | Hiro Stacks API | coincurve, requests |
| 3 | Ordinals API (ord, Hiro), mempool.space | python-bitcoinlib, requests |
| 4 | Alex SDK, Bitflow, Velar, sBTC | Protocol-specific APIs |
| 5 | BNS API, CoinGecko, Onramper, Ledger/Keystone | ledgercomm, various |

---

## Priority Matrix

| Phase | Priority | Business Value | Technical Complexity | Dependencies |
|-------|----------|---------------|---------------------|--------------|
| 1 | CRITICAL | High -- Core BTC operations used by all users | Medium | None |
| 2 | HIGH | High -- Stacks is core to both ecosystems | Medium-High | Phase 1 |
| 3 | HIGH | High -- Ordinals/inscriptions are key Bitcoin NFT use case | Medium | Phase 1 |
| 4 | MEDIUM | Medium-High -- DeFi/swap is key user workflow | High | Phase 1, 2 |
| 5 | LOWER | Medium -- Advanced features for power users | High | Phase 1-4 |

---

## Tool Count Summary

| Phase | Category | Tool Count | Status |
|-------|----------|------------|--------|
| 1 | Core Bitcoin | 19 | **DONE** |
| 2 | Stacks (STX) | 18 | **DONE** |
| 3 | Ordinals & Inscriptions | 7 | Planned |
| 4 | Swaps, DeFi, Bridge, Stacking | 10 | Planned |
| 5 | Advanced & Ecosystem | 25 | Planned |
| **Total** | | **79** | **37 done** |

---

## Appendix: Feature Mapping (Current vs Target)

| Feature | Current MCP | Leather | Xverse | Target Phase |
|---------|------------|---------|--------|-------------|
| BTC Balance | **Yes** | Yes | Yes | 1 |
| BTC Send (multi-recipient) | **Yes** | Yes | Yes | 1 |
| BTC Receive Addresses | **Yes** | Yes | Yes | 1 |
| PSBT Signing | **Yes** | Yes | Yes (batch) | 1 |
| BTC Message Signing | **Yes** | Yes (BIP-322) | Yes (ECDSA + BIP-322) | 1 |
| Fee Estimation | **Yes** | Yes (dynamic) | Yes (dynamic) | 1 |
| UTXO Management | **Yes** | Yes | Yes (extended) | 1 |
| STX Balance | **Yes** | Yes | Yes | 2 |
| STX Transfer | **Yes** | Yes | Yes | 2 |
| STX Token Transfer (SIP-10, SIP-9) | **Yes** | Yes | Yes | 2 |
| Stacks Contracts (call + deploy) | **Yes** | Yes | Yes | 2 |
| Stacks Message Signing | **Yes** | Yes | Yes | 2 |
| Ordinals/Inscriptions | No | Yes (view) | Yes (view + send + split) | 3 |
| Swaps | No | Yes (Alex, Bitflow, Velar) | Yes (multi-protocol) | 4 |
| sBTC Bridge | No | Yes | No | 4 |
| Stacking/Yield | No | Yes | Yes | 4 |
| RBF/Speed-up | No | No | Yes | 5 |
| Hardware Wallets | No | Yes (Ledger) | Yes (Ledger + Keystone) | 5 |
| BNS Names | No | Yes | No | 5 |
| Portfolio | No | Yes | Yes | 5 |
| Inscription Creation | No | No | Yes | 5 |
