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

### Phase 3: Ordinals & Inscriptions -- COMPLETE (7 tools)

| Tool | Description | Status |
|------|-------------|--------|
| `ord_get_inscriptions` | List inscriptions with pagination via Hiro Ordinals API | Done |
| `ord_get_inscription_details` | Detailed inscription info (genesis, content, rarity, location) | Done |
| `ord_send_inscriptions` | Send inscriptions (full UTXO transfer with fee funding) | Done |
| `ord_send_inscriptions_split` | Send inscriptions with UTXO splitting (preserve sat ranges) | Done |
| `ord_extract_from_utxo` | Extract ordinals from mixed UTXO into individual outputs | Done |
| `ord_recover_bitcoin` | Recover BTC from ordinals address (non-inscription UTXOs) | Done |
| `ord_recover_ordinals` | Recover ordinals from payment address to taproot address | Done |

---

### Phase 4: Swaps, DeFi & Bridge -- COMPLETE (10 tools)

#### 4.1 Swap Operations
| Tool | Description | Status |
|------|-------------|--------|
| `swap_get_supported_pairs` | List pools/pairs from Alex DEX | Done |
| `swap_get_quote` | Get quote with estimated output, rate, fees | Done |
| `swap_execute` | Execute swap via DEX contract call | Done |
| `swap_get_history` | Get swap transaction history from on-chain activity | Done |

#### 4.2 sBTC Bridge
| Tool | Description | Status |
|------|-------------|--------|
| `sbtc_get_balance` | Get sBTC token balance | Done |
| `sbtc_bridge_deposit` | Get deposit info for BTC-to-sBTC bridge | Done |
| `sbtc_bridge_withdraw` | Get withdrawal info for sBTC-to-BTC | Done |

#### 4.3 Yield / Stacking
| Tool | Description | Status |
|------|-------------|--------|
| `stx_get_stacking_info` | PoX cycle info, thresholds, wallet stacking state | Done |
| `stx_stack` | Initiate STX solo stacking via PoX contract | Done |
| `stx_revoke_delegation` | Revoke stacking delegation | Done |

---

### Phase 5: Advanced Features & Ecosystem (Priority: LOWER)
**Goal**: Full ecosystem parity including transaction management, wallet management,
name systems, market data, hardware wallets, and inscription creation.
**Total tool count**: 25

#### Sub-phase 5A: Transaction Management & Wallet (8 tools)
**Priority**: Medium -- Useful for power users managing pending transactions.
**Effort**: 1-2 weeks
**Dependencies**: Phase 1 (BTC), Phase 2 (STX)

| MCP Tool | Description | Source | Complexity |
|----------|-------------|--------|-----------|
| `tx_get_history` | Get transaction history (BTC + STX) with filtering | Leather activity, Xverse history | Low -- REST API calls |
| `tx_get_status` | Get status of a specific transaction (BTC or STX) | mempool.space / Stacks API | Low -- REST API calls |
| `tx_speed_up` | Speed up (RBF) a pending BTC transaction | Xverse `rbf.ts` | High -- rebuild + resign tx |
| `tx_cancel` | Cancel a pending BTC transaction via RBF | Derived from RBF | High -- same as speed_up |
| `wallet_get_network` | Get current network configuration | Xverse `wallet_getNetwork` | Low -- read config |
| `wallet_switch_network` | Switch between mainnet/testnet/signet/regtest | Xverse `wallet_changeNetwork` | Low -- write config |
| `wallet_add_network` | Add a custom network configuration | Xverse `wallet_addNetwork` | Low -- write config |
| `wallet_get_supported_methods` | List all available MCP tools with descriptions | Leather `supportedMethods` | Low -- introspect |

#### Sub-phase 5B: BNS & Market Data (8 tools)
**Priority**: Medium -- Valuable for name resolution and portfolio tracking.
**Effort**: 1-2 weeks
**Dependencies**: Phase 2 (STX for BNS), Phase 1 (BTC for market data)

| MCP Tool | Description | Source | Complexity |
|----------|-------------|--------|-----------|
| `bns_lookup` | Look up a BNS name to resolve STX/BTC address | Leather `@leather.io/queries/bns` | Low -- Hiro BNS API |
| `bns_get_names` | Get BNS names owned by an address | Leather BNS queries | Low -- Hiro BNS API |
| `bns_register` | Register a BNS name (contract call) | Stacks BNS contract | Medium -- contract call |
| `market_get_prices` | Multi-asset prices (BTC, STX, tokens) | CoinGecko, Leather market data | Low -- REST API |
| `market_get_history` | Price history for charting | Leather market-history queries | Low -- REST API |
| `portfolio_get_summary` | Full portfolio summary (all assets, all chains) | Xverse portfolio, Leather balances | Medium -- aggregate |
| `portfolio_get_assets` | List all assets with current values | Leather assets queries | Medium -- aggregate |
| `portfolio_get_collectibles` | List all collectibles/NFTs across chains | Leather collectibles queries | Medium -- aggregate |

#### Sub-phase 5C: Hardware Wallets (5 tools)
**Priority**: Lower -- Requires physical device access; useful for custody.
**Effort**: 2-3 weeks
**Dependencies**: Phase 1 (BTC PSBT), Phase 2 (STX signing)
**Special requirements**: `ledgercomm` or `ledgerwallet` Python library, USB access

| MCP Tool | Description | Source | Complexity |
|----------|-------------|--------|-----------|
| `ledger_get_addresses` | Get addresses from Ledger device | Xverse `ledger`, Leather Ledger | High -- USB HID |
| `ledger_sign_psbt` | Sign PSBT via Ledger | Xverse `ledger/btc.ts` | High -- device protocol |
| `ledger_sign_stx_transaction` | Sign STX transaction via Ledger | Xverse `ledger/stx.ts` | High -- device protocol |
| `keystone_get_addresses` | Get addresses from Keystone (QR-based) | Xverse `keystone` | Medium -- QR encode/decode |
| `keystone_sign_psbt` | Sign PSBT via Keystone | Xverse `keystone/btc.ts` | Medium -- QR encode/decode |

#### Sub-phase 5D: Inscription Creation & Onramp (4 tools)
**Priority**: Lower -- Niche features for creators and new users.
**Effort**: 1-2 weeks
**Dependencies**: Phase 1 (BTC transactions), Phase 3 (Ordinals)

| MCP Tool | Description | Source | Complexity |
|----------|-------------|--------|-----------|
| `ord_create_inscription` | Create a new inscription (text, image, etc.) | Xverse `createInscription` | High -- commit/reveal tx |
| `ord_create_repeat_inscriptions` | Create multiple inscriptions in batch | Xverse `createRepeatInscriptions` | High -- batch commit/reveal |
| `buy_get_providers` | List available fiat onramp providers | Xverse `onramper`, Leather fund | Low -- REST API |
| `buy_get_quote` | Get a fiat-to-crypto buy quote | Onramper API | Low -- REST API |

#### Recommended Sub-phase Execution Order

1. **5A** (Tx Management & Wallet) -- foundational, unblocks user workflows
2. **5B** (BNS & Market Data) -- high user value, straightforward APIs
3. **5D** (Inscriptions & Onramp) -- smaller scope, completes ordinals story
4. **5C** (Hardware Wallets) -- most complex, requires device access

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

| Phase | Priority | Business Value | Technical Complexity | Dependencies | Status |
|-------|----------|---------------|---------------------|--------------|--------|
| 1 | CRITICAL | High -- Core BTC operations | Medium | None | **DONE** |
| 2 | HIGH | High -- Stacks core | Medium-High | Phase 1 | **DONE** |
| 3 | HIGH | High -- Ordinals/inscriptions | Medium | Phase 1 | **DONE** |
| 4 | MEDIUM | Medium-High -- DeFi/swaps | High | Phase 1, 2 | **DONE** |
| 5A | MEDIUM | Medium -- Tx mgmt & wallet | Low-Medium | Phase 1-2 | Planned |
| 5B | MEDIUM | Medium -- Names & market data | Low-Medium | Phase 1-2 | Planned |
| 5C | LOWER | Lower -- Hardware wallets | High | Phase 1-2 | Planned |
| 5D | LOWER | Lower -- Inscriptions & onramp | Medium-High | Phase 1, 3 | Planned |

---

## Tool Count Summary

| Phase | Category | Tool Count | Status |
|-------|----------|------------|--------|
| 1 | Core Bitcoin | 19 | **DONE** |
| 2 | Stacks (STX) | 18 | **DONE** |
| 3 | Ordinals & Inscriptions | 7 | **DONE** |
| 4 | Swaps, DeFi, Bridge, Stacking | 10 | **DONE** |
| 5A | Tx Management & Wallet | 8 | Planned |
| 5B | BNS & Market Data | 8 | Planned |
| 5C | Hardware Wallets | 5 | Planned |
| 5D | Inscription Creation & Onramp | 4 | Planned |
| **Total** | | **79** | **54 done** |

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
| Ordinals/Inscriptions | **Yes** | Yes (view) | Yes (view + send + split) | 3 |
| Swaps | **Yes** | Yes (Alex, Bitflow, Velar) | Yes (multi-protocol) | 4 |
| sBTC Bridge | **Yes** | Yes | No | 4 |
| Stacking/Yield | **Yes** | Yes | Yes | 4 |
| RBF/Speed-up | No | No | Yes | 5 |
| Hardware Wallets | No | Yes (Ledger) | Yes (Ledger + Keystone) | 5 |
| BNS Names | No | Yes | No | 5 |
| Portfolio | No | Yes | Yes | 5 |
| Inscription Creation | No | No | Yes | 5 |
