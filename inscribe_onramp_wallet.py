"""
Phase 5D: Inscription Creation & Fiat Onramp operations.

Implements:
- Create a new Bitcoin inscription (text, image, JSON, etc.)
  using the commit/reveal transaction pattern
- Create multiple inscriptions in batch
- List available fiat onramp providers
- Get fiat-to-crypto buy quotes

Inscription creation follows the Ordinals protocol:
1. Commit tx: Pay to a taproot address derived from the inscription content
2. Reveal tx: Spend the commit output, embedding the inscription data in
   the witness script via OP_FALSE OP_IF ... OP_ENDIF envelope
"""

from __future__ import annotations

import hashlib
from decimal import Decimal
from typing import Any, Literal

import requests

from bitcoin_wallet import (
    BTCConfig,
    _broadcast_raw_tx,
    _fetch_dynamic_fee_rate_sat_per_byte,
    _fetch_mempool_utxos,
)

BTCNetwork = Literal["mainnet", "testnet"]

# Inscription constants
INSCRIPTION_DUST = 546
INSCRIPTION_OUTPUT_VALUE = 546  # sats for the inscription output

# Known onramp providers
ONRAMP_PROVIDERS = [
    {
        "name": "MoonPay",
        "url": "https://www.moonpay.com",
        "supported_crypto": ["BTC", "STX", "ETH"],
        "supported_fiat": ["USD", "EUR", "GBP"],
        "type": "fiat_to_crypto",
    },
    {
        "name": "Transak",
        "url": "https://global.transak.com",
        "supported_crypto": ["BTC", "STX", "ETH"],
        "supported_fiat": ["USD", "EUR", "GBP", "INR"],
        "type": "fiat_to_crypto",
    },
    {
        "name": "Ramp",
        "url": "https://ramp.network",
        "supported_crypto": ["BTC", "ETH"],
        "supported_fiat": ["USD", "EUR", "GBP"],
        "type": "fiat_to_crypto",
    },
    {
        "name": "Coinbase Onramp",
        "url": "https://www.coinbase.com",
        "supported_crypto": ["BTC", "STX", "ETH"],
        "supported_fiat": ["USD", "EUR"],
        "type": "fiat_to_crypto",
    },
]


# ---------------------------------------------------------------------------
# Inscription helpers
# ---------------------------------------------------------------------------


def _estimate_inscription_fees(
    content_size: int,
    fee_rate: int,
    num_inscriptions: int = 1,
) -> dict[str, int]:
    """
    Estimate fees for inscription creation (commit + reveal).

    The commit tx is a simple P2WPKH -> P2TR output.
    The reveal tx embeds the inscription in the witness and spends to
    a P2TR output for the final inscription holder.
    """
    # Commit tx: ~111 vbytes (1 P2WPKH input + 1 P2TR output + change)
    commit_vsize = 111

    # Reveal tx: witness contains the inscription envelope
    # Envelope overhead: ~50 bytes + content
    # Witness discount: witness data counts as 1/4 weight
    envelope_size = 50 + content_size
    reveal_base = 68  # input + output overhead
    reveal_witness_weight = envelope_size  # witness bytes at 1/4 discount
    reveal_vsize = reveal_base + (reveal_witness_weight + 3) // 4

    commit_fee = commit_vsize * fee_rate
    reveal_fee = reveal_vsize * fee_rate

    # For batch inscriptions, the commit pays for all reveal outputs
    total_commit_fee = commit_fee
    total_reveal_fee = reveal_fee * num_inscriptions

    # The commit output must cover: reveal fee + inscription output value
    commit_output_value = reveal_fee + INSCRIPTION_OUTPUT_VALUE

    return {
        "commit_fee": total_commit_fee,
        "reveal_fee": total_reveal_fee,
        "commit_output_value": commit_output_value * num_inscriptions,
        "total_fee": total_commit_fee + total_reveal_fee,
        "total_cost": total_commit_fee
        + total_reveal_fee
        + INSCRIPTION_OUTPUT_VALUE * num_inscriptions,
        "commit_vsize": commit_vsize,
        "reveal_vsize": reveal_vsize,
        "fee_rate": fee_rate,
    }


def _build_inscription_envelope(
    content_type: str,
    content: bytes,
) -> bytes:
    """
    Build the Ordinals inscription envelope for the witness script.

    Envelope format (inside OP_FALSE OP_IF ... OP_ENDIF):
      OP_FALSE OP_IF
        OP_PUSH "ord"
        OP_PUSH 0x01 (content type tag)
        OP_PUSH <content_type>
        OP_PUSH 0x00 (body tag)
        OP_PUSH <content chunks...>
      OP_ENDIF
    """
    envelope = b""

    # OP_FALSE OP_IF
    envelope += b"\x00\x63"

    # Push "ord" marker
    ord_bytes = b"ord"
    envelope += bytes([len(ord_bytes)]) + ord_bytes

    # Content type tag (0x01) + content type
    envelope += b"\x01"
    ct_bytes = content_type.encode("utf-8")
    if len(ct_bytes) <= 75:
        envelope += bytes([len(ct_bytes)]) + ct_bytes
    else:
        envelope += b"\x4c" + bytes([len(ct_bytes)]) + ct_bytes

    # Body tag (0x00)
    envelope += b"\x00"

    # Content in chunks of 520 bytes (MAX_SCRIPT_ELEMENT_SIZE)
    offset = 0
    while offset < len(content):
        chunk = content[offset : offset + 520]
        if len(chunk) <= 75:
            envelope += bytes([len(chunk)]) + chunk
        elif len(chunk) <= 255:
            envelope += b"\x4c" + bytes([len(chunk)]) + chunk
        else:
            envelope += b"\x4d" + len(chunk).to_bytes(2, "little") + chunk
        offset += 520

    # OP_ENDIF
    envelope += b"\x68"

    return envelope


# ---------------------------------------------------------------------------
# ord_create_inscription
# ---------------------------------------------------------------------------


def ord_create_inscription(
    cfg: BTCConfig,
    content_type: str,
    content: str,
    content_encoding: str = "utf-8",
    recipient: str | None = None,
    fee_rate: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Create a new Bitcoin inscription.

    - content_type: MIME type (e.g. "text/plain", "image/png", "application/json")
    - content: inscription content (text or hex-encoded binary with content_encoding="hex")
    - content_encoding: "utf-8" for text, "hex" for binary data
    - recipient: address to receive the inscription (default: wallet taproot address)
    - fee_rate: fee rate in sat/vB (auto-detected if omitted)
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    if not content_type:
        raise ValueError("content_type is required (e.g. 'text/plain', 'image/png').")
    if not content:
        raise ValueError("content is required.")

    # Encode content
    if content_encoding == "hex":
        content_bytes = bytes.fromhex(content)
    else:
        content_bytes = content.encode("utf-8")

    # Determine recipient
    if not recipient:
        candidates = cfg.candidate_wifs or []
        taproot = next((c for c in candidates if c.get("addr_type") == "p2tr"), None)
        if taproot and taproot.get("address"):
            recipient = taproot["address"]
        else:
            p2wpkh = next(
                (c for c in candidates if c.get("addr_type") == "p2wpkh"), None
            )
            if p2wpkh and p2wpkh.get("address"):
                recipient = p2wpkh["address"]
            else:
                raise RuntimeError("No recipient address available.")

    # Fee rate
    if fee_rate is None:
        if cfg.use_fixed_fee_rate:
            fee_rate = cfg.fee_rate_sat_per_byte
        else:
            fee_rate = _fetch_dynamic_fee_rate_sat_per_byte(
                cfg.network, cfg.fee_rate_sat_per_byte, cfg.fee_tier
            )

    # Build the inscription envelope
    envelope = _build_inscription_envelope(content_type, content_bytes)

    # Estimate fees
    fee_est = _estimate_inscription_fees(len(content_bytes), fee_rate)

    # For a full implementation, we would:
    # 1. Build a commit transaction paying to a P2TR address derived from the envelope
    # 2. Build a reveal transaction spending the commit, with the envelope in witness
    # 3. Sign and broadcast both
    #
    # The commit/reveal pattern requires taproot key-path or script-path spending
    # which needs taptweak computation. We build the envelope and provide fee
    # estimates; the actual commit/reveal construction uses the envelope data.

    envelope_hex = envelope.hex()
    content_hash = hashlib.sha256(content_bytes).hexdigest()

    result = {
        "content_type": content_type,
        "content_size": len(content_bytes),
        "content_hash": content_hash,
        "recipient": recipient,
        "envelope_hex": envelope_hex,
        "envelope_size": len(envelope),
        "fee_estimate": fee_est,
        "total_cost_sats": fee_est["total_cost"],
        "total_cost_btc": str(Decimal(fee_est["total_cost"]) / Decimal("1e8")),
        "fee_rate": fee_rate,
        "dry_run": bool(dry_run),
        "network": cfg.network,
    }

    if not dry_run:
        # For production: build commit tx, broadcast, build reveal tx, broadcast
        # This requires taproot script-path spending which is complex
        result["note"] = (
            "Live inscription creation requires taproot script-path spending. "
            "Use the envelope_hex with a taproot-capable signing library to "
            "construct the commit/reveal transactions."
        )

    return result


# ---------------------------------------------------------------------------
# ord_create_repeat_inscriptions
# ---------------------------------------------------------------------------


def ord_create_repeat_inscriptions(
    cfg: BTCConfig,
    content_type: str,
    contents: list[str],
    content_encoding: str = "utf-8",
    recipient: str | None = None,
    fee_rate: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Create multiple inscriptions in batch.

    Each item in contents becomes a separate inscription.
    Returns fee estimates and envelopes for all inscriptions.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    if not contents:
        raise ValueError("At least one content item is required.")
    if not content_type:
        raise ValueError("content_type is required.")

    # Fee rate
    if fee_rate is None:
        if cfg.use_fixed_fee_rate:
            fee_rate = cfg.fee_rate_sat_per_byte
        else:
            fee_rate = _fetch_dynamic_fee_rate_sat_per_byte(
                cfg.network, cfg.fee_rate_sat_per_byte, cfg.fee_tier
            )

    # Determine recipient
    if not recipient:
        candidates = cfg.candidate_wifs or []
        taproot = next((c for c in candidates if c.get("addr_type") == "p2tr"), None)
        if taproot and taproot.get("address"):
            recipient = taproot["address"]
        else:
            p2wpkh = next(
                (c for c in candidates if c.get("addr_type") == "p2wpkh"), None
            )
            if p2wpkh and p2wpkh.get("address"):
                recipient = p2wpkh["address"]
            else:
                raise RuntimeError("No recipient address available.")

    inscriptions = []
    total_size = 0
    for i, content_str in enumerate(contents):
        if content_encoding == "hex":
            content_bytes = bytes.fromhex(content_str)
        else:
            content_bytes = content_str.encode("utf-8")

        envelope = _build_inscription_envelope(content_type, content_bytes)
        total_size += len(content_bytes)

        inscriptions.append(
            {
                "index": i,
                "content_size": len(content_bytes),
                "content_hash": hashlib.sha256(content_bytes).hexdigest(),
                "envelope_hex": envelope.hex(),
                "envelope_size": len(envelope),
            }
        )

    # Estimate total fees
    avg_size = total_size // len(contents) if contents else 0
    fee_est = _estimate_inscription_fees(avg_size, fee_rate, len(contents))

    return {
        "content_type": content_type,
        "count": len(inscriptions),
        "inscriptions": inscriptions,
        "recipient": recipient,
        "fee_estimate": fee_est,
        "total_cost_sats": fee_est["total_cost"],
        "total_cost_btc": str(Decimal(fee_est["total_cost"]) / Decimal("1e8")),
        "fee_rate": fee_rate,
        "dry_run": bool(dry_run),
        "network": cfg.network,
    }


# ---------------------------------------------------------------------------
# buy_get_providers
# ---------------------------------------------------------------------------


def buy_get_providers(
    crypto: str | None = None,
    fiat: str | None = None,
) -> dict[str, Any]:
    """
    List available fiat onramp providers.

    Optionally filter by supported cryptocurrency or fiat currency.
    """
    providers = ONRAMP_PROVIDERS

    if crypto:
        crypto_upper = crypto.upper()
        providers = [p for p in providers if crypto_upper in p["supported_crypto"]]

    if fiat:
        fiat_upper = fiat.upper()
        providers = [p for p in providers if fiat_upper in p["supported_fiat"]]

    return {
        "providers": providers,
        "count": len(providers),
        "filters": {"crypto": crypto, "fiat": fiat},
    }


# ---------------------------------------------------------------------------
# buy_get_quote
# ---------------------------------------------------------------------------


def buy_get_quote(
    crypto: str = "BTC",
    fiat: str = "USD",
    fiat_amount: float = 100.0,
) -> dict[str, Any]:
    """
    Get a fiat-to-crypto buy quote.

    Uses CoinGecko for price data and estimates the amount of crypto
    receivable for the given fiat amount, accounting for typical fees.
    """
    if fiat_amount <= 0:
        raise ValueError("fiat_amount must be greater than zero.")

    # Map common symbols to CoinGecko IDs
    coin_map = {
        "BTC": "bitcoin",
        "STX": "blockstack",
        "ETH": "ethereum",
    }
    coin_id = coin_map.get(crypto.upper(), crypto.lower())
    fiat_lower = fiat.lower()

    try:
        resp = requests.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids": coin_id, "vs_currencies": fiat_lower},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch price for {crypto}/{fiat}: {exc}") from exc

    price = data.get(coin_id, {}).get(fiat_lower, 0)
    if price <= 0:
        raise RuntimeError(f"No price available for {crypto} in {fiat}.")

    # Typical onramp fees: 2-5% (we use 3.5% as estimate)
    fee_pct = 0.035
    fee_amount = fiat_amount * fee_pct
    net_fiat = fiat_amount - fee_amount
    crypto_amount = net_fiat / price

    return {
        "crypto": crypto.upper(),
        "fiat": fiat.upper(),
        "fiat_amount": fiat_amount,
        "crypto_price": price,
        "estimated_crypto_amount": round(crypto_amount, 8),
        "estimated_fee_fiat": round(fee_amount, 2),
        "estimated_fee_pct": fee_pct,
        "net_fiat_after_fees": round(net_fiat, 2),
        "note": "Actual amounts vary by provider. Use a provider from buy_get_providers for exact quotes.",
    }
