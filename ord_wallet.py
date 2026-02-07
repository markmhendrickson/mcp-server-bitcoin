"""
Ordinals & Inscriptions wallet operations for Phase 3 MCP support.

Implements:
- Inscription queries via Hiro Ordinals API
- Inscription detail lookup
- Send inscriptions (full UTXO transfer)
- Send inscriptions with UTXO splitting (preserve sat ranges)
- Extract ordinals from mixed UTXOs
- Recover BTC from ordinals address
- Recover ordinals from payment address

Ordinals live on the Bitcoin layer. Inscriptions are typically held in
taproot (P2TR) UTXOs, but can also be in P2WPKH UTXOs. Sending an
inscription means sending the entire UTXO containing it (or splitting
the UTXO to isolate the inscription's sat range).
"""

from __future__ import annotations

import hashlib
from decimal import Decimal
from typing import Any, Literal

import requests

from btc_wallet import (
    BTCConfig,
    _build_native_segwit_tx_multi,
    _build_unspent_list,
    _broadcast_raw_tx,
    _fetch_dynamic_fee_rate_sat_per_byte,
    _fetch_mempool_utxos,
    _make_key_from_wif,
)

BTCNetwork = Literal["mainnet", "testnet"]

HIRO_ORDINALS_MAINNET = "https://api.hiro.so"
HIRO_ORDINALS_TESTNET = "https://api.testnet.hiro.so"

# Dust threshold for inscription UTXOs
INSCRIPTION_DUST = 546


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------


def _ordinals_api_url(network: BTCNetwork) -> str:
    if network == "mainnet":
        return HIRO_ORDINALS_MAINNET
    return HIRO_ORDINALS_TESTNET


def _ord_get(network: BTCNetwork, path: str, params: dict | None = None) -> Any:
    """GET request to Hiro Ordinals API."""
    url = f"{_ordinals_api_url(network)}{path}"
    resp = requests.get(url, params=params, timeout=10)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------


def _get_ordinals_address(cfg: BTCConfig) -> str:
    """
    Get the ordinals (taproot) address from the wallet config.

    Ordinals are typically held on the taproot (P2TR) address.
    Falls back to P2WPKH if no taproot address is available.
    """
    candidates = cfg.candidate_wifs or []
    taproot = next((c for c in candidates if c.get("addr_type") == "p2tr"), None)
    if taproot and taproot.get("address"):
        return taproot["address"]
    # Fall back to p2wpkh
    p2wpkh = next((c for c in candidates if c.get("addr_type") == "p2wpkh"), None)
    if p2wpkh and p2wpkh.get("address"):
        return p2wpkh["address"]
    if candidates and candidates[0].get("address"):
        return candidates[0]["address"]
    raise RuntimeError("No address available for ordinals queries.")


def _get_payment_address(cfg: BTCConfig) -> str:
    """Get the primary payment (P2WPKH) address."""
    candidates = cfg.candidate_wifs or []
    p2wpkh = next((c for c in candidates if c.get("addr_type") == "p2wpkh"), None)
    if p2wpkh and p2wpkh.get("address"):
        return p2wpkh["address"]
    if candidates and candidates[0].get("address"):
        return candidates[0]["address"]
    raise RuntimeError("No payment address available.")


# ---------------------------------------------------------------------------
# 3.1 Inscription queries
# ---------------------------------------------------------------------------


def ord_get_inscriptions(
    cfg: BTCConfig,
    offset: int = 0,
    limit: int = 20,
    address: str | None = None,
) -> dict[str, Any]:
    """
    List inscriptions owned by a wallet address with pagination.

    Matches Xverse ``ord_getInscriptions``.
    Uses the Hiro Ordinals API.
    """
    addr = address or _get_ordinals_address(cfg)
    if limit > 60:
        limit = 60

    try:
        data = _ord_get(
            cfg.network,
            "/ordinals/v1/inscriptions",
            params={"address": addr, "offset": offset, "limit": limit},
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch inscriptions for {addr}: {exc}") from exc

    results = data.get("results", [])
    inscriptions = []
    for r in results:
        inscriptions.append({
            "inscriptionId": r.get("id", ""),
            "inscriptionNumber": str(r.get("number", "")),
            "address": r.get("address", ""),
            "contentType": r.get("content_type", ""),
            "contentLength": r.get("content_length", 0),
            "mimeType": r.get("mime_type", ""),
            "genesisTransaction": r.get("genesis_tx_id", ""),
            "location": r.get("location", ""),
            "output": r.get("output", ""),
            "offset": r.get("offset", "0"),
            "value": r.get("value", "0"),
            "satOrdinal": r.get("sat_ordinal", ""),
            "satRarity": r.get("sat_rarity", "common"),
            "timestamp": r.get("timestamp", 0),
        })

    return {
        "total": data.get("total", 0),
        "limit": limit,
        "offset": offset,
        "inscriptions": inscriptions,
        "address": addr,
        "network": cfg.network,
    }


def ord_get_inscription_details(
    cfg: BTCConfig,
    inscription_id: str,
) -> dict[str, Any]:
    """
    Get detailed information for a specific inscription by ID.

    inscription_id: e.g. "abc123...i0"
    """
    try:
        r = _ord_get(cfg.network, f"/ordinals/v1/inscriptions/{inscription_id}")
    except Exception as exc:
        raise RuntimeError(
            f"Failed to fetch inscription {inscription_id}: {exc}"
        ) from exc

    return {
        "inscriptionId": r.get("id", ""),
        "inscriptionNumber": r.get("number"),
        "address": r.get("address", ""),
        "genesisAddress": r.get("genesis_address", ""),
        "genesisBlockHeight": r.get("genesis_block_height"),
        "genesisBlockHash": r.get("genesis_block_hash", ""),
        "genesisTxId": r.get("genesis_tx_id", ""),
        "genesisFee": r.get("genesis_fee", ""),
        "genesisTimestamp": r.get("genesis_timestamp"),
        "txId": r.get("tx_id", ""),
        "location": r.get("location", ""),
        "output": r.get("output", ""),
        "value": r.get("value", "0"),
        "offset": r.get("offset", "0"),
        "satOrdinal": r.get("sat_ordinal", ""),
        "satRarity": r.get("sat_rarity", "common"),
        "satCoinbaseHeight": r.get("sat_coinbase_height"),
        "mimeType": r.get("mime_type", ""),
        "contentType": r.get("content_type", ""),
        "contentLength": r.get("content_length", 0),
        "timestamp": r.get("timestamp", 0),
        "recursive": r.get("recursive", False),
        "curseType": r.get("curse_type"),
        "network": cfg.network,
    }


# ---------------------------------------------------------------------------
# 3.2 Send inscriptions
# ---------------------------------------------------------------------------


def _find_inscription_utxo(
    cfg: BTCConfig,
    inscription_id: str,
) -> dict[str, Any]:
    """
    Find the UTXO containing a specific inscription.

    Returns dict with outpoint info from the inscription's location.
    """
    details = ord_get_inscription_details(cfg, inscription_id)
    output = details.get("output", "")
    if not output or ":" not in output:
        raise RuntimeError(f"Cannot determine UTXO for inscription {inscription_id}")

    parts = output.split(":")
    txid = parts[0]
    vout = int(parts[1])
    value = int(details.get("value", 0))
    offset = int(details.get("offset", 0))

    return {
        "txid": txid,
        "vout": vout,
        "value": value,
        "offset": offset,
        "inscription_id": inscription_id,
        "address": details.get("address", ""),
    }


def ord_send_inscriptions(
    cfg: BTCConfig,
    transfers: list[dict[str, str]],
    fee_rate: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Send inscriptions to recipients. Each transfer sends the full UTXO.

    transfers: list of {"address": str, "inscriptionId": str}

    Matches Xverse ``ord_sendInscriptions`` / ``sendOrdinals``.
    This sends the entire UTXO containing the inscription to the recipient.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    if not transfers:
        raise ValueError("At least one transfer is required.")

    # Resolve fee rate
    if fee_rate is None:
        if cfg.use_fixed_fee_rate:
            fee_rate = cfg.fee_rate_sat_per_byte
        else:
            fee_rate = _fetch_dynamic_fee_rate_sat_per_byte(
                cfg.network, cfg.fee_rate_sat_per_byte, cfg.fee_tier
            )

    # Look up each inscription's UTXO
    inscription_utxos = []
    for t in transfers:
        iid = t.get("inscriptionId", "")
        if not iid:
            raise ValueError("Each transfer must have an 'inscriptionId'.")
        utxo_info = _find_inscription_utxo(cfg, iid)
        utxo_info["to_address"] = t.get("address", "")
        if not utxo_info["to_address"]:
            raise ValueError(f"Missing 'address' for inscription {iid}.")
        inscription_utxos.append(utxo_info)

    # Build the transaction: each inscription UTXO becomes an input,
    # and each recipient gets a corresponding output.
    # We also need a payment UTXO for fees.
    payment_address = _get_payment_address(cfg)
    payment_utxos = _fetch_mempool_utxos(payment_address, cfg.network)

    # Calculate fee
    num_inputs = len(inscription_utxos) + 1  # inscription inputs + 1 fee input
    num_outputs = len(inscription_utxos) + 1  # recipient outputs + change
    estimated_vsize = 11 + num_inputs * 68 + num_outputs * 34  # segwit estimate
    fee_sats = estimated_vsize * fee_rate

    # Find a payment UTXO to cover fees
    # Exclude UTXOs that are inscription UTXOs
    inscription_outpoints = {
        f"{u['txid']}:{u['vout']}" for u in inscription_utxos
    }
    available_payment = [
        u for u in payment_utxos
        if f"{u.get('txid', '')}:{u.get('vout', 0)}" not in inscription_outpoints
    ]
    available_payment.sort(key=lambda u: int(u.get("value", 0)), reverse=True)

    if not available_payment:
        raise RuntimeError("No payment UTXOs available to cover fees.")

    fee_utxo = available_payment[0]
    fee_utxo_value = int(fee_utxo.get("value", 0))
    if fee_utxo_value < fee_sats:
        raise RuntimeError(
            f"Largest payment UTXO ({fee_utxo_value} sats) insufficient for fee ({fee_sats} sats)."
        )

    change_sats = fee_utxo_value - fee_sats

    # Build recipients list for the multi-output transaction
    recipients = []
    for u in inscription_utxos:
        recipients.append({
            "address": u["to_address"],
            "amount_sats": u["value"],
        })
    # Change output
    if change_sats > INSCRIPTION_DUST:
        recipients.append({
            "address": payment_address,
            "amount_sats": change_sats,
        })

    # Combine all inputs: inscription UTXOs + fee UTXO
    all_utxos = []
    for u in inscription_utxos:
        all_utxos.append({
            "txid": u["txid"],
            "vout": u["vout"],
            "value": u["value"],
        })
    all_utxos.append({
        "txid": fee_utxo.get("txid", ""),
        "vout": fee_utxo.get("vout", 0),
        "value": fee_utxo_value,
    })

    # Build and sign using P2WPKH (payment key handles fee input;
    # inscription inputs are passed through)
    p2wpkh_candidate = next(
        (c for c in (cfg.candidate_wifs or []) if c.get("addr_type") == "p2wpkh"),
        None,
    )
    if not p2wpkh_candidate:
        raise RuntimeError("No P2WPKH key available for signing.")

    raw_hex = _build_native_segwit_tx_multi(
        wif=p2wpkh_candidate["wif"],
        utxos=all_utxos,
        recipients=recipients,
        fee_sats=0,  # fee already subtracted from change
        change_address=payment_address,
        network=cfg.network,
    )

    if dry_run:
        tx_bytes = bytes.fromhex(raw_hex) if isinstance(raw_hex, str) else raw_hex
        fake_txid = hashlib.sha256(tx_bytes).hexdigest()
        txid = f"DRYRUN_{fake_txid[:64]}"
    else:
        txid = _broadcast_raw_tx(raw_hex, cfg.network)

    return {
        "txid": txid,
        "transfers": [
            {"inscriptionId": u["inscription_id"], "toAddress": u["to_address"]}
            for u in inscription_utxos
        ],
        "fee_sats": fee_sats,
        "dry_run": bool(dry_run),
        "network": cfg.network,
    }


def ord_send_inscriptions_split(
    cfg: BTCConfig,
    transfers: list[dict[str, str]],
    fee_rate: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Send inscriptions with UTXO splitting to preserve sat ranges.

    When an inscription sits inside a large UTXO (e.g. 10,000 sats) at
    a specific offset, this splits the UTXO so the inscription's sat
    range goes to the recipient and the remainder returns to the sender.

    transfers: list of {"address": str, "inscriptionId": str}

    Matches Xverse ``sendOrdinalsWithSplit``.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    if not transfers:
        raise ValueError("At least one transfer is required.")

    if fee_rate is None:
        if cfg.use_fixed_fee_rate:
            fee_rate = cfg.fee_rate_sat_per_byte
        else:
            fee_rate = _fetch_dynamic_fee_rate_sat_per_byte(
                cfg.network, cfg.fee_rate_sat_per_byte, cfg.fee_tier
            )

    # Look up each inscription
    inscription_utxos = []
    for t in transfers:
        iid = t.get("inscriptionId", "")
        if not iid:
            raise ValueError("Each transfer must have an 'inscriptionId'.")
        utxo_info = _find_inscription_utxo(cfg, iid)
        utxo_info["to_address"] = t.get("address", "")
        if not utxo_info["to_address"]:
            raise ValueError(f"Missing 'address' for inscription {iid}.")
        inscription_utxos.append(utxo_info)

    ordinals_address = _get_ordinals_address(cfg)
    payment_address = _get_payment_address(cfg)

    # For each inscription UTXO, decide whether to split or send whole
    recipients = []
    input_utxos = []
    split_details = []

    for u in inscription_utxos:
        utxo_value = u["value"]
        offset = u["offset"]
        inscription_size = max(INSCRIPTION_DUST, 546)

        # If the UTXO is small enough (near dust), send the whole thing
        if utxo_value <= inscription_size + INSCRIPTION_DUST:
            recipients.append({
                "address": u["to_address"],
                "amount_sats": utxo_value,
            })
            input_utxos.append({
                "txid": u["txid"],
                "vout": u["vout"],
                "value": utxo_value,
            })
            split_details.append({
                "inscriptionId": u["inscription_id"],
                "split": False,
                "sentValue": utxo_value,
            })
        else:
            # Split: send inscription range to recipient, rest back to sender
            # The inscription sits at 'offset' within the UTXO
            before_sats = offset
            inscription_sats = inscription_size
            after_sats = utxo_value - offset - inscription_sats

            # Inscription output to recipient
            recipients.append({
                "address": u["to_address"],
                "amount_sats": inscription_sats,
            })

            # Return portions before and after the inscription to ordinals address
            if before_sats > INSCRIPTION_DUST:
                recipients.append({
                    "address": ordinals_address,
                    "amount_sats": before_sats,
                })
            if after_sats > INSCRIPTION_DUST:
                recipients.append({
                    "address": ordinals_address,
                    "amount_sats": after_sats,
                })

            input_utxos.append({
                "txid": u["txid"],
                "vout": u["vout"],
                "value": utxo_value,
            })
            split_details.append({
                "inscriptionId": u["inscription_id"],
                "split": True,
                "sentValue": inscription_sats,
                "returnedBefore": before_sats if before_sats > INSCRIPTION_DUST else 0,
                "returnedAfter": after_sats if after_sats > INSCRIPTION_DUST else 0,
            })

    # Add payment UTXO for fees
    payment_utxos = _fetch_mempool_utxos(payment_address, cfg.network)
    input_outpoints = {f"{u['txid']}:{u['vout']}" for u in input_utxos}
    available_payment = [
        u for u in payment_utxos
        if f"{u.get('txid', '')}:{u.get('vout', 0)}" not in input_outpoints
    ]
    available_payment.sort(key=lambda u: int(u.get("value", 0)), reverse=True)

    num_inputs = len(input_utxos) + 1
    num_outputs = len(recipients) + 1  # +1 for fee change
    estimated_vsize = 11 + num_inputs * 68 + num_outputs * 34
    fee_sats = estimated_vsize * fee_rate

    if not available_payment:
        raise RuntimeError("No payment UTXOs available to cover fees.")

    fee_utxo = available_payment[0]
    fee_utxo_value = int(fee_utxo.get("value", 0))
    if fee_utxo_value < fee_sats:
        raise RuntimeError(
            f"Payment UTXO ({fee_utxo_value} sats) insufficient for fee ({fee_sats} sats)."
        )

    change_sats = fee_utxo_value - fee_sats
    if change_sats > INSCRIPTION_DUST:
        recipients.append({
            "address": payment_address,
            "amount_sats": change_sats,
        })

    input_utxos.append({
        "txid": fee_utxo.get("txid", ""),
        "vout": fee_utxo.get("vout", 0),
        "value": fee_utxo_value,
    })

    # Build transaction
    p2wpkh_candidate = next(
        (c for c in (cfg.candidate_wifs or []) if c.get("addr_type") == "p2wpkh"),
        None,
    )
    if not p2wpkh_candidate:
        raise RuntimeError("No P2WPKH key available for signing.")

    raw_hex = _build_native_segwit_tx_multi(
        wif=p2wpkh_candidate["wif"],
        utxos=input_utxos,
        recipients=recipients,
        fee_sats=0,
        change_address=payment_address,
        network=cfg.network,
    )

    if dry_run:
        tx_bytes = bytes.fromhex(raw_hex) if isinstance(raw_hex, str) else raw_hex
        fake_txid = hashlib.sha256(tx_bytes).hexdigest()
        txid = f"DRYRUN_{fake_txid[:64]}"
    else:
        txid = _broadcast_raw_tx(raw_hex, cfg.network)

    return {
        "txid": txid,
        "splits": split_details,
        "fee_sats": fee_sats,
        "dry_run": bool(dry_run),
        "network": cfg.network,
    }


# ---------------------------------------------------------------------------
# 3.3 Extract & Recover
# ---------------------------------------------------------------------------


def ord_extract_from_utxo(
    cfg: BTCConfig,
    outpoint: str,
    fee_rate: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Extract ordinals/inscriptions from a mixed UTXO.

    Queries the UTXO for any inscriptions, then moves them to
    individual outputs at the ordinals address.

    outpoint: "txid:vout" format

    Matches Xverse ``extractOrdinalsFromUtxo``.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    parts = outpoint.split(":")
    if len(parts) != 2:
        raise ValueError("outpoint must be in 'txid:vout' format.")
    txid = parts[0]
    vout = int(parts[1])

    ordinals_address = _get_ordinals_address(cfg)

    # Find inscriptions in this UTXO via the output
    try:
        data = _ord_get(
            cfg.network,
            "/ordinals/v1/inscriptions",
            params={"output": outpoint, "limit": 60},
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to query inscriptions for {outpoint}: {exc}") from exc

    inscriptions = data.get("results", [])
    if not inscriptions:
        return {
            "message": "No inscriptions found in this UTXO.",
            "outpoint": outpoint,
            "network": cfg.network,
        }

    # Build transfers to send each inscription to the ordinals address
    transfers = [
        {"inscriptionId": i.get("id", ""), "address": ordinals_address}
        for i in inscriptions
        if i.get("id")
    ]

    if not transfers:
        return {
            "message": "No extractable inscriptions found.",
            "outpoint": outpoint,
            "network": cfg.network,
        }

    # Use split sending to isolate each inscription
    result = ord_send_inscriptions_split(cfg, transfers, fee_rate, dry_run)
    result["extracted_count"] = len(transfers)
    result["outpoint"] = outpoint
    return result


def ord_recover_bitcoin(
    cfg: BTCConfig,
    outpoint: str | None = None,
    fee_rate: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Recover BTC trapped in the ordinals (taproot) address.

    Finds UTXOs on the ordinals address that do NOT contain inscriptions,
    and sweeps them to the payment address.

    If outpoint is provided, recovers just that specific UTXO.

    Matches Xverse ``recoverBitcoin``.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    ordinals_address = _get_ordinals_address(cfg)
    payment_address = _get_payment_address(cfg)

    if ordinals_address == payment_address:
        raise RuntimeError("Ordinals and payment addresses are the same -- nothing to recover.")

    if fee_rate is None:
        if cfg.use_fixed_fee_rate:
            fee_rate = cfg.fee_rate_sat_per_byte
        else:
            fee_rate = _fetch_dynamic_fee_rate_sat_per_byte(
                cfg.network, cfg.fee_rate_sat_per_byte, cfg.fee_tier
            )

    # Get all UTXOs on the ordinals address
    all_utxos = _fetch_mempool_utxos(ordinals_address, cfg.network)
    if not all_utxos:
        raise RuntimeError("No UTXOs found on ordinals address.")

    if outpoint:
        # Recover a specific UTXO
        parts = outpoint.split(":")
        target_utxos = [
            u for u in all_utxos
            if str(u.get("txid", "")) == parts[0] and int(u.get("vout", -1)) == int(parts[1])
        ]
        if not target_utxos:
            raise RuntimeError(f"UTXO {outpoint} not found on ordinals address.")
        recoverable = target_utxos
    else:
        # Find UTXOs without inscriptions
        recoverable = []
        for u in all_utxos:
            op = f"{u.get('txid', '')}:{u.get('vout', 0)}"
            try:
                data = _ord_get(
                    cfg.network,
                    "/ordinals/v1/inscriptions",
                    params={"output": op, "limit": 1},
                )
                if data.get("total", 0) == 0:
                    recoverable.append(u)
            except Exception:
                # If we can't check, skip it to be safe
                continue

    if not recoverable:
        raise RuntimeError("No recoverable (non-inscription) UTXOs found on ordinals address.")

    total_sats = sum(int(u.get("value", 0)) for u in recoverable)
    num_inputs = len(recoverable)
    estimated_vsize = 11 + num_inputs * 68 + 1 * 34  # 1 output (sweep)
    fee_sats = estimated_vsize * fee_rate
    send_sats = total_sats - fee_sats

    if send_sats <= INSCRIPTION_DUST:
        raise RuntimeError(
            f"After fees ({fee_sats} sats), remaining ({send_sats} sats) is below dust."
        )

    # Build the sweep transaction
    p2wpkh_candidate = next(
        (c for c in (cfg.candidate_wifs or []) if c.get("addr_type") == "p2wpkh"),
        None,
    )
    if not p2wpkh_candidate:
        raise RuntimeError("No P2WPKH key available for signing.")

    input_utxos = [
        {"txid": u.get("txid", ""), "vout": u.get("vout", 0), "value": int(u.get("value", 0))}
        for u in recoverable
    ]

    raw_hex = _build_native_segwit_tx_multi(
        wif=p2wpkh_candidate["wif"],
        utxos=input_utxos,
        recipients=[{"address": payment_address, "amount_sats": send_sats}],
        fee_sats=0,
        change_address=payment_address,
        network=cfg.network,
    )

    if dry_run:
        tx_bytes = bytes.fromhex(raw_hex) if isinstance(raw_hex, str) else raw_hex
        fake_txid = hashlib.sha256(tx_bytes).hexdigest()
        txid = f"DRYRUN_{fake_txid[:64]}"
    else:
        txid = _broadcast_raw_tx(raw_hex, cfg.network)

    return {
        "txid": txid,
        "recovered_sats": send_sats,
        "recovered_btc": str(Decimal(send_sats) / Decimal("1e8")),
        "fee_sats": fee_sats,
        "utxo_count": len(recoverable),
        "from_address": ordinals_address,
        "to_address": payment_address,
        "dry_run": bool(dry_run),
        "network": cfg.network,
    }


def ord_recover_ordinals(
    cfg: BTCConfig,
    outpoint: str | None = None,
    fee_rate: int | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """
    Recover ordinals/inscriptions that ended up on the payment address.

    Finds UTXOs on the payment address that contain inscriptions,
    and moves them to the ordinals (taproot) address.

    Matches Xverse ``recoverOrdinal``.
    """
    if dry_run is None:
        dry_run = cfg.dry_run_default

    ordinals_address = _get_ordinals_address(cfg)
    payment_address = _get_payment_address(cfg)

    if ordinals_address == payment_address:
        raise RuntimeError("Ordinals and payment addresses are the same -- nothing to recover.")

    # Get UTXOs on payment address
    all_utxos = _fetch_mempool_utxos(payment_address, cfg.network)
    if not all_utxos:
        raise RuntimeError("No UTXOs found on payment address.")

    if outpoint:
        parts = outpoint.split(":")
        target_utxos = [
            u for u in all_utxos
            if str(u.get("txid", "")) == parts[0] and int(u.get("vout", -1)) == int(parts[1])
        ]
        if not target_utxos:
            raise RuntimeError(f"UTXO {outpoint} not found on payment address.")
        candidates = target_utxos
    else:
        candidates = all_utxos

    # Find UTXOs that contain inscriptions
    inscription_utxos = []
    for u in candidates:
        op = f"{u.get('txid', '')}:{u.get('vout', 0)}"
        try:
            data = _ord_get(
                cfg.network,
                "/ordinals/v1/inscriptions",
                params={"output": op, "limit": 1},
            )
            if data.get("total", 0) > 0:
                inscription_utxos.append(u)
        except Exception:
            continue

    if not inscription_utxos:
        raise RuntimeError("No inscription-bearing UTXOs found on payment address.")

    # Build transfers to move each inscription UTXO to the ordinals address
    transfers = []
    for u in inscription_utxos:
        op = f"{u.get('txid', '')}:{u.get('vout', 0)}"
        try:
            data = _ord_get(
                cfg.network,
                "/ordinals/v1/inscriptions",
                params={"output": op, "limit": 60},
            )
            for r in data.get("results", []):
                iid = r.get("id", "")
                if iid:
                    transfers.append({
                        "inscriptionId": iid,
                        "address": ordinals_address,
                    })
        except Exception:
            continue

    if not transfers:
        raise RuntimeError("Could not resolve inscriptions to recover.")

    result = ord_send_inscriptions(cfg, transfers, fee_rate, dry_run)
    result["recovered_count"] = len(transfers)
    result["from_address"] = payment_address
    result["to_address"] = ordinals_address
    return result
