"""Request/response pairing for Modbus TCP and RTU traces.

TCP and RTU intentionally use different, explicit rules:

* TCP: same connection generation and (transaction id, unit id, function).
* RTU: no transaction id; chronological outstanding transaction with the RTU
  silent interval closing transactions.
* Unit id 0 RTU requests are broadcasts and close as accepted no-response.
* Exception responses pair but are never converted into successful data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .identity import stable_id
from .importer import ConnectionSpan
from .model import (BROADCAST_UNIT, RESULT_ACCEPTED, RESULT_AMBIGUOUS,
                    RESULT_REJECTED, RESULT_UNMATCHED)
from .modbus import Frame
from .parameters import (RULE_BROADCAST, RULE_EXCEPTION, RULE_RTU_SILENCE,
                         RULE_TCP_TRANSACTION, ParameterVersion)


@dataclass
class PairCandidate:
    request_id: str
    score: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"request_id": self.request_id, "score": self.score,
                "reason": self.reason}


@dataclass
class PairRecord:
    pair_id: str
    transport: str
    channel: str
    connection_id: str | None
    generation: int | None
    request_id: str
    response_id: str | None
    unit_id: int | None
    function: int
    transaction_id: int | None
    status: str
    is_broadcast: bool
    is_exception: bool
    exception_code: int | None
    request_ns: int
    response_ns: int | None
    turnaround_ms: float | None
    retransmissions: list[str] = field(default_factory=list)
    candidates: list[PairCandidate] = field(default_factory=list)
    unmatched_reason: str = ""
    rule_ids: list[str] = field(default_factory=list)
    sequence: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "pair_id": self.pair_id,
            "transport": self.transport,
            "channel": self.channel,
            "connection_id": self.connection_id,
            "generation": self.generation,
            "request_id": self.request_id,
            "response_id": self.response_id,
            "unit_id": self.unit_id,
            "function": self.function,
            "transaction_id": self.transaction_id,
            "status": self.status,
            "is_broadcast": self.is_broadcast,
            "is_exception": self.is_exception,
            "exception_code": self.exception_code,
            "request_ns": self.request_ns,
            "response_ns": self.response_ns,
            "turnaround_ms": self.turnaround_ms,
            "retransmissions": self.retransmissions,
            "candidates": [c.as_dict() for c in self.candidates],
            "unmatched_reason": self.unmatched_reason,
            "rule_ids": self.rule_ids,
            "sequence": self.sequence,
        }


def _connection_for(frame: Frame, connections: list[ConnectionSpan]):
    explicit = frame.extra.get("connection_id")
    if explicit:
        for span in connections:
            if span.connection_id == explicit:
                return span
    channel = frame.extra.get("channel", "")
    matches = [
        span for span in connections
        if span.channel == channel
        and span.opened_ns <= frame.timestamp_ns
        and (span.closed_ns is None or span.closed_ns >= frame.timestamp_ns)
    ]
    if matches:
        return sorted(matches, key=lambda s: (s.opened_ns, s.open_line))[-1]
    return None


def _make_pair_id(transport: str, channel: str, request: Frame,
                  response: Frame | None, generation: int | None) -> str:
    return stable_id(
        "pair", transport, channel, generation,
        request.frame_id,
        response.frame_id if response else "no-response",
        request.transaction_id if transport == "tcp" else None,
    )


def _pair_tcp(frames: list[Frame], connections: list[ConnectionSpan]):
    pairs: list[PairRecord] = []
    unmatched_responses: list[dict[str, Any]] = []
    sequence = 0
    by_channel: dict[str, list[Frame]] = {}
    for frame in frames:
        if frame.transport != "tcp" or not frame.pdu:
            continue
        by_channel.setdefault(frame.extra.get("channel", ""), []).append(frame)

    for channel, channel_frames in by_channel.items():
        ordered = sorted(channel_frames, key=lambda f: (f.timestamp_ns, f.line))
        open_by_key: dict[tuple[int, int, int], PairRecord] = {}
        pair_by_request: dict[str, PairRecord] = {}
        for frame in ordered:
            span = _connection_for(frame, connections)
            generation = span.generation if span else frame.extra.get("generation")
            connection_id = span.connection_id if span else frame.extra.get(
                "connection_id")
            pdu = frame.pdu
            key = (frame.transaction_id or 0, frame.unit_id or 0, pdu.function)
            if frame.direction == "request":
                existing = open_by_key.get(key)
                if existing is not None and existing.generation == generation:
                    # Same (tid, unit, function) before prior close is a
                    # transaction id reuse collision. Keep both legal requests.
                    existing.status = RESULT_AMBIGUOUS
                    existing.unmatched_reason = (
                        "tcp_transaction_id_reused_in_flight")
                    existing.rule_ids.append(RULE_TCP_TRANSACTION)
                    existing.candidates.append(PairCandidate(
                        frame.frame_id, "collision",
                        "later request reused the same open transaction id"))
                    collision = PairRecord(
                        pair_id=_make_pair_id("tcp", channel, frame, None,
                                              generation),
                        transport="tcp", channel=channel,
                        connection_id=connection_id, generation=generation,
                        request_id=frame.frame_id, response_id=None,
                        unit_id=frame.unit_id, function=pdu.function,
                        transaction_id=frame.transaction_id,
                        status=RESULT_AMBIGUOUS, is_broadcast=False,
                        is_exception=False, exception_code=None,
                        request_ns=frame.timestamp_ns, response_ns=None,
                        turnaround_ms=None,
                        unmatched_reason=(
                            "tcp_transaction_id_reused_in_flight"),
                        rule_ids=[RULE_TCP_TRANSACTION],
                        candidates=[PairCandidate(
                            existing.request_id, "collision",
                            "earlier request still held the transaction id")],
                        sequence=sequence)
                    sequence += 1
                    pair_by_request[frame.frame_id] = collision
                    pairs.append(collision)
                    continue
                pair = PairRecord(
                    pair_id=_make_pair_id("tcp", channel, frame, None,
                                          generation),
                    transport="tcp", channel=channel,
                    connection_id=connection_id, generation=generation,
                    request_id=frame.frame_id, response_id=None,
                    unit_id=frame.unit_id, function=pdu.function,
                    transaction_id=frame.transaction_id,
                    status="open", is_broadcast=False, is_exception=False,
                    exception_code=None, request_ns=frame.timestamp_ns,
                    response_ns=None, turnaround_ms=None,
                    rule_ids=[RULE_TCP_TRANSACTION], sequence=sequence)
                sequence += 1
                open_by_key[key] = pair
                pair_by_request[frame.frame_id] = pair
                pairs.append(pair)
            else:
                owner = open_by_key.pop(key, None)
                if owner is None:
                    # A new generation never inherits the previous socket's
                    # open transactions; record the evidence instead of pairing.
                    unmatched_responses.append({
                        "frame_id": frame.frame_id,
                        "transport": "tcp", "channel": channel,
                        "connection_id": connection_id, "generation": generation,
                        "unit_id": frame.unit_id,
                        "transaction_id": frame.transaction_id,
                        "function": pdu.function,
                        "reason": "tcp_response_without_open_transaction",
                        "rule_ids": [RULE_TCP_TRANSACTION],
                        "timestamp_ns": frame.timestamp_ns,
                    })
                    continue
                owner.response_id = frame.frame_id
                owner.response_ns = frame.timestamp_ns
                owner.turnaround_ms = (
                    frame.timestamp_ns - owner.request_ns) / 1_000_000.0
                owner.is_exception = pdu.is_exception
                owner.exception_code = pdu.exception_code
                if pdu.is_exception:
                    owner.status = RESULT_REJECTED
                    owner.unmatched_reason = "modbus_exception_response"
                    owner.rule_ids.append(RULE_EXCEPTION)
                else:
                    owner.status = RESULT_ACCEPTED
        for pair in open_by_key.values():
            if pair.status == "open":
                pair.status = RESULT_UNMATCHED
                pair.unmatched_reason = "tcp_connection_closed_without_response"
    pairs.sort(key=lambda record: (record.request_ns, record.sequence))
    for index, pair in enumerate(pairs):
        pair.sequence = index
    return pairs, unmatched_responses


def _rtu_candidates(response: Frame, transactions: list[PairRecord]) -> list[PairRecord]:
    result: list[PairRecord] = []
    for transaction in transactions:
        if transaction.unit_id != response.unit_id:
            continue
        if transaction.function != response.pdu.function:
            continue
        result.append(transaction)
    # Most recent open request is the natural RTU candidate.
    result.sort(key=lambda record: record.request_ns)
    return result


def _close_silence(transactions: list[PairRecord], frame_ns: int,
                   gap_ms: float, silent_gap_ms: float) -> list[PairRecord]:
    closed: list[PairRecord] = []
    if gap_ms < silent_gap_ms:
        return closed
    for transaction in transactions:
        if transaction.status != "open":
            continue
        transaction.status = RESULT_UNMATCHED
        transaction.unmatched_reason = "rtu_silent_interval_timeout"
        closed.append(transaction)
    return closed


def _pair_rtu(frames: list[Frame], connections: list[ConnectionSpan],
              parameters: ParameterVersion):
    pairs: list[PairRecord] = []
    unmatched_responses: list[dict[str, Any]] = []
    sequence = 0
    p = parameters.rtu
    timeout_ns = int(p["transaction_timeout_ms"] * 1_000_000)
    silent_gap_ms = p["inter_frame_gap_ms"]
    turnaround_ms = p["turnaround_ms"]
    retransmit_ns = int(p["retransmission_ms"] * 1_000_000)
    by_channel: dict[str, list[Frame]] = {}
    for frame in frames:
        if frame.transport != "rtu":
            continue
        by_channel.setdefault(frame.extra.get("channel", ""), []).append(frame)

    for channel, channel_frames in by_channel.items():
        ordered = sorted(channel_frames,
                         key=lambda f: (f.timestamp_ns, f.line))
        open_transactions: list[PairRecord] = []
        request_frame: dict[str, Frame] = {}
        last_request: Frame | None = None
        for frame in ordered:
            gap = frame.gap_before_ms if frame.gap_before_ms is not None else 0.0
            # Observed silent interval closes old transactions before this frame.
            expired_now: list[PairRecord] = []
            for transaction in open_transactions:
                if frame.timestamp_ns - transaction.request_ns > timeout_ns:
                    transaction.status = RESULT_UNMATCHED
                    transaction.unmatched_reason = "rtu_transaction_timeout"
                    expired_now.append(transaction)
                elif gap >= silent_gap_ms and frame.direction == "request":
                    # A new request after a bus-silent gap cannot answer an old
                    # transaction; the old one remains without response.
                    transaction.status = RESULT_UNMATCHED
                    transaction.unmatched_reason = "rtu_silent_interval_timeout"
                    expired_now.append(transaction)
            for item in expired_now:
                open_transactions.remove(item)

            span = _connection_for(frame, connections)
            generation = span.generation if span else frame.extra.get("generation")
            connection_id = span.connection_id if span else frame.extra.get(
                "connection_id")
            if not frame.pdu:
                # Corrupt RTU frame stays visible; it cannot pair or hide data.
                unmatched_responses.append({
                    "frame_id": frame.frame_id,
                    "transport": "rtu", "channel": channel,
                    "connection_id": connection_id, "generation": generation,
                    "unit_id": frame.unit_id, "transaction_id": None,
                    "function": None,
                    "reason": "rtu_corrupt_frame",
                    "rule_ids": [RULE_RTU_SILENCE],
                    "timestamp_ns": frame.timestamp_ns,
                    "diagnostics": [d.as_dict() for d in frame.diagnostics],
                })
                last_request = None
                continue

            pdu = frame.pdu
            if frame.direction == "request":
                duplicate_adus = [
                    transaction for transaction in open_transactions
                    if transaction.unit_id == frame.unit_id
                    and transaction.function == pdu.function
                ]
                duplicate_adus = [
                    transaction for transaction in duplicate_adus
                    if request_frame[transaction.request_id].adu_hex == frame.adu_hex
                ]
                if duplicate_adus and gap < silent_gap_ms and last_request and \
                        frame.timestamp_ns - last_request.timestamp_ns <= retransmit_ns:
                    owner = duplicate_adus[-1]
                    owner.retransmissions.append(frame.frame_id)
                    last_request = frame
                    continue
                pair = PairRecord(
                    pair_id=_make_pair_id("rtu", channel, frame, None,
                                          generation),
                    transport="rtu", channel=channel,
                    connection_id=connection_id, generation=generation,
                    request_id=frame.frame_id, response_id=None,
                    unit_id=frame.unit_id, function=pdu.function,
                    transaction_id=None, status="open",
                    is_broadcast=frame.unit_id == BROADCAST_UNIT,
                    is_exception=False, exception_code=None,
                    request_ns=frame.timestamp_ns, response_ns=None,
                    turnaround_ms=None, rule_ids=[RULE_RTU_SILENCE],
                    sequence=sequence)
                sequence += 1
                request_frame[frame.frame_id] = frame
                if frame.unit_id == BROADCAST_UNIT:
                    pair.status = RESULT_ACCEPTED
                    pair.unmatched_reason = "broadcast_no_response_expected"
                    pair.rule_ids.append(RULE_BROADCAST)
                else:
                    open_transactions.append(pair)
                pairs.append(pair)
                last_request = frame
            else:
                candidates = _rtu_candidates(frame, open_transactions)
                if not candidates:
                    unmatched_responses.append({
                        "frame_id": frame.frame_id,
                        "transport": "rtu", "channel": channel,
                        "connection_id": connection_id,
                        "generation": generation,
                        "unit_id": frame.unit_id, "transaction_id": None,
                        "function": pdu.function,
                        "reason": "rtu_response_without_open_request",
                        "rule_ids": [RULE_RTU_SILENCE],
                        "timestamp_ns": frame.timestamp_ns,
                    })
                    last_request = None
                    continue
                if len(candidates) == 1:
                    owner = candidates[0]
                    open_transactions.remove(owner)
                else:
                    # Multiple identical outstanding requests: the protocol
                    # gives no unique owner, so all legal candidates are kept.
                    owner = candidates[-1]
                    owner.status = RESULT_AMBIGUOUS
                    owner.unmatched_reason = "rtu_multiple_open_candidates"
                    owner.candidates = [
                        PairCandidate(candidate.request_id,
                                      "legal_candidate" if candidate is not owner
                                      else "latest_request",
                                      "same unit/function is still outstanding")
                        for candidate in reversed(candidates)
                    ]
                    for candidate in candidates[:-1]:
                        candidate.status = RESULT_AMBIGUOUS
                        candidate.unmatched_reason = (
                            "rtu_multiple_open_candidates")
                owner.response_id = frame.frame_id
                owner.response_ns = frame.timestamp_ns
                owner.turnaround_ms = (
                    frame.timestamp_ns - owner.request_ns) / 1_000_000.0
                owner.is_exception = pdu.is_exception
                owner.exception_code = pdu.exception_code
                if pdu.is_exception:
                    owner.status = RESULT_REJECTED
                    owner.unmatched_reason = "modbus_exception_response"
                    owner.rule_ids.append(RULE_EXCEPTION)
                elif owner.status != RESULT_AMBIGUOUS:
                    owner.status = RESULT_ACCEPTED
                last_request = None
        for transaction in open_transactions:
            if transaction.status == "open":
                transaction.status = RESULT_UNMATCHED
                transaction.unmatched_reason = "rtu_bus_closed_without_response"
    pairs.sort(key=lambda record: (record.request_ns, record.sequence))
    for index, pair in enumerate(pairs):
        pair.sequence = index
    return pairs, unmatched_responses


def apply_source_corrections(frames: list[Frame],
                             corrections: list[dict[str, Any]]
                             ) -> tuple[list[Frame], list[dict[str, Any]]]:
    """Return frames with one direct source field corrected plus correction refs.

    The original frame is never overwritten; the replacement carries new stable
    identity and a supersedes link, so local dependency changes are auditable.
    """
    result = list(frames)
    by_id = {frame.frame_id: frame for frame in result}
    effects: list[dict[str, Any]] = []
    for correction in sorted(corrections, key=lambda item: (
            str(item.get("correction_id", "")), str(item.get("source", "")))):
        target_id = correction.get("target_frame_id")
        if target_id not in by_id:
            effects.append({
                "correction_id": correction.get("correction_id"),
                "applied": False,
                "reason": "target_frame_not_found",
                "target_frame_id": target_id,
            })
            continue
        original = by_id[target_id]
        field_name = correction.get("field")
        if field_name not in {"adu_hex", "direction", "timestamp_ns"}:
            effects.append({
                "correction_id": correction.get("correction_id"),
                "applied": False,
                "reason": "unsupported_direct_source_field",
                "target_frame_id": target_id,
                "field": field_name,
            })
            continue
        record = {
            "type": "frame",
            "timestamp_ns": (correction["value"] if field_name == "timestamp_ns"
                             else original.timestamp_ns),
            "connection": original.extra.get("channel"),
            "direction": correction["value"] if field_name == "direction"
                         else original.direction,
            "adu_hex": correction["value"] if field_name == "adu_hex"
                       else original.adu_hex,
        }
        from .modbus import parse_rtu_frame, parse_tcp_frame
        parser = parse_tcp_frame if original.transport == "tcp" else parse_rtu_frame
        replacement_id = stable_id(
            "corrfrm", original.frame_id, correction.get("correction_id"),
            correction.get("field"), correction.get("value"))
        replacement = parser(
            record["adu_hex"], frame_id=replacement_id,
            source=str(correction.get("source", "correction")),
            line=int(correction.get("line", original.line)),
            direction=record["direction"], timestamp_ns=record["timestamp_ns"],
            gap_before_ms=original.gap_before_ms, extra=dict(original.extra))
        replacement.extra["supersedes_frame_id"] = original.frame_id
        replacement.extra["correction_id"] = correction.get("correction_id")
        index = result.index(original)
        result[index] = replacement
        by_id[replacement_id] = replacement
        effects.append({
            "correction_id": correction.get("correction_id"),
            "applied": True,
            "target_frame_id": target_id,
            "replacement_frame_id": replacement_id,
            "field": field_name,
            "old_value": getattr(original, field_name),
            "new_value": correction.get("value"),
        })
    return result, effects


def pair_frames(frames: list[Frame], connections: list[ConnectionSpan],
                parameters: ParameterVersion):
    """Run both pairing rules. Returned object is plain dict for persistence."""
    tcp_pairs, tcp_unmatched = _pair_tcp(frames, connections)
    rtu_pairs, rtu_unmatched = _pair_rtu(frames, connections, parameters)
    pairs = sorted(tcp_pairs + rtu_pairs,
                   key=lambda record: (record.request_ns, record.sequence,
                                       record.pair_id))
    for index, pair in enumerate(pairs):
        pair.sequence = index
    unmatched = sorted(tcp_unmatched + rtu_unmatched,
                       key=lambda item: (item["timestamp_ns"],
                                         item.get("channel", ""),
                                         item.get("frame_id", "")))
    return {
        "kind": "pairing",
        "parameter_id": parameters.parameter_id,
        "parameter_version": parameters.version,
        "rule_statements": {
            RULE_TCP_TRANSACTION: __import__(
                "domain.parameters", fromlist=["RULE_STATEMENTS"]
            ).RULE_STATEMENTS[RULE_TCP_TRANSACTION],
            RULE_RTU_SILENCE: __import__(
                "domain.parameters", fromlist=["RULE_STATEMENTS"]
            ).RULE_STATEMENTS[RULE_RTU_SILENCE],
            RULE_BROADCAST: __import__(
                "domain.parameters", fromlist=["RULE_STATEMENTS"]
            ).RULE_STATEMENTS[RULE_BROADCAST],
            RULE_EXCEPTION: __import__(
                "domain.parameters", fromlist=["RULE_STATEMENTS"]
            ).RULE_STATEMENTS[RULE_EXCEPTION],
        },
        "pairs": [pair.as_dict() for pair in pairs],
        "unmatched": unmatched,
        "input_summary": {
            "frame_count": len(frames),
            "connection_count": len(connections),
            "tcp_frame_count": sum(f.transport == "tcp" for f in frames),
            "rtu_frame_count": sum(f.transport == "rtu" for f in frames),
            "corrupt_frame_count": sum(
                f.pdu is None or bool(f.diagnostics) for f in frames),
            "frame_ids": [f.frame_id for f in sorted(
                frames, key=lambda item: item.frame_id)],
        },
    }
