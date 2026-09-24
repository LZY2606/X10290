"""Import immutable materials from trace/event lines and mapping documents.

Original representations stay untouched. Parsing diagnostics carry a source and
line number. Corrupt input is a distinct terminal result from budget or
semantic failures.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .identity import stable_id
from .mapping import DeviceMapping, parse_mapping
from .model import (BROADCAST_UNIT, Diagnostic, DomainError,
                    FAIL_BUDGET_EXHAUSTED, FAIL_FORMAT_CORRUPT)
from .modbus import Frame, parse_rtu_frame, parse_tcp_frame


@dataclass
class ConnectionSpan:
    connection_id: str
    transport: str
    channel: str
    generation: int
    opened_ns: int
    closed_ns: int | None
    source: str
    open_line: int
    close_line: int | None = None
    serial: dict[str, Any] = field(default_factory=dict)
    direction_pairs: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "connection_id": self.connection_id,
            "transport": self.transport,
            "channel": self.channel,
            "generation": self.generation,
            "opened_ns": self.opened_ns,
            "closed_ns": self.closed_ns,
            "source": self.source,
            "open_line": self.open_line,
            "close_line": self.close_line,
            "serial": self.serial,
            "direction_pairs": self.direction_pairs,
        }


@dataclass
class ImportBundle:
    frames: list[Frame]
    connections: list[ConnectionSpan]
    raw_events: list[dict[str, Any]]
    mappings: list[DeviceMapping]
    parameter_versions: list[dict[str, Any]]
    corrections: list[dict[str, Any]]
    scenarios: list[dict[str, Any]]
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def diagnostic_dicts(self) -> list[dict[str, Any]]:
        return [d.as_dict() for d in self.diagnostics]


def _parse_time(value: Any, location: dict[str, Any]) -> int:
    if isinstance(value, bool):
        raise DomainError(FAIL_FORMAT_CORRUPT, "bad_timestamp",
                          "timestamp must be ns integer or 's.mmm' string",
                          [Diagnostic("bad_timestamp", "boolean timestamp", location)])
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value) * 1_000_000_000)
        except ValueError:
            pass
    raise DomainError(
        FAIL_FORMAT_CORRUPT, "bad_timestamp",
        f"unsupported timestamp {value!r}",
        [Diagnostic("bad_timestamp", "timestamp must be ns number or second string",
                    {**location, "found": value})])


def _load_trace_document(doc: dict[str, Any], source: str,
                        bundle: ImportBundle,
                        max_frames: int) -> None:
    if not isinstance(doc, dict):
        raise DomainError(FAIL_FORMAT_CORRUPT, "trace_not_object",
                          f"{source}: trace document must be an object",
                          [Diagnostic("trace_not_object", "root is not object",
                                      {"source": source})])
    frames = doc.get("frames")
    if not isinstance(frames, list):
        raise DomainError(FAIL_FORMAT_CORRUPT, "frames_not_list",
                          f"{source}: frames must be a list",
                          [Diagnostic("frames_not_list", "frames is not a list",
                                      {"source": source})])
    transport = doc.get("transport")
    if transport not in ("tcp", "rtu"):
        raise DomainError(
            FAIL_FORMAT_CORRUPT, "transport_invalid",
            f"{source}: transport must be tcp or rtu",
            [Diagnostic("transport_invalid", "transport missing/invalid",
                        {"source": source, "found": transport})])

    pending_gap: float | None = None
    last_ns: int | None = None
    # Connections: default span per channel, plus explicit open/close events.
    open_spans: dict[str, ConnectionSpan] = {}
    generation: dict[str, int] = {}
    for index, record in enumerate(frames, start=1):
        location = {"source": source, "line": index}
        if len(bundle.frames) >= max_frames:
            raise DomainError(
                FAIL_BUDGET_EXHAUSTED, "frame_budget_exhausted",
                f"frame budget {max_frames} exhausted at {source}:{index}",
                [Diagnostic("frame_budget_exhausted",
                            "refusing to import beyond configured frame budget",
                            location)])
        if not isinstance(record, dict):
            raise DomainError(FAIL_FORMAT_CORRUPT, "record_not_object",
                              "each trace record must be an object",
                              [Diagnostic("record_not_object",
                                          "record is not an object", location)])
        rec_type = record.get("type", "frame")
        timestamp_ns = _parse_time(record.get("timestamp_ns"), location)
        channel = str(record.get("connection")
                      or record.get("channel")
                      or (f"{transport}:{record.get('client','')}-"
                          f"{record.get('server','')}" if transport == "tcp"
                          else f"{transport}:{record.get('port','bus0')}"))
        if rec_type in ("open", "connection_open", "serial_open"):
            generation[channel] = generation.get(channel, 0) + 1
            serial = {
                key: record[key]
                for key in ("baudrate", "bytesize", "parity", "stopbits",
                            "inter_frame_gap_ms", "turnaround_ms")
                if key in record
            }
            span = ConnectionSpan(
                connection_id=stable_id(
                    "conn", source, channel, generation[channel], timestamp_ns),
                transport=transport, channel=channel,
                generation=generation[channel], opened_ns=timestamp_ns,
                closed_ns=None, source=source, open_line=index,
                serial=serial,
                direction_pairs=list(record.get("direction_pairs", [])),
            )
            open_spans[channel] = span
            bundle.connections.append(span)
            bundle.raw_events.append({
                "event_id": stable_id("evt", source, index, "open"),
                "kind": "connection_open", "source": source, "line": index,
                "timestamp_ns": timestamp_ns, "connection_id": span.connection_id,
                "channel": channel, "generation": span.generation,
                "transport": transport, "serial": serial, "raw": record,
            })
            last_ns = timestamp_ns
            continue
        if rec_type in ("close", "connection_close", "serial_close"):
            span = open_spans.get(channel)
            if span is None:
                raise DomainError(
                    FAIL_FORMAT_CORRUPT, "close_without_open",
                    f"{source}:{index}: close event has no preceding open",
                    [Diagnostic("close_without_open",
                                "connection close without open on channel",
                                {**location, "channel": channel})])
            span.closed_ns = timestamp_ns
            span.close_line = index
            bundle.raw_events.append({
                "event_id": stable_id("evt", source, index, "close"),
                "kind": "connection_close", "source": source, "line": index,
                "timestamp_ns": timestamp_ns, "connection_id": span.connection_id,
                "channel": channel, "generation": span.generation,
                "transport": transport, "raw": record,
            })
            open_spans.pop(channel, None)
            last_ns = timestamp_ns
            continue
        if rec_type in ("idle", "silent_interval", "bus_idle"):
            pending_gap = float(record.get("duration_ms", 0.0))
            bundle.raw_events.append({
                "event_id": stable_id("evt", source, index, "idle"),
                "kind": "serial_idle", "source": source, "line": index,
                "timestamp_ns": timestamp_ns, "channel": channel,
                "duration_ms": pending_gap, "raw": record,
            })
            last_ns = timestamp_ns
            continue
        if rec_type in ("noise", "framing_error", "line_noise"):
            bundle.raw_events.append({
                "event_id": stable_id("evt", source, index, "noise"),
                "kind": "serial_noise", "source": source, "line": index,
                "timestamp_ns": timestamp_ns, "channel": channel,
                "diagnostic": record.get("diagnostic", "line noise"),
                "raw": record,
            })
            last_ns = timestamp_ns
            continue
        if rec_type != "frame":
            raise DomainError(
                FAIL_FORMAT_CORRUPT, "unknown_trace_record",
                f"{source}:{index}: unknown record type {rec_type!r}",
                [Diagnostic("unknown_trace_record",
                            "known types: frame/open/close/idle/noise",
                            {**location, "type": rec_type})])
        adu_hex = record.get("adu_hex") or record.get("adu")
        direction = record.get("direction")
        if direction not in ("request", "response"):
            raise DomainError(
                FAIL_FORMAT_CORRUPT, "direction_invalid",
                f"{source}:{index}: direction must be request/response",
                [Diagnostic("direction_invalid", "direction must be request/response",
                            {**location, "found": direction})])
        if not isinstance(adu_hex, str):
            raise DomainError(
                FAIL_FORMAT_CORRUPT, "adu_missing",
                f"{source}:{index}: adu_hex required",
                [Diagnostic("adu_missing", "adu_hex must be a hex string", location)])
        gap = pending_gap
        if gap is None and transport == "rtu" and last_ns is not None:
            gap = max(0.0, (timestamp_ns - last_ns) / 1_000_000.0)
        frame_id = record.get("frame_id") or stable_id(
            "frm", source, index, adu_hex.lower(), direction, channel)
        extra = {key: value for key, value in record.items()
                 if key not in {"type", "timestamp_ns", "connection", "channel",
                                "adu_hex", "adu", "direction", "frame_id",
                                "client", "server", "port"}}
        if transport == "tcp":
            frame = parse_tcp_frame(
                adu_hex, frame_id=frame_id, source=source, line=index,
                direction=direction, timestamp_ns=timestamp_ns, extra=extra)
        else:
            frame = parse_rtu_frame(
                adu_hex, frame_id=frame_id, source=source, line=index,
                direction=direction, timestamp_ns=timestamp_ns,
                gap_before_ms=gap, extra=extra)
        frame.extra["channel"] = channel
        if record.get("client"):
            frame.extra["client"] = record["client"]
        if record.get("server"):
            frame.extra["server"] = record["server"]
        # Attach to a span if one is explicitly open; importer does not invent
        # connection generations from bare frames.
        span = open_spans.get(channel)
        if span is not None:
            frame.extra["connection_id"] = span.connection_id
            frame.extra["generation"] = span.generation
        bundle.frames.append(frame)
        pending_gap = None
        last_ns = timestamp_ns


def import_documents(documents: list[tuple[str, str]],
                     *, max_frames: int = 200_000) -> ImportBundle:
    """Import (filename, text) trace JSON documents and mappings."""
    bundle = ImportBundle([], [], [], [], [], [], [])
    for source, text in documents:
        stripped = text.lstrip()
        if stripped.startswith("{") and '"points"' in stripped[:400]:
            bundle.mappings.append(parse_mapping(text, source=source))
            continue
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DomainError(
                FAIL_FORMAT_CORRUPT, "document_not_json", str(exc),
                [Diagnostic("document_not_json", str(exc),
                            {"source": source, "line": exc.lineno,
                             "column": exc.colno})])
        if not isinstance(doc, dict):
            raise DomainError(
                FAIL_FORMAT_CORRUPT, "document_not_object",
                f"{source}: root must be an object",
                [Diagnostic("document_not_object", "root is not object",
                            {"source": source})])
        doc_type = doc.get("type", "trace")
        if doc_type in ("parameter_version", "parameters"):
            parameters = dict(doc)
            parameters.setdefault("source", source)
            bundle.parameter_versions.append(parameters)
            continue
        if doc_type in ("source_correction", "correction"):
            correction = dict(doc)
            correction.setdefault("source", source)
            bundle.corrections.append(correction)
            continue
        if doc_type == "scenario":
            scenario = dict(doc)
            scenario.setdefault("source", source)
            bundle.scenarios.append(scenario)
            continue
        if doc_type == "mapping_document":
            bundle.mappings.append(parse_mapping(json.dumps(doc.get("mapping", {})),
                                                 source=source))
            continue
        if doc.get("frames") is not None or doc_type == "trace":
            _load_trace_document(doc, source, bundle, max_frames)
            continue
        raise DomainError(
            FAIL_FORMAT_CORRUPT, "unknown_document",
            f"{source}: cannot classify document type {doc_type!r}",
            [Diagnostic("unknown_document",
                        "expected trace, parameters, correction, scenario, mapping",
                        {"source": source, "type": doc_type})])
    # Stable, deterministic ordering: transport channel, timestamp, source line.
    bundle.frames.sort(key=lambda frame: (
        frame.extra.get("channel", ""),
        frame.timestamp_ns,
        frame.source, frame.line, frame.frame_id))
    bundle.connections.sort(key=lambda span: (
        span.channel, span.opened_ns, span.source, span.open_line))
    return bundle


def is_broadcast(frame: Frame) -> bool:
    return frame.transport == "rtu" and frame.direction == "request" \
        and frame.unit_id == BROADCAST_UNIT
