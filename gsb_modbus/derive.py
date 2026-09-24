"""Deterministic replay engine.

Given an ordered list of immutable materials and parameter/decision events, it
produces connection generations, request/response pairs, register
interpretations and unpaired reasons. Every derived object carries a stable
identity computed from its input summary, parameter version and parent
dependencies, so export/import and replay of any old event agree.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .bus import parse_bus
from .decode import interpret_registers
from .errors import SemanticallyUnresolved
from .model import bytes_to_hex, stable_id
from .protocol import (
    BROADCAST_UNIT,
    READ_FCS,
    WRITE_MULTI,
    WRITE_SINGLE,
    parse_pdu,
    parse_rtu_adu,
    parse_tcp_adu,
)

DEFAULT_PARAMS = {
    "rtu": {
        "baud": 9600,
        "framing": "standard",
        "exchange_timeout_seconds": 0.1,
        "default_word_order": "CDAB",
    },
    "display_address_base": 1,
}

EXCEPTION_NAMES = {
    1: "illegal function",
    2: "illegal data address",
    3: "illegal data value",
    4: "server device failure",
    5: "acknowledge",
    6: "server device busy",
    8: "memory parity error",
    10: "gateway path unavailable",
    11: "gateway target no response",
}


@dataclass
class DerivedState:
    params: dict
    events: list[dict]
    materials: list[dict]
    frames: list[dict] = field(default_factory=list)
    generations: list[dict] = field(default_factory=list)
    pairs: list[dict] = field(default_factory=list)
    blocks: list[dict] = field(default_factory=list)
    unpaired: list[dict] = field(default_factory=list)
    mapping_versions: list[dict] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)
    heads: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "params": self.params,
            "frames": self.frames,
            "generations": self.generations,
            "pairs": self.pairs,
            "blocks": self.blocks,
            "unpaired": self.unpaired,
            "mapping_versions": self.mapping_versions,
            "diagnostics": self.diagnostics,
        }


def _normalize_mapping(material: dict, diagnostics: list[dict]) -> dict:
    """Parse a mapping material; unconvertible address strings stay in place."""
    base = int(material.get("address_base", material.get("address_base_declared", 0)))
    if base not in (0, 1):
        raise SemanticallyUnresolved(
            f"mapping address_base must be 0 or 1, got {base}",
            position=f"{material['material_id']}.address_base",
        )
    entries = []
    for idx, entry in enumerate(material.get("entries", [])):
        pos = f"{material['material_id']}.entries[{idx}]"
        raw_addr = entry.get("address_raw", entry.get("address"))
        e = dict(entry)
        e["address_raw"] = raw_addr
        try:
            shown = int(raw_addr, 0) if isinstance(raw_addr, str) else int(raw_addr)
            e["address_wire0"] = shown - base
            e["address_unconvertible"] = False
        except (TypeError, ValueError):
            e["address_wire0"] = None
            e["address_unconvertible"] = True
            diagnostics.append(
                {
                    "code": "mapping_address_unconvertible",
                    "message": f"address {raw_addr!r} cannot be converted; entry retained",
                    "position": pos + ".address",
                    "severity": "error",
                }
            )
        if e.get("address_wire0") is not None and e["address_wire0"] < 0:
            diagnostics.append(
                {
                    "code": "mapping_address_negative_wire",
                    "message": f"{base}-based address {shown} maps below register 0",
                    "position": pos + ".address",
                    "severity": "error",
                }
            )
            e["address_unconvertible"] = True
        entries.append(e)
    return {
        "mapping_id": material["material_id"],
        "name": material.get("name", "device mapping"),
        "version": material.get("version", "?"),
        "unit_id": material.get("unit_id"),
        "address_base": base,
        "effective_at_order": material.get("order"),
        "effective_at_iso": material.get("observed_at"),
        "entries": entries,
        "material_digest": material["digest"],
    }


def _mapping_for(version: dict, wire0: int, quantity: int) -> dict | None:
    best = None
    for entry in version["entries"]:
        if entry.get("address_unconvertible"):
            continue
        start = entry["address_wire0"]
        width = int(entry.get("words", 1))
        if start <= wire0 and wire0 + quantity <= start + width:
            if best is None or start > best["address_wire0"]:
                best = entry
    return best


def _frame_view(material: dict) -> dict:
    data = bytes(material["adu_bytes"])
    try:
        parsed = parse_tcp_adu(data, material["material_id"])
    except Exception as exc_tcp:  # noqa: BLE001 - surfaced as structured diagnostic
        from .errors import GSBError

        diag = exc_tcp.diagnostic.to_dict() if isinstance(exc_tcp, GSBError) else {
            "code": "parse_error",
            "message": str(exc_tcp),
            "position": material["material_id"],
            "severity": "error",
        }
        parsed = {
            "encapsulation": "tcp",
            "transaction_id": None,
            "unit_id": material.get("unit_id"),
            "function_code": None,
            "diagnostics": [diag],
        }
    return {
        "frame_id": stable_id("frm", material["digest"]),
        "material_id": material["material_id"],
        "encapsulation": "tcp",
        "direction": material["direction"],
        "observed_at": material["observed_at"],
        "time_seconds": material.get("time_seconds"),
        "time_base": material.get("time_base", "capture-monotonic-ns"),
        "connection_key": material["connection_key"],
        "adu_hex": bytes_to_hex(data),
        "length": len(data),
        "parse": parsed,
        "import_order": material.get("order"),
    }


def _rtu_frame_view(frame: dict, capture: dict) -> dict:
    data = bytes(frame["data"])
    try:
        parsed = parse_rtu_adu(data, capture["material_id"], verify_crc=False)
    except Exception as exc:  # noqa: BLE001
        from .errors import GSBError

        diag = exc.diagnostic.to_dict() if isinstance(exc, GSBError) else {
            "code": "parse_error",
            "message": str(exc),
            "position": capture["material_id"],
            "severity": "error",
        }
        parsed = {"encapsulation": "rtu", "unit_id": data[0] if data else None,
                  "diagnostics": [diag]}
    parsed.setdefault("diagnostics", []).extend(frame.get("diagnostics", []))
    parsed["crc"] = frame.get("crc")
    return {
        "frame_id": stable_id("frm", capture["digest"], frame["bus_order"], frame["adu_hex"]),
        "material_id": capture["material_id"],
        "encapsulation": "rtu",
        "direction": frame["dir"],
        "observed_at": capture["observed_at"],
        "time_seconds": frame["t0"],
        "time_base": f"bus-seconds:{capture.get('time_base', 'first-edge')}",
        "connection_key": f"rtu:{capture.get('bus', 'main')}",
        "adu_hex": frame["adu_hex"],
        "length": frame["length"],
        "parse": parsed,
        "import_order": capture.get("order", 0) * 100000 + frame["bus_order"],
    }


def _build_tcp_generations(frames: list[dict]) -> tuple[list[dict], dict]:
    gens: list[dict] = []
    by_key: dict[str, list[dict]] = {}
    for fr in frames:
        if fr["encapsulation"] != "tcp":
            continue
        by_key.setdefault(fr["connection_key"], []).append(fr)
    frame_gen: dict[str, str] = {}
    for key, group in by_key.items():
        group.sort(key=lambda f: (f["time_seconds"] or 0, f["import_order"]))
        serial = 0
        current: dict | None = None
        for fr in group:
            open_marker = (fr.get("parse") or {}).get("tcp_event")
            if open_marker == "open":
                serial += 1
                gid = stable_id("gen", key, serial)
                current = {
                    "generation_id": gid,
                    "connection_key": key,
                    "serial": serial,
                    "opened_at": fr["time_seconds"],
                    "closed_at": None,
                    "source_frame_id": fr["frame_id"],
                }
                gens.append(current)
                frame_gen[fr["frame_id"]] = gid
                continue
            if open_marker == "close":
                if current is not None:
                    current["closed_at"] = fr["time_seconds"]
                frame_gen[fr["frame_id"]] = current["generation_id"] if current else None
                continue
            if current is None:
                serial += 1
                gid = stable_id("gen", key, serial)
                current = {
                    "generation_id": gid,
                    "connection_key": key,
                    "serial": serial,
                    "opened_at": fr["time_seconds"],
                    "closed_at": None,
                    "source_frame_id": fr["frame_id"],
                    "inferred": True,
                }
                gens.append(current)
            frame_gen[fr["frame_id"]] = current["generation_id"]
    gens.sort(key=lambda g: (g["connection_key"], g["serial"]))
    return gens, frame_gen


def _is_readable_response(parse: dict) -> bool:
    return parse.get("kind") == "read_response" and "registers" in parse


def replay(events: list[dict], *, budget: int | None = None) -> DerivedState:
    """Replay an ordered event stream into the fully derived review state."""
    if budget is not None and len(events) > budget:
        from .errors import ResourceBudgetExhausted

        raise ResourceBudgetExhausted(
            f"replay budget {budget} exceeded by {len(events)} events",
            position="events",
            used=len(events),
            limit=budget,
        )

    ordered = sorted(events, key=lambda e: e["seq"])
    params = {
        "rtu": dict(DEFAULT_PARAMS["rtu"]),
        "display_address_base": DEFAULT_PARAMS["display_address_base"],
    }
    param_version_id = stable_id("params", "initial", params)
    materials: list[dict] = []
    decisions: dict[str, dict] = {}
    branches: dict[str, list[dict]] = {"main": []}
    heads: dict[str, int] = {}
    diagnostics: list[dict] = []

    for event in ordered:
        heads[event["branch"]] = event["seq"]
        etype = event["type"]
        if etype == "material_imported":
            materials.append(dict(event["payload"], material_id=event["id"],
                                  digest=event["payload"].get("digest", ""),
                                  order=event["seq"], observed_at=event["created_at"]))
        elif etype == "parameters_revised":
            new_rtu = dict(params["rtu"])
            new_rtu.update(event["payload"].get("rtu", {}))
            params = {
                "rtu": new_rtu,
                "display_address_base": int(
                    event["payload"].get(
                        "display_address_base", params["display_address_base"]
                    )
                ),
            }
            param_version_id = event.get("param_version_id") or stable_id(
                "params", event["id"], params
            )
        elif etype in ("pair_accepted", "pair_rejected", "word_order_decided",
                       "candidate_pair_decided", "mapping_choice_decided",
                       "conflicting_decision"):
            subject = event["payload"].get("subject_id")
            prev = decisions.get(subject)
            if prev is not None and prev["event"].get("branch") == event["branch"]:
                if prev["event"]["type"] != etype or prev["event"]["payload"] != event["payload"]:
                    raise SemanticallyUnresolved(
                        f"subject {subject} already decided on branch {event['branch']} "
                        f"by {prev['event']['id']}; conflicting decision is unresolved",
                        position=f"{event['id']}.subject:{subject}",
                    )
            decisions[subject] = {"event": event, "payload": event["payload"]}
            branches.setdefault(event["branch"], []).append(event)

    # --- stages: mappings, serial framing, frame views ---------------------
    mapping_versions: list[dict] = []
    frames: list[dict] = []
    for material in materials:
        if material["kind"] == "mapping":
            mapping_versions.append(_normalize_mapping(material, diagnostics))
        elif material["kind"] == "tcp_frame":
            frames.append(_frame_view(material))
        elif material["kind"] == "serial_capture":
            serial_events = material.get("serial_events", [])
            bus_frames = parse_bus(
                serial_events, params["rtu"], position=material["material_id"]
            )
            frames.extend(_rtu_frame_view(bf, material) for bf in bus_frames)
    frames.sort(key=lambda f: f["import_order"])

    generations, frame_gen = _build_tcp_generations(frames)
    state = DerivedState(
        params=params,
        events=ordered,
        materials=materials,
        frames=frames,
        generations=generations,
        mapping_versions=mapping_versions,
        diagnostics=diagnostics,
        heads=heads,
    )

    tcp_pairs, tcp_unpaired = _pair_tcp(frames, frame_gen, generations, decisions, param_version_id)
    rtu_pairs, rtu_unpaired = _pair_rtu(frames, decisions, params, param_version_id)
    state.pairs = sorted(tcp_pairs + rtu_pairs, key=lambda p: (p["order"], p["pair_id"]))
    for i, pair in enumerate(state.pairs):
        pair["order"] = i
    state.unpaired = sorted(tcp_unpaired + rtu_unpaired, key=lambda u: (u["order"], u["id"]))
    state.blocks = _interpret(state, decisions, param_version_id)
    _apply_pair_decisions(state, decisions)
    return state
