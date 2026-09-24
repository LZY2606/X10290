"""Register interval interpretation and value decoding with NumPy."""
from __future__ import annotations

import numpy as np

from .identity import stable_id
from .mapping import DeviceMapping, MappingPoint, WORD_ORDERS
from .model import (RESULT_ACCEPTED, RESULT_AMBIGUOUS, RESULT_DIAGNOSTIC,
                    RESULT_REJECTED)
from .parameters import (RULE_ADDRESS_DISPLAY, RULE_EXCEPTION,
                         RULE_WORD_ORDER)

REGISTER_FUNCS = {3, 4, 16, 6, 23}
READ_REGISTER_FUNCS = {3, 4}


def words_from_payload(data: bytes) -> np.ndarray:
    if len(data) % 2:
        return np.array([], dtype="<u2")
    return np.frombuffer(data, dtype=">u2").astype(np.uint16)


def _decode_words(words: np.ndarray, order: str, kind: str) -> int | float | None:
    if kind == "uint16":
        return int(words[0])
    if kind == "int16":
        return int(words.astype(">i2")[0])
    if words.size < 2:
        return None
    raw = words[:2].astype(np.uint16)
    if order == "abcd":
        value_bytes = raw.astype(">u2").tobytes()
    elif order == "badc":
        # Swap bytes within each 16 bit word: B A D C.
        value_bytes = bytes((raw[0] & 0xFF, (raw[0] >> 8) & 0xFF,
                             raw[1] & 0xFF, (raw[1] >> 8) & 0xFF))
    elif order == "cdab":
        # Swap the two words: C D A B.
        normal = raw.astype(">u2").tobytes()
        value_bytes = normal[2:] + normal[:2]
    elif order == "dcba":
        # Reverse both words and bytes: D C B A.
        value_bytes = bytes(reversed(raw.astype(">u2").tobytes()))
    else:
        return None
    if kind == "uint32":
        return int.from_bytes(value_bytes, "big", signed=False)
    if kind == "int32":
        return int.from_bytes(value_bytes, "big", signed=True)
    if kind == "float32":
        return float(np.frombuffer(value_bytes, dtype=">f4")[0])
    return None


def decode_32_candidates(words: np.ndarray) -> dict[str, int | float]:
    """All legal byte/word order interpretations; ambiguity is retained."""
    values: dict[str, int | float] = {}
    for order in WORD_ORDERS:
        values[order] = _decode_words(words, order, "uint32")
    return values


def _validity(point: MappingPoint, value: float) -> tuple[bool, str | None]:
    if point.minimum is not None and value < float(point.minimum):
        return False, f"value {value:g} below minimum {point.minimum:g}"
    if point.maximum is not None and value > float(point.maximum):
        return False, f"value {value:g} above maximum {point.maximum:g}"
    return True, None


def _register_interval(pair: dict, frames_by_id: dict) -> dict:
    request = frames_by_id[pair["request_id"]]
    response = frames_by_id.get(pair.get("response_id") or "")
    request_pdu = request.pdu.as_dict() if request.pdu else None
    address = request_pdu.get("address") if request_pdu else None
    quantity = request_pdu.get("quantity") if request_pdu else None
    if pair["function"] == 6:
        address = request_pdu.get("address") if request_pdu else None
        quantity = 1
    payload = b""
    if response is not None and response.pdu and not response.pdu.is_exception:
        payload = response.pdu.data
    return {
        "register_address_zero_based": address,
        "register_quantity": quantity,
        "register_end_exclusive_zero_based": (
            address + quantity if address is not None and quantity is not None
            else None),
        "payload_hex": payload.hex(),
        "word_count": len(payload) // 2,
        "source_request_id": request.frame_id,
        "source_response_id": response.frame_id if response else None,
    }


def interpret_pairs(pairing: dict, frames: list,
                    mappings: list[DeviceMapping],
                    *, mapping_selection: dict | None = None) -> dict:
    """Interpret register carrying pairs against mapping versions.

    mapping_selection: {unit_id|"default": mapping_id}. Missing selection is a
    semantic diagnostic, not a silent default.
    """
    frames_by_id = {frame.frame_id: frame for frame in frames}
    mapping_selection = mapping_selection or {}
    mapping_by_id = {mapping.mapping_id: mapping for mapping in mappings}
    intervals: list[dict] = []
    values: list[dict] = []
    diagnostics: list[dict] = []

    for pair in pairing["pairs"]:
        if pair["function"] not in REGISTER_FUNCS:
            continue
        interval = _register_interval(pair, frames_by_id)
        interval.update({
            "interval_id": stable_id(
                "rng", pair["pair_id"], interval["register_address_zero_based"],
                interval["register_quantity"]),
            "pair_id": pair["pair_id"],
            "unit_id": pair["unit_id"],
            "status": pair["status"],
            "is_exception": pair["is_exception"],
            "exception_code": pair["exception_code"],
            "rule_ids": [RULE_ADDRESS_DISPLAY],
        })
        intervals.append(interval)
        if pair["is_exception"]:
            diagnostics.append({
                "code": "exception_not_data",
                "severity": "rejected",
                "message": ("exception response retained as rejected; no "
                            "successful empty register sample is produced"),
                "location": {"pair_id": pair["pair_id"],
                             "exception_code": pair["exception_code"]},
                "rule_ids": [RULE_EXCEPTION],
            })
            continue
        if pair["status"] not in (RESULT_ACCEPTED,):
            continue
        selection_key = str(pair["unit_id"])
        mapping_id = mapping_selection.get(
            selection_key, mapping_selection.get("default"))
        if not mapping_id:
            diagnostics.append({
                "code": "mapping_selection_missing",
                "severity": "error",
                "message": "no mapping version selected for unit; input incomplete",
                "location": {"pair_id": pair["pair_id"],
                             "unit_id": pair["unit_id"]},
                "rule_ids": [],
            })
            continue
        mapping = mapping_by_id.get(mapping_id)
        if mapping is None:
            diagnostics.append({
                "code": "mapping_version_unknown",
                "severity": "error",
                "message": f"selected mapping {mapping_id} is not imported",
                "location": {"pair_id": pair["pair_id"],
                             "mapping_id": mapping_id},
            })
            continue
        words = words_from_payload(bytes.fromhex(interval["payload_hex"]))
        if pair["function"] == 6:
            request = frames_by_id[pair["request_id"]]
            words = np.array(
                [request.pdu.write_value if request.pdu else 0], dtype=np.uint16)
        start = interval["register_address_zero_based"]
        quantity = interval["register_quantity"]
        if start is None or quantity is None:
            diagnostics.append({
                "code": "register_address_missing",
                "severity": "error",
                "message": "request PDU has no register address",
                "location": {"pair_id": pair["pair_id"]},
            })
            continue
        covered: dict[int, list[MappingPoint]] = {}
        for reg in range(start, start + quantity):
            covered[reg] = [
                point for point in mapping.points
                if point.register_zero_based <= reg
                < point.register_zero_based + point.register_count
            ]
        decoded_names: set[str] = set()
        for reg, points in covered.items():
            if not points:
                diagnostics.append({
                    "code": "register_unmapped",
                    "severity": "warning",
                    "message": f"register {reg} has no point in {mapping.version}",
                    "location": {"pair_id": pair["pair_id"],
                                 "register_zero_based": reg,
                                 "mapping_id": mapping.mapping_id},
                })
                continue
            for point in points:
                if point.name in decoded_names:
                    continue
                offset = point.register_zero_based - start
                window = words[offset:offset + point.register_count]
                if window.size < point.register_count:
                    diagnostics.append({
                        "code": "register_partial_coverage",
                        "severity": "warning",
                        "message": (
                            f"point {point.name} needs "
                            f"{point.register_count} registers, got {window.size}"),
                        "location": {"pair_id": pair["pair_id"],
                                     "point": point.name},
                        "rule_ids": [RULE_ADDRESS_DISPLAY],
                    })
                    continue
                if point.kind in ("uint32", "int32", "float32"):
                    candidates = decode_32_candidates(window)
                    order = point.word_order or mapping.default_word_order
                    raw_value = candidates[order]
                else:
                    candidates = {}
                    raw_value = _decode_words(window, "abcd", point.kind)
                if raw_value is None:
                    diagnostics.append({
                        "code": "value_undecodable",
                        "severity": "error",
                        "message": f"point {point.name} cannot be decoded",
                        "location": {"pair_id": pair["pair_id"],
                                     "point": point.name},
                    })
                    continue
                physical = float(raw_value) * point.scale + point.offset
                valid, validity_message = _validity(point, physical)
                value_id = stable_id(
                    "val", pair["pair_id"], mapping.mapping_id, point.name,
                    interval["payload_hex"], point.word_order
                    or mapping.default_word_order)
                values.append({
                    "value_id": value_id,
                    "pair_id": pair["pair_id"],
                    "interval_id": interval["interval_id"],
                    "point": point.name,
                    "mapping_id": mapping.mapping_id,
                    "mapping_version": mapping.version,
                    "register_zero_based": point.register_zero_based,
                    "register_display": (point.register_raw, point.address_base),
                    "kind": point.kind,
                    "unit": point.unit,
                    "word_order": point.word_order or mapping.default_word_order,
                    "raw_value": int(raw_value) if isinstance(raw_value, (int, np.integer))
                                 else float(raw_value),
                    "physical_value": physical,
                    "scale": point.scale,
                    "offset": point.offset,
                    "minimum": point.minimum,
                    "maximum": point.maximum,
                    "valid": bool(valid),
                    "validity_reason": validity_message,
                    "candidate_orders": candidates,
                    "timestamp_ns": pair["request_ns"],
                    "rule_ids": [RULE_WORD_ORDER, RULE_ADDRESS_DISPLAY],
                })
                decoded_names.add(point.name)

    return {
        "kind": "interpretation",
        "intervals": intervals,
        "values": values,
        "diagnostics": diagnostics,
        "mapping_selection": mapping_selection,
        "input_summary": {
            "pair_count": len(pairing.get("pairs", [])),
            "mapping_ids": sorted(mapping.mapping_id for mapping in mappings),
            "frame_ids": pairing.get("input_summary", {}).get("frame_ids", []),
        },
        "rule_statements": {
            RULE_ADDRESS_DISPLAY: __import__(
                "domain.parameters", fromlist=["RULE_STATEMENTS"]
            ).RULE_STATEMENTS[RULE_ADDRESS_DISPLAY],
            RULE_WORD_ORDER: __import__(
                "domain.parameters", fromlist=["RULE_STATEMENTS"]
            ).RULE_STATEMENTS[RULE_WORD_ORDER],
            RULE_EXCEPTION: __import__(
                "domain.parameters", fromlist=["RULE_STATEMENTS"]
            ).RULE_STATEMENTS[RULE_EXCEPTION],
        },
    }
