from __future__ import annotations

from datetime import datetime
from typing import Any

from .errors import IncompleteInput, MalformedInput, ProtocolError
from .protocol import READ_FUNCS, WRITE_MULTI_FUNCS, WRITE_SINGLE_FUNCS, frame_to_dict, materialize_frame, words_to_uint32

BROADCAST_UNIT = 0


def parse_time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError as exc:
        raise MalformedInput("observed_at must be ISO-8601", "$.observed_at") from exc


def default_params() -> dict[str, Any]:
    return {
        "parameter_version": "params-v1",
        "tcp_match": "transaction_id_unit_connection_generation",
        "rtu_match": "serial_turn_silence_unit_function",
        "rtu_silence_interval_s": 0.20,
        "rtu_response_deadline_s": 1.00,
        "display_address_base": 0,
        "byte_order": "big",
        "word_order": "high_low",
    }


def validate_params(params):
    allowed = set(default_params())
    if not isinstance(params, dict):
        raise MalformedInput("params must be an object", "$.params")
    unknown = sorted(set(params) - allowed)
    if unknown:
        raise MalformedInput("unknown parameter", f"$.params.{unknown[0]}")
    for key in ("rtu_silence_interval_s", "rtu_response_deadline_s"):
        if key in params and (not isinstance(params[key], (int, float)) or params[key] <= 0):
            raise MalformedInput("timing parameter must be positive", f"$.params.{key}")
    if "display_address_base" in params and params["display_address_base"] not in (0, 1):
        raise MalformedInput("display base must be 0 or 1", "$.params.display_address_base")
    if "byte_order" in params and params["byte_order"] not in ("big", "little"):
        raise MalformedInput("byte order must be big or little", "$.params.byte_order")
    if "word_order" in params and params["word_order"] not in ("high_low", "low_high"):
        raise MalformedInput("word order must be high_low or low_high", "$.params.word_order")
    merged = default_params()
    merged.update(params)
    return merged


def normalize_case(data: dict[str, Any], budget=None) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise MalformedInput("case must be an object", "$")
    required = ["case_id", "materials", "parameter_versions", "mapping_versions"]
    missing = [key for key in required if key not in data]
    if missing:
        raise IncompleteInput("case is incomplete", f"$.{','.join(missing)}")
    if not isinstance(data["materials"], dict) or not isinstance(data["materials"].get("frames"), list):
        raise MalformedInput("materials.frames must be a list", "$.materials.frames")
    limit = budget or 5000
    if len(data["materials"]["frames"]) > limit:
        from .errors import BudgetExhausted
        raise BudgetExhausted("frame resource budget exhausted", "$.materials.frames")
    frames = []
    diagnostics = []
    for index, raw_frame in enumerate(data["materials"]["frames"]):
        try:
            frame = materialize_frame(raw_frame, index)
            frames.append(frame)
        except ProtocolError as exc:
            diagnostics.append(exc.to_dict() | {"material_ref": raw_frame.get("material_id", f"frame-{index}") if isinstance(raw_frame, dict) else f"frame-{index}"})
    frames.sort(key=lambda frame: (frame.observed_at, frame.ordinal, frame.material_id))
    events = []
    for item in data["materials"].get("connection_events", []):
        events.append(normalize_connection_event(item))
    serial = []
    for item in data["materials"].get("serial_events", []):
        serial.append(normalize_serial_event(item))
    mappings = normalize_mappings(data["mapping_versions"])
    param_sets = normalize_parameter_versions(data["parameter_versions"])
    return {
        "case_id": str(data["case_id"]),
        "frames": frames,
        "connection_events": events,
        "serial_events": serial,
        "mappings": mappings,
        "parameter_versions": param_sets,
        "diagnostics": diagnostics,
    }


def normalize_connection_event(item):
    if not isinstance(item, dict):
        raise MalformedInput("connection event must be object", "$.materials.connection_events")
    for key in ("event_id", "observed_at", "connection_id", "generation", "kind"):
        if key not in item:
            raise IncompleteInput("connection event is incomplete", f"$.materials.connection_events.{key}")
    if item["kind"] not in ("open", "close", "reopen"):
        raise MalformedInput("connection event kind unsupported", "$.materials.connection_events.kind")
    return dict(item)


def normalize_serial_event(item):
    if not isinstance(item, dict):
        raise MalformedInput("serial event must be object", "$.materials.serial_events")
    for key in ("event_id", "observed_at", "serial_bus", "kind"):
        if key not in item:
            raise IncompleteInput("serial event is incomplete", f"$.materials.serial_events.{key}")
    if item["kind"] not in ("silence", "noise", "turn_boundary"):
        raise MalformedInput("serial event kind unsupported", "$.materials.serial_events.kind")
    return dict(item)


def normalize_parameter_versions(items):
    if not isinstance(items, list) or not items:
        raise MalformedInput("parameter_versions must be a non-empty list", "$.parameter_versions")
    result = []
    for index, item in enumerate(items):
        if not isinstance(item, dict) or "parameter_version" not in item:
            raise MalformedInput("parameter version requires id", f"$.parameter_versions[{index}]")
        result.append(validate_params(item))
    return result


def normalize_mappings(items):
    if not isinstance(items, list) or not items:
        raise MalformedInput("mapping_versions must be a non-empty list", "$.mapping_versions")
    result = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise MalformedInput("mapping must be object", f"$.mapping_versions[{index}]")
        for key in ("mapping_version", "address_base", "register_type", "fields"):
            if key not in item:
                raise IncompleteInput("mapping is incomplete", f"$.mapping_versions[{index}].{key}")
        if item["address_base"] not in (0, 1):
            raise MalformedInput("mapping address_base must be 0 or 1", f"$.mapping_versions[{index}].address_base")
        fields = []
        for field_index, field in enumerate(item["fields"]):
            for key in ("field_id", "start_address", "length", "data_type", "unit", "valid_range"):
                if key not in field:
                    raise IncompleteInput("mapping field is incomplete", f"$.mapping_versions[{index}].fields[{field_index}].{key}")
            fields.append(dict(field))
        result[item["mapping_version"]] = dict(item, fields=fields)
    return result


def derive(case: dict[str, Any], params: dict[str, Any], accepted=None, rejected=None) -> dict[str, Any]:
    frames = case["frames"]
    accepted = set(accepted or [])
    rejected = set(rejected or [])
    tcp_pairs, tcp_unpaired, tcp_rules = pair_tcp(frames, case.get("connection_events", []), params, accepted, rejected)
    rtu_pairs, rtu_unpaired, rtu_rules = pair_rtu(frames, params, accepted, rejected)
    pairs = tcp_pairs + rtu_pairs
    unpaired = tcp_unpaired + rtu_unpaired
    rules = tcp_rules + rtu_rules
    registers, decode_diagnostics = decode_pairs(pairs, case["mappings"], params)
    return {
        "pairs": sorted(pairs, key=lambda item: (item["response"]["observed_at"], item["stable_id"])),
        "unpaired": sorted(unpaired, key=lambda item: (item["observed_at"], item["stable_id"])),
        "registers": sorted(registers, key=lambda item: (item["mapping_version"], item["zero_start_address"], item["stable_id"])),
        "rule_events": rules,
        "diagnostics": case.get("diagnostics", []) + decode_diagnostics,
    }

def pair_key(frame):
    if frame.transport == "tcp":
        return f"tcp:{frame.connection_id}:gen{frame.generation}:tid{frame.transaction_id}:unit{frame.unit_id}"
    return f"rtu:{frame.serial_bus or 'bus'}:gen{frame.generation}:unit{frame.unit_id}:func{frame.function}"


def make_pair(request, response, params, status="matched", candidates=None, rule="", override=None):
    pair_id = f"pair:{request.material_id}->{response.material_id}"
    return {
        "stable_id": pair_id,
        "status": status,
        "pairing_rule": rule,
        "transport": request.transport,
        "connection_id": request.connection_id,
        "serial_bus": request.serial_bus,
        "generation": request.generation,
        "transaction_id": request.transaction_id,
        "unit_id": request.unit_id,
        "function": request.function,
        "request": frame_to_dict(request),
        "response": frame_to_dict(response),
        "candidate_requests": candidates or [request.material_id],
        "parameter_version": params["parameter_version"],
        "human_override": override,
    }


def corrupt_reasons(frame):
    reasons = []
    if not frame.crc_valid:
        reasons.append("rtu_crc_invalid")
    if frame.parse_diagnostic:
        reasons.append(frame.parse_diagnostic["kind"])
    return reasons


def pair_tcp(frames, connection_events, params, accepted, rejected):
    pairs = []
    unpaired = []
    rules = []
    requests = [f for f in frames if f.transport == "tcp" and f.direction == "request"]
    responses = [f for f in frames if f.transport == "tcp" and f.direction == "response"]
    open_requests = {}
    closed_keys = set()
    for frame in requests:
        key = pair_key(frame)
        if frame.unit_id == BROADCAST_UNIT:
            unpaired.append(unpaired_dict(frame, "tcp_broadcast_no_response", params, "tcp_broadcast_no_response"))
            rules.append(rule_event(frame, "tcp_transaction_rule", "broadcast has no Modbus TCP response; request remains unpaired", "adopted"))
            continue
        reasons = corrupt_reasons(frame)
        if reasons:
            unpaired.append(unpaired_dict(frame, "+".join(reasons), params, "frame_not_eligible"))
            continue
        if key in open_requests:
            old = open_requests[key]
            unpaired.append(unpaired_dict(old, "tcp_transaction_id_reused_before_response", params, "tcp_transaction_id_rule"))
            rules.append(rule_event(old, "tcp_transaction_rule", "a later request reused the transaction id before a response arrived", "adopted"))
        open_requests[key] = frame
    for response in responses:
        key = pair_key(response)
        reasons = corrupt_reasons(response)
        if response.unit_id == BROADCAST_UNIT:
            unpaired.append(unpaired_dict(response, "tcp_broadcast_response_unexpected", params, "tcp_broadcast_no_response"))
            rules.append(rule_event(response, "tcp_transaction_rule", "unit 0 must not produce a broadcast response", "adopted"))
            continue
        if reasons:
            unpaired.append(unpaired_dict(response, "+".join(reasons), params, "frame_not_eligible"))
            continue
        request = open_requests.get(key)
        reopened = request is not None and connection_reopened_between(request, response, connection_events)
        if reopened:
            unpaired.append(unpaired_dict(request, "tcp_connection_reopened", params, "tcp_connection_generation_rule"))
            rules.append(rule_event(request, "tcp_connection_generation_rule", "a connection reopen ended the older request generation", "adopted"))
            open_requests.pop(key, None)
            request = None
        if not request:
            reason = "tcp_connection_reopened" if reopened else "tcp_response_without_open_transaction"
            unpaired.append(unpaired_dict(response, reason, params, "tcp_connection_generation_rule" if reopened else "tcp_transaction_id_rule"))
            rules.append(rule_event(response, "tcp_connection_generation_rule" if reopened else "tcp_transaction_id_rule", "response cannot leave the reopened generation", "adopted"))
            continue
        del open_requests[key]
        closed_keys.add(key)
        status = "exception" if response.is_exception else "matched"
        pair = make_pair(request, response, params, status=status, rule="tcp_transaction_id_unit_connection_generation")
        apply_human(pair, accepted, rejected)
        pairs.append(pair)
        rules.append(rule_event(response, "tcp_transaction_rule", "matched by transaction id, unit id, connection id and connection generation", "adopted", pair["stable_id"]))
        if response.is_exception:
            rules.append(rule_event(response, "exception_is_not_success", "exception response is paired but never interpreted as successful empty data", "adopted", pair["stable_id"]))
    for key, frame in open_requests.items():
        unpaired.append(unpaired_dict(frame, "request_timeout_no_response", params, "tcp_transaction_id_rule"))
    return pairs, unpaired, rules


def pair_rtu(frames, params, accepted, rejected):
    pairs = []
    unpaired = []
    rules = []
    rtu = sorted([f for f in frames if f.transport == "rtu"], key=lambda frame: (frame.observed_at, frame.ordinal, frame.material_id))
    active = {}
    last_turn_end = None
    silence = float(params["rtu_silence_interval_s"])
    deadline = float(params["rtu_response_deadline_s"])
    for frame in rtu:
        key = pair_key(frame)
        reasons = corrupt_reasons(frame)
        if reasons:
            unpaired.append(unpaired_dict(frame, "+".join(reasons), params, "frame_not_eligible"))
            continue
        current = parse_time(frame.observed_at)
        if frame.direction == "request":
            if frame.unit_id == BROADCAST_UNIT:
                active[key] = frame
                unpaired.append(unpaired_dict(frame, "rtu_broadcast_no_response", params, "rtu_broadcast_rule"))
                rules.append(rule_event(frame, "rtu_broadcast_rule", "RTU unit 0 is broadcast; no slave may answer", "adopted"))
                continue
            if key in active and last_turn_end is None or key in active and current - parse_time(active[key].observed_at) < silence:
                pass
            active[key] = frame
        else:
            if frame.unit_id == BROADCAST_UNIT:
                unpaired.append(unpaired_dict(response, "rtu_broadcast_response_unexpected", params, "rtu_broadcast_rule"))
                continue
            candidates = []
            if key in active:
                candidate = active[key]
                age = current - parse_time(candidate.observed_at)
                if age <= deadline:
                    candidates.append(candidate)
            if not candidates:
                unpaired.append(unpaired_dict(frame, "rtu_response_without_recent_turn", params, "rtu_silence_interval_rule"))
                rules.append(rule_event(frame, "rtu_silence_interval_rule", "RTU response lacks a request in the current serial turn", "adopted"))
                continue
            chosen = candidates[-1]
            pair = make_pair(chosen, frame, params, status=("exception" if frame.is_exception else "matched"), candidates=[c.material_id for c in candidates], rule="rtu_serial_turn_silence_unit_function")
            apply_human(pair, accepted, rejected)
            pairs.append(pair)
            rules.append(rule_event(frame, "rtu_silence_interval_rule", "matched by serial turn separated by silence, unit id and function echo", "adopted", pair["stable_id"]))
            if frame.is_exception:
                rules.append(rule_event(frame, "exception_is_not_success", "exception response is paired but not successful empty data", "adopted", pair["stable_id"]))
            active.pop(key, None)
            last_turn_end = current
    for key, frame in active.items():
        if frame.unit_id != BROADCAST_UNIT:
            unpaired.append(unpaired_dict(frame, "rtu_turn_closed_without_response", params, "rtu_silence_interval_rule"))
    return pairs, unpaired, rules

def unpaired_dict(frame, reason, params, rule):
    data = frame_to_dict(frame)
    data.update({
        "stable_id": f"unpaired:{frame.material_id}",
        "reason_code": reason,
        "parameter_version": params["parameter_version"],
        "pairing_rule": rule,
    })
    return data


def rule_event(frame, rule_code, judgment, adoption, pair_id=None):
    return {
        "stable_id": f"rule:{frame.material_id}:{rule_code}",
        "rule_code": rule_code,
        "judgment": judgment,
        "adoption": adoption,
        "material_ref": frame.material_id,
        "pair_ref": pair_id,
        "observed_at": frame.observed_at,
    }


def apply_human(pair, accepted, rejected):
    pair_id = pair["stable_id"]
    if pair_id in accepted:
        pair["status"] = "accepted"
        pair["human_override"] = "accepted"
    elif pair_id in rejected:
        pair["status"] = "rejected"
        pair["human_override"] = "rejected"


def decode_pairs(pairs, mappings, params):
    registers = []
    diagnostics = []
    for pair in pairs:
        if pair["status"] == "exception" or pair["response"].get("is_exception"):
            diagnostics.append({
                "kind": "exception_not_success",
                "path": f"$.pairs[{pair['stable_id']}].response",
                "message": f"exception code 0x{pair['response'].get('exception_code', 0):02X} is retained and not decoded",
                "pair_ref": pair["stable_id"],
            })
            continue
        mapping = mappings.get(pair["response"].get("mapping_version") or pair["request"].get("mapping_version"))
        if mapping is None:
            diagnostics.append({"kind": "mapping_missing", "path": f"$.pairs[{pair['stable_id']}]", "message": "mapping version is absent", "pair_ref": pair["stable_id"], "value_retained": True})
            continue
        request = pair["request"]
        response = pair["response"]
        start = request.get("address")
        quantity = request.get("quantity")
        if start is None or quantity is None:
            diagnostics.append({"kind": "address_or_quantity_missing", "path": f"$.pairs[{pair['stable_id']}]", "message": "cannot derive register interval", "pair_ref": pair["stable_id"], "value_retained": True})
            continue
        zero_start = start - int(mapping["address_base"]) if mapping["address_base"] else start
        if zero_start < 0 or zero_start + quantity > 65536:
            diagnostics.append({"kind": "register_interval_outside_address_space", "path": f"$.pairs[{pair['stable_id']}].interval", "message": "zero-based interval is outside 0..65535", "pair_ref": pair["stable_id"], "raw_start_address": start, "value_retained": True})
            continue
        words = response.get("values") if pair["function"] in READ_FUNCS else request.get("values", [])
        if pair["function"] in WRITE_MULTI_FUNCS and not words:
            words = [None] * quantity
        interval_id = f"interval:{pair['stable_id']}:{mapping['mapping_version']}:{zero_start}:{quantity}"
        registers.append({
            "stable_id": interval_id,
            "pair_ref": pair["stable_id"],
            "mapping_version": mapping["mapping_version"],
            "register_type": mapping.get("register_type"),
            "zero_start_address": zero_start,
            "display_start_address": zero_start + int(params["display_address_base"]),
            "address_base_source": mapping["address_base"],
            "display_address_base": params["display_address_base"],
            "quantity": quantity,
            "unit": "register16",
            "coordinate_basis": "Modbus zero-based protocol address; display conversion only",
            "valid_interval": {"zero_start": zero_start, "zero_end": zero_start + quantity - 1, "display_start": zero_start + int(params["display_address_base"]), "display_end": zero_start + quantity - 1 + int(params["display_address_base"])},
            "words": words,
            "fields": decode_fields(mapping, zero_start, quantity, words, params, pair["stable_id"], diagnostics),
            "parameter_version": params["parameter_version"],
            "parent_dependencies": [pair["request"]["material_id"], pair["response"]["material_id"], mapping["mapping_version"], params["parameter_version"]],
            "input_summary": {"adu_request": request["adu_hex"], "adu_response": response["adu_hex"], "function": pair["function"], "word_count": quantity},
        })
    return registers, diagnostics


def decode_fields(mapping, zero_start, quantity, words, params, pair_ref, diagnostics):
    decoded = []
    zero_end = zero_start + quantity - 1
    for field in mapping["fields"]:
        f_start = int(field["start_address"]) - int(mapping["address_base"])
        f_end = f_start + int(field["length"]) - 1
        if f_end < zero_start or f_start > zero_end:
            continue
        local_start = f_start - zero_start
        local_end = local_start + int(field["length"]) - 1
        selected = words[local_start:local_end + 1] if local_start >= 0 and local_end < len(words) else []
        if len(selected) != int(field["length"]):
            diagnostics.append({"kind": "register_window_incomplete", "path": f"$.mappings.{mapping['mapping_version']}.fields.{field['field_id']}", "message": "field cannot be converted; raw words retained", "pair_ref": pair_ref, "raw_words": words, "value_retained": True})
            value = None
            valid = False
            failure = "register_window_incomplete"
        else:
            value, valid, failure = convert_field(field, selected, params)
            if failure:
                diagnostics.append({"kind": failure, "path": f"$.mappings.{mapping['mapping_version']}.fields.{field['field_id']}", "message": "value retained with diagnostic rather than dropped", "pair_ref": pair_ref, "raw_words": selected, "value_retained": True})
        decoded.append({
            "stable_id": f"field:{pair_ref}:{mapping['mapping_version']}:{field['field_id']}",
            "field_id": field["field_id"],
            "zero_start_address": f_start,
            "display_start_address": f_start + int(params["display_address_base"]),
            "length": int(field["length"]),
            "unit": field.get("unit"),
            "coordinate_basis": field.get("coordinate_basis", "Modbus zero-based register address"),
            "value": value,
            "raw_words": selected,
            "is_valid": bool(valid),
            "failure_reason": failure,
            "valid_range": field.get("valid_range"),
            "byte_order": params["byte_order"],
            "word_order": params["word_order"],
        })
    return decoded


def convert_field(field, words, params):
    try:
        length = int(field["length"])
        if length == 1:
            value = int(words[0])
            byte_order = field.get("byte_order", params["byte_order"])
            if byte_order == "little":
                value = int.from_bytes(int(words[0]).to_bytes(2, "big"), "little")
        elif length == 2 and field["data_type"] == "uint32":
            value = words_to_uint32(words, field.get("byte_order", params["byte_order"]), field.get("word_order", params["word_order"]))
        else:
            return None, False, "unsupported_field_type"
        valid_range = field.get("valid_range", {})
        if "min" in valid_range and value < valid_range["min"]:
            return value, False, "value_below_valid_range"
        if "max" in valid_range and value > valid_range["max"]:
            return value, False, "value_above_valid_range"
        scale = field.get("scale", 1)
        offset = field.get("offset", 0)
        return value * scale + offset, True, None
    except (TypeError, ValueError, OverflowError):
        return None, False, "value_not_convertible"
