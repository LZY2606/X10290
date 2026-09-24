from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from .errors import MalformedInput

READ_FUNCS = {1, 2, 3, 4}
WRITE_SINGLE_FUNCS = {5, 6}
WRITE_MULTI_FUNCS = {15, 16}


def stable_event_order(items):
    return sorted(items, key=lambda item: (str(item.get("observed_at", "")), int(item.get("ordinal", 0)), str(item.get("material_id", ""))))


def parse_hex(value, path):
    if isinstance(value, int):
        return bytes_from_int(value, path)
    if isinstance(value, list):
        try:
            raw = bytes(int(x) for x in value)
        except (TypeError, ValueError) as exc:
            raise MalformedInput("ADU bytes must be byte values", path) from exc
        return raw
    if not isinstance(value, str):
        raise MalformedInput("ADU bytes must be a hex string or byte array", path)
    text = value.removeprefix("0x").replace(" ", "").replace("-", "")
    if len(text) % 2 or any(c not in "0123456789abcdefABCDEF" for c in text):
        raise MalformedInput("ADU bytes are not valid hexadecimal", path)
    return bytes.fromhex(text)


def bytes_from_int(value, path):
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise MalformedInput("numeric ADU must be between 0 and 2**64-1", path)
    width = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(width, "big")


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


@dataclass(frozen=True)
class Frame:
    material_id: str
    ordinal: int
    observed_at: str
    transport: str
    direction: str
    connection_id: str
    generation: int
    unit_id: int
    function: int
    is_exception: bool
    exception_code: int | None
    transaction_id: int | None
    protocol_id: int | None
    address: int | None
    quantity: int | None
    values: tuple[int, ...]
    raw: bytes
    crc_present: bool
    crc_stored: int | None
    crc_valid: bool
    address_base: int | None
    mapping_version: str | None
    serial_bus: str | None
    parse_diagnostic: dict[str, Any] | None


def require_keys(obj, keys, path):
    if not isinstance(obj, dict):
        raise MalformedInput("event must be an object", path)
    missing = [key for key in keys if key not in obj]
    if missing:
        raise MalformedInput("missing required fields", f"{path}.{','.join(missing)}")


def materialize_frame(item, ordinal=None):
    path = f"$.materials.frames[{ordinal if ordinal is not None else item.get('ordinal', '?')}]"
    require_keys(item, ["material_id", "observed_at", "transport", "direction", "connection_id", "generation", "unit_id", "adu", "address_base", "mapping_version"], path)
    raw = parse_hex(item["adu"], f"{path}.adu")
    transport = str(item["transport"]).lower()
    if transport not in {"tcp", "rtu"}:
        raise MalformedInput("transport must be tcp or rtu", f"{path}.transport")
    direction = str(item["direction"]).lower()
    if direction not in {"request", "response"}:
        raise MalformedInput("direction must be request or response", f"{path}.direction")
    base = item.get("address_base")
    if base not in (0, 1):
        raise MalformedInput("address_base must be 0 or 1", f"{path}.address_base")
    generation = int(item["generation"])
    unit_id = int(item["unit_id"])
    ordinal_value = int(item.get("ordinal", ordinal or 0))
    parse_diagnostic = None
    crc_present = False
    crc_stored = None
    crc_valid = True
    try:
        if transport == "tcp":
            if len(raw) < 8:
                raise MalformedInput("TCP ADU requires MBAP and PDU", f"{path}.adu")
            transaction_id = int.from_bytes(raw[0:2], "big")
            protocol_id = int.from_bytes(raw[2:4], "big")
            length = int.from_bytes(raw[4:6], "big")
            if protocol_id != 0 or len(raw) != 6 + length or raw[6] != unit_id:
                raise MalformedInput("invalid MBAP header or unit id", f"{path}.adu")
            pdu = raw[7:]
        else:
            if len(raw) < 5:
                raise MalformedInput("RTU ADU requires address, PDU and CRC", f"{path}.adu")
            transaction_id = item.get("transaction_id")
            if transaction_id is not None:
                transaction_id = int(transaction_id)
            protocol_id = None
            if raw[0] != unit_id:
                raise MalformedInput("RTU address does not match unit_id", f"{path}.adu")
            crc_present = True
            crc_stored = int.from_bytes(raw[-2:], "little")
            crc_valid = crc16(raw[:-2]) == crc_stored
            pdu = raw[1:-2]
        function_code, address, quantity, values, is_exception, exception_code = parse_pdu(pdu, direction)
    except MalformedInput as exc:
        parse_diagnostic = exc.to_dict()
        function_code = pdu[0] if transport == "tcp" and len(raw) > 7 else raw[1] if transport == "rtu" and len(raw) > 1 else 0
        address = quantity = None
        values = ()
        is_exception = function_code >= 0x80
        exception_code = pdu[1] if is_exception and len(pdu) > 1 else None
        if transport == "tcp":
            transaction_id = int.from_bytes(raw[0:2], "big") if len(raw) >= 2 else None
            protocol_id = int.from_bytes(raw[2:4], "big") if len(raw) >= 4 else None
    return Frame(
        material_id=str(item["material_id"]), ordinal=ordinal_value, observed_at=str(item["observed_at"]),
        transport=transport, direction=direction, connection_id=str(item["connection_id"]), generation=generation,
        unit_id=unit_id, function=function_code, is_exception=is_exception, exception_code=exception_code,
        transaction_id=transaction_id, protocol_id=protocol_id, address=address, quantity=quantity,
        values=tuple(int(v) for v in values), raw=raw, crc_present=crc_present, crc_stored=crc_stored,
        crc_valid=crc_valid, address_base=base, mapping_version=str(item["mapping_version"]),
        serial_bus=item.get("serial_bus"), parse_diagnostic=parse_diagnostic,
    )


def parse_pdu(pdu, direction):
    if not pdu:
        raise MalformedInput("empty PDU", "$.pdu")
    code = pdu[0]
    is_exception = code >= 0x80
    function = code - 0x80 if is_exception else code
    if is_exception:
        if len(pdu) != 2:
            raise MalformedInput("exception PDU must contain function and exception code", "$.pdu")
        return function, None, None, (), True, pdu[1]
    if direction == "request":
        if function in READ_FUNCS or function in WRITE_MULTI_FUNCS:
            if len(pdu) < 5:
                raise MalformedInput("request PDU is truncated", "$.pdu")
            address = int.from_bytes(pdu[1:3], "big")
            quantity = int.from_bytes(pdu[3:5], "big")
            values = []
            if function in WRITE_MULTI_FUNCS:
                if len(pdu) < 6 or pdu[5] != quantity * 2 or len(pdu) != 6 + pdu[5]:
                    raise MalformedInput("write-multiple byte count does not match quantity", "$.pdu")
                values = [int.from_bytes(pdu[i:i + 2], "big") for i in range(6, len(pdu), 2)]
            return function, address, quantity, values, False, None
        if function in WRITE_SINGLE_FUNCS:
            if len(pdu) != 5:
                raise MalformedInput("single-write PDU must contain address and value", "$.pdu")
            return function, int.from_bytes(pdu[1:3], "big"), 1, (int.from_bytes(pdu[3:5], "big"),), False, None
        raise MalformedInput(f"unsupported function code {function}", "$.pdu.function")
    if function in READ_FUNCS:
        if len(pdu) < 2 or pdu[1] != len(pdu) - 2:
            raise MalformedInput("read response byte count is invalid", "$.pdu")
        values = [int.from_bytes(pdu[i:i + 2], "big") for i in range(2, len(pdu), 2)]
        return function, None, len(values), values, False, None
    if function in WRITE_SINGLE_FUNCS:
        if len(pdu) != 5:
            raise MalformedInput("single-write response is truncated", "$.pdu")
        return function, int.from_bytes(pdu[1:3], "big"), 1, (int.from_bytes(pdu[3:5], "big"),), False, None
    if function in WRITE_MULTI_FUNCS:
        if len(pdu) != 5:
            raise MalformedInput("write-multiple echo is truncated", "$.pdu")
        return function, int.from_bytes(pdu[1:3], "big"), int.from_bytes(pdu[3:5], "big"), (), False, None
    raise MalformedInput(f"unsupported function code {function}", "$.pdu.function")


def frame_to_dict(frame: Frame) -> dict[str, Any]:
    result = {
        "stable_id": frame.material_id,
        "material_id": frame.material_id,
        "ordinal": frame.ordinal,
        "observed_at": frame.observed_at,
        "transport": frame.transport,
        "direction": frame.direction,
        "connection_id": frame.connection_id,
        "generation": frame.generation,
        "unit_id": frame.unit_id,
        "function": frame.function,
        "is_exception": frame.is_exception,
        "exception_code": frame.exception_code,
        "transaction_id": frame.transaction_id,
        "protocol_id": frame.protocol_id,
        "address": frame.address,
        "quantity": frame.quantity,
        "values": list(frame.values),
        "adu_hex": frame.raw.hex(" "),
        "adu_bytes": list(frame.raw),
        "crc_present": frame.crc_present,
        "crc_stored": crc_hex(frame.crc_stored),
        "crc_valid": frame.crc_valid,
        "address_base": frame.address_base,
        "mapping_version": frame.mapping_version,
        "serial_bus": frame.serial_bus,
    }
    if frame.parse_diagnostic:
        result["diagnostic"] = frame.parse_diagnostic
    return result


def crc_hex(value):
    return None if value is None else f"0x{value:04X}"


def make_tcp_adu(transaction_id, unit_id, pdu: bytes) -> bytes:
    return transaction_id.to_bytes(2, "big") + b"\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + bytes([unit_id]) + pdu


def make_rtu_adu(unit_id, pdu: bytes) -> bytes:
    body = bytes([unit_id]) + pdu
    crc = crc16(body)
    return body + crc.to_bytes(2, "little")


def words_to_uint32(words, byte_order, word_order):
    ordered = list(words[:2])
    if word_order == "low_high":
        ordered.reverse()
    packed = b"".join(int(word & 0xFFFF).to_bytes(2, "big") for word in ordered)
    dtype = ">u4" if byte_order == "big" else "<u4"
    if byte_order == "little":
        packed = packed[::-1]
    return int(np.frombuffer(packed, dtype=np.dtype(dtype))[0])


def display_address(zero_address, base):
    if zero_address is None:
        return None
    if base not in (0, 1):
        raise MalformedInput("display address base must be 0 or 1", "$.params.display_address_base")
    return zero_address + base
