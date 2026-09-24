"""Modbus TCP / RTU byte level parsing.

Only structural decoding lives here: every input ADU keeps its original bytes.
The layer never turns an exception response into successful register data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import Diagnostic, DomainError, FAIL_FORMAT_CORRUPT

EXCEPT_FLAG = 0x80

FUNCTION_NAMES = {
    1: "read_coils",
    2: "read_discrete_inputs",
    3: "read_holding_registers",
    4: "read_input_registers",
    5: "write_single_coil",
    6: "write_single_register",
    8: "diagnostics",
    15: "write_multiple_coils",
    16: "write_multiple_registers",
    23: "read_write_multiple_registers",
}

READ_FUNCS = (1, 2, 3, 4)
WRITE_SINGLE_FUNCS = (5, 6)
WRITE_MULTI_FUNCS = (15, 16)


def crc16(data: bytes) -> int:
    """Modbus RTU CRC-16, polynomial 0xA001, little endian on the wire."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def append_crc(data: bytes) -> bytes:
    crc = crc16(data)
    return data + bytes((crc & 0xFF, (crc >> 8) & 0xFF))


@dataclass
class PDU:
    function: int
    is_exception: bool
    raw_pdu: bytes
    address: int | None = None
    quantity: int | None = None
    byte_count: int | None = None
    data: bytes = b""
    exception_code: int | None = None
    write_value: int | None = None

    @property
    def function_name(self) -> str:
        return FUNCTION_NAMES.get(self.function, f"function_{self.function}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "function_name": self.function_name,
            "is_exception": self.is_exception,
            "address": self.address,
            "address_zero_based": self.address,
            "quantity": self.quantity,
            "byte_count": self.byte_count,
            "data": self.data.hex(),
            "exception_code": self.exception_code,
            "write_value": self.write_value,
        }


@dataclass
class Frame:
    """One observed ADU with direction and source position preserved."""

    frame_id: str
    source: str
    line: int
    transport: str
    direction: str  # request / response
    timestamp_ns: int
    adu_hex: str
    unit_id: int | None = None
    transaction_id: int | None = None
    protocol_id: int | None = None
    pdu: PDU | None = None
    crc_received: int | None = None
    crc_computed: int | None = None
    crc_ok: bool | None = None
    gap_before_ms: float | None = None
    diagnostics: list[Diagnostic] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def adu_bytes(self) -> bytes:
        return bytes.fromhex(self.adu_hex)

    def as_dict(self) -> dict[str, Any]:
        return {
            "frame_id": self.frame_id,
            "source": self.source,
            "line": self.line,
            "transport": self.transport,
            "direction": self.direction,
            "timestamp_ns": self.timestamp_ns,
            "timestamp_s": self.timestamp_ns / 1_000_000_000.0,
            "adu_hex": self.adu_hex,
            "unit_id": self.unit_id,
            "transaction_id": self.transaction_id,
            "protocol_id": self.protocol_id,
            "crc_received": self.crc_received,
            "crc_computed": self.crc_computed,
            "crc_ok": self.crc_ok,
            "gap_before_ms": self.gap_before_ms,
            "pdu": self.pdu.as_dict() if self.pdu else None,
            "diagnostics": [d.as_dict() for d in self.diagnostics],
            "extra": self.extra,
        }


def _parse_pdu(pdu: bytes) -> PDU:
    if not pdu:
        raise ValueError("empty PDU")
    function = pdu[0]
    if function & EXCEPT_FLAG:
        base = function & 0x7F
        if len(pdu) != 2:
            raise ValueError("exception PDU must contain one exception code")
        return PDU(
            function=base,
            is_exception=True,
            raw_pdu=pdu,
            exception_code=pdu[1],
        )
    address = quantity = byte_count = None
    data = b""
    write_value = None
    if function in READ_FUNCS:
        if len(pdu) != 5:
            raise ValueError(f"function {function} request PDU must be 5 bytes")
        address = int.from_bytes(pdu[1:3], "big")
        quantity = int.from_bytes(pdu[3:5], "big")
    elif function in WRITE_SINGLE_FUNCS:
        if len(pdu) != 5:
            raise ValueError(f"function {function} request PDU must be 5 bytes")
        address = int.from_bytes(pdu[1:3], "big")
        write_value = int.from_bytes(pdu[3:5], "big")
    elif function in WRITE_MULTI_FUNCS:
        if len(pdu) < 6:
            raise ValueError(f"function {function} request PDU too short")
        address = int.from_bytes(pdu[1:3], "big")
        quantity = int.from_bytes(pdu[3:5], "big")
        byte_count = pdu[5]
        data = pdu[6:]
        expected = (byte_count + 7) // 8 if function == 15 else byte_count * 2
        if len(data) != expected:
            raise ValueError(
                f"function {function} byte_count {byte_count} disagrees with payload"
            )
    elif function == 23:
        if len(pdu) < 10:
            raise ValueError("function 23 PDU too short")
        # read address/qty then write address/qty/byte-count/data.
        address = int.from_bytes(pdu[1:3], "big")
        quantity = int.from_bytes(pdu[3:5], "big")
        data = pdu[10:]
    else:
        # Keep unknown functions as opaque payload instead of pretending.
        data = pdu[1:]
    return PDU(
        function=function,
        is_exception=False,
        raw_pdu=pdu,
        address=address,
        quantity=quantity,
        byte_count=byte_count,
        data=data,
        write_value=write_value,
    )


def parse_response_pdu(pdu: bytes) -> PDU:
    if not pdu:
        raise ValueError("empty PDU")
    function = pdu[0]
    if function & EXCEPT_FLAG:
        if len(pdu) != 2:
            raise ValueError("exception PDU must contain one exception code")
        return PDU(
            function=function & 0x7F,
            is_exception=True,
            raw_pdu=pdu,
            exception_code=pdu[1],
        )
    if function in READ_FUNCS and function in (3, 4):
        if len(pdu) < 2:
            raise ValueError("register response missing byte count")
        byte_count = pdu[1]
        if len(pdu) != 2 + byte_count:
            raise ValueError("register response length disagrees with byte count")
        return PDU(function, False, pdu, byte_count=byte_count, data=pdu[2:])
    if function in (1, 2):
        if len(pdu) < 2:
            raise ValueError("coil response missing byte count")
        byte_count = pdu[1]
        if len(pdu) != 2 + byte_count:
            raise ValueError("coil response length disagrees with byte count")
        return PDU(function, False, pdu, byte_count=byte_count, data=pdu[2:])
    if function in WRITE_SINGLE_FUNCS or function in WRITE_MULTI_FUNCS:
        if len(pdu) != 5:
            raise ValueError("write echo response must be 5 bytes")
        address = int.from_bytes(pdu[1:3], "big")
        value = int.from_bytes(pdu[3:5], "big")
        return PDU(function, False, pdu, address=address,
                   write_value=value, quantity=value if function == 16 else None)
    if function == 23:
        if len(pdu) < 2:
            raise ValueError("read-write response missing byte count")
        byte_count = pdu[1]
        if len(pdu) != 2 + byte_count:
            raise ValueError("read-write response length disagrees")
        return PDU(function, False, pdu, byte_count=byte_count, data=pdu[2:])
    return PDU(function, False, pdu, data=pdu[1:])


def parse_tcp_frame(adu_hex: str, *, frame_id: str, source: str, line: int,
                    direction: str, timestamp_ns: int,
                    extra: dict[str, Any] | None = None) -> Frame:
    try:
        adu = bytes.fromhex(adu_hex)
    except ValueError as exc:
        raise DomainError(
            FAIL_FORMAT_CORRUPT, "non_hex_adu", f"line {line}: {exc}",
            [Diagnostic("non_hex_adu", str(exc), {"source": source, "line": line})],
        )
    if len(adu) < 8:
        raise DomainError(
            FAIL_FORMAT_CORRUPT, "tcp_adu_short",
            f"line {line}: MBAP header needs 8 bytes, got {len(adu)}",
            [Diagnostic("tcp_adu_short", "ADU shorter than MBAP header",
                        {"source": source, "line": line, "length": len(adu)})],
        )
    transaction_id = int.from_bytes(adu[0:2], "big")
    protocol_id = int.from_bytes(adu[2:4], "big")
    length = int.from_bytes(adu[4:6], "big")
    unit_id = adu[6]
    if protocol_id != 0:
        raise DomainError(
            FAIL_FORMAT_CORRUPT, "bad_protocol_id",
            f"line {line}: Modbus protocol id must be 0, got {protocol_id}",
            [Diagnostic("bad_protocol_id", "MBAP protocol id is not zero",
                        {"source": source, "line": line, "protocol_id": protocol_id})],
        )
    if length != len(adu) - 6:
        raise DomainError(
            FAIL_FORMAT_CORRUPT, "tcp_length_mismatch",
            f"line {line}: MBAP length {length} != payload {len(adu) - 6}",
            [Diagnostic("tcp_length_mismatch", "MBAP length field disagrees",
                        {"source": source, "line": line,
                         "declared": length, "actual": len(adu) - 6})],
        )
    pdu_bytes = adu[7:]
    parser = parse_response_pdu if direction == "response" else _parse_pdu
    try:
        pdu = parser(pdu_bytes)
    except ValueError as exc:
        raise DomainError(
            FAIL_FORMAT_CORRUPT, "bad_pdu", f"line {line}: {exc}",
            [Diagnostic("bad_pdu", str(exc),
                        {"source": source, "line": line})],
        )
    return Frame(
        frame_id=frame_id, source=source, line=line, transport="tcp",
        direction=direction, timestamp_ns=timestamp_ns, adu_hex=adu_hex.lower(),
        unit_id=unit_id, transaction_id=transaction_id, protocol_id=0,
        pdu=pdu, extra=extra or {},
    )


def parse_rtu_frame(adu_hex: str, *, frame_id: str, source: str, line: int,
                    direction: str, timestamp_ns: int,
                    gap_before_ms: float | None = None,
                    extra: dict[str, Any] | None = None) -> Frame:
    try:
        adu = bytes.fromhex(adu_hex)
    except ValueError as exc:
        raise DomainError(
            FAIL_FORMAT_CORRUPT, "non_hex_adu", f"line {line}: {exc}",
            [Diagnostic("non_hex_adu", str(exc), {"source": source, "line": line})],
        )
    frame = Frame(
        frame_id=frame_id, source=source, line=line, transport="rtu",
        direction=direction, timestamp_ns=timestamp_ns, adu_hex=adu_hex.lower(),
        gap_before_ms=gap_before_ms, extra=extra or {},
    )
    if len(adu) < 4:
        frame.diagnostics.append(Diagnostic(
            "rtu_adu_short", "RTU ADU needs address, function and 2 CRC bytes",
            {"source": source, "line": line, "length": len(adu)}))
        return frame
    body, crc_bytes = adu[:-2], adu[-2:]
    crc_received = int.from_bytes(crc_bytes, "little")
    crc_computed = crc16(body)
    frame.unit_id = body[0]
    frame.crc_received = crc_received
    frame.crc_computed = crc_computed
    frame.crc_ok = crc_received == crc_computed
    if not frame.crc_ok:
        frame.diagnostics.append(Diagnostic(
            "crc_mismatch",
            f"line {line}: CRC 0x{crc_received:04x} != computed 0x{crc_computed:04x}",
            {"source": source, "line": line,
             "crc_received": crc_received, "crc_computed": crc_computed}))
        return frame
    parser = parse_response_pdu if direction == "response" else _parse_pdu
    try:
        frame.pdu = parser(body[1:])
    except ValueError as exc:
        frame.diagnostics.append(Diagnostic(
            "bad_pdu", str(exc), {"source": source, "line": line}))
    return frame


def read_register_words(pdu: PDU) -> bytes:
    """Payload bytes for register reads; empty for exceptions/non-data PDU."""
    if pdu.is_exception:
        return b""
    return pdu.data
