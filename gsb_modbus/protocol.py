"""Modbus TCP/RTU ADU and PDU parsing.

Parsers are pure functions of the *original ADU bytes*. They never invent
values: malformed input raises :class:`FormatCorrupt` with a position, while
semantic irregularities (bad CRC, exception response, unknown function code)
are returned as structured fields/diagnostics.
"""

from __future__ import annotations

from .errors import FormatCorrupt
from .model import bytes_to_hex

# Function codes this review room understands at PDU level.
READ_FCS = (1, 2, 3, 4)
READ_HOLDING = 3
READ_INPUT = 4
WRITE_SINGLE = (5, 6)
WRITE_MULTI = (15, 16)
BROADCAST_UNIT = 0

_BIT_FCS = (1, 2)
_REGISTER_FCS = (3, 4, 6, 16)


def crc16(data: bytes) -> int:
    """Modbus RTU CRC-16 (poly 0xA001, init 0xFFFF)."""
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


def _diag(code: str, message: str, position: str, severity: str = "warning") -> dict:
    return {"code": code, "message": message, "position": position, "severity": severity}


def parse_pdu(fc: int, payload: bytes, position: str) -> dict:
    raw_fc = fc
    exception = bool(fc & 0x80)
    out: dict = {
        "function_code": fc & 0x7F if exception else fc,
        "raw_function_code": raw_fc,
        "exception": exception,
        "payload_hex": bytes_to_hex(payload),
        "diagnostics": [],
    }
    if exception:
        if len(payload) < 1:
            raise FormatCorrupt("exception response missing exception code", position)
        out["exception_code"] = payload[0]
        return out

    f = out["function_code"]
    try:
        if f in (1, 2, 3, 4):
            if len(payload) >= 4:
                out["address"] = payload[0] << 8 | payload[1]
                out["quantity"] = payload[2] << 8 | payload[3]
                out["kind"] = "read_request"
            elif payload:
                n = payload[0]
                regs = payload[1:]
                out["kind"] = "read_response"
                out["byte_count"] = n
                if f in _BIT_FCS:
                    if len(regs) < n:
                        out["diagnostics"].append(
                            _diag(
                                "pdu_short",
                                f"bit response declares {n} bytes, has {len(regs)}",
                                position + ".pdu",
                            )
                        )
                    out["bits"] = list(regs[:n])
                else:
                    if len(regs) < n:
                        out["diagnostics"].append(
                            _diag(
                                "pdu_short",
                                f"register response declares {n} bytes, has {len(regs)}",
                                position + ".pdu",
                            )
                        )
                    values = [
                        regs[i] << 8 | regs[i + 1]
                        for i in range(0, min(len(regs) - (len(regs) % 2), n), 2)
                    ]
                    out["registers"] = values
                    if n % 2:
                        out["diagnostics"].append(
                            _diag(
                                "pdu_odd_byte_count",
                                f"register response byte count {n} is odd",
                                position + ".pdu",
                            )
                        )
            else:
                raise FormatCorrupt(f"FC {f} PDU is empty", position)
        elif f in (5, 6):
            if len(payload) != 4:
                raise FormatCorrupt(f"FC {f} requires 4 PDU bytes, got {len(payload)}", position)
            out["kind"] = "write_single_request"
            out["address"] = payload[0] << 8 | payload[1]
            out["value"] = payload[2] << 8 | payload[3]
        elif f in (15, 16):
            if len(payload) >= 5:
                out["kind"] = "write_multi_request"
                out["address"] = payload[0] << 8 | payload[1]
                out["quantity"] = payload[2] << 8 | payload[3]
                out["byte_count"] = payload[4]
                body = payload[5:]
                if f == 16:
                    out["registers"] = [
                        body[i] << 8 | body[i + 1] for i in range(0, len(body) - 1, 2)
                    ]
                else:
                    out["bits"] = list(body)
                if len(body) != out["byte_count"]:
                    out["diagnostics"].append(
                        _diag(
                            "pdu_byte_count_mismatch",
                            f"declares {out['byte_count']} data bytes, has {len(body)}",
                            position + ".pdu",
                        )
                    )
            elif len(payload) == 4:
                out["kind"] = "write_multi_response"
                out["address"] = payload[0] << 8 | payload[1]
                out["quantity"] = payload[2] << 8 | payload[3]
            else:
                raise FormatCorrupt(f"FC {f} PDU too short: {len(payload)} bytes", position)
        elif f == 8:
            out["kind"] = "diagnostics"
        else:
            out["kind"] = "unknown"
            out["diagnostics"].append(
                _diag("unknown_function", f"function code {f} is not interpreted", position + ".pdu")
            )
    except FormatCorrupt:
        raise
    return out


def parse_tcp_adu(data: bytes, position: str) -> dict:
    if len(data) < 8:
        raise FormatCorrupt(
            f"TCP ADU needs at least 8 bytes, got {len(data)}", position + ".adu"
        )
    tid = data[0] << 8 | data[1]
    protocol = data[2] << 8 | data[3]
    length = data[4] << 8 | data[5]
    unit = data[6]
    if protocol != 0:
        raise FormatCorrupt(f"MBAP protocol id must be 0, got {protocol}", position + ".mbap")
    if length < 2:
        raise FormatCorrupt(f"MBAP length {length} must be >= 2", position + ".length")
    if len(data) != 6 + length:
        raise FormatCorrupt(
            f"MBAP length {length} but ADU has {len(data) - 6} trailing bytes",
            position + ".length",
        )
    fc = data[7]
    pdu = bytes(data[8:])
    parsed = parse_pdu(fc, pdu, position + ".pdu")
    return {
        "encapsulation": "tcp",
        "transaction_id": tid,
        "protocol_id": protocol,
        "length": length,
        "unit_id": unit,
        **parsed,
    }


def parse_rtu_adu(data: bytes, position: str, *, verify_crc: bool = True) -> dict:
    if len(data) < 4:
        raise FormatCorrupt(
            f"RTU ADU needs at least 4 bytes, got {len(data)}", position + ".adu"
        )
    unit = data[0]
    fc = data[1]
    body = bytes(data[2:-2])
    given_crc = data[-2] | (data[-1] << 8)
    calc_crc = crc16(bytes(data[:-2]))
    parsed = parse_pdu(fc, body, position + ".pdu")
    parsed.update(
        {
            "encapsulation": "rtu",
            "unit_id": unit,
            "crc": {
                "frame_crc": f"0x{given_crc:04X}",
                "computed_crc": f"0x{calc_crc:04X}",
                "valid": given_crc == calc_crc,
            },
        }
    )
    if verify_crc and given_crc != calc_crc:
        parsed["diagnostics"].append(
            _diag(
                "rtu_crc_mismatch",
                f"frame CRC 0x{given_crc:04X} != computed 0x{calc_crc:04X}",
                position + ".crc",
            )
        )
    return parsed
