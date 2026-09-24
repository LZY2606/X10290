"""Turn raw serial byte events into RTU frames using silent intervals.

This implements the RTU pairing rule distinct from TCP transaction ids: frame
boundaries come from the >= 3.5 character-time gap between bytes. The framing
mode is a parameter version, so a parameter revision can change boundaries.
"""

from __future__ import annotations

from .errors import FormatCorrupt
from .model import bytes_to_hex
from .protocol import crc16

STANDARD_FIXED_BAUD = 19200


def char_time_seconds(baud: int) -> float:
    return 11.0 / float(baud)


def framing_thresholds(params: dict) -> tuple[float, float]:
    """Return (t1.5, t3.5) inter-byte gaps in seconds for the parameters."""
    baud = int(params.get("baud", 9600))
    mode = params.get("framing", "standard")
    ct = char_time_seconds(baud)
    if mode == "fixed1750" or (mode == "standard" and baud > STANDARD_FIXED_BAUD):
        return 1.75e-3, 3.5 * ct if mode != "fixed1750" else 1.75e-3
    return 1.5 * ct, 3.5 * ct


def parse_bus(events: list[dict], params: dict, *, position: str) -> list[dict]:
    """Group serial events into frames.

    Each event: {"t": float seconds (bus time base), "dir": "m2s"|"s2m",
                  "hex": "aa bb", "source": "serial-capture-id"}
    """
    t1_5, t3_5 = framing_thresholds(params)
    frames: list[dict] = []
    current: dict | None = None

    def finish(frame: dict) -> None:
        data = bytes(frame["data"])
        frame["adu_hex"] = bytes_to_hex(data)
        frame["length"] = len(data)
        if len(data) >= 4:
            given = data[-2] | (data[-1] << 8)
            calc = crc16(data[:-2])
            frame["crc"] = {
                "frame_crc": f"0x{given:04X}",
                "computed_crc": f"0x{calc:04X}",
                "valid": given == calc,
            }
        else:
            frame["crc"] = None
            frame.setdefault("diagnostics", []).append(
                {
                    "code": "rtu_frame_too_short",
                    "message": f"frame has only {len(data)} bytes",
                    "position": position + f".t={frame['t0']}",
                    "severity": "error",
                }
            )
        frames.append(frame)

    for idx, event in enumerate(events):
        if not isinstance(event, dict) or "hex" not in event or "t" not in event:
            raise FormatCorrupt(
                f"serial event #{idx} needs numeric t and hex",
                position=f"{position}[{idx}]",
            )
        from .model import hex_to_bytes

        chunk = hex_to_bytes(event["hex"], position=f"{position}[{idx}].hex")
        direction = event.get("dir", "m2s")
        t = float(event["t"])
        if current is not None:
            same_dir = current["dir"] == direction
            gap = t - current["last_t"]
            if not same_dir or gap >= t3_5:
                finish(current)
                current = None
            elif gap > t1_5:
                # Between 1.5 and 3.5 char times the frame is suspect; Modbus
                # treats it as corrupt. Record it as a diagnostic, keep bytes.
                current.setdefault("diagnostics", []).append(
                    {
                        "code": "rtu_gap_1_5_to_3_5",
                        "message": f"gap {gap * 1000:.3f} ms inside frame",
                        "position": position + f"[t={t:.6f}]",
                        "severity": "warning",
                    }
                )
        if current is None:
            current = {
                "dir": direction,
                "t0": t,
                "last_t": t,
                "data": bytearray(),
                "source_events": [],
                "diagnostics": [],
            }
        current["data"].extend(chunk)
        current["source_events"].append(event.get("event_id", idx))
        current["last_t"] = t
    if current is not None:
        finish(current)

    frames.sort(key=lambda fr: (fr["t0"], fr["dir"]))
    for order, frame in enumerate(frames):
        frame["bus_order"] = order
    return frames
