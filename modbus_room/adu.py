"""Modbus ADU 解析：TCP MBAP 与 RTU+CRC16。

解析失败返回 format_corrupt 并带字节位置；解析器不做任何语义猜测。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .model import Result, Status

READ_FUNCTIONS = (0x01, 0x02, 0x03, 0x04)


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc & 0xFFFF


@dataclass
class Frame:
    raw: bytes
    transport: str  # "tcp" | "rtu"
    unit_id: int
    function_code: int
    data: bytes  # PDU 中功能码之后的部分
    transaction_id: Optional[int] = None
    crc: Optional[int] = None
    crc_ok: Optional[bool] = None

    @property
    def is_exception(self) -> bool:
        return bool(self.function_code & 0x80)

    @property
    def base_function(self) -> int:
        return self.function_code & 0x7F

    @property
    def exception_code(self) -> Optional[int]:
        return self.data[0] if self.is_exception and len(self.data) >= 1 else None

    @property
    def is_broadcast(self) -> bool:
        return self.transport == "rtu" and self.unit_id == 0

    @property
    def req_address(self) -> Optional[int]:
        return int.from_bytes(self.data[0:2], "big") if len(self.data) >= 4 else None

    @property
    def req_quantity(self) -> Optional[int]:
        return int.from_bytes(self.data[2:4], "big") if len(self.data) >= 4 else None


def parse_tcp_frame(raw: bytes) -> Result:
    if len(raw) < 8:
        return Result.failure(Status.FORMAT_CORRUPT, "short_mbap",
                              f"TCP ADU 不足 MBAP+PDU 最小长度: {len(raw)} 字节", position=0)
    tid = int.from_bytes(raw[0:2], "big")
    pid = int.from_bytes(raw[2:4], "big")
    length = int.from_bytes(raw[4:6], "big")
    if pid != 0:
        return Result.failure(Status.FORMAT_CORRUPT, "bad_protocol_id",
                              f"MBAP 协议标识 {pid} != 0", position=2)
    if length != len(raw) - 6:
        return Result.failure(Status.FORMAT_CORRUPT, "bad_length",
                              f"MBAP 长度字段 {length} 与实际 {len(raw) - 6} 不符", position=4)
    return Result(value=Frame(raw=raw, transport="tcp", unit_id=raw[6],
                              function_code=raw[7], data=raw[8:], transaction_id=tid))


def parse_rtu_frame(raw: bytes) -> Result:
    if len(raw) < 4:
        return Result.failure(Status.FORMAT_CORRUPT, "short_rtu",
                              f"RTU ADU 过短: {len(raw)} 字节", position=0)
    body, crc_bytes = raw[:-2], raw[-2:]
    expected = crc16(body)
    got = crc_bytes[0] | (crc_bytes[1] << 8)
    if got != expected:
        return Result.failure(Status.FORMAT_CORRUPT, "bad_crc",
                              f"CRC 校验不符: 收到 0x{got:04X}, 应为 0x{expected:04X}",
                              position=len(raw) - 2)
    return Result(value=Frame(raw=raw, transport="rtu", unit_id=body[0],
                              function_code=body[1], data=body[2:], crc=got, crc_ok=True))
