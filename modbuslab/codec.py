"""Modbus TCP / RTU ADU 与 PDU 解释。

解析保持原 ADU 字节不被覆盖；任何无法解释的片段返回带位置的诊断。
地址一律保留协议原始值（PDU 零基），一基仅出现在展示层。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

MBAP_LEN = 7
RTU_MIN_LEN = 4

READ_FCS = {1, 2, 3, 4}
WRITE_SINGLE_FCS = {5, 6}
WRITE_MULTI_FCS = {15, 16}
SUPPORTED_FCS = READ_FCS | WRITE_SINGLE_FCS | WRITE_MULTI_FCS | {8, 22, 23}
# 数据对象：0=coil 1=discrete input 3=holding 4=input register
FC_SPACE = {1: 0, 2: 1, 3: 3, 4: 4, 5: 0, 6: 3, 15: 0, 16: 3, 23: 3}
FC_IS_REGISTER = {1: False, 2: False, 3: True, 4: True, 5: False, 6: True, 15: False, 16: True}


class AduError(Exception):
    def __init__(self, code: str, position: str, message: str):
        super().__init__(message)
        self.code = code            # FORMAT_CORRUPT / SEMANTIC_NO_SOLUTION
        self.position = position
        self.message = message


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


def append_crc(body: bytes) -> bytes:
    crc = crc16(body)
    return body + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


@dataclass
class Pdu:
    fc: int
    role: str                    # request | response | exception
    exception_code: Optional[int] = None
    address: Optional[int] = None
    quantity: Optional[int] = None
    values_hex: Optional[str] = None   # 请求写入或响应读出的数据字节
    byte_count: Optional[int] = None
    raw_hex: str = ""


def _check_quantity(fc: int, qty: int) -> None:
    if FC_IS_REGISTER.get(fc):
        if not 1 <= qty <= 125:
            raise AduError("SEMANTIC_NO_SOLUTION", "pdu.quantity",
                           f"功能码 {fc} 寄存器数量 {qty} 越界 (1..125)")
    else:
        if not 1 <= qty <= 2000:
            raise AduError("SEMANTIC_NO_SOLUTION", "pdu.quantity",
                           f"功能码 {fc} 线圈数量 {qty} 越界 (1..2000)")


def _check_addr(addr: int) -> None:
    if not 0 <= addr <= 0xFFFF:
        raise AduError("SEMANTIC_NO_SOLUTION", "pdu.address", f"地址 {addr} 越界")


def parse_pdu(pdu: bytes, role: str) -> Pdu:
    if len(pdu) < 1:
        raise AduError("FORMAT_CORRUPT", "pdu", "PDU 为空")
    fc0 = pdu[0]
    exc = fc0 & 0x80
    fc = fc0 & 0x7F
    if fc not in SUPPORTED_FCS:
        if exc:
            if len(pdu) < 2:
                raise AduError("FORMAT_CORRUPT", "pdu.exception_code", "异常响应缺少异常码")
            return Pdu(fc=fc, role="exception", exception_code=pdu[1], raw_hex=pdu.hex())
        raise AduError("SEMANTIC_NO_SOLUTION", "pdu.fc", f"不支持的功能码 0x{fc0:02X}")

    if exc:
        if role != "response":
            raise AduError("SEMANTIC_NO_SOLUTION", "pdu.fc", f"{role} 不得携带异常位")
        if len(pdu) < 2:
            raise AduError("FORMAT_CORRUPT", "pdu.exception_code", "异常响应缺少异常码")
        return Pdu(fc=fc, role="exception", exception_code=pdu[1], raw_hex=pdu.hex())

    if role == "request":
        return _parse_request(pdu, fc)
    return _parse_response(pdu, fc)


def _parse_request(pdu: bytes, fc: int) -> Pdu:
    if fc in READ_FCS:
        if len(pdu) != 5:
            raise AduError("FORMAT_CORRUPT", "pdu", f"读请求长度应为 5，实际 {len(pdu)}")
        addr, qty = int.from_bytes(pdu[1:3], "big"), int.from_bytes(pdu[3:5], "big")
        _check_addr(addr)
        _check_quantity(fc, qty)
        return Pdu(fc, "request", address=addr, quantity=qty, raw_hex=pdu.hex())
    if fc in WRITE_SINGLE_FCS:
        if len(pdu) != 5:
            raise AduError("FORMAT_CORRUPT", "pdu", f"单写请求长度应为 5，实际 {len(pdu)}")
        addr = int.from_bytes(pdu[1:3], "big")
        _check_addr(addr)
        return Pdu(fc, "request", address=addr, quantity=1, values_hex=pdu[3:5].hex(), raw_hex=pdu.hex())
    if fc in WRITE_MULTI_FCS:
        if len(pdu) < 6:
            raise AduError("FORMAT_CORRUPT", "pdu", "多写请求过短")
        addr = int.from_bytes(pdu[1:3], "big")
        qty = int.from_bytes(pdu[3:5], "big")
        bc = pdu[5]
        if len(pdu) != 6 + bc:
            raise AduError("FORMAT_CORRUPT", "pdu.byte_count",
                           f"字节计数 {bc} 与剩余 {len(pdu) - 6} 不一致")
        _check_addr(addr)
        _check_quantity(fc, qty)
        per = 2 if FC_IS_REGISTER[fc] else 1
        expect = qty * per if FC_IS_REGISTER[fc] else (qty + 7) // 8
        if bc != expect:
            raise AduError("SEMANTIC_NO_SOLUTION", "pdu.byte_count",
                           f"字节计数 {bc} 与数量 {qty} 不一致，期望 {expect}")
        return Pdu(fc, "request", address=addr, quantity=qty, byte_count=bc,
                   values_hex=pdu[6:].hex(), raw_hex=pdu.hex())
    raise AduError("SEMANTIC_NO_SOLUTION", "pdu.fc", f"功能码 {fc} 的请求未实现解释")


def _parse_response(pdu: bytes, fc: int) -> Pdu:
    if fc in READ_FCS:
        if len(pdu) < 2:
            raise AduError("FORMAT_CORRUPT", "pdu", "读响应缺少字节计数")
        bc = pdu[1]
        if len(pdu) != 2 + bc:
            raise AduError("FORMAT_CORRUPT", "pdu.byte_count",
                           f"字节计数 {bc} 与剩余 {len(pdu) - 2} 不一致")
        if bc == 0:
            raise AduError("SEMANTIC_NO_SOLUTION", "pdu.byte_count", "读响应数据长度为 0")
        per = 2 if FC_IS_REGISTER[fc] else 1
        if per == 2 and bc % 2:
            raise AduError("SEMANTIC_NO_SOLUTION", "pdu.data", "寄存器数据字节数为奇数")
        return Pdu(fc, "response", quantity=bc // per if per == 2 else bc * 8,
                   byte_count=bc, values_hex=pdu[2:].hex(), raw_hex=pdu.hex())
    if fc in WRITE_SINGLE_FCS:
        if len(pdu) != 5:
            raise AduError("FORMAT_CORRUPT", "pdu", "单写响应长度应为 5")
        addr = int.from_bytes(pdu[1:3], "big")
        _check_addr(addr)
        return Pdu(fc, "response", address=addr, quantity=1, values_hex=pdu[3:5].hex(),
                   raw_hex=pdu.hex())
    if fc in WRITE_MULTI_FCS:
        if len(pdu) != 5:
            raise AduError("FORMAT_CORRUPT", "pdu", "多写响应长度应为 5")
        addr = int.from_bytes(pdu[1:3], "big")
        qty = int.from_bytes(pdu[3:5], "big")
        _check_addr(addr)
        _check_quantity(fc, qty)
        return Pdu(fc, "response", address=addr, quantity=qty, raw_hex=pdu.hex())
    raise AduError("SEMANTIC_NO_SOLUTION", "pdu.fc", f"功能码 {fc} 的响应未实现解释")


@dataclass
class Adu:
    transport: str               # tcp | rtu
    role: str                    # request | response
    unit: int
    xid: Optional[int]
    pdu: Pdu
    crc_ok: Optional[bool] = None
    crc_received: Optional[int] = None
    crc_calculated: Optional[int] = None


def parse_tcp(adu: bytes, role: str) -> Adu:
    if len(adu) < MBAP_LEN + 1:
        raise AduError("FORMAT_CORRUPT", "mbap", f"TCP ADU 短于 {MBAP_LEN + 1} 字节")
    xid = int.from_bytes(adu[0:2], "big")
    proto = int.from_bytes(adu[2:4], "big")
    length = int.from_bytes(adu[4:6], "big")
    unit = adu[6]
    if proto != 0:
        raise AduError("SEMANTIC_NO_SOLUTION", "mbap.protocol", f"协议标识应为 0，实际 {proto}")
    if length != len(adu) - MBAP_LEN + 1:
        raise AduError("FORMAT_CORRUPT", "mbap.length",
                       f"长度字段 {length} 与实际 {len(adu) - MBAP_LEN + 1} 不一致")
    pdu = parse_pdu(adu[MBAP_LEN:], role)
    return Adu("tcp", role, unit, xid, pdu)


def parse_rtu(adu: bytes, role: str) -> Adu:
    if len(adu) < RTU_MIN_LEN:
        raise AduError("FORMAT_CORRUPT", "adu", f"RTU ADU 短于 {RTU_MIN_LEN} 字节")
    body, tail = adu[:-2], adu[-2:]
    crc_recv = tail[0] | (tail[1] << 8)
    crc_calc = crc16(body)
    crc_ok = crc_recv == crc_calc
    unit = body[0]
    pdu: Pdu
    if crc_ok:
        pdu = parse_pdu(body[1:], role)
    else:
        fc = body[1] & 0x7F if len(body) >= 2 else 0
        pdu = Pdu(fc=fc, role="unverifiable", raw_hex=body[1:].hex())
    return Adu("rtu", role, unit, None, pdu,
               crc_ok=crc_ok, crc_received=crc_recv, crc_calculated=crc_calc)


def retransmit_signature(adu: Adu) -> str:
    parts = [adu.transport, adu.unit, adu.pdu.raw_hex]
    if adu.transport == "tcp":
        parts.append(str(adu.xid))
    return "|".join(parts)
