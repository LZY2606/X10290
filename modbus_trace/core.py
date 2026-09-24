"""不可变材料层：Modbus TCP/RTU ADU 解析。

原则：
- 原 ADU 字节、连接/总线方向、transaction id、unit id、CRC、功能码、
  地址基准与映射表版本全部保留，解析失败不抛异常，而是返回带字节位置
  的诊断（format_corrupt），绝不用空值/默认值伪装成功。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Optional

FUNCTION_NAMES = {
    1: "read_coils",
    2: "read_discrete_inputs",
    3: "read_holding_registers",
    4: "read_input_registers",
    5: "write_single_coil",
    6: "write_single_register",
    15: "write_multiple_coils",
    16: "write_multiple_registers",
}

EXCEPTION_NAMES = {
    1: "illegal_function",
    2: "illegal_data_address",
    3: "illegal_data_value",
    4: "server_device_failure",
    5: "acknowledge",
    6: "server_device_busy",
}

# 三种必须可区分的失败结果
OUTCOME_OK = "ok"
OUTCOME_BUDGET_EXHAUSTED = "budget_exhausted"
OUTCOME_FORMAT_CORRUPT = "format_corrupt"
OUTCOME_SEMANTIC_UNRESOLVED = "semantic_unresolved"

BROADCAST_UNIT_ID = 0


def crc16_modbus(data: bytes) -> int:
    """标准 Modbus CRC16（多项式 0xA001，初值 0xFFFF）。"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def canonical_digest(obj) -> str:
    """稳定摘要：等价输入得到等价摘要，用于输入摘要与身份派生。"""
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class Diagnostic:
    code: str                      # format_corrupt / semantic_unresolved / budget_exhausted / unmapped_address ...
    message: str
    position: Optional[int] = None  # 原始 ADU 中的字节偏移
    frame_id: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class Frame:
    """一条不可变帧材料。raw_hex 为原始 ADU 字节，永不修改。"""
    frame_id: str
    link: str                      # "tcp" | "rtu"
    direction: str                 # tcp: client_to_server/server_to_client; rtu: master_to_slave/slave_to_master
    conn_gen: int                  # 连接代次（重连 +1）
    t_ms: float                    # 时间基准：采集开始起的单调毫秒
    raw_hex: str                   # 原 ADU 字节（TCP 含 MBAP，RTU 含地址与 CRC）
    address_base: str = "zero"     # 来源声明的地址基准（仅展示层使用）
    mapping_version: str = "unknown"
    source: str = ""               # 来路，如 capture 文件:偏移
    # 以下为解析派生字段；解析失败时保持 None 并附诊断
    transaction_id: Optional[int] = None
    unit_id: Optional[int] = None
    function_code: Optional[int] = None
    is_exception: bool = False
    exception_code: Optional[int] = None
    crc: Optional[int] = None
    crc_ok: Optional[bool] = None
    reg_address: Optional[int] = None   # 线上协议地址（零基规范空间）
    reg_quantity: Optional[int] = None
    byte_count: Optional[int] = None
    data_hex: Optional[str] = None
    parse_ok: bool = True
    diagnostics: list = field(default_factory=list)

    @property
    def is_request(self) -> bool:
        return self.direction in ("client_to_server", "master_to_slave")

    @property
    def is_broadcast(self) -> bool:
        return self.unit_id == BROADCAST_UNIT_ID and self.is_request

    def to_dict(self):
        d = asdict(self)
        d["diagnostics"] = [x if isinstance(x, dict) else x.to_dict() for x in self.diagnostics]
        return d

    @staticmethod
    def from_dict(d: dict) -> "Frame":
        d = dict(d)
        d["diagnostics"] = [
            x if isinstance(x, Diagnostic) else Diagnostic(**x) for x in d.get("diagnostics", [])
        ]
        return Frame(**d)


def _classify_pdu(frame: Frame, pdu: bytes, pdu_offset: int) -> None:
    """解析 PDU 公共字段；失败时写带位置的诊断。"""
    if len(pdu) < 1:
        frame.parse_ok = False
        frame.diagnostics.append(Diagnostic(
            OUTCOME_FORMAT_CORRUPT, "PDU 为空，缺少功能码", pdu_offset, frame.frame_id))
        return
    fc = pdu[0]
    frame.function_code = fc & 0x7F if fc & 0x80 else fc
    if fc & 0x80:
        frame.is_exception = True
        if len(pdu) < 2:
            frame.parse_ok = False
            frame.diagnostics.append(Diagnostic(
                OUTCOME_FORMAT_CORRUPT, "异常响应缺少异常码字节", pdu_offset + 1, frame.frame_id))
            return
        frame.exception_code = pdu[1]
        return
    if frame.is_request:
        if frame.function_code in (1, 2, 3, 4):
            if len(pdu) < 5:
                frame.parse_ok = False
                frame.diagnostics.append(Diagnostic(
                    OUTCOME_FORMAT_CORRUPT,
                    f"读请求 PDU 长度不足：需要 5 字节，实得 {len(pdu)}",
                    pdu_offset + len(pdu) - 1, frame.frame_id))
                return
            frame.reg_address = int.from_bytes(pdu[1:3], "big")
            frame.reg_quantity = int.from_bytes(pdu[3:5], "big")
        elif frame.function_code in (5, 6):
            if len(pdu) < 5:
                frame.parse_ok = False
                frame.diagnostics.append(Diagnostic(
                    OUTCOME_FORMAT_CORRUPT, "写单值请求 PDU 长度不足",
                    pdu_offset + len(pdu) - 1, frame.frame_id))
                return
            frame.reg_address = int.from_bytes(pdu[1:3], "big")
            frame.data_hex = pdu[3:5].hex()
    else:
        if frame.function_code in (1, 2, 3, 4):
            if len(pdu) < 2:
                frame.parse_ok = False
                frame.diagnostics.append(Diagnostic(
                    OUTCOME_FORMAT_CORRUPT, "读响应缺少字节计数字段",
                    pdu_offset + 1, frame.frame_id))
                return
            frame.byte_count = pdu[1]
            if len(pdu) < 2 + frame.byte_count:
                frame.parse_ok = False
                frame.diagnostics.append(Diagnostic(
                    OUTCOME_FORMAT_CORRUPT,
                    f"读响应数据截断：声明 {frame.byte_count} 字节，实得 {len(pdu) - 2}",
                    pdu_offset + len(pdu) - 1, frame.frame_id))
                return
            frame.data_hex = pdu[2:2 + frame.byte_count].hex()
        elif frame.function_code in (5, 6, 15, 16):
            if len(pdu) < 5:
                frame.parse_ok = False
                frame.diagnostics.append(Diagnostic(
                    OUTCOME_FORMAT_CORRUPT, "写响应 PDU 长度不足",
                    pdu_offset + len(pdu) - 1, frame.frame_id))
                return
            frame.reg_address = int.from_bytes(pdu[1:3], "big")
            frame.data_hex = pdu[3:5].hex()


def parse_tcp_frame(frame_id: str, raw: bytes, *, direction: str, conn_gen: int,
                    t_ms: float, address_base: str, mapping_version: str,
                    source: str) -> Frame:
    """解析 Modbus TCP ADU（MBAP + PDU）。原始字节始终保留在 raw_hex。"""
    frame = Frame(frame_id=frame_id, link="tcp", direction=direction,
                  conn_gen=conn_gen, t_ms=t_ms, raw_hex=raw.hex(),
                  address_base=address_base, mapping_version=mapping_version,
                  source=source)
    if len(raw) < 7:
        frame.parse_ok = False
        frame.diagnostics.append(Diagnostic(
            OUTCOME_FORMAT_CORRUPT,
            f"TCP ADU 长度不足 MBAP 头：需要 >=7 字节，实得 {len(raw)}",
            len(raw) - 1 if raw else 0, frame_id))
        return frame
    frame.transaction_id = int.from_bytes(raw[0:2], "big")
    protocol_id = int.from_bytes(raw[2:4], "big")
    length = int.from_bytes(raw[4:6], "big")
    frame.unit_id = raw[6]
    if protocol_id != 0:
        frame.parse_ok = False
        frame.diagnostics.append(Diagnostic(
            OUTCOME_FORMAT_CORRUPT,
            f"MBAP protocol id 应为 0，实得 {protocol_id}", 2, frame_id))
        return frame
    if length != len(raw) - 6:
        frame.parse_ok = False
        frame.diagnostics.append(Diagnostic(
            OUTCOME_FORMAT_CORRUPT,
            f"MBAP length={length} 与实际剩余 {len(raw) - 6} 字节不一致", 4, frame_id))
        return frame
    _classify_pdu(frame, raw[7:], 7)
    return frame


def parse_rtu_frame(frame_id: str, raw: bytes, *, direction: str, conn_gen: int,
                    t_ms: float, address_base: str, mapping_version: str,
                    source: str) -> Frame:
    """解析 Modbus RTU ADU（地址 + PDU + CRC16）。CRC 原值与校验结果均保留。"""
    frame = Frame(frame_id=frame_id, link="rtu", direction=direction,
                  conn_gen=conn_gen, t_ms=t_ms, raw_hex=raw.hex(),
                  address_base=address_base, mapping_version=mapping_version,
                  source=source)
    if len(raw) < 4:
        frame.parse_ok = False
        frame.diagnostics.append(Diagnostic(
            OUTCOME_FORMAT_CORRUPT,
            f"RTU ADU 长度不足：需要 >=4 字节，实得 {len(raw)}",
            len(raw) - 1 if raw else 0, frame_id))
        return frame
    frame.unit_id = raw[0]
    frame.crc = int.from_bytes(raw[-2:], "little")
    expected = crc16_modbus(raw[:-2])
    frame.crc_ok = (frame.crc == expected)
    if not frame.crc_ok:
        frame.parse_ok = False
        frame.diagnostics.append(Diagnostic(
            OUTCOME_FORMAT_CORRUPT,
            f"CRC 校验失败：帧内 0x{frame.crc:04x}，计算 0x{expected:04x}",
            len(raw) - 2, frame_id))
        return frame
    _classify_pdu(frame, raw[1:-2], 1)
    return frame


def parse_frame(frame_id: str, raw: bytes, *, link: str, direction: str,
                conn_gen: int, t_ms: float, address_base: str,
                mapping_version: str, source: str) -> Frame:
    if link == "tcp":
        return parse_tcp_frame(frame_id, raw, direction=direction, conn_gen=conn_gen,
                               t_ms=t_ms, address_base=address_base,
                               mapping_version=mapping_version, source=source)
    if link == "rtu":
        return parse_rtu_frame(frame_id, raw, direction=direction, conn_gen=conn_gen,
                               t_ms=t_ms, address_base=address_base,
                               mapping_version=mapping_version, source=source)
    raise ValueError(f"未知链路类型: {link}")
