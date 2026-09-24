"""不可变领域原语：ADU 解析、CRC、结构化诊断。

导入层只保留原始表示（ADU 字节、方向、代次、tick），
解析/规范化全部发生在派生层。解析失败产出带位置的诊断，
绝不用空值或默认值伪装成功。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Any, Optional

# ---- 结果类别：三种失败必须是三种不同结果 ----
OK = "ok"
FORMAT_CORRUPT = "format_corrupt"          # 格式损坏（CRC 错、截断、长度不符）
SEMANTIC_UNSOLVABLE = "semantic_unsolvable"  # 语义无解（未知字节序/字序等）
BUDGET_EXHAUSTED = "budget_exhausted"      # 资源预算耗尽


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


@dataclass
class Diagnostic:
    kind: str                       # format_corrupt / semantic_unsolvable / budget_exhausted / out_of_range ...
    message: str
    position: Optional[int] = None  # ADU 内字节偏移，或帧 tick
    frame_id: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


# ---- TCP (MBAP) ----
def parse_tcp_adu(raw: bytes) -> tuple[Optional[dict], list[Diagnostic]]:
    diags: list[Diagnostic] = []
    if len(raw) < 8:
        return None, [Diagnostic(FORMAT_CORRUPT,
                                 f"TCP ADU 过短: {len(raw)} 字节，至少需要 8 字节(MBAP+PDU)",
                                 position=len(raw))]
    tid = int.from_bytes(raw[0:2], "big")
    pid = int.from_bytes(raw[2:4], "big")
    length = int.from_bytes(raw[4:6], "big")
    uid = raw[6]
    if pid != 0:
        return None, [Diagnostic(FORMAT_CORRUPT, f"MBAP 协议标识 {pid} != 0", position=2)]
    if length != len(raw) - 6:
        return None, [Diagnostic(FORMAT_CORRUPT,
                                 f"MBAP 长度字段 {length} 与实际 {len(raw) - 6} 不符",
                                 position=4)]
    pdu = raw[7:]
    if not pdu:
        return None, [Diagnostic(FORMAT_CORRUPT, "PDU 为空", position=7)]
    return {
        "transaction_id": tid,
        "unit_id": uid,
        "function_code": pdu[0],
        "pdu_hex": pdu.hex(),
        "crc": None,
        "crc_ok": None,
    }, diags


# ---- RTU ----
def parse_rtu_adu(raw: bytes) -> tuple[Optional[dict], list[Diagnostic]]:
    if len(raw) < 4:
        return None, [Diagnostic(FORMAT_CORRUPT,
                                 f"RTU ADU 过短: {len(raw)} 字节，至少需要 4 字节(地址+PDU+CRC)",
                                 position=len(raw))]
    body, crc_bytes = raw[:-2], raw[-2:]
    expected = crc16_modbus(body)
    actual = crc_bytes[0] | (crc_bytes[1] << 8)
    if expected != actual:
        return None, [Diagnostic(FORMAT_CORRUPT,
                                 f"CRC 校验失败: 计算值 0x{expected:04X} != 接收值 0x{actual:04X}",
                                 position=len(raw) - 2)]
    pdu = body[1:]
    return {
        "transaction_id": None,
        "unit_id": body[0],
        "function_code": pdu[0],
        "pdu_hex": pdu.hex(),
        "crc": actual,
        "crc_ok": True,
    }, []


def parse_request_pdu(pdu: bytes) -> Optional[dict]:
    """从请求 PDU 提取地址/数量；不支持的请求功能码返回 None。"""
    if len(pdu) < 5:
        return None
    fc = pdu[0]
    if fc in (1, 2, 3, 4):
        return {"function_code": fc,
                "address": int.from_bytes(pdu[1:3], "big"),
                "count": int.from_bytes(pdu[3:5], "big")}
    if fc in (5, 6):
        return {"function_code": fc,
                "address": int.from_bytes(pdu[1:3], "big"),
                "value": int.from_bytes(pdu[3:5], "big")}
    return None
