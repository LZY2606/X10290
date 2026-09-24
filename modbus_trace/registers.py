"""寄存器解释层（派生层）。

原则：
- 线上协议地址固定为零基规范空间；零基/一基只在展示层转换，永不回写材料。
- 字节序/字序是参数化组合，每次解释记录参数版本。
- 所有领域量携带单位与坐标基准；无法转换的值留在原位置并附诊断，
  不为了画图丢值；异常响应不产生寄存器值（不是“成功的空数据”）。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field, asdict
from typing import Optional

import numpy as np

from .core import Diagnostic, EXCEPTION_NAMES

INTERP_VERSION = "register-interp/v1"

BYTE_ORDERS = ("big", "little")
WORD_ORDERS = ("high_first", "low_first")
ADDRESS_BASES = ("zero", "one")

# 展示层地址转换（唯一允许做基准转换的地方）
def display_address(protocol_address: int, display_base: str) -> int:
    if display_base == "one":
        return protocol_address + 1
    return protocol_address


@dataclass
class RegisterValue:
    value_id: str
    pair_id: str
    protocol_address: int            # 零基规范空间，永不修改
    display_address: int             # 按当前展示基准换算
    display_base: str
    name: str
    unit: str                        # 领域单位，如 "°C" / "kPa" / "count"
    datatype: str
    raw_hex: str                     # 原始字节表示，导入时保留
    value: Optional[float]           # 无法转换时为 None，并附诊断
    valid_min: Optional[float] = None
    valid_max: Optional[float] = None
    in_range: Optional[bool] = None
    invalid_reason: Optional[str] = None
    diagnostic: Optional[dict] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class MappingEntry:
    start: int                       # 协议（零基）起始地址
    count: int
    name: str
    unit: str
    datatype: str                    # uint16/int16/uint32/float32
    scale: float = 1.0
    valid_min: Optional[float] = None
    valid_max: Optional[float] = None
    declared_base: str = "zero"      # 映射表书写时声明的基准（仅溯源用）

    def to_dict(self):
        return asdict(self)


@dataclass
class RegisterMapping:
    mapping_id: str
    version: str
    device: str
    entries: list = field(default_factory=list)

    def to_dict(self):
        return {"mapping_id": self.mapping_id, "version": self.version,
                "device": self.device,
                "entries": [e.to_dict() if hasattr(e, "to_dict") else e for e in self.entries]}

    @staticmethod
    def from_dict(d: dict) -> "RegisterMapping":
        return RegisterMapping(mapping_id=d["mapping_id"], version=d["version"],
                               device=d["device"],
                               entries=[MappingEntry(**e) for e in d["entries"]])


def _decode_words(data: bytes, byte_order: str) -> list[int]:
    words = []
    for i in range(0, len(data) - 1, 2):
        words.append(int.from_bytes(data[i:i + 2], byte_order))
    return words


def _decode_value(words: list[int], datatype: str, byte_order: str,
                  word_order: str) -> float:
    ordered = list(words) if word_order == "high_first" else list(reversed(words))
    raw = b"".join(w.to_bytes(2, "big") for w in ordered)
    if datatype == "uint16":
        return float(int.from_bytes(raw[:2], "big"))
    if datatype == "int16":
        return float(struct.unpack(">h", raw[:2])[0])
    if datatype == "uint32":
        return float(int.from_bytes(raw[:4], "big"))
    if datatype == "float32":
        return float(np.frombuffer(raw[:4], dtype=">f4")[0])
    raise ValueError(f"未知数据类型: {datatype}")


def interpret_pair_registers(pair: dict, request_frame, response_frame,
                             mapping: RegisterMapping, *,
                             byte_order: str = "big",
                             word_order: str = "high_first",
                             display_base: str = "zero") -> dict:
    """把一个配对成功的读寄存器事务解释为带单位的寄存器值。

    返回 {outcome, values, diagnostics}；异常响应返回空值表与说明，
    绝不伪装成“成功的空数据”。
    """
    diagnostics: list[dict] = []
    values: list[RegisterValue] = []
    pair_id = pair["pair_id"]
    if pair["status"] == "exception":
        code = pair.get("exception_code")
        diagnostics.append(Diagnostic(
            "exception_response",
            f"异常响应码 {code}（{EXCEPTION_NAMES.get(code, 'unknown')}）："
            "寄存器值不可用，不能当作成功的空数据").to_dict())
        return {"outcome": "exception", "values": [], "diagnostics": diagnostics}
    if pair["status"] == "ambiguous":
        diagnostics.append(Diagnostic(
            "semantic_unresolved",
            "配对存在多候选，寄存器解释挂起，等待人工决定").to_dict())
        return {"outcome": "semantic_unresolved", "values": [], "diagnostics": diagnostics}
    if request_frame is None or response_frame is None:
        diagnostics.append(Diagnostic(
            "semantic_unresolved", "配对缺少请求或响应帧，无法解释").to_dict())
        return {"outcome": "semantic_unresolved", "values": [], "diagnostics": diagnostics}
    if request_frame.reg_address is None or response_frame.data_hex is None:
        diagnostics.append(Diagnostic(
            "semantic_unresolved", "请求/响应缺少地址或数据字段").to_dict())
        return {"outcome": "semantic_unresolved", "values": [], "diagnostics": diagnostics}

    start = request_frame.reg_address
    data = bytes.fromhex(response_frame.data_hex)
    words = _decode_words(data, byte_order)
    seq = 0
    for entry in mapping.entries:
        if entry.start < start or entry.start + entry.count > start + len(words):
            continue  # 不在本次响应区间内
        offset = entry.start - start
        width = 2 if entry.datatype in ("uint32", "float32") else 1
        for i in range(entry.count):
            w0 = offset + i * width
            if w0 + width > len(words):
                break
            seq += 1
            addr = entry.start + i * width
            raw_words = words[w0:w0 + width]
            raw_hex = b"".join(w.to_bytes(2, "big") for w in raw_words).hex()
            value = None
            diag = None
            in_range = None
            invalid_reason = None
            try:
                value = _decode_value(raw_words, entry.datatype, byte_order, word_order)
                value = value * entry.scale
                if entry.valid_min is not None and value < entry.valid_min:
                    in_range = False
                    invalid_reason = f"低于有效区间下限 {entry.valid_min}{entry.unit}"
                elif entry.valid_max is not None and value > entry.valid_max:
                    in_range = False
                    invalid_reason = f"高于有效区间上限 {entry.valid_max}{entry.unit}"
                else:
                    in_range = True
            except Exception as exc:  # 无法转换：留在原位置并附诊断
                diag = Diagnostic("semantic_unresolved",
                                  f"地址 {addr} 按 {entry.datatype} 解码失败: {exc}",
                                  None, response_frame.frame_id).to_dict()
                diagnostics.append(diag)
            values.append(RegisterValue(
                value_id=f"val-{pair_id}-{seq:03d}", pair_id=pair_id,
                protocol_address=addr,
                display_address=display_address(addr, display_base),
                display_base=display_base, name=entry.name, unit=entry.unit,
                datatype=entry.datatype, raw_hex=raw_hex, value=value,
                valid_min=entry.valid_min, valid_max=entry.valid_max,
                in_range=in_range, invalid_reason=invalid_reason,
                diagnostic=diag))
    covered = {v.protocol_address for v in values}
    for addr in range(start, start + len(words)):
        if addr not in covered:
            seq += 1
            raw_hex = words[addr - start].to_bytes(2, "big").hex()
            diag = Diagnostic(
                "unmapped_address",
                f"地址 {addr} 在映射版本 {mapping.version} 中无条目，"
                "原始字保留在原位置，未做转换").to_dict()
            diagnostics.append(diag)
            values.append(RegisterValue(
                value_id=f"val-{pair_id}-{seq:03d}", pair_id=pair_id,
                protocol_address=addr,
                display_address=display_address(addr, display_base),
                display_base=display_base, name="(未映射)", unit="raw-word",
                datatype="uint16", raw_hex=raw_hex,
                value=float(words[addr - start]), diagnostic=diag))
    return {"outcome": "ok", "values": [v.to_dict() for v in values],
            "diagnostics": diagnostics}


def interpret_all(pairing_result: dict, frames_by_id: dict,
                  mappings: dict, *, byte_order: str = "big",
                  word_order: str = "high_first",
                  display_base: str = "zero") -> dict:
    """对配对结果中的每个读事务做寄存器解释，记录参数版本与输入摘要。"""
    from .core import canonical_digest
    interpretations = []
    diagnostics = []
    for pair in pairing_result["pairs"]:
        req = frames_by_id.get(pair.get("request_id") or "")
        resp = frames_by_id.get(pair.get("response_id") or "")
        mapping_key = (req.mapping_version if req else None) or \
                      (resp.mapping_version if resp else None)
        mapping = mappings.get(mapping_key)
        if mapping is None:
            diagnostics.append(Diagnostic(
                "semantic_unresolved",
                f"映射版本 {mapping_key!r} 不存在，pair {pair['pair_id']} 无法解释").to_dict())
            interpretations.append({"pair_id": pair["pair_id"],
                                    "outcome": "semantic_unresolved",
                                    "values": [], "mapping_version": mapping_key})
            continue
        result = interpret_pair_registers(pair, req, resp, mapping,
                                          byte_order=byte_order,
                                          word_order=word_order,
                                          display_base=display_base)
        result["pair_id"] = pair["pair_id"]
        result["mapping_version"] = mapping.version
        interpretations.append(result)
        diagnostics.extend(result["diagnostics"])
    return {
        "interp_version": INTERP_VERSION,
        "params": {"byte_order": byte_order, "word_order": word_order,
                   "display_base": display_base},
        "input_digest": canonical_digest(
            {"pairing": pairing_result["pairs"],
             "params": [byte_order, word_order, display_base]}),
        "interpretations": interpretations,
        "diagnostics": [d if isinstance(d, dict) else d.to_dict() for d in diagnostics],
    }
