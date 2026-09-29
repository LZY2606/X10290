"""设备映射版本与寄存器解码（NumPy）。

地址基准（零基/一基）只属于展示层；这里保存的永远是零基协议地址。
字节/字序四种组合：ABCD+big、ABCD+little(BADC)、CDAB+big、CDAB+little(DCBA)。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

import numpy as np

from .model import stable_hash


@dataclass(frozen=True)
class RegisterDef:
    address: int  # 零基协议地址（规范坐标）
    name: str
    datatype: str = "u16"  # u16 | i16 | f32
    scale: float = 1.0
    unit: str = ""
    valid_min: Optional[float] = None
    valid_max: Optional[float] = None
    word_order: str = "ABCD"  # ABCD | CDAB
    byte_order: str = "big"   # big | little（little = 每 16 位字内字节交换）
    words: int = 1

    def digest(self) -> str:
        return stable_hash(asdict(self))

    def to_json(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_json(d: dict) -> "RegisterDef":
        return RegisterDef(**d)


@dataclass(frozen=True)
class MappingVersion:
    version: str
    address_base: int  # 0 或 1，仅用于展示层
    registers: tuple

    def by_address(self) -> dict:
        return {r.address: r for r in self.registers}

    def to_json(self) -> dict:
        return {"version": self.version, "address_base": self.address_base,
                "registers": [r.to_json() for r in self.registers]}

    @staticmethod
    def from_json(d: dict) -> "MappingVersion":
        return MappingVersion(d["version"], int(d["address_base"]),
                              tuple(RegisterDef.from_json(r) for r in d["registers"]))


def decode_register(data: bytes, regdef: RegisterDef):
    """按映射定义解码线上字节，返回 (原始值, 工程值)。"""
    if regdef.datatype == "u16":
        raw = int(np.frombuffer(data[:2], dtype=">u2")[0])
    elif regdef.datatype == "i16":
        raw = int(np.frombuffer(data[:2], dtype=">i2")[0])
    elif regdef.datatype == "f32":
        if len(data) < 4:
            raise ValueError("f32 需要 4 字节")
        words = np.frombuffer(data[:4], dtype=">u2")
        if regdef.word_order == "CDAB":
            words = words[::-1]
        buf = words.astype(">u2").tobytes()
        if regdef.byte_order == "little":
            buf = bytes((buf[1], buf[0], buf[3], buf[2]))
        raw = float(np.frombuffer(buf, dtype=">f4")[0])
    else:
        raise ValueError(f"未知数据类型 {regdef.datatype}")
    return raw, raw * regdef.scale


def encode_f32(value: float, word_order: str, byte_order: str) -> bytes:
    """decode_register 的逆操作，用于构造案例线上字节。"""
    buf = np.asarray([value], dtype=">f4").tobytes()
    if byte_order == "little":
        buf = bytes((buf[1], buf[0], buf[3], buf[2]))
    if word_order == "CDAB":
        buf = buf[2:4] + buf[0:2]
    return buf
