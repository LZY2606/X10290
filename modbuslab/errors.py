"""三种必须彼此可区分的失败结果。

- FormatCorrupt:   格式损坏（字节截断、非法十六进制、长度/结构不符）
- ResourceBudget:  资源预算耗尽（帧数/事件数/字节数/推导步数超限）
- SemanticUnresolvable: 语义无解（配对歧义未决定、映射冲突等）

所有诊断都携带 ``pos``（位置）与 ``code``，不使用空值或默认值伪装成功。
"""
from __future__ import annotations

from typing import Any


class LabError(Exception):
    code = "LAB_ERROR"

    def __init__(self, message: str, pos: str | None = None, **extra: Any) -> None:
        super().__init__(message)
        self.message = message
        self.pos = pos
        self.extra = extra

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.pos is not None:
            out["pos"] = self.pos
        out.update(self.extra)
        return out


class FormatCorrupt(LabError):
    code = "FORMAT_CORRUPT"


class ResourceBudgetExhausted(LabError):
    code = "RESOURCE_EXHAUSTED"


class SemanticUnresolvable(LabError):
    code = "SEMANTIC_UNRESOLVABLE"


def diagnostic(code: str, message: str, pos: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"code": code, "message": message, "pos": pos}
    out.update(extra)
    return out
