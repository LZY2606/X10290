"""共享结果类型与稳定身份工具。

三种失败结果必须可区分：budget_exhausted / format_corrupt / semantic_unsolvable。
诊断永远携带位置（字节偏移或对象序号），不允许用空值伪装成功。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class Status(str, Enum):
    OK = "ok"
    BUDGET_EXHAUSTED = "budget_exhausted"
    FORMAT_CORRUPT = "format_corrupt"
    SEMANTIC_UNSOLVABLE = "semantic_unsolvable"


@dataclass
class Diagnostic:
    code: str
    message: str
    position: Optional[int] = None
    subject: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Result:
    status: Status = Status.OK
    value: Any = None
    diagnostics: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == Status.OK

    @classmethod
    def failure(cls, status: Status, code: str, message: str,
                position: Optional[int] = None, subject: Optional[str] = None) -> "Result":
        return cls(status=status, diagnostics=[Diagnostic(code, message, position, subject)])


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


def stable_id(prefix: str, payload: Any, length: int = 16) -> str:
    return f"{prefix}-{stable_hash(payload)[:length]}"
