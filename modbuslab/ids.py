"""稳定身份：全部 ID 由内容决定，不依赖自增主键或墙钟时间。"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(prefix: str, payload: Any) -> str:
    h = hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{h}"


def material_id(kind: str, source: str, index: int) -> str:
    return digest(f"mat-{kind}", {"source": source, "index": index})


def frame_id(frame: dict) -> str:
    return digest("frm", {
        "source": frame["source"],
        "kind": frame["transport"],
        "index": frame["seq"],
        "adu": frame["adu_hex"],
        "dir": frame["dir"],
        "t_ms": frame["t_ms"],
    })


def event_id(seq: int, kind: str, payload: Any) -> str:
    return digest("evt", {"seq": seq, "kind": kind, "payload": payload})
