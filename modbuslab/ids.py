"""稳定身份：内容寻址 + 稳定顺序。

身份只依赖规范化后的内容（不含导入时间、自增序号），因此等价输入在导出、
删除本地数据库再导入后仍得到相同身份与顺序。
"""
from __future__ import annotations

import hashlib
from typing import Any

PREFIX = {
    "case": "case",
    "channel": "ch",
    "frame": "frm",
    "busevent": "evt",
    "map": "map",
    "pair": "pr",
    "value": "val",
    "params": "par",
    "decision": "dec",
    "derivation": "drv",
    "assertion": "rul",
    "archive": "arc",
    "amend": "amd",
}


def canonical(obj: Any) -> bytes:
    """确定性 JSON：键排序、无空白、ensure_ascii=False 后 UTF-8 编码。"""
    import json

    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def digest(prefix: str, *parts: Any) -> str:
    content = canonical(list(parts))
    h = hashlib.sha256(content).hexdigest()[:16]
    return f"{prefix}_{h}"


def stable_order_key(record: dict[str, Any]) -> tuple:
    """等价输入得到稳定顺序：按证据出现的物理坐标排序。"""
    chan = record.get("channel_id", "")
    side = record.get("side", record.get("role", ""))
    side_rank = {"master": 0, "request": 0, "slave": 1, "response": 1}.get(side, 2)
    ts = record.get("t_ms")
    ts_key = (0, ts) if isinstance(ts, (int, float)) else (1, 0)
    seq = record.get("ord", 0)
    return (chan, ts_key, side_rank, seq, record.get("id", ""))
