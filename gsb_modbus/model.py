"""Canonical serialization and stable identity helpers.

Equivalent inputs must always produce the same identity and the same ordering,
before and after an export/import round trip.
"""

from __future__ import annotations

import hashlib
import json
import datetime
from typing import Any

FORMAT_VERSION = 1


def canonical(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def content_digest(payload: dict) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()[:16]


def stable_id(prefix: str, *parts: Any) -> str:
    h = hashlib.sha1(canonical(list(parts))).hexdigest()[:12]
    return f"{prefix}_{h}"


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def bytes_to_hex(data: bytes | bytearray) -> str:
    return bytes(data).hex(" ")


def hex_to_bytes(text: str, *, position: str) -> bytes:
    cleaned = text.replace(" ", "").replace("0x", "").replace("\n", "").replace("\t", "")
    if len(cleaned) % 2 != 0:
        from .errors import FormatCorrupt

        raise FormatCorrupt(
            f"odd-length hex input: {text!r}", position=position
        )
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        from .errors import FormatCorrupt

        raise FormatCorrupt(f"invalid hex input: {exc}", position=position)


def require(obj: Any, kind: str, position: str) -> dict:
    if not isinstance(obj, dict):
        from .errors import FormatCorrupt

        raise FormatCorrupt(f"{kind} must be an object, got {type(obj).__name__}", position)
    return obj
