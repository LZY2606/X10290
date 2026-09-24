"""Deterministic stable identities.

Identities are derived from immutable source content plus position, so an
export -> delete local database -> import round trip keeps every id and order.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable


def digest_json(payload: Any) -> str:
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def stable_id(prefix: str, *parts: Any) -> str:
    material: list[Any] = []
    for part in parts:
        if isinstance(part, (dict, list, tuple)):
            material.append(json.dumps(part, sort_keys=True,
                                       separators=(",", ":"),
                                       ensure_ascii=False))
        else:
            material.append(str(part))
    suffix = hashlib.sha256("\u241f".join(material).encode("utf-8")).hexdigest()
    return f"{prefix}_{suffix[:16]}"


def content_digest(parts: Iterable[Any]) -> str:
    return stable_id("sha", *parts)[4:]
