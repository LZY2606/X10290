"""Device mapping versions.

A mapping is an immutable material. Its declared address base is retained;
internally points are indexed by zero based wire addresses. Conversion to one
based values happens only in the presentation layer.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .identity import stable_id
from .model import Diagnostic, DomainError, FAIL_FORMAT_CORRUPT

WORD_ORDERS = ("abcd", "badc", "cdab", "dcba")
POINT_KINDS = ("uint16", "int16", "uint32", "int32", "float32", "coil", "raw")
_KIND_REGS = {
    "uint16": 1, "int16": 1, "uint32": 2, "int32": 2,
    "float32": 2, "coil": 1,
}


@dataclass
class MappingPoint:
    name: str
    register_raw: int
    register_zero_based: int
    address_base: int
    kind: str
    register_count: int
    unit: str
    scale: float = 1.0
    offset: float = 0.0
    word_order: str | None = None
    minimum: float | None = None
    maximum: float | None = None
    writable: bool = False
    note: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "register": self.register_raw,
            "register_zero_based": self.register_zero_based,
            "address_base": self.address_base,
            "kind": self.kind,
            "register_count": self.register_count,
            "unit": self.unit,
            "scale": self.scale,
            "offset": self.offset,
            "word_order": self.word_order,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "writable": self.writable,
            "note": self.note,
        }


@dataclass
class DeviceMapping:
    mapping_id: str
    version: str
    source: str
    address_base: int
    default_word_order: str
    points: list[MappingPoint]
    raw: dict[str, Any]
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "mapping_id": self.mapping_id,
            "version": self.version,
            "source": self.source,
            "address_base": self.address_base,
            "default_word_order": self.default_word_order,
            "points": [p.as_dict() for p in self.points],
            "digest": self.digest,
        }

    def point_map(self) -> dict[int, list[MappingPoint]]:
        result: dict[int, list[MappingPoint]] = {}
        for point in self.points:
            for reg in range(point.register_zero_based,
                            point.register_zero_based + point.register_count):
                result.setdefault(reg, []).append(point)
        return result


def load_mapping(path_or_file: str, *, source: str | None = None) -> DeviceMapping:
    if isinstance(path_or_file, str) and (
        path_or_file.startswith("{") or "\n" in path_or_file
    ):
        text = path_or_file
        source = source or "<inline>"
    elif isinstance(path_or_file, str):
        with open(path_or_file, "r", encoding="utf-8") as handle:
            text = handle.read()
        source = source or path_or_file
    else:
        text = path_or_file.read()
        source = source or getattr(path_or_file, "name", "<mapping>")
    return parse_mapping(text, source=source)


def parse_mapping(text: str, *, source: str) -> DeviceMapping:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DomainError(
            FAIL_FORMAT_CORRUPT, "mapping_not_json", str(exc),
            [Diagnostic("mapping_not_json", str(exc),
                        {"source": source, "line": exc.lineno,
                         "column": exc.colno})])
    diagnostics: list[Diagnostic] = []
    if not isinstance(raw, dict):
        raise DomainError(
            FAIL_FORMAT_CORRUPT, "mapping_not_object",
            "mapping root must be an object",
            [Diagnostic("mapping_not_object", "root is not an object",
                        {"source": source})])
    version = raw.get("version")
    if not isinstance(version, str) or not version:
        diagnostics.append(Diagnostic(
            "mapping_version_missing", "mapping.version must be a non empty string",
            {"source": source}))
    base = raw.get("address_base")
    if base not in (0, 1):
        diagnostics.append(Diagnostic(
            "address_base_invalid", "mapping.address_base must be 0 or 1",
            {"source": source, "found": base}))
    order = raw.get("default_word_order", "abcd")
    if order not in WORD_ORDERS:
        diagnostics.append(Diagnostic(
            "word_order_invalid",
            f"default_word_order must be one of {WORD_ORDERS}",
            {"source": source, "found": order}))
    raw_points = raw.get("points")
    if not isinstance(raw_points, list) or not raw_points:
        diagnostics.append(Diagnostic(
            "points_invalid", "mapping.points must be a non empty list",
            {"source": source}))
        raw_points = []
    points: list[MappingPoint] = []
    seen_names: set[str] = set()
    for index, item in enumerate(raw_points):
        location = {"source": source, "point_index": index}
        if not isinstance(item, dict):
            diagnostics.append(Diagnostic("point_not_object",
                                          "point entry must be an object",
                                          location))
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name:
            diagnostics.append(Diagnostic("point_name_missing",
                                          "point.name required", location))
            continue
        if name in seen_names:
            diagnostics.append(Diagnostic("point_name_duplicate",
                                          f"duplicate point {name}", location))
        seen_names.add(name)
        reg = item.get("register")
        kind = item.get("kind", "uint16")
        if not isinstance(reg, int) or reg < 0:
            diagnostics.append(Diagnostic(
                "point_register_invalid",
                "point.register must be a non negative integer in declared base",
                {**location, "found": reg}))
            continue
        if kind not in POINT_KINDS:
            diagnostics.append(Diagnostic(
                "point_kind_invalid", f"kind must be one of {POINT_KINDS}",
                {**location, "found": kind}))
            continue
        count = item.get("register_count", _KIND_REGS.get(kind, 1))
        if not isinstance(count, int) or count < 1:
            diagnostics.append(Diagnostic(
                "point_count_invalid", "register_count must be a positive int",
                {**location, "found": count}))
            continue
        p_order = item.get("word_order", order)
        if kind in ("uint32", "int32", "float32") and p_order not in WORD_ORDERS:
            diagnostics.append(Diagnostic(
                "point_word_order_invalid",
                f"32 bit point requires one of {WORD_ORDERS}",
                {**location, "found": p_order}))
        points.append(MappingPoint(
            name=name,
            register_raw=reg,
            register_zero_based=reg - (base if base in (0, 1) else 0),
            address_base=base if base in (0, 1) else 0,
            kind=kind,
            register_count=count,
            unit=str(item.get("unit", "")),
            scale=float(item.get("scale", 1.0)),
            offset=float(item.get("offset", 0.0)),
            word_order=p_order if kind in ("uint32", "int32", "float32") else None,
            minimum=item.get("minimum"),
            maximum=item.get("maximum"),
            writable=bool(item.get("writable", False)),
            note=str(item.get("note", "")),
            raw=item,
        ))
    if diagnostics:
        raise DomainError(FAIL_FORMAT_CORRUPT, "mapping_invalid",
                          f"mapping {source} is not usable", diagnostics)
    mapping_id = raw.get("mapping_id") or f"map-{version}"
    digest = stable_id("map", source, raw)
    return DeviceMapping(
        mapping_id=str(mapping_id), version=version, source=source,
        address_base=base, default_word_order=order, points=points,
        raw=raw, digest=digest)
