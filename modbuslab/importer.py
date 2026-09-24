"""轨迹 / 映射 / 串口事件导入。

三种结果严格区分：
- OK：全部材料入库；
- RESOURCE_EXHAUSTED：资源预算（字节/条数）耗尽，不消费任何材料；
- FORMAT_CORRUPT：容器或记录损坏，定位到文件与行/字段；
- SEMANTIC_NO_SOLUTION：结构可读但业务语义无解（如 CRC 错帧是可保留材料，
  但映射引用了不存在条目等）。
输入不完整时产生带位置诊断，绝不用默认值伪装成功。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .codec import AduError, parse_rtu, parse_tcp
from .ids import material_id

DEFAULT_BUDGET = {"max_bytes": 8 * 1024 * 1024, "max_records": 20_000}


class ImportError2(Exception):
    def __init__(self, code: str, position: str, message: str):
        super().__init__(message)
        self.code, self.position, self.message = code, position, message


@dataclass
class ImportReport:
    ok: bool
    frames: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)       # 连接/串口材料
    mappings: list[dict] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)  # 帧级，仍可保留
    code: str | None = None
    position: str | None = None

    def fatal(self, code: str, position: str, message: str):
        self.ok = False
        self.code, self.position = code, position
        self.diagnostics.append({"code": code, "position": position, "message": message})
        return self


def load_trace_file(text: str, source: str, budget: dict | None = None) -> ImportReport:
    budget = budget or DEFAULT_BUDGET
    rep = ImportReport(ok=True)
    if len(text.encode("utf-8")) > budget["max_bytes"]:
        return ImportReport(ok=False).fatal(
            "RESOURCE_EXHAUSTED", f"file:{source}",
            f"文件超过字节预算 {budget['max_bytes']}")
    lines = text.splitlines()
    if len(lines) > budget["max_records"]:
        return ImportReport(ok=False).fatal(
            "RESOURCE_EXHAUSTED", f"file:{source}",
            f"记录数超过预算 {budget['max_records']}")
    if not lines:
        return ImportReport(ok=False).fatal("FORMAT_CORRUPT", f"file:{source}", "空文件")

    for lineno, line in enumerate(lines, 1):
        if not line.strip():
            continue
        pos = f"{source}:line{lineno}"
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            return ImportReport(ok=False).fatal(
                "FORMAT_CORRUPT", f"{pos}.json", f"JSON 损坏: {exc.msg}")
        try:
            kind = rec["kind"]
        except (TypeError, KeyError):
            return ImportReport(ok=False).fatal("FORMAT_CORRUPT", pos, "缺少 kind 字段")
        if kind == "frame":
            _ingest_frame(rec, source, lineno, pos, rep)
        elif kind in ("connection", "serial"):
            _ingest_event(rec, source, lineno, pos, rep)
        else:
            return ImportReport(ok=False).fatal(
                "FORMAT_CORRUPT", f"{pos}.kind", f"未知记录类型 {kind!r}")
    return rep


def _require(rec: dict, key: str, pos: str, typ: type | tuple):
    if key not in rec:
        raise ImportError2("FORMAT_CORRUPT", f"{pos}.{key}", f"缺少字段 {key}")
    if not isinstance(rec[key], typ):
        raise ImportError2("FORMAT_CORRUPT", f"{pos}.{key}", f"字段 {key} 类型错误")
    return rec[key]


def _ingest_frame(rec: dict, source: str, lineno: int, pos: str, rep: ImportReport):
    try:
        transport = _require(rec, "transport", pos, str)
        direction = _require(rec, "dir", pos, str)
        adu_hex = _require(rec, "adu", pos, str)
        t_ms = _require(rec, "t_ms", pos, (int, float))
    except ImportError2 as exc:
        rep.fatal(exc.code, exc.position, exc.message)
        return
    if transport not in ("tcp", "rtu"):
        rep.fatal("FORMAT_CORRUPT", f"{pos}.transport", f"未知传输 {transport}")
        return
    if direction not in ("out", "in"):
        rep.fatal("FORMAT_CORRUPT", f"{pos}.dir", "dir 必须是 out/in")
        return
    try:
        adu = bytes.fromhex(adu_hex)
    except ValueError:
        rep.fatal("FORMAT_CORRUPT", f"{pos}.adu", "adu 不是十六进制")
        return
    role = "request" if direction == "out" else "response"

    mid = material_id("frame", source, lineno)
    frame = {
        "id": mid, "source": source, "seq": lineno, "transport": transport,
        "dir": direction, "adu_hex": adu.hex(), "t_ms": t_ms,
        "channel": rec.get("channel", "tcp-1" if transport == "tcp" else "bus-1"),
        "raw_note": rec.get("note", ""),
    }
    try:
        parsed = parse_tcp(adu, role) if transport == "tcp" else parse_rtu(adu, role)
        frame["unit"] = parsed.unit
        frame["xid"] = parsed.xid
        frame["fc"] = parsed.pdu.fc
        frame["role"] = parsed.pdu.role
        frame["exception_code"] = parsed.pdu.exception_code
        frame["address"] = parsed.pdu.address
        frame["quantity"] = parsed.pdu.quantity
        frame["values_hex"] = parsed.pdu.values_hex
        frame["byte_count"] = parsed.pdu.byte_count
        frame["crc_ok"] = parsed.crc_ok
        frame["crc_received"] = parsed.crc_received
        frame["crc_calculated"] = parsed.crc_calculated
        frame["parse_code"] = None
        frame["parse_position"] = None
        frame["parse_message"] = None
    except AduError as exc:
        # 原 ADU 保留；派生层按诊断处理，不丢弃材料
        frame.update({"unit": None, "xid": None, "fc": None, "role": None,
                      "exception_code": None, "address": None, "quantity": None,
                      "values_hex": None, "byte_count": None, "crc_ok": None,
                      "crc_received": None, "crc_calculated": None,
                      "parse_code": exc.code, "parse_position": exc.position,
                      "parse_message": exc.message})
        rep.diagnostics.append({"code": exc.code, "position": f"{pos}.{exc.position}",
                                "message": exc.message, "frame_id": mid})
    rep.frames.append(frame)


def _ingest_event(rec: dict, source: str, lineno: int, pos: str, rep: ImportReport):
    try:
        action = _require(rec, "action", pos, str)
        t_ms = _require(rec, "t_ms", pos, (int, float))
    except ImportError2 as exc:
        rep.fatal(exc.code, exc.position, exc.message)
        return
    ev = {"id": material_id(rec["kind"], source, lineno), "kind": rec["kind"],
          "source": source, "seq": lineno, "action": action, "t_ms": t_ms,
          "channel": rec.get("channel", ""), "detail": rec.get("detail", {})}
    if rec["kind"] == "serial" and "gap_ms" in rec:
        if not isinstance(rec["gap_ms"], (int, float)):
            rep.fatal("FORMAT_CORRUPT", f"{pos}.gap_ms", "gap_ms 必须是数字")
            return
        ev["gap_ms"] = rec["gap_ms"]
    rep.events.append(ev)


def load_mapping_file(text: str, source: str) -> ImportReport:
    rep = ImportReport(ok=True)
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        return ImportReport(ok=False).fatal("FORMAT_CORRUPT", f"file:{source}.json", exc.msg)
    if not isinstance(doc, dict) or "version" not in doc or "entries" not in doc:
        return ImportReport(ok=False).fatal(
            "FORMAT_CORRUPT", f"file:{source}", "映射必须含 version 与 entries")
    version = doc["version"]
    base = doc.get("address_base", 0)
    if base not in (0, 1):
        return ImportReport(ok=False).fatal(
            "SEMANTIC_NO_SOLUTION", f"file:{source}.address_base", "地址基准只能是 0 或 1")
    seen: set[tuple] = set()
    for i, e in enumerate(doc["entries"]):
        pos = f"{source}:entry{i}"
        for key in ("name", "space", "address", "dtype"):
            if key not in e:
                return ImportReport(ok=False).fatal("FORMAT_CORRUPT", f"{pos}.{key}",
                                                    f"映射条目缺少 {key}")
        if e["space"] not in (0, 1, 3, 4):
            return ImportReport(ok=False).fatal("SEMANTIC_NO_SOLUTION", f"{pos}.space",
                                                "space 必须是 0/1/3/4")
        if not isinstance(e["address"], int) or not 0 <= e["address"] <= 0xFFFF:
            return ImportReport(ok=False).fatal("SEMANTIC_NO_SOLUTION", f"{pos}.address",
                                                "地址必须是 0..65535 的整数（按该表基准）")
        key = (e["space"], e["address"])
        if key in seen:
            return ImportReport(ok=False).fatal("SEMANTIC_NO_SOLUTION", f"{pos}",
                                                "同一空间内地址重复，无法唯一解释")
        seen.add(key)
        mid = material_id("mapentry", f"{source}#{version}", i)
        rep.mappings.append({
            "id": mid, "version": str(version), "address_base": base,
            "name": e["name"], "space": e["space"], "address": e["address"],
            "dtype": e["dtype"], "scale": e.get("scale", 1.0),
            "offset": e.get("offset", 0.0), "unit": e.get("unit", ""),
            "word_order": e.get("word_order", "big"),
            "valid_min": e.get("valid_min"), "valid_max": e.get("valid_max"),
            "source": source, "seq": i,
        })
    return rep
