"""项目导出 / 导入：事件日志 + 不可变材料 + 决定 + 反例档案。

身份全部内容寻址，所以导出后删除本地数据库再导入，ID、顺序与来源关系保持。
导入逐事件重放并重新推导，校验重算的派生身份与档案记录一致。
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from . import engine
from .ids import canonical

BUNDLE_KIND = "modbus-lab-bundle"
BUNDLE_VERSION = 1

MATERIAL_TABLES = ("materials_frames", "materials_events", "materials_maps")


def export_bundle(conn: sqlite3.Connection) -> dict:
    project = dict(conn.execute("SELECT * FROM projects LIMIT 1").fetchone())
    branches = [dict(r) for r in conn.execute("SELECT * FROM branches ORDER BY created_seq")]
    events = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY branch,seq")]
    decisions = [dict(r) for r in conn.execute("SELECT * FROM decisions ORDER BY rowid")]
    materials = {}
    for table in MATERIAL_TABLES:
        materials[table] = [dict(r) for r in conn.execute(f"SELECT * FROM {table}")]
    archives = [dict(r) for r in conn.execute("SELECT * FROM archive_cases ORDER BY seq")]
    return {
        "kind": BUNDLE_KIND, "bundle_version": BUNDLE_VERSION,
        "project": project, "branches": branches,
        "events": events, "decisions": decisions,
        "materials": materials, "archives": archives,
        "checksum": None,
    }


def export_file(conn: sqlite3.Connection, path: str | Path) -> str:
    bundle = export_bundle(conn)
    bundle["checksum"] = _checksum(bundle)
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)   # 原子替换，防止半写文件被当成有效导出
    return str(path)


def _checksum(bundle: dict) -> str:
    import hashlib
    body = {k: v for k, v in bundle.items() if k != "checksum"}
    return "sha256:" + hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


def import_bundle(conn: sqlite3.Connection, bundle: dict, verify: bool = True) -> dict:
    if bundle.get("kind") != BUNDLE_KIND:
        raise engine.EngineError("FORMAT_CORRUPT", "bundle.kind", "不是 modbus-lab 档案")
    got = bundle.get("checksum")
    if verify and got:
        body = {k: v for k, v in bundle.items() if k != "checksum"}
        if got != _checksum(body):
            raise engine.EngineError("FORMAT_CORRUPT", "bundle.checksum", "档案校验和不匹配")
    existing = conn.execute("SELECT COUNT(*) AS c FROM projects").fetchone()["c"]
    if existing:
        raise engine.EngineError("SEMANTIC_NO_SOLUTION", "database", "目标库非空，请使用空库导入")

    p = bundle["project"]
    conn.execute("INSERT INTO projects VALUES(?,?,?,?,?,?)",
                 (p["id"], p["name"], p["created_seq"], p["epoch_ms"],
                  p["time_base"], p["coordinate_base"]))
    for b in bundle["branches"]:
        conn.execute("INSERT INTO branches VALUES(?,?,?,?,?)",
                     (b["name"], b["parent_branch"], b["forked_at_event"],
                      b["head_event"], b["created_seq"]))

    # 先恢复不可变材料
    for table, rows in bundle["materials"].items():
        for r in rows:
            cols = list(r.keys())
            conn.execute(
                f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                [r[c] for c in cols])

    # 事件必须按分支顺序、seq 排序；派生事件身份由内容决定，重放校验
    events = sorted(bundle["events"], key=lambda e: (e["branch"], e["seq"]))
    for e in events:
        conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                     (e["id"], e["seq"], e["branch"], e["kind"], e["payload"],
                      e["input_summary"], e["params_version"], e["rule_version"],
                      e["parent_event"]))
        conn.execute("UPDATE branches SET head_event=? WHERE name=?",
                     (e["id"], e["branch"]))
    for d in bundle["decisions"]:
        conn.execute("INSERT INTO decisions VALUES(?,?,?,?,?,?,?,?)",
                     (d["id"], d["branch"], d["event_id"], d["subject_id"], d["decision"],
                      d["reason"], d["payload"], d["supersedes"]))
    for a in bundle.get("archives", []):
        cols = list(a.keys())
        conn.execute(
            f"INSERT INTO archive_cases ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
            [a[c] for c in cols])
    return {"events": len(events), "materials": sum(len(v) for v in bundle["materials"].values()),
            "archives": len(bundle.get("archives", []))}
