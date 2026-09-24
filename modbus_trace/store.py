"""SQLite 存储层：不可变材料 + 事件溯源 + 可修改决定，分层持久化。

- materials：不可变材料（帧、映射版本、串口事件），只增不改。
- events：机器可读取的追加式事件日志（导入/推导/决定/参数修订/冲突）。
- batches：每次写入是一个批次；崩溃留下的未提交批次在打开时清除，
  实现半写恢复。
- 导出/导入保持身份、顺序与来源关系。
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS materials (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    body TEXT NOT NULL,
    digest TEXT NOT NULL,
    batch_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    body TEXT NOT NULL,
    parents TEXT NOT NULL,
    batch_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

EXPORT_FORMAT = "modbus-trace-export/v1"


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._recover_half_writes()

    def close(self):
        self.conn.close()

    # ---------- 半写恢复 ----------
    def _recover_half_writes(self):
        """清除上次崩溃留下的未提交批次（半写恢复）。"""
        cur = self.conn.execute("SELECT batch_id FROM batches WHERE status != 'committed'")
        stale = [r["batch_id"] for r in cur.fetchall()]
        for batch_id in stale:
            self.conn.execute("DELETE FROM materials WHERE batch_id=?", (batch_id,))
            self.conn.execute("DELETE FROM events WHERE batch_id=?", (batch_id,))
            self.conn.execute("DELETE FROM batches WHERE batch_id=?", (batch_id,))
        self.conn.commit()
        return stale

    # ---------- 批次写入 ----------
    def commit_batch(self, *, materials: list[dict] | None = None,
                     events: list[dict] | None = None) -> str:
        """原子提交一个批次：材料与事件要么全部落库，要么全部不落。"""
        batch_id = f"batch-{uuid.uuid4().hex[:12]}"
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.conn:  # 单事务，崩溃即整体回滚
            self.conn.execute(
                "INSERT INTO batches(batch_id, status, created_at) VALUES (?,?,?)",
                (batch_id, "writing", now))
            for m in materials or []:
                self.conn.execute(
                    "INSERT OR REPLACE INTO materials(id, kind, body, digest, batch_id)"
                    " VALUES (?,?,?,?,?)",
                    (m["id"], m["kind"], json.dumps(m["body"], ensure_ascii=False,
                                                   sort_keys=True),
                     m["digest"], batch_id))
            for e in events or []:
                self.conn.execute(
                    "INSERT INTO events(event_id, seq, kind, body, parents, batch_id)"
                    " VALUES (?,?,?,?,?,?)",
                    (e["event_id"], e["seq"], e["kind"],
                     json.dumps(e["body"], ensure_ascii=False, sort_keys=True),
                     json.dumps(e.get("parents", [])), batch_id))
            self.conn.execute("UPDATE batches SET status='committed' WHERE batch_id=?",
                              (batch_id,))
        return batch_id

    # ---------- 读取 ----------
    def next_seq(self) -> int:
        row = self.conn.execute("SELECT COALESCE(MAX(seq), 0) AS s FROM events").fetchone()
        return row["s"] + 1

    def all_materials(self, kind: str | None = None) -> list[dict]:
        sql = "SELECT id, kind, body, digest FROM materials"
        args: tuple = ()
        if kind:
            sql += " WHERE kind=?"
            args = (kind,)
        sql += " ORDER BY id"
        return [{"id": r["id"], "kind": r["kind"], "body": json.loads(r["body"]),
                 "digest": r["digest"]}
                for r in self.conn.execute(sql, args).fetchall()]

    def all_events(self, upto_seq: int | None = None) -> list[dict]:
        sql = "SELECT event_id, seq, kind, body, parents FROM events"
        args: tuple = ()
        if upto_seq is not None:
            sql += " WHERE seq<=?"
            args = (upto_seq,)
        sql += " ORDER BY seq"
        return [{"event_id": r["event_id"], "seq": r["seq"], "kind": r["kind"],
                 "body": json.loads(r["body"]), "parents": json.loads(r["parents"])}
                for r in self.conn.execute(sql, args).fetchall()]

    def get_meta(self, key: str, default=None):
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str):
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?,?)",
                              (key, value))

    # ---------- 导出 / 导入 ----------
    def export(self) -> dict:
        """导出为自描述 JSON：身份、顺序、来源关系全部保留，带清单校验。"""
        from .core import canonical_digest
        materials = self.all_materials()
        events = self.all_events()
        manifest_payload = {
            "materials": [[m["id"], m["kind"], m["digest"]] for m in materials],
            "events": [[e["event_id"], e["seq"], e["kind"]] for e in events],
        }
        return {
            "format": EXPORT_FORMAT,
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "manifest": {
                "material_count": len(materials),
                "event_count": len(events),
                "digest": canonical_digest(manifest_payload),
            },
            "materials": materials,
            "events": events,
        }

    def import_(self, doc: dict) -> dict:
        """导入导出文档：先校验清单，再单事务写入；身份与顺序原样恢复。"""
        from .core import canonical_digest
        if doc.get("format") != EXPORT_FORMAT:
            raise ValueError(f"不支持的导出格式: {doc.get('format')!r}")
        materials = doc["materials"]
        events = doc["events"]
        manifest_payload = {
            "materials": [[m["id"], m["kind"], m["digest"]] for m in materials],
            "events": [[e["event_id"], e["seq"], e["kind"]] for e in events],
        }
        expected = doc["manifest"]
        actual = {"material_count": len(materials), "event_count": len(events),
                  "digest": canonical_digest(manifest_payload)}
        if actual["digest"] != expected["digest"]:
            raise ValueError("导出文档清单校验失败：内容被篡改或损坏")
        batch_id = self.commit_batch(
            materials=[{"id": m["id"], "kind": m["kind"], "body": m["body"],
                        "digest": m["digest"]} for m in materials],
            events=[{"event_id": e["event_id"], "seq": e["seq"], "kind": e["kind"],
                     "body": e["body"], "parents": e["parents"]} for e in events])
        return {"batch_id": batch_id, "materials": len(materials), "events": len(events)}
