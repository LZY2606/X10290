"""SQLite 存储层：不可变材料 + 事件流 + 内容寻址派生记录。

- materials：不可变原始材料（原 ADU 字节、方向、tid、unit、CRC、功能码、映射版本）。
- events：一切改动都是事件（导入、推导运行、参数修订、源数据改动、人工决定、规则断言、重放证据）。
- derived + run_items：派生记录内容寻址；每次推导运行记录当时的可见结论，历史不被覆盖。
- 导出/导入保持身份、顺序与来源关系；导入单事务执行，任何失败整体回滚（半写恢复）。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3

from .model import Result, Status, canonical, stable_id

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS materials (
    id TEXT PRIMARY KEY, seq INTEGER NOT NULL, ord INTEGER NOT NULL DEFAULT 0,
    kind TEXT NOT NULL, session TEXT NOT NULL, raw TEXT, direction TEXT,
    tick REAL, connection_id TEXT, meta TEXT NOT NULL, event_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, seq INTEGER NOT NULL, branch TEXT NOT NULL,
    kind TEXT NOT NULL, payload TEXT NOT NULL, parents TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS derived (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, rule_version TEXT NOT NULL,
    input_digest TEXT NOT NULL, parents TEXT NOT NULL,
    status TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS run_items (
    run_id TEXT NOT NULL, ord INTEGER NOT NULL, derived_id TEXT NOT NULL,
    PRIMARY KEY (run_id, ord));
"""

TABLES = ("events", "materials", "derived", "run_items")


def material_id(m: dict) -> str:
    return stable_id("mat", {
        "kind": m["kind"], "session": m.get("session", "session-1"),
        "raw": m.get("raw"), "direction": m.get("direction"),
        "tick": m.get("tick"), "connection_id": m.get("connection_id"),
        "meta": m.get("meta", {})})


class Store:
    def __init__(self, path: str = ":memory:"):
        self.path = path
        self.conn = sqlite3.connect(path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('seq', '0')")

    def close(self):
        self.conn.close()

    def is_empty(self) -> bool:
        return self.conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"] == 0

    def _next_seq(self) -> int:
        seq = int(self.conn.execute("SELECT value FROM meta WHERE key='seq'").fetchone()["value"]) + 1
        self.conn.execute("UPDATE meta SET value=? WHERE key='seq'", (str(seq),))
        return seq

    def add_event(self, branch: str, kind: str, payload: dict, parents=()) -> str:
        seq = self._next_seq()
        eid = f"evt-{seq:04d}"
        self.conn.execute(
            "INSERT INTO events(id, seq, branch, kind, payload, parents) VALUES (?,?,?,?,?,?)",
            (eid, seq, branch, kind, canonical(payload), canonical(list(parents))))
        return eid

    def record_event(self, branch: str, kind: str, payload: dict, parents=()) -> str:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            eid = self.add_event(branch, kind, payload, parents)
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        return eid

    def record_materials(self, branch: str, kind: str, materials: list, payload: dict) -> str:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            ids = [material_id(m) for m in materials]
            full_payload = dict(payload)
            eid = self.add_event(branch, kind, full_payload, parents=ids)
            seq = int(eid.split("-")[1])
            for order, (m, mid) in enumerate(zip(materials, ids)):
                self.conn.execute(
                    "INSERT OR IGNORE INTO materials"
                    "(id, seq, ord, kind, session, raw, direction, tick, connection_id, meta, event_id)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (mid, seq, order, m["kind"], m.get("session", "session-1"), m.get("raw"),
                     m.get("direction"), m.get("tick"), m.get("connection_id"),
                     canonical(m.get("meta", {})), eid))
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        return eid

    def add_derived_run(self, branch: str, rule_version: str, items: list,
                        status: str, diagnostics: list, note: str) -> str:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            run_id = self.add_event(branch, "derive_run", {
                "note": note, "rule_version": rule_version, "status": status,
                "item_count": len(items),
                "diagnostics": [d.to_dict() if hasattr(d, "to_dict") else d for d in diagnostics],
            }, parents=[it["id"] for it in items])
            for it in items:
                self.conn.execute(
                    "INSERT OR IGNORE INTO derived"
                    "(id, kind, rule_version, input_digest, parents, status, payload)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (it["id"], it["kind"], rule_version, it["input_digest"],
                     canonical(it["parents"]), it["status"], canonical(it["payload"])))
            for order, it in enumerate(items):
                self.conn.execute(
                    "INSERT INTO run_items(run_id, ord, derived_id) VALUES (?,?,?)",
                    (run_id, order, it["id"]))
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        return run_id

    # ---- 查询 ----

    def all_events(self) -> list:
        return [dict(r) for r in self.conn.execute("SELECT * FROM events ORDER BY seq")]

    def all_materials(self) -> list:
        rows = self.conn.execute("SELECT * FROM materials ORDER BY seq, ord, id").fetchall()
        return [self._mat(r) for r in rows]

    @staticmethod
    def _mat(row) -> dict:
        d = dict(row)
        d["meta"] = json.loads(d["meta"])
        return d

    def superseded_ids(self, as_of=None) -> set:
        q = "SELECT payload FROM events WHERE kind='source_change'"
        if as_of is not None:
            q += f" AND seq <= {int(as_of)}"
        ids = set()
        for r in self.conn.execute(q):
            ids.add(json.loads(r["payload"])["supersedes"])
        return ids

    def active_materials(self, as_of=None) -> list:
        sup = self.superseded_ids(as_of)
        mats = self.all_materials()
        if as_of is not None:
            mats = [m for m in mats if m["seq"] <= as_of]
        return [m for m in mats if m["id"] not in sup]

    def mapping_materials(self, as_of=None) -> list:
        return [m for m in self.active_materials(as_of) if m["kind"] == "mapping"]

    def active_mapping_meta(self, as_of=None):
        q = "SELECT payload FROM events WHERE kind='param_adjust'"
        if as_of is not None:
            q += f" AND seq <= {int(as_of)}"
        q += " ORDER BY seq DESC LIMIT 1"
        row = self.conn.execute(q).fetchone()
        version = json.loads(row["payload"]).get("active_mapping") if row else None
        maps = self.mapping_materials(as_of)
        if version:
            for m in maps:
                if m["meta"].get("version") == version:
                    return m["meta"]
        return maps[0]["meta"] if maps else None

    def latest_run(self, as_of=None):
        q = "SELECT * FROM events WHERE kind='derive_run'"
        if as_of is not None:
            q += f" AND seq <= {int(as_of)}"
        q += " ORDER BY seq DESC LIMIT 1"
        row = self.conn.execute(q).fetchone()
        if not row:
            return None
        d = dict(row)
        d["payload"] = json.loads(d["payload"])
        d["parents"] = json.loads(d["parents"])
        return d

    def run_records(self, run_id: str) -> list:
        rows = self.conn.execute(
            "SELECT d.* FROM run_items ri JOIN derived d ON d.id = ri.derived_id"
            " WHERE ri.run_id=? ORDER BY ri.ord", (run_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["parents"] = json.loads(d["parents"])
            d["payload"] = json.loads(d["payload"])
            out.append(d)
        return out

    def decisions(self, branch=None, as_of=None) -> list:
        q = "SELECT * FROM events WHERE kind='decision'"
        args: list = []
        if branch:
            q += " AND branch=?"
            args.append(branch)
        if as_of is not None:
            q += f" AND seq <= {int(as_of)}"
        q += " ORDER BY seq"
        out = []
        for r in self.conn.execute(q, args).fetchall():
            d = dict(r)
            d["payload"] = json.loads(d["payload"])
            out.append(d)
        return out

    def counts(self) -> dict:
        return {t: self.conn.execute(f"SELECT COUNT(*) c FROM {t}").fetchone()["c"]
                for t in ("materials", "events", "derived", "run_items")}

    # ---- 导出 / 导入 ----

    def export_archive(self) -> dict:
        archive = {"schema": 1}
        orders = {"materials": "seq, ord, id", "events": "seq",
                  "derived": "id", "run_items": "run_id, ord"}
        for table, order in orders.items():
            archive[table] = [dict(r) for r in
                              self.conn.execute(f"SELECT * FROM {table} ORDER BY {order}")]
        archive["checksum"] = hashlib.sha256(
            canonical(archive).encode("utf-8")).hexdigest()
        return archive

    def import_archive(self, archive) -> Result:
        if not isinstance(archive, dict):
            return Result.failure(Status.FORMAT_CORRUPT, "bad_archive",
                                  "档案不是 JSON 对象", position=0)
        checksum = archive.get("checksum")
        body = {k: v for k, v in archive.items() if k != "checksum"}
        if not checksum or checksum != hashlib.sha256(
                canonical(body).encode("utf-8")).hexdigest():
            return Result.failure(Status.FORMAT_CORRUPT, "bad_checksum",
                                  "档案校验和不符：文件损坏或被截断", position=0)
        conflicts = []
        for table in ("materials", "events", "derived"):
            for row in body.get(table, []):
                existing = self.conn.execute(
                    f"SELECT * FROM {table} WHERE id=?", (row["id"],)).fetchone()
                if existing and canonical(dict(existing)) != canonical(row):
                    conflicts.append(row["id"])
        if conflicts:
            return Result.failure(Status.SEMANTIC_UNSOLVABLE, "identity_conflict",
                                  f"相同身份的内容不一致: {sorted(conflicts)[:3]}",
                                  subject=conflicts[0])
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            for table in TABLES:
                for row in body.get(table, []):
                    cols = ",".join(row.keys())
                    marks = ",".join("?" for _ in row)
                    self.conn.execute(
                        f"INSERT OR IGNORE INTO {table}({cols}) VALUES ({marks})",
                        tuple(row.values()))
            max_seq = self.conn.execute("SELECT MAX(seq) s FROM events").fetchone()["s"] or 0
            self.conn.execute("UPDATE meta SET value=? WHERE key='seq'", (str(max_seq),))
            self.conn.execute("COMMIT")
        except sqlite3.Error as exc:
            self.conn.execute("ROLLBACK")
            return Result.failure(Status.FORMAT_CORRUPT, "import_aborted",
                                  f"导入中途失败，已整体回滚，数据库未受影响: {exc}")
        return Result(value={"imported": {t: len(body.get(t, [])) for t in TABLES}})
