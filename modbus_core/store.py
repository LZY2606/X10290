"""SQLite 事件存储。

- 材料层（material）与事件层（event）共用一条每会话单调 seq，时间旅行按 seq 截断。
- 每次写入是一个 batch：batch 行先以 'writing' 落库，全部条目写完后置 'committed'，
  同一事务提交。崩溃导致的半写 batch 在 recover() 时被清除，绝不留下半成品。
- entry_id / digest 由内容决定：导出、删除本地数据库再导入后，身份、顺序与
  来源关系保持不变。
"""
from __future__ import annotations

import json
import os
import sqlite3
import time

from .domain import digest, canonical_json

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions(
  session_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  created REAL NOT NULL,
  meta TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS batches(
  batch_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  status TEXT NOT NULL,
  created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS entries(
  session_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  entry_id TEXT NOT NULL,
  batch_id TEXT,
  layer TEXT NOT NULL,
  kind TEXT NOT NULL,
  parents TEXT NOT NULL DEFAULT '[]',
  payload TEXT NOT NULL,
  digest TEXT NOT NULL,
  PRIMARY KEY(session_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_entries_id ON entries(entry_id);
"""

EXPORT_FORMAT = "modbus-review-export"
EXPORT_VERSION = 1


class ImportIntegrityError(Exception):
    pass


class Store:
    def __init__(self, path: str = "modbus_review.db"):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self.recover()

    def close(self):
        self.conn.close()

    def reset(self):
        self.conn.executescript(
            "DROP TABLE IF EXISTS entries; DROP TABLE IF EXISTS batches;"
            "DROP TABLE IF EXISTS sessions;" + SCHEMA)
        self.conn.commit()

    # ---- 半写恢复 ----
    def recover(self) -> list[str]:
        dangling = [r[0] for r in self.conn.execute(
            "SELECT batch_id FROM batches WHERE status != 'committed'")]
        for b in dangling:
            self.conn.execute("DELETE FROM entries WHERE batch_id=?", (b,))
            self.conn.execute("DELETE FROM batches WHERE batch_id=?", (b,))
        self.conn.commit()
        return dangling

    # ---- 会话 ----
    def create_session(self, title: str, meta: dict | None = None,
                       session_id: str | None = None, created: float | None = None) -> str:
        created = created if created is not None else time.time()
        meta = meta or {}
        session_id = session_id or "sess-" + digest(
            {"title": title, "created": created, "meta": meta})[:16]
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions(session_id,title,created,meta) VALUES(?,?,?,?)",
            (session_id, title, created, canonical_json(meta)))
        self.conn.commit()
        return session_id

    def list_sessions(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT session_id,title,created,meta FROM sessions ORDER BY created").fetchall()
        return [{"session_id": r[0], "title": r[1], "created": r[2],
                 "meta": json.loads(r[3])} for r in rows]

    def get_session(self, session_id: str) -> dict | None:
        r = self.conn.execute(
            "SELECT session_id,title,created,meta FROM sessions WHERE session_id=?",
            (session_id,)).fetchone()
        if not r:
            return None
        return {"session_id": r[0], "title": r[1], "created": r[2], "meta": json.loads(r[3])}

    # ---- 追加 ----
    def _next_seq(self, session_id: str) -> int:
        r = self.conn.execute(
            "SELECT COALESCE(MAX(seq),0) FROM entries WHERE session_id=?",
            (session_id,)).fetchone()
        return int(r[0]) + 1

    def append(self, session_id: str, items: list[dict]) -> list[str]:
        """items: [{layer, kind, payload, parents?, entry_id?}]，单事务原子提交。"""
        if not items:
            return []
        batch_id = "batch-" + digest(
            {"sid": session_id, "n": self._next_seq(session_id),
             "kinds": [i["kind"] for i in items],
             "t": time.time_ns()})[:16]
        ids = []
        seq = self._next_seq(session_id)
        with self.conn:  # 原子：要么全部落库，要么全部回滚
            self.conn.execute(
                "INSERT INTO batches(batch_id,session_id,status,created) VALUES(?,?,?,?)",
                (batch_id, session_id, "writing", time.time()))
            for item in items:
                payload = item["payload"]
                dg = digest(payload)
                entry_id = item.get("entry_id") or self._make_entry_id(
                    session_id, seq, item["layer"], item["kind"], payload)
                self.conn.execute(
                    "INSERT INTO entries(session_id,seq,entry_id,batch_id,layer,kind,parents,payload,digest)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (session_id, seq, entry_id, batch_id, item["layer"], item["kind"],
                     canonical_json(item.get("parents", [])),
                     canonical_json(payload), dg))
                ids.append(entry_id)
                seq += 1
            self.conn.execute("UPDATE batches SET status='committed' WHERE batch_id=?",
                              (batch_id,))
        return ids

    @staticmethod
    def _make_entry_id(session_id: str, seq: int, layer: str, kind: str, payload: dict) -> str:
        prefix = "mat" if layer == "material" else "ev"
        return f"{prefix}-" + digest(
            {"sid": session_id, "seq": seq, "layer": layer, "kind": kind,
             "payload": payload})[:16]

    # ---- 读取 ----
    def entries(self, session_id: str, upto_seq: int | None = None,
                layer: str | None = None) -> list[dict]:
        sql = ("SELECT e.seq,e.entry_id,e.layer,e.kind,e.parents,e.payload,e.digest "
               "FROM entries e JOIN batches b ON e.batch_id=b.batch_id "
               "WHERE e.session_id=? AND b.status='committed'")
        args: list = [session_id]
        if upto_seq is not None:
            sql += " AND e.seq<=?"
            args.append(upto_seq)
        if layer:
            sql += " AND e.layer=?"
            args.append(layer)
        sql += " ORDER BY e.seq"
        return [{"seq": r[0], "entry_id": r[1], "layer": r[2], "kind": r[3],
                 "parents": json.loads(r[4]), "payload": json.loads(r[5]),
                 "digest": r[6]}
                for r in self.conn.execute(sql, args)]

    def max_seq(self, session_id: str) -> int:
        r = self.conn.execute(
            "SELECT COALESCE(MAX(seq),0) FROM entries WHERE session_id=?",
            (session_id,)).fetchone()
        return int(r[0])

    # ---- 导出 / 导入 ----
    def export_session(self, session_id: str) -> dict:
        session = self.get_session(session_id)
        if not session:
            raise KeyError(f"会话不存在: {session_id}")
        return {
            "format": EXPORT_FORMAT,
            "version": EXPORT_VERSION,
            "session": session,
            "entries": self.entries(session_id),
        }

    def import_session(self, data: dict) -> str:
        if data.get("format") != EXPORT_FORMAT:
            raise ImportIntegrityError(f"未知导出格式: {data.get('format')!r}")
        sess = data["session"]
        sid = sess["session_id"]
        entries = data["entries"]
        # 完整性校验：digest 与 entry_id 必须由内容重算得到
        for e in entries:
            if digest(e["payload"]) != e["digest"]:
                raise ImportIntegrityError(
                    f"条目 {e['entry_id']} 摘要校验失败，拒绝导入")
            expect = self._make_entry_id(sid, e["seq"], e["layer"], e["kind"], e["payload"])
            if expect != e["entry_id"]:
                raise ImportIntegrityError(
                    f"条目 {e['entry_id']} 身份校验失败（应为 {expect}），拒绝导入")
        existing = self.get_session(sid)
        if existing:
            have = self.entries(sid)
            if [x["entry_id"] for x in have] == [x["entry_id"] for x in entries]:
                return sid  # 幂等：同一导出重复导入不产生变化
            raise ImportIntegrityError(f"会话 {sid} 已存在且内容不同，拒绝覆盖")
        self.create_session(sess["title"], meta=sess.get("meta"),
                            session_id=sid, created=sess["created"])
        batch_id = "batch-import-" + digest({"sid": sid, "n": len(entries)})[:16]
        with self.conn:
            self.conn.execute(
                "INSERT INTO batches(batch_id,session_id,status,created) VALUES(?,?,?,?)",
                (batch_id, sid, "writing", time.time()))
            for e in entries:
                self.conn.execute(
                    "INSERT INTO entries(session_id,seq,entry_id,batch_id,layer,kind,parents,payload,digest)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (sid, e["seq"], e["entry_id"], batch_id, e["layer"], e["kind"],
                     canonical_json(e["parents"]), canonical_json(e["payload"]), e["digest"]))
            self.conn.execute("UPDATE batches SET status='committed' WHERE batch_id=?",
                              (batch_id,))
        return sid
