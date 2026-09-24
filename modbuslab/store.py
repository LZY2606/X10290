"""SQLite 存储层。

分层：
- materials_*：不可变原始材料（原 ADU、方向、xid、unit、CRC、功能码、地址基准…）；
- events：事件日志（导入/推导/参数修订/决定），身份由内容决定；
- projections_*：每次 derive 的派生快照，记录输入摘要、规则版本、父级依赖；
- commits：崩溃恢复用暂存标记，启动时未完成的事务整体回滚（半写恢复）。
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY, name TEXT, created_seq INTEGER,
  epoch_ms REAL, time_base TEXT, coordinate_base TEXT
);
CREATE TABLE IF NOT EXISTS branches (
  name TEXT PRIMARY KEY, parent_branch TEXT, forked_at_event TEXT,
  head_event TEXT, created_seq INTEGER
);
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, seq INTEGER, branch TEXT, kind TEXT, payload TEXT,
  input_summary TEXT, params_version TEXT, rule_version TEXT, parent_event TEXT,
  UNIQUE(branch, seq)
);
CREATE TABLE IF NOT EXISTS commits (staging_id TEXT PRIMARY KEY, event_id TEXT, seq INTEGER, branch TEXT);

CREATE TABLE IF NOT EXISTS materials_frames (
  id TEXT PRIMARY KEY, source TEXT, seq INTEGER, transport TEXT, dir TEXT,
  adu_hex TEXT, t_ms REAL, channel TEXT, unit INTEGER, xid INTEGER, fc INTEGER,
  role TEXT, exception_code INTEGER, address INTEGER, quantity INTEGER,
  values_hex TEXT, byte_count INTEGER, crc_ok INTEGER, crc_received INTEGER,
  crc_calculated INTEGER, raw_note TEXT, parse_code TEXT, parse_position TEXT,
  parse_message TEXT, imported_event TEXT
);
CREATE TABLE IF NOT EXISTS materials_events (
  id TEXT PRIMARY KEY, kind TEXT, source TEXT, seq INTEGER, action TEXT,
  t_ms REAL, channel TEXT, gap_ms REAL, detail TEXT, imported_event TEXT
);
CREATE TABLE IF NOT EXISTS materials_maps (
  id TEXT PRIMARY KEY, version TEXT, address_base INTEGER, name TEXT,
  space INTEGER, address INTEGER, dtype TEXT, scale REAL, offset REAL, unit TEXT,
  word_order TEXT, valid_min REAL, valid_max REAL, source TEXT, seq INTEGER,
  imported_event TEXT
);
CREATE TABLE IF NOT EXISTS projections_meta (
  derive_event TEXT PRIMARY KEY, branch TEXT, rule_version TEXT, params_version TEXT,
  input_summary TEXT, parent_event TEXT
);
CREATE TABLE IF NOT EXISTS projections_generations (
  id TEXT, derive_event TEXT, transport TEXT, channel TEXT, gen_index INTEGER,
  opened_t_ms REAL, closed_t_ms REAL, open_evidence TEXT, close_evidence TEXT,
  PRIMARY KEY (derive_event, id)
);
CREATE TABLE IF NOT EXISTS projections_pairs (
  id TEXT, derive_event TEXT, request_ids TEXT, primary_request_id TEXT,
  response_id TEXT, rule TEXT, rule_detail TEXT, status TEXT, t_ms REAL,
  generation_id TEXT, latency_ms REAL, timeout_ms REAL, exception INTEGER,
  exception_code INTEGER,
  PRIMARY KEY (derive_event, id)
);
CREATE TABLE IF NOT EXISTS projections_unpaired (
  id TEXT, derive_event TEXT, frame_id TEXT, reason TEXT, t_ms REAL,
  generation_id TEXT, extra TEXT,
  PRIMARY KEY (derive_event, id)
);
CREATE TABLE IF NOT EXISTS projections_candidates (
  id TEXT, derive_event TEXT, request_id TEXT, response_id TEXT, rule TEXT,
  t_ms REAL, generation_id TEXT, status TEXT, reason TEXT,
  PRIMARY KEY (derive_event, id)
);
CREATE TABLE IF NOT EXISTS projections_intervals (
  id TEXT, derive_event TEXT, frame_id TEXT, space INTEGER, start_zero INTEGER,
  count INTEGER, end_zero INTEGER, t_ms REAL, dir TEXT, address_base_raw INTEGER,
  generation_id TEXT,
  PRIMARY KEY (derive_event, id)
);
CREATE TABLE IF NOT EXISTS projections_silent_gaps (
  id TEXT, derive_event TEXT, channel TEXT, t_ms REAL, gap_ms REAL, threshold_ms REAL,
  segment_close_t_ms REAL,
  PRIMARY KEY (derive_event, id)
);
CREATE TABLE IF NOT EXISTS projections_values (
  id TEXT, derive_event TEXT, pair_id TEXT, mapping_entry_id TEXT, name TEXT,
  space INTEGER, start_zero INTEGER, width INTEGER, raw_words_hex TEXT,
  raw_value REAL, raw_bits_hex TEXT, engineering REAL, unit TEXT, scale REAL,
  offset REAL, word_order TEXT, word_order_abcd TEXT, dtype TEXT, status TEXT,
  valid_min REAL, valid_max REAL, params_version TEXT, rule_version TEXT,
  raw_address_base INTEGER, raw_address INTEGER,
  PRIMARY KEY (derive_event, id)
);
CREATE TABLE IF NOT EXISTS projections_diags (
  id TEXT, derive_event TEXT, pair_id TEXT, code TEXT, address_zero INTEGER,
  message TEXT, extra TEXT,
  PRIMARY KEY (derive_event, id)
);
CREATE TABLE IF NOT EXISTS decisions (
  id TEXT PRIMARY KEY, branch TEXT, event_id TEXT, subject_id TEXT,
  decision TEXT, reason TEXT, payload TEXT, supersedes TEXT
);
CREATE TABLE IF NOT EXISTS archive_cases (
  id TEXT PRIMARY KEY, name TEXT, label TEXT, branch TEXT, baseline_event TEXT,
  mutation_event TEXT, source_kind TEXT, source_ref TEXT,
  changed_pair_ids TEXT, unchanged_pair_ids TEXT, accepted TEXT, rejected TEXT,
  findings TEXT, baseline_json TEXT, mutation_json TEXT, seq INTEGER
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(conn: sqlite3.Connection):
    conn.executescript(SCHEMA)


def recover_pending(conn: sqlite3.Connection) -> list[str]:
    """删除本地数据库模拟半写：启动时发现未完成的暂存事件，整体回滚其写入。"""
    rows = conn.execute("SELECT staging_id, event_id, seq, branch FROM commits ORDER BY seq").fetchall()
    recovered = []
    for r in rows:
        for table in ("events", "materials_frames", "materials_events", "materials_maps",
                      "projections_meta", "projections_generations", "projections_pairs",
                      "projections_unpaired", "projections_candidates", "projections_intervals",
                      "projections_silent_gaps", "projections_values", "projections_diags",
                      "decisions"):
            col = "event_id" if table in ("materials_frames", "materials_events",
                                          "materials_maps", "decisions") else "derive_event"
            if table == "events":
                conn.execute("DELETE FROM events WHERE id=?", (r["event_id"],))
            elif table.startswith("projections_") or table == "projections_meta":
                conn.execute(f"DELETE FROM {table} WHERE derive_event=?", (r["event_id"],))
            else:
                conn.execute(f"DELETE FROM {table} WHERE event_id=?", (r["event_id"],))
        b = conn.execute("SELECT head_event FROM branches WHERE name=?", (r["branch"],)).fetchone()
        if b:
            prev = conn.execute(
                "SELECT id FROM events WHERE branch=? ORDER BY seq DESC LIMIT 1",
                (r["branch"],)).fetchone()
            conn.execute("UPDATE branches SET head_event=? WHERE name=?",
                         (prev["id"] if prev else None, r["branch"]))
        conn.execute("DELETE FROM commits WHERE staging_id=?", (r["staging_id"],))
        recovered.append(r["event_id"])
    return recovered


def next_seq(conn: sqlite3.Connection, branch: str) -> int:
    row = conn.execute("SELECT COALESCE(MAX(seq)+1,0) AS s FROM events WHERE branch=?",
                       (branch,)).fetchone()
    return int(row["s"])


def begin_stage(conn: sqlite3.Connection, staging_id: str, event_id: str, seq: int, branch: str):
    conn.execute("INSERT INTO commits VALUES(?,?,?,?)", (staging_id, event_id, seq, branch))


def drop_stage(conn: sqlite3.Connection, staging_id: str):
    conn.execute("DELETE FROM commits WHERE staging_id=?", (staging_id,))
