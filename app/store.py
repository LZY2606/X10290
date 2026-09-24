from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any
from uuid import uuid4

from .errors import MalformedInput
from .pairing import derive, normalize_case

SCHEMA = """
pragma journal_mode=wal;
create table if not exists branches (
  branch_id text primary key,
  parent_branch_id text,
  label text not null,
  base_event_id text,
  created_at text not null
);
create table if not exists events (
  event_id text primary key,
  branch_id text not null,
  parent_event_id text,
  ordinal integer not null,
  event_type text not null,
  payload_json text not null,
  state_json text not null,
  input_summary_json text not null,
  created_at text not null,
  committed integer not null default 0,
  foreign key(branch_id) references branches(branch_id)
);
create table if not exists materials (
  material_id text primary key,
  branch_id text not null,
  material_kind text not null,
  payload_json text not null,
  introduced_event_id text not null
);
create table if not exists counterexamples (
  archive_id text primary key,
  case_id text not null,
  mutation text not null,
  payload_json text not null
);
"""


def now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path="data/register_trace_room.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()
        self.recover_half_writes()

    def connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("pragma foreign_keys=on")
        return conn

    def init_db(self):
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def recover_half_writes(self):
        with self.connect() as conn:
            pending = conn.execute("select event_id from events where committed=0 order by ordinal").fetchall()
            for row in pending:
                conn.execute("delete from events where event_id=?", (row["event_id"],))
                conn.execute("delete from materials where introduced_event_id=?", (row["event_id"],))
        return len(pending)

    def seed_case_file(self, path="case_package/register_trace_room_case.json"):
        if self.has_data():
            return
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.import_case(payload, branch_label="baseline-import")
        self.create_branch_from_event(self.latest_event_id(), "parameter-revision", parameter_version="params-v2")
        parent = self.latest_event_id()
        self.create_branch_from_event(parent, "local-source-correction", replace_material="RTU-R2-corrected")
        parent = self.latest_event_id()
        self.create_branch_from_event(parent, "conflicting-human-decision", accept_pair="pair:RTU-R1-retry->RTU-A1-late", reject_pair="pair:RTU-R1-retry->RTU-A1-late")
