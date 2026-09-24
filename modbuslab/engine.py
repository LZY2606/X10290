"""领域引擎：材料导入 → 配对推导 → 寄存器解释 → 人工决定/参数修订。

所有写操作走“暂存提交”协议（store.begin_stage / 写多表 / drop_stage）：
若进程在中途崩溃，重启时 recover_pending 会整体回滚该事件，形成半写恢复。
所有计算结果记录输入摘要、参数版本、规则版本与父级事件。
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from . import RULE_VERSION
from .decode import interpret_response
from .ids import digest, event_id
from .importer import ImportReport
from .store import begin_stage, drop_stage, next_seq
from .timeline import RTU_RESPONSE_TIMEOUT_MS, RTU_SILENT_GAP_MS, pair_all

MAIN = "main"


class EngineError(Exception):
    def __init__(self, code: str, position: str, message: str):
        super().__init__(message)
        self.code, self.position, self.message = code, position, message


# ---------- 基础读取 ----------

def ensure_project(conn: sqlite3.Connection, name: str = "寄存器轨迹室"):
    row = conn.execute("SELECT * FROM projects LIMIT 1").fetchone()
    if row:
        return row["id"]
    pid = digest("proj", {"name": name})
    conn.execute("INSERT INTO projects VALUES(?,?,?,?,?,?)",
                 (pid, name, 0, 0.0,
                  "t_ms：自首个原始帧起算的单调毫秒",
                  "零基 PDU 地址（展示层可切一基）"))
    conn.execute("INSERT INTO branches(name,parent_branch,forked_at_event,head_event,created_seq)"
                 " VALUES(?,?,?,?,?)", (MAIN, None, None, None, 0))
    return pid


def branch_head(conn: sqlite3.Connection, branch: str) -> str | None:
    row = conn.execute("SELECT head_event FROM branches WHERE name=?", (branch,)).fetchone()
    return row["head_event"] if row else None


def events_on(conn: sqlite3.Connection, branch: str) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM events WHERE branch=? ORDER BY seq", (branch,)).fetchall())


def _events_until(conn: sqlite3.Connection, branch: str, event_id: str | None):
    evs = events_on(conn, branch)
    if event_id is None:
        return evs
    out = []
    for e in evs:
        out.append(e)
        if e["id"] == event_id:
            return out
    raise EngineError("SEMANTIC_NO_SOLUTION", f"branch:{branch}.event",
                      f"事件 {event_id} 不在分支 {branch} 上")


def fork_branch(conn: sqlite3.Connection, new_name: str, base_event: str,
                parent_branch: str = MAIN):
    if conn.execute("SELECT 1 FROM branches WHERE name=?", (new_name,)).fetchone():
        raise EngineError("SEMANTIC_NO_SOLUTION", "branch.name", f"分支 {new_name} 已存在")
    _events_until(conn, parent_branch, base_event)
    seq = conn.execute("SELECT COALESCE(MAX(created_seq)+1,1) FROM branches").fetchone()[0]
    conn.execute("INSERT INTO branches VALUES(?,?,?,?,?)",
                 (new_name, parent_branch, base_event, base_event, seq))


# ---------- 事件状态回放 ----------

def replay_state(conn: sqlite3.Connection, branch: str, until_event: str | None = None) -> dict:
    """沿事件日志回放，返回该时刻的材料集合、参数版本与人工决定。"""
    state = {"frames": {}, "events": {}, "mapping_versions": {}, "params": {},
             "decisions": {}, "map_active": {}}
    for e in _events_until(conn, branch, until_event):
        p = json.loads(e["payload"])
        if e["kind"] == "import":
            for fid in p.get("frame_ids", []):
                r = conn.execute("SELECT * FROM materials_frames WHERE id=?", (fid,)).fetchone()
                if r:
                    state["frames"][fid] = dict(r)
            for mid in p.get("event_ids", []):
                r = conn.execute("SELECT * FROM materials_events WHERE id=?", (mid,)).fetchone()
                if r:
                    state["events"][mid] = dict(r)
            for fid in p.get("map_entry_ids", []):
                r = conn.execute("SELECT * FROM materials_maps WHERE id=?", (fid,)).fetchone()
                if r:
                    state["mapping_versions"].setdefault(r["version"], []).append(dict(r))
        elif e["kind"] == "params":
            state["params"].update(p.get("values", {}))
            if p.get("mapping_version"):
                state["map_active"]["version"] = p["mapping_version"]
        elif e["kind"] == "decision":
            state["decisions"][p["subject_id"]] = {**p, "event_id": e["id"]}
    return state


# ---------- 派生计算 ----------

def compute_projection(conn: sqlite3.Connection, state: dict, derive_event: str) -> dict:
    frames = list(state["frames"].values())
    events = list(state["events"].values())
    gap = float(state["params"].get("rtu_gap_ms", RTU_SILENT_GAP_MS))
    timeout = float(state["params"].get("rtu_timeout_ms", RTU_RESPONSE_TIMEOUT_MS))
    pr = pair_all(frames, events, rtu_gap_ms=gap, rtu_timeout_ms=timeout)

    # 应用人工决定（接受/拒绝候选）
    applied: dict[str, dict] = {}
    rejected: dict[str, bool] = {}
    for subj, dec in state["decisions"].items():
        if dec.get("subject_type") == "candidate_response":
            if dec["decision"] == "accept":
                applied[subj] = dec
            elif dec["decision"] == "reject":
                rejected[subj] = True

    pair_rows = [dict(p) for p in pr.pairs]
    cand_rows = [dict(c) for c in pr.candidates]
    unpaired_rows = [dict(u) for u in pr.unpaired]

    # 候选被采纳：在该时点产生一条采纳配对，其它候选保持候选（或被否定）
    for subj, dec in applied.items():
        rid = dec["request_id"]
        resp_id = dec["response_id"]
        g = next((c for c in cand_rows if c["request_id"] == rid and c["response_id"] == resp_id), None)
        if g is None:
            continue
        resp = state["frames"].get(resp_id)
        req = state["frames"].get(rid)
        if not resp or not req:
            continue
        pid = digest("pair", {"reqs": [rid], "resp": resp_id, "rule": "manual",
                              "decision": dec["event_id"]})
        if not any(p["id"] == pid for p in pair_rows):
            pair_rows.append({
                "id": pid, "request_ids": [rid], "primary_request_id": rid,
                "response_id": resp_id, "rule": "manual",
                "rule_detail": f"人工采纳候选：{dec.get('reason','')}",
                "status": "adopted-manual", "t_ms": resp["t_ms"],
                "generation_id": g["generation_id"],
                "latency_ms": resp["t_ms"] - req["t_ms"], "timeout_ms": timeout,
                "exception": resp.get("role") == "exception",
                "exception_code": resp.get("exception_code"),
                "decision_event": dec["event_id"]})
        # 被采纳响应上的“在途复用未配对”标记转为 resolved
        for u in unpaired_rows:
            if u["frame_id"] == resp_id and u["reason"] == "tcp_xid_reuse_in_flight":
                u["reason"] = "resolved_by_decision"
    for subj, dec in state["decisions"].items():
        if dec.get("subject_type") == "candidate_response" and dec["decision"] == "reject":
            for u in unpaired_rows:
                if u["frame_id"] == dec["response_id"] and u["reason"] in (
                        "tcp_xid_reuse_in_flight",):
                    u["reason"] = "rejected_by_decision"

    active_version = state["map_active"].get("version")
    mapping = state["mapping_versions"].get(active_version, []) if active_version else []
    params_version = state["params"].get("params_version", "params-v0")

    values_all: list[dict] = []
    diags_all: list[dict] = []
    frame_by_id = state["frames"]
    for pair in pair_rows:
        if pair.get("exception"):
            diags_all.append({
                "id": digest("dval", {"pair": pair["id"], "code": "EXCEPTION_RESPONSE"}),
                "pair_id": pair["id"], "code": "EXCEPTION_RESPONSE",
                "address_zero": None,
                "message": f"异常码 {pair.get('exception_code')}：请求被设备拒绝，"
                           f"不得解释为成功的空数据", "extra": None})
            continue
        resp = frame_by_id.get(pair["response_id"])
        req = frame_by_id.get(pair["primary_request_id"])
        if not resp or not req or resp.get("fc") not in (3, 4):
            continue
        data = bytes.fromhex(resp["values_hex"]) if resp.get("values_hex") else b""
        words = [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2)]
        from .codec import FC_SPACE
        if len(words) != req.get("quantity"):
            diags_all.append({
                "id": digest("dval", {"pair": pair["id"], "code": "LENGTH_MISMATCH"}),
                "pair_id": pair["id"], "code": "LENGTH_MISMATCH",
                "address_zero": req.get("address"),
                "message": f"响应字数 {len(words)} 与请求数量 {req.get('quantity')} 不一致，"
                           f"原始字节 {data.hex()} 保留", "extra": None})
        vals, diags = interpret_response(
            words, req["address"], FC_SPACE[req["fc"]], mapping,
            params_version, RULE_VERSION, pair["id"])
        values_all.extend(vals)
        diags_all.extend(diags)

    return {"generations": [vars(g) for g in pr.generations],
            "pairs": pair_rows, "unpaired": unpaired_rows,
            "candidates": cand_rows, "intervals": pr.intervals,
            "silent_gaps": pr.silent_gaps, "values": values_all,
            "diags": diags_all, "rules": pr.rules,
            "mapping_version": active_version, "params_version": params_version}


def input_summary(state: dict) -> dict:
    return {"frames": sorted(state["frames"].keys()),
            "events": sorted(state["events"].keys()),
            "mapping_versions": {v: [e["id"] for e in entries]
                                 for v, entries in state["mapping_versions"].items()},
            "params": dict(sorted(state["params"].items())),
            "decisions": sorted(state["decisions"].keys())}


# ---------- 提交（事件 + 材料/投影 同一暂存事务） ----------

def _new_event_id(seq: int, kind: str, payload: dict) -> str:
    return event_id(seq, kind, payload)


def commit_import(conn: sqlite3.Connection, branch: str, report: ImportReport,
                  label: str) -> str:
    seq = next_seq(conn, branch)
    payload = {"label": label,
               "frame_ids": sorted(f["id"] for f in report.frames),
               "event_ids": sorted(e["id"] for e in report.events),
               "map_entry_ids": sorted(m["id"] for m in report.mappings),
               "mapping_versions": sorted({m["version"] for m in report.mappings})}
    eid = _new_event_id(seq, "import", payload)
    parent = branch_head(conn, branch)
    staging = f"stg-{uuid.uuid4()}"
    conn.execute("BEGIN IMMEDIATE")
    try:
        begin_stage(conn, staging, eid, seq, branch)
        conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                     (eid, seq, branch, "import", json.dumps(payload, ensure_ascii=False),
                      json.dumps({"n_frames": len(report.frames),
                                  "n_events": len(report.events),
                                  "n_map_entries": len(report.mappings)}, ensure_ascii=False),
                      None, RULE_VERSION, parent))
        for f in report.frames:
            conn.execute(
                "INSERT OR REPLACE INTO materials_frames VALUES("
                + ",".join(["?"] * 25) + ")",
                (f["id"], f["source"], f["seq"], f["transport"], f["dir"], f["adu_hex"],
                 f["t_ms"], f["channel"], f["unit"], f["xid"], f["fc"], f["role"],
                 f["exception_code"], f["address"], f["quantity"], f["values_hex"],
                 f["byte_count"],
                 None if f["crc_ok"] is None else int(f["crc_ok"]),
                 f["crc_received"], f["crc_calculated"], f["raw_note"],
                 f["parse_code"], f["parse_position"], f["parse_message"], eid))
        for ev in report.events:
            conn.execute("INSERT OR REPLACE INTO materials_events VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (ev["id"], ev["kind"], ev["source"], ev["seq"], ev["action"],
                          ev["t_ms"], ev["channel"], ev.get("gap_ms"),
                          json.dumps(ev["detail"], ensure_ascii=False), eid))
        for m in report.mappings:
            conn.execute("INSERT OR REPLACE INTO materials_maps VALUES("
                         + ",".join(["?"] * 16) + ")",
                         (m["id"], m["version"], m["address_base"], m["name"], m["space"],
                          m["address"], m["dtype"], m["scale"], m["offset"], m["unit"],
                          m["word_order"], m["valid_min"], m["valid_max"], m["source"],
                          m["seq"], eid))
        _advance_head(conn, branch, eid)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    drop_stage(conn, staging)
    return eid


def _advance_head(conn: sqlite3.Connection, branch: str, eid: str):
    conn.execute("UPDATE branches SET head_event=? WHERE name=?", (eid, branch))


def commit_params(conn: sqlite3.Connection, branch: str, values: dict,
                  mapping_version: str | None, note: str) -> str:
    state = replay_state(conn, branch)
    new_pv = values.get("params_version") or _bump_params(state)
    values = {**values, "params_version": new_pv}
    payload = {"values": values, "mapping_version": mapping_version, "note": note}
    seq = next_seq(conn, branch)
    eid = _new_event_id(seq, "params", payload)
    parent = branch_head(conn, branch)
    staging = f"stg-{uuid.uuid4()}"
    conn.execute("BEGIN IMMEDIATE")
    try:
        begin_stage(conn, staging, eid, seq, branch)
        conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                     (eid, seq, branch, "params", json.dumps(payload, ensure_ascii=False),
                      json.dumps(input_summary(state), ensure_ascii=False),
                      new_pv, RULE_VERSION, parent))
        _advance_head(conn, branch, eid)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    drop_stage(conn, staging)
    derive(conn, branch)
    return eid


def _bump_params(state: dict) -> str:
    cur = state["params"].get("params_version", "params-v0")
    try:
        n = int(cur.rsplit("-v", 1)[1])
        return f"params-v{n + 1}"
    except (IndexError, ValueError):
        return "params-v1"


def commit_decision(conn: sqlite3.Connection, branch: str, subject_type: str,
                    subject_id: str, decision: str, reason: str,
                    request_id: str | None = None, response_id: str | None = None,
                    supersedes: str | None = None, fork_name: str | None = None) -> str:
    if decision not in ("accept", "reject", "param_change"):
        raise EngineError("SEMANTIC_NO_SOLUTION", "decision.decision",
                          "决定必须是 accept/reject/param_change")
    payload = {"subject_type": subject_type, "subject_id": subject_id,
               "decision": decision, "reason": reason,
               "request_id": request_id, "response_id": response_id}
    seq = next_seq(conn, branch)
    eid = _new_event_id(seq, "decision", payload)
    parent = branch_head(conn, branch)
    staging = f"stg-{uuid.uuid4()}"
    conn.execute("BEGIN IMMEDIATE")
    try:
        begin_stage(conn, staging, eid, seq, branch)
        conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                     (eid, seq, branch, "decision", json.dumps(payload, ensure_ascii=False),
                      None, None, RULE_VERSION, parent))
        conn.execute("INSERT INTO decisions VALUES(?,?,?,?,?,?,?,?)",
                     (digest("dec", {"event": eid}), branch, eid, subject_id, decision,
                      reason, json.dumps(payload, ensure_ascii=False), supersedes))
        _advance_head(conn, branch, eid)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    drop_stage(conn, staging)
    derive(conn, branch)
    return eid


def derive(conn: sqlite3.Connection, branch: str) -> str:
    head = branch_head(conn, branch)
    state = replay_state(conn, branch, head)
    proj = compute_projection(conn, state, head)
    pv = proj["params_version"]
    seq = next_seq(conn, branch)
    payload = {"of_event": head,
               "pair_ids": sorted(p["id"] for p in proj["pairs"]),
               "unpaired_ids": sorted(u["id"] for u in proj["unpaired"]),
               "value_ids": sorted(v["id"] for v in proj["values"])}
    deid = _new_event_id(seq, "derive", payload)
    staging = f"stg-{uuid.uuid4()}"
    conn.execute("BEGIN IMMEDIATE")
    try:
        begin_stage(conn, staging, deid, seq, branch)
        conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                     (deid, seq, branch, "derive", json.dumps(payload, ensure_ascii=False),
                      json.dumps(input_summary(state), ensure_ascii=False),
                      pv, RULE_VERSION, head))
        conn.execute("INSERT INTO projections_meta VALUES(?,?,?,?,?,?)",
                     (deid, branch, RULE_VERSION, pv,
                      json.dumps(input_summary(state), ensure_ascii=False), head))
        _insert_projection(conn, deid, proj)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    drop_stage(conn, staging)
    return deid


def _insert_projection(conn: sqlite3.Connection, deid: str, proj: dict):
    for g in proj["generations"]:
        conn.execute("INSERT INTO projections_generations VALUES(?,?,?,?,?,?,?,?,?)",
                     (g["id"], deid, g["transport"], g["channel"], g["gen_index"],
                      g["opened_t_ms"], g["closed_t_ms"], g["open_evidence"],
                      g["close_evidence"]))
    for p in proj["pairs"]:
        conn.execute("INSERT INTO projections_pairs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (p["id"], deid, json.dumps(p["request_ids"]), p["primary_request_id"],
                      p["response_id"], p["rule"], p["rule_detail"], p["status"],
                      p["t_ms"], p["generation_id"], p["latency_ms"], p.get("timeout_ms"),
                      1 if p.get("exception") else 0, p.get("exception_code")))
    for u in proj["unpaired"]:
        extra = {k: v for k, v in u.items()
                 if k not in ("id", "derive_event", "frame_id", "reason", "t_ms",
                              "generation_id")}
        conn.execute("INSERT INTO projections_unpaired VALUES(?,?,?,?,?,?,?)",
                     (u["id"], deid, u["frame_id"], u["reason"], u["t_ms"],
                      u.get("generation_id"), json.dumps(extra, ensure_ascii=False)))
    for c in proj["candidates"]:
        conn.execute("INSERT INTO projections_candidates VALUES(?,?,?,?,?,?,?,?,?)",
                     (c["id"], deid, c["request_id"], c["response_id"], c["rule"],
                      c["t_ms"], c["generation_id"], c["status"], c["reason"]))
    for it in proj["intervals"]:
        conn.execute("INSERT INTO projections_intervals VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                     (it["id"], deid, it["frame_id"], it["space"], it["start_zero"],
                      it["count"], it["end_zero"], it["t_ms"], it["dir"],
                      it["address_base_raw"], it["generation_id"]))
    for sg in proj["silent_gaps"]:
        conn.execute("INSERT INTO projections_silent_gaps VALUES(?,?,?,?,?,?,?)",
                     (sg["id"], deid, sg["channel"], sg["t_ms"], sg["gap_ms"],
                      sg["threshold_ms"], sg["segment_close_t_ms"]))
    for v in proj["values"]:
        conn.execute("INSERT INTO projections_values VALUES("
                     + ",".join(["?"] * 25) + ")",
                     (v["id"], deid, v["pair_id"], v["mapping_entry_id"], v["name"],
                      v["space"], v["start_zero"], v["width"], v["raw_words_hex"],
                      v["raw_value"], v["raw_bits_hex"], v["engineering"], v["unit"],
                      v["scale"], v["offset"], v["word_order"], v["word_order_abcd"],
                      v["dtype"], v["status"], v["valid_min"], v["valid_max"],
                      v["params_version"], v["rule_version"], v["raw_address_base"],
                      v["raw_address"]))
    for d in proj["diags"]:
        conn.execute("INSERT INTO projections_diags VALUES(?,?,?,?,?,?,?)",
                     (d["id"], deid, d["pair_id"], d["code"], d.get("address_zero"),
                      d["message"], d.get("extra")))


def latest_derive(conn: sqlite3.Connection, branch: str, at_event: str | None = None) -> str | None:
    rows = _events_until(conn, branch, at_event)
    for e in reversed(rows):
        if e["kind"] == "derive":
            return e["id"]
    return None


def get_projection(conn: sqlite3.Connection, branch: str, at_event: str | None = None) -> dict | None:
    deid = latest_derive(conn, branch, at_event)
    if not deid:
        return None

    def rows(table: str) -> list[dict]:
        return [dict(r) for r in conn.execute(
            f"SELECT * FROM {table} WHERE derive_event=?", (deid,)).fetchall()]

    pairs = rows("projections_pairs")
    for p in pairs:
        p["request_ids"] = json.loads(p["request_ids"])
    unpaired = rows("projections_unpaired")
    for u in unpaired:
        u["extra"] = json.loads(u["extra"]) if u["extra"] else {}
    return {
        "derive_event": deid,
        "generations": rows("projections_generations"),
        "pairs": sorted(pairs, key=lambda p: (p["t_ms"], p["id"])),
        "unpaired": sorted(unpaired, key=lambda u: (u["t_ms"], u["id"])),
        "candidates": sorted(rows("projections_candidates"), key=lambda c: (c["t_ms"], c["id"])),
        "intervals": sorted(rows("projections_intervals"), key=lambda i: (i["t_ms"], i["id"])),
        "silent_gaps": sorted(rows("projections_silent_gaps"), key=lambda g: (g["t_ms"], g["id"])),
        "values": sorted(rows("projections_values"), key=lambda v: (v["start_zero"], v["id"])),
        "diags": sorted(rows("projections_diags"), key=lambda d: (d["id"],)),
    }


def get_event_log(conn: sqlite3.Connection, branch: str) -> list[dict]:
    out = []
    for e in events_on(conn, branch):
        d = dict(e)
        d["payload"] = json.loads(e["payload"])
        d["input_summary"] = json.loads(e["input_summary"]) if e["input_summary"] else None
        out.append(d)
    return out


def list_branches(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT name,parent_branch,forked_at_event,head_event,created_seq "
        "FROM branches ORDER BY created_seq").fetchall()]


def frame(conn: sqlite3.Connection, fid: str) -> dict | None:
    r = conn.execute("SELECT * FROM materials_frames WHERE id=?", (fid,)).fetchone()
    return dict(r) if r else None


def all_maps(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM materials_maps ORDER BY version,seq")]


def params_history(conn: sqlite3.Connection, branch: str) -> list[dict]:
    return [{"event_id": e["id"], "seq": e["seq"], **json.loads(e["payload"])}
            for e in events_on(conn, branch) if e["kind"] == "params"]
