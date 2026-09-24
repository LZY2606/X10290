"""把离线案例包灌入空库，形成完整叙事事件序列：

1. 初始导入（TCP+RTU 轨迹、串口/连接事件、映射 v1）
2. 参数修订（映射切到一基 v2：只改展示基准；记录参数版本）
3. 只影响局部依赖的源数据改动（阀门一个字改变，其它身份不变）
4. 互相冲突的人工决定：main 采纳候选 A，review-b 分支否定 A/采纳候选 B
并执行 7 个反例档案。
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from . import archive as arc
from . import engine
from .casebuild import CE_MUTATIONS, ROOT, build
from .ids import digest
from .importer import load_mapping_file, load_trace_file
from .store import connect, init_db, recover_pending


def _read_casepack() -> dict:
    root = ROOT
    if not (root / "manifest.json").exists():
        build(root)
    return {
        "tcp": (root / "traces" / "line-a.tcp.jsonl").read_text(encoding="utf-8"),
        "rtu": (root / "traces" / "rs485-1.rtu.jsonl").read_text(encoding="utf-8"),
        "map1": (root / "mappings" / "device-map-v1.json").read_text(encoding="utf-8"),
        "map2": (root / "mappings" / "device-map-v2.json").read_text(encoding="utf-8"),
        "root": root,
    }


def seed(conn: sqlite3.Connection) -> dict:
    init_db(conn)
    recover_pending(conn)
    pid = engine.ensure_project(conn)
    if conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]:
        return {"project_id": pid, "skipped": True}

    cp = _read_casepack()

    # 1) 初始导入 + 首次推导
    tcp_rep = load_trace_file(cp["tcp"], "line-a.tcp.jsonl")
    rtu_rep = load_trace_file(cp["rtu"], "rs485-1.rtu.jsonl")
    map1_rep = load_mapping_file(cp["map1"], "device-map-v1.json")
    merged = engine.ImportReport(ok=True)
    merged.frames = tcp_rep.frames + rtu_rep.frames
    merged.events = tcp_rep.events + rtu_rep.events
    merged.mappings = map1_rep.mappings
    imp = engine.commit_import(conn, engine.MAIN, merged, "初始导入：TCP+RTU 轨迹/事件/映射 map-v1")
    engine.commit_params(conn, engine.MAIN,
                         {"rtu_gap_ms": 1.75, "rtu_timeout_ms": 100.0},
                         "map-v1", "初始参数：3.5 字符静默间隔@19200，映射零基 map-v1")

    # 2) 参数修订：映射切一基 v2（仅展示基准变化）
    map2_rep = load_mapping_file(cp["map2"], "device-map-v2.json")
    imp2 = engine.commit_import(conn, engine.MAIN,
                                _wrap(map2_rep), "导入设备映射 map-v2（一基文档地址）")
    engine.commit_params(conn, engine.MAIN,
                         {"rtu_gap_ms": 1.75, "rtu_timeout_ms": 100.0},
                         "map-v2", "参数修订：切换映射版本 map-v2，一基仅展示层转换")

    # 3) 局部源数据改动：只追加一个 RTU 帧对（pressure 新值），验证局部依赖
    patch_text = (
        json.dumps({"kind": "serial", "action": "bus_acquire", "t_ms": 500,
                    "channel": "rs485-2"}, ensure_ascii=False) + "\n"
        + json.dumps({"kind": "frame", "transport": "rtu", "dir": "out",
                      "t_ms": 505, "channel": "rs485-2",
                      "adu": __import__("modbuslab.casebuild", fromlist=["rtu_req"]).rtu_req(3, 3, 19, 1)},
                     ensure_ascii=False) + "\n"
        + json.dumps({"kind": "frame", "transport": "rtu", "dir": "in",
                      "t_ms": 507, "channel": "rs485-2",
                      "adu": __import__("modbuslab.casebuild", fromlist=["rtu_resp"]).rtu_resp(3, 3, (0x0080).to_bytes(2, "big"))},
                     ensure_ascii=False)
    )
    patch_rep = load_trace_file(patch_text, "patch-rs485-2.rtu.jsonl")
    engine.commit_import(conn, engine.MAIN, _wrap(patch_rep),
                         "局部源数据改动：新增一条 RTU 总线压力读数（只影响新对象）")
    engine.commit_params(conn, engine.MAIN,
                         {"rtu_gap_ms": 1.75, "rtu_timeout_ms": 100.0},
                         "map-v2", "局部改动后重新推导")

    # 4) 冲突人工决定：找到 xid=103 的候选
    head = engine.branch_head(conn, engine.MAIN)
    proj = engine.get_projection(conn, engine.MAIN)
    amb = [u for u in proj["unpaired"] if u["reason"] == "tcp_xid_reuse_in_flight"]
    base_event = head
    if amb:
        u = amb[0]
        req_ids = u["extra"].get("candidate_request_ids", [])
        resp_id = u["frame_id"]
        # main：采纳候选 A（最早请求）
        engine.commit_decision(
            conn, engine.MAIN, "candidate_response",
            digest("subj", {"response": resp_id}), "accept",
            "main 决定：采纳最早在途请求（addr=9 温度）",
            request_id=req_ids[0], response_id=resp_id)
        # review-b：从决定前分叉，否定 A，采纳 B
        engine.fork_branch(conn, "review-b", base_event)
        engine.commit_decision(
            conn, "review-b", "candidate_response",
            digest("subj", {"response": resp_id}), "reject",
            "review-b 决定：时间线显示响应 20ms 后才到，更可能属于后发请求，否定 A",
            request_id=req_ids[0], response_id=resp_id,
            fork_name="review-b")
        engine.commit_decision(
            conn, "review-b", "candidate_response",
            digest("subj", {"response": resp_id, "request": req_ids[1]}), "accept",
            "review-b 决定：采纳后发请求（addr=11 状态位）",
            request_id=req_ids[1], response_id=resp_id)

    run_archive_cases(conn, cp["root"])
    return {"project_id": pid, "events": conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]}


def _wrap(rep) -> "engine.ImportReport":
    out = engine.ImportReport(ok=True)
    out.frames = list(rep.frames)
    out.events = list(rep.events)
    out.mappings = list(rep.mappings)
    return out


def run_archive_cases(conn: sqlite3.Connection, root: Path) -> int:
    base_tcp = (root / "archive" / "baseline.tcp.jsonl").read_text(encoding="utf-8")
    base_rtu = (root / "archive" / "baseline.rtu.jsonl").read_text(encoding="utf-8")
    base_map = (root / "archive" / "baseline.map.json").read_text(encoding="utf-8")
    base_run = arc.run_case(base_tcp, base_rtu, base_map)

    # 机器可读规则判定（基线）
    baseline_judgements = list(arc.JUDGEMENTS)
    n = 0
    for i, mut in enumerate(CE_MUTATIONS, 1):
        d = root / "archive" / mut["id"]
        ct = (d / "trace.tcp.jsonl").read_text(encoding="utf-8")
        cr = (d / "trace.rtu.jsonl").read_text(encoding="utf-8")
        cm = (d / "map.json").read_text(encoding="utf-8")
        changed = arc.run_case(ct, cr, cm)
        diff = arc.diff_projections(base_run, changed)
        result = arc.evaluate_case(mut["id"], base_run, changed, diff)
        cid = digest("cecase", {"mutation": mut["id"], "label": mut["label"]})
        conn.execute(
            "INSERT OR REPLACE INTO archive_cases VALUES(" + ",".join(["?"] * 16) + ")",
            (cid, mut["label"], mut["id"], "ce-archive", None, None,
             "single-direct-source", mut["id"],
             json.dumps(result["diff"]["pairs"]["added"] + result["diff"]["pairs"]["removed"]),
             json.dumps(result["diff"]["pairs"]["unchanged"]),
             json.dumps(result["accepted"]), json.dumps(result["not_adopted"]),
             json.dumps({"expect": mut["expect"], "judgements": result["judgements"],
                         "all_rules_hold": result["all_rules_hold"],
                         "candidate_details": result["candidate_details"],
                         "baseline_judgements": baseline_judgements,
                         "diff": result["diff"]}, ensure_ascii=False),
             None, None, i))
        n += 1
    return n


def open_seeded_db(path: str | Path) -> sqlite3.Connection:
    conn = connect(path)
    seed(conn)
    return conn
