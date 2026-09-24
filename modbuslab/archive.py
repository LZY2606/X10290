"""反例档案：保存基线，每个反例只改动一个直接来源，对比影响范围。

输出同时保留“被采纳/未采纳”的配对与候选；并把三条核心规则判定写成
机器可读事件（rule_judgement 载荷含 rule/when/holds/evidence）：
- TCP 用 transaction id，RTU 用静默间隔，二者配对规则不同；
- 广播没有响应；
- 零基/一基只在展示层转换；
- 异常响应不能当成功的空数据。
"""
from __future__ import annotations

import json
import sqlite3

from . import RULE_VERSION
from .engine import compute_projection, replay_state
from .ids import digest
from .importer import load_mapping_file, load_trace_file
from .timeline import RTU_RESPONSE_TIMEOUT_MS, RTU_SILENT_GAP_MS

JUDGEMENTS = [
    {"rule": "pairing.tcp_vs_rtu",
     "statement": "TCP 按 MBAP transaction_id(+unit) 在连接代次内配对；"
                  "RTU 按静默间隔的单主站窗口配对"},
    {"rule": "pairing.broadcast_no_response",
     "statement": "unit_id=0 为广播，主站不期待响应，任何应答均非法"},
    {"rule": "address.base_presentation_only",
     "statement": "协议地址零基；一基仅用于展示层转换，不改变匹配与派生身份"},
    {"rule": "response.exception_is_failure",
     "statement": "异常响应表示设备拒绝，不得解释为成功的空数据"},
]


def _state_from_text(tcp_text: str, rtu_text: str, map_text: str,
                     params: dict | None = None) -> dict:
    state = {"frames": {}, "events": {}, "mapping_versions": {},
             "params": {"rtu_gap_ms": RTU_SILENT_GAP_MS,
                        "rtu_timeout_ms": RTU_RESPONSE_TIMEOUT_MS,
                        "params_version": "params-v0"},
             "decisions": {}, "map_active": {"version": "ce-map-v1"}}
    for text, src in ((tcp_text, "ce.tcp.jsonl"), (rtu_text, "ce.rtu.jsonl")):
        rep = load_trace_file(text, src)
        for f in rep.frames:
            state["frames"][f["id"]] = f
        for e in rep.events:
            state["events"][e["id"]] = e
    mrep = load_mapping_file(map_text, "ce.map.json")
    state["mapping_versions"]["ce-map-v1"] = mrep.mappings
    if params:
        state["params"].update(params)
    return state


def _sig(obj: dict, keys: tuple[str, ...]) -> dict:
    return {k: obj.get(k) for k in keys}


def run_case(tcp_text: str, rtu_text: str, map_text: str,
             params: dict | None = None) -> dict:
    state = _state_from_text(tcp_text, rtu_text, map_text, params)
    proj = compute_projection(None, state, "ce-derive")
    return {"state": state, "proj": proj}


def diff_projections(base: dict, changed: dict) -> dict:
    """比较派生对象身份集合，得出被限制的影响范围。"""
    def sigmap(proj, table, keys):
        return {x["id"]: _sig(x, keys) for x in proj[table]}
    pair_keys = ("primary_request_id", "response_id", "rule", "status", "exception")
    unp_keys = ("frame_id", "reason")
    val_keys = ("pair_id", "mapping_entry_id", "raw_words_hex", "engineering", "status")
    out = {}
    for table, keys in (("pairs", pair_keys), ("unpaired", unp_keys),
                        ("values", val_keys), ("candidates",
                                               ("request_id", "response_id", "rule", "status"))):
        b, c = sigmap(base["proj"], table, keys), sigmap(changed["proj"], table, keys)
        out[table] = {
            "added": sorted(set(c) - set(b)),
            "removed": sorted(set(b) - set(c)),
            "changed_signature": sorted(i for i in set(b) & set(c) if b[i] != c[i]),
            "unchanged": sorted(i for i in set(b) & set(c) if b[i] == c[i]),
        }
    # 代次身份比较
    bg = {g["id"]: (g["channel"], g["gen_index"], g["opened_t_ms"], g["closed_t_ms"])
          for g in base["proj"]["generations"]}
    cg = {g["id"]: (g["channel"], g["gen_index"], g["opened_t_ms"], g["closed_t_ms"])
          for g in changed["proj"]["generations"]}
    out["generations"] = {"added": sorted(set(cg) - set(bg)),
                          "removed": sorted(set(bg) - set(cg)),
                          "unchanged": sorted(set(bg) & set(cg))}
    return out


def evaluate_case(mutation_id: str, base_run: dict, changed_run: dict, diff: dict) -> dict:
    """根据各反例期望，输出机器可读 holds/details，含被采纳与未采纳结果。"""
    adopted = [p for p in changed_run["proj"]["pairs"] if p["status"].startswith("adopted")]
    not_adopted = list(changed_run["proj"]["unpaired"])
    candidates = list(changed_run["proj"]["candidates"])
    accepted_ids = [p["id"] for p in adopted]
    rejected_ids = [u["id"] for u in not_adopted]

    checks: list[dict] = []
    if mutation_id == "xid_reuse":
        base_amb = [u for u in base_run["proj"]["unpaired"]
                    if u["reason"] == "tcp_xid_reuse_in_flight"]
        changed_amb = [u for u in not_adopted if u["reason"] == "tcp_xid_reuse_in_flight"]
        changed_noopen = [u for u in not_adopted if u["reason"] == "tcp_no_open_transaction"]
        checks = [
            {"rule": "pairing.tcp_vs_rtu", "holds": len(base_amb) == 1,
             "evidence": {"baseline_inflight_reuses": [u["id"] for u in base_amb]}},
            {"rule": "pairing.tcp_vs_rtu",
             "holds": len(changed_amb) == 0 and len(changed_noopen) >= 1
             and diff["pairs"]["added"] and not diff["pairs"]["removed"],
             "evidence": {"after_change_inflight_reuses": [u["id"] for u in changed_amb],
                          "after_change_no_open": [u["id"] for u in changed_noopen],
                          "scope_added_pairs": diff["pairs"]["added"],
                          "unchanged_pairs": diff["pairs"]["unchanged"]}},
        ]
    elif mutation_id == "rtu_retransmit":
        base_rtx = [p for p in base_run["proj"]["pairs"]
                    if len(p["request_ids"]) > 1 and p["rule"] == "rtu-silent"]
        changed_timeout = [u for u in not_adopted if u["reason"] == "rtu_response_timeout"]
        changed_shared = [p for p in adopted if len(p["request_ids"]) > 1]
        checks = [
            {"rule": "pairing.tcp_vs_rtu", "holds": len(base_rtx) == 1,
             "evidence": {"baseline_shared_response_pairs": [p["id"] for p in base_rtx]}},
            {"rule": "pairing.tcp_vs_rtu",
             "holds": len(changed_shared) == 0 and len(changed_timeout) >= 1
             and diff["pairs"]["removed"],
             "evidence": {"after_change_timeouts": [u["id"] for u in changed_timeout],
                          "scope_removed_pairs": diff["pairs"]["removed"],
                          "unchanged_pairs": diff["pairs"]["unchanged"]}},
        ]
    elif mutation_id == "broadcast":
        base_bc = [u for u in base_run["proj"]["unpaired"]
                   if u["reason"] == "broadcast_no_response"]
        changed_bc = [u for u in not_adopted if u["reason"] == "broadcast_no_response"]
        changed_illegal = [u for u in not_adopted if u["reason"] == "broadcast_reply_illegal"]
        changed_pairs = [p for p in adopted if p["response_id"] in
                         {u["frame_id"] for u in changed_illegal} | set()]
        checks = [
            {"rule": "pairing.broadcast_no_response", "holds": len(base_bc) == 1,
             "evidence": {"baseline_broadcasts": [u["id"] for u in base_bc]}},
            {"rule": "pairing.broadcast_no_response",
             "holds": len(changed_bc) == 0
             and any(p["rule"] == "rtu-silent" and not p["exception"] for p in adopted)
             and len(changed_illegal) <= 1,
             "evidence": {"after_change_broadcasts": [u["id"] for u in changed_bc],
                          "scope_added_pairs": diff["pairs"]["added"],
                          "unchanged_pairs": diff["pairs"]["unchanged"]}},
        ]
    elif mutation_id == "exception_code":
        base_exc = [p for p in base_run["proj"]["pairs"] if p["exception"]]
        base_exc_diag = [d for d in base_run["proj"]["diags"]
                         if d["code"] == "EXCEPTION_RESPONSE"]
        new_values = diff["values"]["added"]
        checks = [
            {"rule": "response.exception_is_failure", "holds": len(base_exc) == 1
             and len(base_exc_diag) == 1,
             "evidence": {"baseline_exception_pairs": [p["id"] for p in base_exc],
                          "no_value_ids_for_exception": True}},
            {"rule": "response.exception_is_failure",
             "holds": (len(new_values) >= 1 or any(
                 d["code"] in ("UNMAPPED_ADDRESS", "LENGTH_MISMATCH")
                 for d in changed_run["proj"]["diags"]))
             and diff["pairs"]["changed_signature"],
             "evidence": {"after_change_added_values": new_values,
                          "after_change_diags": [d["id"] for d in changed_run["proj"]["diags"]],
                          "changed_pairs": diff["pairs"]["changed_signature"]}},
        ]
    elif mutation_id == "address_base":
        checks = [
            {"rule": "address.base_presentation_only",
             "holds": (not diff["pairs"]["added"] and not diff["pairs"]["removed"]
                       and not diff["unpaired"]["added"] and not diff["unpaired"]["removed"]
                       and not diff["values"]["added"] and not diff["values"]["removed"]),
             "evidence": {"unchanged_pairs": diff["pairs"]["unchanged"],
                          "unchanged_unpaired": diff["unpaired"]["unchanged"],
                          "unchanged_values": diff["values"]["unchanged"],
                          "note": "raw_address_base/raw_address 记录原表示，zero_address 不变"}},
        ]
    elif mutation_id == "word_order":
        affected = [v for v in changed_run["proj"]["values"] if v["name"] == "ce_f32"]
        checks = [
            {"rule": "decode.word_order_scope",
             "holds": len(diff["values"]["added"]) == 0
             and len(diff["values"]["removed"]) == 0
             and len(diff["values"]["changed_signature"]) == 1
             and not diff["pairs"]["added"] and not diff["pairs"]["removed"],
             "evidence": {"changed_values": diff["values"]["changed_signature"],
                          "affected_name": [v["name"] for v in affected],
                          "unchanged_pairs": diff["pairs"]["unchanged"],
                          "unchanged_values": [i for i in diff["values"]["unchanged"]
                                               if i not in diff["values"]["changed_signature"]]}},
        ]
    elif mutation_id == "conn_reopen":
        checks = [
            {"rule": "pairing.generation_isolation",
             "holds": len(diff["generations"]["removed"]) >= 1
             or len(diff["generations"]["added"]) >= 1,
             "evidence": {"removed_generations": diff["generations"]["removed"],
                          "added_generations": diff["generations"]["added"],
                          "unchanged_generations": diff["generations"]["unchanged"],
                          "unchanged_pairs": diff["pairs"]["unchanged"],
                          "note": "连接事件变化只影响相关代次与其内配对"}},
        ]

    return {
        "accepted": accepted_ids, "not_adopted": rejected_ids,
        "candidate_ids": [c["id"] for c in candidates],
        "candidate_details": [{"id": c["id"], "request_id": c["request_id"],
                               "response_id": c["response_id"], "status": c["status"],
                               "reason": c["reason"]} for c in candidates],
        "judgements": checks,
        "all_rules_hold": all(c["holds"] for c in checks) if checks else False,
        "diff": diff,
    }
