"""请求/响应配对引擎。

规则（机器可读地记录在结果中）：
- TCP 按 (transaction id, unit id, 连接代次) 配对；tid 复用时保留全部合法候选，
  主配对取最近一次请求，其余记为 tid_reused_superseded。
- RTU 无 tid，按 (unit id, 功能码) 在静默间隔窗口内配对；相同 ADU 的重传
  取代前一请求（rtu_retransmit_superseded），响应归入最后一次重传。
- 广播（unit id 0）没有响应，是终态而非错误。
- 异常响应（功能码 | 0x80）与请求配对，但状态为 exception，绝不当作成功的空数据。
- 连接重开划分代次；上一代未应答的请求记 connection_reopened，跨代次 tid 不互相干扰。
- 资源预算耗尽返回 budget_exhausted，与 format_corrupt / semantic_unsolvable 是三种不同结果。
- 等价输入得到稳定顺序：帧按 (tick, frame_id) 排序，pair_id 为内容摘要。
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional

from .domain import digest, BUDGET_EXHAUSTED


@dataclass(frozen=True)
class PairParams:
    version: str = "pair-v1"
    rtu_response_window_ticks: int = 50    # RTU 静默间隔窗口（响应须在此窗口内到达）
    tcp_response_window_ticks: int = 1000  # TCP 响应窗口
    max_operations: int = 100000           # 资源预算：最大处理帧数

def apply_param_changes(params: PairParams, changes: dict, version: str) -> PairParams:
    allowed = {"rtu_response_window_ticks", "tcp_response_window_ticks", "max_operations"}
    params = replace(params, **{k: v for k, v in changes.items() if k in allowed})
    return replace(params, version=version)


def _pair_id(rule: str, req_id: Optional[str], resp_id: Optional[str], status: str) -> str:
    return "pair-" + digest({"rule": rule, "req": req_id, "resp": resp_id, "status": status})[:12]


def _budget_tick(state: dict, params: PairParams, frame: dict, diags: list) -> bool:
    state["ops"] += 1
    if state["ops"] > params.max_operations:
        state["exhausted"] = True
        diags.append({
            "kind": BUDGET_EXHAUSTED,
            "message": f"配对预算耗尽：第 {state['ops']} 次操作超过上限 {params.max_operations}",
            "position": frame["tick"],
            "frame_id": frame["frame_id"],
        })
        return False
    return True


def _unpaired(frame: dict, role: str, reason: str, message: str) -> dict:
    return {
        "frame_id": frame["frame_id"],
        "role": role,
        "reason": reason,
        "message": message,
        "tick": frame["tick"],
        "generation": frame["conn_generation"],
        "transport": frame["transport"],
    }


def _pair_record(rule, gen, transport, tick, req, resp, status, reason=None,
                 exception_code=None, candidates=None) -> dict:
    req_id = req["frame_id"] if req else None
    resp_id = resp["frame_id"] if resp else None
    return {
        "pair_id": _pair_id(rule, req_id, resp_id, status),
        "rule": rule,
        "generation": gen,
        "transport": transport,
        "tick": tick,
        "request_frame_id": req_id,
        "response_frame_id": resp_id,
        "status": status,
        "reason": reason,
        "exception_code": exception_code,
        "candidates": candidates if candidates is not None else ([req_id] if req_id else []),
    }


def _pair_tcp(frames, params, pairs, unpaired, state, diags, is_last_generation):
    pending: dict[int, list] = {}   # tid -> 未应答请求（最新在末尾）
    shadow: dict[int, list] = {}    # tid -> 被复用取代的候选（保留作合法候选）
    for f in frames:
        if not _budget_tick(state, params, f, diags):
            return
        p = f["parsed"]
        tid, uid = p["transaction_id"], p["unit_id"]
        if f["direction"] == "out":
            if uid == 0:
                pairs.append(_pair_record(
                    "broadcast", f["conn_generation"], "tcp", f["tick"], f, None,
                    "broadcast_no_response",
                    reason="unit id 0 为广播地址，协议规定不产生响应"))
                continue
            if pending.get(tid):
                for old in pending[tid]:
                    shadow.setdefault(tid, []).append(old)
                    unpaired.append(_unpaired(
                        old, "request", "tid_reused_superseded",
                        f"transaction id {tid} 在应答前被复用，本请求被取代"))
                pending[tid] = []
            pending.setdefault(tid, []).append(f)
        else:
            live = pending.get(tid) or []
            allc = live + shadow.get(tid, [])
            if not allc:
                unpaired.append(_unpaired(
                    f, "response", "orphan_response",
                    f"没有等待中的 transaction id {tid} 请求"))
                continue
            primary = live[-1]
            fc = p["function_code"]
            pdu = bytes.fromhex(p["pdu_hex"])
            status, exc = "paired", None
            if fc & 0x80:
                status = "exception"
                exc = pdu[1] if len(pdu) > 1 else None
            if len(allc) > 1 and status == "paired":
                status = "ambiguous_tid_reuse"
            pairs.append(_pair_record(
                "tcp_tid", f["conn_generation"], "tcp", primary["tick"], primary, f,
                status,
                reason=("transaction id 复用，无法唯一决定归属，保留全部合法候选"
                        if status == "ambiguous_tid_reuse" else None),
                exception_code=exc,
                candidates=[c["frame_id"] for c in allc]))
            pending[tid] = []
            shadow[tid] = []
    for tid, lst in pending.items():
        for f in lst:
            reason = "no_response_timeout" if is_last_generation else "connection_reopened"
            msg = ("响应窗口内未收到应答" if is_last_generation
                   else "连接重开划分新代次，上一代请求随之失效")
            unpaired.append(_unpaired(f, "request", reason, msg))


def _pair_rtu(frames, params, pairs, unpaired, state, diags, is_last_generation):
    pending: dict[int, list] = {}   # uid -> 未应答请求
    for f in frames:
        if not _budget_tick(state, params, f, diags):
            return
        p = f["parsed"]
        uid = p["unit_id"]
        if f["direction"] == "out":
            if uid == 0:
                pairs.append(_pair_record(
                    "broadcast", f["conn_generation"], "rtu", f["tick"], f, None,
                    "broadcast_no_response",
                    reason="unit id 0 为广播地址，协议规定不产生响应"))
                continue
            lst = pending.setdefault(uid, [])
            if lst and lst[-1]["adu_hex"] == f["adu_hex"]:
                old = lst.pop()
                unpaired.append(_unpaired(
                    old, "request", "rtu_retransmit_superseded",
                    "相同 ADU 的 RTU 重传，响应归入最后一次重传"))
            else:
                for old in lst:
                    unpaired.append(_unpaired(
                        old, "request", "no_response_timeout",
                        "新请求到达前未收到应答"))
                lst.clear()
            lst.append(f)
        else:
            fc = p["function_code"]
            pdu = bytes.fromhex(p["pdu_hex"])
            lst = pending.get(uid) or []
            match = None
            if fc & 0x80:
                base = fc & 0x7F
                for cand in reversed(lst):
                    if cand["parsed"]["function_code"] == base:
                        match = cand
                        break
            else:
                for cand in reversed(lst):
                    if cand["parsed"]["function_code"] == fc:
                        match = cand
                        break
            if match is None:
                unpaired.append(_unpaired(
                    f, "response", "orphan_response",
                    f"没有等待中的 unit id {uid} 匹配请求"))
                continue
            lst.remove(match)
            if f["tick"] - match["tick"] > params.rtu_response_window_ticks:
                unpaired.append(_unpaired(
                    match, "request", "rtu_silent_interval_exceeded",
                    f"响应间隔 {f['tick'] - match['tick']} tick 超过静默窗口 "
                    f"{params.rtu_response_window_ticks}"))
                unpaired.append(_unpaired(
                    f, "response", "rtu_silent_interval_exceeded",
                    "响应落在静默窗口之外，不与任何请求配对"))
                continue
            status, exc = "paired", None
            if fc & 0x80:
                status = "exception"
                exc = pdu[1] if len(pdu) > 1 else None
            pairs.append(_pair_record(
                "rtu_silent_interval", f["conn_generation"], "rtu", match["tick"],
                match, f, status, exception_code=exc))
    for uid, lst in pending.items():
        for f in lst:
            reason = "no_response_timeout" if is_last_generation else "connection_reopened"
            msg = ("静默窗口内未收到应答" if is_last_generation
                   else "总线/连接重开划分新代次，上一代请求随之失效")
            unpaired.append(_unpaired(f, "request", reason, msg))


def run_pairing(frames: list[dict], params: PairParams) -> dict:
    """frames: 含 frame_id/transport/direction/conn_generation/tick/adu_hex/parsed/diagnostics。"""
    ordered = sorted(frames, key=lambda f: (f["tick"], f["frame_id"]))
    pairs: list[dict] = []
    unpaired: list[dict] = []
    frame_diags: list[dict] = []
    groups: dict[tuple, list] = {}
    group_order: list[tuple] = []
    for f in ordered:
        if f.get("parsed") is None:
            for d in f.get("diagnostics", []):
                frame_diags.append({**d, "frame_id": f["frame_id"]})
            unpaired.append(_unpaired(f, f["direction"], "format_corrupt",
                                      "帧解析失败，不参与配对（详见诊断）"))
            continue
        key = (f["transport"], f["conn_generation"])
        if key not in groups:
            groups[key] = []
            group_order.append(key)
        groups[key].append(f)

    max_gen: dict[str, int] = {}
    for transport, gen in groups:
        max_gen[transport] = max(gen, max_gen.get(transport, gen))

    state = {"ops": 0, "exhausted": False}
    for transport, gen in group_order:
        if state["exhausted"]:
            break
        is_last = gen == max_gen[transport]
        if transport == "tcp":
            _pair_tcp(groups[(transport, gen)], params, pairs, unpaired, state, frame_diags, is_last)
        else:
            _pair_rtu(groups[(transport, gen)], params, pairs, unpaired, state, frame_diags, is_last)

    pairs.sort(key=lambda p: (p["tick"], p["pair_id"]))
    unpaired.sort(key=lambda u: (u["tick"], u["frame_id"]))
    return {
        "status": BUDGET_EXHAUSTED if state["exhausted"] else "ok",
        "param_version": params.version,
        "pairs": pairs,
        "unpaired": unpaired,
        "frame_diagnostics": frame_diags,
        "stats": {"operations": state["ops"]},
    }
