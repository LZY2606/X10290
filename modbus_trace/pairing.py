"""请求/响应配对引擎。

规则版本 pairing-rules/v1：
- TCP：同一连接代次内按 (transaction id, unit id) 配对；连接重开后
  transaction id 复用不会跨代次误配；同一代次内复用导致多候选时，
  保留全部合法候选并标记 semantic_unresolved。
- RTU：按 unit id + 静默间隔窗口配对；完全相同字节的重发请求使前一
  请求被取代（superseded_by_retransmit），响应归最近一次请求。
- 广播（unit id 0）没有响应是正常语义，不是缺失。
- 异常响应（功能码 | 0x80）照常配对，但状态为 exception，
  绝不能当作“成功的空数据”。
- 三种失败结果可区分：budget_exhausted / format_corrupt /
  semantic_unresolved。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

from .core import (Frame, Diagnostic, OUTCOME_OK, OUTCOME_BUDGET_EXHAUSTED,
                   OUTCOME_SEMANTIC_UNRESOLVED)

RULE_VERSION = "pairing-rules/v1"
DEFAULT_TURNAROUND_MS = 100.0   # RTU 静默间隔窗口上限
DEFAULT_BUDGET = 100_000        # 配对比较操作的资源预算

# 未配对原因码
REASON_BROADCAST = "broadcast_no_response_expected"
REASON_AWAITING = "awaiting_response"
REASON_ORPHAN = "orphan_response"
REASON_RETRANSMIT = "superseded_by_retransmit"
REASON_UNPARSED = "unparsed_frame"
REASON_BUDGET = "budget_exhausted"


@dataclass
class Pair:
    pair_id: str
    rule_version: str
    link: str
    conn_gen: int
    request_id: Optional[str]        # ambiguous 时为 None
    response_id: Optional[str]
    status: str                      # paired / exception / ambiguous
    unit_id: Optional[int] = None
    function_code: Optional[int] = None
    exception_code: Optional[int] = None
    candidates: list = field(default_factory=list)   # 无法唯一决定时的全部合法候选
    turnaround_ms: Optional[float] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class UnpairedFrame:
    frame_id: str
    reason: str
    detail: str

    def to_dict(self):
        return asdict(self)


def stable_frame_order(frames: list[Frame]) -> list[Frame]:
    """等价输入得到稳定顺序：时间、连接代次、身份三重键。"""
    return sorted(frames, key=lambda f: (f.t_ms, f.conn_gen, f.frame_id))


def _pair_tcp(frames: list[Frame], budget: list[int]):
    pairs, unpaired = [], []
    requests: dict[tuple, list[Frame]] = {}
    responses: list[Frame] = []
    for f in frames:
        if not f.parse_ok:
            unpaired.append(UnpairedFrame(f.frame_id, REASON_UNPARSED,
                                          "帧解析失败，不参与配对；诊断见材料层"))
            continue
        if f.is_request:
            requests.setdefault((f.conn_gen, f.transaction_id, f.unit_id), []).append(f)
        else:
            responses.append(f)
    matched_req_ids = set()
    for resp in responses:
        key = (resp.conn_gen, resp.transaction_id, resp.unit_id)
        cands = [r for r in requests.get(key, []) if r.frame_id not in matched_req_ids]
        budget[0] -= len(requests.get(key, []))
        if budget[0] < 0:
            return pairs, unpaired, OUTCOME_BUDGET_EXHAUSTED
        seq = len(pairs) + 1
        if not cands:
            unpaired.append(UnpairedFrame(
                resp.frame_id, REASON_ORPHAN,
                f"连接代次 {resp.conn_gen} 内没有 transaction id={resp.transaction_id} "
                f"unit id={resp.unit_id} 的待配请求"))
            continue
        if len(cands) > 1:
            # transaction id 在同一代次内复用：保留全部合法候选
            pairs.append(Pair(
                pair_id=f"pair-{seq:04d}", rule_version=RULE_VERSION, link="tcp",
                conn_gen=resp.conn_gen, request_id=None, response_id=resp.frame_id,
                status="ambiguous", unit_id=resp.unit_id,
                function_code=resp.function_code,
                exception_code=resp.exception_code,
                candidates=[r.frame_id for r in cands],
                turnaround_ms=None))
            for r in cands:
                matched_req_ids.add(r.frame_id)
            continue
        req = cands[0]
        matched_req_ids.add(req.frame_id)
        status = "exception" if resp.is_exception else "paired"
        pairs.append(Pair(
            pair_id=f"pair-{seq:04d}", rule_version=RULE_VERSION, link="tcp",
            conn_gen=resp.conn_gen, request_id=req.frame_id, response_id=resp.frame_id,
            status=status, unit_id=req.unit_id, function_code=req.function_code,
            exception_code=resp.exception_code,
            turnaround_ms=round(resp.t_ms - req.t_ms, 3)))
    for key, reqs in requests.items():
        for r in reqs:
            if r.frame_id in matched_req_ids:
                continue
            if r.is_broadcast:
                unpaired.append(UnpairedFrame(r.frame_id, REASON_BROADCAST,
                                              "广播请求（unit id 0）按协议没有响应"))
            else:
                unpaired.append(UnpairedFrame(r.frame_id, REASON_AWAITING,
                                              "捕获窗口内未出现匹配响应"))
    return pairs, unpaired, OUTCOME_OK


def _pair_rtu(frames: list[Frame], turnaround_ms: float, budget: list[int]):
    pairs, unpaired = [], []
    pending: dict[int, list[Frame]] = {}
    seq = 0
    for f in frames:
        budget[0] -= 1
        if budget[0] < 0:
            return pairs, unpaired, OUTCOME_BUDGET_EXHAUSTED
        if not f.parse_ok:
            unpaired.append(UnpairedFrame(f.frame_id, REASON_UNPARSED,
                                          "帧解析失败（如 CRC 错误），不参与配对"))
            continue
        if f.is_request:
            if f.is_broadcast:
                unpaired.append(UnpairedFrame(f.frame_id, REASON_BROADCAST,
                                              "广播请求（unit id 0）按协议没有响应"))
                continue
            queue = pending.setdefault(f.unit_id, [])
            # 完全相同字节的重发：前一请求被取代
            if queue and queue[-1].raw_hex == f.raw_hex:
                unpaired.append(UnpairedFrame(
                    queue[-1].frame_id, REASON_RETRANSMIT,
                    f"被 {f.frame_id} 的 RTU 重传取代（字节完全一致）"))
                queue[-1] = f
            else:
                queue.append(f)
            continue
        # 响应：取该 unit 静默窗口内最近一次未配请求
        queue = pending.get(f.unit_id, [])
        chosen = None
        for req in reversed(queue):
            budget[0] -= 1
            if budget[0] < 0:
                return pairs, unpaired, OUTCOME_BUDGET_EXHAUSTED
            if 0 <= (f.t_ms - req.t_ms) <= turnaround_ms:
                chosen = req
                break
        if chosen is None:
            unpaired.append(UnpairedFrame(
                f.frame_id, REASON_ORPHAN,
                f"unit id={f.unit_id} 在静默窗口 {turnaround_ms}ms 内无待配请求"))
            continue
        queue.remove(chosen)
        seq += 1
        status = "exception" if f.is_exception else "paired"
        pairs.append(Pair(
            pair_id=f"pair-rtu-{seq:04d}", rule_version=RULE_VERSION, link="rtu",
            conn_gen=f.conn_gen, request_id=chosen.frame_id, response_id=f.frame_id,
            status=status, unit_id=f.unit_id, function_code=chosen.function_code,
            exception_code=f.exception_code,
            turnaround_ms=round(f.t_ms - chosen.t_ms, 3)))
    for unit, queue in pending.items():
        for r in queue:
            unpaired.append(UnpairedFrame(r.frame_id, REASON_AWAITING,
                                          "捕获窗口内未出现匹配响应"))
    return pairs, unpaired, OUTCOME_OK


def pair_frames(frames: list[Frame], *, turnaround_ms: float = DEFAULT_TURNAROUND_MS,
                budget: int = DEFAULT_BUDGET) -> dict:
    """对一批帧执行配对，返回结构化、可重放的结果。"""
    ordered = stable_frame_order(frames)
    budget_box = [budget]
    tcp_frames = [f for f in ordered if f.link == "tcp"]
    rtu_frames = [f for f in ordered if f.link == "rtu"]
    pairs, unpaired, out1 = _pair_tcp(tcp_frames, budget_box)
    p2, u2, out2 = _pair_rtu(rtu_frames, turnaround_ms, budget_box)
    pairs += p2
    unpaired += u2
    outcome = OUTCOME_OK
    diagnostics: list[Diagnostic] = []
    if OUTCOME_BUDGET_EXHAUSTED in (out1, out2):
        outcome = OUTCOME_BUDGET_EXHAUSTED
        diagnostics.append(Diagnostic(
            OUTCOME_BUDGET_EXHAUSTED,
            f"配对预算 {budget} 次操作耗尽，结果不完整，未配对项不得视为无响应"))
    elif any(p.status == "ambiguous" for p in pairs):
        outcome = OUTCOME_SEMANTIC_UNRESOLVED
        diagnostics.append(Diagnostic(
            OUTCOME_SEMANTIC_UNRESOLVED,
            "存在 transaction id 复用导致的多候选配对，全部合法候选已保留"))
    pairs.sort(key=lambda p: p.pair_id)
    unpaired.sort(key=lambda u: u.frame_id)
    return {
        "rule_version": RULE_VERSION,
        "turnaround_ms": turnaround_ms,
        "outcome": outcome,
        "pairs": [p.to_dict() for p in pairs],
        "unpaired": [u.to_dict() for u in unpaired],
        "diagnostics": [d.to_dict() for d in diagnostics],
    }
