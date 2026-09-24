"""连接代次、总线代次与请求/响应配对。

TCP 与 RTU 使用不同配对规则：
- TCP：同一连接代次内按 (transaction_id, unit_id) 先进先出配对；
- RTU：单一主站总线，按静默间隔（默认 3.5 字符时间，19200bps 封顶 1.75ms）
  划分事务窗口，重传在窗口内共享首个响应。
广播（unit=0）没有响应；异常响应是配对成功但业务失败，绝不是空数据成功。
无法唯一决定时保留全部合法候选。
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .ids import digest

RTU_SILENT_GAP_MS = 1.75          # 3.5 字符 @19200bps
RTU_RESPONSE_TIMEOUT_MS = 100.0   # 主站默认超时，作为延迟判定基准

UNPAIRED_REASONS = [
    "tcp_no_open_transaction",
    "tcp_unit_mismatch",
    "tcp_xid_reuse_in_flight",
    "rtu_orphan_response",
    "rtu_unit_mismatch",
    "rtu_response_timeout",
    "rtu_bad_crc",
    "broadcast_no_response",
    "broadcast_reply_illegal",
    "parse_failed",
]


@dataclass
class Generation:
    id: str
    transport: str
    channel: str
    gen_index: int
    opened_t_ms: float
    closed_t_ms: float | None = None
    open_evidence: str = ""
    close_evidence: str = ""


def build_generations(frames: list[dict], events: list[dict]) -> list[Generation]:
    gens: list[Generation] = []
    open_idx: dict[str, int] = {}
    seq = sorted(
        [(f["t_ms"], 0, "frame", f) for f in frames]
        + [(e["t_ms"], 1, "event", e) for e in events],
        key=lambda x: (x[0], x[1]),
    )
    counter: dict[str, int] = defaultdict(int)
    for t_ms, _, kind, item in seq:
        if kind == "event":
            ch = item.get("channel") or ("bus-1" if item["kind"] == "serial" else "tcp-1")
            transport = "rtu" if item["kind"] == "serial" else "tcp"
            if item["action"] in ("open", "reopen", "power_on", "bus_acquire"):
                counter[ch] += 1
                g = Generation(digest("gen", {"channel": ch, "index": counter[ch]}),
                               transport, ch, counter[ch], t_ms,
                               open_evidence=item["id"],
                               close_evidence="")
                gens.append(g)
                open_idx[ch] = len(gens) - 1
            elif item["action"] in ("close", "reopen_close", "power_off", "bus_release"):
                if ch in open_idx:
                    gens[open_idx[ch]].closed_t_ms = t_ms
                    gens[open_idx[ch]].close_evidence = item["id"]
                    del open_idx[ch]
        else:
            ch = item["channel"]
            if ch not in open_idx:
                counter[ch] += 1
                gens.append(Generation(
                    digest("gen", {"channel": ch, "index": counter[ch]}),
                    item["transport"], ch, counter[ch], t_ms,
                    open_evidence="inferred:first-frame"))
                open_idx[ch] = len(gens) - 1
    return gens


def gen_at(gens: list[Generation], channel: str, t_ms: float) -> Generation | None:
    for g in gens:
        if g.channel == channel and g.opened_t_ms <= t_ms and (
                g.closed_t_ms is None or t_ms <= g.closed_t_ms):
            return g
    return None


def _pair_id(req_ids: list[str], resp_id: str, rule: str) -> str:
    return digest("pair", {"reqs": req_ids, "resp": resp_id, "rule": rule})


def _candidate_id(req_id: str, resp_id: str, rule: str) -> str:
    return digest("cand", {"req": req_id, "resp": resp_id, "rule": rule})


def _unpaired_id(frame_id: str, reason: str) -> str:
    return digest("unp", {"frame": frame_id, "reason": reason})


def _interval_id(frame_id: str, kind: str) -> str:
    return digest("ival", {"frame": frame_id, "kind": kind})


@dataclass
class PairResult:
    generations: list[Generation]
    pairs: list[dict] = field(default_factory=list)
    unpaired: list[dict] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    intervals: list[dict] = field(default_factory=list)
    silent_gaps: list[dict] = field(default_factory=list)
    rules: dict = field(default_factory=dict)


def pair_all(frames: list[dict], events: list[dict],
             rtu_gap_ms: float = RTU_SILENT_GAP_MS,
             rtu_timeout_ms: float = RTU_RESPONSE_TIMEOUT_MS) -> PairResult:
    gens = build_generations(frames, events)
    res = PairResult(
        generations=gens,
        rules={"tcp": "MBAP: (transaction_id,unit_id) FIFO per connection generation",
               "rtu": f"silent-gap {rtu_gap_ms}ms single-master window, timeout {rtu_timeout_ms}ms",
               "broadcast": "unit_id=0 writes have no response",
               "address_base": "PDU zero-based; one-based is presentation-only"},
    )
    tcp = sorted([f for f in frames if f["transport"] == "tcp"], key=lambda f: (f["t_ms"], f["seq"]))
    rtu = sorted([f for f in frames if f["transport"] == "rtu"], key=lambda f: (f["t_ms"], f["seq"]))
    _pair_tcp(tcp, gens, res)
    _pair_rtu(rtu, gens, events, res, rtu_gap_ms, rtu_timeout_ms)
    res.intervals.sort(key=lambda x: (x["t_ms"], x["id"]))
    res.pairs.sort(key=lambda x: (x["t_ms"], x["id"]))
    res.unpaired.sort(key=lambda x: (x["t_ms"], x["id"]))
    res.candidates.sort(key=lambda x: (x["t_ms"], x["id"]))
    return res


def _add_interval(res: PairResult, frame: dict):
    f = frame
    if f.get("parse_code") or f.get("role") not in ("request", "response", "exception"):
        return
    fc = f["fc"]
    if fc is None:
        return
    from .codec import FC_SPACE
    if f.get("role") == "exception":
        return
    if f["dir"] == "out":
        addr, qty = f.get("address"), f.get("quantity")
        if addr is None or qty is None:
            return
        res.intervals.append({
            "id": _interval_id(f["id"], "out"), "frame_id": f["id"],
            "space": FC_SPACE.get(fc), "start_zero": addr, "count": qty,
            "end_zero": addr + qty - 1, "t_ms": f["t_ms"], "dir": "out",
            "address_base_raw": 0, "generation_id": _gen_id(f, res),
        })
    elif fc in (3, 4) and f.get("values_hex"):
        n = len(bytes.fromhex(f["values_hex"])) // 2
        res.intervals.append({
            "id": _interval_id(f["id"], "in"), "frame_id": f["id"],
            "space": FC_SPACE.get(fc), "start_zero": None, "count": n,
            "end_zero": None, "t_ms": f["t_ms"], "dir": "in",
            "address_base_raw": 0, "generation_id": _gen_id(f, res),
        })


def _gen_id(frame: dict, res: PairResult) -> str | None:
    g = gen_at(res.generations, frame["channel"], frame["t_ms"])
    return g.id if g else None


def _pair_tcp(tcp: list[dict], gens: list[Generation], res: PairResult):
    queues: dict[str, list[dict]] = defaultdict(list)   # key -> open requests
    for f in tcp:
        _add_interval(res, f)
        if f.get("parse_code"):
            res.unpaired.append({"id": _unpaired_id(f["id"], "parse_failed"),
                                 "frame_id": f["id"], "reason": "parse_failed",
                                 "t_ms": f["t_ms"], "generation_id": _gen_id(f, res)})
            continue
        g = _gen_id(f, res)
        if f["dir"] == "out":
            key = f"{g or 'nog'}:{f['xid']}:{f['unit']}"
            if f["unit"] == 0:
                res.unpaired.append({"id": _unpaired_id(f["id"], "broadcast_no_response"),
                                     "frame_id": f["id"], "reason": "broadcast_no_response",
                                     "t_ms": f["t_ms"], "generation_id": g})
                continue
            queues[key].append(f)
        else:
            _tcp_match(f, g, queues, res)

    for key, qs in queues.items():
        for req in qs:
            res.unpaired.append({"id": _unpaired_id(req["id"], "tcp_no_open_transaction"),
                                 "frame_id": req["id"], "reason": "tcp_no_open_transaction",
                                 "t_ms": req["t_ms"], "generation_id": _gen_id(req, res)})


def _tcp_match(resp: dict, g: str | None, queues: dict, res: PairResult):
    exact = f"{g or 'nog'}:{resp['xid']}:{resp['unit']}"
    if exact in queues and queues[exact]:
        open_reqs = queues[exact]
        if len(open_reqs) == 1:
            req = open_reqs.pop(0)
            res.pairs.append(_pair_row([req], resp, "tcp-xid", g, status="adopted",
                                       rule_detail="transaction_id+unit 唯一待处理请求"))
        else:
            # transaction id 在途复用：保留全部合法候选
            for req in open_reqs:
                res.candidates.append({
                    "id": _candidate_id(req["id"], resp["id"], "tcp-xid-reuse"),
                    "request_id": req["id"], "response_id": resp["id"],
                    "rule": "tcp-xid-reuse", "t_ms": resp["t_ms"], "generation_id": g,
                    "status": "candidate", "reason": "同一连接代次内 transaction id 在途复用",
                })
            res.unpaired.append({"id": _unpaired_id(resp["id"], "tcp_xid_reuse_in_flight"),
                                 "frame_id": resp["id"], "reason": "tcp_xid_reuse_in_flight",
                                 "t_ms": resp["t_ms"], "generation_id": g,
                                 "candidate_request_ids": [r["id"] for r in open_reqs]})
            queues.pop(exact, None)   # 候选保留为待决对象，不再当无响应请求
        return
    # 没有精确待处理队列：区分单元不符 / 无代际匹配 / 已完成复用
    same_xid_other_unit = [k for k in queues if k.startswith(f"{g or 'nog'}:{resp['xid']}:") and queues[k]]
    if same_xid_other_unit:
        reason = "tcp_unit_mismatch"
    else:
        reason = "tcp_no_open_transaction"
    res.unpaired.append({"id": _unpaired_id(resp["id"], reason),
                         "frame_id": resp["id"], "reason": reason,
                         "t_ms": resp["t_ms"], "generation_id": g})


def _pair_row(reqs: list[dict], resp: dict, rule: str, gen_id: str | None,
              status: str, rule_detail: str, timeout_ms: float | None = None) -> dict:
    req_ids = [r["id"] for r in reqs]
    return {
        "id": _pair_id(req_ids, resp["id"], rule) if status == "adopted"
        else digest("pair", {"reqs": req_ids, "resp": resp["id"], "rule": rule, "status": status}),
        "request_ids": req_ids, "primary_request_id": req_ids[0],
        "response_id": resp["id"], "rule": rule, "rule_detail": rule_detail,
        "status": status, "t_ms": resp["t_ms"], "generation_id": gen_id,
        "latency_ms": resp["t_ms"] - reqs[0]["t_ms"],
        "timeout_ms": timeout_ms,
        "exception": resp.get("role") == "exception",
        "exception_code": resp.get("exception_code"),
    }


def _pair_rtu(rtu: list[dict], gens: list[Generation], events: list[dict],
              res: PairResult, gap_ms: float, timeout_ms: float):
    pending: dict[int, dict] = {}     # unit -> 当前待处理请求
    dupes: dict[int, list[dict]] = defaultdict(list)  # unit -> 窗口内重传
    last_t: dict[str, float] = {}    # channel -> 上一帧时间（静默间隔）
    seg_open_since: dict[str, float] = {}

    def timeout_due(now: float):
        for unit in list(pending):
            req = pending[unit]
            if now - req["t_ms"] > timeout_ms:
                g = _gen_id(req, res)
                res.unpaired.append({"id": _unpaired_id(req["id"], "rtu_response_timeout"),
                                     "frame_id": req["id"], "reason": "rtu_response_timeout",
                                     "t_ms": now, "generation_id": g})
                pending.pop(unit, None)
                dupes.pop(unit, None)

    for f in rtu:
        ch = f["channel"]
        timeout_due(f["t_ms"])
        gap = None if ch not in last_t else f["t_ms"] - last_t[ch]
        if gap is not None and gap > gap_ms:
            res.silent_gaps.append({
                "id": digest("gap", {"channel": ch, "t_ms": f["t_ms"]}),
                "channel": ch, "t_ms": f["t_ms"], "gap_ms": gap, "threshold_ms": gap_ms,
                "segment_close_t_ms": last_t[ch]})
            timeout_due(f["t_ms"])
            seg_open_since[ch] = f["t_ms"]
        else:
            seg_open_since.setdefault(ch, f["t_ms"])
        last_t[ch] = f["t_ms"]
        _add_interval(res, f)

        if f.get("parse_code"):
            if f["dir"] == "in" and f.get("crc_ok") is False:
                res.unpaired.append({"id": _unpaired_id(f["id"], "rtu_bad_crc"),
                                     "frame_id": f["id"], "reason": "rtu_bad_crc",
                                     "t_ms": f["t_ms"], "generation_id": _gen_id(f, res),
                                     "crc_received": f.get("crc_received"),
                                     "crc_calculated": f.get("crc_calculated")})
            else:
                res.unpaired.append({"id": _unpaired_id(f["id"], "parse_failed"),
                                     "frame_id": f["id"], "reason": "parse_failed",
                                     "t_ms": f["t_ms"], "generation_id": _gen_id(f, res)})
            continue
        if f["crc_ok"] is False and f["dir"] == "in":
            res.unpaired.append({"id": _unpaired_id(f["id"], "rtu_bad_crc"),
                                 "frame_id": f["id"], "reason": "rtu_bad_crc",
                                 "t_ms": f["t_ms"], "generation_id": _gen_id(f, res),
                                 "crc_received": f.get("crc_received"),
                                 "crc_calculated": f.get("crc_calculated")})
            continue

        g = _gen_id(f, res)
        if f["dir"] == "out":
            if f["unit"] == 0:
                res.unpaired.append({"id": _unpaired_id(f["id"], "broadcast_no_response"),
                                     "frame_id": f["id"], "reason": "broadcast_no_response",
                                     "t_ms": f["t_ms"], "generation_id": g})
                continue
            if pending.get(f["unit"]):
                # 静默窗口内才是共享响应的重传；超过静默间隔则旧请求先超时，新请求独立
                within = (gap is not None and gap <= gap_ms)
                if within:
                    dupes[f["unit"]].append(f)
                else:
                    old = pending.pop(f["unit"])
                    dupes.pop(f["unit"], None)
                    res.unpaired.append({"id": _unpaired_id(old["id"], "rtu_response_timeout"),
                                         "frame_id": old["id"],
                                         "reason": "rtu_response_timeout",
                                         "t_ms": f["t_ms"], "generation_id": g})
                    pending[f["unit"]] = f
            else:
                pending[f["unit"]] = f
        else:
            if f["unit"] == 0:
                res.unpaired.append({"id": _unpaired_id(f["id"], "broadcast_reply_illegal"),
                                     "frame_id": f["id"], "reason": "broadcast_reply_illegal",
                                     "t_ms": f["t_ms"], "generation_id": g})
                continue
            req = pending.get(f["unit"])
            if not req:
                res.unpaired.append({"id": _unpaired_id(f["id"], "rtu_orphan_response"),
                                     "frame_id": f["id"], "reason": "rtu_orphan_response",
                                     "t_ms": f["t_ms"], "generation_id": g})
                continue
            reqs = [req] + dupes.pop(f["unit"], [])
            latency = f["t_ms"] - req["t_ms"]
            detail = "静默窗口内首请求+重传共享响应" if len(reqs) > 1 else "静默窗口内单主站顺序匹配"
            res.pairs.append(_pair_row(reqs, f, "rtu-silent", g, status="adopted",
                                       rule_detail=detail, timeout_ms=timeout_ms))
            pending.pop(f["unit"], None)

    end_t = max([f["t_ms"] for f in rtu], default=0.0) + timeout_ms + 1
    timeout_due(end_t)
