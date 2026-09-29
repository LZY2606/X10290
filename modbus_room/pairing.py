"""请求/响应配对与寄存器解释。

规则要点：
- TCP 按 (transaction id, unit id) 在连接代次内配对；连接重开生成新代次，tid 空间重置。
- RTU 按静默间隔分隔帧，按 (unit id, 功能码) 配对；字节完全相同的重传归入同一逻辑请求。
- 广播（unit id 0）没有响应，不是错误。
- 异常响应（功能码 | 0x80）正常配对，但不产生寄存器值，不能当成功的空数据。
- 无法唯一决定时保留全部合法候选（ambiguous）。
- 等价输入得到稳定顺序：一律按 (tick, material_id) 排序。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

import numpy as np

from .adu import Frame
from .mapping import MappingVersion, decode_register
from .model import Diagnostic, Result, Status, stable_hash, stable_id

PAIRED = "paired"
PAIRED_EXCEPTION = "paired_exception"
UNPAIRED_BROADCAST = "unpaired_broadcast"
UNPAIRED_NO_RESPONSE = "unpaired_no_response"
UNMATCHED_RESPONSE = "unmatched_response"
AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class PairParams:
    version: str = "pair-v1"
    rtu_response_timeout_ms: float = 250.0
    rtu_retransmit_window_ms: float = 600.0
    max_frames: int = 10000
    max_registers: int = 4096

    def digest(self) -> str:
        return stable_hash(asdict(self))


@dataclass
class Envelope:
    material_id: str
    frame: Frame
    tick: float
    direction: str  # "request" | "response"
    connection_id: str


@dataclass
class PairRecord:
    transport: str
    generation: Optional[int]
    connection_id: str
    request_ids: list
    response_id: Optional[str]
    status: str
    reason: str
    transaction_id: Optional[int] = None
    unit_id: Optional[int] = None
    function_code: Optional[int] = None
    exception_code: Optional[int] = None
    candidates: list = field(default_factory=list)
    retransmissions: int = 0
    first_tick: float = 0.0

    def payload(self) -> dict:
        return {
            "transport": self.transport,
            "generation": self.generation,
            "connection_id": self.connection_id,
            "request_ids": list(self.request_ids),
            "response_id": self.response_id,
            "status": self.status,
            "reason": self.reason,
            "transaction_id": self.transaction_id,
            "unit_id": self.unit_id,
            "function_code": self.function_code,
            "exception_code": self.exception_code,
            "candidates": list(self.candidates),
            "retransmissions": self.retransmissions,
        }

    def parents(self) -> list:
        ids = list(self.request_ids) + list(self.candidates)
        if self.response_id:
            ids.append(self.response_id)
        return sorted(set(ids))

    def record_id(self, params: PairParams) -> str:
        # 身份只取决于结果内容与规则版本，不取决于参数取值：
        # 参数微调但结论不变时身份保持稳定。
        return stable_id("pair", {"payload": self.payload(), "rule": params.version})


def pair_frames(envelopes: list, params: PairParams) -> Result:
    if len(envelopes) > params.max_frames:
        return Result.failure(Status.BUDGET_EXHAUSTED, "budget_exhausted",
                              f"帧数 {len(envelopes)} 超出预算 {params.max_frames}",
                              position=params.max_frames)
    envs = sorted(envelopes, key=lambda e: (e.tick, e.material_id))
    records = _pair_tcp([e for e in envs if e.frame.transport == "tcp"], params)
    records += _pair_rtu([e for e in envs if e.frame.transport == "rtu"], params)
    records.sort(key=lambda r: (r.first_tick, r.record_id(params)))
    return Result(value=records)


def _pair_tcp(envs: list, params: PairParams) -> list:
    gens: dict = {}
    for e in envs:
        gens.setdefault(e.connection_id, []).append(e)
    ordered = sorted(gens.items(), key=lambda kv: min(x.tick for x in kv[1]))
    records = []
    for gen_idx, (cid, members) in enumerate(ordered, start=1):
        open_reqs: dict = {}
        for e in sorted(members, key=lambda x: (x.tick, x.material_id)):
            f = e.frame
            key = (f.transaction_id, f.unit_id)
            if e.direction == "request":
                open_reqs.setdefault(key, []).append(e)
                continue
            queue = open_reqs.get(key)
            if queue:
                req = queue.pop(0)
                exc = f.is_exception
                records.append(PairRecord(
                    "tcp", gen_idx, cid, [req.material_id], e.material_id,
                    PAIRED_EXCEPTION if exc else PAIRED,
                    "异常响应：按 transaction id 配对但不产生寄存器值" if exc
                    else "按 transaction id + unit id 在连接代次内配对",
                    transaction_id=f.transaction_id, unit_id=f.unit_id,
                    function_code=req.frame.base_function,
                    exception_code=f.exception_code if exc else None,
                    first_tick=req.tick))
            else:
                records.append(PairRecord(
                    "tcp", gen_idx, cid, [], e.material_id, UNMATCHED_RESPONSE,
                    "本连接代次内没有相同 transaction id + unit id 的未结请求",
                    transaction_id=f.transaction_id, unit_id=f.unit_id,
                    function_code=f.base_function, first_tick=e.tick))
        for queue in open_reqs.values():
            for req in queue:
                records.append(PairRecord(
                    "tcp", gen_idx, cid, [req.material_id], None, UNPAIRED_NO_RESPONSE,
                    "连接代次结束仍未收到响应",
                    transaction_id=req.frame.transaction_id, unit_id=req.frame.unit_id,
                    function_code=req.frame.base_function, first_tick=req.tick))
    return records


def _rtu_no_response(group: dict) -> PairRecord:
    first = group["envs"][0]
    return PairRecord(
        "rtu", None, first.connection_id,
        [x.material_id for x in group["envs"]], None, UNPAIRED_NO_RESPONSE,
        "rtu_response_timeout_ms 内未收到响应",
        unit_id=first.frame.unit_id, function_code=first.frame.base_function,
        retransmissions=len(group["envs"]) - 1, first_tick=first.tick)


def _pair_rtu(envs: list, params: PairParams) -> list:
    records = []
    outstanding: list = []

    def expire(upto_tick: float):
        for g in list(outstanding):
            if upto_tick - g["last_tick"] > params.rtu_response_timeout_ms:
                outstanding.remove(g)
                records.append(_rtu_no_response(g))

    for e in sorted(envs, key=lambda x: (x.tick, x.material_id)):
        expire(e.tick)
        f = e.frame
        if e.direction == "request":
            if f.is_broadcast:
                records.append(PairRecord(
                    "rtu", None, e.connection_id, [e.material_id], None,
                    UNPAIRED_BROADCAST, "广播请求：协议规定没有响应",
                    unit_id=f.unit_id, function_code=f.base_function, first_tick=e.tick))
                continue
            dup = None
            for g in outstanding:
                if (g["envs"][0].frame.raw == f.raw
                        and e.tick - g["last_tick"] <= params.rtu_retransmit_window_ms):
                    dup = g
                    break
            if dup is not None:
                dup["envs"].append(e)
                dup["last_tick"] = e.tick
            else:
                outstanding.append({"envs": [e], "last_tick": e.tick})
            continue
        cands = [g for g in outstanding
                 if g["envs"][0].frame.unit_id == f.unit_id
                 and g["envs"][0].frame.base_function == f.base_function]
        if not cands:
            records.append(PairRecord(
                "rtu", None, e.connection_id, [], e.material_id, UNMATCHED_RESPONSE,
                "总线上没有匹配的未结请求（unit id + 功能码）",
                unit_id=f.unit_id, function_code=f.base_function, first_tick=e.tick))
        elif len(cands) == 1:
            g = cands[0]
            outstanding.remove(g)
            exc = f.is_exception
            records.append(PairRecord(
                "rtu", None, e.connection_id,
                [x.material_id for x in g["envs"]], e.material_id,
                PAIRED_EXCEPTION if exc else PAIRED,
                "异常响应：配对但不产生寄存器值" if exc
                else "按静默间隔分隔后，以 unit id + 功能码配对",
                unit_id=f.unit_id, function_code=g["envs"][0].frame.base_function,
                exception_code=f.exception_code if exc else None,
                retransmissions=len(g["envs"]) - 1, first_tick=g["envs"][0].tick))
        else:
            flat = [x.material_id for g in cands for x in g["envs"]]
            for g in cands:
                outstanding.remove(g)
            records.append(PairRecord(
                "rtu", None, e.connection_id, [], e.material_id, AMBIGUOUS,
                "多个未结请求同时匹配 unit id + 功能码，保留全部合法候选等待人工决定",
                unit_id=f.unit_id, function_code=f.base_function,
                candidates=flat,
                first_tick=min(g["envs"][0].tick for g in cands)))
    for g in outstanding:
        records.append(_rtu_no_response(g))
    return records


@dataclass
class RegisterRecord:
    pair_id: str
    address: int  # 零基规范地址
    name: Optional[str]
    raw_hex: str
    value: Optional[float]
    unit: str
    valid: bool
    invalid_reason: Optional[str]
    regdef_digest: Optional[str]
    source_ids: list

    def payload(self) -> dict:
        return {
            "pair_id": self.pair_id,
            "address": self.address,
            "name": self.name,
            "raw_hex": self.raw_hex,
            "value": self.value,
            "unit": self.unit,
            "valid": self.valid,
            "invalid_reason": self.invalid_reason,
            "source_ids": list(self.source_ids),
        }

    def parents(self) -> list:
        deps = list(self.source_ids)
        if self.regdef_digest:
            deps.append(f"regdef:{self.regdef_digest}")
        return sorted(deps)

    def record_id(self, params: PairParams) -> str:
        return stable_id("reg", {"payload": self.payload(), "rule": params.version})


def _validity(value: float, regdef) -> tuple:
    if value != value:
        return False, "解码结果为 NaN，不是有效读数"
    if regdef.valid_min is not None and value < regdef.valid_min:
        return False, f"低于有效区间 [{regdef.valid_min}, {regdef.valid_max}] {regdef.unit}".strip()
    if regdef.valid_max is not None and value > regdef.valid_max:
        return False, f"高于有效区间 [{regdef.valid_min}, {regdef.valid_max}] {regdef.unit}".strip()
    return True, None


def interpret_pairs(pairs: list, envelopes_by_id: dict,
                    mapping: MappingVersion, params: PairParams) -> Result:
    records, diags = [], []
    total = 0
    by_addr = mapping.by_address()
    for rec in pairs:
        if rec.status != PAIRED:
            continue
        pid = rec.record_id(params)
        req = envelopes_by_id[rec.request_ids[-1]]
        resp = envelopes_by_id[rec.response_id]
        frame = req.frame
        if frame.base_function not in (0x03, 0x04):
            continue
        addr, qty = frame.req_address, frame.req_quantity
        data = resp.frame.data
        src = sorted({rec.request_ids[-1], rec.response_id})
        if addr is None or qty is None or not data:
            diags.append(Diagnostic("semantic_unsolvable",
                                    "读请求或响应缺少必要字段", subject=pid))
            continue
        byte_count = data[0]
        payload = data[1:1 + byte_count]
        if byte_count != qty * 2 or len(payload) != byte_count or len(payload) % 2:
            diags.append(Diagnostic(
                "semantic_unsolvable",
                f"响应字节数 {byte_count} 与请求数量 {qty} 不一致", subject=pid))
            continue
        total += qty
        if total > params.max_registers:
            return Result.failure(Status.BUDGET_EXHAUSTED, "budget_exhausted",
                                  f"寄存器数量超出预算 {params.max_registers}", position=total)
        i = 0
        while i < qty:
            address = addr + i
            regdef = by_addr.get(address)
            if regdef is None:
                seg = payload[2 * i:2 * i + 2]
                records.append(RegisterRecord(
                    pid, address, None, seg.hex(), None, "", False,
                    "该地址无映射定义，原始字节保留在原位置", None, src))
                i += 1
                continue
            seg = payload[2 * i:2 * i + 2 * regdef.words]
            if len(seg) < 2 * regdef.words:
                diags.append(Diagnostic("semantic_unsolvable",
                                        f"地址 {address} 的 {regdef.datatype} 被响应截断",
                                        position=i, subject=pid))
                i += 1
                continue
            try:
                _, value = decode_register(seg, regdef)
            except ValueError as exc:
                records.append(RegisterRecord(
                    pid, address, regdef.name, seg.hex(), None, regdef.unit, False,
                    f"无法转换: {exc}；原始字节保留", regdef.digest(), src))
                i += regdef.words
                continue
            valid, reason = _validity(value, regdef)
            records.append(RegisterRecord(
                pid, address, regdef.name, seg.hex(), value, regdef.unit,
                valid, reason, regdef.digest(), src))
            i += regdef.words
    return Result(value=records, diagnostics=diags)
