"""服务层：导入 → 推导 → 复核 的完整工作流。

- 每个计算结果记录输入摘要、参数版本与父级依赖（parents）。
- 回到任意旧事件：重放 ≤ 该事件序号的状态，恢复当时的依赖版本与
  可见结论，而不是用最新计算覆盖历史。
- 接受/否定/参数调整都生成新事件；互相冲突的人工决定双方保留，
  并产生 conflict_recorded 事件。
"""
from __future__ import annotations

from .core import (Frame, Diagnostic, canonical_digest, parse_frame,
                   OUTCOME_OK)
from .pairing import pair_frames, RULE_VERSION
from .registers import (RegisterMapping, interpret_all, INTERP_VERSION,
                        ADDRESS_BASES, BYTE_ORDERS, WORD_ORDERS)
from .store import Store

DEFAULT_PARAMS = {"byte_order": "big", "word_order": "high_first",
                  "display_base": "zero", "turnaround_ms": 100.0}


class ReviewSession:
    def __init__(self, store: Store):
        self.store = store

    # ---------- 事件写入 ----------
    def _commit(self, kind: str, body: dict, parents: list[str] | None = None,
                materials: list[dict] | None = None) -> str:
        seq = self.store.next_seq()
        event_id = f"evt-{seq:06d}-{canonical_digest([kind, body, seq])[:8]}"
        self.store.commit_batch(
            materials=materials,
            events=[{"event_id": event_id, "seq": seq, "kind": kind,
                     "body": body, "parents": parents or []}])
        return event_id

    # ---------- 导入 ----------
    def import_materials(self, *, frames: list[dict], mappings: list[dict],
                         serial_events: list[dict], source_label: str) -> str:
        materials, frame_ids, mapping_ids, serial_ids = [], [], [], []
        for spec in frames:
            frame_id = spec.get("frame_id") or \
                f"frm-{canonical_digest(spec)[:12]}"
            frame = parse_frame(
                frame_id, bytes.fromhex(spec["raw_hex"]), link=spec["link"],
                direction=spec["direction"], conn_gen=spec["conn_gen"],
                t_ms=spec["t_ms"], address_base=spec.get("address_base", "zero"),
                mapping_version=spec.get("mapping_version", "unknown"),
                source=spec.get("source", source_label))
            materials.append({"id": frame_id, "kind": "frame",
                              "body": frame.to_dict(),
                              "digest": canonical_digest(frame.to_dict())})
            frame_ids.append(frame_id)
        for spec in mappings:
            mapping = RegisterMapping.from_dict(spec)
            materials.append({"id": mapping.mapping_id, "kind": "mapping",
                              "body": mapping.to_dict(),
                              "digest": canonical_digest(mapping.to_dict())})
            mapping_ids.append(mapping.mapping_id)
        for spec in serial_events:
            sid = spec.get("event_id") or f"ser-{canonical_digest(spec)[:12]}"
            body = dict(spec, event_id=sid)
            materials.append({"id": sid, "kind": "serial_event", "body": body,
                              "digest": canonical_digest(body)})
            serial_ids.append(sid)
        return self._commit("materials_imported", {
            "source_label": source_label,
            "frame_ids": frame_ids, "mapping_ids": mapping_ids,
            "serial_event_ids": serial_ids,
            "time_base": "monotonic_ms_since_capture_start",
            "note": "原 ADU 字节、方向、transaction id、unit id、CRC、功能码、"
                    "地址基准与映射表版本均保留在材料层",
        }, materials=materials)

    # ---------- 推导 ----------
    def _current_materials(self, upto_seq: int | None = None):
        events = self.store.all_events(upto_seq=upto_seq)
        frame_ids: list[str] = []
        mapping_ids: list[str] = []
        serial_ids: list[str] = []
        replaced: dict[str, str] = {}
        for ev in events:
            if ev["kind"] == "materials_imported":
                frame_ids.extend(ev["body"]["frame_ids"])
                mapping_ids.extend(ev["body"]["mapping_ids"])
                serial_ids.extend(ev["body"]["serial_event_ids"])
            elif ev["kind"] == "source_corrected":
                replaced[ev["body"]["original_id"]] = ev["body"]["new_id"]
        # 被替换掉的旧版本不再可见，新版本进入视野
        visible = [replaced.get(fid, fid) for fid in frame_ids]
        mats = {m["id"]: m for m in self.store.all_materials()}
        frames = [Frame.from_dict(mats[i]["body"]) for i in visible if i in mats]
        mappings = {i: RegisterMapping.from_dict(mats[i]["body"])
                    for i in dict.fromkeys(mapping_ids) if i in mats}
        serials = [mats[i]["body"] for i in serial_ids if i in mats]
        return frames, mappings, serials

    def derive(self, params: dict | None = None,
               parents: list[str] | None = None) -> str:
        params = {**DEFAULT_PARAMS, **(params or {})}
        frames, mappings, _ = self._current_materials()
        pairing = pair_frames(frames, turnaround_ms=params["turnaround_ms"])
        frames_by_id = {f.frame_id: f for f in frames}
        interp = interpret_all(pairing, frames_by_id, mappings,
                               byte_order=params["byte_order"],
                               word_order=params["word_order"],
                               display_base=params["display_base"])
        input_digest = canonical_digest({
            "frames": [[f.frame_id, f.raw_hex] for f in frames],
            "mappings": sorted(mappings.keys()), "params": params})
        return self._commit("derivation_computed", {
            "rule_version": RULE_VERSION, "interp_version": INTERP_VERSION,
            "params": params, "input_digest": input_digest,
            "pairing": pairing, "interpretation": interp,
        }, parents=parents)

    # ---------- 决定 ----------
    def decide(self, *, target_id: str, verdict: str, reviewer: str,
               rationale: str) -> str:
        if verdict not in ("accept", "reject", "adjust"):
            raise ValueError("verdict 必须是 accept/reject/adjust")
        events = self.store.all_events()
        prior = [e for e in events if e["kind"] == "decision_recorded"
                 and e["body"]["target_id"] == target_id]
        parents = [e["event_id"] for e in prior]
        event_id = self._commit("decision_recorded", {
            "target_id": target_id, "verdict": verdict,
            "reviewer": reviewer, "rationale": rationale}, parents=parents)
        conflicting = [e for e in prior if e["body"]["verdict"] != verdict]
        if conflicting:
            self._commit("conflict_recorded", {
                "target_id": target_id,
                "decisions": [e["event_id"] for e in conflicting] + [event_id],
                "note": "互相冲突的人工决定，双方均保留，未互相覆盖"},
                parents=[event_id])
        return event_id

    # ---------- 参数修订 ----------
    def revise_params(self, *, reason: str, **changes) -> str:
        for key in changes:
            if key == "display_base" and changes[key] not in ADDRESS_BASES:
                raise ValueError("display_base 必须是 zero/one")
            if key == "byte_order" and changes[key] not in BYTE_ORDERS:
                raise ValueError("byte_order 必须是 big/little")
            if key == "word_order" and changes[key] not in WORD_ORDERS:
                raise ValueError("word_order 必须是 high_first/low_first")
        _, latest = self._latest_derivation()
        old_params = (latest or {}).get("params", DEFAULT_PARAMS)
        new_params = {**old_params, **changes}
        event_id = self._commit("parameter_revised", {
            "reason": reason, "old": old_params, "new": new_params})
        return self.derive(params=new_params, parents=[event_id])

    # ---------- 源数据改动（只影响局部依赖） ----------
    def correct_source(self, *, frame_id: str, raw_hex: str, reason: str) -> str:
        mats = {m["id"]: m for m in self.store.all_materials()}
        if frame_id not in mats:
            raise KeyError(f"材料不存在: {frame_id}")
        old = Frame.from_dict(mats[frame_id]["body"])
        n = len([e for e in self.store.all_events()
                 if e["kind"] == "source_corrected"
                 and e["body"]["original_id"] == frame_id]) + 1
        new_id = f"{frame_id}-fix{n}"
        new_frame = parse_frame(new_id, bytes.fromhex(raw_hex), link=old.link,
                                direction=old.direction, conn_gen=old.conn_gen,
                                t_ms=old.t_ms, address_base=old.address_base,
                                mapping_version=old.mapping_version,
                                source=f"correction-of:{old.source}")
        material = {"id": new_id, "kind": "frame", "body": new_frame.to_dict(),
                    "digest": canonical_digest(new_frame.to_dict())}
        event_id = self._commit("source_corrected", {
            "original_id": frame_id, "new_id": new_id, "reason": reason,
            "old_digest": mats[frame_id]["digest"],
            "new_digest": material["digest"]}, materials=[material])
        return self.derive(parents=[event_id])

    # ---------- 状态重放 ----------
    def _latest_derivation(self, upto_seq: int | None = None):
        events = self.store.all_events(upto_seq=upto_seq)
        derivations = [e for e in events if e["kind"] == "derivation_computed"]
        if not derivations:
            return None, None
        last = derivations[-1]
        return last["event_id"], last["body"]

    def state_at(self, seq: int | None = None) -> dict:
        """重放到指定事件序号（缺省最新），恢复当时的依赖版本与可见结论。"""
        frames, mappings, serials = self._current_materials(upto_seq=seq)
        events = self.store.all_events(upto_seq=seq)
        deriv_id, derivation = self._latest_derivation(upto_seq=seq)
        decisions = [e for e in events if e["kind"] == "decision_recorded"]
        conflicts = [e for e in events if e["kind"] == "conflict_recorded"]
        params_events = [e for e in events if e["kind"] == "parameter_revised"]
        corrections = [e for e in events if e["kind"] == "source_corrected"]
        conn_gens: dict[str, dict] = {}
        for f in frames:
            key = f"{f.link}-gen{f.conn_gen}"
            g = conn_gens.setdefault(key, {
                "generation_id": key, "link": f.link, "conn_gen": f.conn_gen,
                "frame_ids": [], "t_first": f.t_ms, "t_last": f.t_ms})
            g["frame_ids"].append(f.frame_id)
            g["t_first"] = min(g["t_first"], f.t_ms)
            g["t_last"] = max(g["t_last"], f.t_ms)
        return {
            "at_seq": seq if seq is not None else (events[-1]["seq"] if events else 0),
            "time_base": "monotonic_ms_since_capture_start",
            "frames": [f.to_dict() for f in frames],
            "mappings": [m.to_dict() for m in mappings.values()],
            "serial_events": serials,
            "connection_generations": sorted(
                conn_gens.values(), key=lambda g: (g["link"], g["conn_gen"])),
            "derivation_event_id": deriv_id,
            "derivation": derivation,
            "decisions": decisions,
            "conflicts": conflicts,
            "parameter_revisions": params_events,
            "source_corrections": corrections,
            "events": events,
        }
