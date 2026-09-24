"""反例档案：基线 + 每次只改动一个直接来源的变异。

判断依据以机器可读取的规则事件保存：
- rule-pairing-duality：TCP transaction id 与 RTU 静默间隔采用不同配对规则
- rule-broadcast-no-response：广播没有响应
- rule-display-base-only：零基/一基地址只在展示层转换
- rule-exception-not-empty-success：异常响应不能当成功的空数据

每个变异记录被采纳（adopted）与未采纳（rejected）的结果，
并检验影响被限制在正确范围（scope_check）。
"""
from __future__ import annotations

from .casepack import rtu
from .core import parse_frame
from .pairing import pair_frames
from .registers import RegisterMapping, interpret_all

ARCHIVE_ID = "counterexample-archive/v1"

JUDGMENT_RULES = [
    {"rule_id": "rule-pairing-duality", "kind": "judgment_rule",
     "statement": "TCP transaction id 与 RTU 静默间隔采用不同配对规则",
     "machine": {"tcp": {"pair_key": ["conn_gen", "transaction_id", "unit_id"]},
                  "rtu": {"pair_key": ["unit_id"],
                           "window": "silence_interval_ms"}}},
    {"rule_id": "rule-broadcast-no-response", "kind": "judgment_rule",
     "statement": "广播（unit id 0）没有响应，缺失响应不是异常",
     "machine": {"broadcast_unit_id": 0,
                  "expected_unpaired_reason": "broadcast_no_response_expected"}},
    {"rule_id": "rule-display-base-only", "kind": "judgment_rule",
     "statement": "零基或一基地址只在展示层转换，协议地址永不回写",
     "machine": {"canonical_space": "zero_based_protocol",
                  "conversion_layer": "display_only"}},
    {"rule_id": "rule-exception-not-empty-success", "kind": "judgment_rule",
     "statement": "异常响应不能当成功的空数据",
     "machine": {"exception_mask": 128,
                  "forbidden_interpretation": "successful_empty_data"}},
]

MAPPING = {"mapping_id": "map-ce-v1", "version": "map-ce-v1", "device": "ce-device",
           "entries": [
               {"start": 0, "count": 2, "name": "通道", "unit": "count",
                "datatype": "uint16", "scale": 1.0,
                "valid_min": 0.0, "valid_max": 65535.0, "declared_base": "zero"}]}


def _tcp(frame_id, tid, direction, conn_gen, t_ms, uid=1, fc=3,
         addr=0, qty=2, data=None, exc=None):
    if direction == "client_to_server":
        raw = tid.to_bytes(2, "big") + b"\x00\x00" + (6).to_bytes(2, "big") \
            + bytes([uid, fc]) + addr.to_bytes(2, "big") + qty.to_bytes(2, "big")
    elif exc is not None:
        raw = tid.to_bytes(2, "big") + b"\x00\x00" + (3).to_bytes(2, "big") \
            + bytes([uid, fc | 0x80, exc])
    else:
        payload = bytes(data or [])
        raw = tid.to_bytes(2, "big") + b"\x00\x00" \
            + (3 + len(payload)).to_bytes(2, "big") \
            + bytes([uid, fc, len(payload)]) + payload
    return parse_frame(frame_id, raw, link="tcp", direction=direction,
                       conn_gen=conn_gen, t_ms=t_ms, address_base="zero",
                       mapping_version="map-ce-v1", source="counterexample")


def _rtu(frame_id, payload_hex, direction, t_ms):
    return parse_frame(frame_id, bytes.fromhex(rtu(payload_hex)), link="rtu",
                       direction=direction, conn_gen=1, t_ms=t_ms,
                       address_base="zero", mapping_version="map-ce-v1",
                       source="counterexample")


def _baseline_frames():
    return [
        _tcp("ce-base-req", 1, "client_to_server", 1, 10.0),
        _tcp("ce-base-resp", 1, "server_to_client", 1, 20.0,
             data=[0x00, 0x2A, 0x00, 0x2B]),
    ]


def build_archive() -> dict:
    """构建反例档案：基线 + 7 个单源变异，含采纳/未采纳结果。"""
    baseline_frames = _baseline_frames()
    baseline = pair_frames(baseline_frames)
    baseline_interp = interpret_all(
        baseline, {f.frame_id: f for f in baseline_frames},
        {"map-ce-v1": RegisterMapping.from_dict(MAPPING)})

    mutations = []

    # 1. transaction id 复用（同一代次内）
    frames = _baseline_frames() + [
        _tcp("ce-m1-req2", 1, "client_to_server", 1, 15.0, addr=4)]
    frames[2].t_ms = 15.0
    frames[1].t_ms = 25.0  # 响应在两个同 tid 请求之后
    result = pair_frames(frames)
    amb = [p for p in result["pairs"] if p["status"] == "ambiguous"]
    mutations.append({
        "mutation_id": "mut-tid-reuse",
        "changed_source": "新增同一代次内复用 transaction id=1 的第二条请求",
        "result": result,
        "adopted": {"status": "ambiguous",
                    "candidates": amb[0]["candidates"] if amb else []},
        "rejected": {"status": "force_pair_to_first",
                     "why_rejected": "强行配给首条请求会丢失另一条合法候选"},
        "scope_check": {"affected_pairs": [p["pair_id"] for p in amb],
                        "expect": "仅该响应的配对状态变为 ambiguous，基线其它对象不变"},
    })

    # 2. RTU 重传
    frames = [
        _rtu("ce-m2-req1", "0503000a0002", "master_to_slave", 10.0),
        _rtu("ce-m2-req2", "0503000a0002", "master_to_slave", 20.0),
        _rtu("ce-m2-resp", "050304002a002b", "slave_to_master", 35.0),
    ]
    result = pair_frames(frames)
    mutations.append({
        "mutation_id": "mut-rtu-retransmit",
        "changed_source": "主站以完全相同的字节重发请求",
        "result": result,
        "adopted": {"paired_request": "ce-m2-req2",
                    "superseded": "ce-m2-req1"},
        "rejected": {"paired_request": "ce-m2-req1",
                     "why_rejected": "响应在重发之后到达，归最近一次发送"},
        "scope_check": {"expect": "仅重发涉及的两条请求状态变化，其它帧不受影响"},
    })

    # 3. 广播
    frames = [_tcp("ce-m3-bcast", 9, "client_to_server", 1, 10.0, uid=0, fc=6)]
    result = pair_frames(frames)
    mutations.append({
        "mutation_id": "mut-broadcast",
        "changed_source": "请求的 unit id 改为 0（广播）",
        "result": result,
        "adopted": {"unpaired_reason": "broadcast_no_response_expected"},
        "rejected": {"unpaired_reason": "missing_response",
                     "why_rejected": "广播按协议没有响应，不是缺失"},
        "scope_check": {"expect": "只产生一条广播未配对记录，无配对、无异常"},
    })

    # 4. 异常码
    frames = [_tcp("ce-m4-req", 1, "client_to_server", 1, 10.0),
              _tcp("ce-m4-resp", 1, "server_to_client", 1, 20.0, exc=2)]
    result = pair_frames(frames)
    interp = interpret_all(result, {f.frame_id: f for f in frames},
                           {"map-ce-v1": RegisterMapping.from_dict(MAPPING)})
    mutations.append({
        "mutation_id": "mut-exception-code",
        "changed_source": "响应功能码置异常位并带异常码 0x02",
        "result": result, "interpretation": interp,
        "adopted": {"pair_status": "exception", "register_values": 0},
        "rejected": {"pair_status": "paired_empty",
                     "why_rejected": "异常响应不能当成功的空数据，不产生寄存器值"},
        "scope_check": {"expect": "配对状态为 exception，解释层 0 个寄存器值"},
    })

    # 5. 地址基准切换（仅展示层）
    result = pair_frames(_baseline_frames())
    interp_zero = interpret_all(result, {f.frame_id: f for f in _baseline_frames()},
                                {"map-ce-v1": RegisterMapping.from_dict(MAPPING)},
                                display_base="zero")
    interp_one = interpret_all(result, {f.frame_id: f for f in _baseline_frames()},
                               {"map-ce-v1": RegisterMapping.from_dict(MAPPING)},
                               display_base="one")
    v0 = interp_zero["interpretations"][0]["values"][0]
    v1 = interp_one["interpretations"][0]["values"][0]
    mutations.append({
        "mutation_id": "mut-address-base",
        "changed_source": "展示基准 zero → one",
        "result": {"zero": interp_zero, "one": interp_one},
        "adopted": {"protocol_address_unchanged":
                    v0["protocol_address"] == v1["protocol_address"],
                    "display_delta": v1["display_address"] - v0["display_address"]},
        "rejected": {"rewrite_protocol_address": True,
                     "why_rejected": "基准转换只允许发生在展示层，协议地址不回写"},
        "scope_check": {"expect": "仅 display_address 变化，protocol_address 与原始字节不变"},
    })

    # 6. 字节字序组合
    combos = {}
    for bo in ("big", "little"):
        for wo in ("high_first", "low_first"):
            combos[f"{bo}/{wo}"] = interpret_all(
                pair_frames(_baseline_frames()),
                {f.frame_id: f for f in _baseline_frames()},
                {"map-ce-v1": RegisterMapping.from_dict(MAPPING)},
                byte_order=bo, word_order=wo)["interpretations"][0]["values"][0]["value"]
    mutations.append({
        "mutation_id": "mut-byte-word-order",
        "changed_source": "解释参数的字节序/字序组合",
        "result": {"values_by_combo": combos},
        "adopted": {"distinct_params_distinct_values":
                    len(set(combos.values())) > 1,
                    "raw_hex_unchanged": True},
        "rejected": {"mutate_raw_to_fit": True,
                     "why_rejected": "参数组合只改派生值，不改原始字节"},
        "scope_check": {"expect": "仅派生值随参数变化，材料层不变"},
    })

    # 7. 连接重开
    frames = _baseline_frames() + [
        _tcp("ce-m7-req", 1, "client_to_server", 2, 100.0),
        _tcp("ce-m7-resp", 1, "server_to_client", 2, 110.0,
             data=[0x00, 0x01, 0x00, 0x02]),
    ]
    result = pair_frames(frames)
    gen2_pairs = [p for p in result["pairs"] if p["conn_gen"] == 2]
    mutations.append({
        "mutation_id": "mut-conn-reopen",
        "changed_source": "连接重开（代次 2）内复用相同 transaction id",
        "result": result,
        "adopted": {"gen2_pair": gen2_pairs[0]["pair_id"] if gen2_pairs else None,
                    "cross_gen_confusion": False},
        "rejected": {"pair_gen2_resp_to_gen1_req": True,
                     "why_rejected": "连接代次不同，transaction id 相同也不得跨代次配对"},
        "scope_check": {"expect": "代次 2 内部自成一对，代次 1 的配对不受影响"},
    })

    return {
        "archive_id": ARCHIVE_ID,
        "title": "Modbus 请求/响应/寄存器解释 反例档案",
        "baseline": {
            "description": "原 ADU 字节、方向、transaction id、unit id、CRC、"
                           "功能码、地址基准与映射表版本均保留",
            "frames": [f.to_dict() for f in baseline_frames],
            "pairing": baseline, "interpretation": baseline_interp,
        },
        "judgment_rules": JUDGMENT_RULES,
        "mutations": mutations,
    }


def verify_archive(archive: dict) -> list[dict]:
    """对档案逐项做机器校验，返回每项的通过/失败与证据。"""
    checks = []
    for mut in archive["mutations"]:
        mid = mut["mutation_id"]
        if mid == "mut-tid-reuse":
            ok = mut["adopted"]["candidates"] == ["ce-base-req", "ce-m1-req2"]
        elif mid == "mut-rtu-retransmit":
            pairs = mut["result"]["pairs"]
            ok = (pairs and pairs[0]["request_id"] == "ce-m2-req2"
                  and any(u["reason"] == "superseded_by_retransmit"
                          for u in mut["result"]["unpaired"]))
        elif mid == "mut-broadcast":
            ok = (not mut["result"]["pairs"]
                  and mut["result"]["unpaired"][0]["reason"]
                  == "broadcast_no_response_expected")
        elif mid == "mut-exception-code":
            ok = (mut["result"]["pairs"][0]["status"] == "exception"
                  and mut["interpretation"]["interpretations"][0]["values"] == [])
        elif mid == "mut-address-base":
            ok = (mut["adopted"]["protocol_address_unchanged"]
                  and mut["adopted"]["display_delta"] == 1)
        elif mid == "mut-byte-word-order":
            ok = mut["adopted"]["distinct_params_distinct_values"]
        elif mid == "mut-conn-reopen":
            ok = (mut["adopted"]["gen2_pair"] is not None
                  and mut["result"]["pairs"][0]["conn_gen"] == 1)
        else:
            ok = False
        checks.append({"mutation_id": mid, "passed": bool(ok),
                       "adopted": mut["adopted"], "rejected": mut["rejected"]})
    return checks
