"""寄存器解释层。

- 原始字（raw words）永远保留；规范化值 = raw * scale，带单位与坐标基准。
- 零基/一基地址只在展示层转换：canonical_address 恒为线上 0 基地址，
  display_address 按映射表 address_base 换算。
- 异常响应不能当成功的空数据：exception 配对只产生 skipped 记录，不产生读数。
- 无法转换的值（未知字节序/字序）留在原位置并附 semantic_unsolvable 诊断。
- 超出有效区间的值保留但标记 out_of_range，并给出失效原因。
"""
from __future__ import annotations

from typing import Optional

import numpy as np

from .domain import Diagnostic, SEMANTIC_UNSOLVABLE, FORMAT_CORRUPT, digest, parse_request_pdu

BYTE_ORDERS = ("AB", "BA")
WORD_ORDERS = ("ABCD", "CDAB", "BADC", "DCBA")

TIME_BASIS = "capture-tick/会话相对单调时钟"
COORD_BASIS = "register/0-based-wire-canonical"


def decode_u16_words(data: bytes, byte_order: str) -> np.ndarray:
    arr = np.frombuffer(data, dtype=">u2")
    if byte_order == "AB":
        return arr
    if byte_order == "BA":
        return arr.byteswap()
    raise ValueError(f"unknown byte_order {byte_order!r}")


def permute32(data: bytes, byte_order: str, word_order: str) -> bytes:
    """先按 byte_order 做字内字节交换，再按 word_order 做 4 字节排列。"""
    if byte_order not in BYTE_ORDERS:
        raise ValueError(f"unknown byte_order {byte_order!r}")
    if word_order not in WORD_ORDERS:
        raise ValueError(f"unknown word_order {word_order!r}")
    w0, w1 = data[0:2], data[2:4]
    if byte_order == "BA":
        w0, w1 = w0[::-1], w1[::-1]
    b = w0 + w1
    if word_order == "ABCD":
        return b
    if word_order == "CDAB":
        return b[2:4] + b[0:2]
    if word_order == "BADC":
        return b[1:2] + b[0:1] + b[3:4] + b[2:3]
    return b[::-1]  # DCBA


def decode_entry(entry: dict, words: bytes) -> tuple[Optional[float], Optional[float], list[dict]]:
    """返回 (raw_value, value, diagnostics)。无法转换时两者为 None 并附诊断。"""
    bo = entry.get("byte_order", "AB")
    dt = entry["dtype"]
    scale = entry.get("scale", 1)
    if bo not in BYTE_ORDERS:
        return None, None, [Diagnostic(
            SEMANTIC_UNSOLVABLE, f"未知字节序 {bo!r}，无法转换，原始字保留在原位置",
            position=0).to_dict()]
    if dt in ("u16", "i16"):
        raw = int(decode_u16_words(words[:2], bo)[0])
        if dt == "i16" and raw >= 0x8000:
            raw -= 0x10000
        return raw, raw * scale, []
    wo = entry.get("word_order")
    if wo not in WORD_ORDERS:
        return None, None, [Diagnostic(
            SEMANTIC_UNSOLVABLE, f"未知字序 {wo!r}，无法转换，原始字保留在原位置",
            position=0).to_dict()]
    b = permute32(words[:4], bo, wo)
    if dt == "u32":
        raw = int.from_bytes(b, "big")
        return raw, raw * scale, []
    if dt == "f32":
        raw = int.from_bytes(b, "big")
        val = float(np.frombuffer(b, dtype=">f4")[0])
        return raw, val * scale, []
    return None, None, [Diagnostic(
        SEMANTIC_UNSOLVABLE, f"未知数据类型 {dt!r}", position=0).to_dict()]


def _reading_id(pair_id: str, addr: int, mapping_version: str) -> str:
    return "rdg-" + digest({"pair": pair_id, "addr": addr, "map": mapping_version})[:12]


def run_registers(pairs: list[dict], frames_by_id: dict, mapping: Optional[dict],
                  param_version: str) -> dict:
    readings: list[dict] = []
    skipped: list[dict] = []
    entries = {e["address"]: e for e in mapping["entries"]} if mapping else {}
    base = mapping["address_base"] if mapping else 0
    map_version = mapping["version"] if mapping else None

    for pair in pairs:
        if pair["status"] == "exception":
            skipped.append({
                "pair_id": pair["pair_id"],
                "reason": "exception_response_not_data",
                "message": "异常响应不能当成功的空数据：不产生任何寄存器读数",
                "exception_code": pair.get("exception_code"),
            })
            continue
        if pair["status"] not in ("paired", "ambiguous_tid_reuse"):
            continue
        req = frames_by_id.get(pair["request_frame_id"])
        resp = frames_by_id.get(pair["response_frame_id"])
        if not req or not resp:
            continue
        rq = parse_request_pdu(bytes.fromhex(req["parsed"]["pdu_hex"]))
        if not rq or rq["function_code"] not in (3, 4):
            skipped.append({"pair_id": pair["pair_id"], "reason": "unsupported_function",
                            "message": "非保持/输入寄存器读取，不解释寄存器区间"})
            continue
        spdu = bytes.fromhex(resp["parsed"]["pdu_hex"])
        if len(spdu) < 2:
            skipped.append({"pair_id": pair["pair_id"], "reason": FORMAT_CORRUPT,
                            "message": "响应 PDU 过短", "position": len(spdu)})
            continue
        declared = spdu[1]
        data = spdu[2:2 + declared]
        if len(data) != declared:
            skipped.append({"pair_id": pair["pair_id"], "reason": FORMAT_CORRUPT,
                            "message": f"字节计数 {declared} 与实际 {len(data)} 不符",
                            "position": 2 + len(data)})
            continue
        addr0 = rq["address"]
        i = 0
        while i < rq["count"]:
            addr = addr0 + i
            entry = entries.get(addr)
            wide = entry is not None and entry["dtype"] in ("u32", "f32")
            nbytes = 4 if wide else 2
            words = data[2 * i:2 * i + nbytes]
            base_rec = {
                "reading_id": _reading_id(pair["pair_id"], addr, map_version or "none"),
                "pair_id": pair["pair_id"],
                "source_frames": [req["frame_id"], resp["frame_id"]],
                "mapping_version": map_version,
                "canonical_address": addr,
                "address_base": base,
                "display_address": addr + (1 if base == 1 else 0),
                "raw_hex": words.hex(),
                "tick": resp["tick"],
                "time_basis": TIME_BASIS,
                "coordinate_basis": COORD_BASIS,
            }
            if entry is None:
                readings.append({**base_rec, "name": None, "unit": None, "dtype": "u16",
                                 "raw_value": int.from_bytes(words, "big") if len(words) == 2 else None,
                                 "scale": None, "value": None, "valid_range": None,
                                 "invalid_reason": None, "status": "no_mapping",
                                 "diagnostics": [{"kind": "no_mapping",
                                                  "message": "映射表未覆盖该地址，原始字保留",
                                                  "position": 2 * i,
                                                  "frame_id": resp["frame_id"]}]})
                i += 1
                continue
            if len(words) < nbytes:
                readings.append({**base_rec, "name": entry["name"], "unit": entry.get("unit"),
                                 "dtype": entry["dtype"], "raw_value": None, "scale": entry.get("scale"),
                                 "value": None, "valid_range": entry.get("valid_range"),
                                 "invalid_reason": "响应数据不足以覆盖该寄存器",
                                 "status": FORMAT_CORRUPT,
                                 "diagnostics": [{"kind": FORMAT_CORRUPT,
                                                  "message": "响应数据不足以覆盖该寄存器",
                                                  "position": 2 * i,
                                                  "frame_id": resp["frame_id"]}]})
                i += 2 if wide else 1
                continue
            raw, value, diags = decode_entry(entry, words)
            status = "ok"
            invalid_reason = None
            if diags:
                status = SEMANTIC_UNSOLVABLE
                for d in diags:
                    d["frame_id"] = resp["frame_id"]
                    d["position"] = 2 * i
            elif entry.get("valid_range") and value is not None:
                lo, hi = entry["valid_range"]
                if value < lo or value > hi:
                    status = "out_of_range"
                    invalid_reason = entry.get("invalid_reason") or "超出有效区间"
                    diags = [{"kind": "out_of_range",
                              "message": f"值 {value} 超出有效区间 [{lo}, {hi}]：{invalid_reason}",
                              "position": 2 * i, "frame_id": resp["frame_id"]}]
            readings.append({**base_rec, "name": entry["name"], "unit": entry.get("unit"),
                             "dtype": entry["dtype"], "raw_value": raw,
                             "scale": entry.get("scale"), "value": value,
                             "valid_range": entry.get("valid_range"),
                             "invalid_reason": invalid_reason, "status": status,
                             "diagnostics": diags})
            i += 2 if wide else 1

    readings.sort(key=lambda r: (r["tick"], r["canonical_address"], r["reading_id"]))
    return {
        "status": "ok",
        "param_version": param_version,
        "mapping_version": map_version,
        "readings": readings,
        "skipped": skipped,
    }
