"""寄存器值解释（派生层）。

- 原始 ADU / PDU 表示不变；这里只生成带父级依赖的派生值；
- 地址：协议与材料始终为零基；address_base=1 的映射表在匹配前归一化，
  展示层再按所选基准显示；
- 32 位量支持 ABCD/CDAB/BADC/DCBA 字节字序组合（NumPy 向量化）；
- 无法转换（跨区间、字节不足、超有效区间、映射缺失）的值留在原位并附诊断，
  异常响应永远不会变成“成功的空数据”。
"""
from __future__ import annotations

import numpy as np

from .ids import digest

WORD_ORDERS = ("big", "little", "big_swapped", "little_swapped")
ORDER_TO_ABCD = {
    "big": "ABCD",            # 大端字、大端字节
    "little": "DCBA",
    "big_swapped": "CDAB",    # 字交换
    "little_swapped": "BADC",
}

_DT = {"u16": ("u2", None), "i16": ("i2", None),
       "u32": ("u4", None), "i32": ("i4", None), "f32": ("f4", None)}
_WIDTH = {"u16": 1, "i16": 1, "u32": 2, "i32": 2, "f32": 2, "bool": 1}


def normalize_mapping(entries: list[dict]) -> list[dict]:
    """把映射表自身的地址基准归一为零基，原表示保留在 raw_* 字段。"""
    out = []
    for e in entries:
        shift = 1 if e["address_base"] == 1 else 0
        out.append({**e, "zero_address": e["address"] - shift,
                    "raw_address_base": e["address_base"],
                    "raw_address": e["address"]})
    return out


def _assemble32(pairs: np.ndarray, order: str) -> np.ndarray:
    # pairs: (n,2) big-endian 寄存器字
    hi, lo = pairs[:, 0].astype(np.uint32), pairs[:, 1].astype(np.uint32)
    # 寄存器字按内存顺序 [w0,w1]；word_order 决定 32 位字装配
    if order == "big":              # ABCD: 高字在前
        word_swap, swap = False, False
    elif order == "big_swapped":    # CDAB: 低字在前
        word_swap, swap = True, False
    elif order == "little":         # DCBA: 低字在前且字节逆序
        word_swap, swap = True, True
    else:                           # little_swapped BADC: 高字在前且字节逆序
        word_swap, swap = False, True
    val = ((lo << 16) | hi) if word_swap else ((hi << 16) | lo)
    if swap:
        val = (((val & 0xFF) << 24) | (((val >> 8) & 0xFF) << 16)
               | (((val >> 16) & 0xFF) << 8) | ((val >> 24) & 0xFF))
    return val


def _coerce(raw: np.ndarray, dtype: str) -> np.ndarray:
    if dtype in ("u16", "i16"):
        return raw.astype(">u2").view(_DT[dtype][0].replace("u2", "u2").replace("i2", "i2"))
    return raw


def interpret_response(words: list[int], start_zero: int, space: int,
                       mapping: list[dict], params_version: str, rule_version: str,
                       pair_id: str) -> tuple[list[dict], list[dict]]:
    """words 为按零基地址 start_zero.. 排布的寄存器字。"""
    values: list[dict] = []
    diags: list[dict] = []
    norm = normalize_mapping(mapping)
    by_addr = {(e["space"], e["zero_address"]): e for e in norm if e["space"] == space}
    arr = np.asarray(words, dtype=np.int64)

    for addr in range(start_zero, start_zero + len(arr)):
        e = by_addr.get((space, addr))
        if e is None:
            word_idx = addr - start_zero
            diags.append(_diag(pair_id, "UNMAPPED_ADDRESS", addr,
                               f"零基地址 {addr} 在映射版本中无条目，原始字 0x{arr[word_idx]:04X} 保留",
                               word=words[word_idx], params_version=params_version))
            continue
        width = _WIDTH.get(e["dtype"], 1)
        word_idx = addr - start_zero
        if width == 2 and word_idx + 1 >= len(arr):
            diags.append(_diag(pair_id, "INCOMPLETE_SPAN", addr,
                               f"{e['name']} 需 2 字，响应在地址 {addr} 截断；已读字保留",
                               word=words[word_idx], params_version=params_version,
                               mapping_id=e["id"]))
            continue
        if width == 1:
            raw_u = int(arr[word_idx])
            if e["dtype"] == "u16":
                raw_val = raw_u
            else:
                raw_val = raw_u - 0x10000 if raw_u >= 0x8000 else raw_u
            raw_words = [raw_u]
        else:
            pair = arr[word_idx:word_idx + 2].astype(np.uint32)
            raw_u32 = int(_assemble32(pair.reshape(1, 2), e["word_order"])[0])
            if e["dtype"] == "u32":
                raw_val = raw_u32
            elif e["dtype"] == "i32":
                raw_val = raw_u32 - 0x100000000 if raw_u32 >= 0x80000000 else raw_u32
            else:
                raw_val = float(np.array([raw_u32], dtype=">u4").view(">f4")[0])
            raw_words = [int(pair[0]), int(pair[1])]
        eng = raw_val * float(e["scale"]) + float(e["offset"])
        status = "ok"
        if e.get("valid_min") is not None and eng < e["valid_min"]:
            status = "out_of_range"
        if e.get("valid_max") is not None and eng > e["valid_max"]:
            status = "out_of_range"
        values.append({
            "id": digest("val", {"pair": pair_id, "mapentry": e["id"],
                                 "words": raw_words, "pv": params_version}),
            "pair_id": pair_id, "mapping_entry_id": e["id"], "name": e["name"],
            "space": space, "start_zero": addr, "width": width,
            "raw_words_hex": "".join(f"{w:04X}" for w in raw_words),
            "raw_value": raw_val if e["dtype"] != "f32" else None,
            "raw_bits_hex": "".join(f"{w:04X}" for w in raw_words),
            "engineering": None if (status != "ok" and e["dtype"] == "f32" and not np.isfinite(eng)) else eng,
            "unit": e["unit"], "scale": e["scale"], "offset": e["offset"],
            "word_order": e["word_order"], "word_order_abcd": ORDER_TO_ABCD[e["word_order"]],
            "dtype": e["dtype"], "status": status,
            "valid_min": e.get("valid_min"), "valid_max": e.get("valid_max"),
            "params_version": params_version, "rule_version": rule_version,
            "raw_address_base": e["raw_address_base"], "raw_address": e["raw_address"],
        })
        if status == "out_of_range":
            diags.append(_diag(pair_id, "OUT_OF_VALID_RANGE", addr,
                               f"{e['name']}={eng}{e['unit']} 超出有效区间 "
                               f"[{e.get('valid_min')},{e.get('valid_max')}]，值保留不丢弃",
                               value_id=values[-1]["id"], params_version=params_version,
                               mapping_id=e["id"]))
    return values, diags


def _diag(pair_id: str, code: str, addr: int, message: str, **extra) -> dict:
    return {"id": digest("dval", {"pair": pair_id, "code": code, "addr": addr,
                                  "extra": {k: v for k, v in extra.items()
                                            if v is not None}}),
            "pair_id": pair_id, "code": code, "address_zero": addr, "message": message,
            **{k: v for k, v in extra.items() if v is not None}}


def response_words(frame: dict) -> tuple[int | None, list[int]]:
    """读响应本身不含起始地址；地址来自对应请求。"""
    if not frame.get("values_hex"):
        return None, []
    data = bytes.fromhex(frame["values_hex"])
    words = [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2)]
    return frame.get("address"), words
