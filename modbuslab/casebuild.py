"""离线案例包构建器：寄存器轨迹室专用材料（非通用表格）。

产物全部确定性（无墙钟、无随机数），覆盖：
主叙事 TCP 与 RTU 轨迹、连接/串口事件、两个映射版本，
以及反例档案基线 + 7 类单点直接来源改动。
单位/坐标基准随材料携带；原始十六进制 ADU 原样保留。
"""
from __future__ import annotations

import json
from pathlib import Path

from .codec import append_crc

ROOT = Path(__file__).resolve().parent.parent / "modbuslab" / "casepack"


def tcp_adu(xid: int, unit: int, pdu: bytes) -> str:
    body = bytes([unit]) + pdu
    return (xid.to_bytes(2, "big") + b"\x00\x00" + (len(body)).to_bytes(2, "big") + body).hex()


def rtu_adu(unit: int, pdu: bytes, *, bad_crc: bool = False) -> str:
    out = append_crc(bytes([unit]) + pdu)
    if bad_crc:
        out = out[:-2] + bytes([out[-2] ^ 0xFF, out[-1]])
    return out.hex()


def rd(unit: int, fc: int, addr: int, qty: int, xid: int) -> str:
    return tcp_adu(xid, unit, bytes([fc]) + addr.to_bytes(2, "big") + qty.to_bytes(2, "big"))


def wr(unit: int, fc: int, addr: int, value: int, xid: int) -> str:
    return tcp_adu(xid, unit, bytes([fc]) + addr.to_bytes(2, "big") + value.to_bytes(2, "big"))


def rd_resp(unit: int, fc: int, data: bytes, xid: int, exc: int | None = None) -> str:
    pdu = bytes([fc | 0x80, exc]) if exc is not None else bytes([fc, len(data)]) + data
    return tcp_adu(xid, unit, pdu)


def w(text: str, **kw) -> str:
    return json.dumps({"kind": "frame", **kw}, ensure_ascii=False)


def main_tcp() -> list[str]:
    L: list[str] = []
    t = 0
    L.append(json.dumps({"kind": "connection", "action": "open", "t_ms": t - 5,
                         "channel": "line-A"}))
    # 1) 正常读保持寄存器（40010 起，6 字）-> 映射 temperature/flow
    L.append(w("r1", transport="tcp", dir="out", t_ms=t, channel="line-A",
               adu=rd(17, 3, 9, 6, xid=100), note="主叙事#1 正常读"))
    data = (0x00E1).to_bytes(2, "big") + bytes.fromhex("41C80000") + (0x0063).to_bytes(2, "big") + (0x00C8).to_bytes(2, "big")
    L.append(w("r1", transport="tcp", dir="in", t_ms=t + 12, channel="line-A",
               adu=rd_resp(17, 3, data, xid=100)))
    # 2) 异常响应 0x02 非法地址（不是空数据）
    t = 40
    L.append(w("r2", transport="tcp", dir="out", t_ms=t, channel="line-A",
               adu=rd(17, 3, 2000, 4, xid=101), note="触发异常码"))
    L.append(w("r2", transport="tcp", dir="in", t_ms=t + 9, channel="line-A",
               adu=rd_resp(17, 3, b"", xid=101, exc=2)))
    # 3) 单写（FC6）+ 完成后的 transaction id 复用：合法
    t = 90
    L.append(w("r3", transport="tcp", dir="out", t_ms=t, channel="line-A",
               adu=wr(17, 6, 9, 0x00E2, xid=102)))
    L.append(w("r3", transport="tcp", dir="in", t_ms=t + 8, channel="line-A",
               adu=wr(17, 6, 9, 0x00E2, xid=102)))
    t = 130
    L.append(w("r4", transport="tcp", dir="out", t_ms=t, channel="line-A",
               adu=rd(17, 3, 9, 2, xid=102), note="事务完成后复用 xid=102：合法"))
    d2 = (0x00E3).to_bytes(2, "big") + (0x0001).to_bytes(2, "big")
    L.append(w("r4", transport="tcp", dir="in", t_ms=t + 7, channel="line-A",
               adu=rd_resp(17, 3, d2, xid=102)))
    # 4) xid 在途复用：两个待处理请求同 xid/unit -> 保留候选
    t = 180
    L.append(w("r5", transport="tcp", dir="out", t_ms=t, channel="line-A",
               adu=rd(17, 3, 9, 1, xid=103), note="xid 在途复用候选 A"))
    L.append(w("r5", transport="tcp", dir="out", t_ms=t + 2, channel="line-A",
               adu=rd(17, 3, 11, 1, xid=103), note="xid 在途复用候选 B"))
    L.append(w("r5", transport="tcp", dir="in", t_ms=t + 20, channel="line-A",
               adu=rd_resp(17, 3, (0x00E4).to_bytes(2, "big"), xid=103),
               note="无法唯一配对，保留两个合法候选"))
    # 5) 单元不符
    t = 230
    L.append(w("r6", transport="tcp", dir="in", t_ms=t, channel="line-A",
               adu=rd_resp(24, 3, (0x0001).to_bytes(2, "big"), xid=999),
               note="unit 不符且无待处理事务"))
    # 6) 广播写不应有响应
    t = 260
    L.append(w("r7", transport="tcp", dir="out", t_ms=t, channel="line-A",
               adu=wr(0, 6, 9, 0x0100, xid=104), note="TCP 广播，无响应"))
    L.append(json.dumps({"kind": "connection", "action": "close", "t_ms": 300,
                         "channel": "line-A"}))
    # 7) 连接重开：xid 重新从 100 开始，必须按代次隔离
    L.append(json.dumps({"kind": "connection", "action": "open", "t_ms": 320,
                         "channel": "line-A"}))
    L.append(w("r8", transport="tcp", dir="out", t_ms=330, channel="line-A",
               adu=rd(17, 3, 9, 1, xid=100), note="重连后 xid 复用，按新代次配对"))
    L.append(w("r8", transport="tcp", dir="in", t_ms=338, channel="line-A",
               adu=rd_resp(17, 3, (0x00E5).to_bytes(2, "big"), xid=100)))
    return L


def rtu_req(unit: int, fc: int, addr: int, qty: int) -> str:
    return rtu_adu(unit, bytes([fc]) + addr.to_bytes(2, "big") + qty.to_bytes(2, "big"))


def rtu_resp(unit: int, fc: int, data: bytes = b"", exc: int | None = None,
             bad_crc: bool = False) -> str:
    pdu = bytes([fc | 0x80, exc]) if exc is not None else bytes([fc, len(data)]) + data
    return rtu_adu(unit, pdu, bad_crc=bad_crc)


def rtu_w1(unit: int, addr: int, value: int) -> str:
    return rtu_adu(unit, bytes([6]) + addr.to_bytes(2, "big") + value.to_bytes(2, "big"))


def rtu_w1_resp(unit: int, addr: int, value: int) -> str:
    return rtu_adu(unit, bytes([6]) + addr.to_bytes(2, "big") + value.to_bytes(2, "big"))


def main_rtu() -> list[str]:
    L: list[str] = []
    L.append(json.dumps({"kind": "serial", "action": "bus_acquire", "t_ms": -5,
                         "channel": "rs485-1", "detail": {"baud": 19200, "databits": 8,
                                                          "parity": "none", "stopbits": 1}}))
    t = 0
    # 正常读 + 静默窗口内一次重传，共享响应
    L.append(w("s1", transport="rtu", dir="out", t_ms=t, channel="rs485-1",
               adu=rtu_req(3, 3, 19, 1), note="RTU 首请求"))
    L.append(w("s1", transport="rtu", dir="out", t_ms=t + 1.0, channel="rs485-1",
               adu=rtu_req(3, 3, 19, 1), note="静默窗口内重传"))
    L.append(w("s1", transport="rtu", dir="in", t_ms=t + 2.0, channel="rs485-1",
               adu=rtu_resp(3, 3, (0x007B).to_bytes(2, "big"))))
    # 广播（unit 0），无响应；后面紧跟非法广播应答
    t = 30
    L.append(w("s2", transport="rtu", dir="out", t_ms=t, channel="rs485-1",
               adu=rtu_w1(0, 19, 0x0001), note="RTU 广播写，无响应"))
    L.append(w("s2", transport="rtu", dir="in", t_ms=t + 1.2, channel="rs485-1",
               adu=rtu_w1_resp(0, 19, 0x0001), note="非法广播应答"))
    # 异常码 0x03
    t = 70
    L.append(w("s3", transport="rtu", dir="out", t_ms=t, channel="rs485-1",
               adu=rtu_req(3, 3, 500, 2), note="触发非法数据值"))
    L.append(w("s3", transport="rtu", dir="in", t_ms=t + 2.0, channel="rs485-1",
               adu=rtu_resp(3, 3, exc=3)))
    # 请求后超过静默窗口且无响应 -> 超时未配对
    t = 120
    L.append(w("s4", transport="rtu", dir="out", t_ms=t, channel="rs485-1",
               adu=rtu_req(5, 4, 0, 2), note="设备掉线，超时"))
    L.append(json.dumps({"kind": "serial", "action": "bus_release", "t_ms": 260,
                         "channel": "rs485-1"}))
    L.append(json.dumps({"kind": "serial", "action": "bus_acquire", "t_ms": 300,
                         "channel": "rs485-1", "detail": {"reason": "重开总线"}}))
    # 重开后正常事务
    L.append(w("s5", transport="rtu", dir="out", t_ms=310, channel="rs485-1",
               adu=rtu_req(3, 3, 19, 1)))
    L.append(w("s5", transport="rtu", dir="in", t_ms=312, channel="rs485-1",
               adu=rtu_resp(3, 3, (0x007C).to_bytes(2, "big"))))
    # CRC 损坏响应：保留原字节，不配对
    t = 350
    L.append(w("s6", transport="rtu", dir="out", t_ms=t, channel="rs485-1",
               adu=rtu_req(3, 3, 20, 1)))
    L.append(w("s6", transport="rtu", dir="in", t_ms=t + 2, channel="rs485-1",
               adu=rtu_resp(3, 3, (0x0001).to_bytes(2, "big"), bad_crc=True),
               note="CRC 损坏"))
    # 孤立响应（无请求）
    t = 400
    L.append(w("s7", transport="rtu", dir="in", t_ms=t, channel="rs485-1",
               adu=rtu_resp(8, 3, (0x0002).to_bytes(2, "big")), note="孤立响应"))
    return L


def mappings_v1() -> dict:
    return {
        "version": "map-v1", "address_base": 0,
        "unit_note": "温度=0.1°C/LSB；流量=32bit float L/min；阀门=%；状态无单位",
        "entries": [
            {"name": "temp_c", "space": 3, "address": 9, "dtype": "u16",
             "scale": 0.1, "offset": 0, "unit": "degC",
             "valid_min": -40, "valid_max": 125},
            {"name": "flow_lmin", "space": 3, "address": 10, "dtype": "f32",
             "scale": 1, "offset": 0, "unit": "L/min", "word_order": "big_swapped",
             "valid_min": 0, "valid_max": 100},
            {"name": "valve_pct", "space": 3, "address": 12, "dtype": "u16",
             "scale": 1, "offset": 0, "unit": "%",
             "valid_min": 0, "valid_max": 100},
            {"name": "status", "space": 3, "address": 13, "dtype": "u16",
             "scale": 1, "offset": 0, "unit": ""},
            {"name": "pressure_rtu", "space": 3, "address": 19, "dtype": "u16",
             "scale": 0.01, "offset": 0, "unit": "bar",
             "valid_min": 0, "valid_max": 25},
        ],
    }


def mappings_v2() -> dict:
    """参数修订：同一设备表改用一基文档地址（仅展示层差异），并给出流量的工程区间。"""
    m = mappings_v1()
    m = json.loads(json.dumps(m, ensure_ascii=False))
    m["version"] = "map-v2"
    m["address_base"] = 1
    for e in m["entries"]:
        e["address"] = e["address"] + 1
    return m


# ---------- 反例档案：独立小基线 ----------

def ce_baseline() -> dict:
    """基线保留：原 ADU、方向、xid、unit、CRC、fc、地址基准、映射版本。"""
    tcp: list[str] = []
    tcp.append(json.dumps({"kind": "connection", "action": "open", "t_ms": -5,
                           "channel": "ce-line"}))
    # 1) 先完成一次 xid=1002 读（2 字，覆盖 f32 ce_rpm @0..1）
    tcp.append(w("ce", transport="tcp", dir="out", t_ms=0, channel="ce-line",
                 adu=rd(2, 3, 0, 2, xid=1002), note="基线 首读 f32"))
    tcp.append(w("ce", transport="tcp", dir="in", t_ms=10, channel="ce-line",
                 adu=rd_resp(2, 3, bytes.fromhex("41C80000"), xid=1002)))
    # 2) xid=1003 在途复用：两个待处理请求，一个响应无法唯一配对
    tcp.append(w("ce", transport="tcp", dir="out", t_ms=30, channel="ce-line",
                 adu=rd(2, 3, 0, 1, xid=1003), note="在途复用候选 A"))
    tcp.append(w("ce", transport="tcp", dir="out", t_ms=31, channel="ce-line",
                 adu=rd(2, 3, 1, 1, xid=1003), note="在途复用候选 B"))
    tcp.append(w("ce", transport="tcp", dir="in", t_ms=42, channel="ce-line",
                 adu=rd_resp(2, 3, (0x0022).to_bytes(2, "big"), xid=1003),
                 note="基线 无法唯一配对，保留两个合法候选"))
    # 3) 连接重开
    tcp.append(json.dumps({"kind": "connection", "action": "close", "t_ms": 80,
                           "channel": "ce-line"}))
    tcp.append(json.dumps({"kind": "connection", "action": "open", "t_ms": 90,
                           "channel": "ce-line"}))
    tcp.append(w("ce", transport="tcp", dir="out", t_ms=95, channel="ce-line",
                 adu=rd(2, 3, 0, 1, xid=1002), note="重连后复用 1002"))
    tcp.append(w("ce", transport="tcp", dir="in", t_ms=103, channel="ce-line",
                 adu=rd_resp(2, 3, (0x0033).to_bytes(2, "big"), xid=1002)))

    rtu: list[str] = []
    rtu.append(json.dumps({"kind": "serial", "action": "bus_acquire", "t_ms": -5,
                           "channel": "ce-bus", "detail": {"baud": 19200}}))
    rtu.append(w("ce", transport="rtu", dir="out", t_ms=0, channel="ce-bus",
                 adu=rtu_req(4, 3, 0, 1)))
    rtu.append(w("ce", transport="rtu", dir="out", t_ms=1.0, channel="ce-bus",
                 adu=rtu_req(4, 3, 0, 1), note="窗口内重传"))
    rtu.append(w("ce", transport="rtu", dir="in", t_ms=2.0, channel="ce-bus",
                 adu=rtu_resp(4, 3, (0x0044).to_bytes(2, "big"))))
    rtu.append(w("ce", transport="rtu", dir="out", t_ms=40, channel="ce-bus",
                 adu=rtu_w1(0, 0, 0xFF00), note="广播写"))
    rtu.append(w("ce", transport="rtu", dir="in", t_ms=41.2, channel="ce-bus",
                 adu=rtu_w1_resp(0, 19, 0x0001), note="非法广播应答"))
    rtu.append(w("ce", transport="rtu", dir="out", t_ms=80, channel="ce-bus",
                 adu=rtu_req(4, 3, 900, 1), note="异常请求"))
    rtu.append(w("ce", transport="rtu", dir="in", t_ms=82, channel="ce-bus",
                 adu=rtu_resp(4, 3, exc=2)))

    mapping = {
        "version": "ce-map-v1", "address_base": 0,
        "unit_note": "反例基线映射（零基）；ce_rpm 为 32 位转速 rpm",
        "entries": [
            {"name": "ce_rpm", "space": 3, "address": 0, "dtype": "f32",
             "word_order": "big", "unit": "rpm", "valid_min": 0, "valid_max": 100},
            {"name": "ce_r2", "space": 3, "address": 2, "dtype": "u16",
             "unit": "-", "valid_min": 0, "valid_max": 60000},
            {"name": "ce_r3", "space": 3, "address": 3, "dtype": "u16",
             "unit": "-", "valid_min": 0, "valid_max": 60000},
        ],
    }
    return {"tcp": tcp, "rtu": rtu, "mapping": mapping}


CE_MUTATIONS = [
    {"id": "xid_reuse", "label": "transaction id 复用",
     "expect": "在途复用产生全部合法候选，不静默配对；完成后复用仍唯一配对"},
    {"id": "rtu_retransmit", "label": "RTU 重传",
     "expect": "静默窗口内重传共享首个响应，超出窗口成为独立超时/新事务"},
    {"id": "broadcast", "label": "广播",
     "expect": "unit=0 写请求不期待响应，出现的应答记为非法"},
    {"id": "exception_code", "label": "异常码",
     "expect": "异常响应是配对成功的失败，不产生寄存器值，不当成空数据成功"},
    {"id": "address_base", "label": "地址基准切换",
     "expect": "只改变展示层一基/零基表示，派生匹配身份不变"},
    {"id": "word_order", "label": "字节字序组合",
     "expect": "仅依赖该 32 位条目的派生值改变，其它对象身份不变"},
    {"id": "conn_reopen", "label": "连接重开",
     "expect": "重开后按新代次隔离，xid 重新计数不与上代次匹配"},
]


def apply_mutation(base: dict, mutation_id: str) -> dict:
    """每个反例只改动一个直接来源；其余材料逐字、顺序不变。"""
    import copy
    m = copy.deepcopy(base)
    if mutation_id == "xid_reuse":
        # 直接来源：在途的第一个 xid=1003 请求(索引3)移到响应(索引5)之后，
        # 则响应到达时只有候选 B 在途 -> 唯一配对；A 最终无响应
        rec_a = json.loads(m["tcp"].pop(3))
        rec_a["t_ms"] = 50
        rec_a["note"] = "改动后：候选 A 改到响应之后，不再在途，最终无响应"
        m["tcp"].insert(5, json.dumps(rec_a, ensure_ascii=False))
        rec_r = json.loads(m["tcp"][4])
        rec_r["note"] = "改动后：xid=1003 仅 B 在途，唯一配对"
        m["tcp"][4] = json.dumps(rec_r, ensure_ascii=False)
    elif mutation_id == "rtu_retransmit":
        dup = json.loads(m["rtu"][1])
        dup["t_ms"] = 60.0
        dup["note"] = "改动后：超出静默窗口，成为独立请求并超时"
        m["rtu"][1] = json.dumps(dup, ensure_ascii=False)
    elif mutation_id == "broadcast":
        # 直接来源：广播写的 unit 由 0 改为 4，并补充它应得的单写回显响应
        rec = json.loads(m["rtu"][3])
        rec["adu"] = rtu_w1(4, 0, 0xFF00)
        rec["t_ms"] = 90.0
        rec["note"] = "改动后：unit 0->4，不再是广播（单写期待回显）"
        m["rtu"][3] = json.dumps(rec, ensure_ascii=False)
        illegal = json.loads(m["rtu"][4])
        m["rtu"][4] = json.dumps(
            {"kind": "frame", "transport": "rtu", "dir": "in", "t_ms": 92.0,
             "channel": "ce-bus", "adu": rtu_w1_resp(4, 0, 0xFF00),
             "note": "改动后：unit 4 单写的正常回显响应"}, ensure_ascii=False)
        del illegal
    elif mutation_id == "exception_code":
        rec = json.loads(m["rtu"][7])
        rec["adu"] = rtu_resp(4, 3, (0x0001).to_bytes(2, "big"))
        rec["note"] = "改动后：异常响应变为正常 1 字响应（地址 900 无映射，留诊断）"
        m["rtu"][7] = json.dumps(rec, ensure_ascii=False)
    elif mutation_id == "address_base":
        m["mapping"]["address_base"] = 1
        for e in m["mapping"]["entries"]:
            e["address"] = e["address"] + 1
    elif mutation_id == "word_order":
        for e in m["mapping"]["entries"]:
            if e["name"] == "ce_rpm":
                e["word_order"] = "big_swapped"
    elif mutation_id == "conn_reopen":
        # 直接来源：去掉 close/open（两代次合并为一代次），其余帧不动
        m["tcp"][5] = json.dumps({"kind": "connection", "action": "open", "t_ms": 80,
                                  "channel": "ce-line", "_removed_marker": True})
        m["tcp"][6] = json.dumps({"kind": "connection", "action": "open", "t_ms": 90,
                                  "channel": "ce-line", "_duplicate_open": True})
    else:
        raise KeyError(mutation_id)
    return m


def build(out_dir: Path | None = None) -> Path:
    out_dir = out_dir or ROOT
    (out_dir / "traces").mkdir(parents=True, exist_ok=True)
    (out_dir / "connections").mkdir(exist_ok=True)
    (out_dir / "serial").mkdir(exist_ok=True)
    (out_dir / "mappings").mkdir(exist_ok=True)
    (out_dir / "archive").mkdir(exist_ok=True)

    (out_dir / "traces" / "line-a.tcp.jsonl").write_text("\n".join(main_tcp()), encoding="utf-8")
    (out_dir / "traces" / "rs485-1.rtu.jsonl").write_text("\n".join(main_rtu()), encoding="utf-8")
    (out_dir / "mappings" / "device-map-v1.json").write_text(
        json.dumps(mappings_v1(), ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "mappings" / "device-map-v2.json").write_text(
        json.dumps(mappings_v2(), ensure_ascii=False, indent=2), encoding="utf-8")

    base = ce_baseline()
    (out_dir / "archive" / "baseline.tcp.jsonl").write_text("\n".join(base["tcp"]), encoding="utf-8")
    (out_dir / "archive" / "baseline.rtu.jsonl").write_text("\n".join(base["rtu"]), encoding="utf-8")
    (out_dir / "archive" / "baseline.map.json").write_text(
        json.dumps(base["mapping"], ensure_ascii=False, indent=2), encoding="utf-8")
    for mut in CE_MUTATIONS:
        mm = apply_mutation(base, mut["id"])
        d = out_dir / "archive" / mut["id"]
        d.mkdir(exist_ok=True)
        (d / "trace.tcp.jsonl").write_text("\n".join(mm["tcp"]), encoding="utf-8")
        (d / "trace.rtu.jsonl").write_text("\n".join(mm["rtu"]), encoding="utf-8")
        (d / "map.json").write_text(json.dumps(mm["mapping"], ensure_ascii=False, indent=2),
                                    encoding="utf-8")
    manifest = {
        "title": "寄存器轨迹室：Modbus 请求配对、地址模型与设备代次",
        "narrative": [
            "工业协议小组导入 Modbus TCP(line-A) 与 RTU(rs485-1) 轨迹、设备映射版本与串口事件",
            "先核对原 ADU/方向/xid/unit/CRC/功能码/地址基准/映射版本均保留",
            "再触发 xid 复用、RTU 重传、广播、异常码、地址基准切换、字节字序、连接重开",
            "第二分支检验 TCP xid 与 RTU 静默间隔两套配对规则",
        ],
        "files": ["traces/line-a.tcp.jsonl", "traces/rs485-1.rtu.jsonl",
                   "mappings/device-map-v1.json", "mappings/device-map-v2.json"],
        "archive": [{"id": m["id"], "label": m["label"], "expect": m["expect"]}
                    for m in CE_MUTATIONS],
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_dir


if __name__ == "__main__":
    p = build()
    print("casepack built at", p)
