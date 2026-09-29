"""离线案例包：寄存器轨迹室 — Modbus 请求配对、地址模型与设备代次。

基线完整保留：原 ADU 字节、连接/总线方向、transaction id、unit id、CRC、
功能码、地址基准与映射表版本。轨迹实际经过：transaction id 复用、RTU 重传、
广播、异常码、地址基准切换、字节字序组合、连接重开。
"""
from __future__ import annotations

from .adu import crc16
from .mapping import encode_f32
from .store import material_id

SESSION = "modbus-review-01"


def _w16(v: int) -> bytes:
    return v.to_bytes(2, "big")


def tcp_adu(tid: int, unit: int, pdu: bytes) -> bytes:
    return (tid.to_bytes(2, "big") + b"\x00\x00"
            + (len(pdu) + 1).to_bytes(2, "big") + bytes([unit]) + pdu)


def rtu_adu(unit: int, pdu: bytes) -> bytes:
    body = bytes([unit]) + pdu
    crc = crc16(body)
    return body + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def read_req(addr: int, qty: int) -> bytes:
    return b"\x03" + _w16(addr) + _w16(qty)


def read_resp(data: bytes) -> bytes:
    return b"\x03" + bytes([len(data)]) + data


def exc_resp(code: int) -> bytes:
    return b"\x83" + bytes([code])


PRESSURE_KPA = 101.325   # CDAB + big
FLOW_LMIN = 12.5         # ABCD + little

DATA_BLOCK_A = _w16(253) + _w16(261) + encode_f32(PRESSURE_KPA, "CDAB", "big")
DATA_BLOCK_B = _w16(3) + encode_f32(FLOW_LMIN, "ABCD", "little")
DATA_TEMPS = _w16(253) + _w16(261)
DATA_RTU_U2 = _w16(200) + _w16(200)

MAPPING_V1 = {
    "version": "map-v1",
    "address_base": 1,
    "registers": [
        {"address": 0, "name": "temp_a", "datatype": "u16", "scale": 0.1, "unit": "°C",
         "valid_min": 0.0, "valid_max": 1000.0, "word_order": "ABCD", "byte_order": "big", "words": 1},
        {"address": 1, "name": "temp_b", "datatype": "u16", "scale": 0.1, "unit": "°C",
         "valid_min": 0.0, "valid_max": 1000.0, "word_order": "ABCD", "byte_order": "big", "words": 1},
        {"address": 2, "name": "pressure", "datatype": "f32", "scale": 1.0, "unit": "kPa",
         "valid_min": 0.0, "valid_max": 5000.0, "word_order": "CDAB", "byte_order": "big", "words": 2},
        {"address": 4, "name": "status", "datatype": "u16", "scale": 1.0, "unit": "",
         "valid_min": None, "valid_max": None, "word_order": "ABCD", "byte_order": "big", "words": 1},
        {"address": 5, "name": "flow", "datatype": "f32", "scale": 1.0, "unit": "L/min",
         "valid_min": 0.0, "valid_max": 200.0, "word_order": "ABCD", "byte_order": "little", "words": 2},
    ],
}

# 参数修订：地址基准一基→零基（仅展示层），pressure 有效区间收紧（影响解释层）
MAPPING_V2 = dict(MAPPING_V1, version="map-v2", address_base=0, registers=[
    (dict(r, valid_max=80.0) if r["name"] == "pressure" else dict(r))
    for r in MAPPING_V1["registers"]
])


def _frame(kind: str, raw: bytes, direction: str, tick: float, conn: str) -> dict:
    return {"kind": kind, "session": SESSION, "raw": raw.hex(), "direction": direction,
            "tick": tick, "connection_id": conn, "meta": {}}


def _serial(tick: float, gap_ms: float, note: str) -> dict:
    return {"kind": "serial_event", "session": SESSION, "raw": None, "direction": "bus",
            "tick": tick, "connection_id": "rtu-b1",
            "meta": {"gap_ms": gap_ms, "note": note, "unit": "ms",
                     "time_base": "capture clock", "silence_chars": 3.5}}


def mapping_material(meta: dict) -> dict:
    return {"kind": "mapping", "session": SESSION, "raw": None, "direction": None,
            "tick": None, "connection_id": None, "meta": meta}


def baseline_materials() -> list:
    c1, c2, bus = "tcp-c1", "tcp-c2", "rtu-b1"
    frames = [
        # 连接代次 1（tcp-c1）
        _frame("tcp_frame", tcp_adu(1, 1, read_req(0, 4)), "request", 10.0, c1),
        _frame("tcp_frame", tcp_adu(1, 1, read_resp(DATA_BLOCK_A)), "response", 25.0, c1),
        _frame("tcp_frame", tcp_adu(2, 1, read_req(4, 3)), "request", 40.0, c1),
        _frame("tcp_frame", tcp_adu(2, 1, read_resp(DATA_BLOCK_B)), "response", 55.0, c1),
        _frame("tcp_frame", tcp_adu(3, 1, read_req(20, 1)), "request", 70.0, c1),
        _frame("tcp_frame", tcp_adu(3, 1, exc_resp(2)), "response", 85.0, c1),
        # transaction id 复用（同一代次内，前一事务已完结）
        _frame("tcp_frame", tcp_adu(1, 1, read_req(0, 2)), "request", 100.0, c1),
        _frame("tcp_frame", tcp_adu(1, 1, read_resp(DATA_TEMPS)), "response", 115.0, c1),
        # 无映射地址：原始字节保留 + 诊断
        _frame("tcp_frame", tcp_adu(4, 1, read_req(8, 1)), "request", 130.0, c1),
        _frame("tcp_frame", tcp_adu(4, 1, read_resp(_w16(300))), "response", 145.0, c1),
        # 连接重开（代次 2）：tid 从 1 重新开始，不得与代次 1 交叉配对
        _frame("tcp_frame", tcp_adu(1, 1, read_req(0, 4)), "request", 1000.0, c2),
        _frame("tcp_frame", tcp_adu(1, 1, read_resp(DATA_BLOCK_A)), "response", 1015.0, c2),
        # RTU 总线
        _frame("rtu_frame", rtu_adu(1, read_req(0, 4)), "request", 200.0, bus),
        _frame("rtu_frame", rtu_adu(1, read_resp(DATA_BLOCK_A)), "response", 225.0, bus),
        # 广播：unit 0 写单寄存器，协议规定没有响应
        _frame("rtu_frame", rtu_adu(0, b"\x06" + _w16(4) + _w16(1)), "request", 300.0, bus),
        # RTU 重传：字节完全相同的请求在重传窗口内再次出现
        _frame("rtu_frame", rtu_adu(2, read_req(0, 2)), "request", 400.0, bus),
        _frame("rtu_frame", rtu_adu(2, read_req(0, 2)), "request", 445.0, bus),
        _frame("rtu_frame", rtu_adu(2, read_resp(DATA_RTU_U2)), "response", 470.0, bus),
        # 无响应请求
        _frame("rtu_frame", rtu_adu(3, read_req(10, 1)), "request", 600.0, bus),
        # 二义性：两个未结请求同 unit 同功能码，保留全部合法候选
        _frame("rtu_frame", rtu_adu(4, read_req(0, 1)), "request", 700.0, bus),
        _frame("rtu_frame", rtu_adu(4, read_req(5, 1)), "request", 720.0, bus),
        _frame("rtu_frame", rtu_adu(4, read_resp(_w16(42))), "response", 750.0, bus),
    ]
    serials = [
        _serial(260.0, 35.0, "静默间隔 ≥3.5 字符，确认帧边界"),
        _serial(340.0, 40.0, "广播后总线静默，无响应到来"),
        _serial(520.0, 50.0, "unit 2 重传窗口结束"),
        _serial(650.0, 50.0, "unit 3 超时无响应"),
        _serial(800.0, 50.0, "unit 4 二义性响应后总线静默"),
    ]
    return [mapping_material(MAPPING_V1)] + frames + serials


def mapping_v2_material() -> dict:
    return mapping_material(MAPPING_V2)


def source_change_material():
    """只影响局部依赖的源数据改动：校正 RTU 重传帧的时间戳 445ms → 430ms。"""
    old = _frame("rtu_frame", rtu_adu(2, read_req(0, 2)), "request", 445.0, "rtu-b1")
    new = dict(old, tick=430.0,
               meta={"correction": "串口日志校正：重传帧时间戳 445ms → 430ms",
                     "unit": "ms", "time_base": "capture clock"})
    return material_id(old), new
