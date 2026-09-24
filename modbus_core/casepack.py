"""离线案例包：寄存器轨迹室 · Modbus 请求配对、地址模型与设备代次。

叙事主线：工业协议小组导入 Modbus TCP 与 RTU 轨迹、设备映射版本和串口事件，
复核每次请求、响应及寄存器值的来路。

阶段安排：
1. 基线导入 —— 原 ADU 字节、方向、transaction id、unit id、CRC、功能码、
   地址基准与映射表版本全部保留；
2. 边界套件 —— transaction id 复用、RTU 重传、广播、异常码、地址基准切换、
   字节字序组合、连接重开、静默间隔越界、损坏帧；
3. 参数修订 —— RTU 静默窗口放宽（只影响 RTU 配对这一局部依赖）；
4. 源数据改动 —— 更正一帧损坏的 RTU 帧（材料修订，旧派生失效）；
5. 冲突决定 —— 两位审阅者对同一模糊配对给出相反结论，随后形成决议。
"""
from __future__ import annotations

from .domain import crc16_modbus

CASE_NAME = "register-trace-room"
CASE_TITLE = "寄存器轨迹室：Modbus 请求配对、地址模型与设备代次"
CASE_NARRATIVE = (
    "工业协议小组导入 Modbus TCP 与 RTU 轨迹、设备映射版本和串口事件，"
    "复核每次请求、响应及寄存器值的来路"
)


def tcp_adu(tid: int, uid: int, pdu: bytes) -> bytes:
    return (tid.to_bytes(2, "big") + b"\x00\x00"
            + (len(pdu) + 1).to_bytes(2, "big") + bytes([uid]) + pdu)


def rtu_adu(uid: int, pdu: bytes) -> bytes:
    body = bytes([uid]) + pdu
    return body + crc16_modbus(body).to_bytes(2, "little")


def read_req(fc: int, addr: int, count: int) -> bytes:
    return bytes([fc]) + addr.to_bytes(2, "big") + count.to_bytes(2, "big")


def read_resp(fc: int, data: bytes) -> bytes:
    return bytes([fc, len(data)]) + data


def exc_resp(fc: int, code: int) -> bytes:
    return bytes([fc | 0x80, code])


def write_single(addr: int, value: int) -> bytes:
    return bytes([6]) + addr.to_bytes(2, "big") + value.to_bytes(2, "big")


def _frame(transport, direction, gen, tick, adu: bytes, note=""):
    return {"kind": "trace_frame",
            "payload": {"transport": transport, "direction": direction,
                        "conn_generation": gen, "tick": tick,
                        "adu_hex": adu.hex(), "note": note}}


# ---------------------------------------------------------------- 映射表
def mapping_v1() -> dict:
    return {"kind": "mapping_version", "payload": {
        "version": "map-v1",
        "address_base": 0,
        "description": "设备映射 v1：0 基地址（协议线上地址即展示地址）",
        "entries": [
            {"address": 0, "name": "tank_temp", "unit": "°C", "dtype": "i16",
             "scale": 0.1, "byte_order": "AB", "valid_range": [-40, 120],
             "invalid_reason": "超出温度传感器量程"},
            {"address": 1, "name": "tank_pressure", "unit": "bar", "dtype": "u16",
             "scale": 0.01, "byte_order": "AB", "valid_range": [0, 25],
             "invalid_reason": "压力变送器过载"},
            {"address": 2, "name": "flow_rate", "unit": "L/min", "dtype": "u16",
             "scale": 1, "byte_order": "AB", "valid_range": [0, 1000],
             "invalid_reason": "超过流量计上限"},
            {"address": 3, "name": "status_flags", "unit": "", "dtype": "u16",
             "scale": 1, "byte_order": "AB", "valid_range": None},
            {"address": 100, "name": "energy_total", "unit": "kWh", "dtype": "u32",
             "scale": 0.1, "byte_order": "AB", "word_order": "ABCD",
             "valid_range": None},
            {"address": 102, "name": "water_meter", "unit": "m³", "dtype": "u32",
             "scale": 0.01, "byte_order": "AB", "word_order": "CDAB",
             "valid_range": None},
            {"address": 104, "name": "power_factor", "unit": "", "dtype": "f32",
             "scale": 1, "byte_order": "AB", "word_order": "ABCD",
             "valid_range": [-1, 1], "invalid_reason": "功率因数越界"},
            {"address": 106, "name": "harmonic_ratio", "unit": "%", "dtype": "f32",
             "scale": 1, "byte_order": "AB", "word_order": "DCBA",
             "valid_range": [0, 100], "invalid_reason": "谐波含量异常"},
        ]}}


def mapping_v2() -> dict:
    """地址基准切换：仅展示层 1 基化，canonical 线上地址不变。"""
    m = mapping_v1()["payload"]
    entries = [dict(e) for e in m["entries"]]
    return {"kind": "mapping_version", "payload": {
        **m, "version": "map-v2", "address_base": 1,
        "description": "设备映射 v2：展示层切换为 1 基地址（线上 0 基不变），内容同 v1",
        "entries": entries}}


# ---------------------------------------------------------------- 基线材料
def baseline_materials() -> list[dict]:
    mats: list[dict] = [mapping_v1()]
    # TCP 代次 1：两组正常请求/响应
    mats.append(_frame("tcp", "out", 1, 0, tcp_adu(1, 1, read_req(3, 0, 4)),
                       "读保持寄存器 0..3"))
    # temp=23.5°C(235) pressure=15.30bar(1530) flow=420 status=0x0002
    mats.append(_frame("tcp", "in", 1, 5,
                       tcp_adu(1, 1, read_resp(3, bytes.fromhex("00eb05fa01a40002"))),
                       "正常响应 8 字节"))
    mats.append(_frame("tcp", "out", 1, 10, tcp_adu(2, 1, read_req(3, 100, 8)),
                       "读保持寄存器 100..107（四种字节/字序组合）"))
    # 100:u32 ABCD=100000  102:u32 CDAB=200000  104:f32 ABCD=1.5(越界)  106:f32 DCBA=2.5
    mats.append(_frame("tcp", "in", 1, 15,
                       tcp_adu(2, 1, read_resp(3, bytes.fromhex(
                           "000186a0" "0d400003" "3fc00000" "00002040"))),
                       "正常响应 16 字节"))
    mats.append({"kind": "serial_event", "payload": {
        "event": "capture_started", "transport": "tcp", "conn_generation": 1,
        "tick": 0, "note": "TCP 连接代次 1 开始抓包"}})
    return mats


# ---------------------------------------------------------------- 边界套件
def boundary_materials() -> list[dict]:
    mats: list[dict] = []
    # 1) transaction id 复用（TCP 代次 1）
    mats.append(_frame("tcp", "out", 1, 100, tcp_adu(7, 1, read_req(3, 0, 2)),
                       "tid=7 第一次使用"))
    mats.append(_frame("tcp", "out", 1, 110, tcp_adu(7, 1, read_req(3, 2, 2)),
                       "tid=7 应答前复用"))
    mats.append(_frame("tcp", "in", 1, 115,
                       tcp_adu(7, 1, read_resp(3, bytes.fromhex("00eb05fa"))),
                       "tid=7 响应：归属无法唯一决定"))
    # 2) RTU 重传（RTU 代次 1）
    req = rtu_adu(2, read_req(3, 0, 2))
    mats.append(_frame("rtu", "out", 1, 200, req, "RTU 读 uid=2 寄存器 0..1"))
    mats.append(_frame("rtu", "out", 1, 230, req, "相同 ADU 重传"))
    mats.append(_frame("rtu", "in", 1, 240,
                       rtu_adu(2, read_resp(3, bytes.fromhex("006400c8"))),
                       "响应归入最后一次重传"))
    # 3) 广播（无响应是协议规定，不是错误）
    mats.append(_frame("rtu", "out", 1, 300, rtu_adu(0, write_single(5, 1)),
                       "广播写单寄存器 uid=0"))
    # 4) 异常码（TCP）
    mats.append(_frame("tcp", "out", 1, 400, tcp_adu(9, 1, read_req(3, 500, 2)),
                       "读未映射区域 500..501"))
    mats.append(_frame("tcp", "in", 1, 405, tcp_adu(9, 1, exc_resp(3, 2)),
                       "异常响应 0x83 code=2 非法数据地址"))
    # 5) 连接重开（TCP 代次 1 -> 2）
    mats.append(_frame("tcp", "out", 1, 490, tcp_adu(12, 1, read_req(3, 8, 1)),
                       "代次 1 末尾未应答请求"))
    mats.append({"kind": "serial_event", "payload": {
        "event": "reconnect", "transport": "tcp", "tick": 500,
        "conn_generation": 2, "from_generation": 1,
        "note": "TCP 连接重开，进入代次 2"}})
    mats.append(_frame("tcp", "out", 2, 510, tcp_adu(12, 1, read_req(3, 8, 1)),
                       "代次 2 复用 tid=12，跨代次不构成复用歧义"))
    mats.append(_frame("tcp", "in", 2, 515,
                       tcp_adu(12, 1, read_resp(3, bytes.fromhex("002a"))),
                       "代次 2 正常应答"))
    # 6) 静默间隔越界（RTU）
    mats.append(_frame("rtu", "out", 1, 700, rtu_adu(3, read_req(3, 0, 1)),
                       "RTU 读 uid=3"))
    mats.append(_frame("rtu", "in", 1, 800,
                       rtu_adu(3, read_resp(3, bytes.fromhex("0001"))),
                       "响应间隔 100 tick，超出静默窗口 50"))
    # 7) 损坏帧：CRC 错误 + 截断
    bad = bytearray(rtu_adu(2, read_req(3, 10, 1)))
    bad[-1] ^= 0xFF
    mats.append(_frame("rtu", "out", 1, 600, bytes(bad), "CRC 被线路噪声翻转"))
    truncated = tcp_adu(20, 1, read_req(3, 0, 2))[:9]
    mats.append(_frame("tcp", "in", 1, 610, truncated, "MBAP 长度字段与实际不符"))
    return mats


# ---------------------------------------------------------------- 材料修订
def corrected_frame_material(supersedes_entry_id: str) -> dict:
    """更正 t=600 那帧 CRC 损坏的 RTU 请求。"""
    return {"kind": "trace_frame",
            "payload": {"transport": "rtu", "direction": "out",
                        "conn_generation": 1, "tick": 600,
                        "adu_hex": rtu_adu(2, read_req(3, 10, 1)).hex(),
                        "note": "修订：更正 CRC 后的同一帧",
                        "supersedes": supersedes_entry_id}}
