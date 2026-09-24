"""离线案例包：寄存器轨迹室 —— Modbus 请求配对、地址模型与设备代次。

叙事：工业协议小组导入 Modbus TCP 与 RTU 轨迹、设备映射版本和串口
事件，复核每次请求、响应及寄存器值的来路。初始导入后依次安排：
一次参数修订（地址基准切换 + 字节字序组合）、一次只影响局部依赖的
源数据改动（修复 CRC 损坏的 RTU 响应）、一次互相冲突的人工决定。
重放轨迹实际经过：transaction id 复用、RTU 重传、广播、异常码、
地址基准切换、字节字序组合和连接重开。
"""
from __future__ import annotations

import json
from pathlib import Path

from .core import crc16_modbus

CASE_ID = "register-trace-room"
CASE_TITLE = "“寄存器轨迹室：Modbus 请求配对、地址模型与设备代次”"


def rtu(payload_hex: str) -> str:
    """给 RTU PDU（含地址）补 CRC，返回完整 ADU hex。"""
    raw = bytes.fromhex(payload_hex)
    crc = crc16_modbus(raw)
    return (raw + crc.to_bytes(2, "little")).hex()


def rtu_bad_crc(payload_hex: str) -> str:
    """故意写错 CRC 的 RTU 帧（用于 format_corrupt 与源数据改动叙事）。"""
    raw = bytes.fromhex(payload_hex)
    crc = crc16_modbus(raw) ^ 0xFFFF
    return (raw + crc.to_bytes(2, "little")).hex()


def build_case() -> dict:
    frames = [
        # ---- TCP 连接代次 1 ----
        {"frame_id": "frm-tcp-001", "link": "tcp", "direction": "client_to_server",
         "conn_gen": 1, "t_ms": 10.0, "raw_hex": "000100000006010300000004",
         "address_base": "zero", "mapping_version": "map-boiler-v1",
         "source": "capture/tcp-2026-09-19.pcap:0"},
        {"frame_id": "frm-tcp-002", "link": "tcp", "direction": "server_to_client",
         "conn_gen": 1, "t_ms": 22.0,
         "raw_hex": "00010000000b01030809c409c50bb80bb9",
         "address_base": "zero", "mapping_version": "map-boiler-v1",
         "source": "capture/tcp-2026-09-19.pcap:1"},
        {"frame_id": "frm-tcp-003", "link": "tcp", "direction": "client_to_server",
         "conn_gen": 1, "t_ms": 40.0, "raw_hex": "000200000006010300640002",
         "address_base": "zero", "mapping_version": "map-boiler-v1",
         "source": "capture/tcp-2026-09-19.pcap:2"},
        {"frame_id": "frm-tcp-004", "link": "tcp", "direction": "server_to_client",
         "conn_gen": 1, "t_ms": 55.0, "raw_hex": "000200000003018302",
         "address_base": "zero", "mapping_version": "map-boiler-v1",
         "source": "capture/tcp-2026-09-19.pcap:3"},
        {"frame_id": "frm-tcp-005", "link": "tcp", "direction": "client_to_server",
         "conn_gen": 1, "t_ms": 70.0, "raw_hex": "000300000006000600000001",
         "address_base": "zero", "mapping_version": "map-boiler-v1",
         "source": "capture/tcp-2026-09-19.pcap:4"},
        # ---- 连接重开：TCP 连接代次 2（transaction id 复用） ----
        {"frame_id": "frm-tcp-006", "link": "tcp", "direction": "client_to_server",
         "conn_gen": 2, "t_ms": 200.0, "raw_hex": "000100000006010300000004",
         "address_base": "zero", "mapping_version": "map-boiler-v1",
         "source": "capture/tcp-2026-09-19.pcap:5"},
        {"frame_id": "frm-tcp-007", "link": "tcp", "direction": "server_to_client",
         "conn_gen": 2, "t_ms": 215.0,
         "raw_hex": "00010000000b01030809d009d10bc80bc9",
         "address_base": "zero", "mapping_version": "map-boiler-v1",
         "source": "capture/tcp-2026-09-19.pcap:6"},
        {"frame_id": "frm-tcp-008", "link": "tcp", "direction": "client_to_server",
         "conn_gen": 2, "t_ms": 230.0, "raw_hex": "000200000006010300040002",
         "address_base": "zero", "mapping_version": "map-boiler-v1",
         "source": "capture/tcp-2026-09-19.pcap:7"},
        {"frame_id": "frm-tcp-009", "link": "tcp", "direction": "client_to_server",
         "conn_gen": 2, "t_ms": 240.0, "raw_hex": "000200000006010300060002",
         "address_base": "zero", "mapping_version": "map-boiler-v1",
         "source": "capture/tcp-2026-09-19.pcap:8"},
        {"frame_id": "frm-tcp-010", "link": "tcp", "direction": "server_to_client",
         "conn_gen": 2, "t_ms": 250.0, "raw_hex": "00020000000701030401f401f5",
         "address_base": "zero", "mapping_version": "map-boiler-v1",
         "source": "capture/tcp-2026-09-19.pcap:9"},
        # ---- RTU 总线（静默间隔配对、重传、广播、CRC 损坏） ----
        {"frame_id": "frm-rtu-001", "link": "rtu", "direction": "master_to_slave",
         "conn_gen": 1, "t_ms": 300.0, "raw_hex": rtu("0503000a0002"),
         "address_base": "zero", "mapping_version": "map-pump-v1",
         "source": "capture/rtu-bus1.log:0"},
        {"frame_id": "frm-rtu-002", "link": "rtu", "direction": "slave_to_master",
         "conn_gen": 1, "t_ms": 320.0, "raw_hex": rtu("05030400fa00fb"),
         "address_base": "zero", "mapping_version": "map-pump-v1",
         "source": "capture/rtu-bus1.log:1"},
        {"frame_id": "frm-rtu-003", "link": "rtu", "direction": "master_to_slave",
         "conn_gen": 1, "t_ms": 400.0, "raw_hex": rtu("050300140001"),
         "address_base": "zero", "mapping_version": "map-pump-v1",
         "source": "capture/rtu-bus1.log:2"},
        {"frame_id": "frm-rtu-004", "link": "rtu", "direction": "master_to_slave",
         "conn_gen": 1, "t_ms": 410.0, "raw_hex": rtu("050300140001"),
         "address_base": "zero", "mapping_version": "map-pump-v1",
         "source": "capture/rtu-bus1.log:3"},
        {"frame_id": "frm-rtu-005", "link": "rtu", "direction": "slave_to_master",
         "conn_gen": 1, "t_ms": 425.0, "raw_hex": rtu("050302010 4".replace(" ", "")),
         "address_base": "zero", "mapping_version": "map-pump-v1",
         "source": "capture/rtu-bus1.log:4"},
        {"frame_id": "frm-rtu-006", "link": "rtu", "direction": "master_to_slave",
         "conn_gen": 1, "t_ms": 500.0, "raw_hex": rtu("00060001ff00"),
         "address_base": "zero", "mapping_version": "map-pump-v1",
         "source": "capture/rtu-bus1.log:5"},
        {"frame_id": "frm-rtu-007", "link": "rtu", "direction": "master_to_slave",
         "conn_gen": 1, "t_ms": 600.0, "raw_hex": rtu("0703001e0002"),
         "address_base": "zero", "mapping_version": "map-pump-v1",
         "source": "capture/rtu-bus1.log:6"},
        # CRC 损坏的响应：修复前不参与配对（format_corrupt）
        {"frame_id": "frm-rtu-008", "link": "rtu", "direction": "slave_to_master",
         "conn_gen": 1, "t_ms": 650.0, "raw_hex": rtu_bad_crc("07030400640065"),
         "address_base": "zero", "mapping_version": "map-pump-v1",
         "source": "capture/rtu-bus1.log:7"},
    ]
    mappings = [
        {"mapping_id": "map-boiler-v1", "version": "map-boiler-v1",
         "device": "boiler-1", "entries": [
             {"start": 0, "count": 4, "name": "炉温", "unit": "°C",
              "datatype": "uint16", "scale": 0.01,
              "valid_min": 0.0, "valid_max": 150.0, "declared_base": "one"},
             {"start": 100, "count": 2, "name": "蒸汽压力", "unit": "kPa",
              "datatype": "uint16", "scale": 0.1,
              "valid_min": 0.0, "valid_max": 2000.0, "declared_base": "one"},
         ]},
        {"mapping_id": "map-boiler-v2", "version": "map-boiler-v2",
         "device": "boiler-1", "entries": [
             {"start": 0, "count": 4, "name": "炉温", "unit": "°C",
              "datatype": "uint16", "scale": 0.01,
              "valid_min": 0.0, "valid_max": 150.0, "declared_base": "zero"},
             {"start": 4, "count": 2, "name": "给水流量", "unit": "m³/h",
              "datatype": "float32", "scale": 1.0,
              "valid_min": 0.0, "valid_max": 500.0, "declared_base": "zero"},
             {"start": 100, "count": 2, "name": "蒸汽压力", "unit": "kPa",
              "datatype": "uint16", "scale": 0.1,
              "valid_min": 0.0, "valid_max": 2000.0, "declared_base": "zero"},
         ]},
        {"mapping_id": "map-pump-v1", "version": "map-pump-v1",
         "device": "pump-5", "entries": [
             {"start": 10, "count": 2, "name": "泵转速", "unit": "rpm",
              "datatype": "uint16", "scale": 1.0,
              "valid_min": 0.0, "valid_max": 3000.0, "declared_base": "zero"},
             {"start": 20, "count": 1, "name": "相电流", "unit": "A",
              "datatype": "uint16", "scale": 0.1,
              "valid_min": 0.0, "valid_max": 50.0, "declared_base": "zero"},
             {"start": 30, "count": 2, "name": "轴承温度", "unit": "°C",
              "datatype": "uint16", "scale": 0.1,
              "valid_min": -20.0, "valid_max": 120.0, "declared_base": "zero"},
         ]},
    ]
    serial_events = [
        {"event_id": "ser-001", "t_ms": 0.0, "kind": "port_open",
         "detail": "/dev/ttyUSB0 9600 8N1", "source": "serial/monitor.log:0"},
        {"event_id": "ser-002", "t_ms": 350.0, "kind": "noise_burst",
         "detail": "线路噪声：3 次帧错误，未产生完整 ADU",
         "source": "serial/monitor.log:1"},
        {"event_id": "ser-003", "t_ms": 900.0, "kind": "port_close",
         "detail": "正常关闭", "source": "serial/monitor.log:2"},
    ]
    script = [
        {"op": "import", "source_label": "casepack/register_trace_room/v1"},
        {"op": "derive"},
        # 一次参数修订：地址基准切换（仅展示层）+ 字节字序组合
        {"op": "revise_params", "reason": "现场审阅习惯一基地址；该设备手册为"
         "小端字节、低字优先", "display_base": "one",
         "byte_order": "little", "word_order": "low_first"},
        # 一次只影响局部依赖的源数据改动：修复 CRC 损坏的 RTU 响应
        {"op": "correct_source", "frame_id": "frm-rtu-008",
         "raw_hex": rtu("07030400640065"),
         "reason": "串口监控重抓确认原帧 CRC 抄录错误，修正后参与配对"},
        # 一次互相冲突的人工决定（双方保留）
        {"op": "decide", "target_id": "pair-rtu-0003", "verdict": "accept",
         "reviewer": "张工", "rationale": "修复后的响应与请求在静默窗口内，配对可信"},
        {"op": "decide", "target_id": "pair-rtu-0003", "verdict": "reject",
         "reviewer": "李工", "rationale": "修正帧来源为人工重抓，要求二次抓包确认"},
    ]
    return {"case_id": CASE_ID, "title": CASE_TITLE, "format": "casepack/v1",
            "time_base": "monotonic_ms_since_capture_start",
            "frames": frames, "mappings": mappings,
            "serial_events": serial_events, "script": script}


def replay_case(session, case: dict | None = None) -> None:
    """把案例包脚本重放到会话里，生成完整事件链。"""
    case = case or build_case()
    for step in case["script"]:
        op = step["op"]
        if op == "import":
            session.import_materials(frames=case["frames"],
                                     mappings=case["mappings"],
                                     serial_events=case["serial_events"],
                                     source_label=step["source_label"])
        elif op == "derive":
            session.derive()
        elif op == "revise_params":
            session.revise_params(reason=step["reason"],
                                  **{k: v for k, v in step.items()
                                     if k not in ("op", "reason")})
        elif op == "correct_source":
            session.correct_source(frame_id=step["frame_id"],
                                   raw_hex=step["raw_hex"],
                                   reason=step["reason"])
        elif op == "decide":
            session.decide(target_id=step["target_id"], verdict=step["verdict"],
                           reviewer=step["reviewer"], rationale=step["rationale"])
        else:
            raise ValueError(f"未知脚本操作: {op}")


def write_case_file(path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    case = build_case()
    path.write_text(json.dumps(case, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return path


if __name__ == "__main__":
    out = write_case_file(Path(__file__).resolve().parent.parent
                          / "casepack" / "register_trace_room.json")
    print(out)
