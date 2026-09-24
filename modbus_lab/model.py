"""领域模型：所有量都带身份、单位/坐标基准与来源。

派生对象身份（stable_id）由确定性材料摘要派生，因此导出后删除数据库再导入，
身份、顺序与来源关系不变。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

TCP = "tcp"
RTU = "rtu"

REQUEST = "request"
RESPONSE = "response"

SECONDS = "s"
ZERO_BASE = 0
ONE_BASE = 1

# 未配对原因（机器可读取的判定事件）
REASON_BROADCAST = "broadcast_no_response"          # 广播没有响应
REASON_NO_RESPONSE = "no_response_before_close"     # TCP 连接关闭/重开前无响应
REASON_RTU_TIMEOUT = "rtu_silent_interval_expired"  # 超过 RTU 静默间隔
REASON_ORPHAN_RESPONSE = "orphan_response"          # 找不到对应请求
REASON_CRC_BAD = "crc_error"                        # CRC 失败
REASON_MALFORMED = "malformed_adu"                  # 结构损坏
REASON_AMBIGUOUS = "ambiguous_multiple_candidates"  # 多个合法候选，未人工决定

# 配对状态
PAIRED = "paired"
UNPAIRED = "unpaired"
EXCEPTED = "exception"
AMBIGUOUS_PAIR = "ambiguous"

# 决定类型
DECISION_ACCEPT = "accept"
DECISION_REJECT = "reject"
DECISION_CHOOSE = "choose_candidate"
DECISION_PARAM = "parameter_revision"

# 读功能码
READ_FCS = {1, 2, 3, 4}
WRITE_SINGLE_FCS = {5, 6}
WRITE_MULTI_FCS = {15, 16}
WRITE_FCS = WRITE_SINGLE_FCS | WRITE_MULTI_FCS

FC_NAMES = {
    1: "read_coils",
    2: "read_discrete_inputs",
    3: "read_holding_registers",
    4: "read_input_registers",
    5: "write_single_coil",
    6: "write_single_register",
    8: "diagnostics",
    15: "write_multiple_coils",
    16: "write_multiple_registers",
}


@dataclass
class Diagnostic:
    code: str
    message: str
    path: Optional[str] = None
    severity: str = "error"
    value: Any = None

    def to_dict(self):
        d = {"code": self.code, "message": self.message, "severity": self.severity}
        if self.path is not None:
            d["path"] = self.path
        if self.value is not None:
            d["value"] = self.value
        return d


@dataclass
class RegisterDef:
    register: int                # 归一化零基地址
    name: str
    access: str                  # holding / input / coil / discrete
    data_type: str               # u16/i16/u32/i32/f32/f64/bit/bool
    length_registers: int
    unit: str = ""
    scale: float = 1.0
    offset: float = 0.0
    word_order: str = "ABCD"
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    enumeration: Optional[dict[int, str]] = None
    raw_register: Optional[int] = None   # 导入时的原始地址表示
    raw_base: Optional[int] = None       # 导入时声明的基准

    def to_dict(self):
        d = {k: v for k, v in self.__dict__.items() if v is not None}
        return d


@dataclass
class MappingVersion:
    version: str
    device: str
    address_base: int
    entries: list[RegisterDef] = field(default_factory=list)
    unit_id: Optional[int] = None

    def lookup(self, register_zero: int) -> Optional[RegisterDef]:
        for e in self.entries:
            if e.register <= register_zero < e.register + e.length_registers:
                return e
        return None

    def to_dict(self):
        return {
            "version": self.version,
            "device": self.device,
            "address_base": self.address_base,
            "unit_id": self.unit_id,
            "entries": [e.to_dict() for e in self.entries],
        }


@dataclass
class Frame:
    """原始帧（不可变材料）。原始表示全部保留，派生字段另行存放。"""

    frame_id: str
    transport: str
    bus_or_connection: str
    direction: str
    observed_at_raw: str                 # 导入时的原始时间表示
    observed_at_s: Optional[float]       # 统一时间基准（秒）
    adu_hex: str                         # 原 ADU 字节
    unit_id: Optional[int]
    function_code: Optional[int]
    function_name: Optional[str]
    is_exception: bool
    transaction_id: Optional[int]        # TCP；RTU 为 None
    crc_ok: Optional[bool]               # RTU；TCP 为 None
    crc_hex: Optional[str]
    pdu_hex: Optional[str]
    address_base: int                   # 导入时声明的地址基准（随材料保留）
    mapping_version: str                # 导入时声明的映射表版本
    source_ref: str
    parse_status: str                   # ok / malformed / crc_bad
    pdu: Optional[dict] = None
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def to_dict(self):
        d = dict(self.__dict__)
        d["diagnostics"] = [x.to_dict() for x in self.diagnostics]
        return d


@dataclass
class SerialEvent:
    event_id: str
    bus: str
    kind: str                            # gap / frame_boundary / idle
    at_raw: str
    at_s: Optional[float]
    gap_raw: Any                         # 原始表示（可能是无法转换的字符串）
    gap_s: Optional[float]              # 规范化后的秒
    unit: str = SECONDS
    source_ref: str = ""
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def to_dict(self):
        d = dict(self.__dict__)
        d["diagnostics"] = [x.to_dict() for x in self.diagnostics]
        return d


@dataclass
class Connection:
    connection_id: str
    transport: str
    bus_or_connection: str
    generation: int
    opened_event_seq: int
    closed_event_seq: Optional[int] = None
    opened_at_s: Optional[float] = None
    closed_at_s: Optional[float] = None

    def to_dict(self):
        return dict(self.__dict__)


@dataclass
class RegisterInterval:
    interval_id: str
    pair_id: str
    frame_id: str
    access: str
    function_code: int
    start_zero: int
    count: int
    mapping_version: str
    address_base: int                    # 展示基准（仅展示层转换）
    display_start: int
    mapping_coverage: list[dict] = field(default_factory=list)

    def to_dict(self):
        return dict(self.__dict__)


@dataclass
class RegisterValue:
    value_id: str
    pair_id: str
    interval_id: str
    frame_id: str
    register_zero: int
    display_register: int
    name: Optional[str]
    raw_words_hex: str
    raw_value: Any
    value: Any
    unit: str
    word_order: str
    mapping_version: str
    address_base: int
    data_type: str
    status: str                          # ok / diagnostic / unmapped / exception
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def to_dict(self):
        d = dict(self.__dict__)
        d["diagnostics"] = [x.to_dict() for x in self.diagnostics]
        return d


@dataclass
class Pair:
    pair_id: str
    scope: str                           # connection id 或 bus
    transport: str
    generation: int
    request_frame_id: Optional[str]
    response_frame_id: Optional[str]
    candidate_frame_ids: list[str]
    unit_id: Optional[int]
    function_code: Optional[int]
    status: str                          # paired/exception/unpaired/ambiguous
    reason: Optional[str]
    rule: str                            # tcp_transaction_id / rtu_silent_gap / human_decision / broadcast
    parameter_version: str
    opened_at_s: Optional[float] = None
    response_at_s: Optional[float] = None
    gap_s: Optional[float] = None
    decided_by_event_seq: Optional[int] = None
    parent_event_seqs: list[int] = field(default_factory=list)
    input_digest: str = ""
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def to_dict(self):
        d = dict(self.__dict__)
        d["diagnostics"] = [x.to_dict() for x in self.diagnostics]
        return d


@dataclass
class RecordedDerivation:
    """每次重放产生的派生结果快照（按参数版本+父事件可追溯，不覆盖历史）。"""

    seq: int
    event_seq: int
    branch: str
    parameter_version: str
    input_digest: str
    kind: str                             # pair / interval / value
    object_id: str
    payload: dict


@dataclass
class Decision:
    event_seq: int
    branch: str
    kind: str
    target_id: str
    payload: dict
    parameter_version: str
    parent_event_seqs: list[int]
