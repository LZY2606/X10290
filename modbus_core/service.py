"""工作流编排：导入 -> 推导 -> 复核 -> 决定 -> 导出/再导入。

所有计算结果记录输入摘要、参数版本与父级依赖；
回到任意旧事件时，state_at(seq) 恢复当时的依赖版本与可见结论，
而不是用最新计算结果覆盖历史。
"""
from __future__ import annotations

from dataclasses import asdict

from . import casepack
from .domain import digest, parse_tcp_adu, parse_rtu_adu
from .pairing import PairParams, apply_param_changes, run_pairing
from .registers import run_registers
from .store import Store


def _frame_id(payload: dict, occurrence: int) -> str:
    key = "|".join(str(payload[k]) for k in
                   ("transport", "direction", "conn_generation", "tick", "adu_hex"))
    return "fr-" + digest(key)[:12] + f"-{occurrence}"


class ReviewService:
    def __init__(self, store: Store):
        self.store = store

    #确定 = None  # 占位避免误用

    # ------------------------------------------------------------ 导入
    def import_case_pack(self) -> str:
        sid = self.store.create_session(
            casepack.CASE_TITLE,
            meta={"case": casepack.CASE_NAME, "narr": casepack.CASE_NARRATIVE})
        items = []
        occ: dict = {}
        for m in casepack.baseline_materials():
            items.append(self._material_item(sid, m, occ))
        self.store.append(sid, items)
        self.derive(sid, note="基线导入：原 ADU 字节/方向/tid/uid/CRC/功能码/地址基准/映射版本全部保留")
        return sid

    def _material_item(self, sid  # noqa
                       ):
        pass
