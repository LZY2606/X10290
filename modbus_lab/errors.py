"""三种必须可区分的失败结果：资源预算耗尽 / 格式损坏 / 语义无解。"""


class ModbusLabError(Exception):
    code = "lab_error"

    def __init__(self, message, *, path=None):
        super().__init__(message)
        self.message = message
        self.path = path

    def to_dict(self):
        d = {"kind": self.code, "message": self.message}
        if self.path is not None:
            d["path"] = self.path
        return d


class BudgetExhausted(ModbusLabError):
    """资源预算耗尽：允许调用方提高预算后重试，不是数据错误。"""

    code = "budget_exhausted"

    def __init__(self, message, *, budget, used, path=None):
        super().__init__(message, path=path)
        self.budget = budget
        self.used = used

    def to_dict(self):
        d = super().to_dict()
        d.update({"budget": self.budget, "used": self.used})
        return d


class FormatCorrupt(ModbusLabError):
    """格式损坏：字节/结构层面无法解析，必须带位置。"""

    code = "format_corrupt"


class SemanticUnresolvable(ModbusLabError):
    """语义无解：结构合法但领域上无法解释（信息不完整、映射冲突等）。"""

    code = "semantic_unresolvable"
