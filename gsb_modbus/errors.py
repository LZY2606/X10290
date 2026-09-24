"""Three deliberately distinct failure outcomes.

* ResourceBudgetExhausted - input is well formed but exceeds an agreed budget.
* FormatCorrupt           - bytes/JSON are structurally unusable at a position.
* SemanticallyUnresolved  - structure is fine, but no unique legal meaning exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass(frozen=True)
class Diagnostic:
    """A located problem. Position strings point at the offending material."""

    code: str
    message: str
    position: str = ""
    severity: str = "error"  # error | warning

    def to_dict(self) -> dict:
        return asdict(self)


class GSBError(Exception):
    diagnostic = Diagnostic("gsb_error", "")

    def __init__(self, message: str, *, position: str = ""):
        super().__init__(message)
        self.diagnostic = Diagnostic(self.code, message, position)

    @property
    def code(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

    def payload(self) -> dict:
        return {"kind": type(self).__name__, "diagnostic": self.diagnostic.to_dict()}


class ResourceBudgetExhausted(GSBError):
    code = "resource_budget_exhausted"

    def __init__(self, message: str, *, position: str = "", used: int = 0, limit: int = 0):
        super().__init__(message, position=position)
        self.used = used
        self.limit = limit

    def payload(self) -> dict:
        data = super().payload()
        data["used"] = self.used
        data["limit"] = self.limit
        return data


class FormatCorrupt(GSBError):
    code = "format_corrupt"


class SemanticallyUnresolved(GSBError):
    code = "semantically_unresolved"
