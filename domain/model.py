"""Shared plain data types for the Modbus trace room."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Result classes that must never collapse into one another.
RESULT_ACCEPTED = "accepted"
RESULT_REJECTED = "rejected"
RESULT_AMBIGUOUS = "ambiguous"
RESULT_UNMATCHED = "unmatched"
RESULT_DIAGNOSTIC = "diagnostic"

# Explicitly different terminal failure classes.
FAIL_BUDGET_EXHAUSTED = "budget_exhausted"
FAIL_FORMAT_CORRUPT = "format_corrupt"
FAIL_SEMANTIC_UNRESOLVABLE = "semantic_unresolvable"

BROADCAST_UNIT = 0


@dataclass
class Diagnostic:
    code: str
    message: str
    location: dict[str, Any] = field(default_factory=dict)
    severity: str = "error"

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "location": self.location,
            "severity": self.severity,
        }


class DomainError(Exception):
    """Structured domain failure carrying a result class and positions."""

    def __init__(self, result: str, code: str, message: str,
                 diagnostics: list[Diagnostic] | None = None):
        super().__init__(message)
        self.result = result
        self.code = code
        self.message = message
        self.diagnostics = diagnostics or []

    def as_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "code": self.code,
            "message": self.message,
            "diagnostics": [d.as_dict() for d in self.diagnostics],
        }
