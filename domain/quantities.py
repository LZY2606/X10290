"""Units, coordinate bases and normalised values with validity ranges."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Time is nanoseconds since the trace epoch; timestamps are coordinates, not
# values the importer is allowed to rewrite.
NANOSECONDS = "ns"
MILLISECONDS = "ms"


@dataclass(frozen=True)
class AddressBase:
    """Modbus wire addresses are zero based; one based is display only."""

    value: int

    def __post_init__(self) -> None:
        if self.value not in (0, 1):
            raise ValueError("address base must be 0 or 1")

    def display(self, zero_based: int) -> int:
        return zero_based + self.value


@dataclass(frozen=True)
class QuantityKind:
    unit: str
    coordinate: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"unit": self.unit, "coordinate": self.coordinate}
