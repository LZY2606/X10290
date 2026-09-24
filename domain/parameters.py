"""Pairing parameter versions and machine readable rule bases."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .identity import stable_id
from .model import Diagnostic, DomainError, FAIL_FORMAT_CORRUPT

# Rule ids are part of machine readable evidence and must remain stable.
RULE_TCP_TRANSACTION = "PAIR-TCP-TRANSACTION-ID"
RULE_RTU_SILENCE = "PAIR-RTU-SILENT-INTERVAL"
RULE_BROADCAST = "PAIR-RTU-BROADCAST-NO-RESPONSE"
RULE_EXCEPTION = "VALUE-EXCEPTION-NOT-EMPTY-DATA"
RULE_ADDRESS_DISPLAY = "ADDR-ZERO-WIRE-ONE-DISPLAY"
RULE_WORD_ORDER = "VALUE-32BIT-WORD-BYTE-ORDER"

RULE_STATEMENTS = {
    RULE_TCP_TRANSACTION: (
        "TCP frames pair only within the same connection generation using "
        "(transaction id, unit id, function); a transaction id is reusable "
        "after the earlier transaction closes or the connection reopens."
    ),
    RULE_RTU_SILENCE: (
        "RTU has no transaction id; a response after a silent turnaround pairs "
        "to the latest outstanding request on the same bus, unit and function, "
        "and a silence at least inter_frame_gap_ms closes the transaction. "
        "Retransmissions are requests repeated inside the same open transaction."
    ),
    RULE_BROADCAST: (
        "RTU unit id 0 is a broadcast write; slaves must not respond, so the "
        "transaction closes with accepted no-response instead of unmatched."
    ),
    RULE_EXCEPTION: (
        "Function code 0x80+ is an exception response. It pairs with its "
        "request but never yields successful register data or an empty sample."
    ),
    RULE_ADDRESS_DISPLAY: (
        "The wire and mapping layer use zero based addresses. One based "
        "addressing is a presentation-layer conversion only."
    ),
    RULE_WORD_ORDER: (
        "32 bit values name byte order in the two 16 bit words: ABCD, BADC, "
        "CDAB or DCBA; order is selected by mapping version/decision."
    ),
}

DEFAULT_PARAMETERS = {
    "label": "baseline-parameters",
    "description": "Initial Modbus pairing parameters.",
    "rtu": {
        "inter_frame_gap_ms": 3.5,
        "turnaround_ms": 50.0,
        "retransmission_ms": 200.0,
        "transaction_timeout_ms": 1000.0,
    },
}


@dataclass
class ParameterVersion:
    parameter_id: str
    version: str
    label: str
    rtu: dict[str, float]
    raw: dict[str, Any]
    digest: str
    parent_parameter_id: str | None = None
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "parameter_id": self.parameter_id,
            "version": self.version,
            "label": self.label,
            "parent_parameter_id": self.parent_parameter_id,
            "reason": self.reason,
            "rtu": self.rtu,
            "digest": self.digest,
        }


def _require_float(raw: dict[str, Any], key: str, location: dict[str, Any],
                   diagnostics: list[Diagnostic]) -> float:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        diagnostics.append(Diagnostic(
            "parameter_invalid", f"{key} must be a non negative number",
            {**location, "found": value}))
        return 0.0
    return float(value)


def parse_parameters(raw: dict[str, Any], *, source: str = "<parameters>") -> ParameterVersion:
    if not isinstance(raw, dict):
        raise DomainError(FAIL_FORMAT_CORRUPT, "parameters_not_object",
                          "parameters document must be an object",
                          [Diagnostic("parameters_not_object", "not an object",
                                      {"source": source})])
    version = raw.get("version")
    if not isinstance(version, str) or not version:
        raise DomainError(FAIL_FORMAT_CORRUPT, "parameter_version_missing",
                          "parameters.version is required",
                          [Diagnostic("parameter_version_missing",
                                      "version must be a non empty string",
                                      {"source": source})])
    rtu_raw = raw.get("rtu", {})
    if not isinstance(rtu_raw, dict):
        raise DomainError(FAIL_FORMAT_CORRUPT, "rtu_parameters_not_object",
                          "parameters.rtu must be an object",
                          [Diagnostic("rtu_parameters_not_object",
                                      "rtu section not object", {"source": source})])
    location = {"source": source, "document": version}
    diagnostics: list[Diagnostic] = []
    keys = ("inter_frame_gap_ms", "turnaround_ms", "retransmission_ms",
            "transaction_timeout_ms")
    rtu = {key: _require_float(rtu_raw, key, location, diagnostics) for key in keys}
    if diagnostics:
        raise DomainError(FAIL_FORMAT_CORRUPT, "parameters_invalid",
                          f"parameter version {version} invalid", diagnostics)
    parent = raw.get("parent_parameter_id")
    return ParameterVersion(
        parameter_id=raw.get("parameter_id") or stable_id("par", source, raw),
        version=version, label=str(raw.get("label", version)),
        rtu=rtu, raw=raw, digest=stable_id("pardg", source, raw),
        parent_parameter_id=parent, reason=str(raw.get("reason", "")),
    )
