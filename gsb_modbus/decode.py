"""Register interpretation.

The wire always stores zero-based register addresses with 16-bit big-endian
register cells. Presentation may shift to one-based addresses; the derivation
never does.

32-bit values are evaluated under all four byte/word orders with NumPy. A
mapping that pins the order is authoritative; otherwise every legal candidate
is retained for the reviewer.
"""

from __future__ import annotations

import numpy as np

# (label, byte stride, byte offsets) for two big-endian-on-the-wire registers.
WORD_ORDERS = {
    "ABCD": (1, (0, 1, 2, 3)),
    "CDAB": (1, (2, 3, 0, 1)),
    "BADC": (1, (1, 0, 3, 2)),
    "DCBA": (1, (3, 2, 1, 0)),
}


def _np_u32(matrix: np.ndarray, offsets: tuple[int, ...]) -> np.ndarray:
    shifts = np.array([24, 16, 8, 0], dtype=np.uint32)
    return (matrix[:, list(offsets)].astype(np.uint32) << shifts).sum(axis=1, dtype=np.uint32)


def _i32(value: int) -> int:
    return value - 0x100000000 if value & 0x80000000 else value


def _scale(raw: float, mapping: dict) -> tuple[float, str | None]:
    try:
        gain = float(mapping.get("gain", 1.0))
        offset = float(mapping.get("offset", 0.0))
        return raw * gain + offset, None
    except (TypeError, ValueError) as exc:
        return raw, f"cannot apply scaling: {exc}"


def decode_candidates(register_values: list[int]) -> dict[str, int]:
    if len(register_values) < 2:
        return {}
    cells = np.asarray(register_values[:2], dtype=np.uint16)
    hi = ((cells & 0xFF00) >> 8).astype(np.uint8)
    lo = (cells & 0xFF).astype(np.uint8)
    matrix = np.stack([hi, lo], axis=0).T.reshape(1, 4)
    out: dict[str, int] = {}
    for label, (_, offsets) in WORD_ORDERS.items():
        out[label] = int(_np_u32(matrix, offsets)[0])
    return out


def interpret_registers(
    wire_address: int,
    register_values: list[int],
    mapping: dict | None,
    *,
    position: str,
) -> dict:
    """Interpret a contiguous register block against one mapping entry."""
    diagnostics: list[dict] = []
    width = len(register_values)
    result: dict = {
        "wire_address": wire_address,  # always zero-based
        "wire_address_end_exclusive": wire_address + width,
        "quantity": width,
        "raw_registers": register_values,
        "mapping_id": (mapping or {}).get("mapping_id"),
        "mapping_version": (mapping or {}).get("version"),
        "data_type": None,
        "unit": None,
        "value": None,
        "raw_value": None,
        "word_order": None,
        "candidates": {},
        "diagnostics": diagnostics,
    }
    if mapping is None:
        diagnostics.append(
            {
                "code": "unmapped_region",
                "message": f"no mapping entry covers register {wire_address}",
                "position": position,
                "severity": "warning",
            }
        )
        return result

    dtype = str(mapping.get("data_type", "u16"))
    result["data_type"] = dtype
    result["unit"] = mapping.get("unit")
    needs = 2 if dtype in ("u32", "s32", "float32") else 1
    if width < needs:
        diagnostics.append(
            {
                "code": "register_block_truncated",
                "message": f"{dtype} needs {needs} register(s), block has {width}",
                "position": position,
                "severity": "error",
            }
        )
        return result

    if dtype == "u16":
        raw = register_values[0]
        val, err = _scale(float(raw), mapping)
        result.update(raw_value=raw, value=val)
    elif dtype == "s16":
        raw = register_values[0] - 0x10000 if register_values[0] & 0x8000 else register_values[0]
        val, err = _scale(float(raw), mapping)
        result.update(raw_value=raw, value=val)
    elif dtype in ("u32", "s32", "float32"):
        cells = np.asarray(register_values[:2], dtype=np.uint16)
        hi = ((cells & 0xFF00) >> 8).astype(np.uint8)
        lo = (cells & 0xFF).astype(np.uint8)
        matrix = np.stack([hi, lo], axis=0).T.reshape(1, 4)
        candidates: dict[str, float | int] = {}
        for label, (_, offsets) in WORD_ORDERS.items():
            u = int(_np_u32(matrix, offsets)[0])
            if dtype == "u32":
                candidates[label] = u
            elif dtype == "s32":
                candidates[label] = _i32(u)
            else:
                candidates[label] = float(np.frombuffer(np.uint32(u).tobytes(), dtype=">f4")[0])
        result["candidates"] = {k: v for k, v in candidates.items()}
        order = mapping.get("word_order")
        if order not in WORD_ORDERS:
            diagnostics.append(
                {
                    "code": "word_order_ambiguous",
                    "message": (
                        "mapping does not pin word_order; all legal byte/word order "
                        "candidates retained"
                    ),
                    "position": position + ".word_order",
                    "severity": "warning",
                }
            )
        else:
            raw = candidates[order]
            if dtype == "float32" and not np.isfinite(raw):
                diagnostics.append(
                    {
                        "code": "non_finite_float",
                        "message": f"{order} decodes to a non-finite float; left in place",
                        "position": position + ".value",
                        "severity": "error",
                    }
                )
                result["raw_value"] = None
                result["word_order"] = order
            else:
                val, err = _scale(float(raw), mapping)
                result.update(raw_value=raw, value=val, word_order=order)
    elif dtype == "u16_enum":
        raw = register_values[0]
        labels = mapping.get("enum", {})
        result.update(raw_value=raw, value=labels.get(str(raw)))
        if result["value"] is None:
            diagnostics.append(
                {
                    "code": "enum_value_unknown",
                    "message": f"enum has no label for {raw}",
                    "position": position + ".value",
                    "severity": "warning",
                }
            )
    else:
        diagnostics.append(
            {
                "code": "unsupported_data_type",
                "message": f"data_type {dtype} cannot be interpreted",
                "position": position + ".data_type",
                "severity": "error",
            }
        )
    if result.get("diagnostics") and mapping.get("valid_range"):
        pass
    vr = mapping.get("valid_range")
    if vr is not None and result.get("value") is not None:
        lo, hi = float(vr[0]), float(vr[1])
        if not (lo <= float(result["value"]) <= hi):
            diagnostics.append(
                {
                    "code": "value_out_of_range",
                    "message": f"value {result['value']} outside valid range [{lo}, {hi}]",
                    "position": position + ".value",
                    "severity": "warning",
                }
            )
    return result
