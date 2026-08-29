"""Inca-style decimal encoding for commercial khipu.

Place on the cord is a power of ten. Cluster size is the digit. 0 is an empty
band. MODELED commercial khipu — not a live lake total.
"""

from __future__ import annotations

from typing import Any

PLACES: tuple[tuple[int, str], ...] = (
    (100000, "100k"),
    (10000, "10k"),
    (1000, "1k"),
    (100, "100"),
    (10, "10"),
    (1, "1"),
)


def encode_decimal(n: int | float) -> list[dict[str, Any]]:
    abs_n = max(0, int(round(float(n))))
    return [
        {"place": place, "label": label, "digit": (abs_n // place) % 10}
        for place, label in PLACES
    ]


def decode_decimal(digits: list[dict[str, Any]]) -> int:
    return sum(int(d["digit"]) * int(d["place"]) for d in digits)


def value_cords(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["digits"] = encode_decimal(row.get("usd", 0))
        out.append(item)
    return out
