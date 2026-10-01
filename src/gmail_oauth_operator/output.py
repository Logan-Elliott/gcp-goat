"""Terminal-safe output helpers."""

from __future__ import annotations

import json
import unicodedata
from typing import Any


def safe_text(value: Any, *, multiline: bool = False) -> str:
    """Remove terminal control characters from mailbox-controlled text."""
    text = str(value)
    allowed = {"\n", "\r", "\t"} if multiline else set()
    return "".join(
        char for char in text if char in allowed or not unicodedata.category(char).startswith("C")
    )


def print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))
