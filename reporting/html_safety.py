"""Context-specific escaping helpers for self-contained HTML reports."""

import json
from typing import Any, Callable, Optional


def json_for_html_script(
    value: Any,
    *,
    default: Optional[Callable[[Any], Any]] = str,
) -> str:
    """Serialize JSON without allowing data to terminate an HTML script element."""
    serialized = json.dumps(value, default=default, ensure_ascii=True)
    return (
        serialized.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
