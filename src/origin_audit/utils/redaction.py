"""Secret redaction helpers."""

import re
from collections.abc import Mapping
from typing import Any

_SECRET_KEYS = re.compile(r"(api[_-]?key|token|secret|password|authorization)", re.I)
_URL_SECRET = re.compile(
    r"([?&](?:api[_-]?key|apikey|key|token|secret|password|authorization)=)"
    r"([^&#\s\"']+)",
    re.I,
)
_BEARER_SECRET = re.compile(r"(\bBearer\s+)([A-Za-z0-9._~+/=-]+)", re.I)


def redact_secret(value: str, *, show_suffix: bool = False) -> str:
    """Redact a secret, optionally retaining at most four trailing characters."""
    if not value:
        return ""
    if show_suffix and len(value) > 4:
        return f"***{value[-4:]}"
    return "***REDACTED***"


def redact_mapping(value: Any) -> Any:
    """Recursively redact values whose keys look secret-bearing."""
    if isinstance(value, Mapping):
        return {
            str(key): redact_secret(str(item))
            if _SECRET_KEYS.search(str(key))
            else redact_mapping(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_mapping(item) for item in value]
    return value


def redact_text(value: str) -> str:
    """Redact common secret-bearing URL parameters and bearer tokens."""
    redacted = _URL_SECRET.sub(r"\1***REDACTED***", value)
    return _BEARER_SECRET.sub(r"\1***REDACTED***", redacted)
