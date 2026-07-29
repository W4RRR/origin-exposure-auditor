"""Human and JSON logging with secret redaction."""

from __future__ import annotations

import json
import logging
from typing import Any, ClassVar

from origin_audit.utils.redaction import redact_mapping
from origin_audit.utils.timestamps import utc_now


class JsonFormatter(logging.Formatter):
    """Emit one redacted JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": utc_now().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "event_data"):
            payload["event_data"] = redact_mapping(record.event_data)
        return json.dumps(payload, ensure_ascii=False)


class ColorFormatter(logging.Formatter):
    """Apply ANSI colors to human-readable log levels."""

    COLORS: ClassVar[dict[int, str]] = {
        logging.DEBUG: "\033[36m",
        logging.INFO: "\033[32m",
        logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m",
        logging.CRITICAL: "\033[1;31m",
    }
    RESET: ClassVar[str] = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        prefix = self.COLORS.get(record.levelno, "")
        return f"{prefix}{message}{self.RESET}" if prefix else message


def configure_logging(
    level: str,
    *,
    json_logs: bool = False,
    quiet: bool = False,
    color: bool = False,
) -> None:
    """Configure process logging once."""
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.ERROR if quiet else getattr(logging, level.upper()))
    handler = logging.StreamHandler()
    if json_logs:
        formatter: logging.Formatter = JsonFormatter()
    elif color:
        formatter = ColorFormatter("%(levelname)s %(message)s")
    else:
        formatter = logging.Formatter("%(levelname)s %(message)s")
    handler.setFormatter(formatter)
    root.addHandler(handler)
