"""Human and JSON logging with secret redaction."""

from __future__ import annotations

import json
import logging
from typing import Any

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


def configure_logging(level: str, *, json_logs: bool = False, quiet: bool = False) -> None:
    """Configure process logging once."""
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.ERROR if quiet else getattr(logging, level.upper()))
    handler = logging.StreamHandler()
    handler.setFormatter(
        JsonFormatter() if json_logs else logging.Formatter("%(levelname)s %(message)s")
    )
    root.addHandler(handler)
