"""Small local JSON cache with TTL and atomic writes."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


class JsonCache:
    """Filesystem-backed cache that never stores request headers or secrets."""

    def __init__(self, root: Path, enabled: bool = True) -> None:
        self.root = root
        self.enabled = enabled

    @staticmethod
    def key(provider: str, operation: str, public_parameters: dict[str, Any]) -> str:
        """Build a deterministic key from non-secret request parameters."""
        payload = json.dumps(public_parameters, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode()).hexdigest()
        return f"{provider}/{operation}-{digest}.json"

    def get(self, key: str, ttl: timedelta) -> Any | None:
        """Return a fresh cached value or ``None``."""
        if not self.enabled:
            return None
        path = self.root / key
        try:
            modified = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
            if datetime.now(UTC) - modified > ttl:
                return None
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def set(self, key: str, value: Any) -> None:
        """Atomically store a JSON-serializable value."""
        if not self.enabled:
            return
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".cache-", text=True)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False, separators=(",", ":"))
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
