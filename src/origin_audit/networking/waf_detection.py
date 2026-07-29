"""Conservative WAF/CDN indicator detection."""

from __future__ import annotations

import json
import shutil

# Subprocesses use a resolved executable, argument arrays, and strict timeouts.
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

import httpx
import yaml

from origin_audit.models import HttpObservation, WAFDetection


def load_provider_indicators(path: Path) -> dict[str, dict[str, list[str]]]:
    """Load non-secret, configurable response indicators."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    providers = data.get("providers", {}) if isinstance(data, dict) else {}
    return providers if isinstance(providers, dict) else {}


def detect_from_observation(
    observation: HttpObservation,
    headers: httpx.Headers | dict[str, str] | None,
    indicators: dict[str, dict[str, list[str]]],
) -> WAFDetection:
    """Match bounded passive response fields against configured indicators."""
    detected: list[str] = []
    reasons: list[str] = []
    lowered = {key.lower(): value.lower() for key, value in (headers or {}).items()}
    server = (observation.server or "").lower()
    cookies = lowered.get("set-cookie", "")
    for provider, rules in indicators.items():
        header_markers = [item.lower() for item in rules.get("headers", [])]
        server_markers = [item.lower() for item in rules.get("server", [])]
        cookie_markers = [item.lower() for item in rules.get("cookies", [])]
        matches = [f"header:{marker}" for marker in header_markers if marker in lowered]
        matches += [f"server:{marker}" for marker in server_markers if marker in server]
        matches += [f"cookie:{marker}" for marker in cookie_markers if marker in cookies]
        if matches:
            detected.append(provider)
            reasons.extend(f"{provider}:{item}" for item in matches)
    return WAFDetection(
        detected=bool(detected),
        providers=sorted(set(detected)),
        indicators=sorted(set(reasons)),
    )


def run_wafw00f(domain: str, timeout: float) -> WAFDetection | None:
    """Run optional wafw00f safely with an argument list and timeout."""
    executable = shutil.which("wafw00f")
    if executable is None:
        return None
    try:
        version = subprocess.run(  # noqa: S603  # nosec B603
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=min(timeout, 5),
            check=False,
        )
        completed = subprocess.run(  # noqa: S603  # nosec B603
            [executable, f"https://{domain}", "-a", "-f", "json"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    providers: list[str] = []
    try:
        payload: Any = json.loads(completed.stdout)
        rows = payload if isinstance(payload, list) else [payload]
        for row in rows:
            if isinstance(row, dict):
                values = row.get("detected") or row.get("firewall")
                if isinstance(values, list):
                    providers.extend(str(item) for item in values)
                elif values:
                    providers.append(str(values))
    except json.JSONDecodeError:
        if "is behind" in completed.stdout.lower():
            providers.append("wafw00f-detected")
    version_text = (version.stdout or version.stderr).strip()[:100]
    return WAFDetection(
        detected=bool(providers),
        providers=sorted(set(providers)),
        indicators=[f"wafw00f exit={completed.returncode}"],
        external_tool=version_text or "wafw00f",
    )
