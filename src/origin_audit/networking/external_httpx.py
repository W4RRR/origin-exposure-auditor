"""Optional adapter for ProjectDiscovery httpx."""

from __future__ import annotations

import json
import shutil
import socket

# A resolved executable is called with fixed arguments, bounded stdin, and a timeout.
import subprocess  # nosec B404
from typing import Any

from origin_audit.exceptions import ConfigurationError
from origin_audit.models import ProviderResult, ProviderState
from origin_audit.providers.base import candidate_from_ip
from origin_audit.utils.domains import normalize_domain
from origin_audit.utils.ips import is_public_ip
from origin_audit.utils.timestamps import utc_now


def find_projectdiscovery_httpx() -> tuple[str, str] | None:
    """Return executable and version only when this is ProjectDiscovery httpx."""
    executable = shutil.which("httpx")
    if executable is None:
        return None
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            [executable, "-version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = f"{completed.stdout}\n{completed.stderr}".strip()
    lowered = output.lower()
    if completed.returncode != 0 or (
        "projectdiscovery" not in lowered and "current version" not in lowered
    ):
        return None
    return executable, output[:200]


def _hostname_is_public(hostname: str) -> bool:
    try:
        addresses = {
            str(item[4][0]) for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        }
    except OSError:
        return False
    return bool(addresses) and all(is_public_ip(item) for item in addresses)


def run_projectdiscovery_httpx(
    hostnames: list[str],
    *,
    timeout_seconds: float,
) -> ProviderResult:
    """Probe a bounded set of public, validated hostnames using external httpx."""
    status = find_projectdiscovery_httpx()
    if status is None:
        return ProviderResult(
            provider="projectdiscovery_httpx",
            state=ProviderState.SKIPPED,
            message="ProjectDiscovery httpx is not installed or was not identified",
            finished_at=utc_now(),
        )
    executable, version = status
    safe_hosts: list[str] = []
    for value in hostnames[:200]:
        try:
            hostname = normalize_domain(value)
        except ConfigurationError:
            continue
        if _hostname_is_public(hostname) and hostname not in safe_hosts:
            safe_hosts.append(hostname)
    if not safe_hosts:
        return ProviderResult(
            provider="projectdiscovery_httpx",
            state=ProviderState.SKIPPED,
            message="No related hostname resolved exclusively to public addresses",
            finished_at=utc_now(),
        )
    command = [
        executable,
        "-json",
        "-silent",
        "-status-code",
        "-title",
        "-server",
        "-tech-detect",
        "-no-color",
    ]
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            command,
            input="".join(f"https://{item}\n" for item in safe_hosts),
            capture_output=True,
            text=True,
            timeout=min(120.0, max(5.0, timeout_seconds * len(safe_hosts))),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ProviderResult(
            provider="projectdiscovery_httpx",
            state=ProviderState.FAILED,
            errors=[str(exc)],
            finished_at=utc_now(),
        )
    candidates = []
    for line in completed.stdout[:2_000_000].splitlines():
        try:
            row: Any = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        ips = row.get("a", [])
        if isinstance(ips, str):
            ips = [ips]
        for value in ips if isinstance(ips, list) else []:
            if not isinstance(value, str):
                continue
            candidate = candidate_from_ip(
                "projectdiscovery_httpx",
                value,
                evidence_type="external_http_probe",
                evidence_value=str(row.get("url") or row.get("input") or value),
                hostname=str(row.get("host") or row.get("input") or ""),
                notes=f"ProjectDiscovery httpx: {version}",
            )
            if candidate:
                candidates.append(candidate)
    state = ProviderState.OK if completed.returncode == 0 else ProviderState.FAILED
    errors = [] if completed.returncode == 0 else [f"httpx exit code {completed.returncode}"]
    return ProviderResult(
        provider="projectdiscovery_httpx",
        state=state,
        candidates=candidates,
        errors=errors,
        message=f"{len(safe_hosts)} related public hostnames probed; {version}",
        finished_at=utc_now(),
    )
