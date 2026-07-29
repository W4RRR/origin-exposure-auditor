"""Common provider contract and parsing helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from origin_audit.config import AppConfig
from origin_audit.http_client import ProviderHTTPClient
from origin_audit.models import CandidateIP, Evidence, ProviderResult, ProviderState, Target
from origin_audit.utils.ips import normalize_ip
from origin_audit.utils.timestamps import utc_now


class ProviderContext:
    """Dependencies made available to a provider."""

    def __init__(
        self,
        *,
        config: AppConfig,
        environment: dict[str, str],
        transport: ProviderHTTPClient,
        save_raw_responses: bool = False,
    ) -> None:
        self.config = config
        self.environment = environment
        self.transport = transport
        self.save_raw_responses = save_raw_responses


class Provider(ABC):
    """Asynchronous provider interface."""

    name: str
    required_environment: tuple[str, ...] = ()

    async def is_available(self, context: ProviderContext) -> bool:
        """Return whether required credentials are configured."""
        return all(context.environment.get(item) for item in self.required_environment)

    def unavailable_result(self) -> ProviderResult:
        """Build a consistent skipped result."""
        missing = ", ".join(self.required_environment)
        return ProviderResult(
            provider=self.name,
            state=ProviderState.SKIPPED,
            message=f"{missing} is not configured",
            finished_at=utc_now(),
        )

    @abstractmethod
    async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
        """Collect bounded evidence for a target."""


def parse_datetime(value: Any) -> datetime | None:
    """Parse common provider timestamps without throwing."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (ValueError, OSError, OverflowError):
            return None
    if isinstance(value, str):
        cleaned = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(cleaned)
        except ValueError:
            try:
                parsed = datetime.strptime(value[:10], "%Y-%m-%d").replace(tzinfo=UTC)
            except ValueError:
                return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def candidate_from_ip(
    provider: str,
    value: str,
    *,
    evidence_type: str,
    evidence_value: str,
    observed_at: datetime | None = None,
    hostname: str | None = None,
    ports: list[int] | None = None,
    asn: str | None = None,
    organization: str | None = None,
    country: str | None = None,
    notes: str | None = None,
) -> CandidateIP | None:
    """Build a candidate, returning ``None`` for malformed provider data."""
    try:
        normalized = normalize_ip(value)
    except Exception:
        return None
    evidence = Evidence(
        source=provider,
        type=evidence_type,
        value=evidence_value,
        observed_at=observed_at,
        notes=notes,
    )
    return CandidateIP(
        ip=normalized,
        sources=[provider],
        first_seen=observed_at,
        last_seen=observed_at,
        hostnames=[hostname] if hostname else [],
        ports=ports or [],
        asn=asn,
        organization=organization,
        country=country,
        evidence=[evidence],
    )


def failed_result(provider: str, error: Exception) -> ProviderResult:
    """Convert an expected provider failure to a non-fatal result."""
    return ProviderResult(
        provider=provider,
        state=ProviderState.FAILED,
        errors=[str(error)],
        finished_at=utc_now(),
    )
