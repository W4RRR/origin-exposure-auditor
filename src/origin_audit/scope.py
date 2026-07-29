"""Authorization scope enforcement for active validation."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

from origin_audit.exceptions import ConfigurationError, ScopeError
from origin_audit.utils.domains import domain_matches, normalize_domain
from origin_audit.utils.ips import is_public_ip, normalize_ip


class ScopeConfig(BaseModel):
    """Explicit authorization policy for direct candidate connections."""

    authorized_domains: list[str] = Field(default_factory=list)
    authorized_ips: list[str] = Field(default_factory=list)
    excluded_domains: list[str] = Field(default_factory=list)
    excluded_ips: list[str] = Field(default_factory=list)
    allow_active_validation: bool = False
    allow_discovered_candidates: bool = False
    max_requests_per_second: float = Field(default=2.0, gt=0, le=20)
    max_concurrent_requests: int = Field(default=5, gt=0, le=20)
    request_timeout_seconds: float = Field(default=10.0, gt=0, le=60)

    @field_validator("authorized_ips", "excluded_ips")
    @classmethod
    def validate_networks(cls, values: list[str]) -> list[str]:
        """Validate IP or CIDR values."""
        for value in values:
            try:
                ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid IP/CIDR: {value}") from exc
        return values

    @field_validator("authorized_domains", "excluded_domains")
    @classmethod
    def validate_domains(cls, values: list[str]) -> list[str]:
        """Validate exact and wildcard domain rules."""
        for value in values:
            try:
                normalize_domain(value[2:] if value.startswith("*.") else value)
            except ConfigurationError as exc:
                raise ValueError(str(exc)) from exc
        return values

    def domain_is_authorized(self, domain: str) -> bool:
        """Return whether a domain is included and not excluded."""
        if any(domain_matches(domain, item) for item in self.excluded_domains):
            return False
        return any(domain_matches(domain, item) for item in self.authorized_domains)

    def ip_is_authorized(self, value: str) -> bool:
        """Return whether an IP is included (or discovery is allowed) and not excluded."""
        normalized = normalize_ip(value)
        address = ip_address(normalized)
        if any(address in ip_network(item, strict=False) for item in self.excluded_ips):
            return False
        if not is_public_ip(normalized):
            return False
        explicit = any(address in ip_network(item, strict=False) for item in self.authorized_ips)
        return explicit or self.allow_discovered_candidates

    def assert_active_allowed(self, domain: str, value: str) -> None:
        """Raise unless active validation is fully allowed."""
        if not self.allow_active_validation:
            raise ScopeError("Scope does not enable active validation")
        if not self.domain_is_authorized(domain):
            raise ScopeError(f"Domain is outside the authorized scope: {domain}")
        if not self.ip_is_authorized(value):
            raise ScopeError(f"Candidate IP is outside the authorized scope: {value}")


def load_scope(path: Path) -> ScopeConfig:
    """Load and validate a scope YAML file."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Unable to read scope {path}: {exc}") from exc
    try:
        return ScopeConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigurationError(f"Invalid scope: {exc}") from exc
