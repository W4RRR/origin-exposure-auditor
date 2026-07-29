"""Configuration and environment loading with explicit precedence."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import dotenv_values
from pydantic import BaseModel, Field, ValidationError

from origin_audit.exceptions import ConfigurationError

DEFAULT_CONFIG_PATH = Path("config.yml")
USER_ENV_PATH = Path.home() / ".config" / "origin-exposure-auditor" / ".env"
_PROVIDER_DEFAULTS: dict[str, dict[str, object]] = {
    "securitytrails": {
        "requests_per_second": 0.2,
        "max_retries": 0,
        "cache_ttl_hours": 24,
    },
}


class ProviderSettings(BaseModel):
    """Per-provider transport controls."""

    enabled: bool = True
    requests_per_second: float = 1.0
    max_retries: int = 3
    cache_ttl_hours: int = 12
    max_pages: int = 3
    query_template: str | None = None


class ScoringSettings(BaseModel):
    """Explainable scoring weights and thresholds."""

    historical_dns: float = 25
    certificate_match: float = 20
    favicon_match: float = 15
    body_hash_match: float = 25
    title_match: float = 8
    multi_source_bonus: float = 10
    hostname_match: float = 8
    current_dns: float = -15
    known_cdn_range: float = -40
    unrelated_certificate: float = -25
    generic_cloud_page: float = -10
    stale_observation: float = -8
    confirmed_threshold: float = 80
    high_threshold: float = 60
    medium_threshold: float = 35
    low_threshold: float = 1


class AppConfig(BaseModel):
    """Complete application configuration."""

    timeout_seconds: float = 10.0
    concurrency: int = 5
    rate_limit: float = 2.0
    user_agent: str = "origin-exposure-auditor/0.2.2"
    max_response_bytes: int = 2_000_000
    max_redirects: int = 5
    cache_dir: Path = Path("cache")
    output_dir: Path = Path("output")
    providers: dict[str, ProviderSettings] = Field(default_factory=dict)
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)

    def provider(self, name: str) -> ProviderSettings:
        """Return explicit settings or safe provider defaults."""
        if name in self.providers:
            return self.providers[name]
        return ProviderSettings.model_validate(_PROVIDER_DEFAULTS.get(name, {}))


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Unable to read config {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError(f"Configuration root must be a mapping: {path}")
    return raw


def load_config(path: Path | None = None) -> AppConfig:
    """Load YAML configuration or defaults if no file is present."""
    selected = path
    if selected is None and DEFAULT_CONFIG_PATH.exists():
        selected = DEFAULT_CONFIG_PATH
    try:
        return AppConfig.model_validate(_read_yaml(selected) if selected else {})
    except ValidationError as exc:
        raise ConfigurationError(f"Invalid configuration: {exc}") from exc


def load_environment(env_file: Path | None = None) -> dict[str, str]:
    """Load secrets with precedence: system, explicit file, cwd, user file."""
    merged: dict[str, str] = {}
    candidates = [USER_ENV_PATH, Path.cwd() / ".env"]
    if env_file is not None:
        candidates.append(env_file)
    for candidate in candidates:
        if not candidate.exists():
            continue
        values = dotenv_values(candidate)
        merged.update({key: value for key, value in values.items() if value is not None})
    merged.update(os.environ)
    return merged


def validate_config_file(path: Path) -> AppConfig:
    """Validate and return a configuration file."""
    if not path.exists():
        raise ConfigurationError(f"Configuration file does not exist: {path}")
    return load_config(path)
