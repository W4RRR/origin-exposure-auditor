"""Shared test helpers."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from origin_audit.cache import JsonCache
from origin_audit.config import AppConfig, ProviderSettings
from origin_audit.providers.base import ProviderContext


class FakeTransport:
    """Minimal queued provider transport."""

    def __init__(self, *responses: dict[str, Any] | list[Any] | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def _next(self) -> dict[str, Any] | list[Any]:
        if not self.responses:
            raise AssertionError("No queued fake response")
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    async def get_json(self, url: str, **kwargs: Any) -> dict[str, Any] | list[Any]:
        self.calls.append(("GET", url, kwargs))
        return self._next()

    async def post_json(self, url: str, **kwargs: Any) -> dict[str, Any] | list[Any]:
        self.calls.append(("POST", url, kwargs))
        return self._next()


@pytest.fixture
def app_config(tmp_path: Path) -> AppConfig:
    """Fast retry-free test configuration."""
    return AppConfig(
        timeout_seconds=1,
        concurrency=2,
        cache_dir=tmp_path / "cache",
        output_dir=tmp_path / "output",
        providers={
            name: ProviderSettings(max_retries=0, max_pages=2, requests_per_second=1000)
            for name in (
                "ct",
                "virustotal",
                "otx",
                "urlscan",
                "shodan",
                "censys",
                "securitytrails",
                "fofa",
                "viewdns",
            )
        },
    )


@pytest.fixture
def context_factory(app_config: AppConfig) -> Iterator[Any]:
    """Build provider contexts with queued transport responses."""

    def factory(
        *responses: dict[str, Any] | list[Any] | Exception,
        environment: dict[str, str] | None = None,
        save_raw: bool = False,
    ) -> tuple[ProviderContext, FakeTransport]:
        transport = FakeTransport(*responses)
        context = ProviderContext(
            config=app_config,
            environment=environment or {},
            transport=transport,  # type: ignore[arg-type]
            save_raw_responses=save_raw,
        )
        return context, transport

    yield factory


@pytest.fixture
def json_cache(tmp_path: Path) -> JsonCache:
    return JsonCache(tmp_path / "cache")
