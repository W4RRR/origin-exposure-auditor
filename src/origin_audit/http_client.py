"""Bounded HTTP transport with cache, retries, and rate limiting."""

from __future__ import annotations

import asyncio
import secrets
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, cast
from urllib.parse import urlparse

import httpx

from origin_audit.cache import JsonCache
from origin_audit.exceptions import ProviderError
from origin_audit.rate_limit import AsyncRateLimiter

_RETRYABLE = {429, 500, 502, 503, 504}


def retry_after_seconds(response: httpx.Response) -> float | None:
    """Parse a Retry-After seconds or HTTP-date header."""
    value = response.headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
            return max(0.0, (parsed - datetime.now(parsed.tzinfo)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None


class ProviderHTTPClient:
    """HTTP JSON client shared by a single provider."""

    def __init__(
        self,
        *,
        client: httpx.AsyncClient,
        cache: JsonCache,
        provider: str,
        rate: float,
        max_retries: int,
        cache_ttl_hours: int,
    ) -> None:
        self.client = client
        self.cache = cache
        self.provider = provider
        self.limiter = AsyncRateLimiter(rate)
        self.max_retries = max_retries
        self.cache_ttl = timedelta(hours=cache_ttl_hours)

    async def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cache_parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """GET JSON with bounded retry and a secret-free cache key."""
        return await self._request_json(
            "GET",
            url,
            params=params,
            headers=headers,
            cache_parameters=cache_parameters,
        )

    async def post_json(
        self,
        url: str,
        *,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
        cache_parameters: dict[str, Any] | None = None,
        cacheable: bool = True,
    ) -> dict[str, Any] | list[Any]:
        """POST JSON with bounded retry."""
        return await self._request_json(
            "POST",
            url,
            json=payload,
            headers=headers,
            cache_parameters=cache_parameters or payload,
            cacheable=cacheable,
        )

    async def _request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cache_parameters: dict[str, Any] | None = None,
        cacheable: bool = True,
    ) -> dict[str, Any] | list[Any]:
        parsed = urlparse(url)
        operation = f"{method.lower()}-{parsed.netloc}{parsed.path}".replace("/", "_")
        key = self.cache.key(self.provider, operation, cache_parameters or params or {})
        if (
            cacheable
            and (cached := self.cache.get(key, self.cache_ttl)) is not None
            and isinstance(cached, (dict, list))
        ):
            return cast(dict[str, Any] | list[Any], cached)
        response: httpx.Response | None = None
        for attempt in range(self.max_retries + 1):
            await self.limiter.acquire()
            try:
                response = await self.client.request(
                    method, url, params=params, json=json, headers=headers
                )
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt >= self.max_retries:
                    raise ProviderError(f"Network failure after retries: {exc}") from exc
                await asyncio.sleep(_backoff(attempt))
                continue
            if response.status_code not in _RETRYABLE:
                break
            if attempt >= self.max_retries:
                break
            delay = retry_after_seconds(response)
            await asyncio.sleep(delay if delay is not None else _backoff(attempt))
        if response is None:
            raise ProviderError("Provider did not return a response")
        if response.status_code in {401, 403}:
            raise ProviderError(
                f"Provider denied access ({response.status_code}); check key and plan permissions"
            )
        if response.status_code == 404:
            raise ProviderError("Provider resource was not found (404)")
        if response.status_code == 429:
            raise ProviderError("Provider rate limit was exceeded after bounded retries (429)")
        if response.status_code >= 400:
            raise ProviderError(f"Provider returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("Provider returned invalid JSON") from exc
        if not isinstance(data, (dict, list)):
            raise ProviderError("Provider JSON root is not an object or array")
        if cacheable:
            self.cache.set(key, data)
        return data


def _backoff(attempt: int) -> float:
    jitter = secrets.randbelow(251) / 1000
    return min(8.0, float(2**attempt) + jitter)
