"""HTTP transport, rate limit, network helper, and active validation tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import dns.resolver
import httpx
import pytest

from origin_audit.cache import JsonCache
from origin_audit.exceptions import ProviderError
from origin_audit.http_client import ProviderHTTPClient, retry_after_seconds
from origin_audit.models import CandidateIP, FaviconEvidence, HttpObservation
from origin_audit.networking.active_validation import validate_candidate
from origin_audit.networking.dns import resolve_related_hostnames
from origin_audit.networking.external_httpx import (
    find_projectdiscovery_httpx,
    run_projectdiscovery_httpx,
)
from origin_audit.networking.favicon import discover_icon_urls, fetch_favicon
from origin_audit.networking.http_probe import detect_technologies, extract_title, probe
from origin_audit.networking.tls import _parse_cert, fetch_certificate
from origin_audit.networking.waf_detection import (
    detect_from_observation,
    load_provider_indicators,
    run_wafw00f,
)
from origin_audit.rate_limit import AsyncRateLimiter
from origin_audit.scope import ScopeConfig


def make_provider_client(
    tmp_path: Path,
    handler: Any,
    *,
    retries: int = 0,
    cache: bool = True,
) -> tuple[ProviderHTTPClient, httpx.AsyncClient]:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = ProviderHTTPClient(
        client=client,
        cache=JsonCache(tmp_path / "cache", enabled=cache),
        provider="test",
        rate=1000,
        max_retries=retries,
        cache_ttl_hours=1,
    )
    return provider, client


@pytest.mark.asyncio
async def test_provider_http_success_and_cache(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"ok": True}, request=request)

    provider, client = make_provider_client(tmp_path, handler)
    first = await provider.get_json(
        "https://example.com/api", cache_parameters={"domain": "example.com"}
    )
    second = await provider.get_json(
        "https://example.com/api", cache_parameters={"domain": "example.com"}
    )
    assert first == second == {"ok": True}
    assert calls == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_provider_http_list_and_post(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"ok": True}], request=request)

    provider, client = make_provider_client(tmp_path, handler)
    assert await provider.post_json(
        "https://example.com/api", payload={"query": "example.com"}
    ) == [{"ok": True}]
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "message"),
    [
        (401, "denied"),
        (403, "denied"),
        (404, "not found"),
        (429, "rate limit"),
        (500, "HTTP 500"),
    ],
)
async def test_provider_http_errors(tmp_path: Path, status: int, message: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": "x"}, request=request)

    provider, client = make_provider_client(tmp_path, handler)
    with pytest.raises(ProviderError, match=message):
        await provider.get_json("https://example.com/api")
    await client.aclose()


@pytest.mark.asyncio
async def test_provider_http_invalid_json_and_root(tmp_path: Path) -> None:
    responses = iter(
        [
            httpx.Response(200, text="not-json"),
            httpx.Response(200, json="string"),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        response = next(responses)
        response.request = request
        return response

    provider, client = make_provider_client(tmp_path, handler, cache=False)
    with pytest.raises(ProviderError, match="invalid JSON"):
        await provider.get_json("https://example.com/one")
    with pytest.raises(ProviderError, match="object or array"):
        await provider.get_json("https://example.com/two")
    await client.aclose()


@pytest.mark.asyncio
async def test_provider_http_network_failure(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    provider, client = make_provider_client(tmp_path, handler)
    with pytest.raises(ProviderError, match="Network failure"):
        await provider.get_json("https://example.com/api")
    await client.aclose()


def test_retry_after_parsing() -> None:
    response = httpx.Response(429, headers={"retry-after": "2"})
    assert retry_after_seconds(response) == 2
    response = httpx.Response(429, headers={"retry-after": "bad"})
    assert retry_after_seconds(response) is None
    assert retry_after_seconds(httpx.Response(429)) is None


@pytest.mark.asyncio
async def test_rate_limiter() -> None:
    limiter = AsyncRateLimiter(1000)
    await limiter.acquire()
    async with limiter:
        pass
    with pytest.raises(ValueError):
        AsyncRateLimiter(0)


def test_http_parsing() -> None:
    body = b"<html><title>  Example \n Site </title><div>wp-content</div></html>"
    assert extract_title(body) == "Example Site"
    assert extract_title(b"<html></html>") is None
    headers = httpx.Headers({"server": "nginx", "x-powered-by": "Django"})
    assert detect_technologies(headers, body) == ["django", "nginx", "wordpress"]


@pytest.mark.asyncio
async def test_probe_bounded_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={
                "server": "Example",
                "content-type": "text/html",
                "location": "/next",
            },
            content=b"<title>Example</title>" + b"x" * 100,
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        observation, body = await probe(client, url="https://example.com/", maximum_bytes=40)
    assert observation.status_code == 302
    assert observation.title == "Example"
    assert observation.final_url == "https://example.com/next"
    assert len(body) == 40


@pytest.mark.asyncio
async def test_probe_rejects_unsafe_scheme_and_ip() -> None:
    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="Only HTTP"):
            await probe(client, url="ftp://example.com/", maximum_bytes=10)
        with pytest.raises(ValueError, match="non-public"):
            await probe(client, url="http://192.0.2.10/", maximum_bytes=10)


def test_favicon_discovery() -> None:
    body = (
        b'<link rel="icon" href="/icon.png">'
        b'<link rel="shortcut icon" href="https://example.org/third.ico">'
    )
    urls = discover_icon_urls("https://example.com/path", body)
    assert urls == ["https://example.com/favicon.ico", "https://example.com/icon.png"]


@pytest.mark.asyncio
async def test_fetch_favicon() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"icon", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await fetch_favicon(client, ["https://example.com/favicon.ico"])
    assert result is not None
    assert result.size == 4
    assert len(result.sha256) == 64


def test_tls_certificate_parser() -> None:
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("commonName", "Example CA"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "api.example.com")),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Jan  1 00:00:00 2027 GMT",
    }
    parsed = _parse_cert(cert, b"certificate", "test")
    assert parsed.common_name == "example.com"
    assert parsed.issuer == "Example CA"
    assert parsed.san == ["example.com", "api.example.com"]
    assert parsed.not_after == datetime(2027, 1, 1, tzinfo=UTC)


@pytest.mark.asyncio
async def test_fetch_certificate_with_fake_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SSLObject:
        def getpeercert(self, binary_form: bool = False) -> Any:
            if binary_form:
                return b"certificate"
            return {
                "subject": ((("commonName", "example.com"),),),
                "issuer": ((("commonName", "Example CA"),),),
                "subjectAltName": (("DNS", "example.com"),),
            }

    class Writer:
        closed = False

        def get_extra_info(self, name: str) -> Any:
            assert name == "ssl_object"
            return SSLObject()

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            return None

    writer = Writer()

    async def fake_open(*args: Any, **kwargs: Any) -> tuple[asyncio.StreamReader, Writer]:
        return asyncio.StreamReader(), writer

    monkeypatch.setattr("origin_audit.networking.tls.asyncio.open_connection", fake_open)
    certificate = await fetch_certificate(
        "example.com",
        server_name="example.com",
        timeout_seconds=1,
    )
    assert certificate.common_name == "example.com"
    assert writer.closed
    with pytest.raises(ValueError, match="non-public"):
        await fetch_certificate(
            "192.0.2.10",
            server_name="example.com",
            timeout_seconds=1,
        )


def test_waf_detection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "providers.yml"
    path.write_text(
        "providers:\n  edge:\n    headers: [x-edge]\n    server: [edge]\n    cookies: []\n",
        encoding="utf-8",
    )
    indicators = load_provider_indicators(path)
    detected = detect_from_observation(
        HttpObservation(url="https://example.com", server="edge"),
        {"x-edge": "yes"},
        indicators,
    )
    assert detected.detected
    assert detected.providers == ["edge"]
    monkeypatch.setattr("origin_audit.networking.waf_detection.shutil.which", lambda _: None)
    assert run_wafw00f("example.com", 1) is None


def test_wafw00f_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    class Completed:
        def __init__(self, stdout: str, returncode: int = 0) -> None:
            self.stdout = stdout
            self.stderr = ""
            self.returncode = returncode

    def fake_run(*args: Any, **kwargs: Any) -> Completed:
        nonlocal calls
        calls += 1
        if calls == 1:
            return Completed("wafw00f 2.3")
        return Completed('[{"detected": ["Example WAF"]}]')

    monkeypatch.setattr("origin_audit.networking.waf_detection.shutil.which", lambda _: "wafw00f")
    monkeypatch.setattr("origin_audit.networking.waf_detection.subprocess.run", fake_run)
    result = run_wafw00f("example.com", 1)
    assert result is not None
    assert result.detected
    assert result.providers == ["Example WAF"]


@pytest.mark.asyncio
async def test_resolve_related_hostnames(monkeypatch: pytest.MonkeyPatch) -> None:
    class Item:
        def __init__(self, value: str) -> None:
            self.value = value

        def to_text(self) -> str:
            return self.value

    class Resolver:
        lifetime = 0.0

        async def resolve(self, hostname: str, record_type: str, search: bool) -> list[Item]:
            assert search is False
            if record_type == "A":
                return [Item("203.0.113.30")]
            raise dns.resolver.NoAnswer

    monkeypatch.setattr("origin_audit.networking.dns.dns.asyncresolver.Resolver", Resolver)
    candidates = await resolve_related_hostnames(
        ["api.example.com", "example.org"],
        "example.com",
        timeout_seconds=1,
        concurrency=2,
    )
    assert [item.ip for item in candidates] == ["203.0.113.30"]


def test_projectdiscovery_httpx_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("origin_audit.networking.external_httpx.shutil.which", lambda _: None)
    assert find_projectdiscovery_httpx() is None

    class Completed:
        def __init__(self, stdout: str, returncode: int = 0) -> None:
            self.stdout = stdout
            self.stderr = ""
            self.returncode = returncode

    calls = 0

    def fake_run(*args: Any, **kwargs: Any) -> Completed:
        nonlocal calls
        calls += 1
        if calls == 1:
            return Completed("ProjectDiscovery httpx Current Version: 1.7.0")
        return Completed(
            '{"url":"https://example.com","host":"example.com","a":["203.0.113.31"]}\n'
        )

    monkeypatch.setattr("origin_audit.networking.external_httpx.shutil.which", lambda _: "httpx")
    monkeypatch.setattr("origin_audit.networking.external_httpx.subprocess.run", fake_run)
    monkeypatch.setattr(
        "origin_audit.networking.external_httpx._hostname_is_public", lambda _: True
    )
    result = run_projectdiscovery_httpx(["example.com"], timeout_seconds=1)
    assert result.state == "ok"
    assert result.candidates[0].ip == "203.0.113.31"


@pytest.mark.asyncio
async def test_active_validation_comparisons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate_observation = HttpObservation(
        url="https://203.0.113.10/",
        status_code=200,
        title="Example",
        body_sha256="same",
    )
    baseline = HttpObservation(
        url="https://example.com/",
        status_code=200,
        title="Example",
        body_sha256="same",
    )
    favicon = FaviconEvidence(
        source_url="https://203.0.113.10/favicon.ico",
        md5="m",
        sha256="icon",
        mmh3=1,
        size=4,
    )

    async def fake_probe(*args: Any, **kwargs: Any) -> tuple[HttpObservation, bytes]:
        return candidate_observation, b"<html></html>"

    async def fake_favicon(*args: Any, **kwargs: Any) -> FaviconEvidence:
        return favicon

    async def fake_certificate(*args: Any, **kwargs: Any) -> Any:
        return _parse_cert(
            {
                "subject": ((("commonName", "example.com"),),),
                "issuer": ((("commonName", "Example CA"),),),
                "subjectAltName": (("DNS", "example.com"),),
            },
            b"cert",
            "active_validation",
        )

    monkeypatch.setattr("origin_audit.networking.active_validation.probe", fake_probe)
    monkeypatch.setattr("origin_audit.networking.active_validation.fetch_favicon", fake_favicon)
    monkeypatch.setattr(
        "origin_audit.networking.active_validation.fetch_certificate", fake_certificate
    )
    monkeypatch.setattr("origin_audit.scope.is_public_ip", lambda _: True)
    scope = ScopeConfig(
        authorized_domains=["example.com"],
        authorized_ips=["203.0.113.0/24"],
        allow_active_validation=True,
    )
    async with httpx.AsyncClient() as client:
        validated = await validate_candidate(
            CandidateIP(ip="203.0.113.10"),
            domain="example.com",
            scope=scope,
            client=client,
            baseline=baseline,
            baseline_favicon_sha256="icon",
            maximum_bytes=100,
            limiter=AsyncRateLimiter(1000),
        )
    types = {item.type for item in validated.evidence}
    assert {"body_hash_match", "title_match", "favicon_match", "certificate_match"} <= types
    assert validated.active_validation_performed
