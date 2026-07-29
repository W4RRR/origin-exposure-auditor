"""Provider parser tests with no real network traffic."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import dns.resolver
import pytest

from origin_audit.exceptions import ProviderError
from origin_audit.models import ProviderState, Target
from origin_audit.providers import provider_registry
from origin_audit.providers.base import (
    Provider,
    ProviderContext,
    candidate_from_ip,
    failed_result,
    parse_datetime,
)
from origin_audit.providers.censys_provider import CensysProvider
from origin_audit.providers.certificate_transparency import CertificateTransparencyProvider
from origin_audit.providers.dns_provider import DNSProvider
from origin_audit.providers.fofa_provider import FOFAProvider
from origin_audit.providers.otx_provider import OTXProvider
from origin_audit.providers.securitytrails_provider import SecurityTrailsProvider
from origin_audit.providers.shodan_provider import ShodanProvider
from origin_audit.providers.urlscan_provider import URLScanProvider
from origin_audit.providers.viewdns_provider import ViewDNSProvider
from origin_audit.providers.virustotal_provider import VirusTotalProvider


class DummyProvider(Provider):
    name = "dummy"
    required_environment = ("DUMMY_KEY",)

    async def collect(self, target: Target, context: ProviderContext) -> Any:
        del target, context
        return None


def fixture(name: str) -> dict[str, Any]:
    path = Path(__file__).parent / "fixtures" / name
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.asyncio
async def test_base_provider_helpers(context_factory: Any) -> None:
    context, _ = context_factory(environment={})
    provider = DummyProvider()
    assert not await provider.is_available(context)
    skipped = provider.unavailable_result()
    assert skipped.state is ProviderState.SKIPPED
    assert "DUMMY_KEY" in (skipped.message or "")
    context.environment["DUMMY_KEY"] = "configured"
    assert await provider.is_available(context)
    assert parse_datetime(0) == datetime(1970, 1, 1, tzinfo=UTC)
    assert parse_datetime("2026-01-01") == datetime(2026, 1, 1, tzinfo=UTC)
    assert parse_datetime("invalid") is None
    assert candidate_from_ip("x", "invalid", evidence_type="x", evidence_value="x") is None
    failed = failed_result("x", ValueError("bad"))
    assert failed.state is ProviderState.FAILED


@pytest.mark.asyncio
async def test_certificate_transparency_provider(context_factory: Any) -> None:
    context, _ = context_factory(
        [
            {"name_value": "*.example.com\napi.example.com"},
            {"name_value": "example.org"},
            {"name_value": "bad_.example.com"},
        ],
        save_raw=True,
    )
    result = await CertificateTransparencyProvider().collect(Target(domain="example.com"), context)
    assert result.state is ProviderState.OK
    assert result.hostnames == ["api.example.com", "example.com"]
    assert result.raw == {"row_count": 3}
    bad_context, _ = context_factory({"not": "a-list"})
    failed = await CertificateTransparencyProvider().collect(
        Target(domain="example.com"), bad_context
    )
    assert failed.state is ProviderState.FAILED


@pytest.mark.asyncio
async def test_virustotal_provider(context_factory: Any) -> None:
    context, transport = context_factory(
        fixture("virustotal_resolutions.json"),
        environment={"VIRUSTOTAL_API_KEY": "test-key"},
    )
    result = await VirusTotalProvider().collect(Target(domain="example.com"), context)
    assert result.candidates[0].ip == "203.0.113.10"
    assert result.candidates[0].evidence[0].type == "historical_dns"
    assert transport.calls[0][2]["headers"]["x-apikey"] == "test-key"
    unavailable, _ = context_factory()
    skipped = await VirusTotalProvider().collect(Target(domain="example.com"), unavailable)
    assert skipped.state is ProviderState.SKIPPED


@pytest.mark.asyncio
async def test_otx_provider(context_factory: Any) -> None:
    context, transport = context_factory(
        {
            "passive_dns": [
                {
                    "address": "203.0.113.11",
                    "hostname": "api.example.com",
                    "last": "2026-01-01T00:00:00Z",
                    "asn": "AS64500",
                }
            ]
        },
        {
            "url_list": [
                {
                    "url": "https://example.com/",
                    "hostname": "example.com",
                    "date": "2026-01-02T00:00:00Z",
                    "result": {"urlworker": {"ip": "203.0.113.12"}},
                }
            ]
        },
        environment={"OTX_API_KEY": "optional"},
    )
    result = await OTXProvider().collect(Target(domain="example.com"), context)
    assert {item.ip for item in result.candidates} == {"203.0.113.11", "203.0.113.12"}
    assert transport.calls[0][2]["headers"]["X-OTX-API-KEY"] == "optional"


@pytest.mark.asyncio
async def test_otx_partial_failure(context_factory: Any) -> None:
    context, _ = context_factory(ProviderError("no dns"), {"url_list": []})
    result = await OTXProvider().collect(Target(domain="example.com"), context)
    assert result.state is ProviderState.FAILED
    assert result.errors


@pytest.mark.asyncio
async def test_urlscan_search_and_submit(context_factory: Any) -> None:
    context, _ = context_factory(
        fixture("urlscan_search.json"),
        environment={"URLSCAN_API_KEY": "key"},
    )
    result = await URLScanProvider().collect(Target(domain="example.com"), context)
    assert result.candidates[0].ip == "203.0.113.20"
    assert result.candidates[0].asn == "AS64500"
    submit_context, transport = context_factory(
        {"uuid": "test", "visibility": "unlisted"},
        environment={"URLSCAN_API_KEY": "key"},
    )
    response = await URLScanProvider().submit(
        Target(domain="example.com"), submit_context, visibility="unlisted"
    )
    assert response["uuid"] == "test"
    assert transport.calls[0][0] == "POST"
    with pytest.raises(ValueError):
        await URLScanProvider().submit(
            Target(domain="example.com"), submit_context, visibility="invalid"
        )
    missing, _ = context_factory()
    with pytest.raises(ValueError):
        await URLScanProvider().submit(Target(domain="example.com"), missing, visibility="unlisted")


@pytest.mark.asyncio
async def test_shodan_provider(context_factory: Any) -> None:
    context, _ = context_factory(
        {
            "matches": [
                {
                    "ip_str": "203.0.113.21",
                    "port": 443,
                    "hostnames": ["api.example.com"],
                    "asn": "AS64500",
                    "org": "Example",
                    "location": {"country_code": "ZZ"},
                }
            ]
        },
        {"matches": []},
        environment={"SHODAN_API_KEY": "key"},
    )
    result = await ShodanProvider().collect(Target(domain="example.com"), context)
    assert result.candidates[0].ports == [443]
    assert result.candidates[0].country == "ZZ"
    missing, _ = context_factory()
    assert (
        await ShodanProvider().collect(Target(domain="example.com"), missing)
    ).state is ProviderState.SKIPPED


@pytest.mark.asyncio
async def test_censys_provider(context_factory: Any) -> None:
    context, transport = context_factory(
        {
            "result": {
                "hits": [
                    {
                        "host": {
                            "ip": "203.0.113.22",
                            "autonomous_system": {"asn": 64500, "name": "Example"},
                            "location": {"country": "ZZ"},
                        },
                        "matched_services": [
                            {"port": 443, "protocol": "HTTP", "transport_protocol": "tcp"}
                        ],
                    }
                ]
            }
        },
        environment={
            "CENSYS_API_TOKEN": "token",
            "CENSYS_ORGANIZATION_ID": "00000000-0000-0000-0000-000000000000",
        },
    )
    result = await CensysProvider().collect(Target(domain="example.com"), context)
    assert result.candidates[0].asn == "AS64500"
    assert result.candidates[0].ports == [443]
    assert transport.calls[0][2]["headers"]["Authorization"] == "Bearer token"


@pytest.mark.asyncio
async def test_securitytrails_provider(context_factory: Any) -> None:
    response = {
        "records": [
            {
                "last_seen": "2026-01-01",
                "values": [{"ip": "203.0.113.23"}],
            }
        ]
    }
    context, _ = context_factory(
        response,
        {"records": []},
        environment={"SECURITYTRAILS_API_KEY": "key"},
    )
    result = await SecurityTrailsProvider().collect(Target(domain="example.com"), context)
    assert result.candidates[0].ip == "203.0.113.23"


@pytest.mark.asyncio
async def test_fofa_provider(context_factory: Any) -> None:
    context, _ = context_factory(
        {
            "error": False,
            "results": [
                [
                    "203.0.113.24",
                    "443",
                    "https://example.com",
                    "example.com",
                    "Example",
                    "certificate",
                    "AS64500",
                    "Example",
                    "2026-01-01",
                ]
            ],
        },
        environment={"FOFA_EMAIL": "user@example.com", "FOFA_API_KEY": "key"},
    )
    result = await FOFAProvider().collect(Target(domain="example.com"), context)
    assert result.candidates[0].ports == [443]
    error_context, _ = context_factory(
        {"error": True, "errmsg": "denied"},
        environment={"FOFA_EMAIL": "user@example.com", "FOFA_API_KEY": "key"},
    )
    assert (
        await FOFAProvider().collect(Target(domain="example.com"), error_context)
    ).state is ProviderState.FAILED


@pytest.mark.asyncio
async def test_viewdns_provider(context_factory: Any) -> None:
    context, _ = context_factory(
        {
            "response": {
                "records": [
                    {
                        "ip": "203.0.113.25",
                        "owner": "Example",
                        "location": "ZZ",
                        "lastseen": "2026-01-01",
                    }
                ]
            }
        },
        environment={"VIEWDNS_API_KEY": "key"},
    )
    result = await ViewDNSProvider().collect(Target(domain="example.com"), context)
    assert result.candidates[0].organization == "Example"


@pytest.mark.asyncio
async def test_dns_provider(monkeypatch: pytest.MonkeyPatch, context_factory: Any) -> None:
    class Item:
        def __init__(self, value: str) -> None:
            self.value = value

        def to_text(self) -> str:
            return self.value

    class Resolver:
        lifetime = 0.0

        async def resolve(self, domain: str, record_type: str, search: bool) -> list[Item]:
            assert domain == "example.com"
            assert not search
            if record_type == "A":
                return [Item("203.0.113.26")]
            if record_type == "AAAA":
                return [Item("2001:db8::26")]
            raise dns.resolver.NoAnswer

    monkeypatch.setattr("origin_audit.providers.dns_provider.dns.asyncresolver.Resolver", Resolver)
    context, _ = context_factory()
    result = await DNSProvider().collect(Target(domain="example.com"), context)
    assert len(result.candidates) == 2
    assert result.records["MX"] == []


def test_provider_registry() -> None:
    registry = provider_registry()
    assert {"dns", "ct", "virustotal", "censys", "urlscan"} <= registry.keys()
