"""Core validation, models, cache, scope, and scoring tests."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from origin_audit.cache import JsonCache
from origin_audit.config import AppConfig, load_config, load_environment, validate_config_file
from origin_audit.deduplication import deduplicate_candidates, merge_candidate
from origin_audit.exceptions import ConfigurationError, ScopeError
from origin_audit.models import CandidateIP, Confidence, Evidence
from origin_audit.scope import ScopeConfig, load_scope
from origin_audit.scoring import classify, score_candidate, score_candidates
from origin_audit.utils.domains import domain_matches, is_related_hostname, normalize_domain
from origin_audit.utils.hashing import md5_hex, normalize_body, sha256_hex, shodan_mmh3
from origin_audit.utils.ips import is_public_ip, normalize_ip, special_address_reasons
from origin_audit.utils.redaction import redact_mapping, redact_secret
from origin_audit.utils.timestamps import timestamp_slug, utc_now


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Example.COM.", "example.com"),
        ("https://example.com/path", "example.com"),
        ("https://EXAMPLE.com:443/", "example.com"),
        ("täst.example", "xn--tst-qla.example"),
    ],
)
def test_normalize_domain(value: str, expected: str) -> None:
    assert normalize_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "localhost", "https://", "ftp://example.com", "-bad.example", "bad_.example"],
)
def test_normalize_domain_rejects_invalid(value: str) -> None:
    with pytest.raises(ConfigurationError):
        normalize_domain(value)


def test_domain_matching() -> None:
    assert domain_matches("api.example.com", "*.example.com")
    assert not domain_matches("example.com", "*.example.com")
    assert domain_matches("example.com", "example.com")
    assert is_related_hostname("api.example.com", "example.com")
    assert not is_related_hostname("example.org", "example.com")


def test_ip_helpers() -> None:
    assert normalize_ip("2001:0db8::1") == "2001:db8::1"
    assert not is_public_ip("192.0.2.10")
    assert "loopback" in special_address_reasons("127.0.0.1")
    assert "link_local" in special_address_reasons("169.254.1.1")
    with pytest.raises(ConfigurationError):
        normalize_ip("999.1.1.1")


def test_hashing_helpers() -> None:
    payload = b"<html>  hello\nworld </html>"
    assert normalize_body(payload) == b"<html> hello world </html>"
    assert len(sha256_hex(payload)) == 64
    assert len(md5_hex(payload)) == 32
    assert isinstance(shodan_mmh3(b"icon"), int)


def test_redaction() -> None:
    assert redact_secret("secret") == "***REDACTED***"
    assert redact_secret("abcdef", show_suffix=True) == "***cdef"
    assert redact_secret("") == ""
    value = {"api_key": "value", "nested": [{"Authorization": "Bearer value"}], "safe": 1}
    redacted = redact_mapping(value)
    assert redacted["api_key"] == "***REDACTED***"
    assert redacted["nested"][0]["Authorization"] == "***REDACTED***"
    assert redacted["safe"] == 1


def test_timestamps() -> None:
    current = utc_now()
    assert current.tzinfo is UTC
    assert timestamp_slug(datetime(2026, 7, 24, 11, tzinfo=UTC)) == "2026-07-24T110000Z"


def test_candidate_derives_version_and_deduplicates() -> None:
    first = CandidateIP(
        ip="203.0.113.10",
        sources=["source-a"],
        hostnames=["example.com"],
        evidence=[Evidence(source="source-a", type="historical_dns", value="first")],
        first_seen=datetime(2025, 1, 1, tzinfo=UTC),
    )
    second = CandidateIP(
        ip="203.0.113.10",
        sources=["source-b"],
        ports=[443],
        organization="Example",
        evidence=[Evidence(source="source-b", type="certificate_match", value="second")],
        last_seen=datetime(2026, 1, 1, tzinfo=UTC),
    )
    merged = deduplicate_candidates([first, second])
    assert len(merged) == 1
    assert merged[0].sources == ["source-a", "source-b"]
    assert merged[0].ports == [443]
    assert merged[0].organization == "Example"
    assert merged[0].ip_version == 4
    with pytest.raises(ValueError):
        merge_candidate(first, CandidateIP(ip="203.0.113.11"))


def test_scoring_and_confirmation(app_config: AppConfig) -> None:
    now = datetime(2026, 7, 24, tzinfo=UTC)
    candidate = CandidateIP(
        ip="203.0.113.10",
        sources=["vt", "ct"],
        active_validation_performed=True,
        evidence=[
            Evidence(source="vt", type="historical_dns", value="x"),
            Evidence(source="ct", type="discovered", value="x"),
            Evidence(source="active_validation", type="body_hash_match", value="x"),
            Evidence(source="active_validation", type="favicon_match", value="x"),
            Evidence(source="active_validation", type="certificate_match", value="x"),
        ],
        hostnames=["example.com"],
        last_seen=now,
    )
    scored = score_candidate(candidate, app_config.scoring, now=now)
    assert scored.score >= app_config.scoring.confirmed_threshold
    assert scored.confidence is Confidence.CONFIRMED
    passive = scored.model_copy(deep=True)
    passive.active_validation_performed = False
    assert classify(passive, app_config.scoring) is Confidence.HIGH
    rejected = CandidateIP(ip="203.0.113.11", rejection_reasons=["excluded"])
    assert classify(rejected, app_config.scoring) is Confidence.REJECTED


def test_scoring_stale_and_sort(app_config: AppConfig) -> None:
    stale = CandidateIP(
        ip="203.0.113.12",
        evidence=[Evidence(source="vt", type="historical_dns", value="x")],
        last_seen=datetime.now(UTC) - timedelta(days=400),
    )
    current = CandidateIP(
        ip="203.0.113.13",
        evidence=[Evidence(source="vt", type="historical_dns", value="x")],
    )
    scored = score_candidates([stale, current], app_config.scoring)
    assert scored[0].ip == "203.0.113.13"
    assert any(item.rule == "stale_observation" for item in scored[1].scoring_reasons)


def test_scope_rules(tmp_path: Path) -> None:
    scope = ScopeConfig(
        authorized_domains=["example.com", "*.example.org"],
        authorized_ips=["203.0.113.0/24"],
        excluded_ips=["203.0.113.50"],
        allow_active_validation=True,
    )
    assert scope.domain_is_authorized("example.com")
    assert scope.domain_is_authorized("api.example.org")
    assert not scope.ip_is_authorized("203.0.113.10")  # documentation ranges are non-global
    with pytest.raises(ScopeError):
        scope.assert_active_allowed("example.com", "203.0.113.10")
    path = tmp_path / "scope.yml"
    path.write_text("authorized_domains: [example.com]\n", encoding="utf-8")
    assert load_scope(path).authorized_domains == ["example.com"]


def test_scope_validation_rejects_bad_values() -> None:
    with pytest.raises(ValueError):
        ScopeConfig(authorized_ips=["not-a-network"])
    with pytest.raises(ValueError):
        ScopeConfig(authorized_domains=["bad_domain"])


def test_config_loading_and_environment_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "config.yml"
    config_path.write_text("concurrency: 3\n", encoding="utf-8")
    assert load_config(config_path).concurrency == 3
    assert validate_config_file(config_path).concurrency == 3
    with pytest.raises(ConfigurationError):
        load_config(tmp_path / "missing.yml")
    broken = tmp_path / "broken.yml"
    broken.write_text("- not\n- a mapping\n", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(broken)
    env_file = tmp_path / "explicit.env"
    env_file.write_text("TEST_ORIGIN_KEY=file\n", encoding="utf-8")
    monkeypatch.setenv("TEST_ORIGIN_KEY", "system")
    assert load_environment(env_file)["TEST_ORIGIN_KEY"] == "system"
    monkeypatch.delenv("TEST_ORIGIN_KEY")
    assert load_environment(env_file)["TEST_ORIGIN_KEY"] == "file"


def test_json_cache(tmp_path: Path) -> None:
    cache = JsonCache(tmp_path / "cache")
    key = cache.key("provider", "op", {"domain": "example.com"})
    assert cache.get(key, timedelta(hours=1)) is None
    cache.set(key, {"ok": True})
    assert cache.get(key, timedelta(hours=1)) == {"ok": True}
    path = cache.root / key
    os.utime(path, (0, 0))
    assert cache.get(key, timedelta(seconds=1)) is None
    path.write_text("{bad", encoding="utf-8")
    assert cache.get(key, timedelta(days=100000)) is None
    disabled = JsonCache(tmp_path / "disabled", enabled=False)
    disabled.set("x.json", {"x": 1})
    assert disabled.get("x.json", timedelta(hours=1)) is None
