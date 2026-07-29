"""Typed domain models shared across providers and reports."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from origin_audit.utils.ips import normalize_ip
from origin_audit.utils.timestamps import utc_now


class Confidence(StrEnum):
    """Explainable confidence categories."""

    CONFIRMED = "confirmed"
    HIGH = "high_confidence"
    MEDIUM = "medium_confidence"
    LOW = "low_confidence"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class ProviderState(StrEnum):
    """Provider execution state."""

    OK = "ok"
    SKIPPED = "skipped"
    FAILED = "failed"


class Evidence(BaseModel):
    """A bounded, human-readable fact about a candidate."""

    source: str
    type: str
    value: str
    observed_at: datetime | None = None
    weight: float = 0.0
    raw_reference: str | None = None
    notes: str | None = None


class CertificateEvidence(BaseModel):
    """Relevant TLS certificate metadata."""

    source: str
    common_name: str | None = None
    san: list[str] = Field(default_factory=list)
    issuer: str | None = None
    fingerprint_sha256: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None


class HttpObservation(BaseModel):
    """A deliberately small HTTP observation."""

    url: str
    status_code: int | None = None
    title: str | None = None
    server: str | None = None
    content_type: str | None = None
    body_length: int | None = None
    final_url: str | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    body_sha256: str | None = None
    elapsed_ms: float | None = None
    technologies: list[str] = Field(default_factory=list)
    error: str | None = None


class FaviconEvidence(BaseModel):
    """Hashes of a safely bounded favicon download."""

    source_url: str
    md5: str
    sha256: str
    mmh3: int
    size: int


class ScoringContribution(BaseModel):
    """One transparent scoring rule application."""

    rule: str
    points: float
    reason: str


class CandidateIP(BaseModel):
    """A normalized candidate IP with merged provenance."""

    ip: str
    ip_version: int = 4
    sources: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    hostnames: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    asn: str | None = None
    organization: str | None = None
    country: str | None = None
    cloud_provider: str | None = None
    cdn_provider: str | None = None
    certificates: list[CertificateEvidence] = Field(default_factory=list)
    http_observations: list[HttpObservation] = Field(default_factory=list)
    favicon_hashes: list[FaviconEvidence] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    rejection_reasons: list[str] = Field(default_factory=list)
    score: float = 0.0
    confidence: Confidence = Confidence.UNKNOWN
    scoring_reasons: list[ScoringContribution] = Field(default_factory=list)
    active_validation_performed: bool = False

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        """Canonicalize the candidate address."""
        return normalize_ip(value)

    def model_post_init(self, __context: Any) -> None:
        """Derive IP version after validation."""
        self.ip_version = 6 if ":" in self.ip else 4


class Target(BaseModel):
    """Normalized scan target."""

    domain: str


class ProviderResult(BaseModel):
    """Bounded result returned by one provider."""

    provider: str
    state: ProviderState = ProviderState.OK
    candidates: list[CandidateIP] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    records: dict[str, list[str]] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    message: str | None = None
    raw: dict[str, Any] | None = None
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None


class WAFDetection(BaseModel):
    """Non-conclusive WAF/CDN indicators."""

    detected: bool = False
    providers: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    external_tool: str | None = None


class ScanReport(BaseModel):
    """Reproducible report produced by one scan."""

    model_config = ConfigDict(use_enum_values=True)

    tool_version: str
    domain: str
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    mode: str
    scope_file: str | None = None
    authorization_acknowledged: bool = False
    dns_records: dict[str, list[str]] = Field(default_factory=dict)
    subdomains: list[str] = Field(default_factory=list)
    waf_detection: WAFDetection = Field(default_factory=WAFDetection)
    baseline_http: HttpObservation | None = None
    baseline_certificate: CertificateEvidence | None = None
    baseline_favicon: FaviconEvidence | None = None
    candidates: list[CandidateIP] = Field(default_factory=list)
    providers: list[ProviderResult] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
