"""Domain normalization and matching."""

import re
from urllib.parse import urlsplit

from origin_audit.exceptions import ConfigurationError

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_domain(value: str) -> str:
    """Normalize a hostname or URL to an ASCII, lower-case domain."""
    candidate = value.strip()
    if not candidate:
        raise ConfigurationError("Domain cannot be empty")
    if "://" in candidate:
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError("Only HTTP(S) URLs with a hostname are accepted")
        candidate = parsed.hostname
    else:
        candidate = candidate.split("/", 1)[0].split(":", 1)[0]
    candidate = candidate.rstrip(".").lower()
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ConfigurationError("Domain is not valid IDNA") from exc
    if len(ascii_domain) > 253 or "." not in ascii_domain:
        raise ConfigurationError("A fully-qualified domain is required")
    if any(not _LABEL.fullmatch(label) for label in ascii_domain.split(".")):
        raise ConfigurationError("Domain contains an invalid label")
    return ascii_domain


def domain_matches(domain: str, pattern: str) -> bool:
    """Match a normalized domain against an exact or ``*.suffix`` rule."""
    normalized = normalize_domain(domain)
    raw_pattern = pattern.strip().lower().rstrip(".")
    if raw_pattern.startswith("*."):
        suffix = normalize_domain(raw_pattern[2:])
        return normalized.endswith(f".{suffix}") and normalized != suffix
    return normalized == normalize_domain(raw_pattern)


def is_related_hostname(hostname: str, domain: str) -> bool:
    """Return whether hostname is the target domain or a subdomain."""
    host = normalize_domain(hostname)
    target = normalize_domain(domain)
    return host == target or host.endswith(f".{target}")
