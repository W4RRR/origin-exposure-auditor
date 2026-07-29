"""IP address normalization and safety classification."""

from ipaddress import IPv4Address, IPv6Address, ip_address

from origin_audit.exceptions import ConfigurationError

IPAddress = IPv4Address | IPv6Address


def normalize_ip(value: str) -> str:
    """Return the canonical spelling of an IPv4 or IPv6 address."""
    try:
        return str(ip_address(value.strip()))
    except ValueError as exc:
        raise ConfigurationError(f"Invalid IP address: {value!r}") from exc


def is_public_ip(value: str) -> bool:
    """Return whether an address is globally routable."""
    return ip_address(normalize_ip(value)).is_global


def special_address_reasons(value: str) -> list[str]:
    """Explain why an address is not suitable for active validation."""
    address = ip_address(normalize_ip(value))
    reasons: list[str] = []
    checks = (
        ("private", address.is_private),
        ("loopback", address.is_loopback),
        ("link_local", address.is_link_local),
        ("multicast", address.is_multicast),
        ("reserved", address.is_reserved),
        ("unspecified", address.is_unspecified),
    )
    reasons.extend(name for name, active in checks if active)
    if not address.is_global and not reasons:
        reasons.append("not_globally_routable")
    return reasons
