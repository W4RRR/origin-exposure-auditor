"""Timestamp helpers."""

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return an aware UTC datetime."""
    return datetime.now(UTC)


def timestamp_slug(value: datetime | None = None) -> str:
    """Return a filesystem-safe compact UTC timestamp."""
    current = (value or utc_now()).astimezone(UTC)
    return current.strftime("%Y-%m-%dT%H%M%SZ")
