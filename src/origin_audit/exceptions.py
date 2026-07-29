"""Application-specific exceptions."""


class OriginAuditError(Exception):
    """Base exception for expected application failures."""


class ConfigurationError(OriginAuditError):
    """Raised when configuration is invalid."""


class ScopeError(OriginAuditError):
    """Raised when an operation is outside the authorized scope."""


class ProviderError(OriginAuditError):
    """Raised when a provider cannot complete its operation."""


class RetryableProviderError(ProviderError):
    """Raised for a provider error that is safe to retry."""


class UnsafeTargetError(OriginAuditError):
    """Raised when a network target fails defensive safety checks."""
