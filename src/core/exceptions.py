"""Core exceptions for the Sniper project."""


class SniperError(Exception):
    """Base exception for all Sniper errors."""

    pass


class ScanConfigError(SniperError):
    """Raised when there is an error in scan configuration."""

    pass


class ScanExecutionError(SniperError):
    """Raised when there is an error during scan execution."""

    pass
