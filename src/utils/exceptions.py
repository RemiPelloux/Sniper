"""
Custom exceptions for the Sniper Security Tool.
"""


class SniperError(Exception):
    """Base exception for all Sniper-specific errors."""

    pass


class DistributionError(SniperError):
    """Exception raised for errors in the distributed architecture."""

    pass
