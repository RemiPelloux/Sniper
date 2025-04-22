"""
Unit tests for the validate_target_url function in validation module.
"""

import pytest
from src.core.validation import validate_target_url


def test_validate_target_url_valid():
    """Test that valid URLs are processed correctly."""
    # Test with already valid URL
    url = "https://example.com"
    result = validate_target_url(url, auto_add_scheme=True)
    assert result == url
    
    # Test with URL without scheme
    url = "example.com"
    result = validate_target_url(url, auto_add_scheme=True)
    assert result == "http://example.com"
    
    # Test with URL with path
    url = "example.com/path"
    result = validate_target_url(url, auto_add_scheme=True)
    assert result == "http://example.com/path"
    
    # Test with URL with parameters
    url = "example.com/path?param=value"
    result = validate_target_url(url, auto_add_scheme=True)
    assert result == "http://example.com/path?param=value"


def test_validate_target_url_invalid():
    """Test that invalid URLs return None."""
    # Test with empty string
    assert validate_target_url("", auto_add_scheme=True) is None
    
    # Test with invalid domain
    assert validate_target_url("not-a-domain", auto_add_scheme=True) is None
    
    # Test with malformed URL
    assert validate_target_url("http://", auto_add_scheme=True) is None
    
    # Test with None - this would raise TypeError even with auto_add_scheme=True
    # Note: The actual function doesn't handle None (would raise TypeError),
    # but in real usage the CLI framework would never pass None
    try:
        validate_target_url(None, auto_add_scheme=True)
        assert False, "Expected TypeError, but no exception was raised"
    except TypeError:
        pass  # This is the expected exception type 