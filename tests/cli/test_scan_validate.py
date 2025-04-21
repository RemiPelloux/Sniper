"""
Unit tests for the validate_target_url function in scan module.
"""

import pytest
from src.cli.scan import validate_target_url


def test_validate_target_url_valid():
    """Test that valid URLs are processed correctly."""
    # Test with already valid URL
    url = "https://example.com"
    result = validate_target_url(url)
    assert result == url
    
    # Test with URL without scheme
    url = "example.com"
    result = validate_target_url(url)
    assert result == "http://example.com"
    
    # Test with URL with path
    url = "example.com/path"
    result = validate_target_url(url)
    assert result == "http://example.com/path"
    
    # Test with URL with parameters
    url = "example.com/path?param=value"
    result = validate_target_url(url)
    assert result == "http://example.com/path?param=value"


def test_validate_target_url_invalid():
    """Test that invalid URLs raise ValueErrors."""
    # Test with empty string
    with pytest.raises(ValueError, match="Target URL cannot be empty"):
        validate_target_url("")
    
    # Test with None - validate_target_url implementation treats None as empty
    with pytest.raises(ValueError, match="Target URL cannot be empty"):
        validate_target_url(None) 