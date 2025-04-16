import pytest
import logging
from unittest.mock import patch, MagicMock
import dns.resolver
import dns.exception

# Absolute imports
from src.recon.dns_enum import get_domain_from_url, enumerate_dns, DEFAULT_RECORD_TYPES
from src.recon.types import DnsResults, DnsRecord

# --- Test Cases for get_domain_from_url ---

@pytest.mark.parametrize(
    "url, expected_domain",
    [
        ("http://example.com", "example.com"),
        ("https://www.example.co.uk/path", "www.example.co.uk"),
        ("http://example.com:8080/", "example.com"),
        ("https://sub.example.com?query=1", "sub.example.com"),
        ("http://127.0.0.1", "127.0.0.1"),
        ("https://[::1]:443", "::1"),
    ]
)
def test_get_domain_from_url_valid(url: str, expected_domain: str):
    """Tests extracting domain from various valid URLs."""
    assert get_domain_from_url(url) == expected_domain

@pytest.mark.parametrize(
    "invalid_url",
    [
        "example.com", # Missing scheme
        "", # Empty string
        "http:///path", # Missing netloc
    ]
)
def test_get_domain_from_url_invalid(invalid_url: str):
    """Tests that invalid URLs raise ValueError during domain extraction."""
    with pytest.raises(ValueError):
        get_domain_from_url(invalid_url)

# --- Test Cases for enumerate_dns ---

@patch('src.recon.dns_enum.dns.resolver.Resolver')
def test_enumerate_dns_success(mock_resolver_cls):
    """Tests successful DNS enumeration for multiple record types."""
    domain = "example.com"
    
    # Configure the mock resolver instance and its resolve method
    mock_resolver_instance = MagicMock()
    mock_resolver_cls.return_value = mock_resolver_instance

    # --- Mock DNS answers ---
    # Mock A record
    mock_a_answer = MagicMock()
    mock_a_answer.__str__.return_value = "93.184.216.34"
    
    # Mock MX record
    mock_mx_answer = MagicMock()
    mock_mx_answer.preference = 10
    mock_mx_answer.exchange = "mail.example.com."

    # Mock TXT record (with bytes)
    mock_txt_answer = MagicMock()
    mock_txt_answer.strings = [b"v=spf1 include:_spf.google.com ~all"]

    # Define side effects for the mock resolve method
    def mock_resolve_side_effect(query_domain, record_type):
        if query_domain == domain:
            if record_type == "A":
                return [mock_a_answer]
            elif record_type == "MX":
                return [mock_mx_answer]
            elif record_type == "TXT":
                 return [mock_txt_answer]
            elif record_type == "AAAA" or record_type == "NS":
                 # Simulate NoAnswer for other types
                 raise dns.resolver.NoAnswer
        raise dns.resolver.NXDOMAIN # Default for other domains

    mock_resolver_instance.resolve.side_effect = mock_resolve_side_effect

    # --- Execute the function ---
    results = enumerate_dns(domain)

    # --- Assertions ---
    assert isinstance(results, DnsResults)
    assert results.domain == domain

    # Check A records
    assert len(results.a_records) == 1
    assert results.a_records[0].record_type == "A"
    assert results.a_records[0].value == "93.184.216.34"

    # Check MX records
    assert len(results.mx_records) == 1
    assert results.mx_records[0].record_type == "MX"
    assert results.mx_records[0].value == "10 mail.example.com."
    
    # Check TXT records
    assert len(results.txt_records) == 1
    assert results.txt_records[0].record_type == "TXT"
    assert results.txt_records[0].value == "v=spf1 include:_spf.google.com ~all"
    
    # Check empty records
    assert len(results.aaaa_records) == 0
    assert len(results.ns_records) == 0

    # Verify resolve was called for each type until NoAnswer/Error
    assert mock_resolver_instance.resolve.call_count == len(DEFAULT_RECORD_TYPES)

@patch('src.recon.dns_enum.dns.resolver.Resolver')
def test_enumerate_dns_nxdomain(mock_resolver_cls):
    """Tests that NXDOMAIN stops further lookups."""
    domain = "nonexistent-domain.invalid"
    mock_resolver_instance = MagicMock()
    mock_resolver_cls.return_value = mock_resolver_instance
    mock_resolver_instance.resolve.side_effect = dns.resolver.NXDOMAIN

    results = enumerate_dns(domain)

    assert results.domain == domain
    assert len(results.a_records) == 0
    assert len(results.aaaa_records) == 0
    # ... check other lists are empty ...

    # Should only be called once (for the first record type) before NXDOMAIN stops it
    mock_resolver_instance.resolve.assert_called_once_with(domain, DEFAULT_RECORD_TYPES[0])

@patch('src.recon.dns_enum.dns.resolver.Resolver')
def test_enumerate_dns_timeout(mock_resolver_cls, caplog):
    """Tests that Timeout logs a warning but continues."""
    domain = "timeout-domain.com"
    mock_resolver_instance = MagicMock()
    mock_resolver_cls.return_value = mock_resolver_instance
    
    # Simulate timeout for A, success for MX
    mock_mx_answer = MagicMock()
    mock_mx_answer.preference = 5
    mock_mx_answer.exchange = "mx.timeout-domain.com."

    def mock_resolve_side_effect(query_domain, record_type):
        if record_type == "A":
            raise dns.exception.Timeout
        elif record_type == "MX":
            return [mock_mx_answer]
        else:
            raise dns.resolver.NoAnswer
            
    mock_resolver_instance.resolve.side_effect = mock_resolve_side_effect

    with caplog.at_level(logging.WARNING):
        results = enumerate_dns(domain)

    assert results.domain == domain
    assert len(results.a_records) == 0 # Failed due to timeout
    assert len(results.mx_records) == 1 # Should still find MX
    assert results.mx_records[0].value == "5 mx.timeout-domain.com."
    assert len(results.txt_records) == 0 # No answer
    
    # Check log message
    assert f"DNS query timed out for A record at {domain}" in caplog.text
    assert mock_resolver_instance.resolve.call_count == len(DEFAULT_RECORD_TYPES) 