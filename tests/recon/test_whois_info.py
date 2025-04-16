import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
import whois # Import the library itself for its exception types

# Absolute imports
from src.recon.whois_info import get_whois_info
from src.recon.types import WhoisInfo

# --- Test Cases for get_whois_info ---

@patch('src.recon.whois_info.whois.whois')
def test_get_whois_info_success(mock_whois):
    """Tests successful WHOIS lookup and parsing."""
    domain = "google.com"
    
    # Create a mock response object simulating the library's output
    mock_response = MagicMock()
    mock_response.domain_name = "google.com"
    mock_response.registrar = "MarkMonitor Inc."
    # Simulate list-based date
    mock_response.creation_date = [datetime(1997, 9, 15, 4, 0, 0)]
    # Simulate single date
    mock_response.expiration_date = datetime(2028, 9, 14, 4, 0, 0)
    mock_response.name_servers = ["ns1.google.com", "NS2.GOOGLE.COM"]
    mock_response.get.side_effect = lambda key: getattr(mock_response, key, None)

    mock_whois.return_value = mock_response
    
    result = get_whois_info(domain)
    
    assert isinstance(result, WhoisInfo)
    assert result.registrar == "MarkMonitor Inc."
    assert result.creation_date == "1997-09-15T04:00:00"
    assert result.expiration_date == "2028-09-14T04:00:00"
    # Check if name servers are lowercased
    assert result.name_servers == ["ns1.google.com", "ns2.google.com"]
    
    mock_whois.assert_called_once_with(domain)

@patch('src.recon.whois_info.whois.whois')
def test_get_whois_info_no_data(mock_whois):
    """Tests scenario where WHOIS query returns minimal/no useful data."""
    domain = "nodata.com"
    
    # Simulate a response with no significant fields
    mock_response = MagicMock()
    mock_response.domain_name = None # Simulate missing domain name
    # ... other fields would likely be None too ...
    mock_response.get.side_effect = lambda key: getattr(mock_response, key, None)
    
    mock_whois.return_value = mock_response
    
    result = get_whois_info(domain)
    
    assert result is None
    mock_whois.assert_called_once_with(domain)

@patch('src.recon.whois_info.whois.whois')
def test_get_whois_info_library_error(mock_whois, caplog):
    """Tests handling of PywhoisError from the library."""
    domain = "error.com"
    error_message = "No WHOIS server found for domain"
    mock_whois.side_effect = whois.parser.PywhoisError(error_message)
    
    result = get_whois_info(domain)
    
    assert result is None
    mock_whois.assert_called_once_with(domain)
    # Check log message
    assert f"WHOIS lookup failed for {domain}: {error_message}" in caplog.text

@patch('src.recon.whois_info.whois.whois')
def test_get_whois_info_unexpected_error(mock_whois, caplog):
    """Tests handling of generic exceptions during WHOIS lookup."""
    domain = "unexpected.com"
    error_message = "Something went wrong"
    mock_whois.side_effect = Exception(error_message)
    
    result = get_whois_info(domain)
    
    assert result is None
    mock_whois.assert_called_once_with(domain)
    # Check log message
    assert f"Unexpected error during WHOIS lookup for {domain}: {error_message}" in caplog.text 