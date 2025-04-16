import pytest
from unittest.mock import patch, MagicMock
import socket
import ssl

# Absolute imports
from src.recon.ssl_analyzer import get_ssl_info, DEFAULT_SSL_PORT
from src.recon.types import SslCertInfo

# --- Mock Certificate Data ---
# Realistic but simplified mock data structure from getpeercert()
MOCK_CERT_DICT = {
    'subject': ((('countryName', 'US'),), (('stateOrProvinceName', 'California'),), (('localityName', 'Mountain View'),), (('organizationName', 'Google LLC'),), (('commonName', '*.google.com'),)),
    'issuer': ((('countryName', 'US'),), (('organizationName', 'Google Trust Services LLC'),), (('commonName', 'GTS CA 1P5'),)),
    'version': 3,
    'serialNumber': 'SOMEHEXSERIAL',
    'notBefore': 'Apr  1 08:00:00 2024 GMT',
    'notAfter': 'Jun 24 07:59:59 2024 GMT',
    'subjectAltName': (('DNS', '*.google.com'), ('DNS', 'google.com'), ('DNS', '*.youtube.com')),
    # ... other fields omitted for brevity
}

MOCK_ISSUER_STR = "{'countryName': 'US', 'organizationName': 'Google Trust Services LLC', 'commonName': 'GTS CA 1P5'}"
MOCK_SUBJECT_STR = "{'countryName': 'US', 'stateOrProvinceName': 'California', 'localityName': 'Mountain View', 'organizationName': 'Google LLC', 'commonName': '*.google.com'}"
MOCK_SANS = ['*.google.com', 'google.com', '*.youtube.com']

# --- Test Cases for get_ssl_info ---

@patch('src.recon.ssl_analyzer.ssl.create_default_context')
@patch('src.recon.ssl_analyzer.socket.create_connection')
def test_get_ssl_info_success(mock_create_connection, mock_create_context):
    """Tests successful retrieval and parsing of SSL cert info."""
    domain = "google.com"
    port = DEFAULT_SSL_PORT
    
    # Configure mocks
    mock_socket = MagicMock()
    mock_sslsocket = MagicMock()
    mock_context = MagicMock()
    
    mock_create_connection.return_value.__enter__.return_value = mock_socket
    mock_create_context.return_value = mock_context
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_sslsocket
    mock_sslsocket.getpeercert.return_value = MOCK_CERT_DICT
    
    result = get_ssl_info(domain, port)
    
    assert isinstance(result, SslCertInfo)
    assert result.issuer == MOCK_ISSUER_STR
    assert result.subject == MOCK_SUBJECT_STR
    assert result.valid_from == "2024-04-01T08:00:00"
    assert result.valid_until == "2024-06-24T07:59:59"
    assert result.sans == MOCK_SANS
    
    mock_create_connection.assert_called_once_with((domain, port), timeout=5)
    mock_context.wrap_socket.assert_called_once_with(mock_socket, server_hostname=domain)
    mock_sslsocket.getpeercert.assert_called_once()

@patch('src.recon.ssl_analyzer.socket.create_connection', side_effect=socket.timeout)
def test_get_ssl_info_timeout(mock_create_connection, caplog):
    """Tests handling of socket timeout during connection."""
    domain = "timeout.com"
    result = get_ssl_info(domain)
    assert result is None
    mock_create_connection.assert_called_once_with((domain, DEFAULT_SSL_PORT), timeout=5)
    assert f"Connection timed out when connecting to {domain}:{DEFAULT_SSL_PORT}" in caplog.text

@patch('src.recon.ssl_analyzer.socket.create_connection', side_effect=socket.gaierror)
def test_get_ssl_info_gaierror(mock_create_connection, caplog):
    """Tests handling of hostname resolution errors (gaierror)."""
    domain = "nonexistent.invalid"
    result = get_ssl_info(domain)
    assert result is None
    mock_create_connection.assert_called_once_with((domain, DEFAULT_SSL_PORT), timeout=5)
    assert f"Could not resolve hostname {domain}" in caplog.text

@patch('src.recon.ssl_analyzer.socket.create_connection', side_effect=ConnectionRefusedError)
def test_get_ssl_info_conn_refused(mock_create_connection, caplog):
    """Tests handling of connection refused errors."""
    domain = "refused.com"
    result = get_ssl_info(domain)
    assert result is None
    mock_create_connection.assert_called_once_with((domain, DEFAULT_SSL_PORT), timeout=5)
    assert f"Connection refused by {domain}:{DEFAULT_SSL_PORT}" in caplog.text

@patch('src.recon.ssl_analyzer.ssl.create_default_context')
@patch('src.recon.ssl_analyzer.socket.create_connection')
def test_get_ssl_info_verification_error(mock_create_connection, mock_create_context, caplog):
    """Tests handling of SSLCertVerificationError."""
    domain = "selfsigned.com"
    mock_socket = MagicMock()
    mock_context = MagicMock()
    mock_create_connection.return_value.__enter__.return_value = mock_socket
    mock_create_context.return_value = mock_context
    # Simulate verification error during wrap_socket
    mock_context.wrap_socket.side_effect = ssl.SSLCertVerificationError("certificate verify failed")
    
    result = get_ssl_info(domain)
    
    assert result is None
    mock_create_connection.assert_called_once_with((domain, DEFAULT_SSL_PORT), timeout=5)
    mock_context.wrap_socket.assert_called_once_with(mock_socket, server_hostname=domain)
    assert f"SSL Certificate Verification Error for {domain}:{DEFAULT_SSL_PORT}" in caplog.text

@patch('src.recon.ssl_analyzer.ssl.create_default_context')
@patch('src.recon.ssl_analyzer.socket.create_connection')
def test_get_ssl_info_no_cert(mock_create_connection, mock_create_context, caplog):
    """Tests scenario where connection succeeds but getpeercert returns None."""
    domain = "nocert.com"
    mock_socket = MagicMock()
    mock_sslsocket = MagicMock()
    mock_context = MagicMock()
    mock_create_connection.return_value.__enter__.return_value = mock_socket
    mock_create_context.return_value = mock_context
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_sslsocket
    mock_sslsocket.getpeercert.return_value = None # Simulate no cert
    
    result = get_ssl_info(domain)
    
    assert result is None
    assert f"Could not retrieve peer certificate from {domain}:{DEFAULT_SSL_PORT}" in caplog.text 