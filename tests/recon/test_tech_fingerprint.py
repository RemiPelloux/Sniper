import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import httpx  # Import for exception types

# Absolute imports
from src.recon.tech_fingerprint import fingerprint_technology
from src.recon.types import TechInfo

# Mark all tests in this module as async
pytestmark = pytest.mark.asyncio

# --- Mock HTTP Responses ---

# Helper to create a mock response
def create_mock_response(status_code: int, headers: dict) -> MagicMock:
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = status_code
    mock_resp.headers = httpx.Headers(headers) # Use httpx.Headers for case-insensitivity
    
    # Mock raise_for_status to behave correctly
    if status_code >= 400:
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"Status error {status_code}", 
            request=MagicMock(), 
            response=mock_resp
        )
    else:
        mock_resp.raise_for_status.return_value = None
    return mock_resp

# --- Test Cases for fingerprint_technology ---

@patch('src.recon.tech_fingerprint.httpx.AsyncClient')
async def test_fingerprint_success_nginx(mock_async_client):
    """Tests successful fingerprinting with Nginx server header."""
    target_url = "http://nginx-site.com"
    mock_headers = {"Server": "nginx/1.18.0", "Content-Type": "text/html"}
    mock_response = create_mock_response(200, mock_headers)
    
    # Configure the mock AsyncClient context manager
    mock_client_instance = MagicMock()
    mock_client_instance.get = AsyncMock(return_value=mock_response)
    mock_async_client.return_value.__aenter__.return_value = mock_client_instance
    
    result = await fingerprint_technology(target_url)
    
    assert isinstance(result, TechInfo)
    assert result.server_header == "nginx/1.18.0"
    assert result.powered_by_header is None
    assert "Nginx" in result.detected_technologies
    assert len(result.detected_technologies) == 1
    
    mock_client_instance.get.assert_awaited_once_with(target_url)

@patch('src.recon.tech_fingerprint.httpx.AsyncClient')
async def test_fingerprint_success_apache_php(mock_async_client):
    """Tests successful fingerprinting with Apache and PHP headers."""
    target_url = "http://apache-php.com"
    mock_headers = {"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"}
    mock_response = create_mock_response(200, mock_headers)
    
    mock_client_instance = MagicMock()
    mock_client_instance.get = AsyncMock(return_value=mock_response)
    mock_async_client.return_value.__aenter__.return_value = mock_client_instance
    
    result = await fingerprint_technology(target_url)
    
    assert isinstance(result, TechInfo)
    assert result.server_header == "Apache/2.4.41 (Ubuntu)"
    assert result.powered_by_header == "PHP/7.4.3"
    assert "Apache" in result.detected_technologies
    assert "PHP" in result.detected_technologies
    assert len(result.detected_technologies) == 2
    
    mock_client_instance.get.assert_awaited_once_with(target_url)

@patch('src.recon.tech_fingerprint.httpx.AsyncClient')
async def test_fingerprint_no_relevant_headers(mock_async_client):
    """Tests scenario with no relevant technology headers."""
    target_url = "http://no-headers.com"
    mock_headers = {"Content-Type": "application/json", "Content-Length": "123"}
    mock_response = create_mock_response(200, mock_headers)
    
    mock_client_instance = MagicMock()
    mock_client_instance.get = AsyncMock(return_value=mock_response)
    mock_async_client.return_value.__aenter__.return_value = mock_client_instance
    
    result = await fingerprint_technology(target_url)
    
    assert isinstance(result, TechInfo)
    assert result.server_header is None
    assert result.powered_by_header is None
    assert len(result.detected_technologies) == 0
    
    mock_client_instance.get.assert_awaited_once_with(target_url)

@patch('src.recon.tech_fingerprint.httpx.AsyncClient')
async def test_fingerprint_http_status_error(mock_async_client, caplog):
    """Tests handling of HTTP status errors (e.g., 404)."""
    target_url = "http://not-found.com"
    mock_headers = {"Content-Type": "text/html"}
    mock_response = create_mock_response(404, mock_headers)
    
    mock_client_instance = MagicMock()
    mock_client_instance.get = AsyncMock(return_value=mock_response)
    mock_async_client.return_value.__aenter__.return_value = mock_client_instance
    
    result = await fingerprint_technology(target_url)
    
    assert result is None
    assert f"HTTP status error for {target_url}: 404" in caplog.text
    mock_client_instance.get.assert_awaited_once_with(target_url)

@patch('src.recon.tech_fingerprint.httpx.AsyncClient')
async def test_fingerprint_request_error(mock_async_client, caplog):
    """Tests handling of general request errors (e.g., connection error)."""
    target_url = "http://conn-error.com"
    error_message = "Connection refused"
    
    mock_client_instance = MagicMock()
    mock_client_instance.get = AsyncMock(side_effect=httpx.RequestError(error_message))
    mock_async_client.return_value.__aenter__.return_value = mock_client_instance
    
    result = await fingerprint_technology(target_url)
    
    assert result is None
    assert f"HTTP request failed for {target_url} during tech fingerprinting: {error_message}" in caplog.text
    mock_client_instance.get.assert_awaited_once_with(target_url) 