from typer.testing import CliRunner
import pytest
import typer
import logging
from unittest.mock import patch, MagicMock, AsyncMock

# Absolute import according to rules
from src.cli.main import app, scan, main_callback
from src.core.logging_config import setup_logging
from src.recon.types import TechInfo, HostScanResults

runner = CliRunner()

# --- Test Cases for CLI interaction ---

def test_cli_entrypoint_help():
    """Tests if the main entry point provides help output.
    """
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage: pentest-cli" in result.stdout
    assert "pentest-cli" in result.stdout
    assert "scan" in result.stdout # Check if scan command is listed

def test_scan_command_help():
    """Tests if the scan command provides help output.
    """
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Usage: pentest-cli scan" in result.stdout
    assert "Initiates a penetration test scan" in result.stdout
    assert "URL" in result.stdout # Check for the metavar

def test_scan_command_missing_url():
    """Tests if scan command exits cleanly when URL is missing.
    """
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0 # Should fail as URL is required
    assert "Missing argument 'URL'" in result.stdout

# Test the scan coroutine directly for integration logic
@pytest.mark.asyncio 
@patch('src.cli.main.get_domain_from_url', return_value="example.com")
@patch('src.cli.main.enumerate_dns')
@patch('src.cli.main.find_subdomains', return_value=[])
@patch('src.cli.main.get_whois_info', return_value=None)
@patch('src.cli.main.get_ssl_info', return_value=None)
@patch('src.cli.main.fingerprint_technology', new_callable=AsyncMock) 
@patch('src.cli.main.scan_ports')
@patch('src.cli.main.validate_url', side_effect=lambda url: url) 
async def test_scan_command_valid_url_runs_recon(
    mock_validate, 
    mock_scan_ports, mock_fingerprint, mock_ssl, mock_whois, mock_subdomains, mock_dns, mock_get_domain
):
    """Tests if scan function calls recon functions when awaited directly."""
    target_url = "https://example.com"
    
    # Configure mock return values 
    mock_dns.return_value = MagicMock(a_records=[], aaaa_records=[], mx_records=[], ns_records=[], txt_records=[])
    mock_fingerprint.return_value = TechInfo(server_header="MockServ/1.0", detected_technologies=["MockTech"])
    mock_scan_ports.return_value = HostScanResults(host="example.com", status="up", open_ports=[])
    
    # Directly await the scan coroutine function
    # Add dummy context if needed by patched functions, though not strictly required here
    await scan(target_url=target_url)
    
    # Verify mocks were called/awaited 
    mock_validate.assert_called_once_with(target_url)
    mock_get_domain.assert_called_once_with(target_url)
    mock_dns.assert_called_once_with("example.com")
    mock_subdomains.assert_called_once_with("example.com")
    mock_whois.assert_called_once_with("example.com")
    mock_ssl.assert_called_once_with("example.com")
    mock_fingerprint.assert_awaited_once_with(target_url) 
    mock_scan_ports.assert_called_once_with("example.com")

# Test logging options by invoking the CLI and checking the callback's effect
# These tests do not need to be async as they test the synchronous callback

@patch('src.cli.main.setup_logging') 
def test_verbose_logging_option(mock_setup_logging):
    """Tests if -v option causes setup_logging to be called with DEBUG level."""
    # Run any command with -v; the callback runs first.
    result = runner.invoke(app, ["-v", "scan", "http://example.com"])
    # We don't check the result code thoroughly as scan itself might fail async
    # The key is checking the setup_logging call by the callback.
    mock_setup_logging.assert_called_once_with(log_level="DEBUG", log_file=None)

@patch('src.cli.main.setup_logging') 
def test_log_file_option(mock_setup_logging, tmp_path):
    """Tests if --log-file option causes setup_logging to be called with the file path."""
    log_file_path = str(tmp_path / "test.log")
    # Run any command with --log-file
    result = runner.invoke(app, ["--log-file", log_file_path, "scan", "http://example.com"])
    # Check the setup_logging call by the callback.
    mock_setup_logging.assert_called_once_with(log_level="INFO", log_file=log_file_path)
