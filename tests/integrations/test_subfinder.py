import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.executors import ExecutionResult
from src.integrations.subfinder import SubfinderIntegration
from src.results.types import FindingSeverity, SubdomainFinding


@pytest.fixture
def subfinder_integration():
    """Create a SubfinderIntegration with mocked executor."""
    mock_executor = MagicMock()
    # Mock the execute method to be asyncable
    mock_executor.execute = AsyncMock()
    return SubfinderIntegration(executor=mock_executor)


@pytest.fixture
def temp_results_file(tmp_path):
    """Create a temporary file with mock subfinder results."""
    file_path = tmp_path / "subfinder_results.txt"
    with open(file_path, "w") as f:
        f.write("sub1.example.com\n")
        f.write("sub2.example.com\n")
        f.write("sub3.example.com\n")
        f.write("\n")  # Empty line to test handling
        f.write("sub4.example.com\n")
    return file_path


def test_check_prerequisites_success():
    """Test the check_prerequisites method when subfinder is available."""
    with patch("shutil.which", return_value="/usr/bin/subfinder"):
        integration = SubfinderIntegration()
        assert integration.check_prerequisites() is True


def test_check_prerequisites_failure():
    """Test the check_prerequisites method when subfinder is not available."""
    with patch("shutil.which", return_value=None):
        integration = SubfinderIntegration()
        assert integration.check_prerequisites() is False


@pytest.mark.asyncio
async def test_run_success(subfinder_integration, tmp_path):
    """Test successful execution of subfinder."""
    # Create a temporary file that will be used as output
    output_file = tmp_path / "output.txt"

    # Mock the tempfile.NamedTemporaryFile to return our controlled file
    mock_file = MagicMock()
    mock_file.name = str(output_file)

    # Mock successful execution
    mock_result = ExecutionResult(
        command=["subfinder", "-d", "example.com", "-o", str(output_file)],
        stdout="Subfinder successful run",
        stderr="",
        return_code=0,
        timed_out=False,
    )
    subfinder_integration._executor.execute.return_value = mock_result

    # Create the actual output file that would be created by subfinder
    output_file.write_text("sub1.example.com\nsub2.example.com\n")

    with patch("tempfile.NamedTemporaryFile", return_value=mock_file):
        with patch.object(mock_file, "__enter__", return_value=mock_file):
            result = await subfinder_integration.run("example.com")

    # Verify the correct command was executed
    subfinder_integration._executor.execute.assert_called_once()
    assert isinstance(result, Path)
    assert result == output_file


@pytest.mark.asyncio
async def test_run_failure(subfinder_integration):
    """Test handling of subfinder execution failure."""
    # Mock failed execution
    mock_result = ExecutionResult(
        command=["subfinder", "-d", "example.com"],
        stdout="",
        stderr="Error: could not run subfinder",
        return_code=1,
        timed_out=False,
    )
    subfinder_integration._executor.execute.return_value = mock_result

    # Mock a non-existent output file
    with patch("tempfile.NamedTemporaryFile"):
        with patch("pathlib.Path.exists", return_value=False):
            with patch("pathlib.Path.unlink"):
                result = await subfinder_integration.run("example.com")

    assert isinstance(result, ExecutionResult)
    assert result.return_code == 1


def test_parse_output_success(subfinder_integration, temp_results_file):
    """Test successful parsing of subfinder output."""
    subfinder_integration._last_target_domain = "example.com"

    findings = subfinder_integration.parse_output(temp_results_file)

    assert findings is not None
    assert len(findings) == 4  # 4 valid lines in the test file

    # Check the first finding
    assert isinstance(findings[0], SubdomainFinding)
    assert findings[0].subdomain == "sub1.example.com"
    assert findings[0].target == "example.com"
    assert findings[0].severity == FindingSeverity.INFO
    assert "Discovered subdomain" in findings[0].description
    assert findings[0].source_tool == "subfinder"


def test_parse_output_empty_file(subfinder_integration, tmp_path):
    """Test parsing when output file is empty."""
    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("")

    subfinder_integration._last_target_domain = "example.com"

    findings = subfinder_integration.parse_output(empty_file)

    assert findings is None


@pytest.mark.asyncio
async def test_scan_integration(subfinder_integration, temp_results_file):
    """Test the scan method that combines run and parse_output."""
    # Mock successful run to return our temp file
    subfinder_integration.run = AsyncMock(return_value=temp_results_file)

    # Mock successful parsing
    subfinder_integration._last_target_domain = "example.com"

    findings = await subfinder_integration.scan("example.com")

    assert len(findings) == 4
    subfinder_integration.run.assert_called_once_with("example.com", options={})
