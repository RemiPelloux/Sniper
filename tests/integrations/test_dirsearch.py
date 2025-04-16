import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.base import ToolIntegrationError
from src.integrations.dirsearch import DirsearchIntegration
from src.integrations.executors import ExecutionResult

# Import result types
from src.results.types import FindingSeverity, WebFinding

# Remove module-level mark
# pytestmark = pytest.mark.asyncio

# Mock dirsearch paths
MOCK_DIRSEARCH_EXEC = "/usr/local/bin/dirsearch"
MOCK_DIRSEARCH_SCRIPT = "/path/to/dirsearch.py"


@pytest.fixture
def mock_executor() -> MagicMock:
    """Fixture to create a mock SubprocessExecutor."""
    executor = MagicMock(spec=AsyncMock)
    executor.execute = AsyncMock(
        return_value=ExecutionResult(
            command="mock dirsearch command",
            return_code=0,
            stdout="",  # Dirsearch output goes to file
            stderr="",
            timed_out=False,
        )
    )
    return executor


# --- Prerequisite Tests ---


@patch(
    "shutil.which",
    side_effect=lambda x: MOCK_DIRSEARCH_EXEC if x == "dirsearch" else None,
)
def test_dirsearch_check_prerequisites_exec_success(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = DirsearchIntegration(executor=mock_executor)
    assert integration.check_prerequisites() is True
    assert integration._dirsearch_path == MOCK_DIRSEARCH_EXEC
    assert not integration._is_script


@patch(
    "shutil.which",
    side_effect=lambda x: MOCK_DIRSEARCH_SCRIPT if x == "dirsearch.py" else None,
)
def test_dirsearch_check_prerequisites_script_success(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = DirsearchIntegration(executor=mock_executor)
    assert integration.check_prerequisites() is True
    assert integration._dirsearch_path == MOCK_DIRSEARCH_SCRIPT
    assert integration._is_script


@patch("shutil.which", return_value=None)
def test_dirsearch_check_prerequisites_fail(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = DirsearchIntegration(executor=mock_executor)
    assert integration.check_prerequisites() is False


# --- Run Tests ---


@pytest.mark.asyncio  # Mark only async tests
@patch("shutil.which", return_value=MOCK_DIRSEARCH_EXEC)
async def test_dirsearch_run_success_returns_path(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = DirsearchIntegration(executor=mock_executor)
    target = "http://example.com"
    result = await integration.run(target)

    assert isinstance(result, Path)
    assert result.suffix == ".json"
    mock_executor.execute.assert_awaited_once()
    called_command = mock_executor.execute.await_args[0][0]
    assert called_command[0] == MOCK_DIRSEARCH_EXEC
    assert "--json-report" in called_command
    assert str(result) in called_command
    assert "-u" in called_command
    assert target in called_command
    # Clean up the dummy file path returned by the test
    result.unlink(missing_ok=True)


@pytest.mark.asyncio  # Mark only async tests
@patch("shutil.which", return_value=MOCK_DIRSEARCH_SCRIPT)
async def test_dirsearch_run_script_uses_python(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = DirsearchIntegration(executor=mock_executor)
    target = "http://example.com"
    result = await integration.run(target)

    assert isinstance(result, Path)
    mock_executor.execute.assert_awaited_once()
    called_command = mock_executor.execute.await_args[0][0]
    assert called_command[0] == sys.executable
    assert called_command[1] == MOCK_DIRSEARCH_SCRIPT
    result.unlink(missing_ok=True)


@pytest.mark.asyncio  # Mark only async tests
@patch("shutil.which", return_value=MOCK_DIRSEARCH_EXEC)
async def test_dirsearch_run_fail_returns_result(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    mock_executor.execute.return_value = ExecutionResult(
        command="dirsearch ...",
        return_code=1,
        stdout="",
        stderr="Error",
        timed_out=False,
    )
    integration = DirsearchIntegration(executor=mock_executor)
    target = "http://example.com"
    result = await integration.run(target)

    assert isinstance(result, ExecutionResult)
    assert result.return_code == 1


@pytest.mark.asyncio  # Mark only async tests
@patch("shutil.which", return_value=MOCK_DIRSEARCH_EXEC)
async def test_dirsearch_run_timeout_returns_result(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    mock_executor.execute.return_value = ExecutionResult(
        command="dirsearch ...", return_code=-1, stdout="", stderr="", timed_out=True
    )
    integration = DirsearchIntegration(executor=mock_executor)
    target = "http://example.com"
    result = await integration.run(target)

    assert isinstance(result, ExecutionResult)
    assert result.timed_out


@pytest.mark.asyncio  # Mark only async tests
@patch("shutil.which", return_value=None)
async def test_dirsearch_run_prereq_fail_raises(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = DirsearchIntegration(executor=mock_executor)
    target = "http://example.com"
    with pytest.raises(ToolIntegrationError, match="Dirsearch prerequisites not met"):
        await integration.run(target)
    mock_executor.execute.assert_not_awaited()


# --- Parse Output Tests ---


@patch("shutil.which", return_value=MOCK_DIRSEARCH_EXEC)
def test_dirsearch_parse_success(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test parsing a valid Dirsearch JSON report."""
    integration = DirsearchIntegration(executor=mock_executor)
    target_url = "http://example.com"
    sample_data = {
        target_url: [
            {
                "status": 200,
                "url": f"{target_url}/index.html",
                "content-type": "text/html",
            },
            {"status": 403, "url": f"{target_url}/admin", "content-type": "text/html"},
            {
                "status": 301,
                "url": f"{target_url}/redirect",
                "content-type": "text/html",
            },
            {
                "status": 500,
                "url": f"{target_url}/error",
                "content-type": "text/html",
            },  # Should be filtered by run command
        ]
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(sample_data, f)
        report_path = Path(f.name)

    parsed = integration.parse_output(report_path)

    assert parsed is not None
    assert len(parsed) == 4  # Expect 4 findings, including the 500 error

    # Finding 1 (index.html)
    f1 = parsed[0]
    assert isinstance(f1, WebFinding)
    assert f1.target == target_url
    assert f1.url == f"{target_url}/index.html"
    assert f1.status_code == 200
    assert f1.severity == FindingSeverity.LOW
    assert f1.source_tool == "dirsearch"
    assert isinstance(f1.raw_evidence, dict)
    assert f1.raw_evidence["status"] == 200

    # Finding 2 (admin)
    f2 = parsed[1]
    assert isinstance(f2, WebFinding)
    assert f2.target == target_url
    assert f2.url == f"{target_url}/admin"
    assert f2.status_code == 403
    assert f2.severity == FindingSeverity.MEDIUM

    # Finding 3 (redirect)
    f3 = parsed[2]
    assert isinstance(f3, WebFinding)
    assert f3.target == target_url
    assert f3.url == f"{target_url}/redirect"
    assert f3.status_code == 301
    assert f3.severity == FindingSeverity.INFO

    # Check file was deleted by parser
    assert not report_path.exists()


@patch("shutil.which", return_value=MOCK_DIRSEARCH_EXEC)
def test_dirsearch_parse_success_empty_results(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test parsing a valid report with no findings."""
    integration = DirsearchIntegration(executor=mock_executor)
    target_url = "http://example.com"
    sample_data: dict[str, list] = {target_url: []}  # Empty list of results
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(sample_data, f)
        report_path = Path(f.name)

    parsed = integration.parse_output(report_path)
    assert parsed is None  # Expect None if no findings were generated
    assert not report_path.exists()


@patch("shutil.which", return_value=MOCK_DIRSEARCH_EXEC)
def test_dirsearch_parse_non_json_file(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test parsing a file that is not valid JSON."""
    integration = DirsearchIntegration(executor=mock_executor)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("this is not json")
        report_path = Path(f.name)

    parsed = integration.parse_output(report_path)
    assert parsed is None
    assert not report_path.exists()  # Should still delete corrupted file


@patch("shutil.which", return_value=MOCK_DIRSEARCH_EXEC)
def test_dirsearch_parse_file_not_found(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = DirsearchIntegration(executor=mock_executor)
    non_existent_path = Path("non_existent_dirsearch_report.json")
    parsed = integration.parse_output(non_existent_path)
    assert parsed is None


@patch("shutil.which", return_value=MOCK_DIRSEARCH_EXEC)
def test_dirsearch_parse_failed_execution_result(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = DirsearchIntegration(executor=mock_executor)
    failed_result = ExecutionResult("cmd", 1, "", "err", False)
    parsed = integration.parse_output(failed_result)
    assert parsed is None
