import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.base import ToolIntegrationError
from src.integrations.executors import ExecutionResult
from src.integrations.sublist3r import Sublist3rIntegration

# Import result types
from src.results.types import FindingSeverity, SubdomainFinding

# Mock paths
MOCK_SUBLIST3R_EXEC = "/usr/local/bin/sublist3r"
MOCK_SUBLIST3R_SCRIPT = "/path/to/sublist3r.py"


@pytest.fixture
def mock_executor() -> MagicMock:
    """Fixture to create a mock SubprocessExecutor."""
    executor = MagicMock(spec=AsyncMock)
    executor.execute = AsyncMock(
        return_value=ExecutionResult(
            command="mock sublist3r command",
            return_code=0,
            stdout="",
            stderr="",
            timed_out=False,
        )
    )
    return executor


# --- Prerequisite Tests ---


@patch(
    "shutil.which",
    side_effect=lambda x: (
        MOCK_SUBLIST3R_SCRIPT
        if x == "sublist3r.py"
        else (MOCK_SUBLIST3R_EXEC if x == "sublist3r" else None)
    ),
)
def test_sublist3r_check_prerequisites_script_priority(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test that the script path is preferred if both exist."""
    integration = Sublist3rIntegration(executor=mock_executor)
    assert integration.check_prerequisites() is True
    # Use public API or specific test setup if needed,
    # avoid accessing _sublist3r_path directly
    assert integration._sublist3r_path == MOCK_SUBLIST3R_SCRIPT
    assert integration._is_script


@patch(
    "shutil.which",
    side_effect=lambda x: MOCK_SUBLIST3R_EXEC if x == "sublist3r" else None,
)
def test_sublist3r_check_prerequisites_exec_success(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = Sublist3rIntegration(executor=mock_executor)
    assert integration.check_prerequisites() is True
    assert integration._sublist3r_path == MOCK_SUBLIST3R_EXEC
    assert not integration._is_script


@patch("shutil.which", return_value=None)
def test_sublist3r_check_prerequisites_fail(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = Sublist3rIntegration(executor=mock_executor)
    assert integration.check_prerequisites() is False


# --- Run Tests ---


@pytest.mark.asyncio
@patch("shutil.which", return_value=MOCK_SUBLIST3R_EXEC)
async def test_sublist3r_run_success_returns_path(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = Sublist3rIntegration(executor=mock_executor)
    target = "example.com"
    result = await integration.run(target)

    assert isinstance(result, Path)
    assert result.suffix == ".txt"
    mock_executor.execute.assert_awaited_once()
    called_command = mock_executor.execute.await_args[0][0]
    assert called_command[0] == MOCK_SUBLIST3R_EXEC
    assert "-o" in called_command
    assert str(result) in called_command
    assert "-d" in called_command
    assert target in called_command
    result.unlink(missing_ok=True)


@pytest.mark.asyncio
@patch("shutil.which", return_value=MOCK_SUBLIST3R_SCRIPT)
async def test_sublist3r_run_script_uses_python(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = Sublist3rIntegration(executor=mock_executor)
    target = "example.com"
    result = await integration.run(target)

    assert isinstance(result, Path)
    mock_executor.execute.assert_awaited_once()
    called_command = mock_executor.execute.await_args[0][0]
    assert called_command[0] == sys.executable
    assert called_command[1] == MOCK_SUBLIST3R_SCRIPT
    result.unlink(missing_ok=True)


@pytest.mark.asyncio
@patch("shutil.which", return_value=MOCK_SUBLIST3R_EXEC)
async def test_sublist3r_run_fail_returns_result(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    mock_executor.execute.return_value = ExecutionResult(
        command="sublist3r ...",
        return_code=1,
        stdout="",
        stderr="Error",
        timed_out=False,
    )
    integration = Sublist3rIntegration(executor=mock_executor)
    target = "example.com"
    # Need to mock Path.exists and Path.stat for the failure check
    with patch.object(Path, "exists", return_value=False), patch.object(Path, "stat"):
        result = await integration.run(target)

    assert isinstance(result, ExecutionResult)
    assert result.return_code == 1


@pytest.mark.asyncio
@patch("shutil.which", return_value=MOCK_SUBLIST3R_EXEC)
async def test_sublist3r_run_fail_but_output_exists_returns_path(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test case where sublist3r exits non-zero but output file exists."""
    mock_executor.execute.return_value = ExecutionResult(
        command="sublist3r ...",
        return_code=1,
        stdout="",
        stderr="Some engines failed",
        timed_out=False,
    )
    integration = Sublist3rIntegration(executor=mock_executor)
    target = "example.com"

    # Mock Path.exists and Path.stat to simulate existing, non-empty output file
    with patch.object(Path, "exists", return_value=True), patch.object(
        Path, "stat", return_value=MagicMock(st_size=100)
    ):
        result = await integration.run(target)

    assert isinstance(result, Path)  # Should return path despite non-zero exit
    result.unlink(missing_ok=True)


@pytest.mark.asyncio
@patch("shutil.which", return_value=MOCK_SUBLIST3R_EXEC)
async def test_sublist3r_run_timeout_returns_result(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    mock_executor.execute.return_value = ExecutionResult(
        command="sublist3r ...", return_code=-1, stdout="", stderr="", timed_out=True
    )
    integration = Sublist3rIntegration(executor=mock_executor)
    target = "example.com"
    result = await integration.run(target)

    assert isinstance(result, ExecutionResult)
    assert result.timed_out


@pytest.mark.asyncio
@patch("shutil.which", return_value=None)
async def test_sublist3r_run_prereq_fail_raises(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = Sublist3rIntegration(executor=mock_executor)
    target = "example.com"
    with pytest.raises(ToolIntegrationError, match="Sublist3r prerequisites not met"):
        await integration.run(target)
    mock_executor.execute.assert_not_awaited()


# --- Parse Output Tests ---


@patch("shutil.which", return_value=MOCK_SUBLIST3R_EXEC)
def test_sublist3r_parse_success(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test parsing a valid Sublist3r output file."""
    integration = Sublist3rIntegration(executor=mock_executor)
    # Simulate that run was called with this target
    target_domain = "example.com"
    integration._last_target_domain = target_domain

    sample_content = "one.example.com\ntwo.example.com\n\nthree.example.com\n"
    # expected_subdomains = ["one.example.com", "two.example.com", "three.example.com"]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(sample_content)
        output_path = Path(f.name)

    parsed = integration.parse_output(output_path)

    assert parsed is not None
    assert len(parsed) == 3

    # Check finding 1
    f1 = parsed[0]
    assert isinstance(f1, SubdomainFinding)
    assert f1.target == target_domain
    assert f1.subdomain == "one.example.com"
    assert f1.severity == FindingSeverity.INFO
    assert f1.source_tool == "sublist3r"
    assert f1.raw_evidence == "one.example.com"

    # Check finding 2
    f2 = parsed[1]
    assert isinstance(f2, SubdomainFinding)
    assert f2.subdomain == "two.example.com"
    assert f2.target == target_domain

    # Check finding 3
    f3 = parsed[2]
    assert isinstance(f3, SubdomainFinding)
    assert f3.subdomain == "three.example.com"

    # assert parsed == expected_subdomains # Old assertion
    assert not output_path.exists()  # File should be deleted after parsing


@patch("shutil.which", return_value=MOCK_SUBLIST3R_EXEC)
def test_sublist3r_parse_success_empty_file(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test parsing an empty output file."""
    integration = Sublist3rIntegration(executor=mock_executor)
    integration._last_target_domain = "example.com"
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        output_path = Path(f.name)

    parsed = integration.parse_output(output_path)
    assert parsed is None
    assert not output_path.exists()


@patch("shutil.which", return_value=MOCK_SUBLIST3R_EXEC)
def test_sublist3r_parse_file_not_found(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = Sublist3rIntegration(executor=mock_executor)
    non_existent_path = Path("non_existent_sublist3r_output.txt")
    parsed = integration.parse_output(non_existent_path)
    assert parsed is None


@patch("shutil.which", return_value=MOCK_SUBLIST3R_EXEC)
def test_sublist3r_parse_failed_execution_result(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    integration = Sublist3rIntegration(executor=mock_executor)
    failed_result = ExecutionResult("cmd", 1, "", "err", False)
    parsed = integration.parse_output(failed_result)
    assert parsed is None


@patch("shutil.which", return_value=MOCK_SUBLIST3R_EXEC)
def test_sublist3r_parse_handles_exception(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test that parsing handles exceptions during file reading and cleans up."""
    integration = Sublist3rIntegration(executor=mock_executor)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        output_path = Path(f.name)

    with patch.object(Path, "open") as mock_open:
        mock_open.side_effect = OSError("Test read error")
        parsed = integration.parse_output(output_path)

    assert parsed is None
    assert not output_path.exists()  # Ensure cleanup happens even on error
