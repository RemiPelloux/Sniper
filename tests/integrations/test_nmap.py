from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.base import ToolIntegrationError
from src.integrations.executors import ExecutionResult
from src.integrations.nmap import NmapIntegration

# Import result types
from src.results.types import FindingSeverity, PortFinding

# Remove module-level mark
# pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock_executor() -> MagicMock:
    """Fixture to create a mock SubprocessExecutor."""
    executor = MagicMock(spec=AsyncMock)  # Use AsyncMock for execute method
    # Set default return value for execute
    executor.execute = AsyncMock(
        return_value=ExecutionResult(
            command="mock nmap command",
            return_code=0,
            stdout="Nmap scan report for ...",
            stderr="",
            timed_out=False,
        )
    )
    return executor


@patch("shutil.which", return_value="/usr/bin/nmap")  # Mock finding nmap
def test_nmap_check_prerequisites_success(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test check_prerequisites when nmap is found."""
    integration = NmapIntegration(executor=mock_executor)
    assert integration.check_prerequisites() is True
    mock_which.assert_called_once_with("nmap")


@patch("shutil.which", return_value=None)  # Mock not finding nmap
def test_nmap_check_prerequisites_fail(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test check_prerequisites when nmap is not found."""
    integration = NmapIntegration(executor=mock_executor)
    assert integration.check_prerequisites() is False
    mock_which.assert_called_once_with("nmap")


@pytest.mark.asyncio  # Mark only async tests
@patch("shutil.which", return_value="/usr/bin/nmap")
async def test_nmap_run_success(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test a successful nmap run."""
    integration = NmapIntegration(executor=mock_executor)
    target = "scanme.nmap.org"
    result = await integration.run(target)

    assert isinstance(result, ExecutionResult)
    assert result.return_code == 0
    mock_executor.execute.assert_awaited_once()
    # Check basic command structure
    called_command = mock_executor.execute.await_args[0][0]
    assert called_command == ["/usr/bin/nmap", "-F", target]


@pytest.mark.asyncio  # Mark only async tests
@patch("shutil.which", return_value="/usr/bin/nmap")
async def test_nmap_run_prereq_fail(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test nmap run when prerequisites check fails initially."""
    # Simulate nmap not found when instance is created
    with patch("shutil.which", return_value=None):
        integration = NmapIntegration(executor=mock_executor)

    target = "scanme.nmap.org"
    with pytest.raises(ToolIntegrationError, match="Nmap prerequisites not met"):
        await integration.run(target)
    mock_executor.execute.assert_not_awaited()


@pytest.mark.asyncio  # Mark only async tests
@patch("shutil.which", return_value="/usr/bin/nmap")
async def test_nmap_run_execution_fail(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test nmap run when executor returns a non-zero exit code."""
    mock_executor.execute.return_value = ExecutionResult(
        command="nmap -F target",
        return_code=1,
        stdout="",
        stderr="Error",
        timed_out=False,
    )
    integration = NmapIntegration(executor=mock_executor)
    target = "scanme.nmap.org"
    result = await integration.run(target)

    assert result.return_code == 1
    assert result.stderr == "Error"


@pytest.mark.asyncio  # Mark only async tests
@patch("shutil.which", return_value="/usr/bin/nmap")
async def test_nmap_run_timeout(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test nmap run when executor indicates a timeout."""
    mock_executor.execute.return_value = ExecutionResult(
        command="nmap -F target",
        return_code=-1,
        stdout="Partial",
        stderr="",
        timed_out=True,
    )
    integration = NmapIntegration(executor=mock_executor)
    target = "scanme.nmap.org"
    result = await integration.run(target)

    assert result.timed_out is True


@patch("shutil.which", return_value="/usr/bin/nmap")
def test_nmap_parse_output_success_finds_ports(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test parsing of successful execution result with open ports."""
    integration = NmapIntegration(executor=mock_executor)
    # Sample output mimicking nmap's text format
    sample_stdout = """
    Starting Nmap 7.92 ( https://nmap.org )
    Nmap scan report for scanme.nmap.org (45.33.32.156)
    Host is up (0.11s latency).
    Not shown: 997 filtered ports
    PORT      STATE  SERVICE
    22/tcp    open   ssh
    80/tcp    open   http
    31337/udp closed elite

    Nmap done: 1 IP address (1 host up) scanned in 15.75 seconds
    """
    mock_result = ExecutionResult(
        command="nmap -F scanme.nmap.org",  # Include target for extraction
        return_code=0,
        stdout=sample_stdout,
        stderr="",
        timed_out=False,
    )
    parsed = integration.parse_output(mock_result)

    assert parsed is not None
    assert len(parsed) == 2

    # Check first finding (SSH)
    finding1 = parsed[0]
    assert isinstance(finding1, PortFinding)
    assert finding1.port == 22
    assert finding1.protocol == "tcp"
    assert finding1.service == "ssh"
    assert finding1.severity == FindingSeverity.INFO
    assert finding1.target == "scanme.nmap.org"
    assert finding1.source_tool == "nmap"
    assert finding1.raw_evidence is not None
    assert isinstance(finding1.raw_evidence, str)
    assert "22/tcp    open   ssh" in finding1.raw_evidence

    # Check second finding (HTTP)
    finding2 = parsed[1]
    assert isinstance(finding2, PortFinding)
    assert finding2.port == 80
    assert finding2.protocol == "tcp"
    assert finding2.service == "http"
    assert finding2.target == "scanme.nmap.org"


@patch("shutil.which", return_value="/usr/bin/nmap")
def test_nmap_parse_output_success_no_ports(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test parsing when nmap output shows no open ports."""
    integration = NmapIntegration(executor=mock_executor)
    sample_stdout = """
    Nmap scan report for example.com (93.184.216.34)
    Host is up.
    All 100 scanned ports on example.com (93.184.216.34) are in ignored states.
    Not shown: 100 filtered ports
    Nmap done: 1 IP address (1 host up) scanned in 2.35 seconds
    """
    mock_result = ExecutionResult(
        command="nmap -F example.com",
        return_code=0,
        stdout=sample_stdout,
        stderr="",
        timed_out=False,
    )
    parsed = integration.parse_output(mock_result)
    assert parsed is None  # Expect None if no findings were generated


@patch("shutil.which", return_value="/usr/bin/nmap")
@pytest.mark.parametrize(
    "failed_result",
    [
        ExecutionResult(
            command="nmap -F target",
            return_code=1,
            stdout="",
            stderr="Error",
            timed_out=False,
        ),
        ExecutionResult(
            command="nmap -F target",
            return_code=-1,
            stdout="Partial",
            stderr="",
            timed_out=True,
        ),
    ],
)
def test_nmap_parse_output_failure(
    mock_which: MagicMock, mock_executor: MagicMock, failed_result: ExecutionResult
) -> None:
    """Test parsing of failed or timed-out execution results."""
    integration = NmapIntegration(executor=mock_executor)
    parsed = integration.parse_output(failed_result)
    assert parsed is None
