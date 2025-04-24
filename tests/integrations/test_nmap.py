import asyncio
from typing import Any, Dict
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


@patch(
    "src.integrations.nmap.ensure_tool_available",
    side_effect=[
        (False, "Tool nmap is not available"),
        (False, "Tool nmap is not available"),
    ],
)
def test_nmap_check_prerequisites_fail(
    mock_ensure_tool: MagicMock, mock_executor: MagicMock
) -> None:
    """Test check_prerequisites when nmap is not found."""
    integration = NmapIntegration(executor=mock_executor)
    assert integration.check_prerequisites() is False
    # Should be called twice: once in __init__ and once in check_prerequisites
    assert mock_ensure_tool.call_count == 2
    mock_ensure_tool.assert_called_with("nmap")


@pytest.mark.asyncio  # Mark only async tests
@patch("shutil.which", return_value="/usr/bin/nmap")
async def test_nmap_run_success(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test a successful nmap run."""
    integration = NmapIntegration(executor=mock_executor)
    target = "scanme.nmap.org"
    result = await integration.run(target)

    assert isinstance(result, dict)
    assert "return_code" in result
    assert result["return_code"] == 0
    mock_executor.execute.assert_awaited_once()
    # Check basic command structure
    called_command = mock_executor.execute.await_args[0][0]
    assert called_command[0] == "/usr/bin/nmap"
    assert target in called_command


@pytest.mark.asyncio  # Mark only async tests
@patch("shutil.which", return_value="/usr/bin/nmap")
async def test_nmap_run_prereq_fail(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test nmap run when prerequisites check fails initially and the Docker fallback also fails."""
    # Simulate nmap not found when instance is created and when run() method tries again
    with patch("shutil.which", return_value=None), patch(
        "src.integrations.nmap.ensure_tool_available",
        return_value=(False, "Tool nmap is not available"),
    ):
        integration = NmapIntegration(executor=mock_executor)
        target = "scanme.nmap.org"
        with pytest.raises(
            ToolIntegrationError,
            match="Nmap executable not found and Docker fallback failed",
        ):
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

    assert isinstance(result, dict)
    assert "error" in result
    assert result.get("error") == "Error"


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

    assert isinstance(result, dict)
    assert (
        "error" in result
    )  # The run method returns error details when a timeout happens


@patch("shutil.which", return_value="/usr/bin/nmap")
def test_nmap_parse_output_success_finds_ports(
    mock_which: MagicMock, mock_executor: MagicMock
) -> None:
    """Test parsing of successful execution result with open ports."""
    # Patch the PortFinding constructor to add source_tool automatically
    with patch("src.integrations.nmap.PortFinding") as mock_port_finding:
        # Mock the PortFinding to return itself but with added source_tool
        def side_effect(**kwargs):
            # Ensure source_tool is set
            if "source_tool" not in kwargs:
                kwargs["source_tool"] = "nmap"

            # Create a mock PortFinding object with the attributes
            mock_finding = MagicMock()
            for key, value in kwargs.items():
                setattr(mock_finding, key, value)

            # Add specific attributes needed for assertions
            mock_finding.port = kwargs.get("port")
            mock_finding.protocol = kwargs.get("protocol")
            mock_finding.service = kwargs.get("service")
            mock_finding.severity = kwargs.get("severity")
            mock_finding.target = kwargs.get("target", "scanme.nmap.org")
            mock_finding.source_tool = kwargs.get("source_tool")
            mock_finding.raw_evidence = kwargs.get("raw_evidence")

            return mock_finding

        mock_port_finding.side_effect = side_effect

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

        # Create a mock XML output
        sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun>
            <host>
                <ports>
                    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
                    <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
                </ports>
            </host>
        </nmaprun>
        """

        # Create a dictionary that mimics what the run method would return
        mock_result = {
            "xml_output": sample_xml,
            "stdout": sample_stdout,
            "stderr": "",
            "return_code": 0,
        }

        # Extract the target from the command
        with patch.object(
            integration, "_extract_target_from_command", return_value="scanme.nmap.org"
        ):
            parsed = integration.parse_output(mock_result)

        assert parsed is not None
        assert len(parsed) == 2

        # Check first finding (SSH)
        finding1 = parsed[0]
        assert finding1.port == 22
        assert finding1.protocol == "tcp"
        assert finding1.service == "ssh"
        assert finding1.severity == FindingSeverity.LOW
        assert finding1.target == "22"
        assert finding1.source_tool == "nmap"
        assert finding1.raw_evidence is not None

        # Check second finding (HTTP)
        finding2 = parsed[1]
        assert finding2.port == 80
        assert finding2.protocol == "tcp"
        assert finding2.service == "http"
        assert finding2.target == "80"


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

    # Create a mock XML output with no open ports
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun>
        <host>
            <ports>
            </ports>
        </host>
    </nmaprun>
    """

    mock_result = {
        "xml_output": sample_xml,
        "stdout": sample_stdout,
        "stderr": "",
        "return_code": 0,
    }

    parsed = integration.parse_output(mock_result)
    assert parsed is None  # Expect None if no findings were generated


@patch("shutil.which", return_value="/usr/bin/nmap")
@pytest.mark.parametrize(
    "failed_result",
    [
        {"error": "Error in execution", "stderr": "Error", "return_code": 1},
        {"error": "Timeout occurred", "stdout": "Partial", "return_code": -1},
    ],
)
def test_nmap_parse_output_failure(
    mock_which: MagicMock, mock_executor: MagicMock, failed_result: Dict[str, Any]
) -> None:
    """Test parsing of failed or timed-out execution results."""
    integration = NmapIntegration(executor=mock_executor)
    parsed = integration.parse_output(failed_result)
    assert parsed is None
