# import asyncio # No longer used directly
import shlex
import sys

import pytest

from src.integrations.base import ToolIntegrationError
from src.integrations.executors import SubprocessExecutor

# Remove module-level mark
# pytestmark = pytest.mark.asyncio


@pytest.mark.asyncio  # Mark only async tests
async def test_subprocess_executor_success() -> None:
    """Test executing a simple successful command."""
    executor = SubprocessExecutor()
    # Use python -c to print known output
    cmd_args = [
        sys.executable,
        "-c",
        "import sys; sys.stdout.write('OK'); sys.stderr.write('ERR')",
    ]
    result = await executor.execute(cmd_args, timeout_seconds=10)

    expected_command_str = shlex.join(cmd_args)
    assert result.command == expected_command_str
    assert result.return_code == 0
    assert result.stdout == "OK"
    assert result.stderr == "ERR"
    assert not result.timed_out


@pytest.mark.asyncio  # Mark only async tests
async def test_subprocess_executor_failure() -> None:
    """Test executing a command that fails."""
    executor = SubprocessExecutor()
    command = [sys.executable, "-c", "import sys; sys.exit(1)"]
    result = await executor.execute(command, timeout_seconds=10)

    assert result.return_code == 1
    assert not result.timed_out


@pytest.mark.asyncio  # Mark only async tests
async def test_subprocess_executor_timeout() -> None:
    """Test executing a command that times out."""
    executor = SubprocessExecutor()
    # Command that sleeps longer than the timeout
    command = [sys.executable, "-c", "import time; time.sleep(5)"]
    result = await executor.execute(command, timeout_seconds=1)

    assert result.timed_out
    # Return code might vary depending on termination signal, focus on timeout flag
    assert result.return_code != 0


@pytest.mark.asyncio  # Mark only async tests
async def test_subprocess_executor_command_not_found() -> None:
    """Test executing a non-existent command."""
    executor = SubprocessExecutor()
    command = ["non_existent_command_hopefully_12345"]

    with pytest.raises(ToolIntegrationError, match="Command not found"):
        await executor.execute(command, timeout_seconds=5)
