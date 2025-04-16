import asyncio
import logging
import shlex
from abc import ABC, abstractmethod
from dataclasses import dataclass

from src.integrations.base import ToolIntegrationError

log = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of executing an external command."""

    command: str
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class BaseExecutor(ABC):
    """Abstract base class for tool execution strategies."""

    @abstractmethod
    async def execute(
        self, command: list[str], timeout_seconds: int | None = 60
    ) -> ExecutionResult:
        """Execute a command and return its result."""
        pass


class SubprocessExecutor(BaseExecutor):
    """Executes tools using asyncio.create_subprocess_exec."""

    async def execute(
        self, command: list[str], timeout_seconds: int | None = 60
    ) -> ExecutionResult:
        """Execute a command using subprocess and capture output."""
        command_str = shlex.join(command)
        log.debug(f"Executing command: {command_str}")

        stdout_data = b""
        stderr_data = b""
        process = None
        timed_out = False
        return_code: int | None = None  # Allow None initially

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(), timeout=timeout_seconds
                )
                return_code = process.returncode
            except asyncio.TimeoutError:
                log.warning(
                    f"Command timed out after {timeout_seconds}s: {command_str}"
                )
                timed_out = True
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    log.error(
                        f"Failed to terminate process after timeout, killing: "
                        f"{command_str}"
                    )
                    process.kill()
                except ProcessLookupError:
                    pass  # Process already finished
                finally:
                    # Ensure communicate() is called even after timeout/terminate
                    # to avoid resource warnings, but capture potential partial output
                    try:
                        stdout_res, stderr_res = await process.communicate()
                        stdout_data += stdout_res
                        stderr_data += stderr_res
                    except Exception:  # Broad except as process state is uncertain
                        log.debug(
                            "Error during final communicate after timeout/terminate."
                        )
                    # process.returncode can be None if killed before exit status set
                    return_code = process.returncode if process else None

            stdout_str = stdout_data.decode(errors="ignore")
            stderr_str = stderr_data.decode(errors="ignore")

            final_return_code = (
                return_code if return_code is not None else -1
            )  # Use default if None

            if final_return_code != 0 and not timed_out:
                log.warning(
                    f"Command '{command_str}' failed with code {final_return_code}. "
                    f"Stderr: {stderr_str[:500]}..."
                )
            elif timed_out:
                log.warning(f"Command '{command_str}' timed out.")
            else:
                log.debug(f"Command finished successfully: {command_str}")

            return ExecutionResult(
                command=command_str,
                return_code=final_return_code,  # Use the handled value
                stdout=stdout_str,
                stderr=stderr_str,
                timed_out=timed_out,
            )

        except FileNotFoundError:
            log.error(f"Command not found: {command[0]}")
            raise ToolIntegrationError(f"Command not found: {command[0]}") from None
        except Exception as e:
            log.error(f"Error executing command '{command_str}': {e}", exc_info=True)
            raise ToolIntegrationError(f"Failed to execute command: {e}") from e
