import logging
import shutil
from typing import Any

from src.integrations.base import ToolIntegration, ToolIntegrationError
from src.integrations.executors import ExecutionResult, SubprocessExecutor

log = logging.getLogger(__name__)


class NmapIntegration(ToolIntegration):
    """Integration for the Nmap network scanner."""

    def __init__(self, executor: SubprocessExecutor | None = None) -> None:
        self._executor = executor or SubprocessExecutor()
        self._nmap_path = shutil.which("nmap")

    @property
    def tool_name(self) -> str:
        return "nmap"

    def check_prerequisites(self) -> bool:
        """Check if the nmap executable is found in PATH."""
        if not self._nmap_path:
            log.error("nmap executable not found in PATH.")
            return False
        log.debug(f"Found nmap executable at: {self._nmap_path}")
        return True

    async def run(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ExecutionResult:
        """Run nmap against the target."""
        if not self.check_prerequisites():
            raise ToolIntegrationError("Nmap prerequisites not met.")
        # Ensure path is not None after prerequisite check
        assert self._nmap_path is not None

        # Basic command: Fast scan (-F)
        # TODO: Allow customization via options
        command = [self._nmap_path, "-F", target]

        log.info(f"Running Nmap scan on {target}...")
        try:
            # Default timeout can be adjusted via options later
            timeout = options.get("timeout_seconds", 600) if options else 600
            result = await self._executor.execute(command, timeout_seconds=timeout)
            if result.timed_out:
                log.warning(f"Nmap scan on {target} timed out.")
                # Include partial output if available
            elif result.return_code != 0:
                log.error(f"Nmap scan failed on {target}. Error: {result.stderr}")
                # Raise error or return result? Returning for now.
            else:
                log.info(f"Nmap scan completed for {target}.")

            return result  # Return the full execution result for now
        except Exception as e:
            log.exception(f"An unexpected error occurred during Nmap execution: {e}")
            raise ToolIntegrationError(f"Nmap execution failed: {e}") from e

    def parse_output(self, raw_output: ExecutionResult) -> Any:
        """Parse Nmap output (basic implementation - returns stdout)."""
        log.debug("Parsing Nmap output (current: returning raw stdout).")
        # TODO: Implement actual Nmap output parsing (e.g., XML or grepable)
        if raw_output.return_code != 0 or raw_output.timed_out:
            log.warning("Cannot parse output from failed or timed-out Nmap scan.")
            return None  # Or return structured error data

        return raw_output.stdout
