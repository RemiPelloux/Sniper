import logging
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from src.integrations.base import ToolIntegration, ToolIntegrationError
from src.integrations.executors import ExecutionResult, SubprocessExecutor

log = logging.getLogger(__name__)


class Sublist3rIntegration(ToolIntegration):
    """Integration for the Sublist3r subdomain enumeration tool."""

    def __init__(self, executor: SubprocessExecutor | None = None) -> None:
        self._executor = executor or SubprocessExecutor()
        # Check for sublist3r.py or sublist3r executable
        # Prefer script if available, as it might be cloned repo
        self._sublist3r_path = shutil.which("sublist3r.py") or shutil.which("sublist3r")
        self._is_script = self._sublist3r_path and self._sublist3r_path.endswith(".py")

    @property
    def tool_name(self) -> str:
        return "sublist3r"

    def check_prerequisites(self) -> bool:
        """Check if sublist3r executable/script is found."""
        if not self._sublist3r_path:
            log.error("sublist3r.py or sublist3r executable not found in PATH.")
            return False
        log.debug(f"Found sublist3r at: {self._sublist3r_path}")
        return True

    async def run(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ExecutionResult | Path:
        """Run sublist3r against the target domain, saving results to a file.

        Args:
            target: The domain name (e.g., example.com).
            options: Tool-specific options (e.g., timeout_seconds).

        Returns:
            Path to the output file on success, or ExecutionResult on failure/timeout.
        """
        if not self.check_prerequisites():
            raise ToolIntegrationError("Sublist3r prerequisites not met.")
        assert self._sublist3r_path is not None

        options = options or {}
        timeout = options.get("timeout_seconds", 600)  # Default timeout

        # Create a temporary file for the output
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".txt", mode="w", encoding="utf-8"
        ) as output_file:
            output_path = Path(output_file.name)

        command = []
        if self._is_script:
            command.append(sys.executable)  # Use current python interpreter
        command.append(self._sublist3r_path)
        command.extend(
            [
                "-d",
                target,
                "-o",
                str(output_path),
            ]
        )
        # Add other options if needed, e.g., -t threads, -p ports
        # command.extend(["-t", "10"])

        log.info(f"Running Sublist3r scan on {target}...")
        try:
            result = await self._executor.execute(command, timeout_seconds=timeout)

            if result.timed_out:
                log.warning(f"Sublist3r scan on {target} timed out.")
                output_path.unlink(missing_ok=True)
                return result
            elif result.return_code != 0:
                # Sublist3r might exit non-zero even if it finds some results but hits errors
                # Check if output file exists and has content before logging as hard error
                if output_path.exists() and output_path.stat().st_size > 0:
                    log.warning(
                        f"Sublist3r scan on {target} finished with exit code {result.return_code}, "
                        f"but output file exists. Report file: {output_path}. Stderr: {result.stderr}"
                    )
                    return output_path  # Treat as success if output file exists
                else:
                    log.error(
                        f"Sublist3r scan failed on {target}. Exit code {result.return_code}. Error: {result.stderr}"
                    )
                    output_path.unlink(missing_ok=True)
                    return result
            else:
                log.info(
                    f"Sublist3r scan completed for {target}. Report: {output_path}"
                )
                return output_path

        except Exception as e:
            output_path.unlink(missing_ok=True)
            log.exception(
                f"An unexpected error occurred during Sublist3r execution: {e}"
            )
            raise ToolIntegrationError(f"Sublist3r execution failed: {e}") from e

    def parse_output(self, raw_output: Path | ExecutionResult) -> list[str] | None:
        """Parse Sublist3r output file (list of subdomains)."""
        if isinstance(raw_output, ExecutionResult):
            log.warning("Cannot parse output from failed/timed-out Sublist3r run.")
            return None

        output_path = raw_output
        log.debug(f"Parsing Sublist3r output file: {output_path}")
        subdomains = []
        try:
            with output_path.open("r", encoding="utf-8") as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain:  # Ignore empty lines
                        subdomains.append(subdomain)
            output_path.unlink(missing_ok=True)  # Clean up
            return subdomains
        except FileNotFoundError:
            log.error(f"Sublist3r output file not found: {output_path}")
            return None
        except Exception as e:
            log.exception(f"Error reading/parsing Sublist3r output {output_path}: {e}")
            output_path.unlink(missing_ok=True)  # Clean up
            return None
