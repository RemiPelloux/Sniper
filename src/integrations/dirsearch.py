import json
import logging

# import os # Unused
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from src.integrations.base import ToolIntegration, ToolIntegrationError
from src.integrations.executors import ExecutionResult, SubprocessExecutor

log = logging.getLogger(__name__)

# Common extensions, could be configurable
DEFAULT_EXTENSIONS = "php,html,js,txt,bak,config,json,xml"


class DirsearchIntegration(ToolIntegration):
    """Integration for the Dirsearch directory enumerator."""

    def __init__(self, executor: SubprocessExecutor | None = None) -> None:
        self._executor = executor or SubprocessExecutor()
        # Check for dirsearch.py or dirsearch executable
        self._dirsearch_path = shutil.which("dirsearch") or shutil.which("dirsearch.py")
        self._is_script = self._dirsearch_path and self._dirsearch_path.endswith(".py")

    @property
    def tool_name(self) -> str:
        return "dirsearch"

    def check_prerequisites(self) -> bool:
        """Check if dirsearch executable/script is found."""
        if not self._dirsearch_path:
            log.error("dirsearch executable or dirsearch.py not found in PATH.")
            return False
        log.debug(f"Found dirsearch at: {self._dirsearch_path}")
        return True

    async def run(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ExecutionResult | Path:
        """Run dirsearch against the target, saving results to a JSON file.

        Returns:
            Path to the JSON report file on success, or ExecutionResult on failure/timeout.
        """
        if not self.check_prerequisites():
            raise ToolIntegrationError("Dirsearch prerequisites not met.")
        # Ensure path is not None after prerequisite check
        assert self._dirsearch_path is not None

        options = options or {}
        extensions = options.get("extensions", DEFAULT_EXTENSIONS)
        timeout = options.get("timeout_seconds", 1800)  # Longer default timeout

        # Create a temporary file for the JSON report
        # Suffix is important for dirsearch to recognize it as JSON report
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".json", mode="w", encoding="utf-8"
        ) as report_file:
            report_path = Path(report_file.name)

        command = []
        if self._is_script:
            command.append(sys.executable)  # Use current python interpreter
        command.append(self._dirsearch_path)
        command.extend(
            [
                "-u",
                target,
                "-e",
                extensions,
                "--json-report",
                str(report_path),
            ]
        )
        # Add other common options or make configurable
        command.extend(["--force-recursive", "--exclude-status=400,404,500-599"])

        log.info(f"Running Dirsearch scan on {target}...")
        try:
            result = await self._executor.execute(command, timeout_seconds=timeout)

            if result.timed_out:
                log.warning(f"Dirsearch scan on {target} timed out.")
                report_path.unlink(missing_ok=True)  # Clean up temp file
                return result
            elif result.return_code != 0:
                log.error(f"Dirsearch scan failed on {target}. Error: {result.stderr}")
                report_path.unlink(missing_ok=True)
                return result
            else:
                log.info(
                    f"Dirsearch scan completed for {target}. Report: {report_path}"
                )
                # On success, return the path to the report file
                return report_path

        except Exception as e:
            report_path.unlink(missing_ok=True)  # Clean up temp file on error
            log.exception(
                f"An unexpected error occurred during Dirsearch execution: {e}"
            )
            raise ToolIntegrationError(f"Dirsearch execution failed: {e}") from e

    def parse_output(self, raw_output: Path | ExecutionResult) -> Any:
        """Parse Dirsearch JSON report file."""
        if isinstance(raw_output, ExecutionResult):
            log.warning("Cannot parse output from failed/timed-out Dirsearch run.")
            return None

        report_path = raw_output
        log.debug(f"Parsing Dirsearch JSON report: {report_path}")
        try:
            with report_path.open("r", encoding="utf-8") as f:
                # The report itself is the results, line-delimited JSON objects per target
                # We assume one target, so load the whole structure.
                # Dirsearch JSON is like: {"target": [{"path": ..., "status": ...}]}
                data = json.load(f)
            # Clean up the temporary file after parsing
            report_path.unlink(missing_ok=True)
            return data
        except FileNotFoundError:
            log.error(f"Dirsearch report file not found: {report_path}")
            return None
        except json.JSONDecodeError as e:
            log.error(f"Failed to parse Dirsearch JSON report {report_path}: {e}")
            report_path.unlink(missing_ok=True)  # Clean up corrupted file
            return None
        except Exception as e:
            log.exception(f"Error reading/parsing Dirsearch report {report_path}: {e}")
            report_path.unlink(missing_ok=True)
            return None
