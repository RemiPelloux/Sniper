import json
import logging

# import os # Unused
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, List, Optional

from src.integrations.base import ToolIntegration, ToolIntegrationError
from src.integrations.executors import ExecutionResult, SubprocessExecutor

# Import result types
from src.results.types import BaseFinding, FindingSeverity, WebFinding

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

    async def parse_output(
        self, raw_output: Path | ExecutionResult
    ) -> list[BaseFinding] | None:
        """Parse Dirsearch JSON report file into WebFinding objects."""
        if isinstance(raw_output, ExecutionResult):
            log.warning("Cannot parse output from failed/timed-out Dirsearch run.")
            return None

        report_path = raw_output
        log.debug(f"Parsing Dirsearch JSON report: {report_path}")
        findings: list[BaseFinding] = []
        try:
            with report_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            # Dirsearch JSON format: {"target_url": [{result_dict}, ...], ...}
            # We iterate through all targets found in the report
            for target_url, results in data.items():
                if not isinstance(results, list):
                    log.warning(
                        f"Unexpected format for results under target {target_url} in {report_path}"
                    )
                    continue

                for result_item in results:
                    if not isinstance(result_item, dict):
                        log.warning(
                            f"Skipping non-dict item in results for {target_url}"
                        )
                        continue

                    status = result_item.get("status")
                    url = result_item.get("url")
                    content_type = result_item.get("content-type")

                    if not url or not status:
                        log.warning(
                            f"Skipping result item with missing URL or status: {result_item}"
                        )
                        continue

                    # Basic severity based on status code (can be refined)
                    severity = FindingSeverity.INFO
                    if 200 <= status < 300:
                        severity = (
                            FindingSeverity.LOW
                        )  # Or INFO? Found path is low impact
                    elif 300 <= status < 400:
                        severity = FindingSeverity.INFO  # Redirects
                    elif 401 <= status <= 403:
                        severity = (
                            FindingSeverity.MEDIUM
                        )  # Forbidden/Unauthorized potentially interesting

                    finding = WebFinding(
                        target=target_url,  # Overall target from report key
                        url=url,  # Specific URL found
                        status_code=status,
                        severity=severity,
                        description=(
                            f"Found web resource at {url} with status {status}. "
                            f"Content-Type: {content_type or 'N/A'}"
                        ),
                        source_tool=self.tool_name,
                        raw_evidence=result_item,  # Store the raw dict entry
                    )
                    findings.append(finding)

            # Clean up the temporary file after parsing
            report_path.unlink(missing_ok=True)
            if not findings:
                log.info(f"No findings parsed from Dirsearch report {report_path}")
                return None

            log.info(
                f"Parsed {len(findings)} findings from Dirsearch report {report_path}"
            )
            return findings
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

    async def scan(
        self, target: str, wordlist_size: str = "medium", verify_ssl: bool = True
    ) -> List[BaseFinding]:
        """
        Legacy method for backward compatibility.

        This is a wrapper around the run and parse_output methods that simplifies the interface
        for callers that don't need the full flexibility of the run method.

        Args:
            target: The URL to scan.
            wordlist_size: Size of wordlist to use (small, medium, large).
            verify_ssl: Whether to verify SSL certificates.

        Returns:
            List of findings from the scan.
        """
        log.warning(
            "The 'scan' method is deprecated. Use 'run' followed by 'parse_output' instead."
        )

        try:
            # Run the scan and get raw results
            scan_result = await self.run(
                target,
                options={"wordlist_size": wordlist_size, "verify_ssl": verify_ssl},
            )

            # Parse the results
            findings = await self.parse_output(scan_result)
            return findings if findings is not None else []
        except Exception as e:
            log.exception(f"Error in scan method: {e}")
            return []
