import logging
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.integrations.base import ToolIntegration, ToolIntegrationError
from src.integrations.executors import ExecutionResult, SubprocessExecutor

# Import result types
from src.results.types import BaseFinding, FindingSeverity, SubdomainFinding

log = logging.getLogger(__name__)


class SubfinderIntegration(ToolIntegration):
    """Integration for the Subfinder subdomain enumeration tool."""

    def __init__(self, executor: SubprocessExecutor | None = None) -> None:
        self._executor = executor or SubprocessExecutor()
        # Check for subfinder executable
        self._subfinder_path = shutil.which("subfinder")

        # Store the target domain when run is called for use in parsing
        self._last_target_domain: str | None = None

    @property
    def tool_name(self) -> str:
        return "subfinder"

    def check_prerequisites(self) -> bool:
        """Check if subfinder executable is found."""
        if not self._subfinder_path:
            log.error("subfinder executable not found in PATH.")
            return False
        log.debug(f"Found subfinder at: {self._subfinder_path}")
        return True

    async def run(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ExecutionResult | Path:
        """Run subfinder against the target domain, saving results to a file.

        Args:
            target: The domain name (e.g., example.com).
            options: Tool-specific options (e.g., timeout_seconds, sources, resolvers).

        Returns:
            Path to the output file on success, or ExecutionResult on failure/timeout.
        """
        if not self.check_prerequisites():
            raise ToolIntegrationError("Subfinder prerequisites not met.")
        assert self._subfinder_path is not None

        # Store target domain for use in parsing
        self._last_target_domain = target

        options = options or {}
        timeout = options.get("timeout_seconds", 600)  # Default timeout

        # Create a temporary file for the output
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".txt", mode="w", encoding="utf-8"
        ) as output_file:
            output_path = Path(output_file.name)

        command = [self._subfinder_path]
        command.extend(["-d", target, "-o", str(output_path)])

        # Add optional subfinder-specific parameters
        if options.get("silent", False):
            command.append("-silent")

        if options.get("sources"):
            command.extend(["-sources", options["sources"]])

        if options.get("resolvers"):
            command.extend(["-r", options["resolvers"]])

        if options.get("all"):
            command.append("-all")

        if options.get("max_time"):
            command.extend(["-timeout", str(options["max_time"])])

        if options.get("rate_limit"):
            command.extend(["-rate-limit", str(options["rate_limit"])])

        log.info(f"Running Subfinder scan on {target}...")
        try:
            result = await self._executor.execute(command, timeout_seconds=timeout)

            if result.timed_out:
                log.warning(f"Subfinder scan on {target} timed out.")
                output_path.unlink(missing_ok=True)
                return result
            elif result.return_code != 0:
                # Check if we have partial results that can be salvaged
                if output_path.exists() and output_path.stat().st_size > 0:
                    log.warning(
                        f"Subfinder scan on {target} finished with exit code {result.return_code}, "
                        f"but output file exists. Report file: {output_path}. Stderr: {result.stderr}"
                    )
                    return output_path  # Treat as success if output file exists
                else:
                    log.error(
                        f"Subfinder scan failed on {target}. Exit code {result.return_code}. Error: {result.stderr}"
                    )
                    output_path.unlink(missing_ok=True)
                    return result
            else:
                log.info(
                    f"Subfinder scan completed for {target}. Report: {output_path}"
                )
                return output_path

        except Exception as e:
            output_path.unlink(missing_ok=True)
            log.exception(
                f"An unexpected error occurred during Subfinder execution: {e}"
            )
            raise ToolIntegrationError(f"Subfinder execution failed: {e}") from e

    def parse_output(
        self, raw_output: Path | ExecutionResult
    ) -> List[BaseFinding] | None:
        """Parse Subfinder output file into SubdomainFinding objects."""
        if isinstance(raw_output, ExecutionResult):
            log.warning("Cannot parse output from failed/timed-out Subfinder run.")
            return None

        output_path = raw_output
        log.debug(f"Parsing Subfinder output file: {output_path}")
        findings: List[BaseFinding] = []
        # Use the target domain stored during the run
        target_domain = self._last_target_domain or "unknown_target"

        try:
            with output_path.open("r", encoding="utf-8") as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain:  # Ignore empty lines
                        finding = SubdomainFinding(
                            target=target_domain,
                            subdomain=subdomain,
                            severity=FindingSeverity.INFO,  # Subdomain discovery is informational
                            description=f"Discovered subdomain: {subdomain}",
                            source_tool=self.tool_name,
                            raw_evidence=subdomain,
                        )
                        findings.append(finding)
            output_path.unlink(missing_ok=True)  # Clean up

            if not findings:
                log.info(f"No subdomains found or parsed from {output_path}")
                return None

            log.info(f"Parsed {len(findings)} subdomains from {output_path}")
            return findings
        except FileNotFoundError:
            log.error(f"Subfinder output file not found: {output_path}")
            return None
        except Exception as e:
            log.exception(f"Error reading/parsing Subfinder output {output_path}: {e}")
            output_path.unlink(missing_ok=True)  # Clean up
            return None

    async def scan(
        self, target: str, options: Dict[str, Any] | None = None
    ) -> List[BaseFinding]:
        """
        Execute a scan against the target and return findings.

        This is a convenience method that runs the tool and parses the output.

        Args:
            target: The domain to scan for subdomains.
            options: Additional options for the scan.

        Returns:
            List of findings from the scan.
        """
        try:
            scan_result = await self.run(target, options=options or {})
            findings = self.parse_output(scan_result)
            return findings if findings is not None else []
        except Exception as e:
            log.exception(f"Error during Subfinder scan: {e}")
            return []
