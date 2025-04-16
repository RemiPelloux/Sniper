import logging
import re
import shutil
from typing import Any

from src.integrations.base import ToolIntegration, ToolIntegrationError
from src.integrations.executors import ExecutionResult, SubprocessExecutor

# Import the specific finding models
from src.results.types import BaseFinding, FindingSeverity, PortFinding

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

    def parse_output(self, raw_output: ExecutionResult) -> list[BaseFinding] | None:
        """Parse Nmap output into a list of PortFinding objects.

        Note: This is a very basic parser based on expected stdout format.
        A robust implementation should parse Nmap's XML output.
        """
        if raw_output.return_code != 0 or raw_output.timed_out:
            log.warning("Cannot parse output from failed or timed-out Nmap scan.")
            return None

        log.debug("Parsing Nmap stdout for open ports.")
        findings: list[BaseFinding] = []
        target_host = self._extract_target_from_command(raw_output.command)

        # Basic regex for lines like: "<port>/tcp open <service>"
        # NOTE: Fragile, relies on default Nmap text output.
        port_line_regex = re.compile(r"^(\d+)/(tcp|udp)\s+(open)\s+(\S+)")

        if not raw_output.stdout:
            log.warning("Nmap stdout was empty, cannot parse ports.")
            return None

        for line in raw_output.stdout.splitlines():
            match = port_line_regex.match(line.strip())
            if match:
                try:
                    port = int(match.group(1))
                    protocol = match.group(2)
                    # state = match.group(3) # 'open'
                    service = match.group(4)

                    finding = PortFinding(
                        # Use the target derived from the command
                        target=target_host or "unknown_target",
                        port=port,
                        protocol=protocol,
                        service=service,
                        # Severity for an open port is typically Info
                        severity=FindingSeverity.INFO,
                        # Description can be more detailed
                        description=(
                            f"Port {port}/{protocol} is open, "
                            f"running service: {service}"
                        ),
                        source_tool=self.tool_name,
                        raw_evidence=line.strip(),
                    )
                    findings.append(finding)
                except (ValueError, IndexError) as e:
                    log.warning(f"Failed to parse Nmap line '{line.strip()}': {e}")
                    continue

        if not findings:
            log.info("No open ports found or parsed from Nmap output.")
            return None

        log.info(f"Parsed {len(findings)} open port findings from Nmap output.")
        return findings

    def _extract_target_from_command(self, command_str: str) -> str | None:
        """Helper to attempt extracting the target from the executed command string."""
        # Very basic: assumes target is the last argument
        # This might break if options are added after the target
        try:
            parts = command_str.split()
            if len(parts) > 1:
                # Simple check if it looks like a domain or IP
                # This is not robust validation
                potential_target = parts[-1]
                if (
                    "." in potential_target
                    or "::" in potential_target
                    or potential_target.replace(".", "").isdigit()
                ):
                    return potential_target
        except Exception:
            log.warning("Could not reliably extract target from command string.")
        return None
