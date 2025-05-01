"""Integration with Nmap network scanner."""

import logging
import re
import tempfile
import os
from typing import Any, Dict, List, Optional

from src.core.config import settings
from src.integrations.base import ToolIntegration, ToolIntegrationError
from src.integrations.docker_utils import ensure_tool_available
from src.integrations.executors import ExecutionResult, SubprocessExecutor

# Import the specific finding models
from src.results.types import BaseFinding, FindingSeverity, PortFinding

log = logging.getLogger(__name__)


class NmapIntegration(ToolIntegration):
    """Integration for the Nmap Network Mapper.

    This class provides integration with Nmap, a powerful network scanning tool.
    It allows running Nmap scans and parsing the results into a standardized format.
    """

    def __init__(self, executor: Optional[SubprocessExecutor] = None) -> None:
        """Initialize the NmapIntegration.

        Args:
            executor: Optional. A SubprocessExecutor to use for running Nmap.
                     If not provided, a new one will be created.
        """
        self._executor = executor or SubprocessExecutor()

        # Try to find Nmap using our tool availability checker
        is_available, nmap_path = ensure_tool_available("nmap")
        if is_available:
            self._nmap_path = nmap_path
        else:
            self._nmap_path = None
            log.warning(
                "Nmap executable not found. Docker fallback will be used if needed."
            )

    @property
    def tool_name(self) -> str:
        """Return the name of the tool for this integration."""
        return "nmap"

    async def run(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Run Nmap scan against a target.

        Args:
            target: The target to scan (URL, IP, hostname)
            options: Optional dictionary of scan options:
                    - ports: Port specification (e.g., "22,80,443", "1-1000", "top1000")
                    - scan_type: Scan type (e.g., "SYN", "TCP", "UDP")
                    - timing: Timing template (0-5)
                    - service_detection: Whether to perform service detection
                    - os_detection: Whether to perform OS detection
                    - script: Specific Nmap scripts to run
                    - args: Additional raw Nmap arguments

        Returns:
            Dictionary with scan results
        """
        log.info(f"Running Nmap scan on {target}...")

        # Ensure we have an Nmap executable, either native or Docker fallback
        if not self._nmap_path:
            is_available, nmap_path = ensure_tool_available("nmap")
            if is_available:
                self._nmap_path = nmap_path
            else:
                raise ToolIntegrationError(
                    "Nmap executable not found and Docker fallback failed"
                )

        options = options or {}

        # Create a temporary file for XML output, ensuring parent directory exists
        temp_dir = tempfile.gettempdir()
        os.makedirs(temp_dir, exist_ok=True)
        
        with tempfile.NamedTemporaryFile(dir=temp_dir, suffix=".xml", delete=False) as temp_xml:
            xml_output_file = temp_xml.name

        try:
            # Base command
            cmd = [self._nmap_path]

            # Add XML output
            cmd.extend(["-oX", xml_output_file])

            # Handle port specification
            if "ports" in options:
                ports = options["ports"]
                cmd.extend(["-p", ports])

            # Handle scan type
            if "scan_type" in options:
                scan_type = options["scan_type"].upper()
                if scan_type == "SYN":
                    cmd.append("-sS")
                elif scan_type == "TCP":
                    cmd.append("-sT")
                elif scan_type == "UDP":
                    cmd.append("-sU")

            # Handle timing template
            if "timing" in options:
                timing = int(options["timing"])
                if 0 <= timing <= 5:
                    cmd.append(f"-T{timing}")

            # Handle service and OS detection
            if options.get("service_detection", False):
                cmd.append("-sV")

            if options.get("os_detection", False):
                cmd.append("-O")

            # Handle scripts
            if "script" in options:
                cmd.extend(["--script", options["script"]])

            # Add any raw arguments
            if "args" in options:
                if isinstance(options["args"], list):
                    cmd.extend(options["args"])
                else:
                    cmd.append(options["args"])

            # Add the target
            cmd.append(target)

            # Run the nmap scan
            log.info(f"Running Nmap command: {' '.join(cmd)}")
            result = await self._executor.execute(cmd)

            if result.return_code != 0:
                log.error(f"Nmap scan failed: {result.stderr}")
                return {"error": result.stderr}

            log.info(f"Nmap scan stdout: {result.stdout}")

            # Read the XML output
            with open(xml_output_file, "r") as f:
                xml_output = f.read()

            log.info(f"Nmap scan completed for {target}.")

            return {
                "xml_output": xml_output,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.return_code,
            }

        except Exception as e:
            log.exception(f"Error running Nmap scan: {e}")
            raise ToolIntegrationError(f"Nmap scan failed: {str(e)}")

        finally:
            # Clean up the temporary file
            try:
                os.unlink(xml_output_file)
            except Exception as e:
                log.warning(f"Failed to delete temporary XML file: {e}")

    def parse_output(self, raw_output: Dict[str, Any]) -> Optional[List[BaseFinding]]:
        """Parse Nmap output into a list of findings.

        Args:
            raw_output: The raw output from the Nmap scan

        Returns:
            List of BaseFinding objects or None if no findings
        """
        findings: List[BaseFinding] = []

        # Check if scan errored out
        if "error" in raw_output:
            log.error(f"Cannot parse Nmap output due to error: {raw_output['error']}")
            return None

        if "xml_output" not in raw_output:
            log.error("No XML output found in Nmap results")
            return None

        # Extract open ports from the XML output
        xml_output = raw_output["xml_output"]
        # Simple regex to extract port information - in production, use a proper XML parser
        port_pattern = r'<port protocol="(\w+)" portid="(\d+)"><state state="open".*?<service name="([^"]*)"'

        port_matches = re.findall(port_pattern, xml_output)

        if not port_matches:
            log.info("No open ports found or parsed from Nmap output.")
            return None

        # Create finding objects for each open port
        for protocol, port, service in port_matches:
            port_num = int(port)

            # Determine severity based on port/service
            severity = FindingSeverity.INFO
            if service in ["ssh", "telnet", "ftp"]:
                severity = FindingSeverity.LOW
            elif port_num in [22, 23, 21, 445, 3389]:
                severity = FindingSeverity.LOW

            # Create the finding
            finding = PortFinding(
                title=f"Open Port: {port}/{protocol}",
                description=f"Detected open port {port}/{protocol} running {service or 'unknown'} service",
                severity=severity,
                target=port,
                port=port_num,
                protocol=protocol,
                service=service or "unknown",
                source_tool=self.tool_name,
                raw_evidence=f"Port {port}/{protocol} is open running {service or 'unknown'}",
            )

            findings.append(finding)

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

    async def scan(
        self, target: str, ports: Optional[str] = None, options: List = []
    ) -> List[BaseFinding]:
        """
        Scan a target using Nmap and return findings.
        
        Args:
            target: The target to scan.
            ports: The ports to scan, e.g. "22,80,443" or "1-1000".
            options: List of additional options as tuples.
            
        Returns:
            List of PortFinding objects.
        """
        log.warning("The 'scan' method is deprecated. Use 'run' followed by 'parse_output' instead.")
        
        try:
            # Ensure we have an Nmap executable
            if not self._nmap_path:
                is_available, nmap_path = ensure_tool_available("nmap")
                if is_available:
                    self._nmap_path = nmap_path
                else:
                    raise ToolIntegrationError("Nmap executable not found")

            # Build command without relying on XML output
            cmd = [self._nmap_path, "-sV"]
            
            # Add port specification
            if ports:
                cmd.extend(["-p", ports])
                
            # Add target
            cmd.append(target)
            
            # Run the command
            log.info(f"Running Nmap command: {' '.join(cmd)}")
            result = await self._executor.execute(cmd)
            
            if result.return_code != 0:
                log.error(f"Nmap scan failed: {result.stderr}")
                return []
                
            log.info(f"Nmap scan stdout: {result.stdout}")
            
            # Parse the output directly
            findings = []
            
            # Simple regex to extract port information from stdout
            port_pattern = r"(\d+)/tcp\s+(open|filtered|closed)\s+(\w+)(?:\s+(.+))?"
            port_matches = re.findall(port_pattern, result.stdout)
            
            for port, state, service, version in port_matches:
                port_num = int(port)
                
                # Determine severity based on port/service and state
                severity = FindingSeverity.INFO
                if state == "open":
                    if service in ["ssh", "telnet", "ftp"]:
                        severity = FindingSeverity.LOW
                    elif port_num in [22, 23, 21, 445, 3389]:
                        severity = FindingSeverity.LOW
                
                # Create the finding
                finding = PortFinding(
                    title=f"Port: {port}/tcp ({state})",
                    description=f"Detected {state} port {port}/tcp running {service or 'unknown'} service{f' version {version}' if version else ''}",
                    severity=severity,
                    target=port,
                    port=port_num,
                    protocol="tcp",
                    service=service or "unknown",
                    source_tool=self.tool_name,
                    raw_evidence=f"Port {port}/tcp is {state} running {service or 'unknown'}{f' version {version}' if version else ''}",
                )
                
                findings.append(finding)
                
            return findings
            
        except Exception as e:
            log.exception(f"Error in scan method: {e}")
            return []

    def check_prerequisites(self) -> bool:
        """Check if Nmap is available either natively or via Docker fallback."""
        if self._nmap_path:
            log.debug(f"Found nmap executable at: {self._nmap_path}")
            return True

        # Try to setup Docker fallback
        is_available, nmap_path = ensure_tool_available("nmap")
        if is_available:
            self._nmap_path = nmap_path
            log.info(f"Using Docker fallback for nmap at: {nmap_path}")
            return True

        log.error("Nmap executable not found in PATH and Docker fallback failed.")
        return False
