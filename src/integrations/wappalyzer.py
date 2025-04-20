import json
import logging
import shutil
from typing import Any, Dict, List, Optional

from src.integrations.base import ToolIntegration, ToolIntegrationError
from src.integrations.executors import ExecutionResult, SubprocessExecutor
from src.results.types import BaseFinding, TechnologyFinding

log = logging.getLogger(__name__)

# NOTE: This integration assumes the use of the 'wappalyzer' PyPI package
# by s0md3v, which requires Firefox and geckodriver.
# See: https://pypi.org/project/wappalyzer/


class WappalyzerIntegration(ToolIntegration):
    """Integration for the Wappalyzer technology detection tool.

    Assumes the use of the 'wappalyzer' package CLI.
    Requires Firefox and geckodriver to be installed and configured.
    """

    def __init__(self, executor: SubprocessExecutor | None = None) -> None:
        self._executor = executor or SubprocessExecutor()
        # The package installs the command as 'wappalyzer'
        self._tool_path = shutil.which("wappalyzer")

    @property
    def tool_name(self) -> str:
        return "wappalyzer"

    def check_prerequisites(self) -> bool:
        """Check if the wappalyzer executable is found in PATH.

        Note: This check does *not* verify Firefox or geckodriver installation.
        Those are prerequisites for the underlying 'wappalyzer' tool itself.
        """
        if not self._tool_path:
            log.error(
                "wappalyzer executable not found in PATH. Ensure 'pip install wappalyzer' "  # noqa: E501
                "or 'poetry install --extras wappalyzer' was successful and PATH is "  # noqa: E501
                "correct."
            )
            return False
        log.debug(f"Found wappalyzer executable at: {self._tool_path}")
        # Add a check for geckodriver? Maybe too complex for now.
        # geckodriver_path = shutil.which("geckodriver")
        # if not geckodriver_path:
        #    log.warning("geckodriver not found in PATH, Wappalyzer might fail.")
        return True

    async def run(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ExecutionResult:
        """Run wappalyzer against the target URL.

        Args:
            target: The target URL (must include schema, e.g., https://example.com).
            options: Tool-specific options (e.g., timeout_seconds, threads, scan_type).
                     Supported options:
                     - timeout_seconds (int): Command timeout (default: 180).
                     - threads (int): Number of threads for the tool (default: 5).
                     - scan_type (str): 'fast', 'balanced', or 'full' (default: 'full').

        Returns:
            ExecutionResult containing the command output.
        """
        if not self.check_prerequisites():
            raise ToolIntegrationError(
                "Wappalyzer prerequisites not met (executable not found)."
            )
        assert self._tool_path is not None

        options = options or {}
        timeout = options.get(
            "timeout_seconds", 180
        )  # Might need longer if browser launches
        threads = options.get("threads", 5)
        scan_type = options.get("scan_type", "full")  # Default to full for accuracy

        # Create a temporary file for JSON output
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
            
        # Command structure for 'wappalyzer' package:
        # wappalyzer -i <url> --scan-type <type> -t <threads> -oJ <temp_file>
        command = [
            self._tool_path,
            "-i",
            target,
            "--scan-type",
            scan_type,
            "-t",
            str(threads),
            "-oJ",
            temp_path,
        ]

        log.info(f"Running Wappalyzer scan ({scan_type}) on {target}...")
        try:
            result = await self._executor.execute(command, timeout_seconds=timeout)

            if result.timed_out:
                log.warning(f"Wappalyzer scan on {target} timed out.")
            elif result.return_code != 0 or "error" in result.stderr.lower():
                log.error(
                    f"Wappalyzer scan failed or reported errors on {target}. "
                    f"Exit: {result.return_code}, Stderr: {result.stderr[:500]}..."  # noqa: E501
                )
            else:
                log.info(f"Wappalyzer scan completed for {target}.")

            # Read the JSON output from the temp file if it exists
            try:
                with open(temp_path, 'r') as f:
                    json_content = f.read()
                    # Create a new ExecutionResult with the JSON content as stdout
                    result = ExecutionResult(
                        return_code=result.return_code,
                        stdout=json_content,
                        stderr=result.stderr,
                        command=result.command,
                        timed_out=result.timed_out
                    )
            except Exception as e:
                log.error(f"Failed to read Wappalyzer output from temp file: {e}")
            
            # Clean up temp file
            try:
                import os
                os.unlink(temp_path)
            except:
                pass

            return result  # Return the raw execution result

        except Exception as e:
            log.exception(
                f"An unexpected error occurred during Wappalyzer execution: {e}"
            )
            raise ToolIntegrationError(f"Wappalyzer execution failed: {e}") from e

    async def parse_output(
        self, raw_output: ExecutionResult
    ) -> list[BaseFinding] | None:
        """Parse Wappalyzer JSON output (expected on stdout) into TechnologyFinding objects.
        
        The Wappalyzer CLI produces JSON in the format:
        {
          "http://example.com": {
            "TechnologyName": {
              "version": "1.0",
              "confidence": 100,
              "categories": ["Category1", "Category2"],
              "groups": ["Group1"]
            },
            ...more technologies
          }
        }
        """
        # Don't parse if execution failed or timed out
        if raw_output.return_code != 0 or raw_output.timed_out:
            log.warning("Cannot parse output from failed or timed-out Wappalyzer scan.")
            return None

        if not raw_output.stdout:
            log.warning("Wappalyzer stdout was empty, cannot parse technologies.")
            return None

        log.debug("Parsing Wappalyzer JSON output.")
        findings: list[BaseFinding] = []

        try:
            # Parse the JSON output
            data = json.loads(raw_output.stdout)

            if not isinstance(data, dict):
                log.error(
                    f"Unexpected Wappalyzer JSON format: Expected dict, got {type(data)}"
                )
                return None

            # The dict keys are URLs
            if not data:
                log.warning("Wappalyzer output contained no URLs.")
                return None
                
            # Process each URL in the output
            for target_url, technologies in data.items():
                if not isinstance(technologies, dict):
                    log.warning(f"Unexpected format for URL {target_url}, skipping.")
                    continue
                    
                log.debug(f"Processing technologies for {target_url}")
                
                # Process each technology found for this URL
                for tech_name, tech_details in technologies.items():
                    if not isinstance(tech_details, dict):
                        log.warning(f"Unexpected format for technology {tech_name}, skipping.")
                        continue
                        
                    # Extract categories from the details
                    categories_list = tech_details.get("categories", [])
                    if not isinstance(categories_list, list):
                        log.warning(f"Invalid categories format for {tech_name}, using empty list.")
                        categories_list = []
                    
                    # Create a TechnologyFinding
                    try:
                        finding = TechnologyFinding(
                            target=target_url,
                            technology_name=tech_name,
                            version=tech_details.get("version") or None,
                            categories=categories_list,
                            # Severity/description handled by model __init__
                            source_tool=self.tool_name,
                            raw_evidence=tech_details,
                        )
                        findings.append(finding)
                    except Exception as e:
                        log.warning(
                            f"Could not create TechnologyFinding for {tech_name} at {target_url}: {e}"
                        )
                        continue

            if not findings:
                log.info("No technologies parsed from Wappalyzer output.")
                return None

            log.info(f"Parsed {len(findings)} technologies from Wappalyzer output.")
            return findings

        except json.JSONDecodeError as e:
            log.error(f"Failed to parse Wappalyzer JSON output: {e}")
            log.debug(f"Raw stdout for Wappalyzer: {raw_output.stdout}")
            return None
        except Exception as e:
            log.exception(f"Error processing Wappalyzer output: {e}")
            return None

    async def scan(self, target: str, verify_ssl: bool = True) -> list[BaseFinding]:
        """
        Legacy method for backward compatibility.

        This is a wrapper around the run and parse_output methods that simplifies the interface
        for callers that don't need the full flexibility of the run method.

        Args:
            target: The URL to scan.
            verify_ssl: Whether to verify SSL certificates.

        Returns:
            List of findings from the scan.
        """
        log.warning("The scan method is deprecated. Use run followed by parse_output.")

        try:
            # Run the scan and get raw results
            scan_result = await self.run(target, options={"verify_ssl": verify_ssl})

            # Parse the results
            findings = await self.parse_output(scan_result)
            return findings if findings is not None else []
        except Exception as e:
            log.exception(f"Error in scan method: {e}")
            return []

    # _extract_target_from_command is no longer needed as URL comes from JSON output
