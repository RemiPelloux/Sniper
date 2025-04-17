import json
import logging
import shutil
from typing import Any

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

        # Command structure for 'wappalyzer' package:
        # wappalyzer -i <url> --scan-type <type> -t <threads>
        # It outputs JSON to stdout by default when used non-interactively.
        command = [
            self._tool_path,
            "-i",
            target,
            "--scan-type",
            scan_type,
            "-t",
            str(threads),
            # Add cookie support? -c option - Maybe later
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

            return result  # Return the raw execution result

        except Exception as e:
            log.exception(
                f"An unexpected error occurred during Wappalyzer execution: {e}"
            )
            raise ToolIntegrationError(f"Wappalyzer execution failed: {e}") from e

    def parse_output(self, raw_output: ExecutionResult) -> list[BaseFinding] | None:
        """Parse Wappalyzer JSON output (expected on stdout) into TechnologyFinding
        objects. Handles the format from the 'wappalyzer' package (s0md3v).
        Expected format: { \"url1\": { \"Tech1\": {...}, \"Tech2\": {...} }, ... }

        New Expected format (from wappalyzer-cli):
        {
          \"urls\": { \"https://example.com\": { \"status\": 200 } },
          \"technologies\": [ { \"name\": \"Nginx\", ... }, ... ]
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
            # The 'wappalyzer' package (s0md3v) outputs a dict where keys are URLs
            data = json.loads(raw_output.stdout)

            if not isinstance(data, dict):
                log.error(
                    f"Unexpected Wappalyzer JSON format: Expected dict, got {type(data)}"
                )
                return None

            # Extract target URL - assumes only one URL is scanned per execution
            target_url = None
            urls_data = data.get("urls", {})
            if isinstance(urls_data, dict) and urls_data:
                # Get the first URL key found
                target_url = next(iter(urls_data.keys()), None)
            if not target_url:
                log.warning("Could not determine target URL from Wappalyzer output.")
                # Attempt to extract from the command if needed (fallback)
                # target_url = self._extract_target_from_command(raw_output.command)
                # For now, return None if URL isn't in output
                return None

            log.debug(f"Target URL identified from Wappalyzer output: {target_url}")

            technologies = data.get("technologies", [])
            if not isinstance(technologies, list):
                log.warning(
                    f"Expected 'technologies' to be a list at the top level, got {type(technologies)}"
                )
                return None

            # Iterate through technologies found
            for tech_details in technologies:
                if not isinstance(tech_details, dict):
                    log.warning("Skipping non-dict item in technologies list.")
                    continue

                tech_name = tech_details.get("name")
                if not tech_name or not isinstance(tech_name, str):
                    log.warning(
                        "Skipping technology entry with missing or invalid name."
                    )
                    continue

                # Extract categories - Ensure it's a list of dictionaries
                categories_raw = tech_details.get("categories", [])
                categories_list = []
                if isinstance(categories_raw, list):
                    # Categories are dicts like {'id': 1, 'slug': 'cms', 'name': 'CMS'}
                    categories_list = [
                        cat.get("name", "Unknown")
                        for cat in categories_raw
                        if isinstance(cat, dict) and "name" in cat
                    ]

                try:
                    finding = TechnologyFinding(
                        target=target_url,  # Use the URL extracted from 'urls' key
                        technology_name=tech_name,
                        version=tech_details.get("version")
                        or None,  # Ensure None if empty/null
                        categories=categories_list,
                        # Severity/description handled by model __init__
                        source_tool=self.tool_name,
                        raw_evidence=tech_details,  # Store original tech details dict
                    )
                    findings.append(finding)
                except Exception as e:  # Catch potential Pydantic validation errors
                    log.warning(
                        "Could not create TechnologyFinding for %s at %s: %s",
                        tech_name,
                        target_url,
                        e,
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

    # _extract_target_from_command is no longer needed as URL comes from JSON output
    # def _extract_target_from_command(self, command_str: str) -> str | None:
    #     ...
