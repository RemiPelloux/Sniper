"""
OWASP ZAP Integration Module

This module provides integration with the OWASP Zed Attack Proxy (ZAP), a powerful
web application security scanner. It allows the tool to perform both passive and
active scans against web applications to identify security vulnerabilities.

Features:
- Support for both passive and active scanning modes
- AJAX spider for JavaScript-heavy applications
- Customizable scan options and configurations
- Detailed vulnerability findings including severity, evidence, and solution recommendations
- Optional daemon management (start/stop) for headless operation

Dependencies:
- Either the 'python-owasp-zap-v2.4' or 'zaproxy' Python package
- OWASP ZAP executable in the PATH for daemon mode

Configuration:
- Supports custom host, port, and API key settings via core configuration
- Can use an existing ZAP instance or start a new one
- Adjustable timeout and scan parameters

Usage:
    integration = ZapIntegration()
    result = await integration.run("https://example.com",
                                 {"active_scan": True, "ajax_spider": False})
    findings = integration.parse_output(result)
"""

import logging
import os
import shutil
import sys
import time
from typing import Any, Dict, List, Optional, Union

from pydantic import ValidationError

from src.integrations.base import ToolIntegration, ToolIntegrationError
from src.integrations.docker_utils import ensure_tool_available
from src.integrations.executors import SubprocessExecutor
from src.results.types import BaseFinding, FindingSeverity, WebFinding
from src.core.config import settings

log = logging.getLogger(__name__)

# Check if ZAP API is available
ZAP_AVAILABLE = False
try:
    # Try new package name
    from zaproxy import ZAPv2  # type: ignore

    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False
    log.warning("ZAP Python API not installed. Install with: pip install zaproxy")


class ZapIntegration(ToolIntegration):
    """Integration for OWASP ZAP (Zed Attack Proxy) web scanner."""

    def __init__(self, executor: Optional[SubprocessExecutor] = None) -> None:
        self._executor = executor or SubprocessExecutor()
        
        # Try to find ZAP using our tool availability checker
        is_available, zap_path = ensure_tool_available("zap")
        if is_available:
            self._zap_path = zap_path
        else:
            self._zap_path = None
        
        # Also check for zap.sh or zap.bat
        self._zap_daemon_path = shutil.which("zap.sh") or shutil.which("zap.bat")
        
        # If we have a zap path but not a daemon path, check if our zap path is usable as daemon
        if self._zap_path and not self._zap_daemon_path:
            if os.path.isfile(self._zap_path) and os.access(self._zap_path, os.X_OK):
                # Try to determine if this is a wrapper or the actual ZAP executable
                with open(self._zap_path, "r") as f:
                    try:
                        content = f.read(1024)  # Read first 1KB to check if it's a script
                        if "#!/bin/bash" in content or "docker" in content:
                            # This looks like a wrapper script, might be usable as daemon
                            self._zap_daemon_path = self._zap_path
                    except UnicodeDecodeError:
                        # Binary file, not a wrapper script
                        pass

        # Get configuration from settings
        self._zap_config = settings.tool_configs.get("zap", {})
        self._api_key = self._zap_config.get("api_key", "")
        self._zap_host = self._zap_config.get("host", "localhost")
        self._zap_port = int(self._zap_config.get("port", 8080))
        self._zap_api: Optional[ZAPv2] = None  # Add type hint

    @property
    def tool_name(self) -> str:
        return "owasp-zap"

    def check_prerequisites(self) -> bool:
        """Check if ZAP is available through API or executable."""
        # First check if Python API is available
        if not ZAP_AVAILABLE:
            log.error("OWASP ZAP Python API (python-owasp-zap-v2.4) not installed.")
            return False

        # If we're using an existing ZAP instance, try to connect to it
        if self._zap_config.get("use_existing_instance", False):
            try:
                self._connect_to_zap()
                return True
            except Exception as e:
                log.error(f"Failed to connect to existing ZAP instance: {e}")
                return False

        # Otherwise, check if ZAP executable is available
        if not self._zap_path and not self._zap_daemon_path:
            log.error("OWASP ZAP executable not found in PATH.")
            # Try to set up Docker fallback
            is_available, zap_path = ensure_tool_available("zap")
            if is_available:
                self._zap_path = zap_path
                self._zap_daemon_path = zap_path
                log.info(f"Using Docker fallback for ZAP at: {zap_path}")
                return True
            return False

        log.debug(f"Found ZAP executable at: {self._zap_path or self._zap_daemon_path}")
        return True

    def _connect_to_zap(self) -> None:
        """Connect to ZAP API."""
        if not ZAP_AVAILABLE:
            raise ToolIntegrationError("ZAP Python API not available")

        try:
            # Assign to self._zap_api
            self._zap_api = ZAPv2(
                apikey=self._api_key,
                proxies={
                    "http": f"http://{self._zap_host}:{self._zap_port}",
                    "https": f"http://{self._zap_host}:{self._zap_port}",
                },
            )
            # Test connection by getting version
            assert self._zap_api is not None  # Assertion for mypy
            version = self._zap_api.core.version
            log.info(f"Connected to ZAP API, version: {version}")
        except Exception as e:
            # Ensure _zap_api is None if connection fails
            self._zap_api = None
            raise ToolIntegrationError(f"Failed to connect to ZAP API: {e}") from e

    async def _start_zap_daemon(self, options: Optional[Dict[str, Any]] = None) -> None:
        """Start ZAP in daemon mode if not already running."""
        if self._zap_config.get("use_existing_instance", False):
            log.info("Using existing ZAP instance, skipping daemon start")
            return

        if not self._zap_daemon_path:
            raise ToolIntegrationError("ZAP daemon executable not found")

        # Build command to start ZAP in daemon mode
        cmd = [
            self._zap_daemon_path,
            "-daemon",
            "-host",
            self._zap_host,
            "-port",
            str(self._zap_port),
            "-config",
            f"api.key={self._api_key}",
        ]

        # Add any additional options specified in configuration
        cmd_options = options.get("daemon_options", []) if options else []
        if cmd_options:
            cmd.extend(cmd_options)

        log.info(f"Starting ZAP daemon on {self._zap_host}:{self._zap_port}")
        try:
            # Run ZAP as a background process
            # Note: We're not capturing output since it's a daemon
            result = await self._executor.execute(
                cmd,
                timeout_seconds=(
                    options.get("daemon_start_timeout", 60) if options else 60
                ),
            )

            if result.return_code != 0 and not result.timed_out:
                # If daemon starts successfully, it might timeout since it keeps running
                log.error(f"Failed to start ZAP daemon: {result.stderr}")
                raise ToolIntegrationError(
                    f"Failed to start ZAP daemon: {result.stderr}"
                )

            # Allow some time for ZAP to initialize
            import asyncio

            await asyncio.sleep(10)

            # Try to connect to the API
            self._connect_to_zap()

        except Exception as e:
            log.exception(f"An error occurred while starting ZAP daemon: {e}")
            raise ToolIntegrationError(f"Failed to start ZAP daemon: {e}") from e

    async def run(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Run ZAP against the target."""
        if not self.check_prerequisites():
            raise ToolIntegrationError("ZAP prerequisites not met.")

        # Parse options with defaults
        scan_options = options or {}
        scan_type = scan_options.get("scan_type", "passive")  # passive or active
        active_scan = scan_options.get("active_scan", False)
        ajax_spider = scan_options.get("ajax_spider", False)
        verify_ssl = scan_options.get("verify_ssl", True)

        try:
            # Start ZAP daemon if needed
            await self._start_zap_daemon(scan_options)

            # Ensure we have a connection to the API
            if not self._zap_api:
                self._connect_to_zap()

            # Add assertion for mypy after ensuring connection
            assert self._zap_api is not None

            log.info(f"Starting ZAP scan of type '{scan_type}' against {target}")

            # Create new session
            self._zap_api.core.new_session()

            # Access the target (Spider or AJAX Spider based on options)
            scan_id: Optional[str] = None  # Hint scan_id type

            if ajax_spider:
                log.info(f"Starting AJAX Spider scan of {target}")
                scan_id = self._zap_api.ajaxSpider.scan(target)
                # Wait for AJAX Spider to complete
                import asyncio

                while self._zap_api.ajaxSpider.status == "running":
                    log.debug("AJAX Spider still running...")
                    await asyncio.sleep(10)
                log.info("AJAX Spider scan complete")
            else:
                log.info(f"Starting traditional Spider scan of {target}")
                scan_id = self._zap_api.spider.scan(target)
                # Wait for Spider to complete
                import asyncio

                while int(self._zap_api.spider.status(scan_id)) < 100:
                    log.debug(
                        f"Spider progress: {self._zap_api.spider.status(scan_id)}%"
                    )
                    await asyncio.sleep(5)
                log.info("Spider scan complete")

            # If active scan requested, run it
            active_scan_id: Optional[str] = None  # Hint active_scan_id type
            if active_scan or scan_type.lower() == "active":
                log.info(f"Starting active scan against {target}")
                active_scan_id = self._zap_api.ascan.scan(target)

                # Wait for active scan to complete
                import asyncio

                while int(self._zap_api.ascan.status(active_scan_id)) < 100:
                    log.debug(
                        f"Active scan progress: {self._zap_api.ascan.status(active_scan_id)}%"
                    )
                    await asyncio.sleep(10)
                log.info("Active scan complete")

            # Get alerts
            alerts = self._zap_api.core.alerts()
            log.info(f"ZAP scan completed with {len(alerts)} alerts found")

            # Get additional scan details
            scan_result = {
                "alerts": alerts,
                "urls": self._zap_api.core.urls(),
                "stats": self._zap_api.stats.all_sites_stats(),
                "spider_id": scan_id,
                "active_scan_id": active_scan_id,
                "scan_type": scan_type,
                "target": target,
            }

            return scan_result

        except Exception as e:
            log.exception(f"An error occurred during ZAP scan: {e}")
            raise ToolIntegrationError(f"ZAP scan failed: {e}") from e

    def scan(
        self,
        target: str,
        active_scan: bool = False,
        ajax_spider: bool = False,
        verify_ssl: bool = True,
    ) -> List[BaseFinding]:
        """
        Legacy method for backward compatibility.

        This is a wrapper around the run and parse_output methods that simplifies the interface
        for callers that don't need the full flexibility of the run method. It directly returns
        the parsed findings instead of the raw results.

        Args:
            target: The URL to scan.
            active_scan: Whether to perform an active scan.
            ajax_spider: Whether to use AJAX spider.
            verify_ssl: Whether to verify SSL certificates.

        Returns:
            List of findings from the scan.
        """
        import asyncio

        log.warning(
            "The 'scan' method is deprecated. Use 'run' followed by 'parse_output' instead."
        )

        # Run the scan and get raw results
        options = {
            "active_scan": active_scan,
            "ajax_spider": ajax_spider,
            "verify_ssl": verify_ssl,
        }

        try:
            # Use asyncio to run the async method
            scan_result = asyncio.run(self.run(target, options=options))

            # Parse the results
            findings = self.parse_output(scan_result)
            return findings if findings is not None else []
        except Exception as e:
            log.exception(f"Error in scan method: {e}")
            return []

    def parse_output(self, raw_output: Dict[str, Any]) -> Optional[List[BaseFinding]]:
        """Parse ZAP output into a list of WebFinding objects."""
        if not raw_output or not raw_output.get("alerts"):
            log.warning("No ZAP alerts found in output.")
            if raw_output and "alerts" in raw_output and raw_output["alerts"] == []:
                # Return empty list for empty alerts, rather than None
                return []
            return None

        try:
            findings: List[BaseFinding] = []
            alerts = raw_output["alerts"]
            target = raw_output.get("target", "")

            for alert in alerts:
                # Map ZAP risk levels to our severity enum
                severity_map = {
                    "Informational": FindingSeverity.INFO,
                    "Low": FindingSeverity.LOW,
                    "Medium": FindingSeverity.MEDIUM,
                    "High": FindingSeverity.HIGH,
                    "Critical": FindingSeverity.CRITICAL,
                }

                risk = alert.get("risk", "Informational")
                # Handle numeric risk levels if they're not strings
                if isinstance(risk, int):
                    # ZAP uses 0-3 for risk levels
                    risk_map = {
                        0: "Informational",
                        1: "Low",
                        2: "Medium",
                        3: "High",
                        4: "Critical",
                    }
                    risk = risk_map.get(risk, "Informational")

                # Get the severity from our map, default to INFO if not found
                severity = severity_map.get(risk, FindingSeverity.INFO)

                # Create a WebFinding from the alert
                finding = WebFinding(
                    title=alert.get("name", "Unknown Vulnerability"),
                    description=alert.get("description", "No description provided"),
                    severity=severity,
                    url=alert.get("url", target),
                    method=alert.get("method", "GET"),
                    parameter=alert.get("param", ""),
                    evidence=alert.get("evidence", ""),
                    solution=alert.get("solution", ""),
                    confidence=alert.get("confidence", "Low"),
                    tool=self.tool_name,
                    raw_data=alert,
                    target=target,
                )

                findings.append(finding)

            return findings
        except (ValueError, ValidationError) as e:
            log.error(f"Error parsing ZAP output: {e}")
            return None

    async def shutdown(self) -> None:
        """Shutdown the ZAP instance if we started it."""
        if self._zap_api and not self._zap_config.get("use_existing_instance", False):
            try:
                log.info("Shutting down ZAP daemon")
                self._zap_api.core.shutdown()
                log.info("ZAP daemon shutdown successfully")
            except Exception as e:
                log.error(f"Failed to shutdown ZAP daemon: {e}")
