import logging
import shutil
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from src.core.config import settings
from src.integrations.base import ToolIntegration, ToolIntegrationError
from src.integrations.executors import SubprocessExecutor
from src.results.types import BaseFinding, FindingSeverity, WebFinding

log = logging.getLogger(__name__)

try:
    from zapv2 import ZAPv2  # type: ignore

    ZAP_AVAILABLE = True
except ImportError:
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
        self._zap_path = shutil.which("zap")  # For ZAP CLI (if available)
        self._zap_daemon_path = shutil.which("zap.sh") or shutil.which("zap.bat")

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
        if not self._zap_daemon_path:
            log.error("OWASP ZAP executable not found in PATH.")
            return False

        log.debug(f"Found ZAP executable at: {self._zap_daemon_path}")
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
        # context_name = scan_options.get("context_name", "Default Context") # Unused for now

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
            use_ajax = scan_options.get("use_ajax_spider", False)
            scan_id: Optional[str] = None  # Hint scan_id type

            if use_ajax:
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
            if scan_type.lower() == "active":
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

    def parse_output(self, raw_output: Dict[str, Any]) -> Optional[List[BaseFinding]]:
        """Parse ZAP output into a list of WebFinding objects."""
        if not raw_output or not raw_output.get("alerts"):
            log.warning("No ZAP alerts found in output.")
            return None

        try:
            findings: List[BaseFinding] = []

            # Map ZAP risk levels to our severity levels
            risk_to_severity = {
                "High": FindingSeverity.HIGH,
                "Medium": FindingSeverity.MEDIUM,
                "Low": FindingSeverity.LOW,
                "Informational": FindingSeverity.INFO,
                # Default to INFO for unknown risk levels
                "": FindingSeverity.INFO,
            }

            for alert in raw_output.get("alerts", []):
                # Map important fields from ZAP alert to our finding format
                try:
                    url = alert.get("url", "")

                    finding = WebFinding(
                        title=f"ZAP: {alert.get('name', 'Unknown Vulnerability')}",
                        description=alert.get(
                            "description", "No description available"
                        ),
                        severity=risk_to_severity.get(
                            alert.get("risk", ""), FindingSeverity.INFO
                        ),
                        target=raw_output.get("target", "unknown"),
                        source_tool=self.tool_name,
                        raw_evidence=alert,
                        url=url,
                        method=alert.get("method"),
                        parameter=alert.get("param", None),
                        status_code=None,  # ZAP doesn't typically include status codes in alerts
                    )
                    findings.append(finding)
                except ValidationError as ve:
                    log.warning(f"Failed to create WebFinding for ZAP alert: {ve}")
                    continue

            if not findings:
                log.info("No findings parsed from ZAP output.")
                return None

            log.info(f"Parsed {len(findings)} findings from ZAP output.")
            return findings

        except Exception as e:
            log.exception(f"Error parsing ZAP output: {e}")
            return None

    async def shutdown(self) -> None:
        """Shut down ZAP daemon if it was started by this integration."""
        if not self._zap_api or self._zap_config.get("use_existing_instance", True):
            # Don't shut down if we're using an existing instance
            return

        # Add assertion for mypy
        assert self._zap_api is not None

        log.info("Shutting down ZAP daemon...")
        try:
            self._zap_api.core.shutdown()
            log.info("ZAP daemon shutdown successfully")
        except Exception as e:
            log.warning(f"Error shutting down ZAP daemon: {e}")
