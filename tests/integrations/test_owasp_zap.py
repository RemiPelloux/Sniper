from typing import Any, Dict, List, cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Import directly to mock
import src.integrations.owasp_zap
from src.integrations.base import ToolIntegrationError
from src.results.types import BaseFinding, FindingSeverity, WebFinding

# from src.results.types import WebFinding  # Unused import


# Create a fake ZAPv2 class for tests
class MockZAPv2:
    pass


# Add the mock to the module
src.integrations.owasp_zap.ZAPv2 = MockZAPv2
src.integrations.owasp_zap.ZAP_AVAILABLE = True

# Now import ZapIntegration after we've patched the module
from src.integrations.owasp_zap import ZapIntegration  # noqa: E402


@pytest.fixture
def zap_integration() -> ZapIntegration:
    integration = ZapIntegration()
    integration._executor = AsyncMock()
    integration._zap_daemon_path = "/mock/path/to/zap.sh"
    return integration


@pytest.fixture
def mock_zap_api() -> MagicMock:
    """Return a mock ZAP API object."""
    mock_api = MagicMock()
    # Set up mock methods used in the integration
    mock_api.core.version = "2.12.0"
    mock_api.core.urls.return_value = [
        "https://example.com",
        "https://example.com/login",
    ]
    mock_api.core.alerts.return_value = [
        {
            "name": "Cross Site Scripting (Reflected)",
            "risk": "High",
            "confidence": "Medium",
            "url": "https://example.com/search?q=test",
            "method": "GET",
            "param": "q",
            "attack": "<script>alert(1)</script>",
            "evidence": "<script>alert(1)</script>",
            "description": "Cross-site Scripting (XSS) is an attack technique that...",
            "solution": "Phase: Architecture and Design\n\nUse a vetted library...",
        },
        {
            "name": "X-Content-Type-Options Header Missing",
            "risk": "Low",
            "confidence": "Medium",
            "url": "https://example.com/",
            "method": "GET",
            "param": "",
            "attack": "",
            "evidence": "",
            "description": ("The Anti-MIME-Sniffing header X-Content-Type-Options..."),
            "solution": (
                "Ensure that the application/web server sets the Content-Type header..."
            ),
        },
    ]
    mock_api.spider.scan.return_value = "1"
    mock_api.spider.status.return_value = "100"

    mock_api.ajaxSpider.scan.return_value = "1"
    mock_api.ajaxSpider.status = "stopped"

    mock_api.ascan.scan.return_value = "1"
    mock_api.ascan.status.return_value = "100"

    mock_api.stats.all_sites_stats.return_value = {
        "https://example.com": {"stat1": "value1"}
    }

    return mock_api


class TestZapIntegration:
    """Test the OWASP ZAP integration."""

    def test_tool_name(self, zap_integration: ZapIntegration) -> None:
        """Test the tool name property."""
        assert zap_integration.tool_name == "owasp-zap"

    def test_check_prerequisites_no_api(self) -> None:
        """Test prerequisite check when ZAP API is not available."""
        with patch("src.integrations.owasp_zap.ZAP_AVAILABLE", False):
            integration = ZapIntegration()
            assert integration.check_prerequisites() is False

    def test_check_prerequisites_no_executable(self) -> None:
        """Test prerequisite check when ZAP executable is not available."""
        with patch("shutil.which", return_value=None):
            integration = ZapIntegration()
            assert integration.check_prerequisites() is False

    def test_check_prerequisites_with_executable(
        self, zap_integration: ZapIntegration
    ) -> None:
        """Test prerequisite check when ZAP executable is available."""
        with patch.object(zap_integration, "_connect_to_zap"):
            assert zap_integration.check_prerequisites() is True

    @pytest.mark.asyncio
    async def test_start_zap_daemon_success(
        self, zap_integration: ZapIntegration
    ) -> None:
        """Test starting ZAP daemon successfully."""
        # Mock executor response
        mock_result = AsyncMock()
        mock_result.return_code = 0
        mock_result.timed_out = False
        # Cast executor to MagicMock to access test attributes
        cast(MagicMock, zap_integration._executor).execute.return_value = mock_result

        # Mock connection
        with patch.object(zap_integration, "_connect_to_zap") as mock_connect:
            # Mock asyncio.sleep to speed up the test
            with patch("asyncio.sleep", return_value=None):
                await zap_integration._start_zap_daemon()

                # Verify the command was executed
                cast(MagicMock, zap_integration._executor).execute.assert_called_once()
                command = cast(MagicMock, zap_integration._executor).execute.call_args[
                    0
                ][0]
                assert "-daemon" in command
                assert "-port" in command
                assert "8080" in command  # Default port

                # Verify connection attempt
                mock_connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_zap_daemon_failure(
        self, zap_integration: ZapIntegration
    ) -> None:
        """Test failure to start ZAP daemon."""
        # Mock executor response with error
        mock_result = AsyncMock()
        mock_result.return_code = 1
        mock_result.timed_out = False
        mock_result.stderr = "Error starting ZAP"
        # Cast executor to MagicMock to access test attributes
        cast(MagicMock, zap_integration._executor).execute.return_value = mock_result

        # Test that an exception is raised
        with pytest.raises(ToolIntegrationError):
            with patch("asyncio.sleep", return_value=None):
                await zap_integration._start_zap_daemon()

    @pytest.mark.asyncio
    async def test_run_passive_scan(
        self, zap_integration: ZapIntegration, mock_zap_api: MagicMock
    ) -> None:
        """Test running a passive scan."""
        # Set up the mock ZAP API
        zap_integration._zap_api = mock_zap_api

        # Mock the start_zap_daemon method
        with patch.object(
            zap_integration, "_start_zap_daemon", AsyncMock()
        ) as mock_start:
            # Mock asyncio.sleep to speed up the test
            with patch("asyncio.sleep", AsyncMock()):
                result = await zap_integration.run(
                    "https://example.com", {"scan_type": "passive"}
                )

                # Verify the API calls
                mock_start.assert_called_once()
                assert mock_zap_api.core.new_session.called
                assert mock_zap_api.spider.scan.called
                assert mock_zap_api.spider.status.called
                assert not mock_zap_api.ascan.scan.called  # Should not call active scan

                # Verify the result structure
                assert "alerts" in result
                assert "urls" in result
                assert "stats" in result
                assert "spider_id" in result
                assert result["scan_type"] == "passive"
                assert result["target"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_run_active_scan(
        self, zap_integration: ZapIntegration, mock_zap_api: MagicMock
    ) -> None:
        """Test running an active scan."""
        # Set up the mock ZAP API
        zap_integration._zap_api = mock_zap_api

        # Mock the start_zap_daemon method
        with patch.object(
            zap_integration, "_start_zap_daemon", AsyncMock()
        ) as mock_start:
            # Mock asyncio.sleep to speed up the test
            with patch("asyncio.sleep", AsyncMock()):
                result = await zap_integration.run(
                    "https://example.com", {"scan_type": "active"}
                )

                # Verify the API calls
                mock_start.assert_called_once()
                assert mock_zap_api.core.new_session.called
                assert mock_zap_api.spider.scan.called
                assert mock_zap_api.spider.status.called
                assert mock_zap_api.ascan.scan.called  # Should call active scan
                assert mock_zap_api.ascan.status.called

                # Verify the result structure
                assert "alerts" in result
                assert "urls" in result
                assert "stats" in result
                assert "spider_id" in result
                assert "active_scan_id" in result
                assert result["scan_type"] == "active"
                assert result["target"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_run_ajax_spider(
        self, zap_integration: ZapIntegration, mock_zap_api: MagicMock
    ) -> None:
        """Test running scan with AJAX spider."""
        # Set up the mock ZAP API
        zap_integration._zap_api = mock_zap_api

        # Mock the start_zap_daemon method
        with patch.object(
            zap_integration, "_start_zap_daemon", AsyncMock()
        ) as mock_start:
            # Mock asyncio.sleep to speed up the test
            with patch("asyncio.sleep", AsyncMock()):
                result = await zap_integration.run(
                    "https://example.com",
                    {"scan_type": "passive", "ajax_spider": True},
                )

                # Verify the API calls
                mock_start.assert_called_once()
                assert mock_zap_api.core.new_session.called
                assert mock_zap_api.ajaxSpider.scan.called
                assert (
                    not mock_zap_api.spider.scan.called
                )  # Should not call normal spider
                assert not mock_zap_api.ascan.scan.called  # Should not call active scan

                # Verify the result structure
                assert "alerts" in result
                assert "urls" in result
                assert "stats" in result
                assert "spider_id" in result
                assert result["scan_type"] == "passive"
                assert result["target"] == "https://example.com"

    def test_parse_output(
        self, zap_integration: ZapIntegration, mock_zap_api: MagicMock
    ) -> None:
        """Test parsing ZAP scan output."""
        # Fix the validation - make sure we're patching the WebFinding validation
        with patch("src.integrations.owasp_zap.WebFinding") as mock_finding:
            # Create a mock finding to return
            mock_finding_instance = MagicMock()
            mock_finding.return_value = mock_finding_instance

            # Create test raw output
            raw_output = {
                "alerts": mock_zap_api.core.alerts.return_value,
                "target": "https://example.com",
            }

            # Parse the output
            findings = zap_integration.parse_output(raw_output)

            # Verify WebFinding was called, indicating parsing worked
            assert mock_finding.called

            # Verify it was called exactly twice (once for each alert)
            assert mock_finding.call_count == 2

    def test_parse_output_numeric_risk(self, zap_integration: ZapIntegration) -> None:
        """Test parsing ZAP scan output with numeric risk values."""
        # Fix the validation - make sure we're patching the WebFinding validation
        with patch("src.integrations.owasp_zap.WebFinding") as mock_finding:
            # Create a mock finding to return
            mock_finding_instance = MagicMock()
            mock_finding.return_value = mock_finding_instance

            # Create test raw output with numeric risk values
            raw_output = {
                "alerts": [
                    {
                        "name": "SQL Injection",
                        "risk": 3,  # High risk as a number
                        "confidence": "High",
                        "url": "https://example.com/search",
                        "method": "POST",
                        "param": "query",
                        "evidence": "error in your SQL syntax",
                        "description": "SQL injection vulnerability",
                        "solution": "Use parameterized queries",
                    },
                    {
                        "name": "Excessive Security Headers",
                        "risk": 0,  # Informational risk as a number
                        "confidence": "Low",
                        "url": "https://example.com/",
                        "method": "GET",
                        "param": "",
                        "evidence": "",
                        "description": "Too many security headers",
                        "solution": "Remove unnecessary headers",
                    },
                ],
                "target": "https://example.com",
            }

            # Parse the output
            findings = zap_integration.parse_output(raw_output)

            # Verify WebFinding was called, indicating parsing worked
            assert mock_finding.called

            # Verify it was called exactly twice (once for each alert)
            assert mock_finding.call_count == 2

            # Verify correct risk mapping for numeric values
            calls = mock_finding.call_args_list
            assert calls[0][1]["severity"] == FindingSeverity.HIGH
            assert calls[1][1]["severity"] == FindingSeverity.INFO

    def test_parse_output_no_alerts(self, zap_integration: ZapIntegration) -> None:
        """Test parsing output with no alerts."""
        # Test with empty alerts
        raw_output_empty = {"alerts": [], "target": "https://example.com"}

        # When alerts is empty, it should return empty list, not None
        with patch("src.integrations.owasp_zap.WebFinding"):
            results = zap_integration.parse_output(raw_output_empty)
            assert isinstance(results, list)
            assert len(results) == 0

        # Test with no alerts key
        raw_output_no_alerts = {"target": "https://example.com"}
        assert zap_integration.parse_output(raw_output_no_alerts) is None

        # Test with None
        assert zap_integration.parse_output(None) is None

    def test_parse_output_with_validation_error(
        self, zap_integration: ZapIntegration
    ) -> None:
        """Test parsing output with data that will cause validation errors."""
        # Create test raw output with invalid data
        raw_output = {
            "alerts": [
                {
                    # Missing required fields like name
                    "risk": "High",
                    "url": "https://example.com/search",
                }
            ],
            "target": "https://example.com",
        }

        # Create a realistic validation error
        from pydantic import ValidationError

        # Mock pydantic validation error with a patched WebFinding that raises Exception
        with patch(
            "src.integrations.owasp_zap.WebFinding",
            side_effect=ValidationError.from_exception_data(
                "WebFinding",
                [{"type": "missing", "loc": ("name",), "msg": "field required"}],
            ),
        ):
            findings = zap_integration.parse_output(raw_output)
            assert findings is None

    @pytest.mark.asyncio
    async def test_shutdown(
        self, zap_integration: ZapIntegration, mock_zap_api: MagicMock
    ) -> None:
        """Test shutting down the ZAP daemon."""
        # Set up the ZAP API
        zap_integration._zap_api = mock_zap_api

        # Test shutdown with use_existing_instance=False
        zap_integration._zap_config = {"use_existing_instance": False}
        await zap_integration.shutdown()
        mock_zap_api.core.shutdown.assert_called_once()

        # Reset the mock
        mock_zap_api.core.shutdown.reset_mock()

        # Test shutdown with use_existing_instance=True
        zap_integration._zap_config = {"use_existing_instance": True}
        await zap_integration.shutdown()
        mock_zap_api.core.shutdown.assert_not_called()

    @pytest.mark.asyncio
    async def test_shutdown_with_exception(
        self, zap_integration: ZapIntegration, mock_zap_api: MagicMock
    ) -> None:
        """Test shutdown when an exception occurs."""
        # Set up the ZAP API
        zap_integration._zap_api = mock_zap_api
        zap_integration._zap_config = {"use_existing_instance": False}

        # Make shutdown raise an exception
        mock_zap_api.core.shutdown.side_effect = Exception("Shutdown error")

        # Ensure the exception is caught and doesn't propagate
        await zap_integration.shutdown()
        mock_zap_api.core.shutdown.assert_called_once()
