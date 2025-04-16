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
                    {"scan_type": "passive", "use_ajax_spider": True},
                )

                # Verify the API calls
                mock_start.assert_called_once()
                assert mock_zap_api.core.new_session.called
                assert mock_zap_api.ajaxSpider.scan.called
                assert (
                    not mock_zap_api.spider.scan.called
                )  # Regular spider should not be called

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
        # Create sample output similar to what run() would return
        raw_output = {
            "alerts": mock_zap_api.core.alerts(),
            "urls": mock_zap_api.core.urls(),
            "stats": mock_zap_api.stats.all_sites_stats(),
            "spider_id": "1",
            "active_scan_id": "1",
            "scan_type": "active",
            "target": "https://example.com",
        }

        # Parse the output
        findings: List[BaseFinding] | None = zap_integration.parse_output(raw_output)

        # Verify findings
        assert findings is not None
        assert len(findings) == 2

        # Check the high severity finding (XSS)
        # Cast to WebFinding to access specific attributes
        xss_finding: WebFinding = cast(
            WebFinding, findings[0]
        )  # Assuming order based on mock
        if "X-Content" in xss_finding.title:  # Handle potential order swap
            xss_finding = cast(WebFinding, findings[1])

        assert "Cross Site Scripting" in xss_finding.title
        assert xss_finding.severity == FindingSeverity.HIGH
        assert xss_finding.url == "https://example.com/search?q=test"
        assert xss_finding.method == "GET"
        assert xss_finding.parameter == "q"

        # Check the low severity finding (missing header)
        header_finding: WebFinding = cast(WebFinding, findings[1])  # Assuming order
        if (
            "Cross Site Scripting" in header_finding.title
        ):  # Handle potential order swap
            header_finding = cast(WebFinding, findings[0])

        assert "X-Content-Type-Options" in header_finding.title
        assert header_finding.severity == FindingSeverity.LOW
        assert header_finding.url == "https://example.com/"
        assert header_finding.method == "GET"
        assert header_finding.parameter == ""

    def test_parse_output_no_alerts(self, zap_integration: ZapIntegration) -> None:
        """Test parsing ZAP output with no alerts."""
        raw_output: Dict[str, Any] = {
            "alerts": [],
            "urls": ["https://example.com"],
            "stats": {},
            "spider_id": "1",
            "scan_type": "passive",
            "target": "https://example.com",
        }

        findings = zap_integration.parse_output(raw_output)
        assert findings is None

    @pytest.mark.asyncio
    async def test_shutdown(
        self, zap_integration: ZapIntegration, mock_zap_api: MagicMock
    ) -> None:
        """Test shutting down ZAP daemon."""
        # Set up the mock ZAP API
        zap_integration._zap_api = mock_zap_api
        zap_integration._zap_config = {"use_existing_instance": False}

        await zap_integration.shutdown()

        # Verify the shutdown call was made
        assert mock_zap_api.core.shutdown.called
