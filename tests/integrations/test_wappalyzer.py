import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.base import ToolIntegrationError
from src.integrations.executors import ExecutionResult
from src.integrations.wappalyzer import WappalyzerIntegration
from src.results.types import FindingSeverity, TechnologyFinding

MOCK_WAPPALYZER_EXEC = "/mock/path/to/wappalyzer"


@pytest.fixture
def wappalyzer_integration() -> WappalyzerIntegration:
    # Patch shutil.which globally for this fixture?
    with patch("shutil.which", return_value=MOCK_WAPPALYZER_EXEC):
        integration = WappalyzerIntegration()
        integration._executor = AsyncMock()  # Use AsyncMock for the executor
        yield integration


# Mock data for successful run
MOCK_SUCCESS_OUTPUT_DICT = json.dumps(
    {
        "urls": {"https://example.com": {"status": 200}},
        "technologies": [
            {
                "slug": "nginx",
                "name": "Nginx",
                "confidence": 100,
                "version": "1.18.0",
                "icon": "Nginx.svg",
                "website": "http://nginx.org/en",
                "cpe": "cpe:/a:igor_sysoev:nginx:1.18.0",
                "categories": [
                    {"id": 22, "slug": "web-servers", "name": "Web servers"}
                ],
            },
            {
                "slug": "react",
                "name": "React",
                "confidence": 100,
                "version": None,
                "icon": "React.svg",
                "website": "https://reactjs.org",
                "cpe": None,
                "categories": [
                    {
                        "id": 12,
                        "slug": "javascript-frameworks",
                        "name": "JavaScript frameworks",
                    }
                ],
            },
        ],
    }
)

MOCK_SUCCESS_OUTPUT_LIST = json.dumps(
    [
        {
            "slug": "nginx",
            "name": "Nginx",
            "confidence": 100,
            "version": "1.18.0",
            "icon": "Nginx.svg",
            "website": "http://nginx.org/en",
            "cpe": "cpe:/a:igor_sysoev:nginx:1.18.0",
            "categories": [{"id": 22, "slug": "web-servers", "name": "Web servers"}],
        },
        {
            "slug": "react",
            "name": "React",
            "confidence": 100,
            "version": None,
            "icon": "React.svg",
            "website": "https://reactjs.org",
            "cpe": None,
            "categories": [
                {
                    "id": 12,
                    "slug": "javascript-frameworks",
                    "name": "JavaScript frameworks",
                }
            ],
        },
    ]
)


class TestWappalyzerIntegration:

    def test_wappalyzer_tool_name(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        assert wappalyzer_integration.tool_name == "wappalyzer"

    def test_wappalyzer_check_prerequisites_success(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test prerequisite check succeeds when executable is found."""
        # Fixture already patches shutil.which
        assert wappalyzer_integration.check_prerequisites() is True

    @patch("shutil.which", return_value=None)
    def test_wappalyzer_check_prerequisites_fail(self, mock_which: MagicMock) -> None:
        """Test prerequisite check fails when executable is not found."""
        integration = WappalyzerIntegration()
        assert integration.check_prerequisites() is False

    @pytest.mark.asyncio
    async def test_wappalyzer_run_success(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test a successful run of Wappalyzer."""
        mock_result = ExecutionResult(
            command=f"{MOCK_WAPPALYZER_EXEC} https://example.com",
            return_code=0,
            stdout=MOCK_SUCCESS_OUTPUT_DICT,
            stderr="",
            timed_out=False,
        )
        # Setup the mock executor's execute method
        wappalyzer_integration._executor.execute = AsyncMock(return_value=mock_result)  # type: ignore

        target_url = "https://example.com"
        result = await wappalyzer_integration.run(target_url)

        # Verify the executor was called correctly
        wappalyzer_integration._executor.execute.assert_called_once_with(
            [MOCK_WAPPALYZER_EXEC, target_url], timeout_seconds=120  # Default timeout
        )

        # Verify the result object is returned
        assert result == mock_result

    @pytest.mark.asyncio
    async def test_wappalyzer_run_timeout(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test Wappalyzer run when it times out."""
        mock_result = ExecutionResult(
            command=f"{MOCK_WAPPALYZER_EXEC} https://example.com",
            return_code=-1,  # Typically not 0 on timeout
            stdout="",  # May have partial output, but often empty
            stderr="",
            timed_out=True,
        )
        wappalyzer_integration._executor.execute = AsyncMock(return_value=mock_result)  # type: ignore

        target_url = "https://example.com"
        result = await wappalyzer_integration.run(
            target_url, options={"timeout_seconds": 1}
        )

        wappalyzer_integration._executor.execute.assert_called_once_with(
            [MOCK_WAPPALYZER_EXEC, target_url], timeout_seconds=1
        )
        assert result.timed_out is True

    @pytest.mark.asyncio
    async def test_wappalyzer_run_failure(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test Wappalyzer run when the command fails."""
        mock_result = ExecutionResult(
            command=f"{MOCK_WAPPALYZER_EXEC} https://invalid-url",
            return_code=1,
            stdout="",
            stderr="Some error message",
            timed_out=False,
        )
        wappalyzer_integration._executor.execute = AsyncMock(return_value=mock_result)  # type: ignore

        target_url = "https://invalid-url"
        result = await wappalyzer_integration.run(target_url)

        wappalyzer_integration._executor.execute.assert_called_once_with(
            [MOCK_WAPPALYZER_EXEC, target_url], timeout_seconds=120
        )
        assert result.return_code == 1
        assert "Some error message" in result.stderr

    # Removed @pytest.mark.asyncio
    def test_wappalyzer_parse_success_dict_format(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing successful JSON output (dict format)."""
        mock_execution_result = ExecutionResult(
            command="wappalyzer https://example.com",
            return_code=0,
            stdout=MOCK_SUCCESS_OUTPUT_DICT,
            stderr="",
            timed_out=False,
        )

        findings = wappalyzer_integration.parse_output(mock_execution_result)

        assert findings is not None
        assert len(findings) == 2

        # Check first finding (Nginx)
        nginx_finding = next(
            (f for f in findings if f.technology_name == "Nginx"), None
        )
        assert nginx_finding is not None
        assert isinstance(nginx_finding, TechnologyFinding)
        assert nginx_finding.target == "https://example.com"  # URL from JSON
        assert nginx_finding.version == "1.18.0"
        assert "Web servers" in nginx_finding.categories
        assert nginx_finding.source_tool == "wappalyzer"
        assert nginx_finding.raw_evidence["slug"] == "nginx"

        # Check second finding (React)
        react_finding = next(
            (f for f in findings if f.technology_name == "React"), None
        )
        assert react_finding is not None
        assert isinstance(react_finding, TechnologyFinding)
        assert react_finding.target == "https://example.com"
        assert react_finding.version is None
        assert "JavaScript frameworks" in react_finding.categories
        assert react_finding.source_tool == "wappalyzer"
        assert react_finding.raw_evidence["slug"] == "react"

    # Removed @pytest.mark.asyncio
    def test_wappalyzer_parse_success_list_format(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing successful JSON output (list format)."""
        mock_execution_result = ExecutionResult(
            command="wappalyzer https://anothersite.com",
            return_code=0,
            stdout=MOCK_SUCCESS_OUTPUT_LIST,
            stderr="",
            timed_out=False,
        )

        findings = wappalyzer_integration.parse_output(mock_execution_result)

        assert findings is not None
        assert len(findings) == 2

        # Check first finding (Nginx)
        nginx_finding = next(
            (f for f in findings if f.technology_name == "Nginx"), None
        )
        assert nginx_finding is not None
        assert isinstance(nginx_finding, TechnologyFinding)
        assert nginx_finding.target == "https://anothersite.com"  # URL from command
        assert nginx_finding.version == "1.18.0"
        assert "Web servers" in nginx_finding.categories
        assert nginx_finding.source_tool == "wappalyzer"

        # Check second finding (React)
        react_finding = next(
            (f for f in findings if f.technology_name == "React"), None
        )
        assert react_finding is not None
        assert isinstance(react_finding, TechnologyFinding)
        assert react_finding.target == "https://anothersite.com"
        assert react_finding.version is None
        assert "JavaScript frameworks" in react_finding.categories
        assert react_finding.source_tool == "wappalyzer"

    # Removed @pytest.mark.asyncio
    def test_wappalyzer_parse_empty_output(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing when Wappalyzer returns empty stdout."""
        mock_execution_result = ExecutionResult(
            command="wappalyzer https://nothing.com",
            return_code=0,
            stdout="",
            stderr="",
            timed_out=False,
        )
        findings = wappalyzer_integration.parse_output(mock_execution_result)
        assert findings is None

    # Removed @pytest.mark.asyncio
    def test_wappalyzer_parse_invalid_json(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing invalid JSON output."""
        mock_execution_result = ExecutionResult(
            command="wappalyzer https://badjson.com",
            return_code=0,
            stdout="{not valid json",
            stderr="",
            timed_out=False,
        )
        findings = wappalyzer_integration.parse_output(mock_execution_result)
        assert findings is None

    # Removed @pytest.mark.asyncio
    def test_wappalyzer_parse_unexpected_format(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing JSON with an unexpected structure."""
        mock_execution_result = ExecutionResult(
            command="wappalyzer https://weird.com",
            return_code=0,
            stdout=json.dumps({"unexpected_key": []}),
            stderr="",
            timed_out=False,
        )
        findings = wappalyzer_integration.parse_output(mock_execution_result)
        assert findings is None

    # Removed @pytest.mark.asyncio
    def test_wappalyzer_parse_failed_execution(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing output from a failed execution."""
        mock_execution_result = ExecutionResult(
            command="wappalyzer https://failed.com",
            return_code=1,
            stdout="",
            stderr="Error occurred",
            timed_out=False,
        )
        findings = wappalyzer_integration.parse_output(mock_execution_result)
        assert findings is None
