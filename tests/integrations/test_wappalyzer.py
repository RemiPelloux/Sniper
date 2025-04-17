import json
from typing import Any, Generator, cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# from src.integrations.base import ToolIntegrationError # Unused
from src.integrations.base import ToolIntegrationError # Added for run exception test
from src.integrations.executors import ExecutionResult
from src.integrations.wappalyzer import WappalyzerIntegration

# from src.results.types import FindingSeverity # Unused
from src.results.types import TechnologyFinding

MOCK_WAPPALYZER_EXEC = "/mock/path/to/wappalyzer"


@pytest.fixture
def wappalyzer_integration() -> Generator[WappalyzerIntegration, Any, None]:
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

# This isn't directly used by the current parser, but kept for potential future use/reference
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
        wappalyzer_integration._executor.execute = AsyncMock(return_value=mock_result) # type: ignore

        target_url = "https://example.com"
        result = await wappalyzer_integration.run(target_url)

        # Verify the executor was called correctly
        expected_command = [
            MOCK_WAPPALYZER_EXEC,
            "-i",
            target_url,
            "--scan-type",
            "full",  # Default scan type
            "-t",
            "5",  # Default threads
        ]
        cast(
            MagicMock, wappalyzer_integration._executor
        ).execute.assert_called_once_with(
            expected_command, timeout_seconds=180  # Default timeout
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
        wappalyzer_integration._executor.execute = AsyncMock(return_value=mock_result) # type: ignore

        target_url = "https://example.com"
        options = {"timeout_seconds": 1, "threads": 3, "scan_type": "fast"}
        result = await wappalyzer_integration.run(target_url, options=options)

        expected_command = [
            MOCK_WAPPALYZER_EXEC,
            "-i",
            target_url,
            "--scan-type",
            "fast",
            "-t",
            "3",
        ]
        cast(
            MagicMock, wappalyzer_integration._executor
        ).execute.assert_called_once_with(expected_command, timeout_seconds=1)
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
        wappalyzer_integration._executor.execute = AsyncMock(return_value=mock_result) # type: ignore

        target_url = "https://invalid-url"
        result = await wappalyzer_integration.run(target_url)

        expected_command = [
            MOCK_WAPPALYZER_EXEC,
            "-i",
            target_url,
            "--scan-type",
            "full",
            "-t",
            "5",
        ]
        cast(
            MagicMock, wappalyzer_integration._executor
        ).execute.assert_called_once_with(
            expected_command, timeout_seconds=180  # Default timeout matches run default
        )
        assert result.return_code == 1
        assert "Some error message" in result.stderr

    @pytest.mark.asyncio
    async def test_wappalyzer_run_executor_exception(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test Wappalyzer run when the executor raises an exception."""
        # Make the mock executor raise an arbitrary exception
        wappalyzer_integration._executor.execute = AsyncMock(side_effect=RuntimeError("Executor exploded")) # type: ignore

        target_url = "https://example.com"
        # Expect ToolIntegrationError to be raised due to the caught exception
        with pytest.raises(ToolIntegrationError, match="Wappalyzer execution failed: Executor exploded"):
            await wappalyzer_integration.run(target_url)

        # Ensure execute was still called
        cast(
            MagicMock, wappalyzer_integration._executor
        ).execute.assert_called_once()


    # --- Tests for parse_output ---

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

        # Check first finding (Nginx) - Cast to TechnologyFinding
        nginx_finding = next(
            (
                cast(TechnologyFinding, f)
                for f in findings
                if cast(TechnologyFinding, f).technology_name == "Nginx"
            ),
            None,
        )
        assert nginx_finding is not None
        assert isinstance(nginx_finding, TechnologyFinding)
        assert nginx_finding.target == "https://example.com"  # URL from JSON
        assert nginx_finding.version == "1.18.0"
        assert "Web servers" in nginx_finding.categories
        assert nginx_finding.source_tool == "wappalyzer"
        assert nginx_finding.raw_evidence is not None # mypy check
        assert nginx_finding.raw_evidence.get("slug") == "nginx"

        # Check second finding (React)
        react_finding = next(
            (
                cast(TechnologyFinding, f)
                for f in findings
                if cast(TechnologyFinding, f).technology_name == "React"
            ),
            None,
        )
        assert react_finding is not None
        assert isinstance(react_finding, TechnologyFinding)
        assert react_finding.target == "https://example.com"
        assert react_finding.version is None
        assert "JavaScript frameworks" in react_finding.categories
        assert react_finding.source_tool == "wappalyzer"
        assert react_finding.raw_evidence is not None # mypy check
        assert react_finding.raw_evidence.get("slug") == "react"


    def test_wappalyzer_parse_failure_or_timeout(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing returns None if execution failed or timed out."""
        failed_result = ExecutionResult("cmd", 1, "", "err", False)
        timed_out_result = ExecutionResult("cmd", -1, "", "", True)

        assert wappalyzer_integration.parse_output(failed_result) is None
        assert wappalyzer_integration.parse_output(timed_out_result) is None

    def test_wappalyzer_parse_empty_stdout(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing returns None when stdout is empty."""
        empty_stdout_result = ExecutionResult("cmd", 0, "", "", False)
        assert wappalyzer_integration.parse_output(empty_stdout_result) is None

    def test_wappalyzer_parse_json_decode_error(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing returns None on JSON decode error."""
        invalid_json_result = ExecutionResult("cmd", 0, "{invalid json", "", False)
        assert wappalyzer_integration.parse_output(invalid_json_result) is None

    def test_wappalyzer_parse_unexpected_format_not_dict(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing returns None when top-level JSON is not a dictionary."""
        list_result = ExecutionResult("cmd", 0, json.dumps([1, 2]), "", False)
        assert wappalyzer_integration.parse_output(list_result) is None

    def test_wappalyzer_parse_missing_urls_key(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing returns None when 'urls' key is missing."""
        mock_data = json.dumps({"technologies": []})
        missing_urls_result = ExecutionResult("cmd", 0, mock_data, "", False)
        assert wappalyzer_integration.parse_output(missing_urls_result) is None

    def test_wappalyzer_parse_empty_urls_dict(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing returns None when 'urls' dict is empty."""
        mock_data = json.dumps({"urls": {}, "technologies": []})
        empty_urls_result = ExecutionResult("cmd", 0, mock_data, "", False)
        assert wappalyzer_integration.parse_output(empty_urls_result) is None


    def test_wappalyzer_parse_missing_technologies_key(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing returns None when 'technologies' key is missing."""
        mock_data = json.dumps({"urls": {"http://a.com": {"status": 200}}})
        missing_tech_result = ExecutionResult("cmd", 0, mock_data, "", False)
        assert wappalyzer_integration.parse_output(missing_tech_result) is None

    def test_wappalyzer_parse_technologies_not_list(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing returns None when 'technologies' is not a list."""
        mock_data = json.dumps(
            {"urls": {"http://a.com": {"status": 200}}, "technologies": "not_a_list"}
        )
        not_list_tech_result = ExecutionResult("cmd", 0, mock_data, "", False)
        assert wappalyzer_integration.parse_output(not_list_tech_result) is None


    def test_wappalyzer_parse_empty_technologies_list(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing returns None when 'technologies' list is empty."""
        mock_data = json.dumps(
            {"urls": {"http://a.com": {"status": 200}}, "technologies": []}
        )
        empty_tech_result = ExecutionResult("cmd", 0, mock_data, "", False)
        # Should return None because the log message indicates no technologies were parsed
        assert wappalyzer_integration.parse_output(empty_tech_result) is None

    def test_wappalyzer_parse_invalid_item_in_technologies(
         self, wappalyzer_integration: WappalyzerIntegration
     ) -> None:
         """Test parsing skips non-dict items in the technologies list."""
         mock_data = json.dumps(
             {
                 "urls": {"http://a.com": {"status": 200}},
                 "technologies": ["not_a_dict", {"name": "ValidTech", "categories": []}], # Contains invalid item
             }
         )
         result = ExecutionResult("cmd", 0, mock_data, "", False)
         findings = wappalyzer_integration.parse_output(result)
         assert findings is not None
         assert len(findings) == 1 # Only the valid tech should be parsed
         assert findings[0].technology_name == "ValidTech" # type: ignore

    def test_wappalyzer_parse_missing_tech_name(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing skips tech entries with missing or invalid names."""
        mock_data = json.dumps(
            {
                "urls": {"http://a.com": {"status": 200}},
                "technologies": [
                    {"name": "Good", "version": "1.0", "categories": []},
                    {"version": "2.0", "categories": []}, # Missing name
                    {"name": 123, "version": "3.0", "categories": []} # Invalid name type
                ],
            }
        )
        result = ExecutionResult("cmd", 0, mock_data, "", False)
        findings = wappalyzer_integration.parse_output(result)
        assert findings is not None
        assert len(findings) == 1
        assert findings[0].technology_name == "Good" # type: ignore


    def test_wappalyzer_parse_invalid_category_format(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing handles invalid category formats gracefully."""
        mock_data = json.dumps(
            {
                "urls": {"http://a.com": {"status": 200}},
                "technologies": [
                    {
                        "name": "TechWithCategories",
                        "categories": [
                            {"id": 1, "slug": "cat1", "name": "Category One"},
                            "not_a_dict", # Invalid item
                            {"id": 2, "slug": "cat2"}, # Missing name
                            {"id": 3, "slug": "cat3", "name": "Category Three"}
                        ]
                    }
                ],
            }
        )
        result = ExecutionResult("cmd", 0, mock_data, "", False)
        findings = wappalyzer_integration.parse_output(result)
        assert findings is not None
        assert len(findings) == 1
        tech_finding = cast(TechnologyFinding, findings[0])
        assert tech_finding.technology_name == "TechWithCategories"
        # Should contain only the valid category names
        assert tech_finding.categories == ["Category One", "Category Three"]


    def test_wappalyzer_parse_finding_creation_error(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing handles errors during TechnologyFinding creation."""
        mock_data = json.dumps(
             {
                 "urls": {"http://a.com": {"status": 200}},
                 "technologies": [
                     {"name": "GoodTech", "categories": []},
                     {"name": "BadTech", "categories": []} # This will cause an error
                 ]
             }
        )
        result = ExecutionResult("cmd", 0, mock_data, "", False)

        # Mock TechnologyFinding to raise an error for the second tech
        original_finding = TechnologyFinding
        def mock_finding_init(*args: Any, **kwargs: Any) -> TechnologyFinding:
            if kwargs.get("technology_name") == "BadTech":
                raise ValueError("Invalid finding data")
            # Call the original __init__ for other cases
            # Need to create an instance first before calling __init__
            instance = object.__new__(original_finding)
            original_finding.__init__(instance, *args, **kwargs)
            return instance

        # Use create=True because TechnologyFinding is imported in the module under test
        with patch("src.integrations.wappalyzer.TechnologyFinding", side_effect=mock_finding_init, create=True) as mock_tf:
             findings = wappalyzer_integration.parse_output(result)

        assert findings is not None
        assert len(findings) == 1 # Only GoodTech should be parsed
        assert findings[0].technology_name == "GoodTech" # type: ignore
        # Ensure our mock was actually called (at least tried for both)
        assert mock_tf.call_count == 2


    def test_wappalyzer_parse_general_exception(
        self, wappalyzer_integration: WappalyzerIntegration
    ) -> None:
        """Test parsing returns None on unexpected exceptions during processing."""
        # Use valid data that would normally parse
        mock_result = ExecutionResult("cmd", 0, MOCK_SUCCESS_OUTPUT_DICT, "", False)

        # Patch json.loads to return a special dict-like object that fails on .get('version')
        original_data = json.loads(MOCK_SUCCESS_OUTPUT_DICT)

        class FaultyDictAccessMock:
            def __init__(self, data: dict) -> None:
                self._data = data

            def get(self, key: str, default: Any = None) -> Any:
                if key == "technologies": # Return a list containing a faulty mock
                    return [FaultyTechDetailsMock(tech) for tech in self._data.get(key, [])]
                return self._data.get(key, default)

            # Make it behave like a dict for isinstance checks if needed
            def __iter__(self): return iter(self._data)
            def keys(self): return self._data.keys()
            # Add other dict methods if required by the parser's checks

        class FaultyTechDetailsMock:
            def __init__(self, data: dict) -> None:
                self._data = data

            def get(self, key: str, default: Any = None) -> Any:
                if key == "version":
                     raise TypeError("Simulated unexpected access issue")
                return self._data.get(key, default)

            # Make it behave like a dict for isinstance checks
            def __iter__(self): return iter(self._data)
            def keys(self): return self._data.keys()
            # Add other dict methods if required by the parser's checks

        def mock_loads(*args, **kwargs):
            # Return our custom faulty mock object instead of a real dict
            return FaultyDictAccessMock(original_data)

        # Patch json.loads within the wappalyzer module
        with patch("src.integrations.wappalyzer.json.loads", side_effect=mock_loads):
            # The exception should be caught by the broad except block in parse_output
             assert wappalyzer_integration.parse_output(mock_result) is None
