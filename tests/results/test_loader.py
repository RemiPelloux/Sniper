"""
Tests for the findings loader module.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Generator, List

import pytest

from src.results.loader import (
    _create_port_finding,
    _create_subdomain_finding,
    _create_technology_finding,
    _create_web_finding,
    _parse_findings_list,
    load_findings,
    save_findings,
)
from src.results.types import (
    BaseFinding,
    FindingSeverity,
    PortFinding,
    SubdomainFinding,
    TechnologyFinding,
    WebFinding,
)


@pytest.fixture
def sample_findings_file() -> Generator[str, None, None]:
    """Create a temporary file with sample findings data."""
    findings = [
        {
            "title": "SQL Injection",
            "description": "SQL Injection vulnerability in login form",
            "severity": "High",
            "target": "http://example.com/login",
            "source_tool": "test-tool",
            "finding_type": "web",
            "url": "http://example.com/login",
        },
        {
            "title": "Open Port 22",
            "description": "SSH port open",
            "severity": "Low",
            "target": "example.com",
            "source_tool": "test-tool",
            "finding_type": "port",
            "port": 22,
            "protocol": "tcp",
            "service": "SSH",
        },
    ]

    # Create a temporary file path
    fd, temp_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    # Write JSON data in text mode
    with open(temp_path, "w", encoding="utf-8") as temp:
        json.dump(findings, temp)

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


class TestFindingsLoader:
    """Test the findings loader functionality."""

    def test_load_findings(self, sample_findings_file: str) -> None:
        """Test loading findings from a JSON file."""
        findings = load_findings(sample_findings_file)

        assert len(findings) == 2

        # Check first finding (web)
        assert findings[0].title == "SQL Injection"
        assert findings[0].severity == "High"
        assert findings[0].target == "http://example.com/login"
        assert isinstance(findings[0], WebFinding)
        assert findings[0].url == "http://example.com/login"

        # Check second finding (port)
        assert findings[1].title == "Open Port 22"
        assert findings[1].severity == "Low"
        assert findings[1].target == "example.com"
        assert isinstance(findings[1], PortFinding)
        assert findings[1].port == 22
        assert findings[1].protocol == "tcp"
        assert findings[1].service == "SSH"

    def test_load_nonexistent_file(self) -> None:
        """Test loading from a non-existent file."""
        # Should return empty list for non-existent file
        assert load_findings("nonexistent_file.json") == []

    def test_save_findings(self) -> None:
        """Test saving findings to a file."""
        findings = [
            BaseFinding(
                title="Test Finding",
                description="Test Description",
                severity=FindingSeverity.MEDIUM,
                target="example.com",
                source_tool="test",
                raw_evidence=None,
            )
        ]

        # Create a temporary file path
        fd, output_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        try:
            # Save findings
            result = save_findings(findings, output_path)
            assert result is True

            # Verify file exists and contains correct data
            assert os.path.exists(output_path)

            with open(output_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            assert len(data) == 1
            assert data[0]["title"] == "Test Finding"
            assert data[0]["severity"] == "Medium"  # Enum value as string
        finally:
            # Cleanup
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_parse_findings_list(self) -> None:
        """Test parsing a list of findings."""
        data: List[Dict[str, Any]] = [
            {
                "title": "Web Finding",
                "description": "Test web finding",
                "severity": "High",
                "target": "example.com",
                "source_tool": "test",
                "finding_type": "web",
                "url": "http://example.com",
            },
            {
                "title": "Port Finding",
                "description": "Test port finding",
                "severity": "Low",
                "target": "example.com",
                "source_tool": "test",
                "finding_type": "port",
                "port": 80,
                "protocol": "tcp",
            },
        ]

        findings = _parse_findings_list(data)

        assert len(findings) == 2
        assert isinstance(findings[0], WebFinding)
        assert isinstance(findings[1], PortFinding)

    def test_create_finding_by_type(self) -> None:
        """Test creating findings of different types."""
        # Test port finding creation
        port_data = {
            "title": "Port Finding",
            "severity": "Low",
            "target": "example.com",
            "source_tool": "test",
            "port": 80,
            "protocol": "tcp",
        }
        port_finding = _create_port_finding(port_data)
        assert isinstance(port_finding, PortFinding)
        assert port_finding.port == 80
        assert port_finding.protocol == "tcp"

        # Test web finding creation
        web_data = {
            "title": "Web Finding",
            "severity": "High",
            "target": "example.com",
            "source_tool": "test",
            "url": "http://example.com",
        }
        web_finding = _create_web_finding(web_data)
        assert isinstance(web_finding, WebFinding)
        assert web_finding.url == "http://example.com"

        # Test subdomain finding creation
        subdomain_data = {
            "title": "Subdomain Finding",
            "severity": "Medium",
            "target": "example.com",
            "source_tool": "test",
            "subdomain": "sub.example.com",
        }
        subdomain_finding = _create_subdomain_finding(subdomain_data)
        assert isinstance(subdomain_finding, SubdomainFinding)
        assert subdomain_finding.subdomain == "sub.example.com"
        # Check that the description includes useful information despite no resolved_ip
        assert "sub.example.com" in subdomain_finding.description

        # Test technology finding creation
        tech_data = {
            "title": "Technology Finding",
            "severity": "Info",
            "target": "example.com",
            "source_tool": "test",
            "technology_name": "Apache",
            "version": "2.4.41",
        }
        tech_finding = _create_technology_finding(tech_data)
        assert isinstance(tech_finding, TechnologyFinding)
        assert tech_finding.technology_name == "Apache"
        assert tech_finding.version == "2.4.41"

    def test_load_different_json_formats(self) -> None:
        """Test loading findings from different JSON formats."""
        # Single finding
        fd, single_file = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(single_file, "w", encoding="utf-8") as temp:
            json.dump(
                {
                    "title": "Single Finding",
                    "description": "Test",
                    "severity": "High",
                    "target": "example.com",
                    "source_tool": "test",
                },
                temp,
            )

        # Object with findings array
        fd, array_file = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(array_file, "w", encoding="utf-8") as temp:
            json.dump(
                {
                    "findings": [
                        {
                            "title": "Finding in Array",
                            "description": "Test",
                            "severity": "Medium",
                            "target": "example.com",
                            "source_tool": "test",
                        }
                    ]
                },
                temp,
            )

        # Target-grouped findings
        fd, grouped_file = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(grouped_file, "w", encoding="utf-8") as temp:
            json.dump(
                {
                    "target": "example.com",
                    "findings": [
                        {
                            "title": "Grouped Finding",
                            "description": "Test",
                            "severity": "Low",
                            "source_tool": "test",
                            "target": "example.com",
                        }
                    ],
                },
                temp,
            )

        # Invalid JSON
        fd, invalid_file = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(invalid_file, "w", encoding="utf-8") as temp:
            temp.write("This is not valid JSON")

        try:
            # Test single finding
            single_findings = load_findings(single_file)
            assert len(single_findings) == 1
            assert single_findings[0].title == "Single Finding"

            # Test findings array
            array_findings = load_findings(array_file)
            assert len(array_findings) == 1
            assert array_findings[0].title == "Finding in Array"

            # Test grouped findings
            grouped_findings = load_findings(grouped_file)
            assert len(grouped_findings) == 1
            assert grouped_findings[0].title == "Grouped Finding"
            assert grouped_findings[0].target == "example.com"

            # Test invalid JSON
            assert load_findings(invalid_file) == []
        finally:
            # Cleanup
            for file_path in [single_file, array_file, grouped_file, invalid_file]:
                if os.path.exists(file_path):
                    os.unlink(file_path)

    def test_unsupported_file_format(self) -> None:
        """Test loading from an unsupported file format."""
        # Create a temporary file with unsupported extension
        fd, unsupported_file = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        with open(unsupported_file, "w", encoding="utf-8") as temp:
            temp.write('{"title": "Test"}')

        try:
            # Should return empty list for unsupported format
            assert load_findings(unsupported_file) == []
        finally:
            # Cleanup
            if os.path.exists(unsupported_file):
                os.unlink(unsupported_file)

    def test_load_findings_unsupported_format(self, tmp_path: Path) -> None:
        """Test loading from an unsupported file format."""
        unsupported_file = tmp_path / "test.txt"
        assert load_findings(str(unsupported_file)) == []

    # --- JSON Loading Tests ---

    def test_load_from_json_list_success(self, tmp_path: Path) -> None:
        """Test loading a valid JSON list of findings."""
        json_file = tmp_path / "findings.json"

        # Create test data
        findings_data = [
            {
                "title": "Test Finding 1",
                "description": "Test Description 1",
                "severity": "High",
                "target": "example.com",
                "source_tool": "test-tool",
                "finding_type": "web",
                "url": "http://example.com",
                "raw_evidence": {"test": "data"},
            },
            {
                "title": "Test Finding 2",
                "description": "Test Description 2",
                "severity": "Low",
                "target": "example.com",
                "source_tool": "test-tool",
                "finding_type": "port",
                "port": 22,
                "protocol": "tcp",
            },
        ]

        # Ensure the directory exists
        os.makedirs(os.path.dirname(json_file), exist_ok=True)

        # Write the test data to the file
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(findings_data, f)

        # Test loading findings
        findings = load_findings(str(json_file))
        assert len(findings) == 2
        assert isinstance(findings[0].raw_evidence, dict)

    def test_load_from_json_object_success(self, tmp_path: Path) -> None:
        """Test loading a valid JSON object with a 'findings' key."""
        json_file = tmp_path / "findings_obj.json"

        # Create test data
        findings_data = {
            "findings": [
                {
                    "title": "Test Finding 1",
                    "description": "Test Description 1",
                    "severity": "High",
                    "target": "example.com",
                    "source_tool": "test-tool",
                },
                {
                    "title": "Test Finding 2",
                    "description": "Test Description 2",
                    "severity": "Low",
                    "target": "example.com",
                    "source_tool": "test-tool",
                },
            ]
        }

        # Ensure the directory exists
        os.makedirs(os.path.dirname(json_file), exist_ok=True)

        # Write the test data to the file
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(findings_data, f)

        # Test loading findings
        findings = load_findings(str(json_file))
        assert len(findings) == 2
        assert findings[0].severity == FindingSeverity.HIGH

    def test_load_from_json_single_object_success(self, tmp_path: Path) -> None:
        """Test loading a JSON file containing a single finding object."""
        json_file = tmp_path / "single_finding.json"

        # Create test data
        finding_data = {
            "title": "Single Finding",
            "description": "Test Description",
            "severity": "Medium",
            "target": "example.com",
            "source_tool": "test-tool",
        }

        # Ensure the directory exists
        os.makedirs(os.path.dirname(json_file), exist_ok=True)

        # Write the test data to the file
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(finding_data, f)

        # Test loading findings
        findings = load_findings(str(json_file))
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.MEDIUM

    def test_load_from_json_target_grouped_success(self, tmp_path: Path) -> None:
        """Test loading a JSON file with findings grouped by target."""
        json_file = tmp_path / "target_grouped.json"

        # Create test data
        findings_data = {
            "target": "example.com",
            "findings": [
                {
                    "title": "Grouped Finding 1",
                    "description": "Test Description 1",
                    "severity": "Medium",
                    "source_tool": "test-tool",
                    "target": "example.com",
                },
                {
                    "title": "Grouped Finding 2",
                    "description": "Test Description 2",
                    "severity": "Low",
                    "source_tool": "test-tool",
                    "target": "example.com",
                },
            ],
        }

        # Ensure the directory exists
        os.makedirs(os.path.dirname(json_file), exist_ok=True)

        # Write the test data to the file
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(findings_data, f)

        # Test loading findings
        findings = load_findings(str(json_file))
        assert len(findings) == 2
        assert findings[1].severity == FindingSeverity.LOW

    def test_load_from_json_invalid_json(self, tmp_path: Path) -> None:
        """Test loading an invalid JSON file."""
        invalid_json_file = tmp_path / "invalid.json"

        # Ensure the directory exists
        os.makedirs(os.path.dirname(invalid_json_file), exist_ok=True)

        # Write invalid JSON to the file
        with open(invalid_json_file, "w", encoding="utf-8") as f:
            f.write("This is not valid JSON")

        findings = load_findings(str(invalid_json_file))
        assert findings == []

    def test_load_from_json_parsing_error(self, tmp_path: Path) -> None:
        """Test handling errors during parsing of individual findings."""
        json_file = tmp_path / "parsing_error.json"

        # Create test data with one valid and one invalid finding
        findings_data = [
            {
                "title": "Valid Finding",
                "description": "Test Description",
                "severity": "Medium",
                "target": "example.com",
                "source_tool": "test-tool",
            },
            {
                # Missing required fields
                "title": "Invalid Finding"
            },
        ]

        # Ensure the directory exists
        os.makedirs(os.path.dirname(json_file), exist_ok=True)

        # Write the test data to the file
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(findings_data, f)

        findings = load_findings(str(json_file))
        assert len(findings) == 1  # Only the valid finding should be loaded

    # --- Finding Type Parsing Tests ---

    def test_parse_findings_list_types(self) -> None:
        """Test parsing findings into correct BaseFinding subclasses."""
        data_list: List[Dict[str, Any]] = [
            {
                "title": "Web Finding",
                "description": "Test web finding",
                "severity": "High",
                "target": "example.com",
                "source_tool": "test",
                "finding_type": "web",
                "url": "http://example.com",
            },
            {
                "title": "Port Finding",
                "description": "Test port finding",
                "severity": "Low",
                "target": "example.com",
                "source_tool": "test",
                "finding_type": "port",
                "port": 80,
                "protocol": "tcp",
            },
            {
                "title": "Subdomain Finding",
                "description": "Test subdomain finding",
                "severity": "Medium",
                "target": "example.com",
                "source_tool": "test",
                "finding_type": "subdomain",
                "subdomain": "sub.example.com",
            },
            {
                "title": "Technology Finding",
                "description": "Test technology finding",
                "severity": "Info",
                "target": "example.com",
                "source_tool": "test",
                "finding_type": "technology",
                "technology_name": "Apache",
                "version": "2.4.41",
            },
        ]
        findings = _parse_findings_list(data_list)
        assert len(findings) == 4
        assert isinstance(findings[0], WebFinding)
        assert isinstance(findings[1], PortFinding)
        assert isinstance(findings[2], SubdomainFinding)
        assert isinstance(findings[3], TechnologyFinding)

    # --- Saving Findings Tests ---

    def test_save_findings_json_success(self, tmp_path: Path) -> None:
        """Test saving findings to a JSON file."""
        # Create the output directory if it doesn't exist
        output_dir = tmp_path / "output"
        os.makedirs(output_dir, exist_ok=True)

        output_file = output_dir / "saved_findings.json"
        findings = [
            BaseFinding(
                title="Test Finding",
                description="Test Description",
                severity=FindingSeverity.MEDIUM,
                target="example.com",
                source_tool="test",
                raw_evidence=None,
            )
        ]
        result = save_findings(findings, str(output_file))
        assert result is True
        assert os.path.exists(output_file)

        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert len(data) == 1  # Example assertion
            assert data[0]["title"] == "Test Finding"
