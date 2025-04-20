"""
Tests for the Result Aggregation module in the distributed scanning architecture.

This module contains tests for the ResultAggregator class which is responsible
for combining and aggregating results from multiple distributed scanning nodes.
"""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.distributed.aggregation import ResultAggregator
from src.results.types import BaseFinding, FindingSeverity, ScanResult


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        BaseFinding(
            title="SQL Injection",
            description="SQL injection vulnerability found",
            severity=FindingSeverity.HIGH,
            target="example.com",
            source_tool="zap",
            finding_id="finding1",
            finding_type="vulnerability",
            location="/login.php",
            confidence=0.9,
            tool_name="zap",
            references=["https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"],
            remediation="Use prepared statements",
            raw_evidence=None,
        ),
        BaseFinding(
            title="XSS",
            description="Cross-site scripting vulnerability found",
            severity=FindingSeverity.MEDIUM,
            target="example.com",
            source_tool="zap",
            finding_id="finding2",
            finding_type="vulnerability",
            location="/search.php",
            confidence=0.8,
            tool_name="zap",
            references=[
                "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)"
            ],
            remediation="Sanitize input",
            raw_evidence=None,
        ),
        BaseFinding(
            title="Weak TLS",
            description="Weak TLS configuration found",
            severity=FindingSeverity.MEDIUM,
            target="example.com",
            source_tool="nmap",
            finding_id="finding3",
            finding_type="misconfiguration",
            location="example.com:443",
            confidence=0.7,
            tool_name="nmap",
            references=[
                "https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet"
            ],
            remediation="Use strong TLS configurations",
            raw_evidence=None,
        ),
        BaseFinding(
            title="SQL Injection",
            description="Another SQL injection vulnerability",
            severity=FindingSeverity.CRITICAL,
            target="example.com",
            source_tool="manual",
            finding_id="finding4",
            finding_type="vulnerability",
            location="/login.php",
            confidence=0.95,
            tool_name="manual",
            references=["https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"],
            remediation="Use prepared statements",
            raw_evidence=None,
        ),
    ]


@pytest.fixture
def sample_scan_results(sample_findings):
    """Create sample scan results for testing."""
    current_time = datetime.now(timezone.utc)

    # First scan result with 2 findings
    result1 = ScanResult(
        scan_id="scan123",
        target="example.com",
        start_time=current_time - timedelta(minutes=30),
        end_time=current_time - timedelta(minutes=20),
        findings=[sample_findings[0], sample_findings[1]],
        raw_results={"zap": {"alerts": [{"name": "SQL Injection"}, {"name": "XSS"}]}},
        metadata={"node_id": "node1"},
    )

    # Second scan result with 2 findings (one duplicate with higher severity)
    result2 = ScanResult(
        scan_id="scan123",
        target="example.com",
        start_time=current_time - timedelta(minutes=25),
        end_time=current_time - timedelta(minutes=10),
        findings=[sample_findings[2], sample_findings[3]],
        raw_results={"nmap": {"ports": [{"port": 443, "state": "open"}]}},
        metadata={"node_id": "node2"},
    )

    return [result1, result2]


@pytest.fixture
def temp_output_dir():
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestResultAggregator:
    """Tests for the ResultAggregator class."""

    def test_init(self, temp_output_dir):
        """Test ResultAggregator initialization."""
        aggregator = ResultAggregator(output_dir=temp_output_dir)
        assert aggregator.output_dir == temp_output_dir
        assert os.path.exists(temp_output_dir)

    def test_deduplicate_findings(self, sample_findings):
        """Test deduplication of findings."""
        aggregator = ResultAggregator()

        # Create two findings with same source_tool, title, and target
        # but different severities to test deduplication
        finding1 = BaseFinding(
            title="Test Finding",
            description="Test Description",
            severity=FindingSeverity.MEDIUM,
            target="example.com",
            source_tool="test-tool",
            raw_evidence=None,
        )

        finding2 = BaseFinding(
            title="Test Finding",
            description="Test Description with higher severity",
            severity=FindingSeverity.HIGH,
            target="example.com",
            source_tool="test-tool",
            raw_evidence=None,
        )

        # Use findings with the same source_tool, title, and target
        # Finding2 has higher severity and should be kept
        deduplicated = aggregator.deduplicate_findings([finding1, finding2])

        assert len(deduplicated) == 1
        assert deduplicated[0].severity == FindingSeverity.HIGH

    def test_aggregate_scan_results(self, sample_scan_results, temp_output_dir):
        """Test aggregation of scan results."""
        aggregator = ResultAggregator(output_dir=temp_output_dir)

        # Aggregate the sample scan results
        aggregated = aggregator.aggregate_scan_results("scan123", sample_scan_results)

        # Check basic properties
        assert aggregated.scan_id == "scan123"
        assert aggregated.target == "example.com"
        assert aggregated.start_time == sample_scan_results[0].start_time
        assert aggregated.end_time == sample_scan_results[1].end_time

        # Check findings (should have 4 findings since our deduplication is now based on source_tool+title+target)
        assert len(aggregated.findings) == 4

        # Check raw results
        assert "zap" in aggregated.raw_results
        assert "nmap" in aggregated.raw_results

        # Check metadata
        assert aggregated.metadata["aggregated"] is True
        assert aggregated.metadata["result_count"] == 2
        assert "node1" in aggregated.metadata["node_ids"]
        assert "node2" in aggregated.metadata["node_ids"]

    def test_aggregate_empty_results(self, temp_output_dir):
        """Test aggregation of empty scan results."""
        aggregator = ResultAggregator(output_dir=temp_output_dir)

        # Aggregate empty results
        aggregated = aggregator.aggregate_scan_results("empty_scan", [])

        # Check properties
        assert aggregated.scan_id == "empty_scan"
        assert aggregated.target == ""
        assert len(aggregated.findings) == 0
        assert not aggregated.raw_results
        assert aggregated.metadata["aggregated"] is True
        assert aggregated.metadata["result_count"] == 0

    def test_generate_statistics(self, sample_scan_results, temp_output_dir):
        """Test generation of statistics from aggregated results."""
        aggregator = ResultAggregator(output_dir=temp_output_dir)

        # Aggregate the sample scan results
        aggregated = aggregator.aggregate_scan_results("scan123", sample_scan_results)

        # Generate statistics
        stats = aggregator.generate_statistics(aggregated)

        # Check statistics
        assert stats["total_findings"] == 4

        # The severity counts will have the enum values as strings
        severity_counts = stats["severity_counts"]
        assert "High" in severity_counts or "Critical" in severity_counts

        # Check that we have counts for tool names
        finding_type_counts = stats["finding_type_counts"]
        assert "zap" in finding_type_counts
        assert "nmap" in finding_type_counts or "manual" in finding_type_counts

        assert stats["scan_duration_seconds"] > 0
        assert len(stats["aggregated_from_nodes"]) == 2

    def test_save_aggregated_result(self, sample_scan_results, temp_output_dir):
        """Test saving aggregated results to a file."""
        aggregator = ResultAggregator(output_dir=temp_output_dir)

        # Aggregate the sample scan results
        aggregated = aggregator.aggregate_scan_results("scan123", sample_scan_results)

        # Check that a file was created
        files = os.listdir(temp_output_dir)
        assert len(files) == 1

        # Check file content
        file_path = os.path.join(temp_output_dir, files[0])
        with open(file_path, "r") as f:
            saved_data = json.load(f)

        assert saved_data["scan_id"] == "scan123"
        assert saved_data["target"] == "example.com"
        assert len(saved_data["findings"]) == 4
