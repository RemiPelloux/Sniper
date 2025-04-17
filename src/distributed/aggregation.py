"""
Result Aggregation Module for Sniper Security Tool Distributed Scanning Architecture.

This module provides functionality to combine and aggregate results from multiple
distributed scanning nodes to create comprehensive, consolidated reports.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import pandas as pd

from src.results.normalizer import ResultNormalizer
from src.results.types import BaseFinding, ScanResult

logger = logging.getLogger(__name__)


class ResultAggregator:
    """Class for aggregating results from distributed scans."""

    def __init__(self, output_dir: str = "./results"):
        """Initialize the result aggregator.

        Args:
            output_dir: Directory to store aggregated results.
        """
        self.output_dir = output_dir
        self.result_normalizer = ResultNormalizer()
        os.makedirs(output_dir, exist_ok=True)

    def aggregate_scan_results(
        self, scan_id: str, results: List[ScanResult]
    ) -> ScanResult:
        """Aggregate results from multiple scan results into a single result.

        Args:
            scan_id: ID of the scan.
            results: List of scan results to aggregate.

        Returns:
            Aggregated scan result.
        """
        if not results:
            logger.warning(f"No results to aggregate for scan {scan_id}")
            return ScanResult(
                scan_id=scan_id,
                target="",
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc),
                findings=[],
                raw_results={},
                metadata={"aggregated": True, "result_count": 0},
            )

        # Initialize the aggregated result with basic information
        target = results[0].target
        start_time = min(result.start_time for result in results)
        end_time = max(result.end_time for result in results)

        # Combine findings, avoiding duplicates
        all_findings: List[BaseFinding] = []
        unique_findings: Set[str] = set()

        for result in results:
            for finding in result.findings:
                # Create a unique identifier for each finding to avoid duplicates
                finding_key = f"{finding.source_tool}:{finding.title}:{finding.target}"

                if finding_key not in unique_findings:
                    unique_findings.add(finding_key)
                    all_findings.append(finding)

        # Combine raw results
        raw_results: Dict[str, Any] = {}
        for result in results:
            for tool, tool_results in result.raw_results.items():
                if tool not in raw_results:
                    raw_results[tool] = []

                # Add tool results to the combined results
                if isinstance(tool_results, list):
                    raw_results[tool].extend(tool_results)
                elif isinstance(tool_results, dict):
                    if not raw_results[tool]:
                        raw_results[tool] = {}
                    raw_results[tool].update(tool_results)
                else:
                    raw_results[tool] = tool_results

        # Create metadata with aggregation information
        metadata = {
            "aggregated": True,
            "result_count": len(results),
            "node_ids": [
                result.metadata.get("node_id", "unknown")
                for result in results
                if result.metadata
            ],
            "aggregation_time": datetime.now(timezone.utc).isoformat(),
        }

        # Create the aggregated result
        aggregated_result = ScanResult(
            scan_id=scan_id,
            target=target,
            start_time=start_time,
            end_time=end_time,
            findings=all_findings,
            raw_results=raw_results,
            metadata=metadata,
        )

        # Save the aggregated result to a file
        self._save_aggregated_result(scan_id, aggregated_result)

        return aggregated_result

    def deduplicate_findings(self, findings: List[BaseFinding]) -> List[BaseFinding]:
        """Deduplicate findings based on similarity.

        Args:
            findings: List of findings to deduplicate.

        Returns:
            Deduplicated list of findings.
        """
        if not findings:
            return []

        # Convert findings to DataFrame for easier processing
        findings_data = []
        for finding in findings:
            findings_data.append(
                {
                    "tool": finding.source_tool,
                    "title": finding.title,
                    "description": finding.description,
                    "target": finding.target,
                    "severity": finding.severity,
                    "confidence": getattr(
                        finding, "confidence", 0.5
                    ),  # Use 0.5 as default if not present
                    "finding_object": finding,
                }
            )

        df = pd.DataFrame(findings_data)

        # Group by tool, title, and target to find duplicates
        grouped = df.groupby(["tool", "title", "target"])

        # Keep the finding with highest severity and confidence from each group
        deduplicated = []
        for _, group in grouped:
            if len(group) == 1:
                # Only one finding in the group, no need to deduplicate
                deduplicated.append(group.iloc[0]["finding_object"])
            else:
                # Multiple findings in the group, keep the one with highest severity
                severity_order = {
                    "Critical": 4,
                    "High": 3,
                    "Medium": 2,
                    "Low": 1,
                    "Info": 0,
                    # Handle enum values directly
                    "FindingSeverity.CRITICAL": 4,
                    "FindingSeverity.HIGH": 3,
                    "FindingSeverity.MEDIUM": 2,
                    "FindingSeverity.LOW": 1,
                    "FindingSeverity.INFO": 0,
                }

                # Get the string representation of the severity and extract the value part
                # This handles both string representations and FindingSeverity enum values
                group["severity_value"] = group["severity"].apply(
                    lambda s: severity_order.get(str(s), 0)
                )

                # Sort by severity (descending) and confidence (descending)
                group = group.sort_values(
                    ["severity_value", "confidence"], ascending=[False, False]
                )

                # Keep the first one (highest severity and confidence)
                deduplicated.append(group.iloc[0]["finding_object"])

        return deduplicated

    def generate_statistics(self, aggregated_result: ScanResult) -> Dict[str, Any]:
        """Generate statistics from an aggregated scan result.

        Args:
            aggregated_result: The aggregated scan result.

        Returns:
            Dictionary with statistics about the scan.
        """
        if not aggregated_result.findings:
            return {
                "total_findings": 0,
                "severity_counts": {},
                "finding_type_counts": {},
                "scan_duration_seconds": 0,
            }

        # Count findings by severity
        severity_counts = {}
        for finding in aggregated_result.findings:
            # Extract severity name from enum value
            if hasattr(finding.severity, "value"):
                severity = finding.severity.value
            else:
                severity = str(finding.severity)

            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Count findings by source tool (as type)
        finding_type_counts = {}
        for finding in aggregated_result.findings:
            finding_type = finding.source_tool
            finding_type_counts[finding_type] = (
                finding_type_counts.get(finding_type, 0) + 1
            )

        # Calculate scan duration
        if aggregated_result.start_time and aggregated_result.end_time:
            scan_duration = (
                aggregated_result.end_time - aggregated_result.start_time
            ).total_seconds()
        else:
            scan_duration = 0

        # Create statistics dictionary
        statistics = {
            "total_findings": len(aggregated_result.findings),
            "severity_counts": severity_counts,
            "finding_type_counts": finding_type_counts,
            "scan_duration_seconds": scan_duration,
            "aggregated_from_nodes": (
                aggregated_result.metadata.get("node_ids", [])
                if aggregated_result.metadata
                else []
            ),
        }

        return statistics

    def _save_aggregated_result(self, scan_id: str, result: ScanResult) -> str:
        """Save the aggregated result to a file.

        Args:
            scan_id: ID of the scan.
            result: Aggregated scan result to save.

        Returns:
            Path to the saved file.
        """
        # Create a filename with the scan ID and timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{scan_id}_{timestamp}_aggregated.json"
        filepath = os.path.join(self.output_dir, filename)

        # Convert the result to a JSON-serializable dictionary
        result_dict = {
            "scan_id": result.scan_id,
            "target": result.target,
            "start_time": result.start_time.isoformat() if result.start_time else None,
            "end_time": result.end_time.isoformat() if result.end_time else None,
            "findings": [finding.model_dump() for finding in result.findings],
            "raw_results": result.raw_results,
            "metadata": result.metadata,
        }

        # Save the result to a JSON file
        with open(filepath, "w") as f:
            json.dump(result_dict, f, indent=2)

        logger.info(f"Saved aggregated result to {filepath}")

        return filepath
