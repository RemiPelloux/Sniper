"""
Results Loader Module

This module provides functions for loading security findings from various file formats.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.results.types import (
    BaseFinding,
    FindingSeverity,
    PortFinding,
    SubdomainFinding,
    TechnologyFinding,
    WebFinding,
)

logger = logging.getLogger(__name__)


def load_findings(findings_file: Union[str, Path]) -> List[BaseFinding]:
    """
    Load security findings from a file.

    This function loads findings from JSON files and automatically
    converts them to the appropriate BaseFinding subclass based on
    the structure of the data.

    Args:
        findings_file: Path to a JSON file containing security findings

    Returns:
        List of BaseFinding objects
    """
    findings_file = Path(findings_file)
    if not findings_file.exists():
        logger.error(f"Findings file not found: {findings_file}")
        return []

    # Support different file extensions
    if findings_file.suffix.lower() == ".json":
        return _load_from_json(findings_file)
    else:
        logger.error(f"Unsupported file format: {findings_file.suffix}")
        return []


def _load_from_json(file_path: Path) -> List[BaseFinding]:
    """
    Load findings from a JSON file.

    Args:
        file_path: Path to the JSON file

    Returns:
        List of BaseFinding objects
    """
    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        # Handle different JSON formats
        if isinstance(data, list):
            # List of findings
            return _parse_findings_list(data)
        elif isinstance(data, dict) and "findings" in data:
            # Object with findings array
            return _parse_findings_list(data["findings"])
        elif isinstance(data, dict):
            # Could be a single finding or another format
            if all(k in data for k in ["title", "description", "severity", "target"]):
                # Looks like a single finding
                return _parse_findings_list([data])
            else:
                # Try to handle other formats or target-grouped findings
                findings: List[BaseFinding] = []
                for target, target_findings in data.items():
                    if isinstance(target_findings, list):
                        # Target-grouped findings
                        parsed = _parse_findings_list(target_findings)
                        # Ensure target is set correctly
                        for finding in parsed:
                            finding.target = target
                        findings.extend(parsed)
                return findings

        # Return empty list for unsupported data format
        return []
    except Exception as e:
        logger.error(f"Error loading findings from {file_path}: {str(e)}")
        return []


def _parse_findings_list(data_list: List[Dict[str, Any]]) -> List[BaseFinding]:
    """
    Parse a list of finding dictionaries into BaseFinding objects.

    Args:
        data_list: List of dictionaries with finding data

    Returns:
        List of BaseFinding objects
    """
    findings: List[BaseFinding] = []

    for item in data_list:
        try:
            # Determine the finding type
            finding_type = item.get("finding_type", "").lower()

            # Create the appropriate finding object based on type
            if finding_type == "port" or "port" in item:
                finding: BaseFinding = _create_port_finding(item)
            elif finding_type == "web" or "url" in item:
                finding = _create_web_finding(item)
            elif finding_type == "subdomain" or "subdomain" in item:
                finding = _create_subdomain_finding(item)
            elif finding_type == "technology" or "technology" in item:
                finding = _create_technology_finding(item)
            else:
                finding = BaseFinding(**item)

            findings.append(finding)
        except Exception as e:
            logger.warning(f"Error parsing finding: {str(e)}")
            continue

    return findings


def _create_port_finding(data: Dict[str, Any]) -> PortFinding:
    """Create a PortFinding from dictionary data."""
    # Extract port-specific fields
    port = data.get("port")
    protocol = data.get("protocol", "tcp")
    service = data.get("service")
    banner = data.get("banner")

    # Create base fields if not present
    if "title" not in data:
        data["title"] = f"Open port {port}/{protocol}" + (
            f" ({service})" if service else ""
        )

    if "description" not in data:
        data["description"] = f"Port {port}/{protocol} is open" + (
            f", running {service}" if service else ""
        )

    # Create the finding
    return PortFinding(
        port=port,
        protocol=protocol,
        service=service,
        banner=banner,
        **{
            k: v
            for k, v in data.items()
            if k not in ["port", "protocol", "service", "banner"]
        },
    )


def _create_web_finding(data: Dict[str, Any]) -> WebFinding:
    """Create a WebFinding from dictionary data."""
    # Extract web-specific fields
    url = data.get("url", data.get("target", ""))
    method = data.get("method")
    parameter = data.get("parameter")
    status_code = data.get("status_code")

    # Create base fields if not present
    if "title" not in data:
        title_parts = ["Web Finding"]
        if status_code:
            title_parts.append(f"(Status: {status_code})")
        data["title"] = " ".join(title_parts)

    if "description" not in data:
        description_parts = [f"A web finding was discovered at {url}"]
        if method:
            description_parts.append(f"using {method}")
        if parameter:
            description_parts.append(f"with parameter {parameter}")
        data["description"] = " ".join(description_parts)

    # Create the finding
    return WebFinding(
        url=url,
        method=method,
        parameter=parameter,
        status_code=status_code,
        **{
            k: v
            for k, v in data.items()
            if k not in ["url", "method", "parameter", "status_code"]
        },
    )


def _create_subdomain_finding(data: Dict[str, Any]) -> SubdomainFinding:
    """Create a SubdomainFinding from dictionary data."""
    # Extract subdomain-specific fields
    subdomain = data.get("subdomain", data.get("target", ""))

    # Get resolved_ip for description only (not a model field)
    resolved_ip = data.get("resolved_ip")

    # Create base fields if not present
    if "title" not in data:
        data["title"] = f"Discovered subdomain: {subdomain}"

    if "description" not in data:
        data["description"] = f"Subdomain {subdomain} was discovered" + (
            f", resolving to {resolved_ip}" if resolved_ip else ""
        )

    # Create the finding - exclude resolved_ip as it's not part of the model
    return SubdomainFinding(
        subdomain=subdomain,
        **{k: v for k, v in data.items() if k not in ["subdomain", "resolved_ip"]},
    )


def _create_technology_finding(data: Dict[str, Any]) -> TechnologyFinding:
    """Create a TechnologyFinding from dictionary data."""
    # Extract technology-specific fields
    technology_name = data.get(
        "technology_name", data.get("technology", data.get("name", ""))
    )
    version = data.get("version")
    categories = data.get("categories", [])

    # Create base fields if not present
    if "title" not in data:
        data["title"] = f"Detected {technology_name}" + (
            f" {version}" if version else ""
        )

    if "description" not in data:
        data["description"] = (
            f"Technology {technology_name}"
            + (f" version {version}" if version else "")
            + " was detected on the target"
        )

    # Create the finding
    return TechnologyFinding(
        technology_name=technology_name,
        version=version,
        categories=categories,
        **{
            k: v
            for k, v in data.items()
            if k
            not in ["technology_name", "technology", "name", "version", "categories"]
        },
    )


def save_findings(findings: List[BaseFinding], output_file: Union[str, Path]) -> bool:
    """
    Save findings to a file.

    Args:
        findings: List of BaseFinding objects
        output_file: Path to the output file

    Returns:
        True if successful, False otherwise
    """
    output_file = Path(output_file)

    # Create directory if it doesn't exist
    os.makedirs(output_file.parent, exist_ok=True)

    try:
        # Convert findings to dictionaries
        findings_data = [finding.model_dump() for finding in findings]

        # Determine format based on file extension
        if output_file.suffix.lower() == ".json":
            with open(output_file, "w") as f:
                json.dump(findings_data, f, indent=2)
            return True
        else:
            logger.error(f"Unsupported output format: {output_file.suffix}")
            return False

    except Exception as e:
        logger.error(f"Error saving findings to {output_file}: {str(e)}")
        return False
