"""Tests for the report generation CLI module."""

import os
import json
import tempfile
import pytest
from typer.testing import CliRunner
from unittest.mock import patch

from src.cli.report import app, ReportFormat, ReportTemplate


runner = CliRunner()


def test_report_help():
    """Test the help output for the report command."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Generate and manage scan reports" in result.stdout


def test_generate_report_missing_input():
    """Test that generate report requires an input file argument."""
    result = runner.invoke(app, ["generate"])
    assert result.exit_code != 0
    assert "Missing argument" in result.stdout


def test_report_format_enum():
    """Test that ReportFormat enum has the expected values."""
    assert ReportFormat.MARKDOWN.value == "markdown"
    assert ReportFormat.HTML.value == "html"
    assert ReportFormat.JSON.value == "json"
    assert ReportFormat.ALL.value == "all"


def test_report_template_enum():
    """Test that ReportTemplate enum has the expected values."""
    assert ReportTemplate.STANDARD.value == "standard"
    assert ReportTemplate.EXECUTIVE.value == "executive"
    assert ReportTemplate.DETAILED.value == "detailed"


def test_list_templates():
    """Test the list-templates command."""
    result = runner.invoke(app, ["list-templates"])
    assert result.exit_code == 0
    assert "Available Report Templates" in result.stdout
    assert "standard" in result.stdout
    assert "executive" in result.stdout
    assert "detailed" in result.stdout


def test_list_formats():
    """Test the formats command."""
    result = runner.invoke(app, ["formats"])
    assert result.exit_code == 0
    assert "Available Report Formats" in result.stdout
    assert "markdown" in result.stdout
    assert "html" in result.stdout
    assert "json" in result.stdout


def test_generate_report():
    """Test generating a report from input."""
    # Create a temporary file path
    temp_fd, temp_filename = tempfile.mkstemp(suffix=".json")
    os.close(temp_fd)
    
    try:
        # Write scan data to the file
        scan_data = {
            "scan_metadata": {
                "target": "https://example.com",
                "timestamp": "2023-04-01T12:00:00Z",
                "scan_duration": "00:10:15",
                "tools_used": ["nmap", "zap"]
            },
            "findings": []
        }
        with open(temp_filename, 'w') as f:
            json.dump(scan_data, f)
        
        # Create a temporary output directory
        with tempfile.TemporaryDirectory() as temp_dir:
            result = runner.invoke(
                app, 
                [
                    "generate", 
                    temp_filename,
                    "--output-dir", temp_dir,
                    "--format", "json"
                ]
            )
            
            # Check command execution
            assert result.exit_code == 0
            assert "Report generation complete" in result.stdout
            
            # Check that output file was created
            output_files = os.listdir(temp_dir)
            assert len(output_files) == 1
            assert output_files[0].endswith(".json")
            
            # Verify content of output file
            with open(os.path.join(temp_dir, output_files[0]), "r") as f:
                report_data = json.load(f)
                assert "scan_metadata" in report_data
                assert report_data["scan_metadata"]["target"] == "https://example.com"
    finally:
        # Clean up the temp file
        os.unlink(temp_filename)


def test_generate_report_multiple_formats():
    """Test generating reports in multiple formats."""
    # Create a temporary file path
    temp_fd, temp_filename = tempfile.mkstemp(suffix=".json")
    os.close(temp_fd)
    
    try:
        # Write scan data to the file
        scan_data = {
            "scan_metadata": {
                "target": "https://example.com",
                "timestamp": "2023-04-01T12:00:00Z"
            },
            "findings": []
        }
        with open(temp_filename, 'w') as f:
            json.dump(scan_data, f)
        
        # Create a temporary output directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Use separate invocations for each format
            # First markdown
            md_result = runner.invoke(
                app, 
                [
                    "generate", 
                    temp_filename,
                    "--output-dir", temp_dir,
                    "--format", "markdown"
                ]
            )
            
            # Then HTML
            html_result = runner.invoke(
                app, 
                [
                    "generate", 
                    temp_filename,
                    "--output-dir", temp_dir,
                    "--format", "html"
                ]
            )
            
            # Check command execution
            assert md_result.exit_code == 0
            assert html_result.exit_code == 0
            
            # Check that output files were created
            output_files = os.listdir(temp_dir)
            assert len(output_files) == 2
            
            # Check file extensions
            extensions = [os.path.splitext(f)[1] for f in output_files]
            assert ".md" in extensions or ".markdown" in extensions
            assert ".html" in extensions
    finally:
        # Clean up the temp file
        if os.path.exists(temp_filename):
            os.unlink(temp_filename)


def test_generate_report_nonexistent_input():
    """Test error handling for nonexistent input file."""
    result = runner.invoke(
        app, 
        [
            "generate", 
            "nonexistent_file.json",
            "--format", "markdown"
        ]
    )
    
    # Command should fail
    assert result.exit_code != 0
    assert "not found" in result.stdout 