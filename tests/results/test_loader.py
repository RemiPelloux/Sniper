"""
Tests for the findings loader module.
"""

import os
import json
import tempfile
import pytest
from pathlib import Path

from src.results.loader import (
    load_findings,
    save_findings,
    _parse_findings_list,
    _create_port_finding,
    _create_web_finding,
    _create_subdomain_finding,
    _create_technology_finding
)
from src.results.types import (
    BaseFinding,
    PortFinding,
    WebFinding,
    SubdomainFinding,
    TechnologyFinding,
    FindingSeverity
)


@pytest.fixture
def sample_findings_file():
    """Create a temporary file with sample findings data."""
    findings = [
        {
            "title": "SQL Injection",
            "description": "SQL Injection vulnerability in login form",
            "severity": "High",
            "target": "http://example.com/login",
            "source_tool": "test-tool",
            "finding_type": "web",
            "url": "http://example.com/login"
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
            "service": "SSH"
        }
    ]
    
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp:
        json.dump(findings, temp)
        temp_path = temp.name
    
    yield temp_path
    
    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


class TestFindingsLoader:
    """Test the findings loader functionality."""
    
    def test_load_findings(self, sample_findings_file):
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
    
    def test_load_nonexistent_file(self):
        """Test loading from a non-existent file."""
        # Should return empty list for non-existent file
        assert load_findings("nonexistent_file.json") == []
    
    def test_save_findings(self):
        """Test saving findings to a file."""
        findings = [
            BaseFinding(
                title="Test Finding",
                description="Test Description",
                severity=FindingSeverity.MEDIUM,
                target="example.com",
                source_tool="test"
            )
        ]
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp:
            output_path = temp.name
        
        try:
            # Save findings
            result = save_findings(findings, output_path)
            assert result is True
            
            # Verify file exists and contains correct data
            assert os.path.exists(output_path)
            
            with open(output_path) as f:
                data = json.load(f)
                
            assert len(data) == 1
            assert data[0]["title"] == "Test Finding"
            assert data[0]["severity"] == "Medium"  # Enum value as string
        finally:
            # Cleanup
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def test_parse_findings_list(self):
        """Test parsing a list of findings."""
        data = [
            {
                "title": "Web Finding",
                "description": "Test web finding",
                "severity": "High",
                "target": "example.com",
                "source_tool": "test",
                "finding_type": "web",
                "url": "http://example.com"
            },
            {
                "title": "Port Finding",
                "description": "Test port finding",
                "severity": "Low",
                "target": "example.com",
                "source_tool": "test",
                "finding_type": "port",
                "port": 80,
                "protocol": "tcp"
            }
        ]
        
        findings = _parse_findings_list(data)
        
        assert len(findings) == 2
        assert isinstance(findings[0], WebFinding)
        assert isinstance(findings[1], PortFinding)
    
    def test_create_finding_by_type(self):
        """Test creating findings of different types."""
        # Test port finding creation
        port_data = {
            "title": "Port Finding",
            "severity": "Low",
            "target": "example.com",
            "source_tool": "test",
            "port": 80,
            "protocol": "tcp"
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
            "url": "http://example.com"
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
            "resolved_ip": "192.168.1.1"
        }
        subdomain_finding = _create_subdomain_finding(subdomain_data)
        assert isinstance(subdomain_finding, SubdomainFinding)
        assert subdomain_finding.subdomain == "sub.example.com"
        assert subdomain_finding.resolved_ip == "192.168.1.1"
        
        # Test technology finding creation
        tech_data = {
            "title": "Technology Finding",
            "severity": "Info",
            "target": "example.com",
            "source_tool": "test",
            "technology": "Apache",
            "version": "2.4.41"
        }
        tech_finding = _create_technology_finding(tech_data)
        assert isinstance(tech_finding, TechnologyFinding)
        assert tech_finding.technology == "Apache"
        assert tech_finding.version == "2.4.41"
        
    def test_load_different_json_formats(self):
        """Test loading findings from different JSON formats."""
        # Single finding
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp:
            json.dump({
                "title": "Single Finding",
                "description": "Test",
                "severity": "High",
                "target": "example.com",
                "source_tool": "test"
            }, temp)
            single_file = temp.name
        
        # Object with findings array
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp:
            json.dump({
                "findings": [
                    {
                        "title": "Finding in Array",
                        "description": "Test",
                        "severity": "Medium",
                        "target": "example.com",
                        "source_tool": "test"
                    }
                ]
            }, temp)
            array_file = temp.name
        
        # Target-grouped findings
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp:
            json.dump({
                "example.com": [
                    {
                        "title": "Grouped Finding",
                        "description": "Test",
                        "severity": "Low",
                        "target": "example.com",
                        "source_tool": "test"
                    }
                ]
            }, temp)
            grouped_file = temp.name
        
        try:
            # Test loading single finding
            single_findings = load_findings(single_file)
            assert len(single_findings) == 1
            assert single_findings[0].title == "Single Finding"
            
            # Test loading findings array
            array_findings = load_findings(array_file)
            assert len(array_findings) == 1
            assert array_findings[0].title == "Finding in Array"
            
            # Test loading grouped findings
            grouped_findings = load_findings(grouped_file)
            assert len(grouped_findings) == 1
            assert grouped_findings[0].title == "Grouped Finding"
            
        finally:
            # Cleanup
            for file in [single_file, array_file, grouped_file]:
                if os.path.exists(file):
                    os.unlink(file)
    
    def test_unsupported_file_format(self):
        """Test loading from an unsupported file format."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as temp:
            temp.write(b"This is not JSON")
            txt_file = temp.name
        
        try:
            # Should return empty list for unsupported format
            assert load_findings(txt_file) == []
        finally:
            if os.path.exists(txt_file):
                os.unlink(txt_file) 