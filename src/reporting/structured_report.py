"""
Structured Report Generator Module

This module creates a well-organized reporting structure with:
1. A main folder named after the normalized target (domain/IP)
2. Separate sub-folders for each finding category
3. JSON and HTML reports for each category
4. A main summary report at the root level
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from urllib.parse import urlparse
import re
import shutil

import markdown2
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.results.types import BaseFinding, FindingSeverity

logger = logging.getLogger(__name__)

# Define category structure and display names
CATEGORIES = {
    "critical": "Critical Vulnerabilities",
    "high": "High-Risk Vulnerabilities",
    "medium": "Medium-Risk Vulnerabilities",
    "low": "Low-Risk Vulnerabilities",
    "info": "Informational Findings",
    "technologies": "Detected Technologies",
    "services": "Discovered Services",
    "ports": "Open Ports",
    "subdomains": "Discovered Subdomains",
    "endpoints": "Web Endpoints",
    "assets": "Digital Assets",
    "prioritized_urls": "Prioritized URLs",
    "performance": "Performance Issues"
}

class StructuredReportGenerator:
    """
    Generates a structured report organized in folders by vulnerability category
    with a main summary at the root level.
    """
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the structured report generator.
        
        Args:
            output_dir: Base directory for all reports
        """
        self.output_dir = output_dir
        self.templates_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.templates_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
    def normalize_target_name(self, target: str) -> str:
        """
        Normalize the target name to use as a directory name.
        
        Args:
            target: Target URL or IP
            
        Returns:
            Normalized string usable as a directory name
        """
        # Handle URLs
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.netloc
        
        # Remove any port numbers
        target = re.sub(r':\d+', '', target)
        
        # Replace invalid characters with underscores
        target = re.sub(r'[^\w\-\.]', '_', target)
        
        # Convert to lowercase for consistency
        return target.lower()
    
    def create_target_directory(self, target: str) -> str:
        """
        Creates a directory for the target.
        
        Args:
            target: Target URL or IP
            
        Returns:
            Path to the created directory
        """
        normalized_target = self.normalize_target_name(target)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_dir = os.path.join(self.output_dir, f"{normalized_target}_{timestamp}")
        
        # Create the directory if it doesn't exist
        os.makedirs(target_dir, exist_ok=True)
        logger.info(f"Created target directory: {target_dir}")
        
        return target_dir
    
    def create_category_directories(self, target_dir: str, categories: List[str]) -> Dict[str, str]:
        """
        Creates subdirectories for each category.
        
        Args:
            target_dir: Target directory path
            categories: List of categories to create directories for
            
        Returns:
            Dictionary mapping category names to their directory paths
        """
        category_dirs = {}
        
        for category in categories:
            category_normalized = category.lower().replace(' ', '_')
            category_dir = os.path.join(target_dir, category_normalized)
            os.makedirs(category_dir, exist_ok=True)
            category_dirs[category] = category_dir
        
        logger.info(f"Created {len(categories)} category directories")
        return category_dirs
    
    def save_finding_to_file(self, finding: Dict[str, Any], category_dir: str, index: int) -> str:
        """
        Saves a finding to a JSON file in the appropriate category directory.
        
        Args:
            finding: Finding data dictionary
            category_dir: Path to the category directory
            index: Index number for the finding
            
        Returns:
            Path to the saved file
        """
        # Generate a filename based on the finding details
        filename = f"finding_{index:03d}.json"
        filepath = os.path.join(category_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(finding, f, indent=2)
        
        return filepath
    
    def categorize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Categorizes findings by severity or explicit category.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Dictionary mapping categories to lists of findings
        """
        categorized = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        
        # Add custom categories as they appear in findings
        for finding in findings:
            # Use the severity as the primary category if available
            if "severity" in finding and finding["severity"]:
                category = finding["severity"].lower()
                if category not in categorized:
                    categorized[category] = []
                categorized[category].append(finding)
            # Fall back to explicit category if available
            elif "category" in finding and finding["category"]:
                category = finding["category"].lower()
                if category not in categorized:
                    categorized[category] = []
                categorized[category].append(finding)
            # Use "info" as a fallback
            else:
                categorized["info"].append(finding)
        
        # Remove empty categories
        return {k: v for k, v in categorized.items() if v}
    
    def generate_category_report(self, 
                               category: str, 
                               findings: List[Dict[str, Any]], 
                               target_dir: str,
                               target: str) -> str:
        """
        Generates an HTML report for a specific category.
        
        Args:
            category: Category name
            findings: List of findings for this category
            target_dir: Target directory path
            target: Target URL or IP
            
        Returns:
            Path to the generated HTML file
        """
        template = self.env.get_template("category_report.html")
        output_file = os.path.join(target_dir, category.lower().replace(' ', '_'), "index.html")
        
        html_content = template.render(
            category=category,
            findings=findings,
            target=target,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        with open(output_file, "w") as f:
            f.write(html_content)
        
        return output_file
    
    def generate_main_report(self, 
                          categories: Dict[str, List[Dict[str, Any]]], 
                          target_dir: str,
                          target: str) -> str:
        """
        Generates the main HTML report that links to all category reports.
        
        Args:
            categories: Dictionary mapping categories to lists of findings
            target_dir: Target directory path
            target: Target URL or IP
            
        Returns:
            Path to the generated HTML file
        """
        template = self.env.get_template("main_report.html")
        output_file = os.path.join(target_dir, "index.html")
        
        # Count total findings and findings by severity
        total_findings = sum(len(findings) for findings in categories.values())
        counts = {category: len(findings) for category, findings in categories.items()}
        
        html_content = template.render(
            categories=categories,
            target=target,
            total_findings=total_findings,
            counts=counts,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        with open(output_file, "w") as f:
            f.write(html_content)
        
        return output_file
    
    def copy_static_assets(self, target_dir: str) -> None:
        """
        Copies static assets (CSS, JS, images) to the target directory.
        
        Args:
            target_dir: Target directory path
        """
        static_dir = os.path.join(self.templates_dir, "static")
        if os.path.exists(static_dir):
            target_static_dir = os.path.join(target_dir, "static")
            if os.path.exists(target_static_dir):
                shutil.rmtree(target_static_dir)
            shutil.copytree(static_dir, target_static_dir)
            logger.info(f"Copied static assets to {target_static_dir}")
    
    def generate_report(self, findings: List[Dict[str, Any]], target: str) -> str:
        """
        Generates a complete structured report with categories and summary.
        
        Args:
            findings: List of all finding dictionaries
            target: Target URL or IP
            
        Returns:
            Path to the main report HTML file
        """
        # Create the target directory
        target_dir = self.create_target_directory(target)
        
        # Categorize findings
        categorized_findings = self.categorize_findings(findings)
        
        # Create category directories
        category_dirs = self.create_category_directories(
            target_dir, 
            list(categorized_findings.keys())
        )
        
        # Save findings to files and generate category reports
        for category, category_findings in categorized_findings.items():
            for i, finding in enumerate(category_findings):
                self.save_finding_to_file(
                    finding, 
                    os.path.join(target_dir, category.lower().replace(' ', '_')), 
                    i+1
                )
            
            self.generate_category_report(
                category,
                category_findings,
                target_dir,
                target
            )
        
        # Copy static assets if they exist
        self.copy_static_assets(target_dir)
        
        # Generate main report
        main_report_path = self.generate_main_report(
            categorized_findings,
            target_dir,
            target
        )
        
        logger.info(f"Generated structured report at {main_report_path}")
        return main_report_path


# For standalone testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Sample findings for testing
    sample_findings = [
        {
            "name": "SQL Injection",
            "url": "https://example.com/search?q=test",
            "severity": "critical",
            "description": "SQL Injection vulnerability found in the search parameter.",
            "evidence": "Error: unterminated quoted string at or near \"''\"",
            "remediation": "Use prepared statements and input validation.",
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
        },
        {
            "name": "Cross-Site Scripting (XSS)",
            "url": "https://example.com/profile?name=test",
            "severity": "high",
            "description": "Reflected XSS vulnerability found in the name parameter.",
            "evidence": "<script>alert('XSS')</script>",
            "remediation": "Implement proper output encoding and CSP.",
            "references": ["https://owasp.org/www-community/attacks/xss/"]
        }
    ]
    
    generator = StructuredReportGenerator()
    report_path = generator.generate_report(sample_findings, "https://example.com")
    print(f"Test report generated at: {report_path}") 