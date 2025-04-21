import os
import re
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from jinja2 import Environment, FileSystemLoader

from src.core.config import get_templates_dir

logger = logging.getLogger(__name__)

def normalize_target_name(target: str) -> str:
    """Normalize target name to create a valid directory name."""
    # Remove protocol and trailing slashes
    target = re.sub(r'^https?://', '', target)
    target = target.rstrip('/')
    # Replace invalid characters with underscores
    target = re.sub(r'[\\/*?:"<>|]', '_', target)
    # Replace periods and spaces with underscores
    target = re.sub(r'[\.\s]', '_', target)
    return target

def generate_html_report(template_name: str, output_path: str, data: Dict[str, Any]) -> Optional[str]:
    """
    Generate an HTML report using a Jinja2 template.
    
    Args:
        template_name: Name of the template file
        output_path: Path where the report will be saved
        data: Dictionary containing data to be used in the template
    
    Returns:
        Path to the generated report or None if generation failed
    """
    try:
        templates_dir = get_templates_dir()
        env = Environment(loader=FileSystemLoader(templates_dir))
        template = env.get_template(template_name)
        
        # Add current date if not present
        if 'scan_date' not in data:
            data['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
        # Render template with provided data
        rendered_content = template.render(**data)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Write the rendered content to the output file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(rendered_content)
            
        logger.info(f"Report generated successfully at {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Failed to generate report: {str(e)}")
        return None

def generate_structured_report(
    target: str,
    findings: Dict[str, List[Dict[str, Any]]],
    output_dir: str = "reports",
    scan_duration: Optional[str] = None,
    scan_config: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """
    Generate a structured report with categories in separate folders.
    
    Args:
        target: The target URL or IP
        findings: Dictionary with categories as keys and lists of findings as values
        output_dir: Base directory for reports
        scan_duration: Duration of the scan
        scan_config: Configuration used for the scan
        
    Returns:
        Path to the main report file or None if generation failed
    """
    try:
        # Create a normalized target name for the directory
        normalized_target = normalize_target_name(target)
        target_dir = os.path.join(output_dir, normalized_target)
        
        # Ensure the target directory exists
        os.makedirs(target_dir, exist_ok=True)
        
        # Define category mappings
        category_templates = {
            "critical": "category_report.html",
            "high": "category_report.html",
            "medium": "category_report.html",
            "low": "category_report.html",
            "info": "category_report.html",
            "vulnerabilities": "vulnerabilities_report.html",
            "technologies": "technologies_report.html",
            "prioritized_urls": "prioritized_urls_report.html",
            "performance": "performance_report.html"
        }
        
        # Process findings by category
        category_reports = {}
        for category, category_findings in findings.items():
            if not category_findings:
                continue
                
            # Create category directory
            category_dir = os.path.join(target_dir, category)
            os.makedirs(category_dir, exist_ok=True)
            
            # Save individual findings as JSON
            for i, finding in enumerate(category_findings):
                finding_path = os.path.join(category_dir, f"finding_{i+1}.json")
                with open(finding_path, 'w', encoding='utf-8') as f:
                    json.dump(finding, f, indent=2)
            
            # Generate category HTML report if template exists
            if category in category_templates:
                template_name = category_templates[category]
                category_data = {
                    "target": target,
                    "category": category,
                    "findings": category_findings,
                    "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "scan_config": scan_config
                }
                
                category_report_path = os.path.join(category_dir, "index.html")
                report_path = generate_html_report(template_name, category_report_path, category_data)
                if report_path:
                    category_reports[category] = {
                        "count": len(category_findings),
                        "path": os.path.relpath(report_path, target_dir)
                    }
        
        # Calculate vulnerability counts by severity
        critical_count = len(findings.get("critical", []))
        high_count = len(findings.get("high", []))
        medium_count = len(findings.get("medium", []))
        low_count = len(findings.get("low", []))
        info_count = len(findings.get("info", []))
        
        # Calculate total findings
        total_findings = sum(len(findings_list) for findings_list in findings.values())
        total_vulnerabilities = critical_count + high_count + medium_count + low_count
        
        # Prepare data for main report
        main_report_data = {
            "target": target,
            "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "scan_duration": scan_duration or "N/A",
            "scan_config": scan_config or {},
            "total_findings": total_findings,
            "total_vulnerabilities": total_vulnerabilities,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "info_count": info_count,
            "critical_vulnerabilities": findings.get("critical", []),
            "high_vulnerabilities": findings.get("high", []),
            "medium_vulnerabilities": findings.get("medium", []),
            "low_vulnerabilities": findings.get("low", []),
            "info_findings": findings.get("info", []),
            "technologies": findings.get("technologies", []),
            "prioritized_urls": findings.get("prioritized_urls", []),
            "category_reports": category_reports
        }
        
        # Generate main report
        main_report_path = os.path.join(target_dir, "index.html")
        main_report = generate_html_report("main_report.html", main_report_path, main_report_data)
        
        # Save all findings as a single JSON file for programmatic access
        all_findings_path = os.path.join(target_dir, "all_findings.json")
        with open(all_findings_path, 'w', encoding='utf-8') as f:
            json.dump({
                "target": target,
                "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "scan_duration": scan_duration,
                "findings": findings
            }, f, indent=2)
            
        logger.info(f"Structured report generated successfully at {target_dir}")
        return main_report
    except Exception as e:
        logger.error(f"Failed to generate structured report: {str(e)}")
        return None 