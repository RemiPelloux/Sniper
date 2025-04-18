#!/usr/bin/env python3
"""
Sniper Security Tool - Scan Results Visualizer

This script visualizes the results from autonomous security tests performed by
the Sniper Security Tool. It can display vulnerability findings, metrics,
and generate reports in various formats.

Usage:
    python visualize_results.py --result-file results.json [--output report.html]
    python visualize_results.py --master-host localhost --master-port 8080 --task-id <task_id>
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional

import matplotlib.pyplot as plt
import pandas as pd
from tabulate import tabulate
import requests
from collections import Counter
import pdfkit
from jinja2 import Environment, FileSystemLoader

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from src.distributed.client import SniperClient
    from src.ml.autonomous_tester import VulnerabilityType
except ImportError:
    print("Error: Sniper modules not found. Make sure you're running from the Sniper root directory.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Vulnerability severity colors
SEVERITY_COLORS = {
    "critical": "#FF0000",  # Red
    "high": "#FF6600",      # Orange
    "medium": "#FFCC00",    # Yellow
    "low": "#00CC00",       # Green
    "info": "#0099FF"       # Blue
}

class ScanResultVisualizer:
    """Visualizer for Sniper Security Tool scan results"""
    
    def __init__(self):
        self.data = None
        self.output_format = "text"
        self.output_file = None
        self.show_graphs = False
        self.include_requests = False
        
    def load_from_file(self, file_path: str) -> None:
        """Load scan results from a JSON file"""
        try:
            with open(file_path, 'r') as f:
                self.data = json.load(f)
            print(f"Loaded data from {file_path}")
        except Exception as e:
            print(f"Error loading file: {e}", file=sys.stderr)
            sys.exit(1)
            
    def load_from_master(self, task_id: str, master_host: str, master_port: int) -> None:
        """Fetch scan results from a master node"""
        try:
            url = f"http://{master_host}:{master_port}/api/results/{task_id}"
            response = requests.get(url)
            response.raise_for_status()
            self.data = response.json()
            print(f"Loaded data from master node for task {task_id}")
        except Exception as e:
            print(f"Error fetching results from master: {e}", file=sys.stderr)
            sys.exit(1)
    
    def validate_data(self) -> bool:
        """Validate that the loaded data has the expected structure"""
        if not self.data:
            print("No data loaded", file=sys.stderr)
            return False
            
        required_fields = ["task_id", "target_url", "vulnerabilities"]
        for field in required_fields:
            if field not in self.data:
                print(f"Missing required field: {field}", file=sys.stderr)
                return False
                
        return True
    
    def generate_vulnerability_summary(self) -> Dict[str, Any]:
        """Generate summary statistics about vulnerabilities"""
        vulns = self.data.get("vulnerabilities", [])
        
        # Count vulnerabilities by severity
        severity_counts = Counter([v.get("severity", "Unknown") for v in vulns])
        
        # Count vulnerabilities by type
        type_counts = Counter([v.get("type", "Unknown") for v in vulns])
        
        # Calculate confidence average
        confidence_values = [v.get("confidence", 0) for v in vulns]
        avg_confidence = sum(confidence_values) / len(confidence_values) if confidence_values else 0
        
        return {
            "total": len(vulns),
            "by_severity": dict(severity_counts),
            "by_type": dict(type_counts),
            "avg_confidence": avg_confidence
        }
    
    def generate_text_report(self) -> str:
        """Generate a text-based report of the scan results"""
        if not self.validate_data():
            return "Invalid data"
            
        report = []
        
        # Basic info
        report.append("=" * 50)
        report.append(f"SNIPER SECURITY SCAN REPORT")
        report.append("=" * 50)
        report.append(f"Task ID: {self.data.get('task_id')}")
        report.append(f"Target: {self.data.get('target_url')}")
        report.append(f"Date: {self.data.get('date_created')}")
        report.append(f"Execution Time: {self.data.get('execution_time', 0):.2f} seconds")
        report.append(f"Requests Sent: {self.data.get('num_requests', 0)}")
        report.append("-" * 50)
        
        # Vulnerability summary
        summary = self.generate_vulnerability_summary()
        report.append(f"\nVULNERABILITIES FOUND: {summary['total']}")
        report.append("\nBy Severity:")
        for severity, count in summary['by_severity'].items():
            report.append(f"  {severity}: {count}")
            
        report.append("\nBy Type:")
        for vuln_type, count in summary['by_type'].items():
            report.append(f"  {vuln_type}: {count}")
            
        report.append(f"\nAverage Confidence: {summary['avg_confidence']:.2f}%")
        
        # Vulnerability details
        report.append("\n" + "=" * 50)
        report.append("VULNERABILITY DETAILS")
        report.append("=" * 50)
        
        for i, vuln in enumerate(self.data.get("vulnerabilities", []), 1):
            report.append(f"\n[{i}] {vuln.get('type')}")
            report.append(f"  Severity: {vuln.get('severity')}")
            report.append(f"  Confidence: {vuln.get('confidence')}%")
            report.append(f"  Location: {vuln.get('location')}")
            report.append(f"  Description: {vuln.get('description')}")
            report.append(f"  Remediation: {vuln.get('remediation')}")
        
        # Request details (if included)
        if self.include_requests and "requests" in self.data:
            report.append("\n" + "=" * 50)
            report.append("REQUEST DETAILS")
            report.append("=" * 50)
            
            for i, req in enumerate(self.data.get("requests", []), 1):
                report.append(f"\n[{i}] {req.get('method')} {req.get('url')}")
                report.append(f"  Status: {req.get('status_code')}")
                report.append(f"  Response Time: {req.get('response_time', 0):.3f}s")
                if "headers" in req:
                    report.append(f"  Headers Sent: {len(req['headers'])}")
        
        return "\n".join(report)
    
    def generate_csv(self) -> pd.DataFrame:
        """Generate a pandas DataFrame of vulnerabilities for CSV export"""
        vulns = self.data.get("vulnerabilities", [])
        df = pd.DataFrame(vulns)
        return df
    
    def create_severity_chart(self, save_path: Optional[str] = None) -> str:
        """Create a pie chart of vulnerabilities by severity"""
        summary = self.generate_vulnerability_summary()
        severities = summary['by_severity']
        
        # Define colors for different severity levels
        colors = {
            'Critical': 'darkred',
            'High': 'red',
            'Medium': 'orange',
            'Low': 'yellow',
            'Info': 'blue',
            'Unknown': 'gray'
        }
        
        # Create a list of colors corresponding to the labels
        chart_colors = [colors.get(s, 'gray') for s in severities.keys()]
        
        plt.figure(figsize=(8, 6))
        plt.pie(
            severities.values(), 
            labels=[f"{k} ({v})" for k, v in severities.items()], 
            autopct='%1.1f%%',
            colors=chart_colors,
            startangle=90
        )
        plt.title('Vulnerabilities by Severity')
        plt.axis('equal')
        
        if save_path:
            plt.savefig(save_path)
            plt.close()
            return save_path
        else:
            # For in-memory use (like in HTML templates)
            from io import BytesIO
            import base64
            
            buffer = BytesIO()
            plt.savefig(buffer, format='png')
            plt.close()
            
            buffer.seek(0)
            image_png = buffer.getvalue()
            buffer.close()
            
            encoded = base64.b64encode(image_png).decode('utf-8')
            return f"data:image/png;base64,{encoded}"
    
    def create_type_chart(self, save_path: Optional[str] = None) -> str:
        """Create a bar chart of vulnerabilities by type"""
        summary = self.generate_vulnerability_summary()
        types = summary['by_type']
        
        plt.figure(figsize=(10, 6))
        plt.barh(list(types.keys()), list(types.values()), color='skyblue')
        plt.xlabel('Count')
        plt.ylabel('Vulnerability Type')
        plt.title('Vulnerabilities by Type')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path)
            plt.close()
            return save_path
        else:
            from io import BytesIO
            import base64
            
            buffer = BytesIO()
            plt.savefig(buffer, format='png')
            plt.close()
            
            buffer.seek(0)
            image_png = buffer.getvalue()
            buffer.close()
            
            encoded = base64.b64encode(image_png).decode('utf-8')
            return f"data:image/png;base64,{encoded}"
    
    def generate_html_report(self) -> str:
        """Generate an HTML report with charts and formatted data"""
        if not self.validate_data():
            return "<h1>Invalid data</h1>"
            
        # Create charts as base64 encoded images
        severity_chart = self.create_severity_chart() if self.show_graphs else None
        type_chart = self.create_type_chart() if self.show_graphs else None
        
        # Create a simple HTML template
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sniper Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background-color: #333; color: white; padding: 20px; margin-bottom: 20px; }}
                .section {{ margin-bottom: 30px; border: 1px solid #ddd; padding: 20px; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .vuln-critical {{ background-color: #ffdddd; }}
                .vuln-high {{ background-color: #ffeeee; }}
                .vuln-medium {{ background-color: #ffffdd; }}
                .vuln-low {{ background-color: #eeffee; }}
                .charts {{ display: flex; justify-content: space-around; flex-wrap: wrap; }}
                .chart {{ margin: 10px; text-align: center; }}
                h1, h2, h3 {{ color: #333; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Sniper Security Scan Report</h1>
                    <p>Target: {self.data.get('target_url')}</p>
                </div>
                
                <div class="section">
                    <h2>Scan Overview</h2>
                    <table>
                        <tr><th>Task ID</th><td>{self.data.get('task_id')}</td></tr>
                        <tr><th>Date</th><td>{self.data.get('date_created')}</td></tr>
                        <tr><th>Execution Time</th><td>{self.data.get('execution_time', 0):.2f} seconds</td></tr>
                        <tr><th>Requests Sent</th><td>{self.data.get('num_requests', 0)}</td></tr>
                        <tr><th>Vulnerabilities Found</th><td>{len(self.data.get('vulnerabilities', []))}</td></tr>
                    </table>
                </div>
        """
        
        # Add charts if enabled
        if self.show_graphs:
            html += f"""
                <div class="section">
                    <h2>Vulnerability Summary</h2>
                    <div class="charts">
                        <div class="chart">
                            <h3>By Severity</h3>
                            <img src="{severity_chart}" alt="Vulnerabilities by Severity" />
                        </div>
                        <div class="chart">
                            <h3>By Type</h3>
                            <img src="{type_chart}" alt="Vulnerabilities by Type" />
                        </div>
                    </div>
                </div>
            """
        
        # Add vulnerability details
        html += """
                <div class="section">
                    <h2>Vulnerability Details</h2>
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Confidence</th>
                            <th>Location</th>
                            <th>Description</th>
                            <th>Remediation</th>
                        </tr>
        """
        
        for vuln in self.data.get("vulnerabilities", []):
            severity_class = f"vuln-{vuln.get('severity', '').lower()}" if vuln.get('severity', '').lower() in ['critical', 'high', 'medium', 'low'] else ""
            html += f"""
                <tr class="{severity_class}">
                    <td>{vuln.get('type', '')}</td>
                    <td>{vuln.get('severity', '')}</td>
                    <td>{vuln.get('confidence', '')}%</td>
                    <td>{vuln.get('location', '')}</td>
                    <td>{vuln.get('description', '')}</td>
                    <td>{vuln.get('remediation', '')}</td>
                </tr>
            """
            
        html += """
                    </table>
                </div>
        """
        
        # Add request details if included
        if self.include_requests and "requests" in self.data:
            html += """
                <div class="section">
                    <h2>Request Details</h2>
                    <table>
                        <tr>
                            <th>Method</th>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Response Time</th>
                        </tr>
            """
            
            for req in self.data.get("requests", []):
                html += f"""
                    <tr>
                        <td>{req.get('method', '')}</td>
                        <td>{req.get('url', '')}</td>
                        <td>{req.get('status_code', '')}</td>
                        <td>{req.get('response_time', 0):.3f}s</td>
                    </tr>
                """
                
            html += """
                    </table>
                </div>
            """
        
        # Close HTML tags
        html += """
            </div>
        </body>
        </html>
        """
        
        return html
    
    def visualize(self, output_format: str, output_file: Optional[str] = None,
                 show_graphs: bool = False, include_requests: bool = False) -> None:
        """Generate visualization in the specified format"""
        self.output_format = output_format.lower()
        self.output_file = output_file
        self.show_graphs = show_graphs
        self.include_requests = include_requests
        
        if not self.validate_data():
            return
        
        # Generate appropriate output based on format
        if self.output_format == "text":
            report = self.generate_text_report()
            if self.output_file:
                with open(self.output_file, 'w') as f:
                    f.write(report)
                print(f"Text report saved to {self.output_file}")
            else:
                print(report)
                
        elif self.output_format == "html":
            html = self.generate_html_report()
            if not self.output_file:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                self.output_file = f"report_{timestamp}.html"
            
            with open(self.output_file, 'w') as f:
                f.write(html)
            print(f"HTML report saved to {self.output_file}")
            
        elif self.output_format == "pdf":
            html = self.generate_html_report()
            if not self.output_file:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                self.output_file = f"report_{timestamp}.pdf"
            
            try:
                pdfkit.from_string(html, self.output_file)
                print(f"PDF report saved to {self.output_file}")
            except Exception as e:
                print(f"Error generating PDF: {e}", file=sys.stderr)
                print("Falling back to HTML output")
                html_file = self.output_file.replace('.pdf', '.html')
                with open(html_file, 'w') as f:
                    f.write(html)
                print(f"HTML report saved to {html_file}")
                
        elif self.output_format == "csv":
            df = self.generate_csv()
            if not self.output_file:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                self.output_file = f"vulnerabilities_{timestamp}.csv"
            
            df.to_csv(self.output_file, index=False)
            print(f"CSV report saved to {self.output_file}")
            
        elif self.output_format == "json":
            # Just output the original data or a subset
            output_data = {
                "scan_info": {
                    "task_id": self.data.get("task_id"),
                    "target_url": self.data.get("target_url"),
                    "date_created": self.data.get("date_created"),
                    "execution_time": self.data.get("execution_time"),
                    "num_requests": self.data.get("num_requests")
                },
                "vulnerabilities": self.data.get("vulnerabilities", [])
            }
            
            if self.include_requests:
                output_data["requests"] = self.data.get("requests", [])
                
            if not self.output_file:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                self.output_file = f"report_{timestamp}.json"
            
            with open(self.output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"JSON report saved to {self.output_file}")
            
        else:
            print(f"Unsupported output format: {self.output_format}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Visualize Sniper Security Tool scan results")
    
    # Input source options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--input-file', type=str, help='Path to JSON result file')
    input_group.add_argument('--task-id', type=str, help='Task ID to fetch from master node')
    
    # Master node connection options (only needed with task-id)
    parser.add_argument('--master-host', type=str, default='localhost', help='Master node hostname')
    parser.add_argument('--master-port', type=int, default=8000, help='Master node port')
    
    # Output options
    parser.add_argument('--output-format', type=str, default='text',
                        choices=['text', 'html', 'pdf', 'csv', 'json'],
                        help='Output format')
    parser.add_argument('--output-file', type=str, help='Output file path')
    
    # Visualization options
    parser.add_argument('--show-graphs', action='store_true', 
                        help='Generate and display graphs (default when using html or pdf output)')
    parser.add_argument('--include-requests', action='store_true',
                        help='Include detailed request information in the report')
    
    args = parser.parse_args()
    
    # Initialize visualizer
    visualizer = ScanResultVisualizer()
    
    # Load data
    if args.input_file:
        visualizer.load_from_file(args.input_file)
    else:
        visualizer.load_from_master(args.task_id, args.master_host, args.master_port)
    
    # Auto-enable graphs for HTML and PDF if not explicitly disabled
    show_graphs = args.show_graphs
    if args.output_format in ['html', 'pdf'] and not args.show_graphs:
        show_graphs = True
    
    # Generate visualization
    visualizer.visualize(
        output_format=args.output_format,
        output_file=args.output_file,
        show_graphs=show_graphs,
        include_requests=args.include_requests
    )


if __name__ == "__main__":
    main() 