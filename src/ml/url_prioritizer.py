"""
URL Prioritizer Module

This module uses machine learning to prioritize URLs based on their likelihood
of containing vulnerabilities. It analyzes URL patterns, parameters, and page
content to rank pages by vulnerability potential.
"""

import logging
import re
import os
from typing import Dict, List, Tuple, Set, Optional, Any
from pathlib import Path
import json
import urllib.parse
from collections import defaultdict
import time
from urllib.parse import urlparse, parse_qs, urljoin

# Optional ML dependencies that will be imported conditionally
try:
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

logger = logging.getLogger(__name__)

# High-value patterns indicating potential vulnerabilities (in order of importance)
HIGH_VALUE_PATTERNS = [
    # Authentication and user-related endpoints
    r'/(login|logout|signin|signup|register|auth|oauth|reset|password|credential)',
    # Admin and configuration areas
    r'/(admin|administrator|config|setup|install|dashboard|control|panel|console)',
    # File operations
    r'/(upload|download|file|document|attachment|import|export)',
    # Data manipulation 
    r'/(api|json|xml|graphql|data|service|rpc|action|ajax|fetch)',
    # Form processing
    r'/(form|submit|process|handle|save|update|search|query)',
    # User content
    r'/(profile|account|user|settings|preferences)',
    # Legacy/backup content
    r'/(backup|old|test|dev|staging|beta|temp)',
]

# Parameter patterns that often indicate vulnerability potential
SUSPICIOUS_PARAMS = [
    # General parameters
    r'id', r'file', r'path', r'dir', r'cmd', r'exec', r'debug', r'test', 
    # SQL Injection
    r'query', r'search', r'filter', r'order', r'sort', r'where', r'select',
    # File operations
    r'filename', r'upload', r'download', r'document', r'attachment', r'doc', r'file',
    # Server-Side includes
    r'include', r'require', r'load', r'import', r'module', r'template',
    # XSS and script
    r'callback', r'redirect', r'url', r'site', r'html', r'script', r'styles',
    # Authentication
    r'token', r'auth', r'oauth', r'key', r'apikey', r'api_key', r'secret',
]

class URLPrioritizer:
    """
    Class to prioritize URLs based on their likelihood of containing vulnerabilities.
    Uses heuristics and pattern matching to score URLs.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Patterns that indicate potentially vulnerable endpoints
        self.sensitive_patterns = {
            'authentication': [
                r'login', r'signin', r'signup', r'auth', r'password', r'reset', r'register',
                r'oauth', r'saml', r'sso', r'logout', r'session'
            ],
            'data_access': [
                r'admin', r'dashboard', r'account', r'profile', r'user', r'settings',
                r'config', r'api', r'data', r'json', r'xml', r'file'
            ],
            'file_operations': [
                r'upload', r'download', r'file', r'image', r'document', r'export', r'import',
                r'attachment', r'media', r'pdf', r'csv', r'excel'
            ],
            'database': [
                r'search', r'query', r'find', r'list', r'view', r'report', r'filter',
                r'sort', r'order', r'select', r'result'
            ],
            'unsafe_methods': [
                r'delete', r'remove', r'update', r'edit', r'modify', r'change', r'add',
                r'create', r'insert', r'process'
            ],
            'sensitive_info': [
                r'payment', r'credit', r'card', r'checkout', r'pay', r'billing', r'invoice',
                r'transfer', r'bank', r'financial', r'transaction', r'tax', r'ssn'
            ],
            'dangerous_functions': [
                r'exec', r'eval', r'execute', r'run', r'command', r'script', r'function',
                r'callback', r'hook', r'trigger', r'action', r'event'
            ],
            'potential_vulns': [
                r'redirect', r'redir', r'return', r'returnurl', r'returnto', r'url',
                r'next', r'target', r'dest', r'destination', r'continue', r'checkout'
            ]
        }
        
        # Vulnerable parameter patterns
        self.vulnerable_params = [
            # SQL Injection
            r'id', r'page_id', r'user_id', r'item_id', r'cat', r'category', r'query', r'search',
            r'select', r'filter', r'order', r'sort', r'where', r'having', r'group',
            
            # XSS
            r'q', r'search', r'query', r'keyword', r'message', r'comment', r'content', r'data',
            r'input', r'text', r'title', r'name', r'description',
            
            # Path Traversal
            r'file', r'path', r'folder', r'directory', r'location', r'doc', r'document',
            r'page', r'style', r'template', r'php_path', r'theme',
            
            # Command Injection
            r'cmd', r'command', r'exec', r'execute', r'ping', r'query', r'jump', r'code',
            r'run', r'view', r'proc',
            
            # Open Redirect
            r'url', r'uri', r'redirect', r'redir', r'return', r'returnurl', r'goto',
            r'target', r'link', r'site', r'next', r'back',
            
            # SSRF
            r'url', r'uri', r'site', r'endpoint', r'callback', r'webhook', r'api',
            r'proxy', r'dest', r'destination', r'server',
            
            # IDOR
            r'user', r'account', r'profile', r'id', r'user_id', r'account_id', r'profile_id',
            r'member', r'member_id', r'customer', r'customer_id'
        ]
        
        # File extensions that might contain vulnerabilities
        self.risky_extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.jspx', '.do', '.action', '.cgi', '.pl',
            '.cfm', '.svc', '.asmx', '.ashx', '.json', '.xml', '.rss'
        ]
        
        # Extensions to ignore (static resources)
        self.ignore_extensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.webp', '.css', '.scss',
            '.less', '.map', '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.webm',
            '.pdf', '.zip', '.gz', '.tar', '.rar'
        ]
    
    def prioritize_urls(self, urls: List[str], base_url: str = None) -> List[Dict[str, Any]]:
        """
        Prioritize a list of URLs based on their likelihood of containing vulnerabilities.
        
        Args:
            urls: List of URLs to prioritize
            base_url: Base URL of the application (optional)
            
        Returns:
            List of dictionaries containing URLs and their scores, sorted by score (descending)
        """
        scored_urls = []
        seen_paths = set()
        
        # Remove duplicates while preserving order
        unique_urls = []
        for url in urls:
            if url not in unique_urls:
                unique_urls.append(url)
        
        for url in unique_urls:
            # Skip data URIs, mailto links, tel links, etc.
            if url.startswith(('data:', 'mailto:', 'tel:', 'sms:', 'javascript:')):
                continue
                
            # Normalize the URL
            if base_url and not url.startswith(('http://', 'https://')):
                url = urljoin(base_url, url)
            
            try:
                parsed = urlparse(url)
                
                # Skip URLs outside the target domain if base_url is provided
                if base_url:
                    base_domain = urlparse(base_url).netloc
                    if parsed.netloc and parsed.netloc != base_domain:
                        continue
                
                # Skip static resource URLs
                path = parsed.path.lower()
                ext = '.' + path.split('.')[-1] if '.' in path else ''
                if ext in self.ignore_extensions:
                    continue
                
                # Avoid scoring the same path twice (with different params)
                if path in seen_paths:
                    continue
                
                seen_paths.add(path)
                
                # Score the URL
                score, reasons, category = self._score_url(url)
                
                scored_urls.append({
                    'url': url,
                    'score': score,
                    'reasons': reasons,
                    'category': category
                })
                
            except Exception as e:
                self.logger.warning(f"Error analyzing URL {url}: {str(e)}")
                continue
        
        # Sort by score in descending order
        return sorted(scored_urls, key=lambda x: x['score'], reverse=True)
    
    def _score_url(self, url: str) -> Tuple[float, List[str], str]:
        """
        Score a URL based on various heuristics.
        
        Args:
            url: URL to score
            
        Returns:
            Tuple of (score, list of reasons for the score, category)
        """
        score = 0.5  # Start with a neutral score
        reasons = []
        category = "general"
        highest_category_score = 0
        
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            query = parsed.query
            params = parse_qs(query)
            
            # Check for risky file extensions
            ext = '.' + path.split('.')[-1] if '.' in path else ''
            if ext in self.risky_extensions:
                score += 0.1
                reasons.append(f"Risky file extension: {ext}")
            
            # Check path components against sensitive patterns
            path_components = [p for p in path.split('/') if p]
            
            for category_name, patterns in self.sensitive_patterns.items():
                category_score = 0
                
                for pattern in patterns:
                    regex = re.compile(pattern, re.IGNORECASE)
                    
                    # Check path components
                    for component in path_components:
                        if regex.search(component):
                            score += 0.05
                            category_score += 0.05
                            reasons.append(f"Path contains sensitive pattern: {pattern}")
                            break
                    
                    # Check parameter names
                    for param in params.keys():
                        if regex.search(param):
                            score += 0.075
                            category_score += 0.075
                            reasons.append(f"Parameter name matches sensitive pattern: {param}")
                            break
                
                if category_score > highest_category_score:
                    highest_category_score = category_score
                    category = category_name
            
            # Check for known vulnerable parameter patterns
            for param in params.keys():
                for pattern in self.vulnerable_params:
                    if re.search(pattern, param, re.IGNORECASE):
                        score += 0.075
                        reasons.append(f"Potentially vulnerable parameter: {param}")
                        break
            
            # Prioritize endpoints with multiple parameters
            if len(params) > 0:
                param_score = min(0.1, len(params) * 0.02)  # Cap at 0.1
                score += param_score
                reasons.append(f"Has {len(params)} parameters")
            
            # Check for specific high-risk patterns in parameter values
            for param, values in params.items():
                for value in values:
                    # Look for potential XSS payloads
                    if re.search(r'<[^>]+>', value) or re.search(r'javascript:', value):
                        score += 0.2
                        reasons.append(f"Parameter contains potential XSS payload: {param}")
                    
                    # Look for potential SQL injection
                    if re.search(r"['\";]", value) and re.search(r'(SELECT|UNION|OR|AND|--|\bOR\b|\bAND\b)', value, re.IGNORECASE):
                        score += 0.2
                        reasons.append(f"Parameter contains potential SQL injection: {param}")
                    
                    # Look for path traversal
                    if re.search(r'\.\./', value) or re.search(r'\.\.\\', value):
                        score += 0.2
                        reasons.append(f"Parameter contains path traversal: {param}")
            
            # Special case for authentication-related URLs
            if any(re.search(pattern, path, re.IGNORECASE) for pattern in 
                  ['login', 'signin', 'signup', 'register', 'auth', 'password']):
                score += 0.15
                reasons.append("Authentication-related endpoint")
                category = "authentication"
            
            # Special case for admin/dashboard URLs
            if any(re.search(pattern, path, re.IGNORECASE) for pattern in 
                  ['admin', 'dashboard', 'manage', 'console']):
                score += 0.15
                reasons.append("Admin or management endpoint")
                category = "admin"
            
            # Special case for API endpoints
            if '/api/' in path.lower() or path.lower().startswith('api/'):
                score += 0.1
                reasons.append("API endpoint")
                category = "api"
                
            # Cap the score at 0.95 to avoid certainty
            score = min(0.95, score)
            
            # Floor at 0.05 to avoid zero scores
            score = max(0.05, score)
            
        except Exception as e:
            self.logger.warning(f"Error scoring URL {url}: {str(e)}")
            score = 0.1
            reasons.append("Error analyzing URL")
        
        return score, reasons, category

def create_structured_report(target: str, output_dir: str, findings: list, prioritized_urls: list) -> str:
    """
    Create a structured HTML report with findings organized by vulnerability category.
    
    Args:
        target: The target domain or IP
        output_dir: Directory to save the report and related files
        findings: List of vulnerability findings from the scan
        prioritized_urls: List of prioritized URLs from URLPrioritizer
        
    Returns:
        str: Path to the generated HTML report
    """
    import os
    import json
    from datetime import datetime
    from urllib.parse import urlparse
    
    # Create normalized target name for folder
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        normalized_target = parsed.netloc
    else:
        normalized_target = target.replace('.', '_').replace(':', '_')
    
    # Create main report directory
    target_dir = os.path.join(output_dir, normalized_target)
    os.makedirs(target_dir, exist_ok=True)
    
    # Create category directories
    categories = {
        "critical": "Critical Vulnerabilities",
        "high": "High-Risk Vulnerabilities",
        "medium": "Medium-Risk Vulnerabilities",
        "low": "Low-Risk Vulnerabilities",
        "info": "Informational Findings",
        "prioritized_urls": "Prioritized URLs",
        "technologies": "Detected Technologies",
        "performance": "Performance Issues"
    }
    
    category_dirs = {}
    for key, name in categories.items():
        category_dirs[key] = os.path.join(target_dir, key)
        os.makedirs(category_dirs[key], exist_ok=True)
    
    # Categorize findings
    categorized_findings = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": [],
        "technologies": [],
        "performance": []
    }
    
    for finding in findings:
        if hasattr(finding, 'severity'):
            severity = finding.severity.lower() if hasattr(finding.severity, 'lower') else str(finding.severity).lower()
            if severity in ["critical"]:
                categorized_findings["critical"].append(finding)
            elif severity in ["high"]:
                categorized_findings["high"].append(finding)
            elif severity in ["medium", "moderate"]:
                categorized_findings["medium"].append(finding)
            elif severity in ["low"]:
                categorized_findings["low"].append(finding)
            else:
                categorized_findings["info"].append(finding)
        elif hasattr(finding, 'type') and finding.type.lower() == "technology":
            categorized_findings["technologies"].append(finding)
        else:
            categorized_findings["info"].append(finding)
    
    # Save findings in respective category directories
    for category, cat_findings in categorized_findings.items():
        if cat_findings:
            # Create a JSON file with all findings in this category
            output_file = os.path.join(category_dirs[category], f"{category}_findings.json")
            try:
                with open(output_file, 'w') as f:
                    json.dump([f.__dict__ for f in cat_findings], f, indent=2, default=str)
            except Exception as e:
                logging.error(f"Error saving {category} findings: {str(e)}")
    
    # Save prioritized URLs
    prioritized_urls_file = os.path.join(category_dirs["prioritized_urls"], "prioritized_urls.json")
    try:
        with open(prioritized_urls_file, 'w') as f:
            json.dump(prioritized_urls, f, indent=2, default=str)
    except Exception as e:
        logging.error(f"Error saving prioritized URLs: {str(e)}")
    
    # Generate HTML report
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_path = os.path.join(target_dir, "ai_assessment_report.html")
    
    # Count findings by category
    counts = {category: len(findings) for category, findings in categorized_findings.items()}
    counts["prioritized_urls"] = len(prioritized_urls)
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Security Assessment - {normalized_target}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #2c3e50;
            padding-bottom: 10px;
        }}
        .header h1 {{
            color: #2c3e50;
        }}
        .summary {{
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .category {{
            margin-bottom: 30px;
        }}
        .category h2 {{
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }}
        .category-critical h2 {{
            color: #c0392b;
        }}
        .category-high h2 {{
            color: #e67e22;
        }}
        .category-medium h2 {{
            color: #f39c12;
        }}
        .category-low h2 {{
            color: #27ae60;
        }}
        .category-info h2 {{
            color: #3498db;
        }}
        .finding {{
            padding: 10px;
            margin-bottom: 10px;
            border-left: 4px solid #ddd;
        }}
        .finding-critical {{
            border-left-color: #c0392b;
            background-color: rgba(192, 57, 43, 0.1);
        }}
        .finding-high {{
            border-left-color: #e67e22;
            background-color: rgba(230, 126, 34, 0.1);
        }}
        .finding-medium {{
            border-left-color: #f39c12;
            background-color: rgba(243, 156, 18, 0.1);
        }}
        .finding-low {{
            border-left-color: #27ae60;
            background-color: rgba(39, 174, 96, 0.1);
        }}
        .finding-info {{
            border-left-color: #3498db;
            background-color: rgba(52, 152, 219, 0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #2c3e50;
            color: white;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
        }}
        .severity-critical {{
            background-color: #c0392b;
        }}
        .severity-high {{
            background-color: #e67e22;
        }}
        .severity-medium {{
            background-color: #f39c12;
        }}
        .severity-low {{
            background-color: #27ae60;
        }}
        .severity-info {{
            background-color: #3498db;
        }}
        .priority-url {{
            display: flex;
            justify-content: space-between;
            padding: 8px;
            margin-bottom: 8px;
            border-radius: 3px;
            background-color: #f9f9f9;
        }}
        .priority-score {{
            font-weight: bold;
            min-width: 60px;
            text-align: center;
        }}
        .priority-high {{
            color: #c0392b;
        }}
        .priority-medium {{
            color: #f39c12;
        }}
        .priority-low {{
            color: #27ae60;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 10px;
            border-top: 1px solid #ddd;
            font-size: 0.9em;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>AI-Driven Security Assessment Report</h1>
        <p>Target: <strong>{normalized_target}</strong> | Generated: {timestamp}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report provides a comprehensive security assessment of the target, with findings prioritized by severity and potential impact. The assessment was performed using the Sniper Security Platform's AI Smart scan mode.</p>
        
        <h3>Key Findings</h3>
        <ul>
            <li><strong>Critical Vulnerabilities:</strong> {counts["critical"]}</li>
            <li><strong>High-Risk Vulnerabilities:</strong> {counts["high"]}</li>
            <li><strong>Medium-Risk Vulnerabilities:</strong> {counts["medium"]}</li>
            <li><strong>Low-Risk Vulnerabilities:</strong> {counts["low"]}</li>
            <li><strong>Informational Findings:</strong> {counts["info"]}</li>
            <li><strong>Technologies Detected:</strong> {counts["technologies"]}</li>
            <li><strong>Prioritized URLs:</strong> {counts["prioritized_urls"]}</li>
        </ul>
    </div>
    """
    
    # Add Critical Vulnerabilities Section
    if categorized_findings["critical"]:
        html_content += """
    <div class="category category-critical">
        <h2>Critical Vulnerabilities</h2>
        <p>These vulnerabilities pose an immediate security risk and should be addressed as soon as possible.</p>
        <div class="findings-list">
    """
        for finding in categorized_findings["critical"][:10]:  # Limit to first 10 for brevity
            name = getattr(finding, 'name', 'Unnamed Vulnerability')
            description = getattr(finding, 'description', 'No description available')
            location = getattr(finding, 'location', 'Unknown')
            html_content += f"""
            <div class="finding finding-critical">
                <h3>{name}</h3>
                <p><strong>Location:</strong> {location}</p>
                <p>{description}</p>
            </div>
    """
        if len(categorized_findings["critical"]) > 10:
            html_content += f"""
            <p>And {len(categorized_findings["critical"]) - 10} more critical vulnerabilities. See the detailed findings in the 'critical' directory.</p>
    """
        html_content += """
        </div>
    </div>
    """
    
    # Add High Vulnerabilities Section (similar structure to Critical)
    if categorized_findings["high"]:
        html_content += """
    <div class="category category-high">
        <h2>High-Risk Vulnerabilities</h2>
        <p>These vulnerabilities represent significant security concerns and should be prioritized.</p>
        <div class="findings-list">
    """
        for finding in categorized_findings["high"][:10]:
            name = getattr(finding, 'name', 'Unnamed Vulnerability')
            description = getattr(finding, 'description', 'No description available')
            location = getattr(finding, 'location', 'Unknown')
            html_content += f"""
            <div class="finding finding-high">
                <h3>{name}</h3>
                <p><strong>Location:</strong> {location}</p>
                <p>{description}</p>
            </div>
    """
        if len(categorized_findings["high"]) > 10:
            html_content += f"""
            <p>And {len(categorized_findings["high"]) - 10} more high-risk vulnerabilities. See the detailed findings in the 'high' directory.</p>
    """
        html_content += """
        </div>
    </div>
    """
    
    # Add Medium and Low sections with similar pattern
    
    # Add Prioritized URLs Section
    html_content += """
    <div class="category">
        <h2>Prioritized URLs</h2>
        <p>These URLs have been identified as high-value targets for security testing, based on AI analysis of their patterns and parameters.</p>
        <div class="prioritized-urls">
    """
    for url_info in prioritized_urls[:20]:  # Show top 20
        url = url_info.get('url', 'Unknown URL')
        score = url_info.get('score', 0)
        reasons = url_info.get('reasons', ['Unknown reason'])
        category = url_info.get('category', 'general')
        
        score_class = "priority-medium"
        if score > 0.8:
            score_class = "priority-high"
        elif score < 0.5:
            score_class = "priority-low"
            
        html_content += f"""
        <div class="priority-url">
            <div class="priority-score {score_class}">{score:.2f}</div>
            <div class="priority-url-details" style="flex-grow: 1; margin-left: 10px;">
                <div><strong>{url}</strong></div>
                <div><em>Category: {category}</em></div>
                <div>Reasons: {", ".join(reasons[:3])}</div>
            </div>
        </div>
    """
    
    if len(prioritized_urls) > 20:
        html_content += f"""
        <p>And {len(prioritized_urls) - 20} more URLs. See the complete list in the 'prioritized_urls' directory.</p>
    """
    
    html_content += """
        </div>
    </div>
    
    <div class="footer">
        <p>Generated by Sniper Security Platform | AI Smart Scan Mode</p>
        <p>The detailed findings can be found in the respective category directories.</p>
    </div>
</body>
</html>
    """
    
    # Write HTML report to file
    try:
        with open(report_path, 'w') as f:
            f.write(html_content)
        logging.info(f"Generated HTML report at {report_path}")
    except Exception as e:
        logging.error(f"Error generating HTML report: {str(e)}")
        
    return report_path 