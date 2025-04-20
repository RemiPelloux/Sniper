"""
Test script for the vulnerability scanner with enhanced URL filtering
"""

import asyncio
import logging
import json
import requests
from urllib.parse import urljoin
from src.integrations.vulnerability_scanner import VulnerabilityScanner
from src.integrations.url_filter import UrlFilter

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger(__name__)

def discover_juice_shop_endpoints(base_url):
    """
    Discover OWASP Juice Shop API endpoints
    """
    api_endpoints = []
    
    # Known API endpoints in Juice Shop
    paths = [
        "/rest/user/login",
        "/rest/user/registration",
        "/rest/products",
        "/rest/basket",
        "/rest/cart",
        "/rest/captcha",
        "/rest/challenges",
        "/rest/feedback",
        "/rest/memories",
        "/rest/track-order",
        "/rest/search",
        "/rest/deluxe-membership",
        "/rest/wallet/balance",
        "/api/Users",
        "/api/Products",
        "/api/Feedbacks",
        "/api/Challenges",
        "/api/Complaints",
        "/api/SecurityQuestions",
        "/api/SecurityAnswers",
        "/api/Quantitys",
        "/api/Addresss",
        "/api/Cards",
        "/api/Deliverys",
        "/api/Memorys"
    ]
    
    log.info(f"Discovering API endpoints for {base_url}")
    
    for path in paths:
        api_url = urljoin(base_url, path)
        try:
            response = requests.get(api_url, timeout=5, verify=False)
            if response.status_code != 404:  # If not 404, the endpoint probably exists
                api_endpoints.append(api_url)
                log.info(f"Found API endpoint: {api_url} (Status: {response.status_code})")
        except Exception as e:
            log.debug(f"Error checking {api_url}: {str(e)}")
    
    return api_endpoints

async def main():
    # Create the vulnerability scanner
    scanner = VulnerabilityScanner()
    
    # Check if prerequisites are met
    if not scanner.check_prerequisites():
        log.error("Scanner prerequisites not met")
        return
    
    # Define the target
    target = "http://localhost:3000"
    
    # Discover Juice Shop API endpoints
    api_endpoints = discover_juice_shop_endpoints(target)
    
    # Define initial URLs to help with crawling
    initial_urls = [
        f"{target}/",
        f"{target}/rest/user/login",
        f"{target}/rest/products/search",
        f"{target}/rest/basket/1",
        f"{target}/rest/user/registration",
        f"{target}/rest/captcha/",
        f"{target}/rest/track-order/",
        f"{target}/api/Users",
    ] + api_endpoints
    
    # Remove duplicates
    initial_urls = list(set(initial_urls))
    
    # Define scan options
    options = {
        "verify_ssl": False,
        "max_urls": 100,
        "scan_types": ["xss", "sqli", "open_redirect", "path_traversal", "command_injection"],
        "scan_depth": "standard",
        "timeout": 10,
        "wait_time": 0.5,
        "initial_urls": initial_urls
    }
    
    log.info(f"Starting vulnerability scan against {target}")
    log.info(f"Initial URLs: {len(initial_urls)}")
    
    try:
        # Run the scan
        result = await scanner.run(target, options)
        
        # Print the number of findings
        num_findings = len(result.get("findings", []))
        log.info(f"Scan completed with {num_findings} findings")
        log.info(f"Crawled {result.get('urls_crawled', 0)} URLs")
        
        # Save the results to a file
        with open("vulnerability_scan_results.json", "w") as f:
            json.dump(result, f, indent=2)
        
        log.info("Results saved to vulnerability_scan_results.json")
        
        # Print a summary of the findings
        if num_findings > 0:
            log.info("Findings summary:")
            for i, finding in enumerate(result.get("findings", []), 1):
                log.info(f"{i}. {finding['title']} - {finding['severity']} - {finding['url']}")
        
    except Exception as e:
        log.error(f"Error running vulnerability scan: {str(e)}")

if __name__ == "__main__":
    # Disable insecure request warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    asyncio.run(main()) 