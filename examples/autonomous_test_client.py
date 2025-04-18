#!/usr/bin/env python3
"""
Example script showing how to use the SniperClient for autonomous vulnerability testing.

This example demonstrates:
1. Connecting to a Sniper master node
2. Submitting autonomous testing tasks
3. Waiting for and retrieving results
"""

import asyncio
import argparse
import json
import logging
from typing import Dict, Any, Optional

from src.distributed.client import SniperClient, run_autonomous_test
from src.distributed.base import TaskPriority
from src.ml.autonomous_tester import VulnerabilityType

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("example.autonomous_test")

async def run_specific_vulnerability_test(master_host: str, master_port: int, target_url: str) -> None:
    """
    Run tests for specific vulnerability types against a target.
    
    Args:
        master_host: Host address of the master node
        master_port: Port number of the master node
        target_url: Target URL to test
    """
    client = SniperClient(master_host, master_port)
    
    try:
        # Connect to the master node
        if not await client.connect():
            logger.error("Failed to connect to master node")
            return
        
        logger.info(f"Connected to master node at {master_host}:{master_port}")
        
        # Test for SQL injection vulnerability
        logger.info(f"Submitting SQL injection test for {target_url}")
        sql_task_id = await client.submit_autonomous_test(
            target_url=target_url,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            priority=TaskPriority.HIGH
        )
        
        if not sql_task_id:
            logger.error("Failed to submit SQL injection test")
        else:
            logger.info(f"SQL injection test submitted with task ID: {sql_task_id}")
        
        # Test for XSS vulnerability in parallel
        logger.info(f"Submitting XSS test for {target_url}")
        xss_task_id = await client.submit_autonomous_test(
            target_url=target_url,
            vulnerability_type=VulnerabilityType.XSS,
            priority=TaskPriority.MEDIUM
        )
        
        if not xss_task_id:
            logger.error("Failed to submit XSS test")
        else:
            logger.info(f"XSS test submitted with task ID: {xss_task_id}")
        
        # Wait for SQL injection test results
        if sql_task_id:
            logger.info(f"Waiting for SQL injection test results...")
            sql_result = await client.wait_for_task_completion(sql_task_id)
            if sql_result:
                print_test_result("SQL INJECTION", sql_result)
            else:
                logger.error("Failed to get SQL injection test results")
        
        # Wait for XSS test results
        if xss_task_id:
            logger.info(f"Waiting for XSS test results...")
            xss_result = await client.wait_for_task_completion(xss_task_id)
            if xss_result:
                print_test_result("XSS", xss_result)
            else:
                logger.error("Failed to get XSS test results")
    
    finally:
        # Always disconnect
        await client.disconnect()
        logger.info("Disconnected from master node")

async def run_comprehensive_scan_example(master_host: str, master_port: int, target_url: str) -> None:
    """
    Run a comprehensive scan against a target.
    
    Args:
        master_host: Host address of the master node
        master_port: Port number of the master node
        target_url: Target URL to test
    """
    logger.info(f"Starting comprehensive scan of {target_url}")
    
    # Use the convenience function
    result = await run_autonomous_test(
        master_host=master_host,
        master_port=master_port,
        target_url=target_url
    )
    
    if result:
        if result.get("status") == "error":
            logger.error(f"Scan failed: {result.get('message')}")
        else:
            print_test_result("COMPREHENSIVE SCAN", result)
    else:
        logger.error("Failed to get scan results")

def print_test_result(test_type: str, result: Dict[str, Any]) -> None:
    """
    Print formatted test results.
    
    Args:
        test_type: Type of test that was run
        result: Test result dictionary
    """
    print("\n" + "="*80)
    print(f" {test_type} TEST RESULTS ")
    print("="*80)
    
    vulnerabilities = result.get("vulnerabilities", [])
    if vulnerabilities:
        print(f"\nFound {len(vulnerabilities)} potential vulnerabilities:")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n{i}. {vuln.get('type', 'Unknown vulnerability type')}")
            print(f"   Severity: {vuln.get('severity', 'Unknown')}")
            print(f"   Confidence: {vuln.get('confidence', 0):.2f}")
            print(f"   Description: {vuln.get('description', 'No description')}")
            
            # Print payload that triggered the vulnerability
            if "payload" in vuln:
                print(f"   Payload: {vuln['payload']}")
            
            # Print affected parameters
            if "affected_parameter" in vuln:
                print(f"   Affected parameter: {vuln['affected_parameter']}")
    else:
        print("\nNo vulnerabilities found.")
    
    # Print execution details
    print("\nExecution details:")
    print(f"  Execution time: {result.get('execution_time', 'Unknown')}s")
    print(f"  Payloads tested: {result.get('payloads_tested', 'Unknown')}")
    print(f"  Requests sent: {result.get('requests_sent', 'Unknown')}")
    
    print("\n" + "="*80 + "\n")

async def main() -> None:
    """Parse command line arguments and run the example."""
    parser = argparse.ArgumentParser(description="Sniper Autonomous Testing Example")
    parser.add_argument("--host", default="localhost", help="Master node host")
    parser.add_argument("--port", type=int, default=8080, help="Master node port")
    parser.add_argument("--target", required=True, help="Target URL to test")
    parser.add_argument("--mode", choices=["comprehensive", "specific"], default="comprehensive",
                      help="Test mode: comprehensive scan or specific vulnerability tests")
    
    args = parser.parse_args()
    
    if args.mode == "comprehensive":
        await run_comprehensive_scan_example(args.host, args.port, args.target)
    else:
        await run_specific_vulnerability_test(args.host, args.port, args.target)

if __name__ == "__main__":
    asyncio.run(main()) 