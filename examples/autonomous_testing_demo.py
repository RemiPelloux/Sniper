#!/usr/bin/env python3
"""
Demo of Autonomous Vulnerability Testing Capabilities

This script demonstrates the autonomous testing features including:
1. Tool discovery and evaluation
2. Dynamic payload generation
3. Automatic vulnerability testing for various vulnerability types
4. Self-improvement through ML-based feedback
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Union

# Add the parent directory to sys.path
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
sys.path.append(str(parent_dir))

from src.ml.autonomous_tester import AutonomousTester, PayloadResult, VulnerabilityType


def print_header(title):
    """Print a formatted header"""
    print("\n" + "=" * 80)
    print(f" {title} ".center(80, "="))
    print("=" * 80 + "\n")


def print_results(results: List[PayloadResult]):
    """Print formatted payload test results"""
    for i, result in enumerate(results, 1):
        status = "✅ SUCCESS" if result.success else "❌ FAILED"
        print(f"\n[{i}] Payload: {result.payload.value}")
        print(f"    Type: {result.payload.vulnerability_type.value}")
        print(f"    Status: {status}")
        if result.evidence:
            print(f"    Evidence: {result.evidence}")
        if result.response_code:
            print(f"    Response Code: {result.response_code}")
        if result.response_time:
            print(f"    Response Time: {result.response_time:.2f}s")
        if result.notes:
            print(f"    Notes: {result.notes}")


def demo_tool_discovery(tester: AutonomousTester):
    """Demonstrate the tool discovery capabilities"""
    print_header("Tool Discovery Demo")

    print("🔍 Discovering new security tools...")
    new_tools = tester.discover_new_tools(max_tools=3)

    print(f"Found {len(new_tools)} new security tools:")
    for i, tool in enumerate(new_tools, 1):
        print(f"\n[{i}] {tool['name']}")
        print(f"    Description: {tool['description']}")
        print(f"    URL: {tool['url']}")
        print(f"    Stars: {tool['stars']}")
        print(f"    Language: {tool['language']}")

    # Select a vulnerability type to get tool recommendations
    print("\n🔍 Getting tool recommendations for XSS testing...")
    xss_tools = tester.tool_discovery.get_recommended_tools(
        VulnerabilityType.XSS, count=2
    )

    print(f"\nRecommended tools for XSS testing:")
    for i, tool in enumerate(xss_tools, 1):
        print(f"[{i}] {tool['name']} (Score: {tool['score']:.2f})")
        print(f"    Description: {tool['description']}")


def demo_payload_generation(tester: AutonomousTester):
    """Demonstrate the payload generation capabilities"""
    print_header("Payload Generation Demo")

    # Generate XSS payloads
    print("🔍 Generating XSS payloads...")
    xss_payloads = tester.payload_generator.generate_payloads(
        VulnerabilityType.XSS, count=3
    )

    print(f"Generated {len(xss_payloads)} XSS payloads:")
    for i, payload in enumerate(xss_payloads, 1):
        print(f"\n[{i}] {payload.value}")
        print(f"    Context: {payload.context}")
        print(f"    Description: {payload.description}")

    # Generate SQL injection payloads
    print("\n🔍 Generating SQL Injection payloads...")
    sqli_payloads = tester.payload_generator.generate_payloads(
        VulnerabilityType.SQLI, count=3
    )

    print(f"Generated {len(sqli_payloads)} SQL Injection payloads:")
    for i, payload in enumerate(sqli_payloads, 1):
        print(f"\n[{i}] {payload.value}")
        print(f"    Description: {payload.description}")

    # Generate CSRF payloads
    print("\n🔍 Generating CSRF payloads...")
    csrf_payloads = tester.payload_generator.generate_payloads(
        VulnerabilityType.CSRF, count=2
    )

    print(f"Generated {len(csrf_payloads)} CSRF payloads:")
    for i, payload in enumerate(csrf_payloads, 1):
        print(f"\n[{i}] {payload.value}")
        print(f"    Context: {payload.context}")
        print(f"    Description: {payload.description}")


def demo_vulnerability_testing(tester: AutonomousTester, target_url: str):
    """Demonstrate vulnerability testing against a target"""
    print_header(f"Vulnerability Testing Demo against {target_url}")

    # Test for XSS vulnerabilities
    print("🔍 Testing for XSS vulnerabilities...")
    xss_results = tester.test_vulnerability(
        target_url=target_url, vulnerability_type=VulnerabilityType.XSS, count=3
    )

    print(f"XSS Test Results:")
    print_results(xss_results)

    # Test for SQL Injection vulnerabilities
    print("\n🔍 Testing for SQL Injection vulnerabilities...")
    sqli_results = tester.test_vulnerability(
        target_url=target_url, vulnerability_type=VulnerabilityType.SQLI, count=3
    )

    print(f"SQL Injection Test Results:")
    print_results(sqli_results)


def demo_comprehensive_scan(tester: AutonomousTester, target_url: str):
    """Demonstrate a comprehensive vulnerability scan"""
    print_header(f"Comprehensive Vulnerability Scan of {target_url}")

    print("🔍 Performing comprehensive vulnerability scan...")
    print("This will test for multiple vulnerability types including:")
    for vuln_type in VulnerabilityType:
        print(f"- {vuln_type.value}")

    print("\nScanning in progress...")
    results = tester.comprehensive_scan(
        target_url=target_url, params={"id": "1", "page": "home"}
    )

    # Generate and print summary
    summary = tester.get_summary(results)

    print("\n📊 Scan Summary:")
    print(f"Total tests performed: {summary['total_tests']}")
    print(f"Successful tests: {summary['successful_tests']}")

    if summary["vulnerabilities_found"]:
        print(f"\nVulnerabilities found ({len(summary['vulnerabilities_found'])}):")
        for vuln_type in summary["vulnerabilities_found"]:
            print(f"- {vuln_type}")
            details = summary["details"][vuln_type]
            print(f"  Tests: {details['tests']}, Successful: {details['successful']}")

            print("  Successful payloads:")
            for i, payload in enumerate(details["payloads"], 1):
                print(f"  [{i}] {payload['value']}")
                if payload["evidence"]:
                    print(f"      Evidence: {payload['evidence']}")
    else:
        print("\nNo vulnerabilities found.")


def main():
    """Main demo function"""
    # Initialize the autonomous tester
    tester = AutonomousTester()

    # Target URL for testing
    # NOTE: Use only against your own test servers with proper authorization
    test_target = "https://example.com"  # Replace with your test target

    # Display welcome message
    print_header("Autonomous Vulnerability Testing Demo")
    print(
        "This demo showcases the autonomous testing capabilities of the Sniper toolkit"
    )
    print(
        "\nWARNING: Only test against systems you own or have explicit permission to test!"
    )

    # Run demonstrations
    demo_tool_discovery(tester)
    demo_payload_generation(tester)

    # Ask for permission before testing against a target
    print("\nWould you like to run tests against a target? (yes/no)")
    response = input("> ").strip().lower()

    if response in ["yes", "y"]:
        print("\nEnter target URL to test (leave empty to use example.com):")
        target_input = input("> ").strip()

        if target_input:
            test_target = target_input

        print(f"\nUsing target: {test_target}")
        print("Note: For demonstration purposes, limited testing will be performed.")

        # Run vulnerability testing demos
        demo_vulnerability_testing(tester, test_target)
        demo_comprehensive_scan(tester, test_target)
    else:
        print("\nSkipping target testing. Demo complete.")


if __name__ == "__main__":
    main()
