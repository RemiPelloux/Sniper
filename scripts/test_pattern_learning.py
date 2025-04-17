#!/usr/bin/env python3
"""
Test script for the Pattern Learning module.

This script demonstrates the capabilities of the Pattern Learning module by:
1. Loading sample security findings
2. Training the pattern learner on these findings
3. Extracting common patterns
4. Finding similar patterns for a new finding
5. Analyzing findings for specific patterns
6. Learning from bug bounty reports

Usage:
    python scripts/test_pattern_learning.py

Requirements:
    - All Sniper dependencies must be installed
    - The Pattern Learning module must be implemented
"""

import argparse
import json
import os
import sys
from pprint import pprint
from typing import Any, Dict, List

# Add the src directory to the path so we can import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.ml.pattern_learning import PatternLearner

# Sample findings for demonstration
SAMPLE_FINDINGS = [
    {
        "id": "finding-1",
        "title": "XSS Vulnerability",
        "description": "Cross-site scripting vulnerability found in login form",
        "severity": "high",
        "confidence": "medium",
        "type": "xss",
        "details": "The application does not properly sanitize user input",
        "source": "zap",
    },
    {
        "id": "finding-2",
        "title": "SQL Injection",
        "description": "SQL injection vulnerability found in search function",
        "severity": "critical",
        "confidence": "high",
        "type": "sqli",
        "details": "The application uses unsanitized user input in SQL queries",
        "source": "zap",
    },
    {
        "id": "finding-3",
        "title": "Information Disclosure",
        "description": "Server version information exposed in HTTP headers",
        "severity": "low",
        "confidence": "high",
        "type": "info_disclosure",
        "details": "Server: Apache 2.4.41 (Ubuntu)",
        "source": "nmap",
    },
    {
        "id": "finding-4",
        "title": "Cross-Site Request Forgery",
        "description": "CSRF vulnerability found in profile update form",
        "severity": "medium",
        "confidence": "medium",
        "type": "csrf",
        "details": "The application does not implement CSRF tokens properly",
        "source": "zap",
    },
    {
        "id": "finding-5",
        "title": "Another XSS Vulnerability",
        "description": "Cross-site scripting vulnerability found in comment section",
        "severity": "high",
        "confidence": "high",
        "type": "xss",
        "details": "User input in comments is not properly sanitized",
        "source": "manual",
    },
    {
        "id": "finding-6",
        "title": "Path Traversal",
        "description": "Path traversal vulnerability in file download functionality",
        "severity": "high",
        "confidence": "medium",
        "type": "path_traversal",
        "details": "The application does not properly validate file paths",
        "source": "zap",
    },
    {
        "id": "finding-7",
        "title": "Insecure Direct Object Reference",
        "description": "IDOR vulnerability in user profile access",
        "severity": "medium",
        "confidence": "high",
        "type": "idor",
        "details": "Users can access other user profiles by changing the ID parameter",
        "source": "manual",
    },
]

# Sample bug bounty reports for demonstration
SAMPLE_BUG_BOUNTY_REPORTS = [
    {
        "id": "report-1",
        "title": "Stored XSS in User Profile",
        "description": "I discovered a stored XSS vulnerability in the user profile page",
        "severity": "high",
        "vulnerability_type": "xss",
        "proof_of_concept": "<script>alert(document.cookie)</script> in the bio field",
    },
    {
        "id": "report-2",
        "title": "SQL Injection in Search API",
        "description": "The search API endpoint is vulnerable to SQL injection attacks",
        "severity": "critical",
        "vulnerability_type": "sql injection",
        "proof_of_concept": "' OR 1=1 -- -",
    },
]


def print_section_header(title: str):
    """Print a formatted section header."""
    print("\n" + "=" * 80)
    print(f" {title} ".center(80, "="))
    print("=" * 80 + "\n")


def print_json(data: Any):
    """Print data in a formatted JSON-like structure."""
    print(json.dumps(data, indent=4))


def demo_pattern_learning(args):
    """Run a demonstration of the pattern learning module."""
    print_section_header("Pattern Learning Module Demonstration")

    # Initialize the pattern learner
    print("Initializing PatternLearner...")
    learner = PatternLearner()
    print("✅ PatternLearner initialized")

    # Demonstrate text preprocessing
    print_section_header("Text Preprocessing")
    test_text = "This is a sample text with SQL Injection and XSS vulnerabilities (CVE-2022-12345)."
    preprocessed = learner._preprocess_text(test_text)
    print(f"Original text: {test_text}")
    print(f"Preprocessed: {preprocessed}")

    # Demonstrate feature extraction
    print_section_header("Feature Extraction")
    features = learner._extract_features_from_finding(SAMPLE_FINDINGS[0])
    print("Extracted features from a finding:")
    print_json(features)

    # Train the pattern learner
    print_section_header("Training Pattern Learner")
    train_result = learner.train(SAMPLE_FINDINGS)
    print("Training result:")
    print_json(train_result)

    # Extract common patterns
    print_section_header("Common Patterns")
    patterns = learner.extract_common_patterns(SAMPLE_FINDINGS)
    print(f"Found {len(patterns)} common patterns:")
    for i, pattern in enumerate(patterns):
        print(f"\nPattern {i+1}:")
        print(f"  Text: '{pattern['pattern']}'")
        print(f"  Support: {pattern['support']:.2f} ({pattern['count']} occurrences)")
        print(f"  Found in: {', '.join(pattern['findings'])}")

    # Find instances of a specific pattern
    print_section_header("Pattern Instances")
    pattern_to_search = "cross-site scripting"
    instances = learner.find_pattern_instances(pattern_to_search, SAMPLE_FINDINGS)
    print(f"Findings matching pattern '{pattern_to_search}':")
    for i, instance in enumerate(instances):
        print(f"\nInstance {i+1}:")
        print(f"  ID: {instance['id']}")
        print(f"  Title: {instance['title']}")
        print(f"  Severity: {instance['severity']}")

    # Find similar patterns
    print_section_header("Similar Patterns")
    new_finding = {
        "id": "new-finding",
        "title": "Potential XSS in Comment Form",
        "description": "Cross-site scripting vulnerability may exist in the comment form",
        "severity": "medium",
        "confidence": "low",
        "type": "xss",
        "details": "User input needs proper validation",
    }
    similar = learner.find_similar_patterns(new_finding)
    print("Similar patterns for a new finding:")
    print_json(similar)

    # Learn from bug bounty reports
    print_section_header("Learning from Bug Bounty Reports")
    bb_result = learner.learn_from_bug_bounty(SAMPLE_BUG_BOUNTY_REPORTS)
    print("Bug bounty learning result:")
    print_json(bb_result)

    print_section_header("Demonstration Complete")
    print("The Pattern Learning module has been successfully demonstrated!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test the Pattern Learning module")
    parser.add_argument(
        "--model-dir", type=str, help="Directory to store/load models", default=None
    )
    args = parser.parse_args()

    try:
        demo_pattern_learning(args)
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
