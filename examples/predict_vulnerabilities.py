#!/usr/bin/env python3
"""
Example script showing how to use the ML module to predict vulnerabilities.

This script demonstrates how to:
1. Load security findings from a file
2. Use the vulnerability prediction model to analyze them
3. Calculate risk scores
4. Display results with highlighting for high-risk findings

Usage:
    python predict_vulnerabilities.py findings.json
"""

import os
import sys
import json
import argparse
from pathlib import Path
import colorama
from colorama import Fore, Style

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.ml.model import predict_vulnerabilities, calculate_risk_scores
from src.results.loader import load_findings


def setup_color():
    """Initialize colorama for colored output."""
    colorama.init()


def get_severity_color(severity):
    """Get appropriate color for a severity level."""
    severity = severity.lower()
    if severity == 'critical':
        return Fore.LIGHTRED_EX
    elif severity == 'high':
        return Fore.RED
    elif severity == 'medium':
        return Fore.YELLOW
    elif severity == 'low':
        return Fore.LIGHTBLUE_EX
    elif severity == 'info':
        return Fore.GREEN
    else:
        return Fore.WHITE


def get_probability_color(probability):
    """Get appropriate color for a probability value."""
    if probability >= 0.8:
        return Fore.LIGHTRED_EX
    elif probability >= 0.6:
        return Fore.RED
    elif probability >= 0.4:
        return Fore.YELLOW
    elif probability >= 0.2:
        return Fore.LIGHTBLUE_EX
    else:
        return Fore.GREEN


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Predict vulnerabilities from security findings using ML"
    )
    parser.add_argument(
        "findings_file", 
        help="Path to a JSON file containing security findings"
    )
    parser.add_argument(
        "--threshold", "-t", 
        type=float, 
        default=0.5, 
        help="Probability threshold for classifying vulnerabilities (0.0-1.0)"
    )
    parser.add_argument(
        "--top", "-n", 
        type=int, 
        default=10, 
        help="Show only top N findings by risk score"
    )
    return parser.parse_args()


def display_findings(findings, scores, threshold=0.5, top_n=10):
    """Display findings with highlighting based on risk and probability."""
    # Sort findings by risk score
    sorted_findings = [
        (finding, scores.get(finding.id, 0))
        for finding in findings
    ]
    sorted_findings.sort(key=lambda x: x[1], reverse=True)
    
    # Take top N
    if top_n > 0:
        sorted_findings = sorted_findings[:top_n]
    
    # Get prediction results
    prediction_results = predict_vulnerabilities(findings)
    probabilities = {finding.id: prob for finding, prob in prediction_results}
    
    # Display header
    print("\n" + "=" * 80)
    print(f"TOP {len(sorted_findings)} FINDINGS BY RISK SCORE")
    print("=" * 80)
    
    # Display findings
    for i, (finding, risk_score) in enumerate(sorted_findings, 1):
        probability = probabilities.get(finding.id, 0)
        severity = getattr(finding, 'severity', 'unknown')
        
        # Highlight findings based on probability and risk
        severity_color = get_severity_color(severity)
        prob_color = get_probability_color(probability)
        
        # Display finding info
        print(f"\n{i}. {Fore.WHITE}{finding.title} {Fore.LIGHTBLACK_EX}(ID: {finding.id})")
        print(f"   Type: {Fore.CYAN}{getattr(finding, 'finding_type', 'unknown')}{Style.RESET_ALL}")
        print(f"   Severity: {severity_color}{severity}{Style.RESET_ALL}")
        print(f"   Target: {Fore.BLUE}{finding.target}{Style.RESET_ALL}")
        print(f"   Risk Score: {get_probability_color(risk_score)}{risk_score:.2f}{Style.RESET_ALL}")
        print(f"   Probability: {prob_color}{probability:.2f}{Style.RESET_ALL}")
        
        # Add a "likely vulnerability" marker if probability is above threshold
        if probability >= threshold:
            print(f"   {Fore.LIGHTRED_EX}[LIKELY VULNERABILITY]{Style.RESET_ALL}")
        
        # Show description (truncated)
        description = getattr(finding, 'description', '')
        if len(description) > 100:
            description = description[:100] + "..."
        print(f"   Description: {Fore.WHITE}{description}{Style.RESET_ALL}")
        print("-" * 80)
    
    # Display summary
    high_risk_count = sum(1 for _, score in sorted_findings if score >= 0.7)
    likely_vuln_count = sum(1 for f, _ in sorted_findings if probabilities.get(f.id, 0) >= threshold)
    
    print("\nSUMMARY:")
    print(f"Total findings analyzed: {len(findings)}")
    print(f"High risk findings (score >= 0.7): {Fore.RED}{high_risk_count}{Style.RESET_ALL}")
    print(f"Likely vulnerabilities (probability >= {threshold}): {Fore.RED}{likely_vuln_count}{Style.RESET_ALL}")
    print("=" * 80)


def main():
    """Main function to analyze findings."""
    args = parse_arguments()
    
    # Initialize colorized output
    setup_color()
    
    print(f"Analyzing findings in {args.findings_file}...")
    
    try:
        # Load findings
        findings = load_findings(args.findings_file)
        if not findings:
            print(f"{Fore.RED}Error: No findings loaded from the file.{Style.RESET_ALL}")
            return 1
        
        print(f"Loaded {len(findings)} findings")
        
        # Calculate risk scores
        risk_scores = calculate_risk_scores(findings)
        
        # Display findings with highlighting
        display_findings(findings, risk_scores, args.threshold, args.top)
        
        return 0
        
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 