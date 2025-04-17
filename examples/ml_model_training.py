#!/usr/bin/env python3
"""
Example script for training the ML model using simulated security finding data.

This script demonstrates how to:
1. Generate synthetic security findings
2. Label findings as vulnerabilities or non-vulnerabilities
3. Train the vulnerability prediction model
4. Evaluate the model performance
5. Save the trained model

Usage:
    python ml_model_training.py
"""

import argparse
import json
import os
import random

# Add the project root to the Python path
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.ml.model import VulnerabilityPredictor, get_prediction_model
from src.results.types import BaseFinding, FindingSeverity


def create_sample_finding(
    id, severity, finding_type, description, is_vulnerability=False, confidence=None
):
    """Create a sample finding with required attributes."""
    finding = type("FindingObject", (), {})()
    finding.id = id
    finding.title = f"Sample {finding_type} finding #{id}"
    finding.severity = severity
    finding.finding_type = finding_type
    finding.description = description
    finding.target = "https://example.com"
    finding.source_tool = "sample-generator"
    finding.is_vulnerability = is_vulnerability

    # Set confidence if provided, otherwise based on vulnerability status
    if confidence is not None:
        finding.confidence = confidence
    else:
        finding.confidence = (
            random.uniform(0.7, 0.9) if is_vulnerability else random.uniform(0.1, 0.6)
        )

    return finding


def generate_sample_findings(count=100):
    """Generate sample findings for training the model."""
    findings = []

    # Define possible characteristics
    severities = ["critical", "high", "medium", "low", "info"]

    finding_types = [
        "sql_injection",
        "xss",
        "csrf",
        "command_injection",
        "path_traversal",
        "information_disclosure",
        "authentication_bypass",
        "insecure_configuration",
        "weak_cryptography",
        "authorization_issue",
        "general_security",
        "missing_headers",
    ]

    # Text templates for descriptions
    vuln_templates = [
        "A {severity} {type} vulnerability was found in {component}.",
        "Security issue detected: {type} in {component} with {severity} impact.",
        "{type} vulnerability allows attackers to {impact} using {vector}.",
        "The {component} is vulnerable to {type} attacks, with {severity} risk.",
        "Detected {severity} {type} vulnerability that could lead to {impact}.",
    ]

    nonvuln_templates = [
        "Potential {type} issue found in {component}, but verification failed.",
        "The system uses {component} which is typically secure against {type}.",
        "Information gathering: {component} version detected.",
        "Configuration note: {component} settings could be optimized.",
        "Good security practice found in {component}.",
    ]

    components = [
        "login form",
        "user authentication system",
        "database query",
        "file upload",
        "URL parameters",
        "API endpoint",
        "payment processing",
        "admin interface",
        "password storage",
        "session management",
        "configuration file",
        "error handling",
    ]

    impacts = [
        "access sensitive data",
        "execute arbitrary code",
        "escalate privileges",
        "bypass authentication",
        "modify data",
        "perform unauthorized actions",
        "impersonate users",
        "leak information",
        "disrupt service",
        "tamper with logs",
    ]

    vectors = [
        "specially crafted requests",
        "manipulated input",
        "intercepted traffic",
        "session fixation",
        "brute force attacks",
        "CSRF tokens",
        "broken validation",
        "missing encryption",
        "outdated components",
        "misconfiguration",
        "default credentials",
    ]

    # Generate findings
    for i in range(count):
        # Determine if this will be a vulnerability
        is_vuln = random.random() < 0.6  # 60% of findings are vulnerabilities

        # Select characteristics more realistically
        if is_vuln:
            # Vulnerabilities are more likely to have higher severity
            severity = random.choices(
                severities, weights=[0.15, 0.25, 0.35, 0.15, 0.1], k=1
            )[0]
            # Select a finding type that's more likely to be a vulnerability
            finding_type = random.choices(
                finding_types[:8],  # First 8 are more likely to be vulnerabilities
                weights=[0.2, 0.2, 0.1, 0.15, 0.1, 0.1, 0.1, 0.05],
                k=1,
            )[0]

            # Create a description using vulnerability templates
            template = random.choice(vuln_templates)
            description = template.format(
                severity=severity,
                type=finding_type.replace("_", " "),
                component=random.choice(components),
                impact=random.choice(impacts),
                vector=random.choice(vectors),
            )

            # Sometimes add "CVE" to descriptions for critical/high vulnerabilities
            if severity in ["critical", "high"] and random.random() < 0.3:
                year = random.randint(2018, 2023)
                cve_id = random.randint(1000, 9999)
                description += f" See CVE-{year}-{cve_id} for details."

        else:
            # Non-vulnerabilities are more likely to have lower severity
            severity = random.choices(
                severities, weights=[0.05, 0.1, 0.2, 0.3, 0.35], k=1
            )[0]
            # Select a finding type that's more likely to be a non-vulnerability
            finding_type = random.choices(
                finding_types,
                weights=[
                    0.05,
                    0.05,
                    0.05,
                    0.05,
                    0.1,
                    0.1,
                    0.1,
                    0.1,
                    0.1,
                    0.1,
                    0.1,
                    0.1,
                ],
                k=1,
            )[0]

            # Create a description using non-vulnerability templates
            template = random.choice(nonvuln_templates)
            description = template.format(
                severity=severity,
                type=finding_type.replace("_", " "),
                component=random.choice(components),
            )

        finding = create_sample_finding(
            id=f"finding-{i+1}",
            severity=severity,
            finding_type=finding_type,
            description=description,
            is_vulnerability=is_vuln,
        )

        findings.append(finding)

    return findings


def save_findings_to_file(findings, output_file):
    """Save generated findings to a JSON file."""
    # Convert findings to dictionaries
    findings_data = []
    for finding in findings:
        finding_dict = {
            attr: getattr(finding, attr)
            for attr in dir(finding)
            if not attr.startswith("__") and not callable(getattr(finding, attr))
        }
        findings_data.append(finding_dict)

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Save as JSON
    with open(output_file, "w") as f:
        json.dump(findings_data, f, indent=2)

    print(f"Saved {len(findings)} findings to {output_file}")


def train_and_evaluate_model(findings, model_output_path):
    """Train and evaluate the vulnerability prediction model."""
    # Extract data and labels
    labels = [1 if f.is_vulnerability else 0 for f in findings]

    # Split into training and testing sets
    train_findings, test_findings, train_labels, test_labels = train_test_split(
        findings, labels, test_size=0.3, random_state=42
    )

    print(
        f"Training on {len(train_findings)} findings, testing on {len(test_findings)} findings"
    )

    # Create and train the model
    predictor = VulnerabilityPredictor()

    print("Training model...")
    result = predictor.train(train_findings, train_labels)

    if not result:
        print("Error: Failed to train the model")
        return

    # Make predictions on the test set
    print("Testing model...")
    predictions = predictor.predict(test_findings)

    # Convert to binary predictions using 0.5 threshold
    binary_preds = [1 if p >= 0.5 else 0 for p in predictions]

    # Calculate metrics
    accuracy = accuracy_score(test_labels, binary_preds)
    precision = precision_score(test_labels, binary_preds, zero_division=0)
    recall = recall_score(test_labels, binary_preds, zero_division=0)
    f1 = f1_score(test_labels, binary_preds, zero_division=0)

    print("\nModel Evaluation Results:")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")

    # Save the model
    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    if predictor.save_model(model_output_path):
        print(f"Model saved to {model_output_path}")
    else:
        print("Error: Failed to save model")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Train a vulnerability prediction model with synthetic data"
    )
    parser.add_argument(
        "--count", type=int, default=500, help="Number of findings to generate"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/synthetic_findings.json",
        help="Output file for findings",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="models/vulnerability_model.pkl",
        help="Output file for model",
    )
    return parser.parse_args()


def main():
    """Main function to generate data and train the model."""
    args = parse_arguments()

    print(f"Generating {args.count} synthetic security findings...")
    findings = generate_sample_findings(args.count)

    # Save findings to file
    save_findings_to_file(findings, args.output)

    # Train and evaluate the model
    train_and_evaluate_model(findings, args.model)

    print("\nDone! The model is now ready to use for vulnerability prediction.")
    print("You can use the following command to predict vulnerabilities:")
    print(f"  python -m src.cli.ml predict {args.output} --threshold 0.7")
    print("\nOr to calculate risk scores:")
    print(
        f"  python -m src.cli.ml risk {args.output} --format chart --output risk_chart.png"
    )


if __name__ == "__main__":
    main()
