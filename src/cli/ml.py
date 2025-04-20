"""
ML CLI Module

This module provides command line interface for vulnerability prediction
and risk assessment using the machine learning models.
"""

import json
import logging
import os
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import matplotlib.pyplot as plt
import pandas as pd
import typer
from colorama import Fore, Style

from src.core.config import load_config
from src.ml.model import (
    VulnerabilityPredictor,
    calculate_risk_scores,
    get_prediction_model,
    predict_vulnerabilities,
)
from src.results.loader import load_findings
from src.results.types import BaseFinding

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("sniper.cli.ml")


# Create format enum for better CLI experience
class OutputFormat(str, Enum):
    """Output formats for ML commands."""

    JSON = "json"
    CSV = "csv"
    TEXT = "text"
    CHART = "chart"  # For visualizations


class VisualizationType(str, Enum):
    """Types of visualizations available."""

    RISK_DISTRIBUTION = "risk_distribution"
    SEVERITY_COMPARISON = "severity_comparison"
    CONFIDENCE_VS_RISK = "confidence_vs_risk"
    FINDINGS_BY_TYPE = "findings_by_type"


# Create typer app
ml = typer.Typer(
    name="ml",
    help="Machine learning commands for vulnerability prediction and risk assessment.",
    add_completion=False,
)


@ml.command("predict")
def predict(
    findings_file: Path = typer.Argument(
        ..., exists=True, help="Path to a JSON file containing security findings"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file for prediction results"
    ),
    threshold: float = typer.Option(
        0.5,
        "--threshold",
        "-t",
        help="Probability threshold for classifying vulnerabilities (0.0-1.0)",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.JSON, "--format", "-f", help="Output format"
    ),
):
    """
    Predict vulnerabilities using the ML model.

    This command takes a findings file (JSON) and applies the vulnerability
    prediction model to assess which findings are likely to be actual
    vulnerabilities requiring attention.
    """
    logger.info(f"Loading findings from {findings_file}")
    try:
        findings = load_findings(findings_file)
        if not findings:
            logger.error("No findings loaded from the file.")
            typer.echo("Error: No findings loaded from the file.", err=True)
            raise typer.Exit(code=1)

        logger.info(f"Loaded {len(findings)} findings, running prediction")
        prediction_results = predict_vulnerabilities(findings)

        # Filter based on threshold
        filtered_results = [
            (finding, score)
            for finding, score in prediction_results
            if score >= threshold
        ]

        logger.info(
            f"Found {len(filtered_results)} findings above threshold {threshold}"
        )

        # Format and output results
        output_prediction_results(filtered_results, output, format)

    except Exception as e:
        logger.error(f"Error processing findings: {str(e)}")
        typer.echo(f"Error: {str(e)}", err=True)
        raise typer.Exit(code=1)


@ml.command("risk")
def risk(
    findings_file: Path = typer.Argument(
        ..., exists=True, help="Path to a JSON file containing security findings"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file for risk assessment"
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.JSON, "--format", "-f", help="Output format"
    ),
    top: int = typer.Option(
        10, "--top", "-n", help="Show only top N highest risk findings"
    ),
):
    """
    Perform risk assessment on security findings.

    This command calculates risk scores for each finding and identifies
    those that pose the highest risk to the system.
    """
    logger.info(f"Loading findings from {findings_file}")
    try:
        findings = load_findings(findings_file)
        if not findings:
            logger.error("No findings loaded from the file.")
            typer.echo("Error: No findings loaded from the file.", err=True)
            raise typer.Exit(code=1)

        logger.info(f"Loaded {len(findings)} findings, calculating risk scores")
        risk_scores = calculate_risk_scores(findings)

        # Sort findings by risk score
        sorted_findings = [
            (finding, risk_scores[finding.id])
            for finding in findings
            if finding.id in risk_scores
        ]
        sorted_findings.sort(key=lambda x: x[1], reverse=True)

        # Take top N if specified
        if top > 0:
            sorted_findings = sorted_findings[:top]

        logger.info(f"Prepared risk assessment for {len(sorted_findings)} findings")

        # Format and output results
        output_risk_results(sorted_findings, output, format)

    except Exception as e:
        logger.error(f"Error performing risk assessment: {str(e)}")
        typer.echo(f"Error: {str(e)}", err=True)
        raise typer.Exit(code=1)


@ml.command("train")
def train(
    training_data: Path = typer.Argument(
        ..., exists=True, help="Path to a CSV/JSON file containing training data"
    ),
    label_column: str = typer.Argument(
        ..., help="Name of the column containing the labels (0 or 1)"
    ),
    model_path: Path = typer.Option(
        "models/vulnerability_model.pkl",
        "--model-path",
        "-m",
        help="Path to save the trained model",
    ),
    test_size: float = typer.Option(
        0.2, "--test-size", help="Proportion of data to use for testing (0.0-1.0)"
    ),
):
    """
    Train the vulnerability prediction model.

    This command trains a new model using labeled data. The data should be in CSV
    or JSON format with one column indicating the true label (is_vulnerability).
    """
    from sklearn.model_selection import train_test_split

    logger.info(f"Loading training data from {training_data}")
    try:
        # Load the training data
        if str(training_data).endswith(".csv"):
            df = pd.read_csv(training_data)
        elif str(training_data).endswith(".json"):
            df = pd.read_json(training_data)
        else:
            logger.error("Training data must be CSV or JSON format")
            typer.echo("Error: Training data must be CSV or JSON format", err=True)
            raise typer.Exit(code=1)

        if label_column not in df.columns:
            logger.error(f"Label column '{label_column}' not found in the data")
            typer.echo(
                f"Error: Label column '{label_column}' not found in the data", err=True
            )
            raise typer.Exit(code=1)

        # Extract labels and data
        labels = df[label_column].values

        # Create a list of finding-like objects for the model
        findings = []
        for _, row in df.iterrows():
            finding = type("FindingLike", (), {})()
            for col in df.columns:
                if col != label_column:
                    setattr(finding, col, row[col])
            findings.append(finding)

        # Create and train the model
        predictor = VulnerabilityPredictor()

        # Train/test split if we have enough data
        if len(findings) > 10:
            train_findings, test_findings, train_labels, test_labels = train_test_split(
                findings, labels, test_size=test_size, random_state=42
            )

            logger.info(
                f"Training on {len(train_findings)} samples, testing on {len(test_findings)} samples"
            )
            typer.echo(
                f"Training on {len(train_findings)} samples, testing on {len(test_findings)} samples"
            )

            if not predictor.train(train_findings, train_labels):
                logger.error("Failed to train the model")
                typer.echo("Error: Failed to train the model", err=True)
                raise typer.Exit(code=1)

            # Evaluate on test set
            predictions = predictor.predict(test_findings)
            evaluate_model(test_labels, predictions)
        else:
            logger.warning(
                "Not enough data for train/test split, using all data for training"
            )
            typer.echo(
                "Warning: Not enough data for train/test split, using all data for training"
            )
            if not predictor.train(findings, labels):
                logger.error("Failed to train the model")
                typer.echo("Error: Failed to train the model", err=True)
                raise typer.Exit(code=1)

        # Save the trained model
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        if predictor.save_model(model_path):
            logger.info(f"Model successfully saved to {model_path}")
            typer.echo(f"Model successfully saved to {model_path}")
        else:
            logger.error("Failed to save the model")
            typer.echo("Error: Failed to save the model", err=True)
            raise typer.Exit(code=1)

    except Exception as e:
        logger.error(f"Error training model: {str(e)}")
        typer.echo(f"Error: {str(e)}", err=True)
        raise typer.Exit(code=1)


@ml.command("visualize")
def visualize(
    findings_file: Path = typer.Argument(
        ..., exists=True, help="Path to a JSON file containing security findings"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file for visualizations"
    ),
    type: VisualizationType = typer.Option(
        VisualizationType.RISK_DISTRIBUTION,
        "--type",
        "-t",
        help="Type of visualization to generate",
    ),
):
    """
    Generate visualizations for security findings.

    This command creates various charts and plots to help analyze security findings
    and risk assessments.
    """
    from collections import Counter

    import matplotlib.pyplot as plt
    import numpy as np

    logger.info(f"Loading findings from {findings_file}")
    try:
        findings = load_findings(findings_file)
        if not findings:
            logger.error("No findings loaded from the file.")
            typer.echo("Error: No findings loaded from the file.", err=True)
            raise typer.Exit(code=1)

        # Generate visualization based on type
        if type == VisualizationType.RISK_DISTRIBUTION:
            risk_scores = calculate_risk_scores(findings)
            scores = list(risk_scores.values())

            plt.figure(figsize=(10, 6))
            plt.hist(scores, bins=20, alpha=0.7, color="blue")
            plt.xlabel("Risk Score")
            plt.ylabel("Number of Findings")
            plt.title("Distribution of Risk Scores")
            plt.grid(True, alpha=0.3)

            # Calculate and show statistics
            mean_score = np.mean(scores)
            median_score = np.median(scores)
            plt.axvline(
                mean_score,
                color="red",
                linestyle="dashed",
                linewidth=1,
                label=f"Mean: {mean_score:.2f}",
            )
            plt.axvline(
                median_score,
                color="green",
                linestyle="dashed",
                linewidth=1,
                label=f"Median: {median_score:.2f}",
            )
            plt.legend()

        elif type == VisualizationType.SEVERITY_COMPARISON:
            # Count findings by severity
            severity_counts = Counter(
                [finding.severity for finding in findings if finding.severity]
            )

            # Create bar chart
            plt.figure(figsize=(10, 6))
            severities = ["critical", "high", "medium", "low", "info"]
            counts = [severity_counts.get(sev, 0) for sev in severities]

            # Use different colors for different severity levels
            colors = ["darkred", "red", "orange", "yellow", "green"]

            plt.bar(severities, counts, color=colors)
            plt.xlabel("Severity Level")
            plt.ylabel("Number of Findings")
            plt.title("Findings by Severity Level")
            plt.grid(True, alpha=0.3, axis="y")

            # Add count labels on top of bars
            for i, count in enumerate(counts):
                plt.text(i, count + 0.5, str(count), ha="center")

        elif type == VisualizationType.CONFIDENCE_VS_RISK:
            # Calculate risk scores
            risk_scores = calculate_risk_scores(findings)

            # Extract confidence values (default to 0.5 if not present)
            confidences = [getattr(finding, "confidence", 0.5) for finding in findings]
            risks = [risk_scores.get(finding.id, 0) for finding in findings]

            plt.figure(figsize=(10, 6))
            plt.scatter(confidences, risks, alpha=0.7)
            plt.xlabel("Confidence")
            plt.ylabel("Risk Score")
            plt.title("Confidence vs. Risk Score")
            plt.grid(True, alpha=0.3)

            # Add a trend line
            if len(confidences) > 1:
                z = np.polyfit(confidences, risks, 1)
                p = np.poly1d(z)
                plt.plot(sorted(confidences), p(sorted(confidences)), "r--", alpha=0.7)

        elif type == VisualizationType.FINDINGS_BY_TYPE:
            # Count findings by type
            type_counts = Counter(
                [getattr(finding, "finding_type", "unknown") for finding in findings]
            )

            # Get the top 10 types by count
            top_types = type_counts.most_common(10)

            plt.figure(figsize=(12, 6))
            types = [t[0] for t in top_types]
            counts = [t[1] for t in top_types]

            # Create horizontal bar chart for better readability of long type names
            plt.barh(types, counts, color="blue", alpha=0.7)
            plt.xlabel("Number of Findings")
            plt.ylabel("Finding Type")
            plt.title("Top 10 Finding Types")
            plt.grid(True, alpha=0.3, axis="x")

            # Add count labels
            for i, count in enumerate(counts):
                plt.text(count + 0.5, i, str(count), va="center")

        # Save or show the visualization
        if output:
            plt.tight_layout()
            plt.savefig(output, dpi=300, bbox_inches="tight")
            logger.info(f"Visualization saved to {output}")
            typer.echo(f"Visualization saved to {output}")
        else:
            plt.tight_layout()
            plt.show()

    except Exception as e:
        logger.error(f"Error generating visualization: {str(e)}")
        typer.echo(f"Error: {str(e)}", err=True)
        raise typer.Exit(code=1)


# Helper functions


def output_prediction_results(
    results: List[Tuple[BaseFinding, float]],
    output: Optional[Path],
    format_type: OutputFormat,
):
    """Format and output prediction results"""
    if format_type == OutputFormat.JSON:
        # Format as JSON
        json_results = [
            {
                "id": finding.id,
                "title": getattr(finding, "title", "Untitled"),
                "type": getattr(finding, "finding_type", "unknown"),
                "severity": getattr(finding, "severity", "unknown"),
                "probability": float(score),
                "description": getattr(finding, "description", ""),
            }
            for finding, score in results
        ]

        output_data = json.dumps(json_results, indent=2)

    elif format_type == OutputFormat.CSV:
        # Format as CSV
        rows = [
            {
                "id": finding.id,
                "title": getattr(finding, "title", "Untitled"),
                "type": getattr(finding, "finding_type", "unknown"),
                "severity": getattr(finding, "severity", "unknown"),
                "probability": float(score),
                "description": getattr(finding, "description", ""),
            }
            for finding, score in results
        ]

        df = pd.DataFrame(rows)
        output_data = df.to_csv(index=False)

    else:  # text format
        # Format as text
        lines = []
        lines.append("VULNERABILITY PREDICTION RESULTS")
        lines.append("=" * 40)
        lines.append(f"Total findings: {len(results)}")
        lines.append("")

        for finding, score in results:
            lines.append(f"ID: {finding.id}")
            lines.append(f"Title: {getattr(finding, 'title', 'Untitled')}")
            lines.append(f"Type: {getattr(finding, 'finding_type', 'unknown')}")
            lines.append(f"Severity: {getattr(finding, 'severity', 'unknown')}")
            lines.append(f"Probability: {score:.2f}")
            lines.append(f"Description: {getattr(finding, 'description', '')[:100]}...")
            lines.append("-" * 40)

        output_data = "\n".join(lines)

    # Output to file or stdout
    if output:
        with open(output, "w") as f:
            f.write(output_data)
        logger.info(f"Results written to {output}")
        typer.echo(f"Results written to {output}")
    else:
        typer.echo(output_data)


def output_risk_results(
    results: List[Tuple[BaseFinding, float]],
    output: Optional[Path],
    format_type: OutputFormat,
):
    """Format and output risk assessment results"""
    if format_type == OutputFormat.JSON:
        # Format as JSON
        json_results = [
            {
                "id": finding.id,
                "title": getattr(finding, "title", "Untitled"),
                "type": getattr(finding, "finding_type", "unknown"),
                "severity": getattr(finding, "severity", "unknown"),
                "risk_score": float(score),
                "description": getattr(finding, "description", ""),
            }
            for finding, score in results
        ]

        output_data = json.dumps(json_results, indent=2)

    elif format_type == OutputFormat.CSV:
        # Format as CSV
        rows = [
            {
                "id": finding.id,
                "title": getattr(finding, "title", "Untitled"),
                "type": getattr(finding, "finding_type", "unknown"),
                "severity": getattr(finding, "severity", "unknown"),
                "risk_score": float(score),
                "description": getattr(finding, "description", ""),
            }
            for finding, score in results
        ]

        df = pd.DataFrame(rows)
        output_data = df.to_csv(index=False)

    elif format_type == OutputFormat.CHART:
        # Create a visual chart of top risks
        import matplotlib.pyplot as plt
        import numpy as np

        # Extract data for plotting
        titles = [
            getattr(finding, "title", f"Finding {finding.id}")[:30]
            for finding, _ in results
        ]
        scores = [score for _, score in results]

        # Create chart
        plt.figure(figsize=(12, 8))
        colors = [
            (
                "darkred"
                if score > 0.8
                else "red" if score > 0.6 else "orange" if score > 0.4 else "yellow"
            )
            for score in scores
        ]

        y_pos = np.arange(len(titles))
        plt.barh(y_pos, scores, color=colors)
        plt.yticks(y_pos, titles)
        plt.xlabel("Risk Score")
        plt.title("Risk Assessment")

        if output:
            plt.tight_layout()
            plt.savefig(output, dpi=300, bbox_inches="tight")
            logger.info(f"Risk chart saved to {output}")
            typer.echo(f"Risk chart saved to {output}")
            return
        else:
            plt.tight_layout()
            plt.show()
            return

    else:  # text format
        # Format as text
        lines = []
        lines.append("RISK ASSESSMENT RESULTS")
        lines.append("=" * 40)
        lines.append(f"Total findings: {len(results)}")
        lines.append("")

        for i, (finding, score) in enumerate(results, 1):
            lines.append(
                f"{i}. {getattr(finding, 'title', f'Finding {finding.id}')} (ID: {finding.id})"
            )
            lines.append(f"   Type: {getattr(finding, 'finding_type', 'unknown')}")
            lines.append(f"   Severity: {getattr(finding, 'severity', 'unknown')}")
            lines.append(f"   Risk Score: {score:.2f}")
            lines.append("")

        output_data = "\n".join(lines)

    # Output to file or stdout
    if output:
        with open(output, "w") as f:
            f.write(output_data)
        logger.info(f"Results written to {output}")
        typer.echo(f"Results written to {output}")
    else:
        typer.echo(output_data)


def evaluate_model(true_labels, predictions, threshold=0.5):
    """Evaluate and display model performance metrics"""
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    # Convert predictions to binary using threshold
    binary_preds = [1 if p >= threshold else 0 for p in predictions]

    # Calculate metrics
    accuracy = accuracy_score(true_labels, binary_preds)
    precision = precision_score(true_labels, binary_preds, zero_division=0)
    recall = recall_score(true_labels, binary_preds, zero_division=0)
    f1 = f1_score(true_labels, binary_preds, zero_division=0)

    try:
        auc = roc_auc_score(true_labels, predictions)
    except:
        auc = 0  # In case of single-class predictions

    # Confusion matrix
    cm = confusion_matrix(true_labels, binary_preds)

    # Display results
    logger.info("Model Evaluation Metrics:")
    logger.info(f"Accuracy: {accuracy:.4f}")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall: {recall:.4f}")
    logger.info(f"F1 Score: {f1:.4f}")
    logger.info(f"AUC: {auc:.4f}")
    logger.info(f"Confusion Matrix:\n{cm}")

    # Also display to the user
    typer.echo("\nModel Evaluation Metrics:")
    typer.echo(f"Accuracy:  {accuracy:.4f}")
    typer.echo(f"Precision: {precision:.4f}")
    typer.echo(f"Recall:    {recall:.4f}")
    typer.echo(f"F1 Score:  {f1:.4f}")
    typer.echo(f"AUC:       {auc:.4f}")

    # Print confusion matrix in a readable format
    typer.echo("\nConfusion Matrix:")
    typer.echo("              Predicted")
    typer.echo("             Neg    Pos")
    typer.echo(f"Actual Neg | {cm[0][0]:<4}   {cm[0][1]:<4}")
    typer.echo(f"       Pos | {cm[1][0]:<4}   {cm[1][1]:<4}")


if __name__ == "__main__":
    ml()
