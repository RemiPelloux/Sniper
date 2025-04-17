"""
Machine Learning Utilities

This module provides utility functions for the machine learning components
of the application, including feature extraction, data processing, and
evaluation metrics.
"""

import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

# Regex patterns for feature extraction
PATTERNS = {
    "sql_injection": r"(?i)(sql\s*injection|sqli|\bsql\b.*\battack\b)",
    "xss": r"(?i)(cross\s*site\s*scripting|\bxss\b)",
    "command_injection": r"(?i)(command\s*injection|code\s*injection|os\s*command|shell\s*command)",
    "path_traversal": r"(?i)(path\s*traversal|directory\s*traversal|\.\.\/)",
    "authentication": r"(?i)(auth.*fail|weak\s*password|brute\s*force|credential)",
    "authorization": r"(?i)(authorization|permission|privilege|access\s*control)",
    "information_disclosure": r"(?i)(information\s*disclosure|data\s*leak|sensitive\s*data)",
    "security_misconfiguration": r"(?i)(misconfiguration|default\s*config|insecure\s*setting)",
    "cve": r"CVE-\d{4}-\d{4,7}",
}

# Risk weights for different vulnerability types
VULNERABILITY_WEIGHTS = {
    "sql_injection": 0.9,
    "command_injection": 0.9,
    "xss": 0.8,
    "path_traversal": 0.7,
    "authentication": 0.7,
    "authorization": 0.6,
    "information_disclosure": 0.5,
    "security_misconfiguration": 0.5,
    "other": 0.3,
}

# Severity mapping
SEVERITY_MAPPING = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.1,
    "none": 0.0,
}


def extract_text_features(text: str) -> Dict[str, float]:
    """
    Extract features from text descriptions using regex patterns.

    Args:
        text: The text to analyze

    Returns:
        Dictionary of feature names and their values
    """
    if not text or not isinstance(text, str):
        return {}

    features = {}

    # Check for each pattern
    for feature_name, pattern in PATTERNS.items():
        matches = re.findall(pattern, text)
        features[f"{feature_name}_count"] = len(matches)
        features[f"{feature_name}_present"] = 1.0 if matches else 0.0

    # Add text length as a feature
    features["text_length"] = len(text)

    # Add word count
    features["word_count"] = len(text.split())

    return features


def normalize_features(features: Dict[str, float]) -> Dict[str, float]:
    """
    Normalize numerical features to the 0-1 range.

    Args:
        features: Dictionary of feature names and their raw values

    Returns:
        Dictionary of feature names with normalized values
    """
    normalized = features.copy()

    # Normalize text length (typical range 10-1000)
    if "text_length" in normalized:
        normalized["text_length"] = min(1.0, normalized["text_length"] / 1000.0)

    # Normalize word count (typical range 2-200)
    if "word_count" in normalized:
        normalized["word_count"] = min(1.0, normalized["word_count"] / 200.0)

    return normalized


def calculate_vulnerability_score(features: Dict[str, float]) -> float:
    """
    Calculate a vulnerability score based on extracted features.

    Args:
        features: Dictionary of feature names and their values

    Returns:
        A score between 0 and 1 indicating vulnerability severity
    """
    score = 0.0
    total_weight = 0.0

    # Add weighted scores for each vulnerability type
    for vuln_type, weight in VULNERABILITY_WEIGHTS.items():
        if f"{vuln_type}_present" in features and features[f"{vuln_type}_present"] > 0:
            score += weight
            total_weight += 1.0

    # Normalize if we found any vulnerabilities
    if total_weight > 0:
        score = score / total_weight

    return score


def get_severity_value(severity: str) -> float:
    """
    Convert a severity string to a numerical value.

    Args:
        severity: String severity level

    Returns:
        Numerical value between 0 and 1
    """
    severity = severity.lower() if severity else "none"
    return SEVERITY_MAPPING.get(severity, 0.3)  # Default to 0.3 for unknown values


def features_to_vector(
    features: Dict[str, float], feature_names: List[str] = None
) -> np.ndarray:
    """
    Convert a features dictionary to a feature vector.

    Args:
        features: Dictionary of feature names and their values
        feature_names: Optional list of feature names to include

    Returns:
        Numpy array of feature values
    """
    if feature_names is None:
        feature_names = sorted(features.keys())

    return np.array([features.get(name, 0.0) for name in feature_names])


def evaluate_model_performance(
    true_labels: List[int], predictions: List[float], threshold: float = 0.5
) -> Dict[str, float]:
    """
    Evaluate model performance using standard metrics.

    Args:
        true_labels: List of true binary labels (0 or 1)
        predictions: List of predicted probabilities
        threshold: Threshold for converting probabilities to binary predictions

    Returns:
        Dictionary of performance metrics
    """
    if not true_labels or not predictions or len(true_labels) != len(predictions):
        return {}

    # Convert predictions to binary using threshold
    binary_preds = [1 if p >= threshold else 0 for p in predictions]

    # Calculate basic counts
    tp = sum(1 for t, p in zip(true_labels, binary_preds) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(true_labels, binary_preds) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(true_labels, binary_preds) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(true_labels, binary_preds) if t == 1 and p == 0)

    # Calculate metrics
    accuracy = (tp + tn) / len(true_labels) if len(true_labels) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = (
        2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
    }


def extract_finding_features(finding: Any) -> Dict[str, float]:
    """
    Extract features from a finding object.

    Args:
        finding: A finding object with severity, description, and type attributes

    Returns:
        Dictionary of features extracted from the finding
    """
    features = {}

    # Extract basic properties
    if hasattr(finding, "severity") and finding.severity:
        features["severity"] = get_severity_value(finding.severity)

    if hasattr(finding, "confidence") and finding.confidence is not None:
        features["confidence"] = float(finding.confidence)
    else:
        features["confidence"] = 0.5  # Default confidence

    # Extract type-based features
    if hasattr(finding, "finding_type") and finding.finding_type:
        finding_type = finding.finding_type.lower()
        for vuln_type in VULNERABILITY_WEIGHTS:
            if vuln_type in finding_type:
                features[f"{vuln_type}_present"] = 1.0
                features["vulnerability_weight"] = VULNERABILITY_WEIGHTS.get(
                    vuln_type, VULNERABILITY_WEIGHTS["other"]
                )
                break
        else:
            features["vulnerability_weight"] = VULNERABILITY_WEIGHTS["other"]

    # Extract text features if description is available
    if hasattr(finding, "description") and finding.description:
        text_features = extract_text_features(finding.description)
        features.update(text_features)

    return features
