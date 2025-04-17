"""Machine Learning module for vulnerability prediction and risk assessment.

This module provides functionality to analyze security findings using machine
learning techniques, helping to prioritize findings and predict vulnerabilities.
"""

from src.ml.model import (
    VulnerabilityPredictor,
    calculate_risk_scores,
    get_prediction_model,
    predict_vulnerabilities,
)
from src.ml.utils import (
    calculate_vulnerability_score,
    evaluate_model_performance,
    extract_finding_features,
    extract_text_features,
    features_to_vector,
    get_severity_value,
    normalize_features,
)

__all__ = [
    # Main model classes and functions
    "VulnerabilityPredictor",
    "get_prediction_model",
    "predict_vulnerabilities",
    "calculate_risk_scores",
    # Utility functions
    "extract_text_features",
    "normalize_features",
    "calculate_vulnerability_score",
    "get_severity_value",
    "features_to_vector",
    "evaluate_model_performance",
    "extract_finding_features",
]
