"""Machine Learning module for vulnerability prediction and risk assessment.

This module provides functionality to analyze security findings using machine
learning techniques, helping to prioritize findings and predict vulnerabilities.
"""

from src.ml.model import (
    VulnerabilityPredictor,
    get_prediction_model,
    predict_vulnerabilities,
    calculate_risk_scores
)

from src.ml.utils import (
    extract_text_features,
    normalize_features,
    calculate_vulnerability_score,
    get_severity_value,
    features_to_vector,
    evaluate_model_performance,
    extract_finding_features
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
    "extract_finding_features"
] 