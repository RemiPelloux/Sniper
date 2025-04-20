"""
Machine Learning Module for Vulnerability Prediction

This module provides machine learning capabilities for predicting and classifying
vulnerabilities based on scan results and historical data.

Features:
- Vulnerability classification by severity
- Risk prediction based on historical CVE data
- Anomaly detection for identifying unusual patterns
- Feature extraction from scan results
- Model training and evaluation capabilities
"""

import json
import logging
import os
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Import Sniper modules
from src.core.config import settings
from src.core.logging import setup_logging
from src.results.types import BaseFinding

# For Sprint 4 implementation - import specific ML libraries
# import sklearn
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.model_selection import train_test_split
# from sklearn.metrics import classification_report, confusion_matrix
# from sklearn.preprocessing import StandardScaler
# from sklearn.feature_extraction.text import TfidfVectorizer


# Set up logging
logger = logging.getLogger(__name__)
setup_logging()

# Load configuration
ml_config = settings.tool_configs.get("ml", {})


class VulnerabilityPredictor:
    """
    Machine learning model for vulnerability prediction and risk assessment.

    This class implements a machine learning model that analyzes security findings
    to predict potential vulnerabilities and assess risk levels.
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the vulnerability predictor.

        Args:
            model_path: Path to a saved model file. If None, a new model is created.
        """
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()

        if model_path and os.path.exists(model_path):
            self._load_model()
        else:
            self._create_model()

    def _create_model(self) -> None:
        """Create a new prediction model."""
        self.model = RandomForestClassifier(
            n_estimators=100, max_depth=10, random_state=42
        )

    def _load_model(self) -> None:
        """Load a pre-trained model from disk."""
        try:
            with open(self.model_path, "rb") as f:
                saved_data = pickle.load(f)
                self.model = saved_data["model"]
                self.scaler = saved_data.get("scaler", StandardScaler())
        except (IOError, pickle.PickleError) as e:
            print(f"Error loading model: {e}")
            self._create_model()

    def save_model(self, path: Optional[str] = None) -> bool:
        """
        Save the trained model to disk.

        Args:
            path: Path where to save the model. If None, uses the path from initialization.

        Returns:
            bool: True if successful, False otherwise.
        """
        save_path = path or self.model_path
        if not save_path:
            return False

        try:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, "wb") as f:
                pickle.dump({"model": self.model, "scaler": self.scaler}, f)
            return True
        except (IOError, pickle.PickleError) as e:
            print(f"Error saving model: {e}")
            return False

    def extract_features(self, finding: BaseFinding) -> List[float]:
        """
        Extract numerical features from a security finding.

        Args:
            finding: Security finding to extract features from.

        Returns:
            List of numerical features.
        """
        features = []

        # Convert severity to numerical value
        severity_value = self._convert_severity_to_value(finding.severity)
        features.append(severity_value)

        # Add confidence as a feature if available
        confidence = getattr(finding, "confidence", 0.5)
        features.append(float(confidence))

        # Add feature for finding type
        finding_type = getattr(finding, "finding_type", "")
        type_feature = hash(finding_type) % 100 / 100.0  # Normalize to 0-1
        features.append(type_feature)

        # Feature for description length
        desc_length = len(getattr(finding, "description", ""))
        features.append(min(desc_length / 1000, 1.0))  # Normalize to 0-1

        return features

    def _convert_severity_to_value(self, severity: str) -> float:
        """
        Convert severity string to numerical value.

        Args:
            severity: Severity level as string.

        Returns:
            Numerical value representing severity.
        """
        severity_map = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
            "info": 0.1,
            "none": 0.0,
        }
        return severity_map.get(severity.lower(), 0.3)

    def calculate_risk_score(self, finding: BaseFinding) -> float:
        """
        Calculate a risk score for a security finding.

        Args:
            finding: Security finding to score.

        Returns:
            Risk score between 0.0 and 1.0.
        """
        features = self.extract_features(finding)

        # Simple weighted calculation for now
        severity_weight = 0.6
        confidence_weight = 0.3
        type_weight = 0.05
        desc_weight = 0.05

        score = (
            features[0] * severity_weight
            + features[1] * confidence_weight
            + features[2] * type_weight
            + features[3] * desc_weight
        )

        return min(max(score, 0.0), 1.0)  # Ensure score is between 0 and 1

    def train(self, findings: List[BaseFinding], labels: List[int]) -> bool:
        """
        Train the model with security findings.

        Args:
            findings: List of security findings.
            labels: Target labels for training (0 = false positive, 1 = real vulnerability).

        Returns:
            True if training was successful.
        """
        if not findings or len(findings) != len(labels):
            return False

        features = [self.extract_features(finding) for finding in findings]
        features_array = np.array(features)

        # Scale features
        scaled_features = self.scaler.fit_transform(features_array)

        # Train model
        self.model.fit(scaled_features, labels)
        return True

    def predict(self, findings: List[BaseFinding]) -> List[float]:
        """
        Predict the likelihood of findings being actual vulnerabilities.

        Args:
            findings: List of security findings to analyze.

        Returns:
            List of prediction probabilities (0.0 to 1.0).
        """
        if not findings or not self.model:
            return []

        # Check if model has been trained
        if (
            not hasattr(self.model, "estimators_")
            or len(getattr(self.model, "estimators_", [])) == 0
        ):
            # Model not trained yet, return default scores based on severity
            return [
                self._convert_severity_to_value(finding.severity)
                for finding in findings
            ]

        features = [self.extract_features(finding) for finding in findings]
        features_array = np.array(features)

        # Scale features
        scaled_features = self.scaler.transform(features_array)

        # Make predictions
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(scaled_features)
            return [prob[1] for prob in probabilities]  # Return probability of class 1
        else:
            predictions = self.model.predict(scaled_features)
            return [float(pred) for pred in predictions]

    def predict_risk(self, findings: List[BaseFinding]) -> List[float]:
        """Predict risk scores for a list of findings."""
        if not self.model or not self.vectorizer:
            return []

        # Check if model has been trained
        if (
            not hasattr(self.model, "estimators_")
            or len(getattr(self.model, "estimators_", [])) == 0
        ):
            # Model not trained yet, return default scores based on severity
            return [
                self._convert_severity_to_value(finding.severity)
                for finding in findings
            ]

        features = [self.extract_features(finding) for finding in findings]
        features_array = np.array(features)

        # Scale features
        scaled_features = self.scaler.transform(features_array)

        # Make predictions
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(scaled_features)
            predicted_risks = [prob[1] for prob in probabilities]
        else:
            predictions = self.model.predict(scaled_features)
            predicted_risks = [float(pred) for pred in predictions]

        # Assign risk scores back to findings (example, adjust as needed)
        risk_scores = []
        for i, finding in enumerate(findings):
            # finding.risk_score = predicted_risks[i] # Assuming BaseFinding gets a risk_score field
            # finding.predicted_severity = FindingSeverity.INFO # Placeholder
            # log.debug(f"Predicted risk for finding {finding.id}: {predicted_risks[i]}")
            risk_scores.append(predicted_risks[i])

        return risk_scores


def get_prediction_model(model_path: Optional[str] = None) -> VulnerabilityPredictor:
    """
    Get or create a vulnerability prediction model.

    Args:
        model_path: Optional path to a saved model.

    Returns:
        Initialized VulnerabilityPredictor instance.
    """
    # Default model path if none provided
    if model_path is None:
        home_dir = os.path.expanduser("~")
        model_path = os.path.join(home_dir, ".sniper", "ml_model.pkl")

    return VulnerabilityPredictor(model_path)


def predict_vulnerabilities(
    findings: List[BaseFinding], model_path: Optional[str] = None
) -> List[Tuple[BaseFinding, float]]:
    """
    Predict which findings are likely to be actual vulnerabilities.

    Args:
        findings: List of security findings to analyze.
        model_path: Optional path to a saved model.

    Returns:
        List of tuples containing (finding, prediction_score).
    """
    if not findings:
        return []

    predictor = get_prediction_model(model_path)
    try:
        predictions = predictor.predict(findings)
        return list(zip(findings, predictions))
    except AttributeError:
        # If model is not trained, use severity-based scores
        scores = [
            predictor._convert_severity_to_value(finding.severity)
            for finding in findings
        ]
        return list(zip(findings, scores))


def calculate_risk_scores(findings: List[BaseFinding]) -> Dict[str, float]:
    """
    Calculate risk scores for a list of findings.

    Args:
        findings: List of security findings to analyze.

    Returns:
        Dictionary mapping finding IDs to risk scores.
    """
    predictor = get_prediction_model()

    risk_scores = {}
    for finding in findings:
        risk_score = predictor.calculate_risk_score(finding)
        risk_scores[finding.id] = risk_score

    return risk_scores
