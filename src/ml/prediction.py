"""
ML Prediction Module

This module provides vulnerability prediction capabilities for the Sniper security
scanning tool. It uses machine learning models to predict vulnerabilities based on
patterns in collected data, analyze potential attack vectors, and prioritize findings.

The module supports:
1. Vulnerability prediction based on collected data
2. Attack chain analysis and visualization
3. Risk prioritization based on learned patterns
4. Integration with the distributed scanning system
"""

import json
import logging
import os
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from pydantic import BaseModel, Field
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from src.ml.utils import extract_features, normalize_features
from src.results.types import BaseFinding

# Setup logging
logger = logging.getLogger(__name__)


class PredictionModel:
    """Machine learning model for vulnerability prediction."""

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the prediction model.

        Args:
            model_path: Optional path to a saved model file. If not provided,
                       the default model will be loaded.
        """
        self.model = None
        self.scaler = None
        self.feature_names = []

        # If path not provided, use default model path
        if not model_path:
            model_dir = Path(__file__).parent / "models"
            model_path = model_dir / "vulnerability_predictor.pkl"

        # Load model if it exists
        if os.path.exists(model_path):
            try:
                with open(model_path, "rb") as f:
                    model_data = pickle.load(f)
                    self.model = model_data.get("model")
                    self.scaler = model_data.get("scaler")
                    self.feature_names = model_data.get("feature_names", [])
                logger.info(f"Loaded prediction model from {model_path}")
            except Exception as e:
                logger.error(f"Failed to load model from {model_path}: {e}")
                self._initialize_default_model()
        else:
            logger.warning(
                f"Model not found at {model_path}, initializing default model"
            )
            self._initialize_default_model()

    def _initialize_default_model(self):
        """Initialize a default model when no saved model is available."""
        self.model = RandomForestClassifier(
            n_estimators=100, max_depth=10, random_state=42
        )
        self.scaler = StandardScaler()
        self.feature_names = [
            "url_depth",
            "param_count",
            "has_auth",
            "content_type_risk",
            "technology_risk",
            "path_risk",
            "param_risk",
        ]
        logger.info("Initialized default prediction model")

    def save_model(self, path: str):
        """
        Save the current model to file.

        Args:
            path: Path where the model will be saved.
        """
        if not self.model:
            logger.error("No model to save")
            return False

        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(path), exist_ok=True)

            # Save model, scaler and feature names
            model_data = {
                "model": self.model,
                "scaler": self.scaler,
                "feature_names": self.feature_names,
            }

            with open(path, "wb") as f:
                pickle.dump(model_data, f)

            logger.info(f"Model saved to {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save model to {path}: {e}")
            return False

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make predictions about vulnerability likelihood based on features.

        Args:
            features: Dictionary of features extracted from a target.

        Returns:
            Dictionary containing prediction results with probabilities.
        """
        if not self.model:
            logger.error("Model not loaded")
            return {"error": "Model not loaded"}

        try:
            # Extract and prepare features
            feature_vector = self._prepare_features(features)

            # Make prediction
            prediction = self.model.predict([feature_vector])[0]

            # Get prediction probabilities
            probabilities = self.model.predict_proba([feature_vector])[0]

            # Convert probabilities to percentages rounded to 2 decimal places
            class_probabilities = {
                str(i): round(float(prob) * 100, 2)
                for i, prob in enumerate(probabilities)
            }

            # Determine risk level based on vulnerability probability
            vuln_probability = class_probabilities.get("1", 0)
            risk_level = self._determine_risk_level(vuln_probability)

            return {
                "prediction": int(prediction),
                "probabilities": class_probabilities,
                "risk_level": risk_level,
                "confidence": self._calculate_confidence(probabilities),
            }
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {"error": str(e)}

    def _prepare_features(self, features: Dict[str, Any]) -> List[float]:
        """
        Prepare features for prediction.

        Args:
            features: Dictionary of raw features.

        Returns:
            List of feature values in the correct order for the model.
        """
        # Create a vector with features in the correct order
        feature_vector = []

        for feature_name in self.feature_names:
            feature_value = features.get(feature_name, 0)
            feature_vector.append(feature_value)

        # Scale features if scaler exists
        if self.scaler:
            feature_vector = self.scaler.transform([feature_vector])[0]

        return feature_vector

    def _determine_risk_level(self, vulnerability_probability: float) -> str:
        """
        Determine risk level based on vulnerability probability.

        Args:
            vulnerability_probability: Probability of vulnerability presence (0-100).

        Returns:
            Risk level as string (critical, high, medium, low, info).
        """
        if vulnerability_probability >= 80:
            return "critical"
        elif vulnerability_probability >= 60:
            return "high"
        elif vulnerability_probability >= 40:
            return "medium"
        elif vulnerability_probability >= 20:
            return "low"
        else:
            return "info"

    def _calculate_confidence(self, probabilities: np.ndarray) -> float:
        """
        Calculate confidence level for the prediction.

        Args:
            probabilities: Array of class probabilities.

        Returns:
            Confidence score between 0-1.
        """
        # Get the maximum probability
        max_prob = max(probabilities)

        # Confidence is high if the model strongly favors one class
        return round(float(max_prob), 2)

    def train(self, training_data: Union[str, pd.DataFrame]) -> bool:
        """
        Train the prediction model with new data.

        Args:
            training_data: Either a path to a CSV file or a pandas DataFrame
                          containing training data.

        Returns:
            True if training was successful, False otherwise.
        """
        try:
            # Load data if a file path is provided
            if isinstance(training_data, str):
                if not os.path.exists(training_data):
                    logger.error(f"Training data file not found: {training_data}")
                    return False

                df = pd.read_csv(training_data)
            else:
                df = training_data

            # Check if dataframe has required columns
            required_columns = self.feature_names + ["has_vulnerability"]
            missing_columns = [col for col in required_columns if col not in df.columns]

            if missing_columns:
                logger.error(
                    f"Missing required columns in training data: {missing_columns}"
                )
                return False

            # Extract features and target
            X = df[self.feature_names].values
            y = df["has_vulnerability"].values

            # Scale features
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)

            # Train model
            self.model = RandomForestClassifier(
                n_estimators=100, max_depth=10, random_state=42
            )
            self.model.fit(X_scaled, y)

            logger.info("Model training completed successfully")
            return True
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return False


class PredictionService:
    """Service for managing vulnerability predictions and risk assessment."""

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the prediction service.

        Args:
            model_path: Optional path to model file.
        """
        self.model = PredictionModel(model_path)
        self.min_confidence_threshold = (
            0.6  # Minimum confidence to consider a prediction
        )

    def analyze_target(self, target_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a target for potential vulnerabilities.

        Args:
            target_data: Target information, including URL, parameters, technologies, etc.

        Returns:
            Dictionary with analysis results.
        """
        # Extract features from target data
        features = extract_features(target_data)

        # Normalize features
        normalized_features = normalize_features(features)

        # Get prediction
        prediction = self.model.predict(normalized_features)

        # Add additional analysis information
        result = {
            **prediction,
            "target": target_data.get("url", ""),
            "analysis_timestamp": pd.Timestamp.now().isoformat(),
            "recommended_actions": self._get_recommended_actions(
                prediction, target_data
            ),
        }

        return result

    def analyze_findings(self, findings: List[BaseFinding]) -> Dict[str, Any]:
        """
        Analyze a list of findings to identify patterns and prioritize vulnerabilities.

        Args:
            findings: List of BaseFinding objects.

        Returns:
            Dictionary with analysis results, including prioritized findings.
        """
        if not findings:
            return {
                "prioritized_findings": [],
                "risk_summary": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                "recommendations": [],
            }

        # Convert findings to feature dictionaries
        feature_dicts = []
        for finding in findings:
            feature_dict = self._finding_to_features(finding)
            feature_dicts.append(feature_dict)

        # Get predictions for each finding
        predictions = []
        for feature_dict in feature_dicts:
            prediction = self.model.predict(feature_dict)
            predictions.append(prediction)

        # Pair findings with predictions
        finding_predictions = list(zip(findings, predictions))

        # Sort by risk level and probability
        risk_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        sorted_findings = sorted(
            finding_predictions,
            key=lambda x: (
                risk_levels.get(x[1]["risk_level"], 0),
                x[1]["probabilities"].get("1", 0),
            ),
            reverse=True,
        )

        # Count findings by risk level
        risk_summary = {level: 0 for level in risk_levels.keys()}
        for _, prediction in sorted_findings:
            risk_level = prediction["risk_level"]
            risk_summary[risk_level] += 1

        # Generate prioritized findings list
        prioritized_findings = []
        for finding, prediction in sorted_findings:
            if prediction.get("confidence", 0) >= self.min_confidence_threshold:
                prioritized_findings.append(
                    {"finding": finding.dict(), "prediction": prediction}
                )

        # Generate recommendations based on findings
        recommendations = self._generate_recommendations(sorted_findings)

        return {
            "prioritized_findings": prioritized_findings,
            "risk_summary": risk_summary,
            "recommendations": recommendations,
        }

    def _finding_to_features(self, finding: BaseFinding) -> Dict[str, Any]:
        """
        Convert a finding to feature dictionary for prediction.

        Args:
            finding: BaseFinding object.

        Returns:
            Dictionary of features.
        """
        # Extract basic features
        features = {
            "url_depth": 0,
            "param_count": 0,
            "has_auth": 0,
            "content_type_risk": 0,
            "technology_risk": 0,
            "path_risk": 0,
            "param_risk": 0,
        }

        # Web finding specific features
        if hasattr(finding, "url") and finding.url:
            from urllib.parse import urlparse

            parsed_url = urlparse(finding.url)
            path_parts = parsed_url.path.strip("/").split("/")

            features["url_depth"] = len(path_parts)

            # Check for high-risk path segments
            high_risk_paths = ["admin", "login", "config", "setup", "install"]
            for high_risk in high_risk_paths:
                if high_risk in path_parts:
                    features["path_risk"] += 1

            # Parameter count and risk
            if hasattr(finding, "parameter") and finding.parameter:
                features["param_count"] = 1

                # Check for high-risk parameters
                high_risk_params = ["id", "file", "redirect", "cmd", "exec"]
                if any(param in finding.parameter for param in high_risk_params):
                    features["param_risk"] += 1

        # Use severity as a feature
        severity_risk = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

        if hasattr(finding, "severity"):
            severity = (
                finding.severity.lower()
                if isinstance(finding.severity, str)
                else "info"
            )
            content_type_risk = severity_risk.get(severity, 1)
            features["content_type_risk"] = content_type_risk

        return features

    def _get_recommended_actions(
        self, prediction: Dict[str, Any], target_data: Dict[str, Any]
    ) -> List[str]:
        """
        Generate recommended actions based on prediction and target data.

        Args:
            prediction: Prediction results.
            target_data: Target information.

        Returns:
            List of recommended actions.
        """
        recommendations = []
        risk_level = prediction.get("risk_level", "info")

        # Add generic recommendations based on risk level
        if risk_level in ("critical", "high"):
            recommendations.append(
                "Perform comprehensive security scanning immediately"
            )
            recommendations.append("Implement input validation and sanitization")

        if risk_level in ("critical", "high", "medium"):
            recommendations.append("Review authentication and authorization mechanisms")

        # Add technology-specific recommendations
        technologies = target_data.get("technologies", [])
        for tech in technologies:
            if "wordpress" in tech.lower():
                recommendations.append(
                    "Update WordPress core, themes, and plugins to latest versions"
                )
            elif "php" in tech.lower():
                recommendations.append(
                    "Ensure PHP is updated to the latest secure version"
                )
            elif "apache" in tech.lower() or "nginx" in tech.lower():
                recommendations.append("Review web server security configuration")

        return recommendations

    def _generate_recommendations(
        self, finding_predictions: List[Tuple[BaseFinding, Dict[str, Any]]]
    ) -> List[str]:
        """
        Generate overall recommendations based on findings and predictions.

        Args:
            finding_predictions: List of tuples containing (finding, prediction).

        Returns:
            List of recommendations.
        """
        recommendations = []

        # Count vulnerabilities by type
        vuln_types = {}
        for finding, _ in finding_predictions:
            vuln_type = finding.title if hasattr(finding, "title") else "Unknown"
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

        # Get top vulnerability types
        top_vulns = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:3]

        # Generate recommendations for top vulnerabilities
        for vuln_type, count in top_vulns:
            if "injection" in vuln_type.lower() or "sql" in vuln_type.lower():
                recommendations.append(
                    "Implement parameterized queries and input validation"
                )
            elif "xss" in vuln_type.lower():
                recommendations.append(
                    "Implement content security policy and output encoding"
                )
            elif "csrf" in vuln_type.lower():
                recommendations.append("Implement anti-CSRF tokens in all forms")
            elif (
                "authentication" in vuln_type.lower() or "session" in vuln_type.lower()
            ):
                recommendations.append(
                    "Review authentication mechanisms and session management"
                )

        # Add general recommendations
        recommendations.append("Review and update security headers")
        recommendations.append(
            "Implement secure coding practices across development team"
        )

        return recommendations


# Singleton instance for global use
prediction_service = PredictionService()


def analyze_target(target_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a target for vulnerabilities (global function).

    Args:
        target_data: Target information.

    Returns:
        Analysis results.
    """
    return prediction_service.analyze_target(target_data)


def analyze_findings(findings: List[BaseFinding]) -> Dict[str, Any]:
    """
    Analyze findings to identify patterns and priorities (global function).

    Args:
        findings: List of BaseFinding objects.

    Returns:
        Analysis results with prioritized findings.
    """
    return prediction_service.analyze_findings(findings)
