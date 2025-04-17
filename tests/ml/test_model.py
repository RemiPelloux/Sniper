"""
Tests for the vulnerability prediction module.
"""

import os
import tempfile
from unittest.mock import Mock, patch

import numpy as np
import pytest

from src.ml.model import (
    VulnerabilityPredictor,
    calculate_risk_scores,
    get_prediction_model,
    predict_vulnerabilities,
)
from src.results.types import BaseFinding


@pytest.fixture
def mock_finding():
    """Create a mock finding for testing."""
    finding = Mock(spec=BaseFinding)
    finding.id = "test-finding-1"
    finding.severity = "medium"
    finding.description = "This is a test finding for SQL injection"
    finding.finding_type = "sql_injection"
    finding.confidence = 0.8
    return finding


@pytest.fixture
def mock_findings():
    """Create a list of mock findings for testing."""
    findings = []
    severities = ["critical", "high", "medium", "low", "info"]
    types = [
        "sql_injection",
        "xss",
        "rce",
        "information_disclosure",
        "misconfiguration",
    ]

    for i in range(5):
        finding = Mock(spec=BaseFinding)
        finding.id = f"test-finding-{i+1}"
        finding.severity = severities[i]
        finding.description = f"This is test finding #{i+1}"
        finding.finding_type = types[i]
        finding.confidence = 0.5 + (i * 0.1)
        findings.append(finding)

    return findings


class TestVulnerabilityPredictor:
    """Test suite for the VulnerabilityPredictor class."""

    def test_init_creates_model(self):
        """Test that initializing creates a model."""
        predictor = VulnerabilityPredictor()
        assert predictor.model is not None

    def test_extract_features(self, mock_finding):
        """Test feature extraction from a finding."""
        predictor = VulnerabilityPredictor()
        features = predictor.extract_features(mock_finding)

        assert isinstance(features, list)
        assert len(features) == 4  # We expect 4 features
        assert 0 <= features[0] <= 1  # Severity feature should be normalized

    def test_severity_conversion(self):
        """Test conversion of severity strings to numerical values."""
        predictor = VulnerabilityPredictor()

        assert predictor._convert_severity_to_value("critical") == 1.0
        assert predictor._convert_severity_to_value("high") == 0.8
        assert predictor._convert_severity_to_value("medium") == 0.5
        assert predictor._convert_severity_to_value("low") == 0.2
        assert predictor._convert_severity_to_value("info") == 0.1
        assert predictor._convert_severity_to_value("none") == 0.0

        # Test unknown severity
        assert predictor._convert_severity_to_value("unknown") == 0.3

    def test_calculate_risk_score(self, mock_finding):
        """Test risk score calculation."""
        predictor = VulnerabilityPredictor()
        risk_score = predictor.calculate_risk_score(mock_finding)

        assert 0 <= risk_score <= 1.0

    def test_save_and_load_model(self):
        """Test saving and loading a model."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tf:
            temp_path = tf.name

        try:
            # Create and save model
            predictor = VulnerabilityPredictor()
            save_result = predictor.save_model(temp_path)
            assert save_result is True

            # Load model
            loaded_predictor = VulnerabilityPredictor(temp_path)
            assert loaded_predictor.model is not None
        finally:
            # Clean up
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_train_model(self, mock_findings):
        """Test training the model."""
        predictor = VulnerabilityPredictor()
        # Create binary labels (0 or 1)
        labels = [1, 1, 0, 0, 1]

        result = predictor.train(mock_findings, labels)
        assert result is True

        # Test with mismatched lengths
        result = predictor.train(mock_findings, [1, 0])
        assert result is False

    def test_predict(self, mock_findings):
        """Test prediction functionality."""
        predictor = VulnerabilityPredictor()
        # First train the model
        labels = [1, 1, 0, 0, 1]
        predictor.train(mock_findings, labels)

        # Then make predictions
        predictions = predictor.predict(mock_findings)

        assert len(predictions) == len(mock_findings)
        for pred in predictions:
            assert 0 <= pred <= 1.0


class TestHelperFunctions:
    """Test suite for helper functions in the ML module."""

    def test_get_prediction_model(self):
        """Test that get_prediction_model returns a VulnerabilityPredictor."""
        model = get_prediction_model()
        assert isinstance(model, VulnerabilityPredictor)

    def test_predict_vulnerabilities(self, mock_findings):
        """Test the predict_vulnerabilities helper function."""
        results = predict_vulnerabilities(mock_findings)

        assert len(results) == len(mock_findings)
        for finding, score in results:
            assert finding in mock_findings
            assert 0 <= score <= 1.0

    def test_calculate_risk_scores(self, mock_findings):
        """Test the calculate_risk_scores helper function."""
        risk_scores = calculate_risk_scores(mock_findings)

        assert len(risk_scores) == len(mock_findings)
        for finding in mock_findings:
            assert finding.id in risk_scores
            assert 0 <= risk_scores[finding.id] <= 1.0
