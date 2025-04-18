"""
Tests for the ML utility functions
"""

from unittest.mock import Mock

import numpy as np
import pytest

from src.ml.utils import (
    SEVERITY_MAPPING,
    VULNERABILITY_WEIGHTS,
    calculate_vulnerability_score,
    evaluate_model_performance,
    extract_finding_features,
    extract_text_features,
    features_to_vector,
    get_severity_value,
    normalize_features,
)


class TestFeatureExtraction:
    """Test the feature extraction utilities"""

    def test_extract_text_features(self):
        """Test that text features are extracted correctly."""
        test_text = "This contains a SQL injection vulnerability that allows attackers to bypass authentication."
        features = extract_text_features(test_text)
        
        # Check basic text features
        assert features["text_length"] == len(test_text)
        assert features["word_count"] == 12  # Updated from 15 to 12
        
        # Check vulnerability patterns
        assert features["sql_injection_present"] == 1.0
        assert features["sql_injection_count"] >= 1
        assert features["authentication_present"] == 1.0
        
        # Features that shouldn't be present
        assert features["xss_present"] == 0.0
        assert features["command_injection_present"] == 0.0

        # Test with empty text
        assert extract_text_features("") == {}
        assert extract_text_features(None) == {}

        # Test with XSS text
        xss_text = "Cross-site scripting (XSS) vulnerability found in form input."
        xss_features = extract_text_features(xss_text)
        assert xss_features["xss_present"] == 1.0
        assert xss_features["sql_injection_present"] == 0.0

    def test_normalize_features(self):
        """Test feature normalization"""
        features = {
            "text_length": 1500,
            "word_count": 300,
            "sql_injection_present": 1.0,
            "other_feature": 0.5,
        }

        normalized = normalize_features(features)

        # Text length should be capped at 1.0
        assert normalized["text_length"] == 1.0
        # Word count should be capped at 1.0
        assert normalized["word_count"] == 1.0
        # Binary features should remain unchanged
        assert normalized["sql_injection_present"] == 1.0
        assert normalized["other_feature"] == 0.5

        # Test with smaller values
        small_features = {"text_length": 500, "word_count": 100}
        small_normalized = normalize_features(small_features)
        assert small_normalized["text_length"] == 0.5
        assert small_normalized["word_count"] == 0.5

    def test_calculate_vulnerability_score(self):
        """Test vulnerability score calculation"""
        # Test with multiple vulnerability indicators
        features = {
            "sql_injection_present": 1.0,
            "xss_present": 1.0,
            "command_injection_present": 0.0,
        }

        score = calculate_vulnerability_score(features)
        expected_score = (
            VULNERABILITY_WEIGHTS["sql_injection"] + VULNERABILITY_WEIGHTS["xss"]
        ) / 2
        assert score == expected_score

        # Test with no vulnerabilities
        empty_features = {
            "sql_injection_present": 0.0,
            "xss_present": 0.0,
            "text_length": 100,
        }
        assert calculate_vulnerability_score(empty_features) == 0.0

        # Test with one vulnerability
        single_feature = {"path_traversal_present": 1.0}
        assert (
            calculate_vulnerability_score(single_feature)
            == VULNERABILITY_WEIGHTS["path_traversal"]
        )


class TestSeverityHandling:
    """Test severity conversion utilities"""

    def test_get_severity_value(self):
        """Test converting severity strings to numerical values"""
        # Test all defined mappings
        for severity, expected in SEVERITY_MAPPING.items():
            assert get_severity_value(severity) == expected
            # Test case insensitivity
            assert get_severity_value(severity.upper()) == expected

        # Test unknown severity
        assert get_severity_value("unknown") == 0.3
        assert get_severity_value(None) == SEVERITY_MAPPING["none"]


class TestFeatureVectorization:
    """Test feature vectorization utilities"""

    def test_features_to_vector(self):
        """Test converting feature dictionaries to vectors"""
        features = {"feature1": 0.5, "feature2": 0.7, "feature3": 0.0}

        # Test with default feature order (alphabetical)
        vector = features_to_vector(features)
        assert isinstance(vector, np.ndarray)
        assert len(vector) == 3
        assert vector[0] == 0.5  # feature1
        assert vector[1] == 0.7  # feature2
        assert vector[2] == 0.0  # feature3

        # Test with custom feature order
        custom_vector = features_to_vector(
            features, ["feature2", "feature3", "feature1"]
        )
        assert len(custom_vector) == 3
        assert custom_vector[0] == 0.7  # feature2
        assert custom_vector[1] == 0.0  # feature3
        assert custom_vector[2] == 0.5  # feature1

        # Test with missing features
        sparse_vector = features_to_vector({"feature1": 0.5}, ["feature1", "missing"])
        assert len(sparse_vector) == 2
        assert sparse_vector[0] == 0.5
        assert sparse_vector[1] == 0.0  # Default for missing feature


class TestModelEvaluation:
    """Test model evaluation utilities"""

    def test_evaluate_model_performance(self):
        """Test evaluation metrics calculation"""
        # Perfect predictions
        true_labels = [1, 0, 1, 0, 1]
        perfect_preds = [1.0, 0.0, 1.0, 0.0, 1.0]

        metrics = evaluate_model_performance(true_labels, perfect_preds)
        assert metrics["accuracy"] == 1.0
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0
        assert metrics["f1_score"] == 1.0
        assert metrics["true_positives"] == 3
        assert metrics["false_positives"] == 0
        assert metrics["true_negatives"] == 2
        assert metrics["false_negatives"] == 0

        # Mixed predictions
        mixed_preds = [0.9, 0.4, 0.6, 0.3, 0.4]  # Threshold is 0.5
        mixed_metrics = evaluate_model_performance(true_labels, mixed_preds)

        assert mixed_metrics["accuracy"] == 0.8  # 4/5 correct
        assert mixed_metrics["true_positives"] == 2  # Correctly predicted 2 positives
        assert mixed_metrics["false_negatives"] == 1  # Missed 1 positive

        # Test with different threshold
        high_threshold = evaluate_model_performance(
            true_labels, mixed_preds, threshold=0.7
        )
        assert (
            high_threshold["true_positives"] == 1
        )  # Only the 0.9 prediction passes threshold

        # Test with empty inputs
        assert evaluate_model_performance([], []) == {}
        assert evaluate_model_performance([1], []) == {}

        # Test with mismatched lengths
        assert evaluate_model_performance([1, 0], [0.5]) == {}


class TestFindingFeatures:
    """Test extracting features from finding objects"""

    def test_extract_finding_features(self):
        """Test feature extraction from finding objects"""
        # Create a mock finding
        finding = Mock()
        finding.severity = "high"
        finding.confidence = 0.8
        finding.finding_type = "sql_injection"
        finding.description = "SQL Injection vulnerability in login form"

        features = extract_finding_features(finding)

        # Check basic properties
        assert features["severity"] == SEVERITY_MAPPING["high"]
        assert features["confidence"] == 0.8
        assert (
            features["vulnerability_weight"] == VULNERABILITY_WEIGHTS["sql_injection"]
        )
        assert features["sql_injection_present"] == 1.0

        # Check text features were extracted
        assert "text_length" in features
        assert "word_count" in features
        assert features["sql_injection_count"] >= 1

        # Test with minimal finding
        min_finding = Mock()
        min_finding.severity = "low"
        min_finding.finding_type = "other"
        min_finding.description = None
        min_finding.confidence = None

        min_features = extract_finding_features(min_finding)
        assert min_features["severity"] == SEVERITY_MAPPING["low"]
        assert min_features["vulnerability_weight"] == VULNERABILITY_WEIGHTS["other"]
        assert min_features["confidence"] == 0.5  # Default confidence
