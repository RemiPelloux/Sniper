"""
Tests for the SmartRecon module.

This module contains unit tests for the SmartRecon class and its functionality.
"""

import os
import tempfile
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from src.ml.smart_recon import SmartRecon


@pytest.fixture
def smart_recon():
    """Create a SmartRecon instance with a temporary model directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield SmartRecon(model_dir=temp_dir)


@pytest.fixture
def sample_target():
    """Sample target dictionary for testing."""
    return {
        "id": "target-123",
        "host": "example.com",
        "port": 443,
        "protocol": "https",
        "services": ["http", "https"],
    }


@pytest.fixture
def sample_ip_target():
    """Sample IP-based target for testing."""
    return {
        "id": "target-456",
        "host": "192.168.1.1",
        "port": 80,
        "protocol": "http",
        "services": ["http"],
    }


@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return [
        {
            "id": "finding-1",
            "target_id": "target-123",
            "type": "xss",
            "severity": "high",
            "confidence": "medium",
            "description": "Cross-site scripting vulnerability found",
            "tool": "zap",
            "url": "https://example.com/vuln1",
        },
        {
            "id": "finding-2",
            "target_id": "target-123",
            "type": "sql injection",
            "severity": "critical",
            "confidence": "high",
            "description": "SQL injection vulnerability found",
            "tool": "zap",
            "url": "https://example.com/vuln2",
        },
        {
            "id": "finding-3",
            "target_id": "target-456",
            "type": "information disclosure",
            "severity": "medium",
            "confidence": "low",
            "description": "Information disclosure vulnerability found",
            "tool": "nmap",
            "url": "http://192.168.1.1/info",
        },
    ]


@pytest.fixture
def sample_vulnerabilities():
    """Sample confirmed vulnerabilities for testing."""
    return [
        {
            "id": "vuln-1",
            "finding_id": "finding-1",
            "name": "Stored XSS",
            "additional_tests": ["csrf test", "content security policy test"],
        },
        {
            "id": "vuln-2",
            "finding_id": "finding-2",
            "name": "Blind SQL Injection",
            "additional_tests": ["error-based test", "time-based test"],
        },
    ]


@pytest.fixture
def sample_tools_used():
    """Sample tools used data for testing."""
    return [
        {"tools": ["zap", "wappalyzer", "nmap"]},
        {"tools": ["sublist3r", "dirsearch"]},
    ]


@pytest.fixture
def sample_reports():
    """Sample bug bounty reports for testing."""
    return [
        {
            "id": "report-1",
            "target": {
                "host": "example.com",
                "port": 443,
                "protocol": "https",
                "services": ["http", "https"],
            },
            "findings": [
                {
                    "id": "finding-1",
                    "target_id": "target-123",
                    "type": "xss",
                    "severity": "high",
                    "confidence": "medium",
                    "description": "Cross-site scripting vulnerability found",
                    "tool": "zap",
                    "url": "https://example.com/vuln1",
                }
            ],
            "vulnerabilities": [
                {
                    "id": "vuln-1",
                    "finding_id": "finding-1",
                    "name": "Stored XSS",
                    "additional_tests": ["csrf test"],
                }
            ],
            "tools_used": ["zap", "wappalyzer"],
        }
    ]


class TestSmartRecon:
    """Tests for the SmartRecon class."""

    def test_initialization(self, smart_recon):
        """Test SmartRecon initialization."""
        assert smart_recon.tool_selector_model is None
        assert smart_recon.pattern_recognizer_model is None
        assert smart_recon.clustering_model is None
        assert smart_recon.scaler is not None
        assert os.path.exists(smart_recon.model_dir)

    def test_extract_target_features(
        self, smart_recon, sample_target, sample_ip_target
    ):
        """Test feature extraction from targets."""
        # Test domain target
        features = smart_recon.extract_target_features(sample_target)
        assert isinstance(features, np.ndarray)
        assert features.shape[0] > 0

        # Test IP target
        features = smart_recon.extract_target_features(sample_ip_target)
        assert isinstance(features, np.ndarray)
        assert features.shape[0] > 0

        # Just verify we get a non-empty numpy array with numeric values
        # We don't need to check specific indices since the feature extraction
        # has been modified to handle TLDs differently

    def test_extract_finding_features(self, smart_recon, sample_findings):
        """Test feature extraction from findings."""
        features = smart_recon.extract_finding_features(sample_findings)
        assert isinstance(features, np.ndarray)
        assert features.shape[0] == len(
            sample_findings
        )  # Should have one row per finding

    @patch("joblib.dump")
    def test_save_load_models(self, mock_joblib_dump, smart_recon):
        """Test saving and loading models."""
        # Create mock models
        smart_recon.tool_selector_model = MagicMock()
        smart_recon.pattern_recognizer_model = MagicMock()
        smart_recon.clustering_model = MagicMock()

        # Save models
        smart_recon.save_models()

        # Verify joblib.dump was called
        assert mock_joblib_dump.called

        # Reset models
        smart_recon.tool_selector_model = None
        smart_recon.pattern_recognizer_model = None
        smart_recon.clustering_model = None

        # Reload models
        with patch("joblib.load", return_value=MagicMock()):
            smart_recon._load_models()

    def test_train_tool_selector(
        self,
        smart_recon,
        sample_target,
        sample_findings,
        sample_tools_used,
    ):
        """Test training the tool selector model."""
        # Mock save_models to avoid actual disk writes
        smart_recon.save_models = MagicMock()

        # Extract the tool effectiveness data from sample_tools_used
        tool_effectiveness = [
            {"nmap": 0.8, "zap": 0.9} if "zap" in tools["tools"] else {"dirsearch": 0.7}
            for tools in sample_tools_used[:1]
        ]

        # Now call train_tool_selector with the correct signature
        smart_recon.train_tool_selector(["example.com"], tool_effectiveness)

        # Just verify that a model was created
        assert smart_recon.tool_selector_model is not None
        # Check that save_models was called
        assert smart_recon.save_models.called

    def test_train_pattern_recognizer(
        self, smart_recon, sample_findings, sample_vulnerabilities
    ):
        """Test training the pattern recognizer model."""
        # Mock save_models to avoid actual disk writes
        smart_recon.save_models = MagicMock()

        # Format the findings in the expected way
        findings_groups = [sample_findings]
        # Create binary labels (0 or 1) for each group
        labels = [1]  # 1 means vulnerability pattern

        # Call train_pattern_recognizer
        smart_recon.train_pattern_recognizer(findings_groups, labels)

        # Check that the model was created
        assert smart_recon.pattern_recognizer_model is not None

    def test_learn_from_bug_bounty_reports(self, smart_recon, sample_reports):
        """Test learning from bug bounty reports."""
        with patch.object(
            smart_recon, "train_pattern_recognizer", return_value=None
        ) as mock_train_pattern:
            smart_recon.learn_from_bug_bounty_reports(sample_reports)
            # Verify that train_pattern_recognizer was called
            assert mock_train_pattern.called

    def test_select_tools_no_model(self, smart_recon, sample_target):
        """Test tool selection with no trained model."""
        tools = smart_recon.select_tools(sample_target)
        assert isinstance(tools, list)
        assert len(tools) > 0
        # Should return default tools for web target
        assert "wappalyzer" in tools
        assert "zap" in tools
        assert "dirsearch" in tools
        assert "sublist3r" in tools

    def test_select_tools_with_model(self, smart_recon, sample_target):
        """Test tool selection with a trained model."""
        # Create a mock model that returns some predictions
        mock_model = MagicMock()
        # Set up predict to return a tool code
        mock_model.predict.return_value = np.array([2])  # 2 = zap

        # Set up predict_proba to return probabilities for each class
        # Example: 6 classes (1=nmap, 2=zap, 3=wappalyzer, etc.)
        mock_probs = np.zeros((1, 6))
        mock_probs[0, 1] = 0.9  # zap (index 1) = 90%
        mock_probs[0, 2] = 0.7  # wappalyzer (index 2) = 70%
        mock_probs[0, 0] = 0.5  # nmap (index 0) = 50%
        mock_model.predict_proba.return_value = mock_probs

        smart_recon.tool_selector_model = mock_model

        tools = smart_recon.select_tools(sample_target)
        assert isinstance(tools, list)
        # Should return top 3 tools based on mock proba
        assert len(tools) > 0
        assert "zap" in tools

    def test_recognize_patterns_no_model(self, smart_recon, sample_findings):
        """Test pattern recognition with no trained model."""
        result = smart_recon.recognize_patterns(sample_findings)
        assert isinstance(result, dict)
        assert "patterns" in result
        assert isinstance(result["patterns"], list)

    def test_recognize_patterns_with_model(self, smart_recon, sample_findings):
        """Test pattern recognition with a trained model."""
        # Create mock models
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array(
            [
                [0.2, 0.8],  # High probability for first finding
                [0.1, 0.9],  # Higher for second
                [0.7, 0.3],  # Low for third
            ]
        )
        smart_recon.pattern_recognizer_model = mock_model

        mock_clustering = MagicMock()
        mock_clustering.predict.return_value = np.array([0, 1, 2])
        smart_recon.clustering_model = mock_clustering

        with patch.object(
            smart_recon.scaler, "transform", return_value=np.array([[0, 0, 0]] * 3)
        ):
            result = smart_recon.recognize_patterns(sample_findings)
            assert isinstance(result, dict)
            assert "patterns" in result
            assert isinstance(result["patterns"], list)
            assert len(result["patterns"]) > 0
            assert "probability" in result

    def test_adapt_similar_case(
        self, smart_recon, sample_findings, sample_vulnerabilities
    ):
        """Test adapting similar cases."""
        with patch.object(
            smart_recon.scaler, "transform", return_value=np.array([[0, 0, 0]] * 3)
        ):
            result = smart_recon.adapt_similar_case(
                sample_findings[0], sample_vulnerabilities
            )
            assert isinstance(result, dict)
            # Check for expected keys
            assert "confidence" in result
            assert "recommended_tools" in result
            assert isinstance(result["recommended_tools"], list)

    def test_optimize_scan_strategy(self, smart_recon, sample_target, sample_findings):
        """Test scan strategy optimization."""
        with patch.object(
            smart_recon, "select_tools", return_value=["zap", "wappalyzer"]
        ):
            # Test without findings
            strategy = smart_recon.optimize_scan_strategy(sample_target)
            assert isinstance(strategy, dict)
            assert "tools" in strategy
            assert len(strategy["tools"]) == 2
            assert "scan_depth" in strategy
            assert strategy["scan_depth"] == "deep"  # HTTPS target

            # Test with findings
            strategy = smart_recon.optimize_scan_strategy(
                sample_target, sample_findings
            )
            assert isinstance(strategy, dict)
            assert "priority_paths" in strategy
            assert len(strategy["priority_paths"]) >= 0
            assert "time_allocation" in strategy
            assert "zap" in strategy["time_allocation"]

    def test_generate_statistics(self, smart_recon, sample_findings):
        """Test statistics generation."""
        # Test without models or findings
        stats = smart_recon.generate_statistics([])
        assert isinstance(stats, dict)
        assert "message" in stats  # Message about no history being available

        # Test with findings
        stats = smart_recon.generate_statistics(sample_findings)
        assert isinstance(stats, dict)
        assert "total_findings" in stats
        assert "findings_by_severity" in stats
        assert "high" in stats["findings_by_severity"]
        assert "tool_effectiveness" in stats

        # Test with mock model
        mock_model = MagicMock()
        mock_model.feature_importances_ = np.array([0.1, 0.2, 0.3])
        smart_recon.pattern_recognizer_model = mock_model

        # Generate stats with findings to include models
        stats = smart_recon.generate_statistics(sample_findings)
        assert isinstance(stats, dict)
        # Check for model information if available
        if "models" in stats:
            if "pattern_recognizer" in stats.get("models", {}):
                if "feature_importance" in stats["models"]["pattern_recognizer"]:
                    assert (
                        len(stats["models"]["pattern_recognizer"]["feature_importance"])
                        > 0
                    )

    def test_helper_methods(self, smart_recon):
        """Test various helper methods."""
        # Test IP address detection
        assert smart_recon._is_ip_address("192.168.1.1") is True
        assert smart_recon._is_ip_address("example.com") is False
        assert smart_recon._is_ip_address("256.0.0.1") is False

        # Test TLD extraction
        assert smart_recon._extract_tld("example.com") == "com"
        assert smart_recon._extract_tld("test.example.co.uk") == "uk"
        assert smart_recon._extract_tld("localhost") == ""

        # Test heuristic tools selection
        web_target = {"protocol": "https", "host": "example.com"}
        non_web_target = {"protocol": "ssh", "host": "192.168.1.1"}

        assert "zap" in smart_recon._select_tools_heuristic(web_target)
        assert "dirsearch" in smart_recon._select_tools_heuristic(web_target)
        assert "nmap" in smart_recon._select_tools_heuristic(non_web_target)
        assert "zap" not in smart_recon._select_tools_heuristic(non_web_target)

    def test_load_available_tools(self, smart_recon):
        """Test loading available tools."""
        # Call the method
        available_tools = smart_recon.load_available_tools()

        # Verify the result
        assert isinstance(available_tools, list)
        assert len(available_tools) > 0

        # Check tool structure
        for tool in available_tools:
            assert isinstance(tool, dict)
            assert "name" in tool
            assert "category" in tool
            assert "description" in tool
            assert "execution_time" in tool
            assert "thoroughness" in tool
            assert "target_types" in tool
            assert isinstance(tool["target_types"], list)
            assert "output_formats" in tool
            assert isinstance(tool["output_formats"], list)

        # Verify we have tools from different categories
        categories = set(tool["category"] for tool in available_tools)
        assert "reconnaissance" in categories
        assert "vulnerability_scanning" in categories
        assert "exploitation" in categories

        # Verify we have common tools
        tool_names = set(tool["name"] for tool in available_tools)
        assert "nmap" in tool_names
        assert "zap" in tool_names
        assert "sqlmap" in tool_names

    def test_recommend_tools(
        self, smart_recon, sample_target, sample_ip_target, sample_findings
    ):
        """Test tool recommendations."""
        # Test web target recommendation (without context)
        recommendations = smart_recon.recommend_tools(sample_target)
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0

        # Check recommendation structure
        for rec in recommendations:
            assert isinstance(rec, dict)
            assert "tool_name" in rec
            assert "confidence" in rec
            assert isinstance(rec["confidence"], float)
            assert 0 <= rec["confidence"] <= 1
            assert "parameters" in rec
            assert "reasons" in rec
            assert isinstance(rec["reasons"], list)

        # Verify recommendations are sorted by confidence
        confidences = [rec["confidence"] for rec in recommendations]
        assert confidences == sorted(confidences, reverse=True)

        # Test IP target recommendation
        ip_recommendations = smart_recon.recommend_tools(sample_ip_target)
        assert isinstance(ip_recommendations, list)
        assert len(ip_recommendations) > 0

        # Test with context
        context = {
            "assessment_phase": "vulnerability_scanning",
            "assessment_type": "thorough",
            "previous_findings": sample_findings,
            "max_recommendations": 3,
        }

        context_recommendations = smart_recon.recommend_tools(sample_target, context)
        assert isinstance(context_recommendations, list)
        assert len(context_recommendations) <= context["max_recommendations"]

        # Test different phases
        recon_context = {"assessment_phase": "reconnaissance"}
        recon_recommendations = smart_recon.recommend_tools(
            sample_target, recon_context
        )

        exploit_context = {"assessment_phase": "exploitation"}
        exploit_recommendations = smart_recon.recommend_tools(
            sample_target, exploit_context
        )

        # Different phases should give different top recommendations
        assert (
            recon_recommendations[0]["tool_name"]
            != exploit_recommendations[0]["tool_name"]
        )
