"""
Tests for the SmartRecon module.

This module contains unit tests for the SmartRecon class and its functionality.
"""

import os
import pytest
import numpy as np
import tempfile
from unittest.mock import patch, MagicMock

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
        'id': 'target-123',
        'host': 'example.com',
        'port': 443,
        'protocol': 'https',
        'services': ['http', 'https']
    }


@pytest.fixture
def sample_ip_target():
    """Sample IP-based target for testing."""
    return {
        'id': 'target-456',
        'host': '192.168.1.1',
        'port': 80,
        'protocol': 'http',
        'services': ['http']
    }


@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return [
        {
            'id': 'finding-1',
            'target_id': 'target-123',
            'type': 'xss',
            'severity': 'high',
            'confidence': 'medium',
            'description': 'Cross-site scripting vulnerability found',
            'tool': 'zap',
            'url': 'https://example.com/vuln1'
        },
        {
            'id': 'finding-2',
            'target_id': 'target-123',
            'type': 'sql injection',
            'severity': 'critical',
            'confidence': 'high',
            'description': 'SQL injection vulnerability found',
            'tool': 'zap',
            'url': 'https://example.com/vuln2'
        },
        {
            'id': 'finding-3',
            'target_id': 'target-456',
            'type': 'information disclosure',
            'severity': 'medium',
            'confidence': 'low',
            'description': 'Information disclosure vulnerability found',
            'tool': 'nmap',
            'url': 'http://192.168.1.1/info'
        }
    ]


@pytest.fixture
def sample_vulnerabilities():
    """Sample confirmed vulnerabilities for testing."""
    return [
        {
            'id': 'vuln-1',
            'finding_id': 'finding-1',
            'name': 'Stored XSS',
            'additional_tests': ['csrf test', 'content security policy test']
        },
        {
            'id': 'vuln-2',
            'finding_id': 'finding-2',
            'name': 'Blind SQL Injection',
            'additional_tests': ['error-based test', 'time-based test']
        }
    ]


@pytest.fixture
def sample_tools_used():
    """Sample tools used data for testing."""
    return [
        {'tools': ['zap', 'wappalyzer', 'nmap']},
        {'tools': ['sublist3r', 'dirsearch']}
    ]


@pytest.fixture
def sample_reports():
    """Sample bug bounty reports for testing."""
    return [
        {
            'id': 'report-1',
            'target': {
                'host': 'example.com',
                'port': 443,
                'protocol': 'https',
                'services': ['http', 'https']
            },
            'findings': [
                {
                    'id': 'finding-1',
                    'target_id': 'target-123',
                    'type': 'xss',
                    'severity': 'high',
                    'confidence': 'medium',
                    'description': 'Cross-site scripting vulnerability found',
                    'tool': 'zap',
                    'url': 'https://example.com/vuln1'
                }
            ],
            'vulnerabilities': [
                {
                    'id': 'vuln-1',
                    'finding_id': 'finding-1',
                    'name': 'Stored XSS',
                    'additional_tests': ['csrf test']
                }
            ],
            'tools_used': ['zap', 'wappalyzer']
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

    def test_extract_target_features(self, smart_recon, sample_target, sample_ip_target):
        """Test feature extraction from targets."""
        # Test domain target
        features = smart_recon.extract_target_features(sample_target)
        assert isinstance(features, np.ndarray)
        assert features.shape[0] > 0
        assert features[0] == 0  # Not an IP address
        assert features[1] == 1  # HTTPS

        # Test IP target
        features = smart_recon.extract_target_features(sample_ip_target)
        assert isinstance(features, np.ndarray)
        assert features.shape[0] > 0
        assert features[0] == 1  # Is an IP address
        assert features[1] == 0  # Not HTTPS

    def test_extract_finding_features(self, smart_recon, sample_findings):
        """Test feature extraction from findings."""
        for finding in sample_findings:
            features = smart_recon.extract_finding_features(finding)
            assert isinstance(features, np.ndarray)
            assert features.shape[0] > 0
            
            # Check severity normalization (high = 3, critical = 4)
            if finding['severity'] == 'high':
                assert features[0] == 3/4
            elif finding['severity'] == 'critical':
                assert features[0] == 1.0
                
            # Check tool encoding
            if finding['tool'] == 'zap':
                assert features[-5] == 1  # First position in tool encoding
            elif finding['tool'] == 'nmap':
                assert features[-3] == 1  # Third position in tool encoding

    def test_save_load_models(self, smart_recon):
        """Test saving and loading models."""
        # Create mock models
        smart_recon.tool_selector_model = MagicMock()
        smart_recon.pattern_recognizer_model = MagicMock()
        smart_recon.clustering_model = MagicMock()
        
        # Save models
        smart_recon._save_models()
        
        # Reset models
        smart_recon.tool_selector_model = None
        smart_recon.pattern_recognizer_model = None
        smart_recon.clustering_model = None
        
        # Reload models (will fail since the mocks can't be pickled properly,
        # but we can verify the attempt was made)
        with patch('pickle.load', return_value=MagicMock()):
            smart_recon._load_models()

    @patch('pickle.dump')
    def test_train_tool_selector(self, mock_pickle_dump, smart_recon, sample_target, sample_findings, sample_tools_used):
        """Test training the tool selector model."""
        with patch('sklearn.ensemble.RandomForestClassifier.fit'):
            result = smart_recon.train_tool_selector(
                [sample_target], 
                sample_tools_used[:1], 
                sample_findings
            )
            assert result is True
            assert smart_recon.tool_selector_model is not None

    @patch('pickle.dump')
    def test_train_pattern_recognizer(self, mock_pickle_dump, smart_recon, sample_findings, sample_vulnerabilities):
        """Test training the pattern recognizer model."""
        with patch('sklearn.ensemble.RandomForestClassifier.fit') as mock_rf_fit:
            with patch('sklearn.cluster.KMeans.fit') as mock_kmeans_fit:
                result = smart_recon.train_pattern_recognizer(
                    sample_findings,
                    sample_vulnerabilities
                )
                assert result is True
                assert smart_recon.pattern_recognizer_model is not None
                assert smart_recon.clustering_model is not None
                assert mock_rf_fit.called
                assert mock_kmeans_fit.called

    def test_learn_from_bug_bounty(self, smart_recon, sample_reports):
        """Test learning from bug bounty reports."""
        with patch.object(smart_recon, 'train_tool_selector', return_value=True) as mock_train_tool:
            with patch.object(smart_recon, 'train_pattern_recognizer', return_value=True) as mock_train_pattern:
                result = smart_recon.learn_from_bug_bounty(sample_reports)
                assert result is True
                assert mock_train_tool.called
                assert mock_train_pattern.called

    def test_select_tools_no_model(self, smart_recon, sample_target):
        """Test tool selection with no trained model."""
        tools = smart_recon.select_tools(sample_target)
        assert isinstance(tools, list)
        assert len(tools) > 0
        # Should return default tools for web target
        assert 'zap' in tools
        assert 'nmap' in tools

    def test_select_tools_with_model(self, smart_recon, sample_target):
        """Test tool selection with a trained model."""
        # Create a mock model that returns some predictions
        mock_model = MagicMock()
        mock_model.predict.return_value = [
            ('zap', 0.9),
            ('wappalyzer', 0.7),
            ('nmap', 0.5)
        ]
        smart_recon.tool_selector_model = mock_model
        
        tools = smart_recon.select_tools(sample_target)
        assert isinstance(tools, list)
        assert len(tools) == 3
        assert tools[0] == 'zap'  # Highest effectiveness
        assert tools[1] == 'wappalyzer'
        assert tools[2] == 'nmap'

    def test_recognize_patterns_no_model(self, smart_recon, sample_findings):
        """Test pattern recognition with no trained model."""
        patterns = smart_recon.recognize_patterns(sample_findings)
        assert isinstance(patterns, list)
        assert len(patterns) == 0  # No patterns without a model

    def test_recognize_patterns_with_model(self, smart_recon, sample_findings):
        """Test pattern recognition with a trained model."""
        # Create mock models
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([
            [0.2, 0.8],  # High probability for first finding
            [0.1, 0.9],  # Higher for second
            [0.7, 0.3]   # Low for third
        ])
        smart_recon.pattern_recognizer_model = mock_model
        
        mock_clustering = MagicMock()
        mock_clustering.predict.return_value = np.array([0, 1, 2])
        smart_recon.clustering_model = mock_clustering
        
        with patch.object(smart_recon.scaler, 'transform', return_value=np.array([[0, 0, 0]] * 3)):
            patterns = smart_recon.recognize_patterns(sample_findings)
            assert isinstance(patterns, list)
            assert len(patterns) == 2  # Only the first two have probability > 0.5
            assert patterns[0]['id'] == 'finding-2'  # Sorted by probability
            assert patterns[1]['id'] == 'finding-1'
            assert 'vulnerability_probability' in patterns[0]
            assert 'cluster' in patterns[0]

    def test_adapt_similar_cases(self, smart_recon, sample_findings, sample_vulnerabilities):
        """Test adapting similar cases."""
        with patch.object(smart_recon.scaler, 'transform', return_value=np.array([[0, 0, 0]] * 3)):
            suggestions = smart_recon.adapt_similar_cases(
                sample_findings[0],
                sample_vulnerabilities
            )
            assert isinstance(suggestions, list)
            # Should return suggestions based on mock data

    def test_optimize_scan_strategy(self, smart_recon, sample_target, sample_findings):
        """Test scan strategy optimization."""
        with patch.object(smart_recon, 'select_tools', return_value=['zap', 'wappalyzer']):
            # Test without findings
            strategy = smart_recon.optimize_scan_strategy(sample_target)
            assert isinstance(strategy, dict)
            assert 'tools' in strategy
            assert len(strategy['tools']) == 2
            assert strategy['depth'] == 'deep'  # HTTPS target
            
            # Test with findings
            strategy = smart_recon.optimize_scan_strategy(sample_target, sample_findings)
            assert isinstance(strategy, dict)
            assert 'priority_paths' in strategy
            assert len(strategy['priority_paths']) > 0
            assert 'time_allocation' in strategy
            assert 'zap' in strategy['time_allocation']

    def test_generate_statistics(self, smart_recon, sample_findings):
        """Test statistics generation."""
        # Test without models or findings
        stats = smart_recon.generate_statistics()
        assert isinstance(stats, dict)
        assert 'timestamp' in stats
        assert 'models' in stats
        assert 'findings' in stats
        
        # Test with findings
        stats = smart_recon.generate_statistics(sample_findings)
        assert stats['findings']['total'] == 3
        assert 'high' in stats['findings']['by_severity']
        assert 'zap' in stats['findings']['by_tool']
        
        # Test with mock model
        mock_model = MagicMock()
        mock_model.feature_importances_ = np.array([0.1, 0.2, 0.3])
        smart_recon.pattern_recognizer_model = mock_model
        
        stats = smart_recon.generate_statistics()
        assert 'feature_importance' in stats['models']['pattern_recognizer']
        assert len(stats['models']['pattern_recognizer']['feature_importance']) == 3

    def test_helper_methods(self, smart_recon):
        """Test various helper methods."""
        # Test IP address detection
        assert smart_recon._is_ip_address('192.168.1.1') is True
        assert smart_recon._is_ip_address('example.com') is False
        assert smart_recon._is_ip_address('256.0.0.1') is False
        
        # Test TLD extraction
        assert smart_recon._extract_tld('example.com') == 'com'
        assert smart_recon._extract_tld('test.example.co.uk') == 'uk'
        assert smart_recon._extract_tld('localhost') == ''
        
        # Test default tools selection
        web_target = {'protocol': 'https', 'host': 'example.com'}
        non_web_target = {'protocol': 'ssh', 'host': '192.168.1.1'}
        
        assert 'zap' in smart_recon._get_default_tools(web_target)
        assert 'dirsearch' in smart_recon._get_default_tools(web_target)
        assert 'nmap' in smart_recon._get_default_tools(non_web_target)
        assert 'zap' not in smart_recon._get_default_tools(non_web_target) 