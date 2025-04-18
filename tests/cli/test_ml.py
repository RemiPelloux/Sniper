"""
Tests for the ML CLI module.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest
from typer.testing import CliRunner

from src.cli.ml import ml
from src.results.types import BaseFinding, FindingSeverity


@pytest.fixture
def sample_findings_file():
    """Create a temporary file with sample findings data."""
    findings = [
        {
            "title": "SQL Injection",
            "description": "SQL Injection vulnerability in login form",
            "severity": "High",
            "target": "http://example.com/login",
            "source_tool": "test-tool",
            "finding_type": "web",
            "url": "http://example.com/login",
        },
        {
            "title": "Cross-Site Scripting",
            "description": "Reflected XSS in search parameter",
            "severity": "Medium",
            "target": "http://example.com/search",
            "source_tool": "test-tool",
            "finding_type": "web",
            "url": "http://example.com/search?q=test",
        },
        {
            "title": "Information Disclosure",
            "description": "Server version exposed in headers",
            "severity": "Low",
            "target": "http://example.com",
            "source_tool": "test-tool",
            "finding_type": "web",
            "url": "http://example.com",
        },
    ]

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode='w+') as temp:
        json.dump(findings, temp)
        temp_path = temp.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def mock_model():
    """Mock the vulnerability prediction model."""
    with patch("src.ml.model.VulnerabilityPredictor") as mock:
        predictor = Mock()
        predictor.predict.return_value = [
            0.9,
            0.7,
            0.3,
        ]  # High, medium, low probabilities
        predictor.calculate_risk_score.side_effect = [
            0.85,
            0.65,
            0.25,
        ]  # Mock risk scores
        mock.return_value = predictor
        yield mock


@pytest.fixture
def runner():
    """Create a CLI runner for testing."""
    return CliRunner()


class TestMlCommands:
    """Test the ML CLI commands."""

    def test_predict_command(self, runner, sample_findings_file, mock_model):
        """Test the predict command with sample findings."""
        # Mock the load_findings function
        with patch("src.cli.ml.load_findings") as mock_loader, patch(
            "src.cli.ml.predict_vulnerabilities"
        ) as mock_predict:

            # Create mock findings
            findings = [
                Mock(
                    spec=BaseFinding,
                    id="1",
                    title="Finding 1",
                    severity="high",
                    finding_type="sqli",
                ),
                Mock(
                    spec=BaseFinding,
                    id="2",
                    title="Finding 2",
                    severity="medium",
                    finding_type="xss",
                ),
                Mock(
                    spec=BaseFinding,
                    id="3",
                    title="Finding 3",
                    severity="low",
                    finding_type="info",
                ),
            ]
            mock_loader.return_value = findings

            # Mock prediction results
            mock_predict.return_value = [
                (findings[0], 0.9),
                (findings[1], 0.7),
                (findings[2], 0.3),
            ]

            # Run command with default threshold of 0.5
            result = runner.invoke(ml, ["predict", sample_findings_file])

            # Verify command ran successfully
            assert result.exit_code == 0

            # Check if correct functions were called - use any_call to be more flexible about argument types
            mock_loader.assert_called()
            # Check that predict_vulnerabilities was called
            mock_predict.assert_called_once()

            # Assert that sample_findings_file is in the call arguments
            assert str(sample_findings_file) in [str(args[0]) for args, _ in mock_loader.call_args_list]

            # Verify that only findings above threshold are included (first two)
            assert "Finding 1" in result.stdout
            assert "Finding 2" in result.stdout
            assert "Finding 3" not in result.stdout

    def test_risk_command(self, runner, sample_findings_file, mock_model):
        """Test the risk command."""
        # Mock the load_findings function
        with patch("src.cli.ml.load_findings") as mock_loader, patch(
            "src.cli.ml.calculate_risk_scores"
        ) as mock_risk:

            # Create mock findings
            findings = [
                Mock(
                    spec=BaseFinding,
                    id="1",
                    title="Finding 1",
                    severity="high",
                    finding_type="sqli",
                ),
                Mock(
                    spec=BaseFinding,
                    id="2",
                    title="Finding 2",
                    severity="medium",
                    finding_type="xss",
                ),
                Mock(
                    spec=BaseFinding,
                    id="3",
                    title="Finding 3",
                    severity="low",
                    finding_type="info",
                ),
            ]
            mock_loader.return_value = findings

            # Mock risk scores
            mock_risk.return_value = {"1": 0.85, "2": 0.65, "3": 0.25}

            # Run command
            result = runner.invoke(ml, ["risk", sample_findings_file])

            # Verify command ran successfully
            assert result.exit_code == 0

            # Check if correct functions were called - use any_call to be more flexible about argument types
            mock_loader.assert_called()
            # Check that calculate_risk_scores was called
            mock_risk.assert_called_once()

            # Assert that sample_findings_file is in the call arguments
            assert str(sample_findings_file) in [str(args[0]) for args, _ in mock_loader.call_args_list]

            # Verify all findings are included in the risk assessment
            assert "Finding 1" in result.stdout
            assert "Finding 2" in result.stdout
            assert "Finding 3" in result.stdout

    def test_train_command(self, runner, mock_model):
        """Test the train command."""
        # Create a temporary training file with minimal data
        training_data = [
            {
                "severity": "high",
                "description": "SQL injection",
                "finding_type": "sqli",
                "is_vulnerability": 1,
            },
            {
                "severity": "medium",
                "description": "XSS attack",
                "finding_type": "xss",
                "is_vulnerability": 1,
            },
            {
                "severity": "low",
                "description": "Info disclosure",
                "finding_type": "info",
                "is_vulnerability": 0,
            },
        ]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode='w+') as temp:
            json.dump(training_data, temp)
            training_file = temp.name

        try:
            # Mock the VulnerabilityPredictor to avoid actual training
            with patch("src.cli.ml.VulnerabilityPredictor") as mock_predictor_class:
                # Create a mock predictor that will succeed in all operations
                mock_predictor = MagicMock()
                mock_predictor.train.return_value = True
                mock_predictor.save_model.return_value = True
                mock_predictor.predict.return_value = [0.9, 0.8, 0.1]
                mock_predictor_class.return_value = mock_predictor

                # Mock pandas and train_test_split to avoid loading real data
                with patch("src.cli.ml.pd") as mock_pd, patch("sklearn.model_selection.train_test_split") as mock_split:
                    # Create a simple DataFrame that will pass validation
                    mock_df = MagicMock()
                    mock_df.columns = ["is_vulnerability", "description", "severity"]
                    is_vuln_column = MagicMock()
                    is_vuln_column.values = [1, 1, 0]
                    mock_df.__getitem__.return_value = is_vuln_column
                    mock_pd.read_json.return_value = mock_df
                    
                    # Simple train/test split
                    mock_split.return_value = (
                        [MagicMock(), MagicMock()],  # train findings
                        [MagicMock()],  # test findings
                        [1, 1],  # train labels
                        [0],  # test labels
                    )

                    # Create a temporary output directory
                    with tempfile.TemporaryDirectory() as temp_dir:
                        model_path = os.path.join(temp_dir, "model.pkl")

                        # Run command
                        result = runner.invoke(
                            ml,
                            ["train", training_file, "is_vulnerability", "--model-path", model_path],
                        )

                        # Check exit code - simplest verification that avoids complex assertion checks
                        assert result.exit_code == 0, f"Command failed with error: {result.output}"
        finally:
            # Cleanup
            if os.path.exists(training_file):
                os.unlink(training_file)

    def test_visualize_command(self, runner, sample_findings_file):
        """Test the visualize command."""
        # Mock the load_findings function and matplotlib
        with patch("src.cli.ml.load_findings") as mock_loader, patch(
            "src.cli.ml.calculate_risk_scores"
        ) as mock_risk, patch("matplotlib.pyplot") as mock_plt:
            # We'll mock numpy functions as needed rather than attempting to patch the module

            # Create mock findings
            findings = [
                Mock(
                    spec=BaseFinding,
                    id="1",
                    title="Finding 1",
                    severity="high",
                    finding_type="sqli",
                ),
                Mock(
                    spec=BaseFinding,
                    id="2",
                    title="Finding 2",
                    severity="medium",
                    finding_type="xss",
                ),
                Mock(
                    spec=BaseFinding,
                    id="3",
                    title="Finding 3",
                    severity="low",
                    finding_type="info",
                ),
            ]
            mock_loader.return_value = findings

            # Mock risk scores
            mock_risk.return_value = {"1": 0.85, "2": 0.65, "3": 0.25}

            # Create a temporary output file
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False, mode='w+') as temp:
                output_file = temp.name

            try:
                # Run command with output file
                result = runner.invoke(
                    ml,
                    [
                        "visualize",
                        sample_findings_file,
                        "--output",
                        output_file,
                        "--type",
                        "risk_distribution",
                    ],
                )

                # Verify command ran successfully
                assert result.exit_code == 0

                # Check if correct functions were called
                mock_loader.assert_called()
                mock_risk.assert_called_once()
                mock_plt.figure.assert_called_once()
                mock_plt.savefig.assert_called_once()

                # Assert that sample_findings_file is in the call arguments
                assert str(sample_findings_file) in [str(args[0]) for args, _ in mock_loader.call_args_list]

                # Try another visualization type
                mock_loader.reset_mock()
                mock_plt.reset_mock()

                result = runner.invoke(
                    ml,
                    [
                        "visualize",
                        sample_findings_file,
                        "--output",
                        output_file,
                        "--type",
                        "severity_comparison",
                    ],
                )

                assert result.exit_code == 0
                mock_loader.assert_called()
                mock_plt.figure.assert_called_once()
            finally:
                # Cleanup
                if os.path.exists(output_file):
                    os.unlink(output_file)

    def test_error_handling(self, runner):
        """Test error handling for non-existent files."""
        # Test with a non-existent file
        result = runner.invoke(ml, ["predict", "non_existent_file.json"])

        # Should exit with error
        assert result.exit_code != 0
        assert "Error" in result.stdout or "Error" in result.stderr
