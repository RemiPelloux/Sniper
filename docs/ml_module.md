# Machine Learning Module Documentation

## Overview

The Machine Learning (ML) module in Sniper provides vulnerability prediction and risk assessment capabilities for security findings. It uses statistical models to:

1. Predict which findings are likely to be actual vulnerabilities
2. Calculate risk scores to prioritize findings
3. Extract meaningful features from security findings
4. Visualize risk distributions and trends

## Key Components

The ML module consists of the following main components:

### Core ML Model (`src/ml/model.py`)

The core ML functionality is implemented in the `VulnerabilityPredictor` class, which provides:

- Training on labeled security findings
- Prediction of vulnerability likelihood
- Risk score calculation
- Model persistence (save/load)

The default implementation uses a Random Forest classifier that considers various attributes of a finding (severity, type, description, etc.) to make predictions.

### ML Utilities (`src/ml/utils.py`)

Utility functions for ML processing, including:

- Feature extraction from text descriptions
- Normalization of features
- Vulnerability scoring
- Model evaluation metrics
- Conversion functions between different data formats

### CLI Interface (`src/cli/ml.py`)

The command-line interface provides easy access to ML functionality:

- `predict`: Analyze findings and predict which are vulnerabilities
- `risk`: Calculate risk scores for findings
- `train`: Train a new model with labeled data
- `visualize`: Generate visualizations of findings and risk data

### Data Loader (`src/results/loader.py`)

The data loader provides functions for:

- Loading findings from JSON files
- Converting JSON data to BaseFinding objects
- Saving findings data to files

## Installation Requirements

The ML module depends on the following Python packages:

- `scikit-learn`: For machine learning algorithms
- `numpy`: For numerical computations
- `pandas`: For data manipulation
- `matplotlib`: For visualizations

## Usage Examples

### Predicting Vulnerabilities

To predict vulnerabilities from a findings file:

```bash
python -m src.cli.ml predict findings.json --threshold 0.7 --output predictions.json
```

This command will:
1. Load findings from the JSON file
2. Apply the prediction model with a 0.7 threshold
3. Save the results to predictions.json

### Risk Assessment

To calculate risk scores for findings:

```bash
python -m src.cli.ml risk findings.json --format json --output risk_scores.json
```

### Training a Custom Model

To train a model with your own labeled data:

```bash
python -m src.cli.ml train training_data.csv is_vulnerability --model-path models/custom_model.pkl
```

The training data should contain a column indicating whether each finding is a real vulnerability.

### Generating Visualizations

To create visualizations of your security findings:

```bash
python -m src.cli.ml visualize findings.json --type risk_distribution --output risk_chart.png
```

Available visualization types:
- `risk_distribution`: Histogram of risk scores
- `severity_comparison`: Bar chart of findings by severity
- `confidence_vs_risk`: Scatter plot of confidence vs. risk
- `findings_by_type`: Top finding types by count

## Example Scripts

The `examples/` directory contains example scripts to help you get started:

- `ml_model_training.py`: Demonstrates how to generate synthetic data and train a model
- `predict_vulnerabilities.py`: Shows how to use a trained model for prediction

## Model Details

### Feature Extraction

The ML model extracts the following features from findings:

- Severity level (converted to numerical value)
- Confidence score
- Finding type (with type-specific weights)
- Text features from the description:
  - Presence of known vulnerability keywords
  - Word count and text length
  - Presence of CVE identifiers

### Risk Scoring

Risk scores are calculated based on:

- Severity level
- Confidence score
- Finding type weight
- Text features (e.g., presence of certain keywords)

### Model Performance

The default model typically achieves:

- Accuracy: 80-85%
- Precision: 75-80%
- Recall: 80-85%
- F1 Score: 75-80%

Performance may vary depending on the quality and nature of your security findings.

## Extending the ML Module

You can extend the ML module in several ways:

1. **Custom Feature Extraction**: Add new features to `extract_finding_features()` in `utils.py`
2. **Alternative Models**: Create a subclass of `VulnerabilityPredictor` with a different algorithm
3. **New Visualizations**: Add visualization types to the `visualize` command in `ml.py`
4. **Additional Metrics**: Implement new risk scoring or evaluation metrics

## Best Practices

- Train models with data that resembles your production environment
- Use a balanced dataset with both vulnerabilities and non-vulnerabilities
- Periodically retrain models as new finding patterns emerge
- Adjust prediction thresholds based on your risk tolerance
- Combine ML predictions with expert review for critical systems 