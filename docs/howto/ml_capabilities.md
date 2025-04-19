# Using Machine Learning Capabilities in Sniper

This guide explains how to leverage Sniper's machine learning features for more effective security testing.

## Overview of ML Features

Sniper includes several ML-powered capabilities:

1. **Vulnerability Prediction**: Assess risk and predict vulnerabilities
2. **Smart Reconnaissance**: Optimize tool selection and testing strategies
3. **Pattern Recognition**: Identify vulnerability patterns across findings
4. **Tool Recommendation**: Select the most effective tools for specific targets

## Prerequisites

Before using ML features, ensure you have:

- Sniper installed with ML dependencies (`pip install sniper-security[ml]`)
- ML models downloaded (`sniper ml download-models`)
- Sufficient system resources (at least 4GB RAM recommended)

## Basic ML Usage

### Enabling ML Features in Scans

You can enable ML features directly from the command line:

```bash
# Enable ML-based tool selection
sniper scan -t example.com --ml-tool-selection

# Enable ML-based vulnerability prediction
sniper scan -t example.com --ml-vuln-prediction

# Enable pattern learning
sniper scan -t example.com --ml-pattern-learning

# Enable all ML features
sniper scan -t example.com --ml-all
```

### Adjusting ML Confidence Thresholds

Control how aggressively the ML models make predictions:

```bash
# Set higher threshold for more conservative predictions
sniper scan -t example.com --ml-all --ml-confidence-threshold 0.8

# Set lower threshold for more aggressive predictions
sniper scan -t example.com --ml-all --ml-confidence-threshold 0.5
```

## ML-Based Tool Selection

The Tool Selection ML feature helps choose the most effective security tools for a specific target.

### Basic Usage

```bash
# Let ML select the most appropriate tools
sniper scan -t example.com --ml-tool-selection

# View which tools would be selected without running a scan
sniper ml predict-tools -t example.com

# Limit the number of tools selected by ML
sniper scan -t example.com --ml-tool-selection --max-tools 5
```

### Customizing Tool Selection

```bash
# Override ML selection for specific categories
sniper scan -t example.com --ml-tool-selection --force-categories network,webapp

# Combine ML selection with specific tools
sniper scan -t example.com --ml-tool-selection --include-tools nmap,zap
```

## Vulnerability Prediction

The Vulnerability Prediction model assesses security findings and predicts potential vulnerabilities.

### Risk Assessment

```bash
# Enable vulnerability risk assessment
sniper scan -t example.com --ml-vuln-prediction

# Generate a risk-prioritized report
sniper scan -t example.com --ml-vuln-prediction --output-file risk_report.html
```

### Prediction-Based Testing

```bash
# Focus testing on predicted vulnerability types
sniper scan -t example.com --ml-vuln-prediction --adaptive-testing

# Set time allocation based on vulnerability predictions
sniper scan -t example.com --ml-vuln-prediction --adaptive-timing
```

## Pattern Recognition

The Pattern Recognition feature identifies related issues and vulnerability patterns across findings.

### Finding Clusters

```bash
# Enable pattern recognition to cluster related findings
sniper scan -t example.com --ml-pattern-learning

# Analyze existing findings for patterns
sniper ml analyze-patterns --input-file findings.json
```

### Pattern-Based Reporting

```bash
# Generate a report with grouped findings based on patterns
sniper report generate --input-file findings.json --pattern-grouping
```

## Training and Improving ML Models

Sniper's ML models can learn from your scan results to improve over time.

### Training with New Data

```bash
# Train models with new finding data
sniper ml train --data-file new_findings.json

# Train on recent scan results
sniper ml train --from-recent-scans --days 30

# Train a specific model
sniper ml train --model vulnerability_predictor --data-file new_data.json
```

### Evaluating Model Performance

```bash
# Evaluate all models
sniper ml evaluate

# Evaluate a specific model
sniper ml evaluate --model tool_selector

# Generate detailed evaluation metrics
sniper ml evaluate --detailed-metrics --output-file ml_evaluation.json
```

### Managing ML Models

```bash
# List available models
sniper ml list-models

# Check model details
sniper ml model-info --model vulnerability_predictor

# Reset a model to factory settings
sniper ml reset-model --model tool_selector

# Export a trained model
sniper ml export-model --model pattern_learner --output-file my_pattern_model.pkl

# Import a model
sniper ml import-model --model pattern_learner --input-file my_pattern_model.pkl
```

## Advanced ML Configuration

For more granular control of ML behavior, use the configuration system:

```bash
# View current ML configuration
sniper config show ml

# Configure ML threading behavior
sniper config set ml.max_threads 4

# Set model file locations
sniper config set ml.models_dir /path/to/custom/models

# Configure feature extraction
sniper config set ml.feature_extraction.max_features 2000

# Set advanced algorithm parameters
sniper config set ml.vulnerability_predictor.random_forest.n_estimators 200
```

## Integrating with the Autonomous Testing Module

ML features can be combined with autonomous testing for more effective vulnerability discovery:

```bash
# Run autonomous testing with ML-enhanced payload generation
sniper autonomous-test -t example.com --vulnerability-type xss --ml-enhanced-payloads

# Use ML to prioritize testing paths
sniper autonomous-test -t example.com --ml-path-prioritization
```

## Distributed ML Processing

For larger environments, ML processing can be distributed:

```bash
# Submit ML training job to distributed system
sniper distributed submit-ml-job --job-type train --data-file large_dataset.json

# Check ML job status
sniper distributed status --job-id abc123

# Retrieve distributed ML job results
sniper distributed get-results --job-id abc123
```

## Case Studies

### Example 1: Optimized Web Application Testing

```bash
# Full scan with ML-optimized tool selection and vulnerability prediction
sniper scan -t https://example.com --type webapp --ml-tool-selection --ml-vuln-prediction --output-file ml_enhanced_scan.html
```

### Example 2: Reconnaissance Optimization

```bash
# Use ML to optimize reconnaissance phase
sniper scan -t example.com --type recon --ml-tool-selection --ml-pattern-learning
```

### Example 3: Training Custom Models

```bash
# Train a custom model on your organization's findings
sniper ml train --data-file organization_findings.json --custom-model --output-prefix org_custom
```

## Troubleshooting

If you encounter issues with ML features:

```bash
# Check ML system status
sniper ml status

# Verify model integrity
sniper ml verify-models

# Run with debug logging for ML components
sniper scan -t example.com --ml-all --log-level debug --ml-debug

# Reset all ML models and configuration
sniper ml reset-all
```

## Next Steps

After mastering the basic ML capabilities, you might want to explore:

- [Autonomous Testing](autonomous_testing.md) for self-directed security testing
- [Custom Tool Integration](tool_integration.md) to extend Sniper's capabilities
- [Advanced Reporting](report_generation.md) for customized security reports 