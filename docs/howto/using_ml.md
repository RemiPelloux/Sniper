# How to Use the ML Module

This document describes how to use the Machine Learning (ML) capabilities within Sniper.

## Overview

Sniper incorporates ML models for tasks like:
-   **Vulnerability Prediction**: Predicting potential vulnerabilities based on system characteristics.
-   **Scan Optimization**: Suggesting relevant tools or scan profiles based on the target.
-   **Pattern Learning**: Identifying recurring patterns in scan results.
-   **Finding Correlation**: Grouping related findings from different tools.

## Using ML Features

ML features are typically integrated automatically into relevant workflows.

### Vulnerability Prediction

During scans, the ML module analyzes target information (e.g., open ports, detected technologies) to predict likely vulnerabilities. These predictions may influence the tools selected or highlight areas for deeper investigation.

### Scan Optimization

Based on initial reconnaissance, the ML module can recommend specific tools or configurations that are most likely to yield results for the given target.

```bash
# Example: Initiate a scan with ML-driven optimization (conceptual)
sniper scan <target> --optimize ml
```

### Viewing ML Insights

ML-generated insights, such as predicted vulnerabilities or correlations, are usually included in the standard scan reports.

```bash
sniper results view <scan_id> --show-ml
```

## Training ML Models

Training is typically handled offline by developers using historical scan data.

1.  **Data Preparation**: Collect and preprocess historical scan data and known vulnerability information.
2.  **Feature Extraction**: Extract relevant features from the data (e.g., technology stacks, port information, configurations).
3.  **Model Training**: Use the scripts in `src/ml/training/` to train the models (e.g., vulnerability prediction, pattern recognition).
4.  **Model Evaluation**: Evaluate model performance using appropriate metrics.
5.  **Deployment**: Place the trained model files in the `models/` directory for Sniper to load.

## Configuration

ML module behavior can sometimes be configured via `config/default.yml`, such as enabling/disabling specific ML features or adjusting thresholds.

```yaml
ml:
  vulnerability_prediction:
    enabled: true
    threshold: 0.7
  scan_optimization:
    enabled: true
```

Refer to the `src/ml/` directory and specific training scripts for more technical details. 