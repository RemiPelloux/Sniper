# Add the following targets for ML functionality
# ... existing code ... 

# ML model targets
ml-train:
	python examples/ml_model_training.py --count 1000 --output data/synthetic_findings.json --model models/vulnerability_model.pkl

ml-predict:
	python -m src.cli.ml predict data/example_findings.json --threshold 0.7 --format json

ml-risk:
	python -m src.cli.ml risk data/example_findings.json --format json

ml-visualize:
	python -m src.cli.ml visualize data/example_findings.json --type risk_distribution --output risk_chart.png

ml-example:
	python examples/predict_vulnerabilities.py data/example_findings.json --threshold 0.6

# Create directories if they don't exist
ml-setup:
	mkdir -p models data

# Run all ML examples
ml-demo: ml-setup ml-train ml-predict ml-risk ml-visualize ml-example
	@echo "ML demonstration completed!" 