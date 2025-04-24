# Contributing to Sniper Security Tool

Thank you for your interest in contributing to the Sniper Security Tool! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Set up the development environment (see below)
4. Create a new branch for your feature or bugfix
5. Make your changes
6. Run tests to ensure your changes don't break existing functionality
7. Submit a pull request

## Development Environment Setup

### Using Poetry

We use Poetry for dependency management. To set up your development environment:

```bash
# Install Poetry if you don't have it already
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
poetry install

# Activate the virtual environment
poetry shell
```

### Using Docker

Alternatively, you can use Docker for development:

```bash
docker build -t sniper-dev -f Dockerfile.dev .
docker run -it --rm -v $(pwd):/app sniper-dev bash
```

## Testing Framework

The Sniper project uses pytest for testing. Our testing structure includes unit tests, integration tests, and end-to-end tests.

### Directory Structure

```
tests/
├── unit/           # Unit tests for individual components
├── integration/    # Tests for interactions between components
├── e2e/            # End-to-end tests for complete workflows
├── conftest.py     # Shared pytest fixtures and configuration
└── pytest.ini      # pytest configuration
```

### Running Tests

To run the full test suite:

```bash
poetry run pytest
```

To run tests with verbose output:

```bash
poetry run pytest -v
```

To run a specific test file or directory:

```bash
poetry run pytest tests/unit/test_specific_module.py
poetry run pytest tests/integration/
```

To run tests matching a specific pattern:

```bash
poetry run pytest -k "master or worker"
```

### Writing Tests

When writing tests:

1. Follow the same directory structure as the code you're testing
2. Use descriptive test names following the pattern `test_<functionality>_<scenario>`
3. Use fixtures from `conftest.py` where appropriate
4. Mock external dependencies and services
5. Test edge cases and error conditions
6. Aim for high code coverage

Example test:

```python
def test_scan_result_aggregation_with_empty_results():
    # Arrange
    aggregator = ResultAggregator(output_dir="./test_results")
    scan_id = "test-scan-1"
    results = []
    
    # Act
    aggregated = aggregator.aggregate_scan_results(scan_id, results)
    
    # Assert
    assert aggregated.findings == []
    assert aggregated.scan_id == scan_id
```

### Test Coverage

We aim for high test coverage. To generate a coverage report:

```bash
poetry run pytest --cov=src --cov-report=term --cov-report=html
```

View the HTML report in `htmlcov/index.html`.

## Coding Standards

The project adheres to strict coding standards as defined in [STANDARDS.md](docs/STANDARDS.md). Key points:

1. Follow PEP 8 style guidelines
2. Use type hints for all function parameters and return values
3. Write comprehensive docstrings
4. Keep functions small and focused on a single responsibility
5. Use meaningful variable and function names

We use the following tools to enforce standards:

- `black` for code formatting
- `isort` for sorting imports
- `flake8` for linting
- `mypy` for type checking

Run these tools before submitting a pull request:

```bash
poetry run black src tests
poetry run isort src tests
poetry run flake8 src tests
poetry run mypy src
```

## Commit Guidelines

We follow the Conventional Commits specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Example commit messages:
- `feat(scanner): add support for incremental scanning`
- `fix(api): resolve authentication timeout issue`
- `docs(readme): update installation instructions`
- `test(worker): add tests for task distribution`

## Pull Request Process

1. Update the documentation to reflect any changes
2. Update the README.md with details of changes to the interface, if applicable
3. Increase the version numbers in any examples files and the README.md to the new version that this PR would represent
4. Ensure all automated CI checks pass
5. The PR must be approved by at least one maintainer

## License

By contributing, you agree that your contributions will be licensed under the project's [LICENSE](LICENSE). 