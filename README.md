# PenTest CLI Tool with ML

This project is a command-line interface (CLI) application designed for automated penetration testing. It utilizes machine learning to enhance its testing strategies based on real-world vulnerability data.

## Features (Planned)

*   Automated scanning of target URLs
*   Comprehensive reporting (JSON, HTML, Markdown)
*   Modular scanner architecture
*   Reconnaissance capabilities
*   Machine learning integration (using HackerOne Hacktivity data)

## Status

Alpha - Under Development

## Installation

```bash
# Clone the repository (if you haven't already)
git clone <repository-url>
cd pentest-cli

# Install dependencies using Poetry
poetry install
```

## Basic Usage

```bash
poetry run pentest-cli scan <target-url>
```

Example:

```bash
poetry run pentest-cli scan https://example.com
```

## Development

This project uses Poetry for dependency management.

*   Run tests: `poetry run pytest`
*   Check formatting: `poetry run black . --check`
*   Apply formatting: `poetry run black .`
*   Run linter: `poetry run flake8`
*   Run type checking: `poetry run mypy src tests`

(Further development instructions will be added here) 