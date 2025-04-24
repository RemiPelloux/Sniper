# Testing Guide for Sniper Security Tool

## Overview

This guide explains how to run tests for the Sniper Security Tool and how to contribute new tests to the project. The Sniper project uses pytest as its primary testing framework.

## Test Structure

The test suite is organized as follows:

```
tests/
├── unit/              # Unit tests for individual components
├── integration/       # Tests for interactions between components
├── distributed/       # Tests for distributed scanning system
├── plugins/           # Tests for plugin functionality
├── cli/               # Tests for command-line interface
├── ml/                # Tests for machine learning modules
├── conftest.py        # Shared pytest fixtures and configuration
└── pytest.ini         # pytest configuration
```

## Running Tests

### Prerequisites

Ensure you have all dependencies installed:

```bash
poetry install
```

### Running All Tests

To run the entire test suite:

```bash
poetry run pytest
```

### Running Tests with Verbose Output

```bash
poetry run pytest -v
```

### Running Specific Tests

Run tests in a specific directory:

```bash
poetry run pytest tests/unit/
poetry run pytest tests/distributed/
```

Run a specific test file:

```bash
poetry run pytest tests/unit/test_finding.py
```

Run a specific test function:

```bash
poetry run pytest tests/unit/test_finding.py::test_finding_creation
```

### Running Tests by Pattern

```bash
poetry run pytest -k "master or worker"
```

### Generating Test Coverage Reports

```bash
poetry run pytest --cov=src --cov-report=term --cov-report=html
```

View the HTML coverage report in `htmlcov/index.html`.

## Writing Tests

### Test Naming Conventions

- Test files should be named `test_*.py`
- Test functions should be named `test_*`
- Test function names should be descriptive and follow the pattern `test_<functionality>_<scenario>`

### Test Structure

Follow the Arrange-Act-Assert (AAA) pattern:

```python
def test_something():
    # Arrange - set up test data and prerequisites
    scanner = Scanner(target="example.com")
    
    # Act - execute the functionality being tested
    result = scanner.scan()
    
    # Assert - verify the expected outcome
    assert result.success is True
    assert len(result.findings) > 0
```

### Using Fixtures

Use pytest fixtures for common setup/teardown operations:

```python
@pytest.fixture
def mock_scanner():
    scanner = Scanner(target="example.com")
    # Configure mock behavior
    return scanner

def test_scanner_with_fixture(mock_scanner):
    result = mock_scanner.scan()
    assert result.success is True
```

Common fixtures are defined in `tests/conftest.py`.

### Mocking External Dependencies

Use `pytest-mock` or `unittest.mock` to mock external dependencies:

```python
def test_api_client(mocker):
    # Mock the HTTP request
    mock_response = mocker.patch('requests.get')
    mock_response.return_value.status_code = 200
    mock_response.return_value.json.return_value = {"status": "ok"}
    
    # Test the client
    client = ApiClient()
    result = client.get_status()
    
    assert result == {"status": "ok"}
```

### Testing Asynchronous Code

For async functions, use pytest-asyncio:

```python
import pytest

@pytest.mark.asyncio
async def test_async_function():
    result = await async_function()
    assert result is not None
```

## Testing Strategies

### Unit Testing

- Test each function/method in isolation
- Mock all external dependencies
- Focus on business logic, edge cases, and error handling
- Aim for high coverage

### Integration Testing

- Test interactions between components
- Use minimal mocking
- Verify correct communication between modules
- Focus on common workflows

### End-to-End Testing

- Test complete features from a user perspective
- Simulate real user interactions
- Use the CLI or API clients directly
- Focus on critical workflows

## Tips for Effective Tests

1. **Keep tests independent**: Each test should run independently of others
2. **Use clear assertions**: Make assertions specific and include messages
3. **Test positive and negative cases**: Test both success and failure paths
4. **Use parameterized tests**: Test multiple inputs with `@pytest.mark.parametrize`
5. **Avoid test duplication**: Use fixtures and helper functions
6. **Test edge cases**: Null values, empty collections, invalid inputs, etc.
7. **Keep tests fast**: Slow tests reduce development velocity

## Adding Tests for New Features

When adding a new feature:

1. Add unit tests for all new functions/methods
2. Add integration tests for interactions with existing components
3. Add CLI tests if the feature has command-line support
4. If applicable, add tests for error handling and edge cases
5. Ensure coverage does not decrease

## Debugging Tests

To debug failing tests:

```bash
# Show detailed output
poetry run pytest -v

# Show local variables in failures
poetry run pytest --showlocals

# Drop into debugger on failure
poetry run pytest --pdb

# Increase log level
poetry run pytest --log-level=DEBUG
```

## Testing CI/CD Pipeline

The CI pipeline runs all tests automatically when you push changes or create a pull request. 

To replicate the CI environment locally:

```bash
make test-ci
```

This will run all tests, check coverage, and run linters.

## Common Issues and Solutions

- **Module not found errors**: Ensure you're running tests from the project root directory
- **Fixture not found**: Check for typos or ensure the fixture is defined in conftest.py
- **Random test failures**: Look for side effects between tests or race conditions in async tests
- **Mocking issues**: Ensure you're mocking the correct path (where the object is used, not defined)

## Mock API for Testing

For tests requiring API interaction, use the built-in mock API server:

```python
from tests.utils.mock_api import start_mock_api, stop_mock_api

@pytest.fixture
def api_server():
    server = start_mock_api()
    yield server
    stop_mock_api(server)

def test_with_api(api_server):
    # Test code that interacts with the API
    pass
```

## Recording Test Coverage History

Test coverage history is maintained for major releases:

```bash
poetry run pytest --cov=src --cov-report=xml
```

This generates a coverage report that can be submitted to coverage tracking services. 