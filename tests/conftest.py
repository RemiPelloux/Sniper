import os
import sys
from pathlib import Path

import pytest

# Add the src directory to Python path for imports in tests
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

# Set up paths for various directories
BASE_DIR = Path(__file__).parent.parent
SRC_DIR = BASE_DIR / "src"
TESTS_DIR = BASE_DIR / "tests"
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"


# Make these directories available to all tests
@pytest.fixture
def base_dir():
    """Return the base directory path."""
    return BASE_DIR


@pytest.fixture
def src_dir():
    """Return the src directory path."""
    return SRC_DIR


@pytest.fixture
def tests_dir():
    """Return the tests directory path."""
    return TESTS_DIR


@pytest.fixture
def data_dir():
    """Return the data directory path."""
    return DATA_DIR


@pytest.fixture
def results_dir():
    """Return the results directory path."""
    return RESULTS_DIR


# Common fixtures that should be available to all tests
@pytest.fixture
def sample_target_url():
    """Sample target URL for testing."""
    return "https://example.com"


@pytest.fixture
def mock_task_result():
    """Sample task result for testing."""
    return {
        "task_id": "task-123",
        "status": "completed",
        "result": {"vulnerabilities": [], "scan_time": 10.5},
    }
