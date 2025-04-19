"""
Tests for the distributed worker client module.

This module tests the WorkerNodeClient functionality, including:
- Configuration loading
- Worker lifecycle management
- Reconnection logic
"""

import os
import signal
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

import pytest
import yaml

from src.distributed.base import NodeStatus
from src.distributed.client import WorkerNodeClient


@pytest.fixture
def mock_worker():
    """Create a mock SniperWorkerNode for testing."""
    with mock.patch("src.distributed.client.SniperWorkerNode") as mock_worker_cls:
        mock_worker_instance = mock_worker_cls.return_value
        mock_worker_instance.id = "test-worker-id"
        mock_worker_instance.status = NodeStatus.ACTIVE
        mock_worker_instance.start.return_value = True
        mock_worker_instance.register_with_master.return_value = True
        yield mock_worker_cls


@pytest.fixture
def config_file():
    """Create a temporary configuration file for testing."""
    config = {
        "master_host": "test-master.example.com",
        "master_port": 9999,
        "worker_id": "test-worker-from-config",
        "protocol_type": "rest",
        "capabilities": ["basic", "port_scan", "web_scan"],
        "max_concurrent_tasks": 10,
        "heartbeat_interval": 30,
    }

    # Create a temporary file with yaml content
    tmp_path = tempfile.mktemp(suffix=".yaml")
    with open(tmp_path, "w") as f:
        yaml.dump(config, f)

    yield tmp_path

    # Clean up
    if os.path.exists(tmp_path):
        os.unlink(tmp_path)


@pytest.mark.usefixtures("mock_worker")
class TestWorkerNodeClient:
    """Tests for the WorkerNodeClient class."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        with mock.patch("src.distributed.client.setup_logging") as mock_setup_logging:
            # Initialization MUST happen inside the patch context
            client = WorkerNodeClient(master_host="default_host", master_port=1234)

            assert client.worker_node.master_host == "default_host"
            assert client.worker_node.master_port == 1234
            assert client.worker_node.protocol_type == "REST"

            # Check the actual capabilities
            expected_capabilities = [
                "scan",
                "vuln",
                "recon",
                "autonomous_test",
                "vulnerability_scan",
            ]
            assert sorted(client.worker_node.capabilities) == sorted(
                expected_capabilities
            )

            assert client.worker_node.max_concurrent_tasks == 5
            assert client.worker_node.heartbeat_interval == 30
            # mock_setup_logging.assert_called_once() # setup_logging is not called in __init__
