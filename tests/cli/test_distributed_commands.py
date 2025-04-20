"""
Tests for the distributed CLI commands.
"""

import os
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

# Try to import the distributed CLI app
try:
    from src.cli.distributed import distributed_app
except ImportError:
    # Mark all tests as skipped if the module doesn't exist
    pytest.skip("src.cli.distributed module not found", allow_module_level=True)


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture
def mock_master_client():
    """Mock the master client used by distributed CLI commands."""
    master_client = MagicMock()
    master_client.start.return_value = True
    master_client.stop.return_value = True
    master_client.get_workers.return_value = [
        {
            "id": "worker-1",
            "hostname": "worker1.example.com",
            "address": "192.168.1.101",
            "status": "ACTIVE",
            "capabilities": ["port_scan", "web_scan"],
            "last_heartbeat": "2023-01-01T00:00:00Z",
        },
        {
            "id": "worker-2",
            "hostname": "worker2.example.com",
            "address": "192.168.1.102",
            "status": "IDLE",
            "capabilities": ["web_scan", "vuln_scan"],
            "last_heartbeat": "2023-01-01T00:00:00Z",
        },
    ]
    master_client.get_tasks.return_value = [
        {
            "id": "task-1",
            "type": "port_scan",
            "target": "example.com",
            "status": "COMPLETED",
            "assigned_worker": "worker-1",
            "created_at": "2023-01-01T00:00:00Z",
            "priority": "HIGH",
        },
        {
            "id": "task-2",
            "type": "web_scan",
            "target": "test.com",
            "status": "RUNNING",
            "assigned_worker": "worker-2",
            "created_at": "2023-01-01T00:00:00Z",
            "priority": "MEDIUM",
        },
    ]

    with patch("src.cli.distributed.create_master_client", return_value=master_client):
        yield master_client


@pytest.fixture
def mock_worker_client():
    """Mock the worker client used by distributed CLI commands."""
    worker_client = MagicMock()
    worker_client.start.return_value = True
    worker_client.stop.return_value = True
    worker_client.get_status.return_value = {
        "status": "ACTIVE",
        "active_tasks": 2,
        "completed_tasks": 5,
        "failed_tasks": 1,
    }

    with patch("src.cli.distributed.create_worker_client", return_value=worker_client):
        yield worker_client


def test_start_master_command(cli_runner, mock_master_client):
    """Test starting a master node."""
    result = cli_runner.invoke(distributed_app, ["master", "start"])
    assert result.exit_code == 0
    assert "Master node started" in result.stdout
    mock_master_client.start.assert_called_once()


def test_stop_master_command(cli_runner, mock_master_client):
    """Test stopping a master node."""
    result = cli_runner.invoke(distributed_app, ["master", "stop"])
    assert result.exit_code == 0
    assert "Master node stopped" in result.stdout
    mock_master_client.stop.assert_called_once()


def test_master_status_command(cli_runner, mock_master_client):
    """Test getting master node status."""
    mock_master_client.get_status.return_value = {
        "status": "ACTIVE",
        "address": "localhost:5000",
        "workers": 2,
        "active_tasks": 1,
        "queued_tasks": 0,
        "uptime": "0:10:30",
    }

    result = cli_runner.invoke(distributed_app, ["master", "status"])
    assert result.exit_code == 0
    assert "Master Node Status" in result.stdout
    assert "ACTIVE" in result.stdout
    mock_master_client.get_status.assert_called_once()


def test_list_workers_command(cli_runner, mock_master_client):
    """Test listing workers registered with the master."""
    result = cli_runner.invoke(distributed_app, ["workers", "list"])
    assert result.exit_code == 0
    assert "worker-1" in result.stdout
    assert "worker-2" in result.stdout
    assert "ACTIVE" in result.stdout
    assert "IDLE" in result.stdout
    mock_master_client.get_workers.assert_called_once()


def test_list_tasks_command(cli_runner, mock_master_client):
    """Test listing tasks managed by the master."""
    result = cli_runner.invoke(distributed_app, ["tasks", "list"])
    assert result.exit_code == 0
    assert "task-1" in result.stdout
    assert "task-2" in result.stdout
    assert "COMPLETED" in result.stdout
    assert "RUNNING" in result.stdout
    mock_master_client.get_tasks.assert_called_once()


def test_start_worker_command(cli_runner, mock_worker_client):
    """Test starting a worker node."""
    # Test with defaults
    result = cli_runner.invoke(distributed_app, ["worker", "start"])
    assert result.exit_code == 0
    assert "Worker node started" in result.stdout

    # Test with custom parameters
    result = cli_runner.invoke(
        distributed_app,
        [
            "worker",
            "start",
            "--master",
            "example.com:5000",
            "--capabilities",
            "port_scan,web_scan",
        ],
    )
    assert result.exit_code == 0
    # Check that parameters were passed correctly to the client
    call_args = mock_worker_client.start.call_args[1]
    assert call_args.get("master_host") == "example.com"
    assert call_args.get("master_port") == 5000
    assert "port_scan" in call_args.get("capabilities", [])
    assert "web_scan" in call_args.get("capabilities", [])


def test_stop_worker_command(cli_runner, mock_worker_client):
    """Test stopping a worker node."""
    result = cli_runner.invoke(distributed_app, ["worker", "stop"])
    assert result.exit_code == 0
    assert "Worker node stopped" in result.stdout
    mock_worker_client.stop.assert_called_once()


def test_worker_status_command(cli_runner, mock_worker_client):
    """Test getting worker node status."""
    result = cli_runner.invoke(distributed_app, ["worker", "status"])
    assert result.exit_code == 0
    assert "Worker Node Status" in result.stdout
    assert "ACTIVE" in result.stdout
    mock_worker_client.get_status.assert_called_once()
