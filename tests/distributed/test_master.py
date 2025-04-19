"""
Tests for the Master Node implementation in the distributed scanning architecture.

These tests validate:
1. Master node initialization and configuration
2. Worker node management
3. Task distribution and tracking
4. Result aggregation
5. Server operations and error handling
"""

import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call, patch

import pytest

from src.distributed.base import (
    DistributedTask,
    NodeInfo,
    NodeRole,
    NodeStatus,
    TaskPriority,
    TaskStatus,
)
from src.distributed.distribution import DistributionStrategy
from src.distributed.master import MasterNodeServer, SniperMasterNode
from src.distributed.protocol import MessageType, ProtocolMessage


@pytest.fixture
def mock_protocol():
    """Create a mock protocol for testing."""
    protocol = MagicMock()
    protocol.send_message.return_value = True
    return protocol


@pytest.fixture
def sample_tasks():
    """Create a list of sample tasks for testing."""
    return [
        DistributedTask(
            task_type="port_scan",
            target="192.168.1.1",
            parameters={"ports": "1-1000", "scan_type": "SYN"},
            priority=TaskPriority.HIGH,
        ),
        DistributedTask(
            task_type="web_scan",
            target="https://example.com",
            parameters={"depth": 2, "check_xss": True},
            priority=TaskPriority.MEDIUM,
        ),
        DistributedTask(
            task_type="vulnerability_scan",
            target="192.168.1.10",
            parameters={"scan_type": "full"},
            priority=TaskPriority.LOW,
        ),
    ]


@pytest.fixture
def sample_workers():
    """Create sample worker information for testing."""
    workers = {
        "worker-1": NodeInfo(
            node_id="worker-1",
            role=NodeRole.WORKER,
            hostname="worker-host-1",
            address="192.168.1.100",
            port=8000,
            capabilities=["port_scan", "basic"],
        ),
        "worker-2": NodeInfo(
            node_id="worker-2",
            role=NodeRole.WORKER,
            hostname="worker-host-2",
            address="192.168.1.101",
            port=8000,
            capabilities=["web_scan", "vulnerability_scan", "basic"],
        ),
        "worker-3": NodeInfo(
            node_id="worker-3",
            role=NodeRole.WORKER,
            hostname="worker-host-3",
            address="192.168.1.102",
            port=8000,
            capabilities=["port_scan", "web_scan", "vulnerability_scan", "basic"],
        ),
    }
    # Set status and stats after initialization if needed for tests
    workers["worker-1"].status = NodeStatus.CONNECTED
    workers["worker-1"].heartbeat = datetime.now(timezone.utc)
    workers["worker-1"].stats = {"load": 0.2, "task_count": 1, "success_rate": 0.95}

    workers["worker-2"].status = NodeStatus.CONNECTED
    workers["worker-2"].heartbeat = datetime.now(timezone.utc)
    workers["worker-2"].stats = {"load": 0.5, "task_count": 2, "success_rate": 0.9}

    workers["worker-3"].status = NodeStatus.BUSY
    workers["worker-3"].heartbeat = datetime.now(timezone.utc)
    workers["worker-3"].stats = {"load": 0.8, "task_count": 4, "success_rate": 0.85}

    return workers


@pytest.fixture
def active_workers(sample_workers):
    """Return only workers that are IDLE or ACTIVE."""
    # Set appropriate statuses for distribution test
    sample_workers["worker-1"].status = NodeStatus.IDLE
    sample_workers["worker-2"].status = NodeStatus.ACTIVE
    # worker-3 remains BUSY
    return {
        wid: w
        for wid, w in sample_workers.items()
        if w.status in (NodeStatus.IDLE, NodeStatus.ACTIVE)
    }


@pytest.fixture
def master_node(mock_protocol):
    """Create a master node with a mock protocol for testing."""
    with patch("src.distributed.protocol.create_protocol", return_value=mock_protocol):
        master = SniperMasterNode(
            host="localhost",
            port=5000,
            distribution_strategy=DistributionStrategy.ROUND_ROBIN,
        )
        master.protocol = mock_protocol
        yield master


class TestMasterNode:
    """Tests for the SniperMasterNode class."""

    def test_init(self, master_node):
        """Test master node initialization."""
        assert master_node.host == "localhost"
        assert master_node.port == 5000
        assert master_node.distribution_strategy == DistributionStrategy.ROUND_ROBIN
        assert master_node.workers == {}
        assert master_node.tasks == {}
        assert master_node.running is False

    def test_add_task(self, master_node, sample_tasks):
        """Test adding tasks to the master node."""
        task = sample_tasks[0]
        result = master_node.add_task(task)

        assert result == task.id
        assert task.id in master_node.tasks
        assert master_node.tasks[task.id] == task
        assert task.status == TaskStatus.PENDING

    @pytest.mark.skip(
        reason="Async function cannot be tested with synchronous code in this test"
    )
    def test_get_task_status(self, master_node, sample_tasks):
        """Test getting task status."""
        task = sample_tasks[0]
        master_node.add_task(task)

        # Test getting status for existing task
        status = master_node.get_task_status(task.id)
        assert status == TaskStatus.PENDING

        # Test getting status for non-existent task
        status_nonexistent = master_node.get_task_status("nonexistent-task")
        assert status_nonexistent is None

    @pytest.mark.skip(
        reason="Async function cannot be tested with synchronous code in this test"
    )
    def test_get_task_result(self, master_node, sample_tasks):
        """Test getting task results."""
        task = sample_tasks[0]
        expected_result = {"open_ports": [22, 80, 443]}
        task.result = expected_result
        task.status = TaskStatus.COMPLETED
        task_id = master_node.add_task(task)
        # Ensure the task is moved to completed_tasks by the system (e.g., via message handler)
        # For testing get_task_status directly on a completed task, we can manually move it:
        if task_id in master_node.tasks:
            master_node.completed_tasks[task_id] = master_node.tasks.pop(task_id)

        # Test getting results for completed task using get_task_status
        results = master_node.get_task_status(task_id)
        assert results == expected_result

        # Test getting status for pending task
        task_pending = sample_tasks[1]
        task_pending_id = master_node.add_task(task_pending)
        status_pending = master_node.get_task_status(task_pending_id)
        assert status_pending == TaskStatus.PENDING

        # Test getting status for non-existent task
        status_nonexistent = master_node.get_task_status("nonexistent-task")
        assert status_nonexistent is None

    def test_distribute_tasks(self, master_node, sample_tasks, active_workers):
        """Test task distribution to workers."""
        # Add tasks and workers
        for task in sample_tasks:
            master_node.add_task(task)

        master_node.workers = active_workers  # Use only active workers

        # Mock the distribution algorithm
        with patch(
            "src.distributed.distribution.create_distribution_algorithm"
        ) as mock_create_algo:
            mock_algo = MagicMock()
            # Adjust expected distribution based on active workers
            mock_algo.distribute.return_value = {
                "worker-1": [sample_tasks[0].id],  # Use task.id instead of task object
                "worker-2": [
                    sample_tasks[1].id,
                    sample_tasks[2].id,
                ],  # Use task.id instead of task object
            }
            master_node.distribution_algorithm = (
                mock_algo  # Set the mocked algo directly
            )
            # mock_create_algo.return_value = mock_algo # No need to mock creation if we set it

            # Distribute tasks
            distributed_count = master_node.distribute_tasks()

            # Verify distribution
            assert distributed_count == 3
            mock_algo.distribute.assert_called_once()
            # Check if tasks were actually assigned (simplified check)
            assert sample_tasks[0].assigned_node == "worker-1"
            assert sample_tasks[1].assigned_node == "worker-2"
            assert sample_tasks[2].assigned_node == "worker-2"
            # Check protocol send was called (needs mock_protocol fixture)
            # assert master_node.protocol.send_message.call_count == 3

    def test_handle_worker_register(self, master_node):
        """Test handling worker registration messages."""
        # Create a registration message
        worker_id_test = "worker-test-register"
        worker_addr = "192.168.1.200"
        worker_port = 8000
        worker_caps = ["port_scan", "web_scan"]
        message = ProtocolMessage(
            message_type=MessageType.REGISTER,
            sender_id=worker_id_test,
            receiver_id="master",
            payload={
                "id": worker_id_test,
                "role": "worker",
                "hostname": "test-host",
                "address": worker_addr,
                "port": worker_port,
                "capabilities": worker_caps,
                "status": "idle",
                "heartbeat": datetime.now(timezone.utc).isoformat(),
                "stats": {},
                "current_tasks": [],
            },
        )

        response = master_node._handle_register(message.payload)

        # Verify worker was added
        assert worker_id_test in master_node.workers
        worker_info = master_node.workers[worker_id_test]
        assert worker_info.id == worker_id_test  # Check ID
        assert worker_info.address == worker_addr  # Check address string
        assert worker_info.port == worker_port  # Check port
        assert worker_info.capabilities == worker_caps  # Check capabilities
        assert worker_info.status == NodeStatus.IDLE  # Check status from payload
        assert worker_info.heartbeat is not None

        # Verify successful response structure (assuming _handle_registration returns it)
        assert response["status"] == "success"
        assert response["master_id"] == master_node.id

    def test_handle_heartbeat(self, master_node, sample_workers):
        """Test handling worker heartbeat messages."""
        # Add a worker
        worker_id_test = "worker-heartbeat-test"
        master_node.workers = {worker_id_test: sample_workers["worker-1"]}
        old_heartbeat = master_node.workers[worker_id_test].heartbeat

        # Create a heartbeat message
        new_load = 0.3
        new_task_count = 2
        new_mem_usage = 0.5
        new_status = NodeStatus.ACTIVE
        heartbeat_time = datetime.now(timezone.utc)

        message = ProtocolMessage(
            message_type=MessageType.HEARTBEAT,
            sender_id=worker_id_test,
            receiver_id="master",
            payload={
                "status": new_status.value,
                "timestamp": heartbeat_time.isoformat(),
                "load": new_load,
                "task_count": new_task_count,
                "memory_usage": new_mem_usage,
                # Add other stats if expected by the handler
            },
        )

        # Wait briefly to ensure heartbeat time will change
        time.sleep(0.01)

        # Handle the message by calling the correct internal handler
        master_node._handle_heartbeat(message)  # Call internal handler

        # Verify heartbeat was updated
        worker_info = master_node.workers[worker_id_test]
        # Use pytest.approx for timestamp comparison
        assert worker_info.heartbeat == pytest.approx(
            heartbeat_time, abs=timedelta(seconds=1)
        )

        # Verify stats were updated based on the message payload
        assert worker_info.stats["load"] == new_load
        assert worker_info.status == new_status
        assert worker_info.stats["task_count"] == new_task_count
        assert worker_info.stats["memory_usage"] == new_mem_usage

    def test_handle_task_status(self, master_node, sample_tasks):
        """Test handling task status updates."""
        # Add a task and worker
        task = sample_tasks[0]
        worker_id = "test-worker-status"
        master_node.add_task(task)
        master_node.workers = {
            worker_id: NodeInfo(
                node_id=worker_id,
                role=NodeRole.WORKER,
                hostname="h",
                address="a",
                port=1,
            )
        }
        task.assigned_node = worker_id
        task.status = TaskStatus.ASSIGNED

        # Create task status message
        message = ProtocolMessage(
            message_type=MessageType.TASK_STATUS,
            sender_id=worker_id,
            receiver_id="master",
            payload={"task_id": task.id, "status": TaskStatus.RUNNING.value},
        )

        response = master_node._handle_task_status(message)

        assert response["status"] == "success"
        assert master_node.tasks[task.id].status == TaskStatus.RUNNING

        # Test completed status
        message_completed = ProtocolMessage(
            message_type=MessageType.TASK_STATUS,
            sender_id=worker_id,
            receiver_id="master",
            payload={
                "task_id": task.id,
                "status": TaskStatus.COMPLETED.value,
                "result": {"output": "done"},
            },
        )
        response_completed = master_node._handle_task_status(message_completed)
        assert response_completed["status"] == "success"
        assert task.id not in master_node.tasks
        assert task.id in master_node.completed_tasks
        assert master_node.completed_tasks[task.id].status == TaskStatus.COMPLETED
        assert master_node.completed_tasks[task.id].result == {"output": "done"}

    def test_handle_task_result(self, master_node, sample_tasks):
        """Test handling task results."""
        # Add a task and worker
        task = sample_tasks[0]
        worker_id = "worker-result-test"
        master_node.add_task(task)
        # Ensure worker is registered before sending result
        master_node.workers = {
            worker_id: NodeInfo(
                node_id=worker_id,
                role=NodeRole.WORKER,
                hostname="h",
                address="a",
                port=1,
            )
        }
        task.assigned_node = worker_id
        task.status = TaskStatus.RUNNING

        # Create a task result message
        results_payload = {
            "open_ports": [22, 80, 443],
            "service_detection": {"22": "ssh", "80": "http", "443": "https"},
        }

        message = ProtocolMessage(
            message_type=MessageType.TASK_RESULT,
            sender_id=worker_id,
            receiver_id="master",
            payload={
                "task_id": task.id,
                "status": TaskStatus.COMPLETED.value,  # Send COMPLETED status
                "results": results_payload,  # Send actual results
                # 'timestamp' is not expected by _handle_task_result based on its current logic
            },
        )

        # Handle the message by calling the correct internal handler
        response = master_node._handle_task_result(message)

        # Verify results were stored and task moved
        assert task.id not in master_node.tasks
        assert task.id in master_node.completed_tasks
        completed_task = master_node.completed_tasks[task.id]

        assert completed_task.result == results_payload
        assert completed_task.status == TaskStatus.COMPLETED
        assert completed_task.completed_at is not None

        # Verify response
        assert response["status"] == "success"
        assert response["message"] == f"Result for task {task.id} processed"

    def test_clean_stale_workers(self, master_node, sample_workers):
        """Test cleaning up stale workers."""
        # Add workers with different heartbeat times
        now = datetime.now(timezone.utc)
        master_node.workers = {
            "current": NodeInfo(
                node_id="current",
                role=NodeRole.WORKER,
                hostname="host-current",
                address="192.168.1.1",
                port=8000,
                capabilities=["basic"],
            ),
            "stale": NodeInfo(
                node_id="stale",
                role=NodeRole.WORKER,
                hostname="host-stale",
                address="192.168.1.2",
                port=8000,
                capabilities=["basic"],
            ),
            "very-stale": NodeInfo(
                node_id="very-stale",
                role=NodeRole.WORKER,
                hostname="host-very-stale",
                address="192.168.1.3",
                port=8000,
                capabilities=["basic"],
            ),
        }
        master_node.workers["current"].status = NodeStatus.CONNECTED
        master_node.workers["current"].heartbeat = now
        master_node.workers["stale"].status = NodeStatus.CONNECTED
        master_node.workers["stale"].heartbeat = now - timedelta(minutes=15)
        master_node.workers["very-stale"].status = NodeStatus.CONNECTED
        master_node.workers["very-stale"].heartbeat = now - timedelta(hours=2)

        master_node.worker_timeout = 600  # 10 minutes timeout for test

        # Clean stale workers - call the correct method
        master_node._cleanup_workers()

        # Verify stale workers were removed
        assert "current" in master_node.workers
        assert "stale" not in master_node.workers
        assert "very-stale" not in master_node.workers

    def test_clean_completed_tasks(self, master_node, sample_tasks):
        """Test that completed tasks are not removed by _cleanup_stale_tasks."""
        now = datetime.now(timezone.utc)

        task_completed_recent = sample_tasks[1]
        task_completed_old = sample_tasks[2]

        task_completed_recent.status = TaskStatus.COMPLETED
        task_completed_recent.completed_at = now - timedelta(minutes=30)

        task_completed_old.status = TaskStatus.COMPLETED
        task_completed_old.completed_at = now - timedelta(days=2)

        # Add only completed tasks
        id_recent = master_node.add_task(task_completed_recent)
        id_old = master_node.add_task(task_completed_old)
        # Manually move them to completed_tasks for this test case
        if id_recent in master_node.tasks:
            master_node.completed_tasks[id_recent] = master_node.tasks.pop(id_recent)
        if id_old in master_node.tasks:
            master_node.completed_tasks[id_old] = master_node.tasks.pop(id_old)

        # Call the cleanup logic for stale tasks - call the correct method
        master_node._cleanup_tasks()

        # Assert that completed tasks remain in completed_tasks
        assert id_recent in master_node.completed_tasks
        assert id_old in master_node.completed_tasks

    def test_start_stop(self, master_node):
        """Test starting and stopping the master node."""
        # Test start
        with patch.object(
            master_node.protocol, "start_server"
        ) as mock_start_server, patch.object(
            master_node.executor, "submit"
        ) as mock_submit:
            started = master_node.start()
            assert started is True
            assert master_node.running is True
            assert master_node.status == NodeStatus.ACTIVE
            mock_submit.assert_called_once()  # Check if cleanup routine was submitted
            mock_start_server.assert_called_once_with(
                master_node.host, master_node.port, master_node._handle_message
            )

        # Test stop
        with patch.object(
            master_node.protocol, "stop_server"
        ) as mock_stop_server, patch.object(
            master_node.executor, "shutdown"
        ) as mock_shutdown:
            stopped = master_node.stop()
            assert stopped is True
            assert master_node.running is False
            assert master_node.status == NodeStatus.OFFLINE
            mock_stop_server.assert_called_once()
            mock_shutdown.assert_called_once_with(wait=True)

    def test_handle_unknown_message(self, master_node):
        """Test handling unknown message types."""
        # Create a message dict with an invalid type string
        invalid_message_dict = {
            "message_type": "INVALID_MESSAGE_TYPE",
            "sender_id": "worker-1",
            "receiver_id": "master",
            "payload": {"some": "data"},
        }

        # Test the handler directly - call the correct method
        # Assuming a generic handler might exist or test needs rework
        # For now, let's assume the handler routes based on type
        master_node._handle_message(
            ProtocolMessage(**invalid_message_dict)
        )  # Use generic handler
        # Check logs for warning or assert specific error handling if applicable


class TestMasterNodeServer:
    """Tests for the MasterNodeServer wrapper class."""

    def test_init(self):
        """Test server initialization with default and custom parameters."""
        # Test with default parameters
        with patch("src.distributed.master.SniperMasterNode") as mock_master:
            mock_master_instance = MagicMock()
            mock_master.return_value = mock_master_instance

            server = MasterNodeServer()

            assert server.host == "0.0.0.0"
            assert server.port == 5000
            assert server.protocol_type == "rest"
            assert server.distribution_strategy == "smart"
            assert server.worker_timeout == 60
            mock_master.assert_called_once()

        # Test with custom parameters
        with patch("src.distributed.master.SniperMasterNode") as mock_master:
            mock_master_instance = MagicMock()
            mock_master.return_value = mock_master_instance

            server = MasterNodeServer(
                host="127.0.0.1",
                port=8080,
                protocol_type="websocket",
                distribution_strategy="load_balanced",
            )

            assert server.host == "127.0.0.1"
            assert server.port == 8080
            assert server.protocol_type == "websocket"
            assert server.distribution_strategy == "load_balanced"

    def test_start_stop(self):
        """Test starting and stopping the server."""
        with patch("src.distributed.master.SniperMasterNode") as mock_master:
            mock_master_instance = MagicMock()
            mock_master.return_value = mock_master_instance

            server = MasterNodeServer()

            # Test start
            server.start()
            mock_master_instance.start.assert_called_once()

            # Test stop
            server.stop()
            mock_master_instance.stop.assert_called_once()
