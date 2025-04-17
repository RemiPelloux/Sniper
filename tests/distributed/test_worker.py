"""
Tests for the worker node implementation in the distributed scanning architecture.
"""

import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.distributed.base import DistributedTask, NodeStatus, TaskPriority, TaskStatus
from src.distributed.protocol import MessageType, ProtocolMessage
from src.distributed.worker import SniperWorkerNode, WorkerNodeClient


@pytest.fixture
def mock_protocol():
    """Create a mock protocol for testing."""
    mock = MagicMock()
    mock.connect.return_value = True
    mock.send_message.return_value = True
    return mock


@pytest.fixture
def worker_node(mock_protocol):
    """Create a worker node with a mock protocol for testing."""
    with patch("src.distributed.worker.create_protocol", return_value=mock_protocol):
        worker = SniperWorkerNode(
            master_host="localhost",
            master_port=5555,
            worker_id="test-worker-1",
            capabilities=["nmap", "vulnerability_scan", "port_scan"],
            heartbeat_interval=1,  # Fast heartbeat for testing
            max_concurrent_tasks=3,
        )
        yield worker


@pytest.fixture
def sample_task():
    """Create a sample task for testing."""
    return DistributedTask(
        task_type="port_scan",
        target={"host": "192.168.1.1", "port_range": "1-1000"},
        parameters={"scan_type": "quick"},
        priority=TaskPriority.MEDIUM,
        timeout=3600,
        dependencies=[],
    )


class TestWorkerNodeBasics:
    """Test basic worker node functionality."""

    def test_initialization(self, worker_node):
        """Test worker node initialization."""
        assert worker_node.id == "test-worker-1"
        assert worker_node.master_address == "localhost"
        assert worker_node.master_port == 5555
        assert "port_scan" in worker_node.capabilities
        assert worker_node.max_concurrent_tasks == 3
        assert worker_node.heartbeat_interval == 1
        assert worker_node.status == NodeStatus.INITIALIZING

    def test_start_stop(self, worker_node, mock_protocol):
        """Test worker node start and stop functionality."""
        # Patch _start_rest_server to avoid actual server startup
        with patch.object(worker_node, "_start_rest_server"):
            # Start the worker
            assert worker_node.start() is True
            assert worker_node.running is True
            assert worker_node.status == NodeStatus.ACTIVE

            # Verify heartbeat thread is running
            assert worker_node.heartbeat_thread is not None
            assert worker_node.heartbeat_thread.is_alive()

            # Stop the worker
            worker_node.stop()
            assert worker_node.running is False

            # Give time for threads to stop
            time.sleep(0.1)

            # Verify heartbeat thread is stopped or stopping
            assert (
                not worker_node.heartbeat_thread.is_alive()
                or worker_node.heartbeat_thread.daemon
            )

    def test_register_with_master(self, worker_node, mock_protocol):
        """Test worker registration with master."""
        result = worker_node._register_with_master()
        assert result is True
        assert worker_node.status == NodeStatus.ACTIVE

        # Verify registration message was created properly
        # In a real test with a mock, we would assert on the call arguments
        # but our implementation is simplified for this test


class TestTaskHandling:
    """Test task handling functionality."""

    def test_execute_task(self, worker_node, sample_task):
        """Test task execution."""
        # Add task to worker's tasks
        with worker_node.task_lock:
            worker_node.tasks[sample_task.id] = sample_task

        # Patch executor to avoid actual submission
        with patch.object(worker_node.executor, "submit") as mock_submit:
            worker_node._execute_task(sample_task.id)

            # Verify task status was updated
            assert sample_task.status == TaskStatus.RUNNING
            assert sample_task.start_time is not None

            # Verify task was submitted to executor
            mock_submit.assert_called_once()

    def test_cancel_task(self, worker_node, sample_task):
        """Test task cancellation."""
        # Add task to worker's tasks
        with worker_node.task_lock:
            worker_node.tasks[sample_task.id] = sample_task
            # Add a mock future
            mock_future = MagicMock()
            mock_future.done.return_value = False
            worker_node.future_tasks[sample_task.id] = mock_future

        # Cancel the task
        worker_node._cancel_task(sample_task.id)

        # Verify task was removed
        with worker_node.task_lock:
            assert sample_task.id not in worker_node.tasks
            assert sample_task.id not in worker_node.future_tasks

        # Verify future was cancelled
        mock_future.cancel.assert_called_once()

    def test_handle_task_assignment(self, worker_node):
        """Test handling of task assignment messages."""
        # Create a task assignment message
        message = ProtocolMessage(
            message_type=MessageType.TASK_ASSIGNMENT,
            sender_id="master",
            receiver_id="test-worker-1",
            payload={
                "task": {
                    "id": "task-456",
                    "task_type": "port_scan",  # Using a capability the worker has
                    "priority": TaskPriority.HIGH.value,
                    "target": {"host": "192.168.1.100"},
                    "parameters": {"scan_type": "deep"},
                }
            },
        )

        # Patch execute_task to avoid actual execution
        with patch.object(worker_node, "_execute_task"):
            worker_node._handle_task_assignment(message)

            # Verify task was added and accepted
            with worker_node.task_lock:
                assert "task-456" in worker_node.tasks
                task = worker_node.tasks["task-456"]
                assert task.task_type == "port_scan"
                assert task.status == TaskStatus.ASSIGNED

    def test_handle_task_assignment_at_capacity(self, worker_node, sample_task):
        """Test handling of task assignment when at capacity."""
        # Fill worker to capacity
        with worker_node.task_lock:
            for i in range(worker_node.max_concurrent_tasks):
                task = DistributedTask(
                    task_type="port_scan",
                    target={"host": "192.168.1.1"},
                    parameters={"scan_type": "quick"},
                    priority=TaskPriority.MEDIUM,
                    timeout=3600,
                )
                worker_node.tasks[task.id] = task

        # Create a task assignment message
        message = ProtocolMessage(
            message_type=MessageType.TASK_ASSIGNMENT,
            sender_id="master",
            receiver_id="test-worker-1",
            payload={
                "task": {
                    "id": "overflow-task",
                    "task_type": "port_scan",
                    "priority": TaskPriority.HIGH.value,
                    "target": {"host": "192.168.1.100"},
                    "parameters": {"scan_type": "deep"},
                }
            },
        )

        # Patch send_task_status to capture rejection
        with patch.object(worker_node, "_send_task_status") as mock_send_status:
            worker_node._handle_task_assignment(message)

            # Verify task was rejected
            mock_send_status.assert_called_with(
                "overflow-task", TaskStatus.FAILED, "Worker at capacity"
            )

            # Verify task was not added
            with worker_node.task_lock:
                assert "overflow-task" not in worker_node.tasks

    def test_handle_task_assignment_missing_capability(self, worker_node):
        """Test handling of task assignment requiring missing capability."""
        # Create a task assignment message with unsupported capability
        message = ProtocolMessage(
            message_type=MessageType.TASK_ASSIGNMENT,
            sender_id="master",
            receiver_id="test-worker-1",
            payload={
                "task": {
                    "id": "unsupported-task",
                    "task_type": "unsupported_scan_type",  # Not in capabilities
                    "priority": TaskPriority.MEDIUM.value,
                    "target": {"host": "192.168.1.100"},
                    "parameters": {"scan_type": "quick"},
                }
            },
        )

        # Patch send_task_status to capture rejection
        with patch.object(worker_node, "_send_task_status") as mock_send_status:
            worker_node._handle_task_assignment(message)

            # Verify capability check rejection
            mock_send_status.assert_called_with(
                "unsupported-task",
                TaskStatus.FAILED,
                "Worker doesn't support unsupported_scan_type",
            )

            # Verify task was not added
            with worker_node.task_lock:
                assert "unsupported-task" not in worker_node.tasks


class TestMessageHandling:
    """Test message handling functionality."""

    def test_handle_cancel_task(self, worker_node, sample_task):
        """Test handling of cancel task messages."""
        # Add task to worker's tasks
        with worker_node.task_lock:
            worker_node.tasks[sample_task.id] = sample_task

        # Create a cancel task message
        message = ProtocolMessage(
            message_type=MessageType.CANCEL_TASK,
            sender_id="master",
            receiver_id="test-worker-1",
            payload={"task_id": sample_task.id},
        )

        # Patch _cancel_task to verify it's called
        with patch.object(worker_node, "_cancel_task") as mock_cancel:
            worker_node._handle_cancel_task(message)
            mock_cancel.assert_called_with(sample_task.id)

    def test_handle_shutdown(self, worker_node):
        """Test handling of shutdown messages."""
        # Create a shutdown message
        message = ProtocolMessage(
            message_type=MessageType.SHUTDOWN,
            sender_id="master",
            receiver_id="test-worker-1",
            payload={"grace_period": 10},
        )

        # Patch threading.Thread to verify graceful shutdown is started
        with patch("threading.Thread") as mock_thread:
            worker_node._handle_shutdown(message)

            # Verify thread was created for graceful shutdown
            mock_thread.assert_called_once()

            # Verify the first arg to Thread constructor is the graceful shutdown method
            args, kwargs = mock_thread.call_args
            assert kwargs["target"] == worker_node._graceful_shutdown
            assert kwargs["args"] == (10,)
            assert kwargs["daemon"] is True

    def test_handle_message_dispatch(self, worker_node):
        """Test message handling dispatch to appropriate handlers."""
        # Create messages of different types
        task_msg = ProtocolMessage(
            message_type=MessageType.TASK_ASSIGNMENT,
            sender_id="master",
            receiver_id="test-worker-1",
            payload={"task": {"id": "test-task", "task_type": "port_scan"}},
        )

        cancel_msg = ProtocolMessage(
            message_type=MessageType.CANCEL_TASK,
            sender_id="master",
            receiver_id="test-worker-1",
            payload={"task_id": "test-task"},
        )

        shutdown_msg = ProtocolMessage(
            message_type=MessageType.SHUTDOWN,
            sender_id="master",
            receiver_id="test-worker-1",
            payload={},
        )

        unknown_msg = ProtocolMessage(
            message_type=MessageType.REGISTER,  # Not handled by worker
            sender_id="master",
            receiver_id="test-worker-1",
            payload={},
        )

        # Create mock handlers
        mock_task_handler = MagicMock()
        mock_cancel_handler = MagicMock()
        mock_shutdown_handler = MagicMock()

        # Save original handlers
        original_handlers = worker_node._message_handlers

        try:
            # Replace the real handlers with mocks in the message_handlers dictionary
            worker_node._message_handlers = {
                MessageType.TASK_ASSIGNMENT: mock_task_handler,
                MessageType.CANCEL_TASK: mock_cancel_handler,
                MessageType.SHUTDOWN: mock_shutdown_handler,
            }

            # Test dispatch to each handler
            worker_node._handle_message(task_msg)
            mock_task_handler.assert_called_with(task_msg)

            worker_node._handle_message(cancel_msg)
            mock_cancel_handler.assert_called_with(cancel_msg)

            worker_node._handle_message(shutdown_msg)
            mock_shutdown_handler.assert_called_with(shutdown_msg)

            # Test unknown message type
            with patch("src.distributed.worker.logger.warning") as mock_warn:
                worker_node._handle_message(unknown_msg)
                mock_warn.assert_called_once()
        finally:
            # Restore original handlers
            worker_node._message_handlers = original_handlers


class TestTaskExecutors:
    """Test task executor methods."""

    def test_execute_nmap_scan(self, worker_node, sample_task):
        """Test nmap scan executor."""
        # Update task to be nmap_scan
        sample_task.task_type = "nmap_scan"
        sample_task.parameters = {"target": "192.168.1.1", "scan_type": "basic"}

        # Mock time.sleep to avoid waiting
        with patch("time.sleep"):
            result = worker_node._execute_nmap_scan(sample_task)

            # Verify result structure
            assert "target" in result
            assert result["target"] == "192.168.1.1"
            assert "scan_type" in result
            assert "ports" in result
            assert "open_services" in result

    def test_execute_vulnerability_scan(self, worker_node, sample_task):
        """Test vulnerability scan executor."""
        # Update task to be vulnerability_scan
        sample_task.task_type = "vulnerability_scan"
        sample_task.parameters = {"target": "192.168.1.1", "depth": "deep"}

        # Mock time.sleep to avoid waiting
        with patch("time.sleep"):
            result = worker_node._execute_vulnerability_scan(sample_task)

            # Verify result structure
            assert "target" in result
            assert result["target"] == "192.168.1.1"
            assert "depth" in result
            assert "vulnerabilities" in result
            assert len(result["vulnerabilities"]) > 0

    def test_execute_web_scan(self, worker_node, sample_task):
        """Test web scan executor."""
        # Update task to be web_scan
        sample_task.task_type = "web_scan"
        sample_task.parameters = {"target": "example.com", "scan_depth": 2}

        # Mock time.sleep to avoid waiting
        with patch("time.sleep"):
            result = worker_node._execute_web_scan(sample_task)

            # Verify result structure
            assert "target" in result
            assert result["target"] == "example.com"
            assert "scan_depth" in result
            assert "findings" in result
            assert len(result["findings"]) > 0

    def test_execute_port_scan(self, worker_node, sample_task):
        """Test port scan executor."""
        # Update task to be port_scan
        sample_task.task_type = "port_scan"
        sample_task.parameters = {"target": "192.168.1.1", "port_range": "1-5000"}

        # Mock time.sleep to avoid waiting
        with patch("time.sleep"):
            result = worker_node._execute_port_scan(sample_task)

            # Verify result structure
            assert "target" in result
            assert result["target"] == "192.168.1.1"
            assert "port_range" in result
            assert "open_ports" in result
            # Should include port 3306 since range is 1-5000
            assert 3306 in result["open_ports"]

    def test_execute_default_task(self, worker_node, sample_task):
        """Test default task executor for unknown task types."""
        # Update task to be an unknown type
        sample_task.task_type = "unknown_task_type"
        sample_task.parameters = {"param1": "value1"}

        # Mock time.sleep to avoid waiting and logger to verify warning
        with patch("time.sleep"), patch(
            "src.distributed.worker.logger.warning"
        ) as mock_warn:

            result = worker_node._execute_default_task(sample_task)

            # Verify warning was logged
            mock_warn.assert_called_once()

            # Verify result structure
            assert "status" in result
            assert result["status"] == "completed"
            assert "message" in result


class TestWorkerNodeClient:
    """Test the WorkerNodeClient wrapper class."""

    def test_client_initialization(self):
        """Test client initialization."""
        with patch("src.distributed.worker.setup_logging"), patch(
            "src.distributed.worker.SniperWorkerNode"
        ) as mock_worker:

            client = WorkerNodeClient(
                master_host="test-master.local",
                master_port=5555,
                worker_id="test-client-worker",
                protocol_type="rest",
                capabilities=["nmap", "web_scan"],
            )

            # Verify worker node was created with correct params
            mock_worker.assert_called_once()
            args, kwargs = mock_worker.call_args
            assert kwargs["master_host"] == "test-master.local"
            assert kwargs["master_port"] == 5555
            assert kwargs["worker_id"] == "test-client-worker"
            assert kwargs["protocol_type"] == "rest"
            assert kwargs["capabilities"] == ["nmap", "web_scan"]

    def test_detect_capabilities(self):
        """Test capability detection."""
        with patch('src.distributed.worker.setup_logging'), \
             patch('src.distributed.worker.SniperWorkerNode'):
            
            client = WorkerNodeClient()
            capabilities = client._detect_capabilities()
            
            # Verify some capabilities were detected
            assert isinstance(capabilities, list)
            assert len(capabilities) > 0
            assert "basic" in capabilities

    def test_start_stop(self):
        """Test start and stop methods."""
        with patch('src.distributed.worker.setup_logging'), \
             patch('src.distributed.worker.SniperWorkerNode') as mock_worker:
            
            # Create mock worker node
            mock_worker_instance = MagicMock()
            mock_worker.return_value = mock_worker_instance
            
            # Configure mock methods
            mock_worker_instance.start.return_value = True
            
            # Create client
            client = WorkerNodeClient()
            
            # Test start
            result = client.start()
            assert result is True
            mock_worker_instance.start.assert_called_once()
            
            # Test stop
            client.stop()
            mock_worker_instance.stop.assert_called_once()
