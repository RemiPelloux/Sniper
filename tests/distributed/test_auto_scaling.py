"""
Unit tests for the auto-scaling module of the distributed architecture.
"""

import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from src.distributed.auto_scaling import (
    AutoScaler,
    DockerWorkerProvider,
    LocalWorkerProvider,
    ScalingConfig,
    ScalingMode,
    ScalingPolicy,
    ScalingRule,
    WorkerProvider,
)
from src.distributed.base import (
    DistributedTask,
    NodeInfo,
    NodeRole,
    NodeStatus,
    TaskPriority,
    TaskStatus,
)


class TestAutoScaler(unittest.TestCase):
    """Test suite for the AutoScaler class."""

    def setUp(self):
        """Set up test fixtures."""
        # Mock master node
        self.master_node = MagicMock()
        self.master_node.host = "localhost"
        self.master_node.port = 5000
        self.master_node.workers = {}
        self.master_node.worker_metrics = {}
        self.master_node.pending_tasks = []
        self.master_node.tasks = {}

        # Basic config with dummy provider
        self.config = ScalingConfig(
            min_nodes=1,
            max_nodes=5,
            scaling_policy=ScalingPolicy.QUEUE_DEPTH,
            scaling_mode=ScalingMode.BIDIRECTIONAL,
            provider=WorkerProvider.LOCAL,
            check_interval=1,  # 1 second for faster testing
        )

        # Setup test paths
        self.temp_dir = tempfile.mkdtemp()

        # Create auto-scaler with mocked provider
        with patch("src.distributed.auto_scaling.LocalWorkerProvider") as mock_provider:
            self.provider_instance = mock_provider.return_value
            self.provider_instance.create_worker.return_value = "worker-test-1"
            self.auto_scaler = AutoScaler(
                master_node=self.master_node, config=self.config
            )

    def tearDown(self):
        """Clean up test fixtures."""
        # Ensure auto-scaler is stopped
        if hasattr(self, "auto_scaler") and self.auto_scaler.running:
            self.auto_scaler.stop()

    def test_init(self):
        """Test auto-scaler initialization."""
        self.assertEqual(self.auto_scaler.master_node, self.master_node)
        self.assertEqual(self.auto_scaler.config.min_nodes, 1)
        self.assertEqual(self.auto_scaler.config.max_nodes, 5)
        self.assertEqual(
            self.auto_scaler.config.scaling_policy, ScalingPolicy.QUEUE_DEPTH
        )
        self.assertFalse(self.auto_scaler.running)

    def test_start_stop(self):
        """Test starting and stopping the auto-scaler."""
        # Start
        self.auto_scaler.start()
        self.assertTrue(self.auto_scaler.running)
        self.assertIsNotNone(self.auto_scaler.scaling_thread)

        # Stop
        self.auto_scaler.stop()
        self.assertFalse(self.auto_scaler.running)

    @patch("src.distributed.auto_scaling.LocalWorkerProvider")
    def test_create_provider(self, mock_provider_class):
        """Test provider creation based on type."""
        # Setup
        mock_provider_instance = mock_provider_class.return_value

        # Test local provider
        auto_scaler = AutoScaler(
            master_node=self.master_node,
            config=ScalingConfig(provider=WorkerProvider.LOCAL),
        )
        self.assertEqual(auto_scaler.provider, mock_provider_instance)

        # Test with Docker provider
        with patch("src.distributed.auto_scaling.DockerWorkerProvider") as mock_docker:
            docker_instance = mock_docker.return_value
            auto_scaler = AutoScaler(
                master_node=self.master_node,
                config=ScalingConfig(provider=WorkerProvider.DOCKER),
            )
            self.assertEqual(auto_scaler.provider, docker_instance)

    def test_create_default_rules(self):
        """Test default scaling rules creation."""
        rules = self.auto_scaler._create_default_rules()
        self.assertEqual(len(rules), 4)

        # Check scale up rule
        scale_up_rule = rules[0]
        self.assertEqual(scale_up_rule.metric, "queue_depth_per_worker")
        self.assertEqual(scale_up_rule.threshold, 5.0)
        self.assertEqual(scale_up_rule.operation, ">")
        self.assertEqual(scale_up_rule.action, "add")

        # Check scale down rule
        scale_down_rule = rules[1]
        self.assertEqual(scale_down_rule.metric, "queue_depth_per_worker")
        self.assertEqual(scale_down_rule.threshold, 1.0)
        self.assertEqual(scale_down_rule.operation, "<")
        self.assertEqual(scale_down_rule.action, "remove")

    def test_collect_metrics(self):
        """Test metrics collection."""
        # Create mock workers and metrics
        worker1 = NodeInfo(
            node_id="worker-1",
            role=NodeRole.WORKER,
            hostname="worker1",
            address="192.168.1.101",
            port=5000,
            capabilities=["scan", "analyze"],
        )
        worker1.status = NodeStatus.ACTIVE

        worker2 = NodeInfo(
            node_id="worker-2",
            role=NodeRole.WORKER,
            hostname="worker2",
            address="192.168.1.102",
            port=5000,
            capabilities=["scan", "analyze"],
        )
        worker2.status = NodeStatus.ACTIVE

        self.master_node.workers = {"worker-1": worker1, "worker-2": worker2}

        # Mock worker metrics
        worker1_metrics = MagicMock()
        worker1_metrics.current_load = 0.5
        worker2_metrics = MagicMock()
        worker2_metrics.current_load = 0.7
        self.master_node.worker_metrics = {
            "worker-1": worker1_metrics,
            "worker-2": worker2_metrics,
        }

        # Add pending tasks
        self.master_node.pending_tasks = [MagicMock(), MagicMock(), MagicMock()]

        # Collect metrics
        metrics = self.auto_scaler._collect_metrics()

        # Verify metrics
        self.assertEqual(metrics["active_workers"], 2)
        self.assertEqual(metrics["queue_depth"], 3)
        self.assertEqual(metrics["queue_depth_per_worker"], 1.5)  # 3 tasks / 2 workers
        self.assertEqual(metrics["worker_utilization"], 0.6)  # (0.5 + 0.7) / 2

    def test_should_apply_rule_queue_depth(self):
        """Test rule application based on queue depth."""
        # Setup rule and metrics
        rule = ScalingRule(
            metric="queue_depth_per_worker",
            threshold=2.0,
            operation=">",
            action="add",
            cooldown=10,
        )

        # Metrics where rule should apply (queue depth too high)
        high_metrics = {
            "active_workers": 2,
            "queue_depth": 5,
            "queue_depth_per_worker": 2.5,
            "worker_utilization": 0.5,
        }

        # Metrics where rule should not apply (queue depth acceptable)
        low_metrics = {
            "active_workers": 2,
            "queue_depth": 3,
            "queue_depth_per_worker": 1.5,
            "worker_utilization": 0.5,
        }

        # Reset last_scale_up to pass the cooldown check for the first test
        self.auto_scaler.last_scale_up = datetime.now() - timedelta(
            seconds=20
        )  # Set time in the past

        # Test when rule should apply
        self.assertTrue(self.auto_scaler._should_apply_rule(rule, high_metrics))

        # Test when rule should not apply
        self.assertFalse(self.auto_scaler._should_apply_rule(rule, low_metrics))

        # Test cooldown period
        self.auto_scaler.last_scale_up = datetime.now()  # Reset to current time
        # Now cooldown should prevent the rule from applying
        self.assertFalse(self.auto_scaler._should_apply_rule(rule, high_metrics))

    def test_should_apply_rule_min_max_constraints(self):
        """Test rule application with min/max node constraints."""
        # Setup rules
        add_rule = ScalingRule(
            metric="queue_depth_per_worker",
            threshold=2.0,
            operation=">",
            action="add",
            cooldown=0,  # No cooldown for testing
        )

        remove_rule = ScalingRule(
            metric="queue_depth_per_worker",
            threshold=1.0,
            operation="<",
            action="remove",
            cooldown=0,  # No cooldown for testing
        )

        # Metrics
        metrics = {
            "active_workers": self.config.max_nodes,  # At max nodes
            "queue_depth": 10,
            "queue_depth_per_worker": 2.5,
            "worker_utilization": 0.5,
        }

        # Test at max nodes - should not add more
        self.assertFalse(self.auto_scaler._should_apply_rule(add_rule, metrics))

        # Test at min nodes - should not remove more
        metrics["active_workers"] = self.config.min_nodes
        metrics["queue_depth_per_worker"] = 0.5
        self.assertFalse(self.auto_scaler._should_apply_rule(remove_rule, metrics))

    def test_should_apply_rule_scaling_mode(self):
        """Test rule application with different scaling modes."""
        # Setup rules
        add_rule = ScalingRule(
            metric="queue_depth_per_worker",
            threshold=2.0,
            operation=">",
            action="add",
            cooldown=0,
        )

        remove_rule = ScalingRule(
            metric="queue_depth_per_worker",
            threshold=1.0,
            operation="<",
            action="remove",
            cooldown=0,
        )

        # Metrics
        add_metrics = {
            "active_workers": 2,
            "queue_depth": 10,
            "queue_depth_per_worker": 5.0,
            "worker_utilization": 0.5,
        }

        remove_metrics = {
            "active_workers": 3,
            "queue_depth": 1,
            "queue_depth_per_worker": 0.3,
            "worker_utilization": 0.1,
        }

        # Test UP_ONLY mode
        self.auto_scaler.config.scaling_mode = ScalingMode.UP_ONLY
        self.assertTrue(self.auto_scaler._should_apply_rule(add_rule, add_metrics))
        self.assertFalse(
            self.auto_scaler._should_apply_rule(remove_rule, remove_metrics)
        )

        # Test DOWN_ONLY mode
        self.auto_scaler.config.scaling_mode = ScalingMode.DOWN_ONLY
        self.assertFalse(self.auto_scaler._should_apply_rule(add_rule, add_metrics))
        self.assertTrue(
            self.auto_scaler._should_apply_rule(remove_rule, remove_metrics)
        )

        # Test BIDIRECTIONAL mode
        self.auto_scaler.config.scaling_mode = ScalingMode.BIDIRECTIONAL
        self.assertTrue(self.auto_scaler._should_apply_rule(add_rule, add_metrics))
        self.assertTrue(
            self.auto_scaler._should_apply_rule(remove_rule, remove_metrics)
        )

    def test_apply_scaling_action_add(self):
        """Test applying scaling action to add workers."""
        # Setup
        rule = ScalingRule(
            metric="queue_depth_per_worker",
            threshold=2.0,
            operation=">",
            action="add",
            adjustment=2,  # Add 2 workers
        )

        metrics = {
            "active_workers": 2,
            "queue_depth": 10,
            "queue_depth_per_worker": 5.0,
        }

        # Mock scale_up method
        with patch.object(self.auto_scaler, "_scale_up") as mock_scale_up:
            # Apply scaling action
            self.auto_scaler._apply_scaling_action(rule, metrics)

            # Verify scale_up was called twice
            self.assertEqual(mock_scale_up.call_count, 2)

            # Verify last_scale_up was updated
            self.assertTrue(
                (datetime.now() - self.auto_scaler.last_scale_up).total_seconds() < 1
            )

    def test_apply_scaling_action_remove(self):
        """Test applying scaling action to remove workers."""
        # Setup
        rule = ScalingRule(
            metric="worker_utilization",
            threshold=0.2,
            operation="<",
            action="remove",
            adjustment=1,  # Remove 1 worker
        )

        metrics = {
            "active_workers": 3,
            "queue_depth": 1,
            "queue_depth_per_worker": 0.3,
            "worker_utilization": 0.1,
        }

        # Mock scale_down method
        with patch.object(self.auto_scaler, "_scale_down") as mock_scale_down:
            # Apply scaling action
            self.auto_scaler._apply_scaling_action(rule, metrics)

            # Verify scale_down was called with correct argument
            mock_scale_down.assert_called_once_with(1)

            # Verify last_scale_down was updated
            self.assertTrue(
                (datetime.now() - self.auto_scaler.last_scale_down).total_seconds() < 1
            )

    def test_scale_up(self):
        """Test scaling up by adding a worker."""
        # Setup
        self.provider_instance.create_worker.return_value = "worker-new-1"

        # Scale up
        self.auto_scaler._scale_up()

        # Verify provider.create_worker was called with correct arguments
        self.provider_instance.create_worker.assert_called_once_with(
            master_host=self.master_node.host, master_port=self.master_node.port
        )

        # Verify worker was recorded in history
        self.assertIn("worker-new-1", self.auto_scaler.node_history)
        self.assertEqual(
            self.auto_scaler.node_history["worker-new-1"]["status"], "creating"
        )

    def test_scale_down(self):
        """Test scaling down by removing workers."""
        # Setup workers with different utilization
        worker1_metrics = MagicMock()
        worker1_metrics.current_load = 0.8

        worker2_metrics = MagicMock()
        worker2_metrics.current_load = 0.1

        worker3_metrics = MagicMock()
        worker3_metrics.current_load = 0.4

        self.master_node.worker_metrics = {
            "worker-1": worker1_metrics,
            "worker-2": worker2_metrics,
            "worker-3": worker3_metrics,
        }

        self.master_node.workers = {
            "worker-1": MagicMock(),
            "worker-2": MagicMock(),
            "worker-3": MagicMock(),
        }

        # Mock remove_worker method
        with patch.object(self.auto_scaler, "_remove_worker") as mock_remove_worker:
            # Scale down by 2
            self.auto_scaler._scale_down(2)

            # Should remove worker-2 (lowest load) and worker-3 (second lowest)
            self.assertEqual(mock_remove_worker.call_count, 2)
            mock_remove_worker.assert_any_call("worker-2")  # Lowest load first
            mock_remove_worker.assert_any_call("worker-3")  # Second lowest

    def test_remove_worker(self):
        """Test removing a specific worker."""
        # Setup
        worker_id = "worker-to-remove"
        self.master_node.unregister_worker.return_value = True

        # Record in history
        self.auto_scaler.node_history[worker_id] = {
            "created_at": datetime.now() - timedelta(hours=1),
            "status": "active",
        }

        # Remove worker
        self.auto_scaler._remove_worker(worker_id)

        # Verify master.unregister_worker was called
        self.master_node.unregister_worker.assert_called_once_with(worker_id)

        # Verify provider.remove_worker was called
        self.provider_instance.remove_worker.assert_called_once_with(worker_id)

        # Verify history was updated
        self.assertEqual(self.auto_scaler.node_history[worker_id]["status"], "removed")
        self.assertIn("removed_at", self.auto_scaler.node_history[worker_id])


class TestLocalWorkerProvider(unittest.TestCase):
    """Test suite for the LocalWorkerProvider class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {}
        self.provider = LocalWorkerProvider(self.config)

    @patch("subprocess.Popen")
    def test_create_worker(self, mock_popen):
        """Test creating a local worker process."""
        # Setup
        mock_process = mock_popen.return_value
        master_host = "localhost"
        master_port = 5000

        # Create worker
        worker_id = self.provider.create_worker(master_host, master_port)

        # Verify worker ID was returned
        self.assertIsNotNone(worker_id)
        self.assertTrue(worker_id.startswith("worker-"))

        # Verify subprocess.Popen was called with correct arguments
        mock_popen.assert_called_once()
        args, kwargs = mock_popen.call_args
        cmd = args[0]

        # Check command arguments
        self.assertIn("python", cmd)
        self.assertIn("-m", cmd)
        self.assertIn("src.distributed.worker", cmd)
        self.assertIn("--worker-id", cmd)
        self.assertIn("--master-host", cmd)
        self.assertIn("--master-port", cmd)

        # Check worker was stored in config
        self.assertIn("processes", self.config)
        self.assertIn(worker_id, self.config["processes"])
        self.assertEqual(self.config["processes"][worker_id], mock_process)

    def test_remove_worker(self):
        """Test removing a local worker process."""
        # Setup mock process
        worker_id = "worker-test-1"
        mock_process = MagicMock()
        self.config["processes"] = {worker_id: mock_process}

        # Remove worker
        result = self.provider.remove_worker(worker_id)

        # Verify result and process termination
        self.assertTrue(result)
        mock_process.terminate.assert_called_once()

        # Verify worker was removed from config
        self.assertNotIn(worker_id, self.config["processes"])

    def test_remove_nonexistent_worker(self):
        """Test removing a worker that doesn't exist."""
        # Setup empty processes dict
        self.config["processes"] = {}

        # Attempt to remove nonexistent worker
        result = self.provider.remove_worker("nonexistent-worker")

        # Should return False
        self.assertFalse(result)


@pytest.mark.skipif(
    not os.path.exists("/var/run/docker.sock"), reason="Docker not available"
)
class TestDockerWorkerProvider(unittest.TestCase):
    """Test suite for the DockerWorkerProvider class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {"image": "sniper-worker:latest", "network": "host"}
        self.provider = DockerWorkerProvider(self.config)

    @patch("subprocess.run")
    def test_create_worker(self, mock_run):
        """Test creating a Docker container worker."""
        # Setup mock return value
        mock_run.return_value.stdout = "container-id-123"
        master_host = "localhost"
        master_port = 5000

        # Create worker
        worker_id = self.provider.create_worker(master_host, master_port)

        # Verify worker ID was returned
        self.assertIsNotNone(worker_id)
        self.assertTrue(worker_id.startswith("worker-"))

        # Verify subprocess.run was called with correct arguments
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        cmd = args[0]

        # Check command arguments
        self.assertEqual(cmd[0], "docker")
        self.assertEqual(cmd[1], "run")
        self.assertIn("-d", cmd)
        self.assertIn("--name", cmd)
        self.assertIn("--network", cmd)
        self.assertIn("-e", cmd)
        self.assertIn(self.config["image"], cmd)

        # Check worker was stored in config
        self.assertIn("containers", self.config)
        self.assertIn(worker_id, self.config["containers"])
        container_info = self.config["containers"][worker_id]
        self.assertEqual(container_info["container_id"], "container-id-123")
        self.assertTrue(container_info["container_name"].startswith("sniper-worker-"))

    @patch("subprocess.run")
    def test_remove_worker(self, mock_run):
        """Test removing a Docker container worker."""
        # Setup mock container
        worker_id = "worker-test-1"
        container_id = "container-id-123"
        container_name = "sniper-worker-test-1"
        self.config["containers"] = {
            worker_id: {"container_id": container_id, "container_name": container_name}
        }

        # Remove worker
        result = self.provider.remove_worker(worker_id)

        # Verify result and Docker commands
        self.assertTrue(result)
        self.assertEqual(mock_run.call_count, 2)  # stop and rm commands

        # First call should be 'docker stop'
        args1, _ = mock_run.call_args_list[0]
        cmd1 = args1[0]
        self.assertEqual(cmd1[0], "docker")
        self.assertEqual(cmd1[1], "stop")
        self.assertEqual(cmd1[2], container_id)

        # Second call should be 'docker rm'
        args2, _ = mock_run.call_args_list[1]
        cmd2 = args2[0]
        self.assertEqual(cmd2[0], "docker")
        self.assertEqual(cmd2[1], "rm")
        self.assertEqual(cmd2[2], container_id)

        # Verify worker was removed from config
        self.assertNotIn(worker_id, self.config["containers"])


if __name__ == "__main__":
    unittest.main()
