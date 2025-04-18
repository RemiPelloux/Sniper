"""
Auto-Scaling Module for Sniper Distributed Architecture

This module implements auto-scaling capabilities for the Sniper Security Tool
distributed scanning architecture. It automatically adjusts the number of worker
nodes based on current workload, queue depth, and resource utilization.

The module supports:
1. Horizontal scaling of worker nodes
2. Smart scaling decisions based on task types and worker capabilities
3. Configurable scaling policies and thresholds
4. Platform-specific provisioning (local, Docker, Kubernetes, cloud)
"""

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from src.distributed.base import NodeInfo, NodeStatus, TaskStatus
from src.distributed.master import SniperMasterNode

logger = logging.getLogger("sniper.distributed.auto_scaling")


class ScalingPolicy(str, Enum):
    """Defines the auto-scaling policy to apply."""
    
    QUEUE_DEPTH = "queue_depth"        # Scale based on task queue depth
    CPU_UTILIZATION = "cpu_utilization"  # Scale based on CPU utilization
    TASK_TYPE = "task_type"            # Scale based on task type requirements
    HYBRID = "hybrid"                 # Combine multiple metrics


class ScalingMode(str, Enum):
    """Defines whether scaling adjusts in one or both directions."""
    
    UP_ONLY = "up_only"               # Only scale up, manual scale down
    DOWN_ONLY = "down_only"           # Only scale down, manual scale up
    BIDIRECTIONAL = "bidirectional"   # Scale both up and down


class WorkerProvider(str, Enum):
    """Defines the platform where worker nodes run."""
    
    LOCAL = "local"                   # Local process workers
    DOCKER = "docker"                 # Docker container workers
    KUBERNETES = "kubernetes"         # Kubernetes pod workers
    AWS = "aws"                       # AWS EC2 instances
    AZURE = "azure"                   # Azure VMs
    GCP = "gcp"                       # Google Cloud VMs


@dataclass
class ScalingRule:
    """Defines a rule for when to trigger scaling."""
    
    metric: str                      # Metric to monitor
    threshold: float                 # Threshold to trigger scaling
    operation: str                   # Operation to apply (> or <)
    action: str                      # Action to take (add or remove)
    cooldown: int = 300              # Cooldown period in seconds
    adjustment: int = 1              # Number of nodes to add/remove


@dataclass
class ScalingConfig:
    """Configuration for the auto-scaler."""
    
    min_nodes: int = 1               # Minimum number of worker nodes
    max_nodes: int = 10              # Maximum number of worker nodes
    scaling_policy: ScalingPolicy = ScalingPolicy.QUEUE_DEPTH
    scaling_mode: ScalingMode = ScalingMode.BIDIRECTIONAL
    provider: WorkerProvider = WorkerProvider.DOCKER
    check_interval: int = 60         # Seconds between scaling checks
    rules: List[ScalingRule] = None  # Scaling rules
    node_startup_timeout: int = 300  # Max seconds to wait for new node to start
    node_ready_timeout: int = 60     # Max seconds to wait for node to become ready


class AutoScaler:
    """
    Manages automatic scaling of worker nodes based on workload demands.
    
    The AutoScaler monitors task queue depths, worker utilization, and other metrics
    to determine when to scale the worker pool up or down. It uses a provider
    implementation to create and destroy worker nodes on the appropriate platform.
    """
    
    def __init__(
        self,
        master_node: SniperMasterNode,
        config: Optional[ScalingConfig] = None,
        provider_config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the auto-scaler.
        
        Args:
            master_node: The master node to monitor and control scaling for
            config: Scaling configuration parameters
            provider_config: Provider-specific configuration
        """
        self.master_node = master_node
        self.config = config or ScalingConfig()
        self.provider_config = provider_config or {}
        
        self.provider = self._create_provider(self.config.provider)
        self.running = False
        self.scaling_thread = None
        self.last_scale_up = datetime.now()
        self.last_scale_down = datetime.now()
        self.lock = threading.RLock()
        self.node_history = {}  # Tracks created/removed nodes
        
        # Ensure config.rules exists
        if self.config.rules is None:
            self.config.rules = self._create_default_rules()
    
    def _create_provider(self, provider_type: WorkerProvider):
        """Create the appropriate provider implementation."""
        if provider_type == WorkerProvider.LOCAL:
            return LocalWorkerProvider(self.provider_config)
        elif provider_type == WorkerProvider.DOCKER:
            return DockerWorkerProvider(self.provider_config)
        elif provider_type == WorkerProvider.KUBERNETES:
            return KubernetesWorkerProvider(self.provider_config)
        elif provider_type == WorkerProvider.AWS:
            return AwsWorkerProvider(self.provider_config)
        elif provider_type == WorkerProvider.AZURE:
            return AzureWorkerProvider(self.provider_config)
        elif provider_type == WorkerProvider.GCP:
            return GcpWorkerProvider(self.provider_config)
        else:
            logger.warning(f"Unknown provider type: {provider_type}, using Docker")
            return DockerWorkerProvider(self.provider_config)
    
    def _create_default_rules(self) -> List[ScalingRule]:
        """Create default scaling rules if none are provided."""
        return [
            # Scale up when queue depth exceeds 5 tasks per worker
            ScalingRule(
                metric="queue_depth_per_worker",
                threshold=5.0,
                operation=">",
                action="add",
                cooldown=300,
                adjustment=1
            ),
            # Scale down when queue depth is less than 1 task per worker
            ScalingRule(
                metric="queue_depth_per_worker",
                threshold=1.0,
                operation="<",
                action="remove",
                cooldown=600,
                adjustment=1
            ),
            # Scale up when worker utilization exceeds 80%
            ScalingRule(
                metric="worker_utilization",
                threshold=0.8,
                operation=">",
                action="add",
                cooldown=300,
                adjustment=1
            ),
            # Scale down when worker utilization is below 20%
            ScalingRule(
                metric="worker_utilization",
                threshold=0.2,
                operation="<",
                action="remove",
                cooldown=600,
                adjustment=1
            )
        ]
    
    def start(self):
        """Start the auto-scaler."""
        if self.running:
            logger.warning("Auto-scaler is already running")
            return False
        
        logger.info(f"Starting auto-scaler with {self.config.provider} provider")
        self.running = True
        self.scaling_thread = threading.Thread(target=self._scaling_loop, daemon=True)
        self.scaling_thread.start()
        return True
    
    def stop(self):
        """Stop the auto-scaler."""
        if not self.running:
            logger.warning("Auto-scaler is not running")
            return False
        
        logger.info("Stopping auto-scaler")
        self.running = False
        if self.scaling_thread and self.scaling_thread.is_alive():
            self.scaling_thread.join(timeout=10)
        return True
    
    def _scaling_loop(self):
        """Main scaling loop that periodically checks metrics and applies rules."""
        logger.info("Auto-scaling monitoring loop started")
        while self.running:
            try:
                self._check_and_apply_scaling()
            except Exception as e:
                logger.error(f"Error in auto-scaling loop: {e}", exc_info=True)
            
            time.sleep(self.config.check_interval)
    
    def _check_and_apply_scaling(self):
        """Check metrics and apply scaling rules if thresholds are met."""
        with self.lock:
            # Get current metrics
            metrics = self._collect_metrics()
            
            # Check if we need to scale based on our rules
            for rule in self.config.rules:
                if self._should_apply_rule(rule, metrics):
                    self._apply_scaling_action(rule, metrics)
    
    def _collect_metrics(self) -> Dict[str, float]:
        """Collect all metrics needed for scaling decisions."""
        # Count active workers
        active_workers = len([w for w in self.master_node.workers.values() 
                             if w.status in [NodeStatus.ACTIVE, NodeStatus.IDLE]])
        
        # Adjust if zero to avoid division by zero
        if active_workers == 0:
            active_workers = 1
        
        # Get queue depth
        queue_depth = len(self.master_node.pending_tasks)
        
        # Calculate metrics
        queue_depth_per_worker = queue_depth / active_workers
        
        # Calculate worker utilization
        total_utilization = 0.0
        for metrics in self.master_node.worker_metrics.values():
            total_utilization += metrics.current_load
        
        avg_worker_utilization = total_utilization / active_workers
        
        # Get active/processing task counts
        active_tasks = len(self.master_node.tasks)
        
        return {
            "active_workers": active_workers,
            "queue_depth": queue_depth,
            "queue_depth_per_worker": queue_depth_per_worker,
            "worker_utilization": avg_worker_utilization,
            "active_tasks": active_tasks,
        }
    
    def _should_apply_rule(self, rule: ScalingRule, metrics: Dict[str, float]) -> bool:
        """Determine if a rule should be applied based on metrics and cooldown."""
        # Skip if metric isn't in our collected metrics
        if rule.metric not in metrics:
            return False
        
        current_value = metrics[rule.metric]
        
        # Check if threshold is exceeded based on the operation
        threshold_exceeded = False
        if rule.operation == ">" and current_value > rule.threshold:
            threshold_exceeded = True
        elif rule.operation == "<" and current_value < rule.threshold:
            threshold_exceeded = True
        elif rule.operation == ">=" and current_value >= rule.threshold:
            threshold_exceeded = True
        elif rule.operation == "<=" and current_value <= rule.threshold:
            threshold_exceeded = True
        
        if not threshold_exceeded:
            return False
        
        # Check cooldown period
        now = datetime.now()
        if rule.action == "add":
            if (now - self.last_scale_up).total_seconds() < rule.cooldown:
                return False
        elif rule.action == "remove":
            if (now - self.last_scale_down).total_seconds() < rule.cooldown:
                return False
        
        # Check scaling mode
        if self.config.scaling_mode == ScalingMode.UP_ONLY and rule.action == "remove":
            return False
        elif self.config.scaling_mode == ScalingMode.DOWN_ONLY and rule.action == "add":
            return False
        
        # Check min/max node constraints
        active_workers = metrics["active_workers"]
        if rule.action == "add" and active_workers >= self.config.max_nodes:
            return False
        elif rule.action == "remove" and active_workers <= self.config.min_nodes:
            return False
        
        return True
    
    def _apply_scaling_action(self, rule: ScalingRule, metrics: Dict[str, float]):
        """Apply the scaling action specified by the rule."""
        count = rule.adjustment
        
        if rule.action == "add":
            logger.info(f"Auto-scaling: Adding {count} worker nodes")
            for _ in range(count):
                self._scale_up()
            self.last_scale_up = datetime.now()
        
        elif rule.action == "remove":
            logger.info(f"Auto-scaling: Removing {count} worker nodes")
            self._scale_down(count)
            self.last_scale_down = datetime.now()
    
    def _scale_up(self):
        """Add a new worker node."""
        try:
            # Create a new worker through the provider
            worker_id = self.provider.create_worker(
                master_host=self.master_node.host,
                master_port=self.master_node.port
            )
            
            if not worker_id:
                logger.error("Failed to create new worker node")
                return
            
            # Record in history
            self.node_history[worker_id] = {
                "created_at": datetime.now(),
                "status": "creating",
                "provider": self.config.provider
            }
            
            # Wait for node to register with master (on a separate thread)
            threading.Thread(
                target=self._wait_for_node_registration,
                args=(worker_id,),
                daemon=True
            ).start()
            
            logger.info(f"Initiated scaling up with new worker node {worker_id}")
            
        except Exception as e:
            logger.error(f"Error scaling up: {e}", exc_info=True)
    
    def _wait_for_node_registration(self, worker_id: str):
        """Wait for a node to register with the master node."""
        start_time = datetime.now()
        timeout = timedelta(seconds=self.config.node_startup_timeout)
        
        while datetime.now() - start_time < timeout:
            # Check if worker has registered
            with self.master_node.worker_lock:
                for node_id, node_info in self.master_node.workers.items():
                    if node_id == worker_id or (
                        hasattr(node_info, 'worker_id') and node_info.worker_id == worker_id
                    ):
                        logger.info(f"Worker {worker_id} successfully registered")
                        if worker_id in self.node_history:
                            self.node_history[worker_id]["status"] = "active"
                        return True
            
            # Sleep and try again
            time.sleep(5)
        
        # Timeout occurred
        logger.warning(f"Worker {worker_id} did not register within timeout")
        if worker_id in self.node_history:
            self.node_history[worker_id]["status"] = "failed"
        
        # Try to clean up the failed node
        try:
            self.provider.remove_worker(worker_id)
        except Exception as e:
            logger.error(f"Error cleaning up failed worker {worker_id}: {e}")
        
        return False
    
    def _scale_down(self, count: int = 1):
        """Remove worker nodes."""
        with self.master_node.worker_lock:
            # Find candidates for removal
            candidates = []
            for worker_id, metrics in self.master_node.worker_metrics.items():
                # Skip if not found in workers
                if worker_id not in self.master_node.workers:
                    continue
                
                # Prioritize workers with low utilization
                candidates.append((worker_id, metrics.current_load))
            
            # Sort by utilization (lowest first)
            candidates.sort(key=lambda x: x[1])
            
            # Limit to requested count
            to_remove = candidates[:count]
            
            # Remove each selected worker
            for worker_id, _ in to_remove:
                self._remove_worker(worker_id)
    
    def _remove_worker(self, worker_id: str):
        """Remove a specific worker node."""
        logger.info(f"Auto-scaling: Removing worker {worker_id}")
        
        try:
            # Tell the master to unregister this worker
            if self.master_node.unregister_worker(worker_id):
                # Record in history
                if worker_id in self.node_history:
                    self.node_history[worker_id]["status"] = "removed"
                    self.node_history[worker_id]["removed_at"] = datetime.now()
                
                # Remove through provider
                self.provider.remove_worker(worker_id)
                logger.info(f"Successfully removed worker {worker_id}")
            else:
                logger.warning(f"Failed to unregister worker {worker_id} from master")
        except Exception as e:
            logger.error(f"Error removing worker {worker_id}: {e}", exc_info=True)


class WorkerProviderBase:
    """Base class for worker node providers."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize with provider-specific configuration."""
        self.config = config
    
    def create_worker(self, master_host: str, master_port: int) -> Optional[str]:
        """
        Create a new worker node.
        
        Args:
            master_host: Host address of the master node
            master_port: Port of the master node
            
        Returns:
            Worker ID if created successfully, None otherwise
        """
        raise NotImplementedError("Subclasses must implement create_worker")
    
    def remove_worker(self, worker_id: str) -> bool:
        """
        Remove a worker node.
        
        Args:
            worker_id: ID of the worker to remove
            
        Returns:
            True if removed successfully, False otherwise
        """
        raise NotImplementedError("Subclasses must implement remove_worker")


class LocalWorkerProvider(WorkerProviderBase):
    """Provider that launches worker nodes as local processes."""
    
    def create_worker(self, master_host: str, master_port: int) -> Optional[str]:
        """Launch a worker as a local process."""
        import subprocess
        import uuid
        
        worker_id = f"worker-{uuid.uuid4()}"
        
        try:
            # Build command
            cmd = [
                "python", "-m", "src.distributed.worker",
                "--worker-id", worker_id,
                "--master-host", master_host,
                "--master-port", str(master_port)
            ]
            
            # Add optional arguments from config
            if "log_level" in self.config:
                cmd.extend(["--log-level", self.config["log_level"]])
            
            # Launch process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Store process information
            self.config.setdefault("processes", {})
            self.config["processes"][worker_id] = process
            
            logger.info(f"Started local worker process {worker_id}")
            return worker_id
        
        except Exception as e:
            logger.error(f"Failed to start local worker process: {e}", exc_info=True)
            return None
    
    def remove_worker(self, worker_id: str) -> bool:
        """Terminate a local worker process."""
        processes = self.config.get("processes", {})
        
        if worker_id not in processes:
            logger.warning(f"Worker {worker_id} not found in local processes")
            return False
        
        try:
            # Get process
            process = processes[worker_id]
            
            # Terminate
            process.terminate()
            
            # Wait for exit
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Force kill if needed
                process.kill()
            
            # Remove from processes
            del processes[worker_id]
            
            logger.info(f"Terminated local worker process {worker_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error terminating worker {worker_id}: {e}", exc_info=True)
            return False


class DockerWorkerProvider(WorkerProviderBase):
    """Provider that launches worker nodes as Docker containers."""
    
    def create_worker(self, master_host: str, master_port: int) -> Optional[str]:
        """Launch a worker as a Docker container."""
        import subprocess
        import uuid
        
        worker_id = f"worker-{uuid.uuid4()}"
        container_name = f"sniper-worker-{worker_id}"
        
        try:
            # Get container image from config
            image = self.config.get("image", "sniper-worker:latest")
            
            # Build command
            cmd = [
                "docker", "run", "-d",
                "--name", container_name,
                "--network", self.config.get("network", "host"),
                "-e", f"WORKER_ID={worker_id}",
                "-e", f"MASTER_HOST={master_host}",
                "-e", f"MASTER_PORT={master_port}"
            ]
            
            # Add optional environment variables
            for key, value in self.config.get("env_vars", {}).items():
                cmd.extend(["-e", f"{key}={value}"])
            
            # Add volumes
            for volume in self.config.get("volumes", []):
                cmd.extend(["-v", volume])
            
            # Add image name
            cmd.append(image)
            
            # Launch container
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            
            container_id = result.stdout.strip()
            
            # Store container information
            self.config.setdefault("containers", {})
            self.config["containers"][worker_id] = {
                "container_id": container_id,
                "container_name": container_name
            }
            
            logger.info(f"Started Docker worker container {worker_id} ({container_id})")
            return worker_id
        
        except Exception as e:
            logger.error(f"Failed to start Docker worker container: {e}", exc_info=True)
            return None
    
    def remove_worker(self, worker_id: str) -> bool:
        """Stop and remove a Docker container."""
        import subprocess
        
        containers = self.config.get("containers", {})
        
        if worker_id not in containers:
            logger.warning(f"Worker {worker_id} not found in Docker containers")
            return False
        
        try:
            # Get container info
            container_info = containers[worker_id]
            container_id = container_info.get("container_id")
            container_name = container_info.get("container_name")
            
            if not container_id and not container_name:
                logger.error(f"No container ID or name for worker {worker_id}")
                return False
            
            # Build command to stop container
            container_ref = container_id if container_id else container_name
            cmd = ["docker", "stop", container_ref]
            
            # Stop container
            subprocess.run(cmd, check=True)
            
            # Remove container
            cmd = ["docker", "rm", container_ref]
            subprocess.run(cmd, check=True)
            
            # Remove from containers
            del containers[worker_id]
            
            logger.info(f"Stopped and removed Docker container for worker {worker_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error removing Docker container for worker {worker_id}: {e}", exc_info=True)
            return False


class KubernetesWorkerProvider(WorkerProviderBase):
    """Provider that launches worker nodes as Kubernetes pods."""
    
    def create_worker(self, master_host: str, master_port: int) -> Optional[str]:
        """Launch a worker as a Kubernetes pod."""
        import subprocess
        import uuid
        import yaml
        from tempfile import NamedTemporaryFile
        
        worker_id = f"worker-{uuid.uuid4()}"
        pod_name = f"sniper-worker-{worker_id.split('-')[1][:8]}"
        
        try:
            # Create pod manifest
            pod_manifest = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": pod_name,
                    "labels": {
                        "app": "sniper-worker",
                        "worker-id": worker_id
                    }
                },
                "spec": {
                    "containers": [{
                        "name": "worker",
                        "image": self.config.get("image", "sniper-worker:latest"),
                        "env": [
                            {"name": "WORKER_ID", "value": worker_id},
                            {"name": "MASTER_HOST", "value": master_host},
                            {"name": "MASTER_PORT", "value": str(master_port)}
                        ]
                    }]
                }
            }
            
            # Add namespace if specified
            if "namespace" in self.config:
                pod_manifest["metadata"]["namespace"] = self.config["namespace"]
            
            # Add resource limits if specified
            if "resources" in self.config:
                pod_manifest["spec"]["containers"][0]["resources"] = self.config["resources"]
            
            # Write manifest to temporary file
            with NamedTemporaryFile("w", suffix=".yaml") as f:
                yaml.dump(pod_manifest, f)
                f.flush()
                
                # Create pod
                cmd = ["kubectl", "apply", "-f", f.name]
                subprocess.run(cmd, check=True)
            
            # Store pod information
            self.config.setdefault("pods", {})
            self.config["pods"][worker_id] = {
                "pod_name": pod_name,
                "namespace": self.config.get("namespace", "default")
            }
            
            logger.info(f"Created Kubernetes pod {pod_name} for worker {worker_id}")
            return worker_id
        
        except Exception as e:
            logger.error(f"Failed to create Kubernetes pod: {e}", exc_info=True)
            return None
    
    def remove_worker(self, worker_id: str) -> bool:
        """Delete a Kubernetes pod."""
        pods = self.config.get("pods", {})
        
        if worker_id not in pods:
            logger.warning(f"Worker {worker_id} not found in Kubernetes pods")
            return False
        
        try:
            # Get pod info
            pod_info = pods[worker_id]
            pod_name = pod_info.get("pod_name")
            namespace = pod_info.get("namespace", "default")
            
            if not pod_name:
                logger.error(f"No pod name for worker {worker_id}")
                return False
            
            # Build command to delete pod
            cmd = ["kubectl", "delete", "pod", pod_name]
            if namespace:
                cmd.extend(["-n", namespace])
            
            # Delete pod
            subprocess.run(cmd, check=True)
            
            # Remove from pods
            del pods[worker_id]
            
            logger.info(f"Deleted Kubernetes pod {pod_name} for worker {worker_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error deleting Kubernetes pod for worker {worker_id}: {e}", exc_info=True)
            return False


# Placeholder classes for cloud providers

class AwsWorkerProvider(WorkerProviderBase):
    """Provider that launches worker nodes as AWS EC2 instances."""
    
    def create_worker(self, master_host: str, master_port: int) -> Optional[str]:
        """Launch a worker as an AWS EC2 instance."""
        # Implementation would use boto3 to create EC2 instances
        logger.warning("AWS worker provider is not fully implemented")
        return None
    
    def remove_worker(self, worker_id: str) -> bool:
        """Terminate an AWS EC2 instance."""
        logger.warning("AWS worker provider is not fully implemented")
        return False


class AzureWorkerProvider(WorkerProviderBase):
    """Provider that launches worker nodes as Azure VMs."""
    
    def create_worker(self, master_host: str, master_port: int) -> Optional[str]:
        """Launch a worker as an Azure VM."""
        # Implementation would use Azure SDK to create VMs
        logger.warning("Azure worker provider is not fully implemented")
        return None
    
    def remove_worker(self, worker_id: str) -> bool:
        """Delete an Azure VM."""
        logger.warning("Azure worker provider is not fully implemented")
        return False


class GcpWorkerProvider(WorkerProviderBase):
    """Provider that launches worker nodes as Google Cloud VMs."""
    
    def create_worker(self, master_host: str, master_port: int) -> Optional[str]:
        """Launch a worker as a Google Cloud VM."""
        # Implementation would use Google Cloud SDK to create VMs
        logger.warning("GCP worker provider is not fully implemented")
        return None
    
    def remove_worker(self, worker_id: str) -> bool:
        """Delete a Google Cloud VM."""
        logger.warning("GCP worker provider is not fully implemented")
        return False 