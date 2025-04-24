"""
Work Distribution Algorithms for Distributed Scanning

This module implements various algorithms for distributing scanning tasks across worker
nodes in an efficient manner, taking into account factors such as worker capabilities,
load, and task dependencies.
"""

import abc
import heapq
import logging
import math
import random
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from src.distributed.base import (
    DistributedTask,
    NodeInfo,
    NodeRole,
    NodeStatus,
    TaskPriority,
    TaskStatus,
)
from src.distributed.worker_metrics import WorkerMetrics, WorkerMetricsManager
from src.utils.exceptions import DistributionError

# Create module logger
logger = logging.getLogger(__name__)


class DistributionStrategy(Enum):
    """Enumeration of task distribution strategies."""

    ROUND_ROBIN = "round_robin"
    PRIORITY_BASED = "priority_based"
    CAPABILITY_BASED = "capability_based"
    WEIGHTED = "weighted"
    LOAD_BALANCED = "load_balanced"
    SMART = "smart"


@dataclass
class WorkerMetrics:
    """Metrics for a worker node to use in distribution decisions."""

    node_id: str
    capabilities: List[str]
    current_load: float = 0.0  # Between 0.0 and 1.0
    task_count: int = 0
    success_rate: float = 1.0  # Between 0.0 and 1.0
    response_time: float = 0.0  # Average response time in seconds
    last_heartbeat: float = 0.0  # Timestamp of last heartbeat
    penalty_score: float = 0.0  # Penalty score for unreliable workers

    @property
    def is_available(self) -> bool:
        """Check if the worker is available for tasks."""
        return (
            self.current_load < 0.9
            and self.task_count < 10
            and time.time() - self.last_heartbeat < 60
        )


class DistributionAlgorithm(abc.ABC):
    """Base class for task distribution algorithms."""

    @abc.abstractmethod
    def distribute(
        self,
        tasks: List[DistributedTask],
        workers: Dict[str, NodeInfo],
        worker_metrics: Dict[str, WorkerMetrics],
    ) -> Dict[str, List[str]]:
        """
        Distribute tasks to worker nodes.

        Args:
            tasks: List of tasks to distribute
            workers: Dictionary of worker information keyed by worker ID
            worker_metrics: Dictionary of worker metrics keyed by worker ID

        Returns:
            Dictionary mapping worker IDs to lists of task IDs
        """
        pass

    def filter_capable_workers(
        self,
        task: DistributedTask,
        workers: Dict[str, NodeInfo],
        worker_metrics: Dict[str, WorkerMetrics],
    ) -> List[str]:
        """
        Filter workers that are capable of executing a task.

        Args:
            task: Task to execute
            workers: Dictionary of worker information keyed by worker ID
            worker_metrics: Dictionary of worker metrics keyed by worker ID

        Returns:
            List of worker IDs that can execute the task
        """
        capable_workers = []

        print(f"DEBUG: Filtering workers for task type: {task.task_type}")

        for worker_id, worker_info in workers.items():
            print(
                f"DEBUG: Worker {worker_id} status: {worker_info.status}, capabilities: {worker_info.capabilities}"
            )

            # Check if worker is active
            if (
                worker_info.status != NodeStatus.ACTIVE
                and worker_info.status != NodeStatus.IDLE
            ):
                print(
                    f"DEBUG: Worker {worker_id} skipped due to status: {worker_info.status}"
                )
                continue

            # Check if worker has required capabilities
            if task.task_type not in worker_info.capabilities:
                print(
                    f"DEBUG: Worker {worker_id} skipped due to missing capability: {task.task_type}"
                )
                continue

            # Check if worker is available according to metrics
            metrics = worker_metrics.get(worker_id)
            if metrics is None:
                print(f"DEBUG: Worker {worker_id} skipped due to missing metrics")
                continue

            if not metrics.is_available:
                print(
                    f"DEBUG: Worker {worker_id} skipped due to availability: load={metrics.current_load}, tasks={metrics.task_count}, last_heartbeat={time.time() - metrics.last_heartbeat}s ago"
                )
                continue

            print(f"DEBUG: Worker {worker_id} is capable and available")
            capable_workers.append(worker_id)

        print(f"DEBUG: Found {len(capable_workers)} capable workers: {capable_workers}")
        return capable_workers


class RoundRobinDistribution(DistributionAlgorithm):
    """Simple round-robin distribution of tasks."""

    def __init__(self):
        """Initialize the algorithm."""
        self.last_worker_index = -1

    def distribute(
        self,
        tasks: List[DistributedTask],
        workers: Dict[str, NodeInfo],
        worker_metrics: Dict[str, WorkerMetrics],
    ) -> Dict[str, List[str]]:
        """Distribute tasks using round-robin."""
        distribution = {worker_id: [] for worker_id in workers.keys()}
        worker_ids = list(workers.keys())

        if not worker_ids:
            return distribution

        for task in tasks:
            capable_workers = self.filter_capable_workers(task, workers, worker_metrics)
            if not capable_workers:
                continue

            # Get the next worker in the round-robin sequence
            self.last_worker_index = (self.last_worker_index + 1) % len(capable_workers)
            worker_id = capable_workers[self.last_worker_index]

            distribution[worker_id].append(task.id)

        return distribution


class PriorityBasedDistribution(DistributionAlgorithm):
    """Distribute tasks based on priority and worker metrics."""

    def distribute(
        self,
        tasks: List[DistributedTask],
        workers: Dict[str, NodeInfo],
        worker_metrics: Dict[str, WorkerMetrics],
    ) -> Dict[str, List[str]]:
        """Distribute tasks by priority."""
        distribution = {worker_id: [] for worker_id in workers.keys()}

        # Sort tasks by priority (highest first)
        sorted_tasks = sorted(
            tasks,
            key=lambda t: (t.priority.value, t.created_at.timestamp()),
            reverse=True,
        )

        for task in sorted_tasks:
            capable_workers = self.filter_capable_workers(task, workers, worker_metrics)
            if not capable_workers:
                continue

            # Find the worker with the lowest current load
            best_worker = min(
                capable_workers,
                key=lambda w: (
                    worker_metrics[w].current_load if w in worker_metrics else 1.0
                ),
            )

            distribution[best_worker].append(task.id)

            # Update worker metrics to reflect new task assignment
            if best_worker in worker_metrics:
                worker_metrics[best_worker].current_load += 0.1
                worker_metrics[best_worker].task_count += 1

        return distribution


class CapabilityBasedDistribution(DistributionAlgorithm):
    """Distribute tasks based on worker capabilities and proficiency."""

    def distribute(
        self,
        tasks: List[DistributedTask],
        workers: Dict[str, NodeInfo],
        worker_metrics: Dict[str, WorkerMetrics],
    ) -> Dict[str, List[str]]:
        """Distribute tasks by worker capability."""
        distribution = {worker_id: [] for worker_id in workers.keys()}

        # Group tasks by type
        task_groups = {}
        for task in tasks:
            if task.task_type not in task_groups:
                task_groups[task.task_type] = []
            task_groups[task.task_type].append(task)

        # For each task type, find the best workers
        for task_type, type_tasks in task_groups.items():
            # Get workers that can handle this task type
            capable_workers = []
            for worker_id, info in workers.items():
                if (
                    task_type in info.capabilities
                    and info.status in [NodeStatus.ACTIVE, NodeStatus.IDLE]
                    and worker_id in worker_metrics
                    and worker_metrics[worker_id].is_available
                ):
                    capable_workers.append(worker_id)

            if not capable_workers:
                continue

            # Distribute tasks evenly among capable workers
            for i, task in enumerate(type_tasks):
                worker_id = capable_workers[i % len(capable_workers)]
                distribution[worker_id].append(task.id)

                # Update worker metrics
                if worker_id in worker_metrics:
                    worker_metrics[worker_id].current_load += 0.1
                    worker_metrics[worker_id].task_count += 1

        return distribution


class WeightedDistribution(DistributionAlgorithm):
    """
    Distribute tasks using a weighted algorithm that considers multiple factors:
    - Worker capabilities
    - Current load
    - Success rate
    - Response time
    """

    def __init__(
        self,
        capability_weight: float = 0.4,
        load_weight: float = 0.3,
        success_weight: float = 0.2,
        response_weight: float = 0.1,
    ):
        """
        Initialize the weighted distribution algorithm.

        Args:
            capability_weight: Weight for worker capabilities
            load_weight: Weight for worker load
            success_weight: Weight for worker success rate
            response_weight: Weight for worker response time
        """
        self.capability_weight = capability_weight
        self.load_weight = load_weight
        self.success_weight = success_weight
        self.response_weight = response_weight

    def distribute(
        self,
        tasks: List[DistributedTask],
        workers: Dict[str, NodeInfo],
        worker_metrics: Dict[str, WorkerMetrics],
    ) -> Dict[str, List[str]]:
        """Distribute tasks using a weighted algorithm."""
        distribution = {worker_id: [] for worker_id in workers.keys()}

        for task in tasks:
            capable_workers = self.filter_capable_workers(task, workers, worker_metrics)
            if not capable_workers:
                continue

            # Calculate scores for each capable worker
            worker_scores = {}
            for worker_id in capable_workers:
                if worker_id not in worker_metrics:
                    continue

                metrics = worker_metrics[worker_id]

                # Calculate capability score (higher is better)
                capability_score = (
                    1.0 if task.task_type in workers[worker_id].capabilities else 0.0
                )

                # Calculate load score (lower load is better)
                load_score = 1.0 - metrics.current_load

                # Success rate score (higher is better)
                success_score = metrics.success_rate

                # Response time score (lower is better)
                response_score = (
                    1.0 / (1.0 + metrics.response_time)
                    if metrics.response_time > 0
                    else 1.0
                )

                # Calculate weighted score
                score = (
                    self.capability_weight * capability_score
                    + self.load_weight * load_score
                    + self.success_weight * success_score
                    + self.response_weight * response_score
                )

                worker_scores[worker_id] = score

            if not worker_scores:
                continue

            # Select the worker with the highest score
            best_worker = max(worker_scores.items(), key=lambda x: x[1])[0]

            distribution[best_worker].append(task.id)

            # Update worker metrics
            if best_worker in worker_metrics:
                worker_metrics[best_worker].current_load += 0.1
                worker_metrics[best_worker].task_count += 1

        return distribution


class LoadBalancedDistribution(DistributionAlgorithm):
    """
    Distribute tasks to maintain balanced load across workers,
    taking into account worker capabilities and current load.
    """

    def distribute(
        self,
        tasks: List[DistributedTask],
        workers: Dict[str, NodeInfo],
        worker_metrics: Dict[str, WorkerMetrics],
    ) -> Dict[str, List[str]]:
        """Distribute tasks for balanced load."""
        distribution = {worker_id: [] for worker_id in workers.keys()}

        # Create a priority queue of workers based on load (lowest first)
        worker_queue = [
            (
                (
                    worker_metrics[worker_id].current_load
                    if worker_id in worker_metrics
                    else 0.0
                ),
                worker_id,
            )
            for worker_id in workers.keys()
        ]
        heapq.heapify(worker_queue)

        for task in tasks:
            capable_workers = self.filter_capable_workers(task, workers, worker_metrics)
            if not capable_workers:
                continue

            # Find the worker with the lowest load among capable workers
            found = False
            temp_queue = []

            while worker_queue and not found:
                load, worker_id = heapq.heappop(worker_queue)

                if worker_id in capable_workers:
                    distribution[worker_id].append(task.id)

                    # Update load for this worker
                    new_load = load + 0.1
                    heapq.heappush(worker_queue, (new_load, worker_id))

                    # Update worker metrics
                    if worker_id in worker_metrics:
                        worker_metrics[worker_id].current_load = new_load
                        worker_metrics[worker_id].task_count += 1

                    found = True
                else:
                    temp_queue.append((load, worker_id))

            # Put back any workers we removed from the queue
            for item in temp_queue:
                heapq.heappush(worker_queue, item)

            # If no capable worker was found, try again with the next task
            if not found:
                continue

        return distribution


class SmartDistribution(DistributionAlgorithm):
    """
    Advanced distribution algorithm that combines multiple strategies and uses
    machine learning techniques to optimize task assignment.

    Features:
    - Uses historical performance data to predict execution time
    - Considers worker specialization for specific task types
    - Accounts for network latency and resource usage
    - Adapts to changing conditions and worker performance
    - Implements dynamic penalty scores for unreliable workers
    """

    def __init__(self, use_ml: bool = True, alpha: float = 0.2):
        """
        Initialize the smart distribution algorithm.

        Args:
            use_ml: Whether to use machine learning for predictions
            alpha: Learning rate for performance history updates (0-1)
        """
        self.execution_history = {}  # {(task_type, worker_id): [execution_times]}
        self.worker_specialization = {}  # {worker_id: {task_type: score}}
        self.use_ml = use_ml
        self.alpha = alpha  # Learning rate for exponential moving average
        self.min_history_size = (
            5  # Minimum samples before using history-based decisions
        )

    def update_history(
        self,
        task_id: str,
        worker_id: str,
        task_type: str,
        execution_time: float,
        success: bool,
    ):
        """
        Update execution history with a new data point.

        Args:
            task_id: ID of the completed task
            worker_id: ID of the worker that executed the task
            task_type: Type of task
            execution_time: Time taken to execute the task in seconds
            success: Whether the task was completed successfully
        """
        key = (task_type, worker_id)

        # Initialize history if needed
        if key not in self.execution_history:
            self.execution_history[key] = []

        # Add execution time to history
        self.execution_history[key].append((execution_time, success, task_id))

        # Limit history size to avoid memory growth
        if len(self.execution_history[key]) > 100:
            self.execution_history[key] = self.execution_history[key][-100:]

        # Update worker specialization score
        if worker_id not in self.worker_specialization:
            self.worker_specialization[worker_id] = {}

        if task_type not in self.worker_specialization[worker_id]:
            self.worker_specialization[worker_id][task_type] = 1.0

        # Calculate new score based on performance
        current_score = self.worker_specialization[worker_id][task_type]
        performance_factor = 1.0

        if not success:
            # Penalize failures
            performance_factor = 0.8
        elif execution_time > 0:
            # Calculate average execution time for this task type across all workers
            all_times = []
            for (tt, _), history in self.execution_history.items():
                if tt == task_type:
                    successful_times = [t for t, s, _ in history if s]
                    if successful_times:
                        all_times.extend(successful_times)

            if all_times:
                avg_time = sum(all_times) / len(all_times)
                if avg_time > 0:
                    # If faster than average, increase score, otherwise decrease
                    performance_factor = avg_time / execution_time
                    # Clip to reasonable range
                    performance_factor = max(0.5, min(1.5, performance_factor))

        # Update score using exponential moving average
        new_score = (current_score * (1 - self.alpha)) + (
            performance_factor * self.alpha
        )
        self.worker_specialization[worker_id][task_type] = new_score

    def get_expected_execution_time(self, task_type: str, worker_id: str) -> float:
        """
        Predict expected execution time for a task on a specific worker.

        Args:
            task_type: Type of task
            worker_id: ID of the worker

        Returns:
            Predicted execution time in seconds
        """
        key = (task_type, worker_id)

        if key in self.execution_history:
            history = self.execution_history[key]
            successful_history = [
                (time, tid) for time, success, tid in history if success
            ]

            if len(successful_history) >= self.min_history_size:
                # Use weighted average with recent executions weighted more heavily
                times, _ = zip(*successful_history[-10:])
                weights = list(range(1, len(times) + 1))
                weighted_avg = sum(t * w for t, w in zip(times, weights)) / sum(weights)
                return weighted_avg

        # Fallback: return default time if no history
        return 60.0  # Default expected execution time in seconds

    def get_worker_score(
        self, worker_id: str, task_type: str, worker_metrics: Dict[str, WorkerMetrics]
    ) -> float:
        """
        Calculate a score for a worker for a specific task type.
        Higher score means better suitability.

        Args:
            worker_id: ID of the worker
            task_type: Type of task
            worker_metrics: Dictionary of worker metrics

        Returns:
            Worker score (higher is better)
        """
        metrics = worker_metrics.get(worker_id)
        if not metrics:
            return 0.0

        # Start with base score
        score = 1.0

        # Factor 1: Current load (higher load = lower score)
        load_factor = 1.0 - (
            metrics.current_load * 0.8
        )  # Allow for some tasks even at high load
        score *= load_factor

        # Factor 2: Specialization score for this task type
        specialization = 1.0
        if (
            worker_id in self.worker_specialization
            and task_type in self.worker_specialization[worker_id]
        ):
            specialization = self.worker_specialization[worker_id][task_type]
        score *= specialization

        # Factor 3: Success rate (penalize workers with failures)
        score *= metrics.success_rate

        # Factor 4: Response time (faster response = higher score)
        if metrics.response_time > 0:
            # Normalize response time with exponential decay
            response_factor = math.exp(
                -metrics.response_time / 60.0
            )  # 60 seconds base scale
            score *= response_factor

        # Factor 5: Penalty score (reduce score for problematic workers)
        if metrics.penalty_score > 0:
            penalty_factor = math.exp(-metrics.penalty_score / 10.0)
            score *= penalty_factor

        return score

    def distribute(
        self,
        tasks: List[DistributedTask],
        workers: Dict[str, NodeInfo],
        worker_metrics: Dict[str, WorkerMetrics],
    ) -> Dict[str, List[str]]:
        """
        Distribute tasks to workers using the smart distribution algorithm.

        Args:
            tasks: List of tasks to distribute
            workers: Dictionary of worker information
            worker_metrics: Dictionary of worker metrics

        Returns:
            Dictionary mapping worker IDs to lists of task IDs
        """
        distribution = {worker_id: [] for worker_id in workers}

        # Skip if no tasks or workers
        if not tasks or not workers:
            return distribution

        # Phase 1: Analyze tasks and workers
        task_priorities = {}
        task_types = {}

        for task in tasks:
            # Calculate task priority value (higher = more important)
            priority_value = task.priority.value

            # Adjust priority based on waiting time
            if task.created_at:
                # Ensure the created_at is timezone-aware
                if task.created_at.tzinfo is None:
                    # If naive datetime, assume it's UTC and make it timezone-aware
                    task_created_at = task.created_at.replace(tzinfo=timezone.utc)
                else:
                    task_created_at = task.created_at

                wait_time = (
                    datetime.now(timezone.utc) - task_created_at
                ).total_seconds()
                # Increase priority with waiting time (avoid starvation)
                priority_factor = min(
                    3.0, 1.0 + (wait_time / 3600.0)
                )  # Max 3x boost after 2 hours
                priority_value *= priority_factor

            task_priorities[task.id] = priority_value
            task_types[task.id] = task.task_type

        # Phase 2: Calculate scores for each worker-task combination
        scores = {}

        for task in tasks:
            for worker_id, worker_info in workers.items():
                # Skip workers that don't support this task type
                if task.task_type not in worker_info.capabilities:
                    continue

                # Skip workers that are not active
                if worker_info.status not in [NodeStatus.ACTIVE, NodeStatus.IDLE]:
                    continue

                # Calculate worker score for this task
                worker_score = self.get_worker_score(
                    worker_id, task.task_type, worker_metrics
                )

                # Combine with task priority
                final_score = worker_score * task_priorities.get(task.id, 1.0)

                scores[(task.id, worker_id)] = final_score

        # Phase 3: Assign tasks using a variant of the Hungarian algorithm
        # First, assign highest-scoring tasks to their best workers
        assigned_tasks = set()
        assigned_workers = Counter()

        # Sort task-worker pairs by score (highest first)
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        for (task_id, worker_id), score in sorted_scores:
            # Stop if all tasks are assigned
            if len(assigned_tasks) >= len(tasks):
                break

            # Skip already assigned tasks
            if task_id in assigned_tasks:
                continue

            # Check if worker has capacity
            worker_metrics_data = worker_metrics.get(worker_id)
            max_tasks = 5  # Default limit
            if worker_metrics_data:
                # Use worker's reported limit or default
                current_tasks = (
                    assigned_workers[worker_id] + worker_metrics_data.task_count
                )
                max_worker_tasks = getattr(
                    worker_metrics_data, "max_concurrent_tasks", max_tasks
                )

                if current_tasks >= max_worker_tasks:
                    continue
            else:
                # Skip workers without metrics data
                continue

            # Assign task to worker
            distribution[worker_id].append(task_id)
            assigned_tasks.add(task_id)
            assigned_workers[worker_id] += 1

        return distribution


# Factory function to create distribution algorithm
def create_distribution_algorithm(
    strategy: DistributionStrategy, **kwargs
) -> DistributionAlgorithm:
    """
    Create a distribution algorithm.

    Args:
        strategy: Distribution strategy to use
        **kwargs: Additional arguments for the algorithm

    Returns:
        Distribution algorithm implementation
    """
    if strategy == DistributionStrategy.ROUND_ROBIN:
        return RoundRobinDistribution()
    elif strategy == DistributionStrategy.PRIORITY_BASED:
        return PriorityBasedDistribution()
    elif strategy == DistributionStrategy.CAPABILITY_BASED:
        return CapabilityBasedDistribution()
    elif strategy == DistributionStrategy.WEIGHTED:
        return WeightedDistribution(
            capability_weight=kwargs.get("capability_weight", 0.4),
            load_weight=kwargs.get("load_weight", 0.3),
            success_weight=kwargs.get("success_weight", 0.2),
            response_weight=kwargs.get("response_weight", 0.1),
        )
    elif strategy == DistributionStrategy.LOAD_BALANCED:
        return LoadBalancedDistribution()
    elif strategy == DistributionStrategy.SMART:
        return SmartDistribution(use_ml=kwargs.get("use_ml", True))
    else:
        raise ValueError(f"Unsupported distribution strategy: {strategy}")
