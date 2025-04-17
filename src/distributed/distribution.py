"""
Work Distribution Algorithms for Distributed Scanning

This module implements various algorithms for distributing scanning tasks across worker
nodes in an efficient manner, taking into account factors such as worker capabilities,
load, and task dependencies.
"""

import abc
import heapq
import logging
import random
import time
from dataclasses import dataclass
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
    Smart distribution algorithm that uses machine learning to optimize
    task distribution based on historical performance and task characteristics.
    """

    def __init__(self, use_ml: bool = True):
        """
        Initialize the smart distribution algorithm.

        Args:
            use_ml: Whether to use ML model for distribution
        """
        self.use_ml = use_ml
        self.task_history = {}  # Maps task types to past execution times by worker
        self.fallback = WeightedDistribution()

    def update_history(self, task_id: str, worker_id: str, execution_time: float):
        """
        Update task execution history.

        Args:
            task_id: ID of the completed task
            worker_id: ID of the worker that executed the task
            execution_time: Time taken to execute the task (seconds)
        """
        task_type = self.task_history.get(task_id, {}).get("task_type")
        if not task_type:
            return

        if task_type not in self.task_history:
            self.task_history[task_type] = {}

        if worker_id not in self.task_history[task_type]:
            self.task_history[task_type][worker_id] = []

        self.task_history[task_type][worker_id].append(execution_time)

        # Keep only the last 20 executions
        if len(self.task_history[task_type][worker_id]) > 20:
            self.task_history[task_type][worker_id] = self.task_history[task_type][
                worker_id
            ][-20:]

    def get_expected_execution_time(self, task_type: str, worker_id: str) -> float:
        """
        Get the expected execution time for a task type on a worker.

        Args:
            task_type: Type of task
            worker_id: ID of the worker

        Returns:
            Expected execution time in seconds
        """
        if (
            task_type not in self.task_history
            or worker_id not in self.task_history[task_type]
        ):
            return 60.0  # Default to 1 minute if no history

        history = self.task_history[task_type][worker_id]
        if not history:
            return 60.0

        # Use a weighted average with more recent executions having higher weight
        weights = [
            i / sum(range(1, len(history) + 1)) for i in range(1, len(history) + 1)
        ]
        return sum(t * w for t, w in zip(history, weights))

    def distribute(
        self,
        tasks: List[DistributedTask],
        workers: Dict[str, NodeInfo],
        worker_metrics: Dict[str, WorkerMetrics],
    ) -> Dict[str, List[str]]:
        """Distribute tasks using smart algorithm."""
        if not self.use_ml or not tasks or not workers:
            # Fall back to weighted distribution if ML is disabled or no tasks/workers
            return self.fallback.distribute(tasks, workers, worker_metrics)

        distribution = {worker_id: [] for worker_id in workers.keys()}

        # Sort tasks by priority and creation time
        sorted_tasks = sorted(
            tasks,
            key=lambda t: (t.priority.value, -t.created_at.timestamp()),
            reverse=True,
        )

        # Track estimated completion time for each worker
        worker_completion_times = {worker_id: 0.0 for worker_id in workers.keys()}

        for task in sorted_tasks:
            capable_workers = self.filter_capable_workers(task, workers, worker_metrics)
            if not capable_workers:
                continue

            # Find the worker that can complete this task the earliest
            best_worker = None
            earliest_completion = float("inf")

            for worker_id in capable_workers:
                # Get expected execution time for this task type on this worker
                expected_time = self.get_expected_execution_time(
                    task.task_type, worker_id
                )

                # Calculate when this worker would complete the task
                completion_time = worker_completion_times[worker_id] + expected_time

                if completion_time < earliest_completion:
                    earliest_completion = completion_time
                    best_worker = worker_id

            if best_worker:
                distribution[best_worker].append(task.id)

                # Update worker metrics
                if best_worker in worker_metrics:
                    worker_metrics[best_worker].current_load += 0.1
                    worker_metrics[best_worker].task_count += 1

                # Update estimated completion time
                worker_completion_times[best_worker] = earliest_completion

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
