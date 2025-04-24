import logging
import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class WorkerMetrics:
    """
    Comprehensive metrics for a worker node to inform distribution decisions.

    Attributes:
        worker_id: Unique identifier of the worker
        task_count: Current number of tasks being processed
        max_concurrent_tasks: Maximum number of concurrent tasks this worker can handle
        success_rate: Ratio of successfully completed tasks (0.0-1.0)
        current_load: Current resource utilization (0.0-1.0)
        response_time: Average time in seconds to acknowledge tasks
        throughput: Tasks completed per minute
        penalty_score: Accumulated penalty score for unreliable behavior
        last_heartbeat: Time of last heartbeat
        capabilities: Set of task types this worker can handle
        hardware_metrics: Optional hardware performance metrics
    """

    worker_id: str
    task_count: int = 0
    max_concurrent_tasks: int = 5
    success_rate: float = 1.0
    current_load: float = 0.0
    response_time: float = 0.0
    throughput: float = 0.0
    penalty_score: float = 0.0
    last_heartbeat: Optional[datetime] = None
    capabilities: Set[str] = field(default_factory=set)
    hardware_metrics: Dict[str, float] = field(default_factory=dict)

    # Performance history
    completed_tasks: int = 0
    failed_tasks: int = 0
    task_execution_times: Dict[str, List[float]] = field(default_factory=dict)

    # Recent history window (for adaptive metrics)
    recent_task_results: List[Tuple[str, bool, float]] = field(default_factory=list)

    def update_task_result(self, task_type: str, success: bool, execution_time: float):
        """Update metrics with a new task result"""

        # Update historical performance
        if task_type not in self.task_execution_times:
            self.task_execution_times[task_type] = []

        self.task_execution_times[task_type].append(execution_time)

        # Limit history size to avoid memory issues
        if len(self.task_execution_times[task_type]) > 100:
            self.task_execution_times[task_type] = self.task_execution_times[task_type][
                -100:
            ]

        # Update completion counters
        if success:
            self.completed_tasks += 1
        else:
            self.failed_tasks += 1

        # Update recent history (limit to last 20 tasks)
        self.recent_task_results.append((task_type, success, execution_time))
        if len(self.recent_task_results) > 20:
            self.recent_task_results = self.recent_task_results[-20:]

        # Update success rate
        total_tasks = self.completed_tasks + self.failed_tasks
        if total_tasks > 0:
            self.success_rate = self.completed_tasks / total_tasks

        # Apply penalty for failures
        if not success:
            self.penalty_score += 1.0
        else:
            # Gradually reduce penalty score over time
            self.penalty_score = max(0, self.penalty_score - 0.1)

        # Calculate throughput (tasks per minute)
        if execution_time > 0:
            # This is an instantaneous measurement, need to average over time
            task_per_sec = 1.0 / execution_time
            task_per_min = task_per_sec * 60

            # Use exponential moving average for throughput
            alpha = 0.2  # Learning rate
            self.throughput = (self.throughput * (1 - alpha)) + (task_per_min * alpha)

    def update_heartbeat(self, load: float, task_count: int):
        """Update metrics with heartbeat information"""
        self.last_heartbeat = datetime.now(timezone.utc)
        self.current_load = load
        self.task_count = task_count

    def update_response_time(self, response_time: float):
        """Update the average response time"""
        alpha = 0.2  # Learning rate
        if self.response_time == 0:
            self.response_time = response_time
        else:
            self.response_time = (self.response_time * (1 - alpha)) + (
                response_time * alpha
            )

    def get_average_execution_time(self, task_type: str) -> float:
        """Get average execution time for a task type"""
        if (
            task_type in self.task_execution_times
            and self.task_execution_times[task_type]
        ):
            return statistics.mean(self.task_execution_times[task_type])
        return 60.0  # Default 1 minute if no data

    def get_health_score(self) -> float:
        """
        Calculate overall health score for this worker (0.0-1.0)
        Higher is better/healthier
        """
        score = 1.0

        # Factor 1: Success rate
        score *= self.success_rate

        # Factor 2: Penalty score
        if self.penalty_score > 0:
            penalty_factor = math.exp(-self.penalty_score / 10.0)
            score *= penalty_factor

        # Factor 3: Heartbeat recency
        if self.last_heartbeat:
            seconds_since_heartbeat = (
                datetime.now(timezone.utc) - self.last_heartbeat
            ).total_seconds()
            if seconds_since_heartbeat > 300:  # 5 minutes
                # Severe penalty for stale heartbeat
                score *= 0.2
            elif seconds_since_heartbeat > 60:  # 1 minute
                # Moderate penalty
                score *= 0.8

        return score

    def is_healthy(self) -> bool:
        """Check if worker is considered healthy based on metrics"""
        return self.get_health_score() > 0.7  # Threshold for health

    def can_accept_task(self, task_type: str = None) -> bool:
        """Check if worker can accept a new task"""
        # Check capacity
        if self.task_count >= self.max_concurrent_tasks:
            return False

        # Check load
        if self.current_load > 0.9:  # 90% load
            return False

        # Check capabilities
        if task_type and task_type not in self.capabilities:
            return False

        # Check health
        if not self.is_healthy():
            return False

        return True

    def predicted_completion_time(self, task_type: str) -> float:
        """
        Predict how long it will take this worker to complete a new task
        based on current load and historical performance
        """
        # Base execution time from history
        base_time = self.get_average_execution_time(task_type)

        # Adjust for current load
        load_factor = 1 + (self.current_load * 0.5)  # Up to 50% slower at full load

        # Adjust for queue depth
        queue_factor = 1 + (self.task_count * 0.2)  # 20% slower per queued task

        return base_time * load_factor * queue_factor


class WorkerMetricsManager:
    """
    Manages metrics for all workers in the distributed system.
    Provides analysis and statistics for the distribution algorithm.
    """

    def __init__(self):
        self.metrics: Dict[str, WorkerMetrics] = {}
        self.alpha = 0.2  # Learning rate for exponential averages

    def get_or_create_metrics(self, worker_id: str) -> WorkerMetrics:
        """Get metrics for a worker or create if not exists"""
        if worker_id not in self.metrics:
            self.metrics[worker_id] = WorkerMetrics(worker_id=worker_id)
        return self.metrics[worker_id]

    def update_task_result(
        self, worker_id: str, task_type: str, success: bool, execution_time: float
    ):
        """Update metrics with a task result"""
        metrics = self.get_or_create_metrics(worker_id)
        metrics.update_task_result(task_type, success, execution_time)

    def update_heartbeat(self, worker_id: str, load: float, task_count: int):
        """Update metrics with heartbeat information"""
        metrics = self.get_or_create_metrics(worker_id)
        metrics.update_heartbeat(load, task_count)

    def update_response_time(self, worker_id: str, response_time: float):
        """Update response time metrics"""
        metrics = self.get_or_create_metrics(worker_id)
        metrics.update_response_time(response_time)

    def update_capabilities(self, worker_id: str, capabilities: Set[str]):
        """Update worker capabilities"""
        metrics = self.get_or_create_metrics(worker_id)
        metrics.capabilities = capabilities

    def update_max_concurrent_tasks(self, worker_id: str, max_tasks: int):
        """Update maximum concurrent tasks"""
        metrics = self.get_or_create_metrics(worker_id)
        metrics.max_concurrent_tasks = max_tasks

    def get_all_metrics(self) -> Dict[str, WorkerMetrics]:
        """Get metrics for all workers"""
        return self.metrics

    def get_healthy_workers(self) -> Dict[str, WorkerMetrics]:
        """Get metrics for only healthy workers"""
        return {
            wid: metrics
            for wid, metrics in self.metrics.items()
            if metrics.is_healthy()
        }

    def get_available_workers_for_task(
        self, task_type: str
    ) -> Dict[str, WorkerMetrics]:
        """Get metrics for workers that can accept a specific task type"""
        return {
            wid: metrics
            for wid, metrics in self.metrics.items()
            if metrics.can_accept_task(task_type)
        }

    def get_best_worker_for_task(self, task_type: str) -> Optional[str]:
        """
        Find the best worker for a specific task type based on
        predicted completion time
        """
        available_workers = self.get_available_workers_for_task(task_type)
        if not available_workers:
            return None

        # Find worker with shortest predicted completion time
        predictions = {
            wid: metrics.predicted_completion_time(task_type)
            for wid, metrics in available_workers.items()
        }

        # Sort by predicted time (ascending)
        sorted_workers = sorted(predictions.items(), key=lambda x: x[1])
        if sorted_workers:
            return sorted_workers[0][0]

        return None

    def prune_inactive_workers(self, max_inactive_seconds: int = 300):
        """Remove workers that haven't sent heartbeats recently"""
        now = datetime.now(timezone.utc)
        inactive_workers = []

        for worker_id, metrics in self.metrics.items():
            if not metrics.last_heartbeat:
                # No heartbeat received yet
                continue

            inactive_time = (now - metrics.last_heartbeat).total_seconds()
            if inactive_time > max_inactive_seconds:
                inactive_workers.append(worker_id)

        for worker_id in inactive_workers:
            logger.info(f"Pruning inactive worker: {worker_id}")
            del self.metrics[worker_id]

    def get_system_statistics(self) -> Dict[str, float]:
        """Get overall system statistics"""
        if not self.metrics:
            return {
                "active_workers": 0,
                "total_capacity": 0,
                "used_capacity": 0,
                "avg_success_rate": 0,
                "avg_load": 0,
                "avg_response_time": 0,
                "system_health": 0,
            }

        active_workers = sum(1 for m in self.metrics.values() if m.is_healthy())
        total_capacity = sum(
            m.max_concurrent_tasks for m in self.metrics.values() if m.is_healthy()
        )
        used_capacity = sum(m.task_count for m in self.metrics.values())

        # Calculate averages only for active workers
        active_metrics = [m for m in self.metrics.values() if m.is_healthy()]
        if active_metrics:
            avg_success_rate = sum(m.success_rate for m in active_metrics) / len(
                active_metrics
            )
            avg_load = sum(m.current_load for m in active_metrics) / len(active_metrics)
            avg_response_time = sum(m.response_time for m in active_metrics) / len(
                active_metrics
            )
            system_health = sum(m.get_health_score() for m in active_metrics) / len(
                active_metrics
            )
        else:
            avg_success_rate = 0
            avg_load = 0
            avg_response_time = 0
            system_health = 0

        return {
            "active_workers": active_workers,
            "total_capacity": total_capacity,
            "used_capacity": used_capacity,
            "capacity_utilization": (
                used_capacity / total_capacity if total_capacity > 0 else 0
            ),
            "avg_success_rate": avg_success_rate,
            "avg_load": avg_load,
            "avg_response_time": avg_response_time,
            "system_health": system_health,
        }
