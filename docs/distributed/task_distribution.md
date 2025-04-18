# Task Distribution in Distributed Scanning

This document outlines the task distribution mechanism in the Sniper distributed scanning architecture.

## Task Distribution Process

The distributed scanning architecture uses a central master node to distribute tasks to multiple worker nodes. The distribution process involves several steps:

1. Tasks are added to the master node's pending queue via the `add_task` or `add_tasks` methods.
2. The master node periodically calls `distribute_tasks()` which in turn calls the internal `_distribute_pending_tasks()` method.
3. The `_distribute_pending_tasks()` method uses the configured distribution algorithm to assign tasks to available worker nodes.
4. Tasks are sent to the assigned workers for execution.
5. Workers process tasks and return results to the master node.

## The `_distribute_pending_tasks()` Method

The `_distribute_pending_tasks()` method is the core of the distribution mechanism. It performs the following steps:

```python
def _distribute_pending_tasks(self) -> int:
    """
    Distribute pending tasks to available workers based on the selected distribution algorithm.
    
    Returns:
        Number of tasks distributed
    """
    with self.task_lock, self.worker_lock:
        # Get available active workers
        active_workers = {
            worker_id: info
            for worker_id, info in self.workers.items()
            if info.status in [NodeStatus.ACTIVE, NodeStatus.IDLE]
        }
        
        if not active_workers:
            logger.warning("No active workers available for task distribution")
            return 0
            
        if not self.pending_tasks:
            logger.debug("No pending tasks to distribute")
            return 0
            
        # Use the distribution algorithm to assign tasks to workers
        task_distribution = self.distribution_algorithm.distribute(
            self.pending_tasks,
            active_workers,
            self.worker_metrics
        )
        
        total_assigned = 0
        
        # Send tasks to assigned workers
        for worker_id, tasks in task_distribution.items():
            for task in self.pending_tasks:
                if task.id in tasks:
                    success = self._send_task_to_worker(task, worker_id)
                    if success:
                        total_assigned += 1
        
        # Remove assigned tasks from pending list
        self.pending_tasks = [
            task for task in self.pending_tasks
            if task.status == TaskStatus.PENDING
        ]
        
        logger.info(f"Distributed {total_assigned} tasks to {len(active_workers)} active workers")
        return total_assigned
```

## Distribution Algorithms

The system supports multiple task distribution algorithms:

1. **Round Robin Distribution**: Distributes tasks evenly among workers in a cyclic fashion.
2. **Capability Based Distribution**: Assigns tasks to workers based on their capabilities and expertise.
3. **Priority Based Distribution**: Prioritizes tasks by importance before distribution.
4. **Load Balanced Distribution**: Distributes tasks to maintain balanced load across workers.
5. **Smart Distribution**: Uses machine learning to optimize task assignments based on historical performance.

The distribution algorithm can be specified when creating the master node by setting the `distribution_strategy` parameter.

## Task Flow

1. Client submits a task via the REST API or command-line interface.
2. The master node adds the task to its pending task queue.
3. During the next distribution cycle, the master node assigns the task to an available worker.
4. The worker executes the task and sends status updates to the master.
5. When the task is completed, the worker sends the results to the master.
6. The master processes the results and makes them available to the client.

## Fault Tolerance

The task distribution mechanism includes fault tolerance features:

- If a worker fails during task execution, the master node can reassign the task to another worker.
- If all workers are busy, tasks remain in the pending queue until workers become available.
- If a task fails, the master node can retry it with a different worker up to a configurable retry limit.

## Auto-Scaling Integration

The task distribution mechanism integrates with the auto-scaling subsystem:

- The distribution process provides metrics about pending tasks and worker load.
- The auto-scaler uses these metrics to determine when to add or remove worker nodes.
- When new workers are added, they become available for task distribution in the next cycle.

## Monitoring and Metrics

The task distribution process collects metrics that can be used for monitoring:

- Number of tasks distributed per cycle
- Distribution success rate
- Worker load and availability
- Task completion rates
- Average time spent in pending queue

These metrics help administrators tune the distribution process for optimal performance. 