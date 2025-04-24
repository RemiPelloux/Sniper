#!/usr/bin/env python3
"""
Example demonstrating the use of Sniper's distributed scanning architecture.

This script shows how to:
1. Start a complete distributed system with auto-discovery
2. Submit different types of tasks
3. Wait for and retrieve results
4. Shutdown the system cleanly
"""

import asyncio
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.logging import setup_logging
from src.distributed.api import get_distributed_api
from src.distributed.autodiscovery import get_discovery_manager
from src.distributed.base import TaskPriority

# Set up logging
setup_logging(level="INFO")
logger = logging.getLogger("sniper.examples.distributed")


async def run_example():
    """Run the distributed system example."""
    # Step 1: Start the distributed system
    logger.info("Starting distributed system...")

    # Get the discovery manager (singleton)
    discovery_manager = get_discovery_manager()

    # Start master node and auto-discovery (will auto-start workers)
    if not discovery_manager.start():
        logger.error("Failed to start distributed system")
        return

    logger.info("Distributed system started")
    logger.info("Waiting for workers to register...")

    # Give workers time to register with master
    await asyncio.sleep(5)

    try:
        # Step 2: Submit some example tasks
        logger.info("Submitting example tasks...")

        # Get the API client
        api = get_distributed_api()

        # Submit an autonomous testing task
        task1_id = await api.submit_autonomous_test(
            target_url="https://example.com",
            vulnerability_type="xss",
            priority=TaskPriority.HIGH,
            wait_for_result=False,
        )
        logger.info(f"Submitted autonomous test task with ID: {task1_id}")

        # Submit a vulnerability scanning task
        task2_id = await api.submit_vulnerability_scan(
            target={"url": "https://example.org"},
            scan_type="quick",
            priority=TaskPriority.MEDIUM,
            wait_for_result=False,
        )
        logger.info(f"Submitted vulnerability scan task with ID: {task2_id}")

        # Submit a reconnaissance task
        task3_id = await api.submit_recon_task(
            target={"domain": "example.net"},
            recon_type="passive",
            priority=TaskPriority.LOW,
            wait_for_result=False,
        )
        logger.info(f"Submitted reconnaissance task with ID: {task3_id}")

        # Step 3: Wait for and retrieve results
        logger.info("Waiting for task results...")

        # Check status periodically
        for _ in range(30):  # Wait up to 30 seconds
            # Get status of all tasks
            status1 = await api.check_task_status(task1_id)
            status2 = await api.check_task_status(task2_id)
            status3 = await api.check_task_status(task3_id)

            logger.info(f"Task statuses: {status1}, {status2}, {status3}")

            # If all tasks are done, break
            if all(
                status in ["COMPLETED", "FAILED", "CANCELLED"]
                for status in [status1, status2, status3]
                if status
            ):
                break

            await asyncio.sleep(1)

        # Retrieve results
        result1 = await api.get_task_result(task1_id)
        result2 = await api.get_task_result(task2_id)
        result3 = await api.get_task_result(task3_id)

        # Display results (if available)
        if result1:
            logger.info(f"Task 1 result: {json.dumps(result1, indent=2)}")
        if result2:
            logger.info(f"Task 2 result: {json.dumps(result2, indent=2)}")
        if result3:
            logger.info(f"Task 3 result: {json.dumps(result3, indent=2)}")

        # Get active workers
        workers = await api.get_active_workers()
        logger.info(f"Active workers: {len(workers)}")

    except Exception as e:
        logger.error(f"Error during example execution: {str(e)}")
    finally:
        # Step 4: Clean shutdown
        logger.info("Shutting down distributed system...")
        discovery_manager.stop()
        logger.info("System shutdown complete")


if __name__ == "__main__":
    # Handle keyboard interrupts
    def signal_handler(sig, frame):
        logger.info("Shutdown requested via signal")
        discovery_manager = get_discovery_manager()
        discovery_manager.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run the example
    asyncio.run(run_example())
