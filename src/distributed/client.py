"""
Client Module for Sniper Distributed Scanning Architecture.

This module provides client-side functionality for worker nodes to connect to
the master node and participate in distributed scanning operations.
"""

import logging
import os
import sys
import time
from typing import Dict, List, Callable, Any, Optional

from .worker import WorkerNodeClient, SniperWorkerNode
from .base import TaskStatus
from .protocol import create_protocol

logger = logging.getLogger("sniper.distributed.client")

def setup_logging(log_level: str = "INFO", log_file: str = None):
    """
    Set up logging for the distributed client.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path to log to
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    
    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            *([] if not log_file else [logging.FileHandler(log_file)])
        ]
    )
    
    # Set level for our loggers
    for logger_name in ["sniper.distributed", "sniper.distributed.client", 
                        "sniper.distributed.worker", "sniper.distributed.protocol"]:
        logging.getLogger(logger_name).setLevel(numeric_level)

def create_worker_client(master_host: str, master_port: int, 
                        protocol_type: str = "REST",
                        capabilities: List[str] = None,
                        max_concurrent_tasks: int = 5,
                        heartbeat_interval: int = 30) -> WorkerNodeClient:
    """
    Create a new worker node client.
    
    Args:
        master_host: Host address of the master node
        master_port: Port of the master node
        protocol_type: Communication protocol to use
        capabilities: List of task types this worker can execute
        max_concurrent_tasks: Maximum concurrent tasks
        heartbeat_interval: Heartbeat interval in seconds
        
    Returns:
        WorkerNodeClient: Configured worker node client
    """
    client = WorkerNodeClient(
        master_host=master_host,
        master_port=master_port,
        protocol_type=protocol_type,
        capabilities=capabilities,
        max_concurrent_tasks=max_concurrent_tasks,
        heartbeat_interval=heartbeat_interval
    )
    
    return client

def register_default_handlers(client: WorkerNodeClient) -> None:
    """
    Register default task handlers for common Sniper operations.
    
    Args:
        client: The worker node client to register handlers with
    """
    # Import task handlers from appropriate modules
    from ..scan import scanner
    from ..smartrecon import recon
    from ..analysis import analyzer
    
    # Register scan handler
    def scan_handler(target: str, **kwargs) -> Dict[str, Any]:
        """Handler for scan tasks"""
        try:
            scan_type = kwargs.get("scan_type", "default")
            options = kwargs.get("options", {})
            
            logger.info(f"Running {scan_type} scan on {target}")
            result = scanner.run_scan(target, scan_type, options)
            return {"status": "success", "findings": result}
        except Exception as e:
            logger.error(f"Error in scan handler: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    # Register recon handler
    def recon_handler(target: str, **kwargs) -> Dict[str, Any]:
        """Handler for reconnaissance tasks"""
        try:
            recon_type = kwargs.get("recon_type", "default")
            depth = kwargs.get("depth", 1)
            
            logger.info(f"Running {recon_type} recon on {target} with depth {depth}")
            result = recon.run_recon(target, recon_type, depth)
            return {"status": "success", "findings": result}
        except Exception as e:
            logger.error(f"Error in recon handler: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    # Register analysis handler
    def analysis_handler(target: str, **kwargs) -> Dict[str, Any]:
        """Handler for analysis tasks"""
        try:
            analysis_type = kwargs.get("analysis_type", "default")
            data = kwargs.get("data", {})
            
            logger.info(f"Running {analysis_type} analysis on {target}")
            result = analyzer.analyze(target, analysis_type, data)
            return {"status": "success", "findings": result}
        except Exception as e:
            logger.error(f"Error in analysis handler: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    # Register all handlers with the client
    client.register_task_handler("scan", scan_handler)
    client.register_task_handler("recon", recon_handler)
    client.register_task_handler("analysis", analysis_handler)
    
    logger.info("Registered default task handlers for scan, recon, and analysis")

def run_worker(master_host: str, master_port: int, 
               protocol_type: str = "REST",
               capabilities: List[str] = None,
               max_concurrent_tasks: int = 5,
               heartbeat_interval: int = 30,
               register_defaults: bool = True,
               log_level: str = "INFO") -> None:
    """
    Run a worker node client (blocking).
    
    Args:
        master_host: Host address of the master node
        master_port: Port number of the master node
        protocol_type: Communication protocol to use
        capabilities: List of supported task types
        max_concurrent_tasks: Maximum number of concurrent tasks
        heartbeat_interval: Heartbeat interval in seconds
        register_defaults: Whether to register default task handlers
        log_level: Logging level
    """
    # Set up logging
    setup_logging(log_level)
    
    logger.info(f"Starting Sniper worker node, connecting to {master_host}:{master_port}")
    
    # Create client
    client = create_worker_client(
        master_host=master_host,
        master_port=master_port,
        protocol_type=protocol_type,
        capabilities=capabilities,
        max_concurrent_tasks=max_concurrent_tasks,
        heartbeat_interval=heartbeat_interval
    )
    
    # Register default handlers if requested
    if register_defaults:
        register_default_handlers(client)
    
    try:
        # Start the client
        if not client.start():
            logger.error("Failed to start worker node client")
            sys.exit(1)
        
        logger.info("Worker node started successfully")
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
    except Exception as e:
        logger.error(f"Error in worker node: {str(e)}")
    finally:
        # Stop the client
        client.stop()
        logger.info("Worker node stopped")

if __name__ == "__main__":
    # Simple command-line handling when run directly
    import argparse
    
    parser = argparse.ArgumentParser(description="Sniper Distributed Worker Node")
    parser.add_argument("--host", default="localhost", help="Master node host")
    parser.add_argument("--port", type=int, default=5000, help="Master node port")
    parser.add_argument("--protocol", default="REST", help="Communication protocol")
    parser.add_argument("--max-tasks", type=int, default=5, help="Max concurrent tasks")
    parser.add_argument("--heartbeat", type=int, default=30, help="Heartbeat interval (seconds)")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    parser.add_argument("--capabilities", nargs="+", default=["scan", "vuln", "recon"], 
                        help="Supported task types")
    
    args = parser.parse_args()
    
    run_worker(
        master_host=args.host,
        master_port=args.port,
        protocol_type=args.protocol,
        capabilities=args.capabilities,
        max_concurrent_tasks=args.max_tasks,
        heartbeat_interval=args.heartbeat,
        log_level=args.log_level
    ) 