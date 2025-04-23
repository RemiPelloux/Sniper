#!/usr/bin/env python3
"""
Simplified Typer-based CLI for Sniper's distributed scanning architecture.
Provides commands for managing master nodes, worker nodes, and tasks.
"""

import os
import sys
import json
import typer
import signal
import time
from typing import List, Optional, Dict, Any

# Create the main app
app = typer.Typer(help="Sniper Security Tool - Distributed Scanning CLI")
distributed_app = typer.Typer(help="Distributed scanning capabilities")
app.add_typer(distributed_app, name="distributed")

# Create subcommands
master_app = typer.Typer(help="Master node management")
worker_app = typer.Typer(help="Worker node management")
tasks_app = typer.Typer(help="Distributed task management")
workers_app = typer.Typer(help="Worker node information")

distributed_app.add_typer(master_app, name="master")
distributed_app.add_typer(worker_app, name="worker")
distributed_app.add_typer(tasks_app, name="tasks")
distributed_app.add_typer(workers_app, name="workers")

# Mock classes for demonstration
class MockMaster:
    def __init__(self, host: str, port: int, strategy: str):
        self.host = host
        self.port = port
        self.strategy = strategy
        self.running = False
        self.workers = []
        self.tasks = {}
    
    def start(self):
        self.running = True
        return {"status": "running", "host": self.host, "port": self.port}
    
    def stop(self):
        self.running = False
        return {"status": "stopped"}
    
    def status(self):
        status = "running" if self.running else "stopped"
        return {
            "status": status,
            "host": self.host,
            "port": self.port,
            "strategy": self.strategy,
            "workers_count": len(self.workers),
            "tasks_count": len(self.tasks)
        }

class MockWorker:
    def __init__(self, master_host: str, master_port: int, worker_id: str, 
                 capabilities: List[str], max_tasks: int):
        self.master_host = master_host
        self.master_port = master_port
        self.worker_id = worker_id or f"worker-{os.getpid()}"
        self.capabilities = capabilities
        self.max_tasks = max_tasks
        self.running = False
        self.active_tasks = {}
    
    def start(self):
        self.running = True
        return {
            "status": "running", 
            "worker_id": self.worker_id,
            "master": f"{self.master_host}:{self.master_port}"
        }
    
    def stop(self):
        self.running = False
        return {"status": "stopped", "worker_id": self.worker_id}
    
    def status(self):
        status = "running" if self.running else "stopped"
        return {
            "status": status,
            "worker_id": self.worker_id,
            "master": f"{self.master_host}:{self.master_port}",
            "capabilities": self.capabilities,
            "max_tasks": self.max_tasks,
            "active_tasks": len(self.active_tasks)
        }

class MockTaskManager:
    def __init__(self):
        self.tasks = {
            "task-123": {
                "id": "task-123",
                "type": "vulnerability_scan",
                "target": "example.com",
                "status": "running",
                "progress": 45,
                "worker": "worker-1"
            },
            "task-456": {
                "id": "task-456",
                "type": "recon",
                "target": "test.org",
                "status": "completed",
                "progress": 100,
                "worker": "worker-2"
            }
        }
    
    def list_tasks(self):
        return self.tasks
    
    def get_task(self, task_id: str):
        return self.tasks.get(task_id)
    
    def cancel_task(self, task_id: str):
        if task_id in self.tasks:
            self.tasks[task_id]["status"] = "canceled"
            return {"status": "success", "message": f"Task {task_id} canceled"}
        return {"status": "error", "message": f"Task {task_id} not found"}
    
    def submit_task(self, task_type: str, target: str, options: Dict[str, Any]):
        task_id = f"task-{len(self.tasks) + 1}"
        self.tasks[task_id] = {
            "id": task_id,
            "type": task_type,
            "target": target,
            "status": "pending",
            "progress": 0,
            "options": options
        }
        return {"status": "success", "task_id": task_id}

# Global instances for demonstration
_master = None
_worker = None
_task_manager = MockTaskManager()

# Master commands
@master_app.command("start")
def master_start(
    host: str = typer.Option("127.0.0.1", help="Host to bind the master node to"),
    port: int = typer.Option(5000, help="Port to bind the master node to"),
    strategy: str = typer.Option("round-robin", help="Task distribution strategy")
):
    """Start a master node with the specified configuration"""
    global _master
    _master = MockMaster(host, port, strategy)
    result = _master.start()
    typer.echo(json.dumps(result, indent=2))

@master_app.command("stop")
def master_stop():
    """Stop the running master node"""
    global _master
    if not _master:
        typer.echo(json.dumps({"status": "error", "message": "No master node is running"}, indent=2))
        return
    
    result = _master.stop()
    typer.echo(json.dumps(result, indent=2))

@master_app.command("status")
def master_status():
    """Get the status of the master node"""
    global _master
    if not _master:
        typer.echo(json.dumps({"status": "not_running"}, indent=2))
        return
    
    result = _master.status()
    typer.echo(json.dumps(result, indent=2))

# Worker commands
@worker_app.command("start")
def worker_start(
    master_host: str = typer.Option("127.0.0.1", help="Master node host"),
    master_port: int = typer.Option(5000, help="Master node port"),
    worker_id: Optional[str] = typer.Option(None, help="Worker ID (auto-generated if not provided)"),
    capabilities: str = typer.Option("vuln_scan,recon", help="Comma-separated list of capabilities"),
    max_tasks: int = typer.Option(5, help="Maximum concurrent tasks")
):
    """Start a worker node connecting to the specified master"""
    global _worker
    capabilities_list = capabilities.split(",")
    _worker = MockWorker(master_host, master_port, worker_id, capabilities_list, max_tasks)
    result = _worker.start()
    
    def handle_signal(sig, frame):
        typer.echo("\nStopping worker...")
        _worker.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, handle_signal)
    typer.echo(json.dumps(result, indent=2))
    typer.echo("Worker is running. Press Ctrl+C to stop.")
    
    # This would normally be a loop to keep the worker running
    try:
        signal.pause()
    except KeyboardInterrupt:
        _worker.stop()

@worker_app.command("stop")
def worker_stop():
    """Stop the running worker node"""
    global _worker
    if not _worker:
        typer.echo(json.dumps({"status": "error", "message": "No worker node is running"}, indent=2))
        return
    
    result = _worker.stop()
    typer.echo(json.dumps(result, indent=2))

@worker_app.command("status")
def worker_status():
    """Get the status of the worker node"""
    global _worker
    if not _worker:
        typer.echo(json.dumps({"status": "not_running"}, indent=2))
        return
    
    result = _worker.status()
    typer.echo(json.dumps(result, indent=2))

# Task commands
@tasks_app.command("list")
def list_tasks():
    """List all tasks in the distributed system"""
    tasks = _task_manager.list_tasks()
    typer.echo(json.dumps({"tasks": list(tasks.values())}, indent=2))

@tasks_app.command("info")
def task_info(task_id: str = typer.Argument(..., help="ID of the task to get info about")):
    """Get detailed information about a specific task"""
    task = _task_manager.get_task(task_id)
    if task:
        typer.echo(json.dumps(task, indent=2))
    else:
        typer.echo(json.dumps({"status": "error", "message": f"Task {task_id} not found"}, indent=2))

@tasks_app.command("cancel")
def cancel_task(task_id: str = typer.Argument(..., help="ID of the task to cancel")):
    """Cancel a running task"""
    result = _task_manager.cancel_task(task_id)
    typer.echo(json.dumps(result, indent=2))

@tasks_app.command("submit")
def submit_task(
    task_type: str = typer.Option(..., help="Type of task to submit (e.g., vulnerability_scan, recon)"),
    target: str = typer.Option(..., help="Target to scan (e.g., domain, IP, URL)"),
    options_json: str = typer.Option("{}", help="JSON string of task options")
):
    """Submit a new task to the distributed system"""
    try:
        options = json.loads(options_json)
    except json.JSONDecodeError:
        typer.echo(json.dumps({"status": "error", "message": "Invalid JSON in options"}, indent=2))
        return
    
    result = _task_manager.submit_task(task_type, target, options)
    typer.echo(json.dumps(result, indent=2))

@tasks_app.command("scan")
def submit_scan(
    target: str = typer.Argument(..., help="Target URL, domain, or IP to scan"),
    scan_type: str = typer.Option("full", help="Type of scan to perform (full, quick, vuln)"),
    depth: int = typer.Option(3, help="Scan depth (1-5)"),
    timeout: int = typer.Option(300, help="Timeout in seconds"),
):
    """Submit a scan task to the distributed system"""
    options = {
        "scan_type": scan_type,
        "depth": depth,
        "timeout": timeout,
        "timestamp": int(time.time())
    }
    
    result = _task_manager.submit_task("vulnerability_scan", target, options)
    
    if result.get("status") == "success":
        task_id = result.get("task_id")
        typer.echo(f"Scan task submitted with ID: {task_id}")
        typer.echo(json.dumps(result, indent=2))
        
        # Display a helpful message
        typer.echo(f"\nTo check the status: tasks info {task_id}")
        typer.echo(f"To cancel the scan: tasks cancel {task_id}")
    else:
        typer.echo("Failed to submit scan task")
        typer.echo(json.dumps(result, indent=2))

# Worker list commands
@workers_app.command("list")
def list_workers():
    """List all registered workers"""
    # Mock implementation
    workers = [
        {"id": "worker-1", "status": "active", "capabilities": ["vuln_scan", "recon"], "tasks": 2},
        {"id": "worker-2", "status": "active", "capabilities": ["vuln_scan"], "tasks": 1},
        {"id": "worker-3", "status": "idle", "capabilities": ["recon", "fuzzing"], "tasks": 0}
    ]
    typer.echo(json.dumps({"workers": workers}, indent=2))

if __name__ == "__main__":
    app() 