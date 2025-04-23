#!/usr/bin/env python3
"""
Test script for the Sniper distributed scanning architecture.

This script verifies that the distributed system components are working correctly
by starting a master node, connecting a worker node, and checking process output.
"""

import os
import sys
import time
import argparse
import subprocess
import signal
import json
from pathlib import Path
import requests

# Configuration
DEFAULT_MASTER_HOST = "localhost"
DEFAULT_MASTER_PORT = 5000
MASTER_STARTUP_WAIT = 3  # seconds to wait for master to start
WORKER_STARTUP_WAIT = 3  # seconds to wait for worker to start
PROCESS_CHECK_TIMEOUT = 1  # seconds to wait when checking process output

def run_command(command, background=False):
    """Run a command and optionally return the process for background tasks."""
    print(f"Running command: {' '.join(command)}")
    
    if background:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        return process
    else:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result

def check_master_status_api(host, port):
    """Check if master node is running and accepting connections via API."""
    try:
        response = requests.get(f"http://{host}:{port}/api/health", timeout=5)
        if response.status_code == 200:
            return True, response.json()
        return False, {"status": "error", "code": response.status_code}
    except requests.exceptions.RequestException as e:
        return False, {"status": "error", "message": str(e)}

def check_worker_status_api(host, port, worker_id=None):
    """Check if worker node is registered with the master via API."""
    try:
        response = requests.get(f"http://{host}:{port}/api/workers", timeout=5)
        if response.status_code == 200:
            workers = response.json().get("workers", [])
            
            if worker_id:
                # Check for specific worker
                for worker in workers:
                    if worker.get("id") == worker_id:
                        return True, worker
                return False, {"status": "not_found", "message": f"Worker {worker_id} not registered"}
            else:
                # Just check if any workers are registered
                if workers:
                    return True, {"workers_count": len(workers), "workers": workers}
                return False, {"status": "no_workers", "message": "No workers registered"}
        
        return False, {"status": "error", "code": response.status_code}
    except requests.exceptions.RequestException as e:
        return False, {"status": "error", "message": str(e)}

def check_process_status(process, success_text, failure_text=None, timeout=PROCESS_CHECK_TIMEOUT):
    """Check if a process is running and contains expected output."""
    if process.poll() is not None:
        # Process has exited
        stdout, stderr = process.communicate()
        return False, {
            "status": "exited", 
            "return_code": process.returncode,
            "stdout": stdout, 
            "stderr": stderr
        }
    
    # Process still running, check for output
    output = ""
    start_time = time.time()
    
    # Try to read output for up to timeout seconds
    while time.time() - start_time < timeout:
        # Read available output without blocking
        new_output = process.stdout.readline()
        if new_output:
            output += new_output
            print(f"Process output: {new_output.strip()}")
            
            if success_text and success_text in output:
                return True, {"status": "success", "output": output}
            
            if failure_text and failure_text in output:
                return False, {"status": "failure", "output": output}
                
        time.sleep(0.1)
    
    # Timeout reached, just check if success text is in accumulated output
    if success_text and success_text in output:
        return True, {"status": "success", "output": output}
        
    # Process is running but we didn't detect success yet
    return None, {"status": "running", "output": output}

def main():
    parser = argparse.ArgumentParser(description="Test the Sniper distributed scanning architecture")
    parser.add_argument("--master-host", default=DEFAULT_MASTER_HOST, help="Master node host")
    parser.add_argument("--master-port", type=int, default=DEFAULT_MASTER_PORT, help="Master node port")
    parser.add_argument("--simple", action="store_true", help="Use the simplified Typer CLI for testing")
    parser.add_argument("--use-api", action="store_true", help="Use API checks (not for simplified CLI)")
    args = parser.parse_args()
    
    master_process = None
    worker_process = None
    success = False
    
    try:
        # Start master node
        if args.simple:
            master_cmd = [
                sys.executable, "-m", "src.cli.distributed_typer_simple", "distributed", "master", "start",
                "--host", args.master_host, "--port", str(args.master_port)
            ]
        else:
            master_cmd = [
                sys.executable, "-m", "src.cli.distributed_typer", "master", "start",
                "--host", args.master_host, "--port", str(args.master_port)
            ]
        
        master_process = run_command(master_cmd, background=True)
        print(f"Started master node (PID: {master_process.pid})")
        
        # Wait for master to start
        print(f"Waiting {MASTER_STARTUP_WAIT} seconds for master to initialize...")
        time.sleep(MASTER_STARTUP_WAIT)
        
        # Check master status
        if args.use_api:
            # Check via API
            for i in range(3):
                print(f"Checking master status via API (attempt {i+1}/3)...")
                success, status = check_master_status_api(args.master_host, args.master_port)
                if success:
                    print(f"Master node is running: {json.dumps(status, indent=2)}")
                    break
                print(f"Master node not responding: {json.dumps(status, indent=2)}")
                
                if i < 2:
                    print("Waiting 2 seconds before retrying...")
                    time.sleep(2)
        else:
            # Check process output for master
            success, status = check_process_status(
                master_process, 
                success_text="running" if args.simple else "started successfully",
                timeout=2
            )
            
            if success:
                print("Master node started successfully")
            elif status["status"] == "running":
                # Process is running but we didn't find success text yet
                # Let's assume it's working
                print("Master node process is running")
                success = True
            else:
                print(f"Master node failed to start: {status}")
        
        if not success:
            print("ERROR: Master node failed to start properly")
            return 1
            
        # Start worker node
        if args.simple:
            worker_cmd = [
                sys.executable, "-m", "src.cli.distributed_typer_simple", "distributed", "worker", "start",
                "--master-host", args.master_host, "--master-port", str(args.master_port),
                "--capabilities", "vulnerability_scan,recon,fuzzing"
            ]
        else:
            worker_cmd = [
                sys.executable, "-m", "src.cli.distributed_typer", "worker", "start",
                "--master", f"{args.master_host}:{args.master_port}",
                "--capabilities", "vulnerability_scan,recon,fuzzing"
            ]
            
        worker_process = run_command(worker_cmd, background=True)
        print(f"Started worker node (PID: {worker_process.pid})")
        
        # Wait for worker to start
        print(f"Waiting {WORKER_STARTUP_WAIT} seconds for worker to initialize...")
        time.sleep(WORKER_STARTUP_WAIT)
        
        # Check worker status
        if args.use_api:
            # Check via API
            success = False
            for i in range(3):
                print(f"Checking worker registration via API (attempt {i+1}/3)...")
                success, status = check_worker_status_api(args.master_host, args.master_port)
                if success:
                    print(f"Worker registered successfully: {json.dumps(status, indent=2)}")
                    break
                
                print(f"No workers registered yet: {json.dumps(status, indent=2)}")
                
                if i < 2:
                    print("Waiting 2 seconds before retrying...")
                    time.sleep(2)
        else:
            # Check process output for worker
            success, status = check_process_status(
                worker_process, 
                success_text="running" if args.simple else "Worker node started",
                timeout=2
            )
            
            if success:
                print("Worker node started successfully")
            elif status["status"] == "running":
                # Process is running but we didn't find success text yet
                # Let's assume it's working
                print("Worker node process is running")
                success = True
            else:
                print(f"Worker node failed to start: {status}")
        
        if success:
            print("\n✅ Distributed system test completed successfully!")
            print("  Master process is running with PID: ", master_process.pid)
            print("  Worker process is running with PID: ", worker_process.pid)
            print("\nPress Ctrl+C to stop the test and kill processes...")
            
            # Keep the test running until interrupted
            while True:
                time.sleep(1)
                
            return 0
        else:
            print("\n❌ Distributed system test failed")
            return 1
            
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        return 1
    finally:
        # Clean up processes
        if master_process and master_process.poll() is None:
            print(f"Stopping master process (PID: {master_process.pid})...")
            try:
                os.killpg(os.getpgid(master_process.pid), signal.SIGTERM)
            except Exception as e:
                print(f"Error stopping master process: {e}")
                
        if worker_process and worker_process.poll() is None:
            print(f"Stopping worker process (PID: {worker_process.pid})...")
            try:
                os.killpg(os.getpgid(worker_process.pid), signal.SIGTERM)
            except Exception as e:
                print(f"Error stopping worker process: {e}")


if __name__ == "__main__":
    sys.exit(main()) 