#!/usr/bin/env python3
"""
Simple script to run a Sniper worker node using the simplified Typer CLI.

This script provides a direct way to start a worker node that connects to a master node.
"""

import sys
import os
from src.cli.distributed_typer_simple import worker_app

if __name__ == "__main__":
    # For nicer help output, make it look like we're running just the worker command
    sys.argv[0] = "worker"
    
    # If no arguments, print help
    if len(sys.argv) == 1:
        sys.argv.append("--help")
        
    # Run the worker app
    worker_app() 