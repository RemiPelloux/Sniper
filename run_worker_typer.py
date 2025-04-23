#!/usr/bin/env python
"""
Script to run a Sniper worker node using the Typer CLI.
"""

import sys
from src.cli.distributed_typer import worker_app

if __name__ == "__main__":
    sys.argv[0] = "worker"
    worker_app() 