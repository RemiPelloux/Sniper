#!/usr/bin/env python3
"""
Runner script for the simplified distributed CLI.

This script simplifies running the distributed CLI commands.
"""

import sys
from src.cli.distributed_typer_simple import distributed_app

if __name__ == "__main__":
    distributed_app() 