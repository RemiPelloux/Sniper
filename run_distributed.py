#!/usr/bin/env python
"""
Script to run the Sniper distributed scanning CLI.
"""

import sys
from src.cli.distributed_typer import distributed_app

if __name__ == "__main__":
    distributed_app() 