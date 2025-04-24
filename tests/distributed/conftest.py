import os
import sys
import pytest
from pathlib import Path

# Add specific fixtures for distributed tests here


@pytest.fixture
def mock_master_node():
    """Mock master node for testing."""
    class MockMaster:
        def __init__(self):
            self.workers = []
            self.tasks = {}
            self.running = True
            
        def start(self):
            self.running = True
            return True
            
        def stop(self):
            self.running = False
            return True
            
        def get_status(self):
            return {
                "status": "running" if self.running else "stopped",
                "workers": len(self.workers),
                "tasks": len(self.tasks)
            }
    
    return MockMaster()

@pytest.fixture
def mock_worker_node():
    """Mock worker node for testing."""
    class MockWorker:
        def __init__(self):
            self.running = False
            self.tasks = {}
            self.capabilities = ["vulnerability_scan", "recon"]
            
        def start(self):
            self.running = True
            return True
            
        def stop(self):
            self.running = False
            return True
            
        def get_status(self):
            return {
                "status": "running" if self.running else "stopped",
                "tasks": len(self.tasks),
                "capabilities": self.capabilities
            }
    
    return MockWorker()
