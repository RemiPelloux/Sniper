"""
Payload Library for Sniper Security Tool

This module provides a centralized collection of payloads for different types of security vulnerabilities.
Payloads are organized by vulnerability category and can be easily accessed for use in scanning modules.
"""

import os
import json
from typing import Dict, List, Optional, Union
from pathlib import Path

# Base path for all payload files
PAYLOADS_DIR = Path(__file__).parent.absolute()

# Dictionary mapping vulnerability types to payloads
PAYLOAD_TYPES = {
    "SQL_INJECTION": "SQL injection payloads",
    "XSS": "Cross-site scripting payloads",
    "OPEN_REDIRECT": "Open redirect payloads",
    "PATH_TRAVERSAL": "Path traversal payloads",
    "COMMAND_INJECTION": "Command injection payloads",
    "SSRF": "Server-side request forgery payloads",
    "NOSQL_INJECTION": "NoSQL injection payloads",
    "XXE": "XML external entity payloads",
}

def get_payload_categories() -> List[str]:
    """
    Get a list of all available payload categories.
    
    Returns:
        List of category names (directory names in the payloads directory)
    """
    return [d.name for d in PAYLOADS_DIR.iterdir() 
            if d.is_dir() and not d.name.startswith("__") and not d.name.startswith(".")]

def load_payloads(category: str, payload_file: str = "default.json") -> List[str]:
    """
    Load payloads from a specific category and file.
    
    Args:
        category: The vulnerability category (e.g., 'sqli', 'xss')
        payload_file: The payload file to load (default: 'default.json')
        
    Returns:
        List of payload strings
        
    Raises:
        FileNotFoundError: If the payload file doesn't exist
        ValueError: If the category doesn't exist
    """
    category_path = PAYLOADS_DIR / category
    
    if not category_path.exists() or not category_path.is_dir():
        raise ValueError(f"Payload category '{category}' not found")
    
    payload_path = category_path / payload_file
    
    if not payload_path.exists():
        raise FileNotFoundError(f"Payload file '{payload_file}' not found in category '{category}'")
    
    with open(payload_path, 'r') as f:
        if payload_path.suffix == '.json':
            return json.load(f)
        else:
            # Assume text file with one payload per line
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

def get_all_payloads() -> Dict[str, List[str]]:
    """
    Load all available payloads from all categories.
    
    Returns:
        Dictionary mapping category names to payload lists
    """
    result = {}
    
    for category in get_payload_categories():
        try:
            result[category] = load_payloads(category)
        except (FileNotFoundError, ValueError):
            # Skip categories with missing default payload files
            continue
    
    return result

def add_payload(category: str, payload: str, payload_file: str = "default.json") -> bool:
    """
    Add a new payload to a category.
    
    Args:
        category: The vulnerability category
        payload: The payload string to add
        payload_file: The payload file to update (default: 'default.json')
        
    Returns:
        True if the payload was added successfully, False otherwise
    """
    category_path = PAYLOADS_DIR / category
    
    if not category_path.exists():
        try:
            os.makedirs(category_path)
        except OSError:
            return False
    
    payload_path = category_path / payload_file
    
    try:
        if payload_path.exists() and payload_path.suffix == '.json':
            with open(payload_path, 'r') as f:
                payloads = json.load(f)
                
            if payload not in payloads:
                payloads.append(payload)
                
                with open(payload_path, 'w') as f:
                    json.dump(payloads, f, indent=2)
                    
                return True
            else:
                # Payload already exists
                return False
        elif payload_path.exists():
            # Text file
            with open(payload_path, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                
            if payload not in payloads:
                with open(payload_path, 'a') as f:
                    f.write(f"\n{payload}")
                    
                return True
            else:
                # Payload already exists
                return False
        else:
            # Create new file
            if payload_path.suffix == '.json':
                with open(payload_path, 'w') as f:
                    json.dump([payload], f, indent=2)
            else:
                with open(payload_path, 'w') as f:
                    f.write(f"{payload}\n")
                    
            return True
    except Exception:
        return False

def create_payload_category(category: str) -> bool:
    """
    Create a new payload category directory.
    
    Args:
        category: The name of the category to create
        
    Returns:
        True if the category was created successfully, False otherwise
    """
    category_path = PAYLOADS_DIR / category
    
    if category_path.exists():
        return False
    
    try:
        os.makedirs(category_path)
        return True
    except OSError:
        return False 