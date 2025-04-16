import pytest

# Absolute imports
from src.recon.subdomain_finder import find_subdomains
from src.recon.types import Subdomain

# --- Test Cases for find_subdomains (Placeholder) ---

def test_find_subdomains_placeholder():
    """Tests the placeholder implementation of find_subdomains."""
    domain = "example.com"
    expected_subs = ["www", "mail", "ftp", "dev", "staging", "api"]
    expected_results = [Subdomain(name=f"{sub}.{domain}") for sub in expected_subs]
    
    results = find_subdomains(domain)
    
    assert isinstance(results, list)
    # Check if all expected subdomains are present
    assert len(results) == len(expected_results)
    
    # Convert to sets for easier comparison regardless of order
    result_names = {r.name for r in results}
    expected_names = {e.name for e in expected_results}
    assert result_names == expected_names
    
    # Optionally, check specific items
    assert Subdomain(name="www.example.com") in results

def test_find_subdomains_different_domain():
    """Tests the placeholder with a different domain name."""
    domain = "test.org"
    expected_subs = ["www", "mail", "ftp", "dev", "staging", "api"]
    
    results = find_subdomains(domain)
    assert len(results) == len(expected_subs)
    assert Subdomain(name="api.test.org") in results
    assert Subdomain(name="www.test.org") in results 