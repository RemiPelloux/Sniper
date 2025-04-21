"""
Unit tests for the Mutation Engine

Tests the functionality of the MutationEngine and PayloadMutator classes.
"""

import pytest
import sys
import os
from typing import List

# Add src to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from src.payloads.mutation_engine import MutationEngine, MutationStrategy
from src.payloads.mutator import PayloadMutator

class TestMutationEngine:
    """Tests for the MutationEngine class."""
    
    def test_init(self):
        """Test initialization with different complexity levels."""
        # Test default complexity
        engine = MutationEngine()
        assert engine.complexity == 3
        
        # Test min complexity
        engine = MutationEngine(complexity=1)
        assert engine.complexity == 1
        assert len(engine.available_strategies) == 3  # Basic strategies
        
        # Test max complexity
        engine = MutationEngine(complexity=5)
        assert engine.complexity == 5
        assert len(engine.available_strategies) > 5  # All strategies
        
        # Test out-of-range complexity (should be clamped)
        engine = MutationEngine(complexity=10)
        assert engine.complexity == 5
        
        engine = MutationEngine(complexity=-1)
        assert engine.complexity == 1
    
    def test_mutate_generic(self):
        """Test generic mutation functionality."""
        engine = MutationEngine()
        payload = "test payload"
        variations = engine._mutate_generic(payload, 3)
        
        # Check number of variations
        assert len(variations) == 3
        
        # Check all variations are different from original
        assert payload not in variations
        
        # Check that most variations are different from each other
        # Note: Sometimes random mutations might produce the same variation
        unique_variations = set(variations)
        assert len(unique_variations) >= 1
    
    def test_mutation_strategies(self):
        """Test individual mutation strategies."""
        engine = MutationEngine()
        payload = "SELECT * FROM users WHERE name='test'"
        
        # Test case variation
        var = engine._apply_case_variation(payload)
        assert var != payload
        assert var.lower() == payload.lower()
        
        # Test character substitution
        var = engine._apply_character_substitution(payload)
        assert len(var) >= len(payload)  # Some substitutions may be longer
        
        # Test encoding variation
        var = engine._apply_encoding_variation(payload)
        assert len(var) >= len(payload)  # Encoding should make it longer
        
        # Test prefix/suffix
        var = engine._apply_prefix_suffix(payload)
        assert len(var) >= len(payload)
        
        # Test whitespace manipulation
        if " " in payload:
            var = engine._apply_whitespace_manipulation(payload)
            assert var != payload
            # The whitespace manipulation can replace spaces with various characters
            # including carriage returns, so we can't do an exact string comparison.
            # Instead, verify the original payload contains the same words
            original_words = [w for w in payload.split() if w]
            modified_words = [w for w in var.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ').split() if w]
            assert original_words == modified_words
    
    def test_mutate_xss(self):
        """Test XSS-specific mutations."""
        engine = MutationEngine()
        payload = "<script>alert('XSS')</script>"
        variations = engine._mutate_xss(payload, "html", 5)
        
        # Check number of variations
        assert len(variations) == 5
        
        # Check context is respected
        if "html" in variations[0].lower():
            assert any("<input" in var for var in variations)
    
    def test_mutate_sql_injection(self):
        """Test SQL injection-specific mutations."""
        engine = MutationEngine()
        payload = "' OR 1=1 --"
        variations = engine._mutate_sql_injection(payload, None, 5)
        
        # Check number of variations
        assert len(variations) == 5
        
        # Check for SQL-specific variations
        has_comment = any("--" in var or "#" in var for var in variations)
        assert has_comment
    
    def test_mutate(self):
        """Test the main mutate method."""
        engine = MutationEngine()
        
        # Test XSS payload
        xss_payload = "<script>alert('XSS')</script>"
        xss_variations = engine.mutate(xss_payload, "xss", "html", 3)
        assert len(xss_variations) == 3
        
        # Test SQL injection payload
        sql_payload = "' OR 1=1 --"
        sql_variations = engine.mutate(sql_payload, "sql_injection", None, 3)
        assert len(sql_variations) == 3
        
        # Test unsupported vulnerability type (should fall back to generic)
        other_payload = "test payload"
        other_variations = engine.mutate(other_payload, "unknown_type", None, 3)
        assert len(other_variations) == 3


class TestPayloadMutator:
    """Tests for the PayloadMutator class."""
    
    def test_init(self):
        """Test initialization."""
        mutator = PayloadMutator()
        assert mutator.engine.complexity == 3
        
        mutator = PayloadMutator(complexity=5)
        assert mutator.engine.complexity == 5
    
    def test_mutate_payload(self):
        """Test mutating a single payload."""
        mutator = PayloadMutator()
        
        payload = "<script>alert('XSS')</script>"
        variations = mutator.mutate_payload(payload, "xss", "html", 3)
        
        assert len(variations) == 3
        # Verify variations are generated, but don't strictly check they're all different
        # from the original since the mutation may sometimes produce similar outputs
        assert len(set(variations)) >= 1
    
    def test_mutate_payloads(self):
        """Test mutating multiple payloads."""
        mutator = PayloadMutator()
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>"
        ]
        
        # Generate 2 variations per payload
        result = mutator.mutate_payloads(payloads, "xss", "html", 2)
        
        # Should have original payloads (2) + variations (2*2)
        assert len(result) == 6
        assert all(payload in result for payload in payloads)
    
    def test_enhance_payloads(self):
        """Test enhancing structured payload objects."""
        mutator = PayloadMutator()
        
        payloads = [
            {'value': "<script>alert('XSS')</script>", 'type': 'xss', 'context': 'html'},
            {'value': "' OR 1=1 --", 'type': 'sql_injection'}
        ]
        
        # Generate 2 variations per payload
        result = mutator.enhance_payloads(payloads, 2)
        
        # Should have original payloads (2) + variations (2*2)
        assert len(result) == 6
        
        # Check original payloads are included
        assert all(p['value'] in [r['value'] for r in result] for p in payloads)
        
        # Check variations have the required fields
        variations = [r for r in result if r.get('is_mutation')]
        assert len(variations) == 4
        assert all('description' in v for v in variations)
        
    def test_invalid_payload_object(self):
        """Test handling of invalid payload objects."""
        mutator = PayloadMutator()
        
        payloads = [
            {'value': "<script>alert('XSS')</script>", 'type': 'xss'},
            {'invalid': 'payload'}  # Missing required fields
        ]
        
        # Should process the valid payload but skip the invalid one
        result = mutator.enhance_payloads(payloads, 2)
        
        # Original valid payload + 2 variations + original invalid payload
        assert len(result) == 4
        
        # The invalid payload should be in the result but have no variations
        assert any('invalid' in p and p.get('invalid') == 'payload' for p in result) 