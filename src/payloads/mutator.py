"""
Payload Mutator Module

This module provides utilities for mutating security test payloads using the MutationEngine.
It serves as a high-level interface for other modules to request payload mutations.
"""

from typing import List, Dict, Optional, Union, Any
import logging
from .mutation_engine import MutationEngine

logger = logging.getLogger(__name__)

class PayloadMutator:
    """
    High-level interface for mutating security test payloads.
    Wraps the MutationEngine and provides convenience methods.
    """
    
    def __init__(self, complexity: int = 3):
        """
        Initialize a PayloadMutator with the specified complexity.
        
        Args:
            complexity: Mutation complexity level (1-5)
                1: Basic mutations only
                2: Add character substitutions
                3: Add encoding variations (default)
                4: Add fragmentation and comments
                5: Add advanced obfuscation
        """
        self.engine = MutationEngine(complexity=complexity)
        logger.debug(f"Initialized PayloadMutator with complexity {complexity}")
    
    def mutate_payload(self, payload: str, vulnerability_type: str, 
                      context: Optional[str] = None, num_variations: int = 3) -> List[str]:
        """
        Generate variations of a payload string.
        
        Args:
            payload: Original payload string
            vulnerability_type: Type of vulnerability (e.g., "xss", "sql_injection")
            context: Optional context information (e.g., "html", "attribute", "javascript")
            num_variations: Number of variations to generate
            
        Returns:
            List of mutated payload strings
        """
        logger.debug(f"Generating {num_variations} mutations for {vulnerability_type} payload: {payload}")
        return self.engine.mutate(payload, vulnerability_type, context, num_variations)
    
    def mutate_payloads(self, payloads: List[str], vulnerability_type: str,
                       context: Optional[str] = None, num_variations_per_payload: int = 2) -> List[str]:
        """
        Generate variations for a list of payloads.
        
        Args:
            payloads: List of original payload strings
            vulnerability_type: Type of vulnerability
            context: Optional context information
            num_variations_per_payload: Number of variations to generate per payload
            
        Returns:
            List containing original payloads and their variations
        """
        result = []
        
        # Add all original payloads
        result.extend(payloads)
        
        # Generate variations for each payload
        for payload in payloads:
            variations = self.mutate_payload(
                payload, 
                vulnerability_type, 
                context, 
                num_variations_per_payload
            )
            result.extend(variations)
        
        logger.debug(f"Generated {len(result) - len(payloads)} variations from {len(payloads)} payloads")
        return result
    
    def enhance_payloads(self, payloads: List[Dict[str, Any]], num_variations: int = 2) -> List[Dict[str, Any]]:
        """
        Generate variations of structured payload objects.
        
        Args:
            payloads: List of payload objects (dictionaries with at least 'value' and 'type' keys)
            num_variations: Number of variations to generate per payload
            
        Returns:
            List containing original payloads and their variations as dictionaries
        """
        result = []
        
        # Add all original payloads
        result.extend(payloads)
        
        # Generate variations for each payload
        for payload in payloads:
            if 'value' not in payload or 'type' not in payload:
                logger.warning(f"Skipping malformed payload: {payload}")
                continue
                
            context = payload.get('context')
            variations = self.mutate_payload(
                payload['value'], 
                payload['type'], 
                context, 
                num_variations
            )
            
            # Create new payload dictionaries for each variation
            for idx, var_value in enumerate(variations):
                # Create a copy of the original payload
                var_payload = payload.copy()
                # Update with the new value
                var_payload['value'] = var_value
                var_payload['description'] = f"Variation {idx+1} of: {payload.get('description', 'payload')}"
                var_payload['is_mutation'] = True
                
                result.append(var_payload)
        
        logger.debug(f"Enhanced payload set from {len(payloads)} to {len(result)} items")
        return result 