"""
Mutation Engine for Payload Variation

This module provides a MutationEngine class that generates variations of security test payloads.
It supports multiple mutation strategies for different vulnerability types, allowing for more
comprehensive security testing by creating diverse attack payloads.
"""

import random
import string
import re
from typing import List, Dict, Optional, Callable, Union, Tuple
from enum import Enum, auto
import logging

logger = logging.getLogger(__name__)

class MutationStrategy(Enum):
    """Mutation strategies that can be applied to payloads."""
    CASE_VARIATION = auto()
    CHARACTER_SUBSTITUTION = auto()
    ENCODING_VARIATION = auto()
    PREFIX_SUFFIX_ADDITION = auto()
    WHITESPACE_MANIPULATION = auto()
    FRAGMENTATION = auto()
    COMMENT_INJECTION = auto()
    CONTEXT_ADAPTATION = auto()
    SYNTAX_VARIATION = auto()
    OBFUSCATION = auto()

class MutationEngine:
    """
    Engine to generate variations of security test payloads.
    Uses different mutation strategies to create payload variations
    optimized for different vulnerability types.
    """
    
    def __init__(self, complexity: int = 3):
        """
        Initialize the mutation engine.
        
        Args:
            complexity: Complexity level for mutations (1-5)
                1: Basic mutations only
                2: Add character substitutions
                3: Add encoding variations (default)
                4: Add fragmentation and comments
                5: Add advanced obfuscation
        """
        self.complexity = max(1, min(5, complexity))  # Ensure complexity is between 1-5
        
        # Define mutation strategies based on complexity
        self.available_strategies = self._get_strategies_for_complexity()
        
        # Register vulnerability-specific mutation functions
        self.vuln_type_mutators = {
            "xss": self._mutate_xss,
            "sql_injection": self._mutate_sql_injection,
            "command_injection": self._mutate_command_injection,
            "path_traversal": self._mutate_path_traversal,
            "open_redirect": self._mutate_open_redirect,
            "ssrf": self._mutate_ssrf,
            "xxe": self._mutate_xxe,
            "jwt_vulnerability": self._mutate_jwt,
            "nosql_injection": self._mutate_nosql,
        }
        
        # Initialize character substitution tables
        self.char_substitutions = {
            'a': ['a', '4', '@', 'á', 'à', 'â', '&#97;'],
            'e': ['e', '3', 'é', 'è', 'ê', '&#101;'],
            'i': ['i', '1', '!', 'í', 'ì', 'î', '&#105;'],
            'o': ['o', '0', 'ó', 'ò', 'ô', '&#111;'],
            'u': ['u', 'ú', 'ù', 'û', '&#117;'],
            's': ['s', '5', '$', '&#115;'],
            'l': ['l', '1', '|', '&#108;'],
            '<': ['<', '&lt;', '%3C', '&#60;'],
            '>': ['>', '&gt;', '%3E', '&#62;'],
            '"': ['"', '&quot;', '%22', '&#34;'],
            "'": ["'", '&#39;', '%27'],
            '/': ['/', '%2F', '&#47;'],
            '\\': ['\\', '%5C', '&#92;'],
            ' ': [' ', '%20', '+', '\t', '/**/']
        }
        
        # Comment patterns for different languages
        self.comments = {
            'sql': ['-- ', '/**/'],
            'html': ['<!--', '-->'],
            'javascript': ['//', '/*', '*/']
        }
        
        logger.info(f"Initialized MutationEngine with complexity level {self.complexity}")
    
    def _get_strategies_for_complexity(self) -> List[MutationStrategy]:
        """Get available mutation strategies based on complexity level."""
        # Base strategies available at all complexity levels
        strategies = [
            MutationStrategy.CASE_VARIATION,
            MutationStrategy.PREFIX_SUFFIX_ADDITION,
            MutationStrategy.WHITESPACE_MANIPULATION
        ]
        
        # Add strategies for complexity level 2+
        if self.complexity >= 2:
            strategies.append(MutationStrategy.CHARACTER_SUBSTITUTION)
        
        # Add strategies for complexity level 3+
        if self.complexity >= 3:
            strategies.append(MutationStrategy.ENCODING_VARIATION)
            strategies.append(MutationStrategy.CONTEXT_ADAPTATION)
        
        # Add strategies for complexity level 4+
        if self.complexity >= 4:
            strategies.append(MutationStrategy.FRAGMENTATION)
            strategies.append(MutationStrategy.COMMENT_INJECTION)
            strategies.append(MutationStrategy.SYNTAX_VARIATION)
        
        # Add strategies for complexity level 5
        if self.complexity >= 5:
            strategies.append(MutationStrategy.OBFUSCATION)
            
        return strategies
    
    def mutate(self, payload: str, vulnerability_type: str, context: Optional[str] = None,
               num_variations: int = 3) -> List[str]:
        """
        Generate variations of a payload.
        
        Args:
            payload: Original payload string
            vulnerability_type: Type of vulnerability (e.g., "xss", "sql_injection")
            context: Optional context information (e.g., "html", "attribute", "javascript")
            num_variations: Number of variations to generate
            
        Returns:
            List of mutated payload strings
        """
        # Normalize vulnerability type to lowercase
        vuln_type = vulnerability_type.lower()
        
        if vuln_type in self.vuln_type_mutators:
            # Use vulnerability-specific mutator if available
            variations = self.vuln_type_mutators[vuln_type](payload, context, num_variations)
        else:
            # Fall back to generic mutation
            variations = self._mutate_generic(payload, num_variations)
            
        # Ensure we have unique variations
        unique_variations = list(set(variations))
        
        # If we don't have enough variations, add some generic ones
        while len(unique_variations) < num_variations:
            generic_var = self._mutate_generic(payload, 1)[0]
            if generic_var not in unique_variations:
                unique_variations.append(generic_var)
                
        # Return the requested number of variations
        return unique_variations[:num_variations]
    
    def _mutate_generic(self, payload: str, num_variations: int) -> List[str]:
        """
        Apply generic mutations to a payload.
        
        Args:
            payload: Original payload string
            num_variations: Number of variations to generate
            
        Returns:
            List of mutated payload strings
        """
        variations = [payload]  # Start with the original
        
        # Generate more variations than requested to account for duplicates
        target_count = num_variations * 2
        
        for _ in range(target_count):
            # Choose a random strategy
            strategy = random.choice(self.available_strategies)
            
            # Apply the selected strategy
            if strategy == MutationStrategy.CASE_VARIATION:
                var = self._apply_case_variation(payload)
            elif strategy == MutationStrategy.CHARACTER_SUBSTITUTION:
                var = self._apply_character_substitution(payload)
            elif strategy == MutationStrategy.ENCODING_VARIATION:
                var = self._apply_encoding_variation(payload)
            elif strategy == MutationStrategy.PREFIX_SUFFIX_ADDITION:
                var = self._apply_prefix_suffix(payload)
            elif strategy == MutationStrategy.WHITESPACE_MANIPULATION:
                var = self._apply_whitespace_manipulation(payload)
            elif strategy == MutationStrategy.FRAGMENTATION:
                var = self._apply_fragmentation(payload)
            elif strategy == MutationStrategy.COMMENT_INJECTION:
                var = self._apply_comment_injection(payload)
            elif strategy == MutationStrategy.OBFUSCATION:
                var = self._apply_obfuscation(payload)
            else:
                # Default to original payload
                var = payload
                
            if var not in variations:
                variations.append(var)
                
            # If we have enough unique variations, stop
            if len(variations) >= num_variations + 1:  # +1 because we include the original
                break
                
        # Remove the original and return only the variations
        variations.remove(payload)
        
        # If we couldn't generate enough variations, duplicate some
        while len(variations) < num_variations:
            variations.append(random.choice(variations))
            
        return variations[:num_variations]

    # Specific mutation strategies
    def _apply_case_variation(self, payload: str) -> str:
        """Apply random case variations to the payload."""
        result = ""
        for char in payload:
            if char.isalpha() and random.random() > 0.5:
                result += char.swapcase()
            else:
                result += char
        return result
    
    def _apply_character_substitution(self, payload: str) -> str:
        """Replace characters with similar looking alternatives."""
        result = ""
        for char in payload:
            if char.lower() in self.char_substitutions and random.random() > 0.7:
                # Only substitute some characters to avoid making payload completely unrecognizable
                result += random.choice(self.char_substitutions[char.lower()])
            else:
                result += char
        return result
    
    def _apply_encoding_variation(self, payload: str) -> str:
        """Apply URL or HTML encoding to parts of the payload."""
        # Decide if we use URL encoding or HTML encoding
        if random.random() > 0.5:
            # URL encoding for some characters
            chars_to_encode = "<>'\"/\\&"
            result = ""
            for char in payload:
                if char in chars_to_encode and random.random() > 0.5:
                    result += f"%{ord(char):02X}"
                else:
                    result += char
            return result
        else:
            # HTML entity encoding for some characters
            chars_to_encode = "<>'\"/\\&"
            result = ""
            for char in payload:
                if char in chars_to_encode and random.random() > 0.5:
                    result += f"&#{ord(char)};"
                else:
                    result += char
            return result
    
    def _apply_prefix_suffix(self, payload: str) -> str:
        """Add random prefixes or suffixes to the payload."""
        prefixes = ["", " ", "\t", "\n", "+"]
        suffixes = ["", " ", "\t", "\n", "--", "#", "//"]
        
        return random.choice(prefixes) + payload + random.choice(suffixes)
    
    def _apply_whitespace_manipulation(self, payload: str) -> str:
        """Manipulate whitespace in the payload."""
        # Replace spaces with tabs, newlines, or multiple spaces
        whitespace_options = ["\t", "\n", "  ", " \t ", "\r\n"]
        
        result = payload
        if " " in payload:
            # Force a change by selecting a non-space option
            replacement = random.choice(whitespace_options)
            result = payload.replace(" ", replacement)
            
        # If no change was made (no spaces in payload), add some whitespace
        if result == payload:
            # Add a prefix or suffix whitespace
            prefix_suffix = random.choice(["\t", "\n", " ", "\r"])
            position = random.choice(["prefix", "suffix"])
            if position == "prefix":
                result = prefix_suffix + result
            else:
                result = result + prefix_suffix
                
        return result
    
    def _apply_fragmentation(self, payload: str) -> str:
        """Fragment the payload by inserting harmless characters."""
        # This is more complex and depends on the payload type
        # As a simple implementation, we'll just add zero-width spaces or null bytes
        if random.random() > 0.5:
            # Insert zero-width space at random positions
            result = ""
            for char in payload:
                result += char
                if random.random() > 0.8:
                    result += "\u200B"  # zero-width space
            return result
        else:
            # Insert null bytes at random positions (for code contexts)
            result = ""
            for char in payload:
                result += char
                if random.random() > 0.8:
                    result += "%00"
            return result
    
    def _apply_comment_injection(self, payload: str) -> str:
        """Inject comments into the payload."""
        # For simplicity, we'll only handle SQL and JavaScript comments
        sql_comment = "/**/"
        js_comment = "/**//"
        
        # Decide which type of comment to use
        comment = random.choice([sql_comment, js_comment])
        
        # Insert comment at a random position
        if len(payload) > 1:
            pos = random.randint(1, len(payload) - 1)
            return payload[:pos] + comment + payload[pos:]
        else:
            return payload
    
    def _apply_obfuscation(self, payload: str) -> str:
        """Apply advanced obfuscation techniques."""
        # This depends heavily on the payload context and type
        # As a simple implementation, we'll use a combination of techniques
        
        # First apply character substitution
        result = self._apply_character_substitution(payload)
        
        # Then apply case variation
        result = self._apply_case_variation(result)
        
        # Finally add some fragmentation
        result = self._apply_fragmentation(result)
        
        return result
    
    # Vulnerability-specific mutation functions
    def _mutate_xss(self, payload: str, context: Optional[str], num_variations: int) -> List[str]:
        """Generate XSS-specific mutations."""
        variations = []
        
        # Base case variations
        variations.append(self._apply_case_variation(payload))
        
        # XSS event handler variations
        if "onerror" in payload.lower():
            handlers = ["onerror", "onload", "onmouseover", "onclick", "onmouseout", "onfocus"]
            for handler in handlers:
                var = payload.lower().replace("onerror", handler)
                if var not in variations:
                    variations.append(var)
        
        # XSS alert variations
        if "alert(" in payload:
            alerts = ["alert(", "confirm(", "prompt(", "console.log(", "eval(", "new Function("]
            for alert in alerts:
                var = payload.replace("alert(", alert)
                if var not in variations:
                    variations.append(var)
                    
        # Script tag variations
        if "<script>" in payload:
            scripts = ["<script>", "<sCrIpT>", "<SCRIPT>", "<ScRiPt>", 
                      "<script >", "<script\t>", "<script\n>", 
                      "<%00script>", "<script%00>"]
            for script in scripts:
                var = payload.replace("<script>", script)
                if var not in variations:
                    variations.append(var)
        
        # Context-specific variations
        if context:
            if context.lower() == "html":
                if "<img" in payload:
                    var = payload.replace("<img", "<input type='image'")
                    variations.append(var)
            elif context.lower() == "attribute":
                if "javascript:" in payload:
                    var = payload.replace("javascript:", "&#106;avascript:")
                    variations.append(var)
            elif context.lower() == "javascript":
                if "\"" in payload:
                    var = payload.replace("\"", "'")
                    variations.append(var)
        
        # Add generic mutations if we need more variations
        while len(variations) < num_variations:
            var = self._mutate_generic(payload, 1)[0]
            if var not in variations:
                variations.append(var)
        
        return variations[:num_variations]
    
    def _mutate_sql_injection(self, payload: str, context: Optional[str], num_variations: int) -> List[str]:
        """Generate SQL injection-specific mutations."""
        variations = []
        
        # Add SQL comment variations
        if "--" not in payload and "#" not in payload:
            variations.append(payload + " --")
            variations.append(payload + "#")
            
        # Add whitespace variations
        variations.append(payload.replace(" ", "/**/"))
        
        # Replace single quotes with double quotes or vice versa
        if "'" in payload:
            variations.append(payload.replace("'", "\""))
        elif "\"" in payload:
            variations.append(payload.replace("\"", "'"))
        
        # Add case variations for SQL keywords
        for keyword in ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM", "AND", "OR"]:
            if keyword in payload:
                variations.append(payload.replace(keyword, keyword.lower()))
                variations.append(payload.replace(keyword, keyword.title()))
                variations.append(payload.replace(keyword, ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(keyword))))
        
        # Add more advanced obfuscation if complexity allows
        if self.complexity >= 4:
            if "OR" in payload:
                variations.append(payload.replace("OR", "||"))
            if "AND" in payload:
                variations.append(payload.replace("AND", "&&"))
                
        # Add encoding variations
        if self.complexity >= 3:
            if "'" in payload:
                variations.append(payload.replace("'", "%27"))
            if " " in payload:
                variations.append(payload.replace(" ", "%20"))
        
        # Add DBMS-specific variations if context is provided
        if context:
            if context.lower() == "mysql":
                # MySQL-specific variations
                pass
            elif context.lower() == "mssql":
                # MSSQL-specific variations
                pass
            
        # Add generic mutations if we need more variations
        while len(variations) < num_variations:
            var = self._mutate_generic(payload, 1)[0]
            if var not in variations:
                variations.append(var)
                
        return variations[:num_variations]
    
    # Stub implementation for other vulnerability types
    def _mutate_command_injection(self, payload: str, context: Optional[str], num_variations: int) -> List[str]:
        """Generate command injection-specific mutations."""
        variations = []
        
        # Command separator variations
        separators = [";", "|", "||", "&&", "&", "`"]
        if any(sep in payload for sep in separators):
            for sep in separators:
                if sep not in payload:
                    for existing_sep in separators:
                        if existing_sep in payload:
                            var = payload.replace(existing_sep, sep)
                            variations.append(var)
        
        # Add generic mutations if we need more variations
        while len(variations) < num_variations:
            var = self._mutate_generic(payload, 1)[0]
            if var not in variations:
                variations.append(var)
                
        return variations[:num_variations]
    
    def _mutate_path_traversal(self, payload: str, context: Optional[str], num_variations: int) -> List[str]:
        """Generate path traversal-specific mutations."""
        # Default implementation: just use generic mutations
        return self._mutate_generic(payload, num_variations)
    
    def _mutate_open_redirect(self, payload: str, context: Optional[str], num_variations: int) -> List[str]:
        """Generate open redirect-specific mutations."""
        # Default implementation: just use generic mutations
        return self._mutate_generic(payload, num_variations)
    
    def _mutate_ssrf(self, payload: str, context: Optional[str], num_variations: int) -> List[str]:
        """Generate SSRF-specific mutations."""
        # Default implementation: just use generic mutations
        return self._mutate_generic(payload, num_variations)
    
    def _mutate_xxe(self, payload: str, context: Optional[str], num_variations: int) -> List[str]:
        """Generate XXE-specific mutations."""
        # Default implementation: just use generic mutations
        return self._mutate_generic(payload, num_variations)
    
    def _mutate_jwt(self, payload: str, context: Optional[str], num_variations: int) -> List[str]:
        """Generate JWT-specific mutations."""
        # Default implementation: just use generic mutations
        return self._mutate_generic(payload, num_variations)
    
    def _mutate_nosql(self, payload: str, context: Optional[str], num_variations: int) -> List[str]:
        """Generate NoSQL injection-specific mutations."""
        # Default implementation: just use generic mutations
        return self._mutate_generic(payload, num_variations) 