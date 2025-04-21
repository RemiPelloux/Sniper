# Using the Payload Mutation Engine

The Sniper Security Platform includes a powerful Payload Mutation Engine that can generate variations of security testing payloads. This document explains how to use this feature to enhance your security testing by creating more diverse attack vectors.

## Overview

The mutation engine can transform payloads for various vulnerability types by applying different mutation strategies:

- Case variation (alternating uppercase and lowercase)
- Character substitution (replacing characters with similar-looking alternatives)
- Encoding variation (URL or HTML entity encoding)
- Whitespace manipulation
- Comment injection
- Syntax variations
- And more advanced obfuscation techniques

These mutations help evade simple WAF filters and increase the chances of finding vulnerabilities that may be missed with standard payloads.

## Mutation Complexity Levels

The engine supports five complexity levels:

1. **Basic** - Simple mutations like case variations and whitespace manipulation
2. **Standard** - Adds character substitutions
3. **Enhanced** - Adds encoding variations and context-aware mutations (default)
4. **Advanced** - Adds fragmentation, comment injection, and syntax variations
5. **Maximum** - Adds advanced obfuscation techniques

Higher complexity levels may generate more effective variations but might also create payloads that are less likely to work in all contexts.

## Using the Mutation Engine

### Basic Usage

The easiest way to use the mutation engine is through the payload module:

```python
from src.payloads import mutate_payloads

# Define some payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>"
]

# Generate mutations (2 variations per payload)
mutated_payloads = mutate_payloads(
    payloads=xss_payloads,
    vulnerability_type="xss",
    context="html",
    num_variations=2,
    complexity=3
)

# Use the mutated payloads
for payload in mutated_payloads:
    print(f"Testing payload: {payload}")
    # Your testing code here
```

### Advanced Usage with PayloadMutator

For more control, you can use the PayloadMutator class directly:

```python
from src.payloads.mutator import PayloadMutator

# Initialize the mutator with desired complexity
mutator = PayloadMutator(complexity=4)  # Advanced complexity

# Mutate a single payload
variations = mutator.mutate_payload(
    payload="' OR 1=1 --",
    vulnerability_type="sql_injection",
    context="mysql",
    num_variations=3
)

# Use with structured payload objects
payload_objects = [
    {
        'value': "<script>alert('XSS')</script>",
        'type': 'xss',
        'context': 'html',
        'description': 'Basic XSS payload'
    },
    {
        'value': "' OR 1=1 --",
        'type': 'sql_injection',
        'description': 'Basic SQLi authentication bypass'
    }
]

enhanced_payloads = mutator.enhance_payloads(
    payloads=payload_objects,
    num_variations=2
)

# Enhanced payloads include the originals plus variations
# Each variation includes metadata from the original
for payload in enhanced_payloads:
    print(f"Payload: {payload['value']}")
    print(f"Description: {payload['description']}")
    print(f"Type: {payload['type']}")
    if payload.get('is_mutation'):
        print("This is a mutation of an original payload")
    print("---")
```

### Direct Access to the Engine

For complete control, you can use the MutationEngine class:

```python
from src.payloads.mutation_engine import MutationEngine, MutationStrategy

engine = MutationEngine(complexity=5)  # Maximum complexity

# Apply specific mutation strategies
payload = "<script>alert('XSS')</script>"
case_variation = engine._apply_case_variation(payload)
encoded_variation = engine._apply_encoding_variation(payload)

# Get mutations for a specific payload
mutations = engine.mutate(
    payload=payload,
    vulnerability_type="xss",
    context="html",
    num_variations=5
)
```

## Command Line Interface

You can use the mutation engine from the command line:

```bash
# Generate mutations for testing
sniper payloads mutate --input "<script>alert('XSS')</script>" --type xss --context html --count 5

# Generate and directly test mutations against a target
sniper autonomous-test --target https://example.com --enable-mutations --mutation-complexity 4
```

## Supported Vulnerability Types

The mutation engine provides specialized mutations for:

- Cross-Site Scripting (XSS)
- SQL Injection
- Command Injection
- Path Traversal
- Open Redirect
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- JWT Vulnerabilities
- NoSQL Injection

For other vulnerability types, it falls back to generic mutation strategies.

## Best Practices

1. **Start with standard payloads** - Use the mutation engine to enhance your existing payload library rather than replacing it.

2. **Consider the context** - Always provide context information when available (e.g., "html", "attribute", "javascript" for XSS) to get more relevant mutations.

3. **Adjust complexity appropriately** - Higher isn't always better. For initial testing, use complexity level 3. Increase to 4-5 only when needed for evasion.

4. **Review mutations** - Especially at higher complexity levels, review generated mutations to ensure they're still valid for your testing scenario.

5. **Combine with AI testing** - The mutation engine works well with Sniper's autonomous testing capabilities, providing dynamic payload generation.

## Examples

### Testing for XSS with mutations

```python
from src.payloads import mutate_payloads
from src.integrations.vulnerability_scanner import VulnerabilityScanner

# Original XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>"
]

# Generate mutations with context awareness
html_context_payloads = mutate_payloads(
    xss_payloads, "xss", "html", num_variations=3, complexity=3
)

js_context_payloads = mutate_payloads(
    xss_payloads, "xss", "javascript", num_variations=3, complexity=3
)

# Use the scanner with mutated payloads
scanner = VulnerabilityScanner("https://example.com")
scanner.add_payloads("xss", html_context_payloads)
scanner.add_payloads("xss_js", js_context_payloads)
scanner.start()
```

### SQL Injection with Database-Specific Mutations

```python
from src.payloads.mutator import PayloadMutator

# Base SQLi payloads
sqli_payloads = [
    "' OR 1=1 --",
    "'; DROP TABLE users; --"
]

# Create mutations for different databases
mutator = PayloadMutator(complexity=4)

mysql_mutations = []
mssql_mutations = []

for payload in sqli_payloads:
    mysql_mutations.extend(
        mutator.mutate_payload(payload, "sql_injection", "mysql", 2)
    )
    mssql_mutations.extend(
        mutator.mutate_payload(payload, "sql_injection", "mssql", 2)
    )

print(f"Generated {len(mysql_mutations)} MySQL-specific mutations")
print(f"Generated {len(mssql_mutations)} MSSQL-specific mutations")
```

## Conclusion

The Payload Mutation Engine is a powerful tool for enhancing your security testing capabilities. By generating variations of payloads, you can increase the coverage of your security tests and potentially discover vulnerabilities that would be missed with standard payloads alone.

Remember that while mutations can help bypass simple filters and discover edge cases, they should complement, not replace, a solid understanding of the vulnerabilities you're testing for. 