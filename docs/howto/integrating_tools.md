# How to Integrate Security Tools

This document explains how to integrate new security tools into the Sniper framework.

## Tool Integration Architecture

Sniper uses an abstract base class (`ToolBase`) system for integrating external security tools. Each tool requires a dedicated integration class that inherits from `ToolBase` and implements its required methods.

## Key Components

- **Integration Class**: A Python class specific to the tool (e.g., `NmapIntegration`). It handles:
    - Running the tool's command-line interface.
    - Parsing the tool's output.
    - Mapping the output to Sniper's standardized `Finding` data model.
- **Configuration**: Tool-specific configurations (e.g., paths, API keys) are managed via Sniper's configuration system.
- **Parser**: A dedicated function or class to parse the specific output format of the tool (e.g., XML, JSON, plain text).
- **Data Model**: Tool results must be converted into Sniper's `Finding` objects, which represent detected vulnerabilities or issues.

## Steps for Integration

1.  **Create the Integration Class**: Create a new Python file in `src/integrations/tools/` (e.g., `src/integrations/tools/my_tool.py`). Define a class inheriting from `src.integrations.base.ToolBase`.
2.  **Implement `run` Method**: Implement the `_run` method to execute the tool's command with appropriate arguments based on the target and configuration.
3.  **Implement `_parse_output` Method**: Implement the `_parse_output` method to process the raw output from the tool.
4.  **Map to `Finding` Model**: Convert the parsed results into a list of `Finding` objects defined in `src.results.models`.
5.  **Register the Tool**: Add the new integration class to the tool registry in `src/integrations/__init__.py`.
6.  **Add Configuration**: Define necessary configuration options in `config/default.yml`.
7.  **Write Tests**: Add unit and integration tests for the new tool integration in the `tests/integrations/` directory.

## Example (Conceptual)

```python
# src/integrations/tools/my_tool.py
from src.integrations.base import ToolBase
from src.results.models import Finding

class MyToolIntegration(ToolBase):
    name = "my_tool"

    def _run(self, target: str) -> str:
        # Code to run 'my_tool <target>' and return raw output
        command = f"my_tool {target}"
        # ... execute command ...
        return raw_output

    def _parse_output(self, raw_output: str) -> list[Finding]:
        findings = []
        # Code to parse raw_output
        # for issue in parsed_issues:
        #     finding = Finding(
        #         title=issue['name'],
        #         description=issue['details'],
        #         severity=issue['severity'],
        #         # ... other fields ...
        #     )
        #     findings.append(finding)
        return findings
```

Refer to existing tool integrations (e.g., `NmapIntegration`, `SSLyzeIntegration`) for concrete examples. 