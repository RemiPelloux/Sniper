# TODO

This file tracks outstanding tasks for the Sniper project.

## Sprint 2 - Testing & Refinement

### High Priority
- [x] Increase test coverage for `src/cli/tools.py` (Initial tests added, but skipped due to Typer incompatibility)
- [ ] Investigate and resolve `typer.testing.CliRunner` incompatibility issue preventing `tests/cli/test_tools.py` from running.
- [ ] Implement `ToolManager.update_tool()` method.
- [ ] Implement `ToolManager.check_for_updates()` method.
- [ ] Add tests for `install_tool`, `update_tool`, `add_tool`, `remove_tool`, `categories`, `check_updates` commands in `tests/cli/test_tools.py` (once Typer issue resolved).
- [ ] Increase test coverage for other low-coverage areas (target >85% overall).
    - `src/cli/custom_tools.py`
    - `src/cli/distributed.py`
    - `src/cli/ml.py` (partially covered)
    - `src/distributed/client.py`
    - `src/distributed/manager.py`
    - `src/distributed/master.py`
    - `src/distributed/worker.py`
    - `src/ml/autonomous_tester.py`
    - `src/ml/risk_scoring.py`
    - `src/ml/tool_selection.py`
- [ ] Refactor `src/cli/main.py` to improve testability (related to skipped tests).

### Medium Priority
- [ ] Review and potentially update Typer version if it resolves testing issues.
- [ ] Refine error handling and logging in `ToolManager` installation/update methods.
- [ ] Improve documentation for `ToolManager` and CLI commands.

### Low Priority
- [ ] Address `DeprecationWarning` for `pkg_resources`.
- [ ] Configure `pytest-asyncio` loop scope explicitly.

## Backlog

- Feature: Add support for more package managers (e.g., yum/dnf, pacman).
- Feature: Implement automated tool update checks (e.g., daily/weekly).
- Refactor: Standardize output formatting across all CLI commands.
- Enhancement: Add richer progress indicators for long-running operations (install/update). 