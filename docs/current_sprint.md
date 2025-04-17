# Sprint Planning

## Sprint 2 (Current) - Tool Integrations Focus

### Tasks
- [x] Design abstract base classes for tool integration
- [x] Create standardized finding models
- [x] Implement Nmap integration for port scanning
- [x] Create OWASP ZAP integration for web scanning
  - [x] Core implementation of ZAP integration class
  - [x] Support for passive and active scanning modes
  - [x] AJAX spider functionality
  - [x] Result parsing into WebFinding objects
  - [x] Comprehensive unit tests
  - [x] Documentation
  - [x] Configuration via settings
  - [x] Optional dependency management
- [x] Create Wappalyzer integration for technology detection
- [x] Implement Sublist3r integration for subdomain enumeration
- [x] Design a flexible result normalization system
  - [x] Fixed technology finding deduplication to preserve important attributes
  - [x] All tests now pass, coverage at 87%
- [x] Build CLI interface for scan orchestration
  - [x] Implemented scan command with various options for depth, modules, etc.
  - [x] Added support for different scan types (ports, web, subdomain, etc.)
  - [x] Integrated with the result normalization system
- [x] Create reporting module with basic templates
  - [x] Added support for multiple output formats (Markdown, HTML, JSON)
  - [x] Implemented different report templates (standard, executive, detailed)
  - [x] Created options for controlling report content and detail level

### Deferred from Sprint 1
- [ ] Implement basic ML model for vulnerability prediction
- [ ] Design configuration management system
- [ ] Add containerization support for tool isolation

### Notes
- Focusing on tool integrations this sprint
- Simplified finding models to focus on practical use
- Result normalization system will map tool outputs to standard models
- Each integration should include unit tests and documentation
- ZAP, Wappalyzer, and Sublist3r integrations completed.
- All Sprint 2 tasks have been completed successfully
- Some test coverage issues remain to be addressed in Sprint 3
- CLI interface has been implemented with all required functionality
- Reporting module provides foundation for comprehensive reporting

# Coverage Note: Overall test coverage currently at ~87% for core modules, but lower for CLI modules that will be improved in Sprint 3.

## Sprint 3 (Next) - Integration and Reporting Focus

### Planned Tasks
- [x] Design and implement result normalization system
- [x] Implement scan orchestration system
- [x] Design and implement reporting module
- [x] Add CLI commands for all major functions
- [ ] Improve test coverage to reach target of 85%
- [ ] Documentation improvements
- [ ] Basic ML feature implementation
