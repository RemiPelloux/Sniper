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
- [~] Create Wappalyzer integration for technology detection (In Progress)
- [ ] Implement Sublist3r integration for subdomain enumeration
- [ ] Design a flexible result normalization system
- [ ] Build CLI interface for scan orchestration
- [ ] Create reporting module with basic templates

### Deferred from Sprint 1
- [ ] Implement basic ML model for vulnerability prediction
- [ ] Design configuration management system
- [ ] Add containerization support for tool isolation

### Notes
- Focusing on tool integrations this sprint
- Simplified finding models to focus on practical use
- Result normalization system will map tool outputs to standard models
- Each integration should include unit tests and documentation
- The ZAP integration has been completed with all necessary features

## Sprint 3 (Next) - Integration and Reporting Focus

### Planned Tasks
- [ ] Complete remaining tool integrations (Wappalyzer, Sublist3r)
- [ ] Implement scan orchestration system
- [ ] Design and implement reporting module
- [ ] Add CLI commands for all major functions
- [ ] Improve test coverage to reach target of 85%
- [ ] Documentation improvements
- [ ] Basic ML feature implementation
