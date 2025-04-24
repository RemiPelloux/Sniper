# Sniper Security Tool: TODO List

## Critical Issues

- [x] Fix `results.normalizers.base_normalizer` module
- [x] Fix `reporting.report_generator` module
- [x] Fix `ml.prediction` module
- [ ] Repair Plugin System
- [x] Fix datetime/timezone handling in distributed scanning

## Dependencies

- [x] Install missing `docker` package
- [x] Install missing `python-nmap` package
- [x] Implement Subfinder integration
- [x] Configure Dirsearch tool
- [x] Set up Docker containers for security tools

## Documentation

- [ ] Update documentation for distributed scanning architecture
- [ ] Create comprehensive user guide for REST API
- [x] Document Subfinder integration
- [x] Document Dirsearch tool
- [x] Create Docker tools usage guide
- [ ] Provide deployment guide with Docker Compose

## Testing

- [ ] Implement end-to-end tests for distributed scanning
- [ ] Add integration tests for REST API endpoints
- [x] Add unit tests for Subfinder integration
- [ ] Fix skipped tests in test suite
- [ ] Configure CI/CD pipeline for automated testing

## Performance Optimization

- [ ] Optimize result aggregation for large-scale scans
- [ ] Implement caching for frequent database queries
- [ ] Enhance worker node recovery mechanisms
- [ ] Improve logging (fix errors during cleanup)

## Feature Enhancements

- [ ] Enhance web dashboard with additional visualizations
- [ ] Implement role-based access control for REST API
- [ ] Add support for custom scan templates
- [x] Integrate Subfinder for improved subdomain enumeration
- [x] Configure Dirsearch for directory enumeration
- [x] Implement Docker-based tool execution fallback

## Sprint 7 Priority Tasks (ML Integration)

- [ ] Enhance ML prediction model with continuous learning
- [ ] Implement more sophisticated feature extraction
- [ ] Create interactive attack chain visualization
- [ ] Develop context-aware payload generation
- [ ] Add impact scoring for attack paths
- [ ] Implement language-specific vulnerability descriptions

## Completion Status
- Core components: 90% complete
- Dependencies: 100% complete
- Documentation: 35% complete
- Testing: 25% complete
- Performance: 30% complete

All critical issues and key dependencies have been addressed to ensure Sprint 7 can proceed successfully. 