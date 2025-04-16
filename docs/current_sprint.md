# Current Sprint

All tasks for Sprint 2 are complete. Ready for Sprint 3. 

# Sprint 3: Advanced Reconnaissance Module

## Goals
- Implement advanced reconnaissance techniques (DNS, Subdomain, WHOIS, SSL/TLS, Tech Stack).
- Implement initial active reconnaissance techniques (Port Scanning, Service ID).
- Define data models for storing reconnaissance findings.
- Add tests for all new reconnaissance modules.

## Tasks

### Recon Module Setup
- [X] Add reconnaissance dependencies (e.g., `dnspython`)
- [X] Create reconnaissance data models (`src/recon/types.py` - DNS parts)
- [ ] Create core reconnaissance runner/handler (potentially in `src/recon/core.py` or integrated into `src/core/scan_manager.py` later).

### Passive Reconnaissance
- [X] Implement DNS enumeration module (`src/recon/dns_enum.py` - A, AAAA, MX, NS, TXT).
- [X] Test DNS enumeration module (`tests/recon/test_dns_enum.py`).
- [X] Implement Subdomain discovery module (`src/recon/subdomain_finder.py` - Placeholder).
- [X] Test Subdomain discovery module (`tests/recon/test_subdomain_finder.py` - Placeholder).
- [X] Implement WHOIS information gathering (`src/recon/whois_info.py`).
- [X] Test WHOIS information gathering (`tests/recon/test_whois_info.py`).
- [X] Implement SSL/TLS certificate analysis (`src/recon/ssl_analyzer.py`).
- [X] Test SSL/TLS certificate analysis (`tests/recon/test_ssl_analyzer.py`).
- [X] Implement Technology stack fingerprinting (Basic HTTP headers/content analysis) (`src/recon/tech_fingerprint.py`).
- [X] Test Technology stack fingerprinting (`tests/recon/test_tech_fingerprint.py`).

### Active Reconnaissance (Initial)
- [X] Implement Port scanning module (`src/recon/port_scanner.py` using `python-nmap`).
- [X] Test Port scanning module (`tests/recon/test_port_scanner.py`).
- [X] Implement Service identification (using results from port scan) (`src/recon/service_detector.py`).
- [X] Test Service identification (`tests/recon/test_service_detector.py`).

### Integration & Documentation
- [X] Integrate reconnaissance modules into the main scan workflow (TBD - simple integration for now).
- [X] Update `roadmap.md` with Sprint 3 progress.
- [X] Review and refine Sprint 3 tasks. 