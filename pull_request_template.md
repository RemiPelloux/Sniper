# DVWA Scan Functionality

## Description

This PR adds specialized scanning capabilities for the Damn Vulnerable Web Application (DVWA), improving Sniper's ability to effectively test and detect vulnerabilities in DVWA instances. It includes both a dedicated scan command and a scan mode configuration.

## Features Added

- Added a dedicated DVWA scan command (`sniper scan dvwa`) with DVWA-specific options
- Created a new DVWA scan mode in `scan_modes.yaml` for use with the generic scan command
- Added support for detecting file inclusion vulnerabilities, common in DVWA
- Implemented automatic DVWA login functionality with default credentials
- Added security level control for DVWA scanning
- Updated documentation to include DVWA scanning capabilities
- Created tests for the DVWA scan functionality (need refinement)

## Bug Fixes

- Fixed an issue with the `evidence` field in the `WebFinding` class
- Fixed scan mode handling to properly use ScanDepth enum
- Fixed module selection when using scan modes

## How Has This Been Tested?

- Manual testing with Docker-based DVWA instance
- Created automated tests (currently failing and require refinement)

## Checklist:

- [x] My code follows the style guidelines of this project
- [x] I have performed a self-review of my own code
- [x] I have commented my code, particularly in hard-to-understand areas
- [x] I have made corresponding changes to the documentation
- [x] My changes generate no new warnings
- [x] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [x] Any dependent changes have been merged and published in downstream modules

## Future Work

- Fix and improve test suite for DVWA scanning
- Add more DVWA-specific payloads
- Improve session handling for authenticated scanning
- Better correlation of findings with DVWA's known vulnerabilities 