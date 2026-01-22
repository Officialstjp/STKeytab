# Changelog

All notable changes to STKeytab will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-01-22

### Added
- **PSGallery Release Infrastructure**: Complete publishing workflow
  - `release.yml` workflow for manual PSGallery publishing with version input
  - Automatic help artifact (CAB) publishing to stable `help` release tag
- **CHANGELOG.md**: Standalone changelog following Keep a Changelog format
- **Update-Help Support**: Enabled `HelpInfoURI` with automatic CAB hosting on GitHub Releases

### Changed
- **README.md**: Complete rewrite with badges, ktpass comparison table, and conversational tone
- **Manifest**: Added Copyright, MIT/RFC8009 tags, enabled HelpInfoURI
- **PSScriptAnalyzer Settings**: Reorganized with documentation, added exclusions for CI helpers

### Fixed
- Unused variable references
- Empty catch block in `STKeytab.psm1` now logs with Write-Verbose

---

## [0.6.0] - 2025-09-01

### Added
- **AES-SHA2 Support**: RFC 8009 implementation for modern encryption types
  - AES128-CTS-HMAC-SHA256-128 (etype 19) and AES256-CTS-HMAC-SHA384-192 (etype 20)
  - Enhanced `New-KeytabFromPassword` with PBKDF2-HMAC-SHA256/SHA384 support
- **Crypto Infrastructure**: Generalized PBKDF2 implementation supporting multiple hash algorithms
  - Unified `Invoke-PBKDF2Hmac` function with pluggable HMAC algorithms
  - Extended `Derive-AesKeyWithPbkdf2` supporting etypes 17, 18, 19, 20

---

## [0.5.0] - 2025-08-28

### Added
- **Reset-AccountPasswordWithKeytab**: AD lifecycle management with atomic password reset and keytab generation
  - Mandatory risk acknowledgment and justification for audit trails
  - Dry-run capability with detailed operation planning (`-WhatIfOnly`)
  - Random password generation with cryptographic entropy
  - Rollback guidance on failure
- **Set-AccountSpn**: Transactional SPN management with conflict detection
  - Domain-wide SPN conflict detection before operations
  - Atomic add/remove operations with automatic rollback on failure
  - Detailed operation planning and impact assessment
- **Enhanced Security Integration**: Centralized security policy enforcement across all cmdlets
  - AES-only enforcement on password derivation paths with hard guardrails
  - Policy composition and validation for consistent security posture

---

## [0.4.0] - 2025-08-26

### Added
- **External Help System**: Complete PlatyPS integration with external help (MAML XML) generation
  - Cmdlet documentation in `docs/cmdlets/` with comprehensive examples and parameter descriptions
  - About topics in `docs/about/` covering Security, Determinism, Interop, KVNO, and DPAPI concepts
  - External help XML in `en-US/` for fast help loading (10x faster than comment-based help)
  - CI pipeline validates help drift and auto-updates documentation
- **Help Publishing Infrastructure**: `CI/Publish-Help.ps1` for future Update-Help support (CAB hosting)

### Changed
- **Refactored CI/CD**: Consolidated test, analyze, sign, and package operations into single wrapper

---

## [0.3.1] - 2025-08-17

### Added
- **Structured Function Design**: Begin-Process-End blocks and standardized comment-based help across all public functions
- **Enhanced Parameter Descriptions**: Help for all parameters with examples

---

## [0.3.0] - 2025-08-17

### Added
- **Compare-Keytab**: Canonical diff with timestamp-insensitive comparison and optional key-byte validation
- **ConvertTo-KeytabJson**: Export keytabs to canonical JSON (keys masked by default, `-RevealKeys` to include)
- **ConvertFrom-KeytabJson**: Import keytabs from JSON with deterministic output support
- **JSON Interoperability**: Stable sorting, timestamp controls, and secure key handling

---

## [0.2.0] - 2025-08-16

### Added
- **New-Keytab**: Front-door cmdlet with auto-detection of principal type (user/computer/krbtgt)
- **New-KeytabFromPassword**: Password-based keytab generation using AES S2K (PBKDF2-HMAC-SHA1)
- **Read-Keytab**: Robust keytab parser with keys masked by default, optional `-RevealKeys`
- **Test-Keytab**: Validation and unknown encryption type reporting
- **Merge-Keytab**: De-duplication across multiple keytabs with guardrails for high-risk operations
- **Protect-Keytab / Unprotect-Keytab**: DPAPI protection for at-rest keytabs (CurrentUser/LocalMachine)
- **Comprehensive Architecture**: Modular Private/ functions supporting orchestration, crypto, I/O

---

## [0.1.0] - 2025-08-10

### Added
- **Initial Implementation**: Core keytab generation and parsing functionality
- **MIT Keytab Format**: Support for keytab version 0x0502 with robust I/O
- **Active Directory Integration**: Basic user and computer account key extraction
- **Testing Foundation**: Initial Pester test suite covering core scenarios
