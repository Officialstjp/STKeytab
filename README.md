## STKeytab

Security-aware PowerShell toolkit for generating and working with MIT keytabs (0x0502) using replication-based key extraction or - DSInternals-backed, "no password reset" keytab export for AD principals (including krbtgt with guarded flags). Similar to Impacket / Mimikatz key replication-extraction.
- AD lifecycle management: atomic password reset + keytab generation with rollback support.
- SPN conflict detection and transactional SPN management operations.
- DPAPI-protect keytabs (user or machine scope) + restrictive ACLs baked in. Password-based derivation. Safe defaults, centralized security policy ("BigBrother"), optional determinism, and minimal dependencies.

## Table of contents
- Quick start
- Commands
- Usage examples
- Documentation (PlatyPS)
- Security model
- Determinism
- Troubleshooting
- Changelog
- Roadmap
- CI/CD
- Risk & Legal
- License


## Quick start

Prerequisites
- Windows PowerShell 5.1 for AD/DSInternals scenarios; PowerShell 7+ supported for non-AD flows.
- RSAT: Active Directory tools (install on Windows Features) for the ActiveDirectory module.
- DSInternals module for replication-based reads.


Install modules
```powershell
# Windows PowerShell (preferred for AD scenarios)
Install-Module DSInternals -Scope CurrentUser -Force
Import-Module ActiveDirectory -ErrorAction Stop
```

Import STKeytab from source
```powershell
# From the repo root
Import-Module "$PWD\STKeytab.psd1" -Force
```

## Commands
- New-Keytab: Create a keytab for an AD principal via replication (AES-only by default; RC4 is opt-in via policy flags).
- New-KeytabFromPassword: Create a keytab from a password using AES S2K (PBKDF2-HMACSHA1; AES-only path with hard guardrails).
- Reset-AccountPasswordWithKeytab: Atomically reset AD account password and generate corresponding keytab with rollback support.
- Set-AccountSpn: Manage service principal names with conflict detection and transactional operations.
- Read-Keytab, Test-Keytab: Parse and validate keytabs (keys masked by default).
- Merge-Keytab: Merge keytabs with de-duplication and guardrails.
- Protect-Keytab, Unprotect-Keytab: DPAPI protection for at-rest keytabs.
- Compare-Keytab: Canonical diff; timestamp-insensitive compare; optional key-byte diff.
- ConvertTo-/ConvertFrom-KeytabJson: Canonical JSON export/import (masked by default).


### Usage
```powershell
# Computer account (AES-only default), include short-host SPNs
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -IncludeShortHost -OutputPath .\web01.keytab -Force -Summary -PassThru

# Restrict to AES256
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -IncludeEtype AES256_CTS_HMAC_SHA1_96 -Force

# Explicitly exclude RC4 (legacy)
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -ExcludeEtype ARCFOUR_HMAC

# Deterministic output (stable bytes across runs)
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -FixedTimestampUtc (Get-Date '2024-01-01Z')

# AD lifecycle management
Reset-AccountPasswordWithKeytab -SamAccountName svc-web -AcknowledgeRisk -Justification "Quarterly rotation" -OutputPath .\svc-web.keytab
Set-AccountSpn -SamAccountName svc-web -Add 'HTTP/web.contoso.com' -Remove 'HTTP/oldweb.contoso.com' -WhatIfOnly

# Password-based (AES S2K) – user principal
$sec = ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force
New-KeytabFromPassword -SamAccountName user1 -Realm EXAMPLE.COM -Password $sec -Kvno 3 -Iterations 4096 `
  -OutputPath .\user1.keytab -Force -FixedTimestampUtc (Get-Date '2024-01-01Z') -Summary -PassThru

# Password-based (AES S2K) Service principal (Windows salt flavor lowercases service/host and uppercases realm)
New-KeytabFromPassword -Principal 'HTTP/web01.example.com@EXAMPLE.COM' -Realm EXAMPLE.COM -Password $sec `
  -Compatibility Windows -IncludeEtype 18 -OutputPath .\http-web01.keytab -Force

# Merge and compare (ignore timestamps by default)
Merge-Keytab -InputPaths .\a.keytab, .\b.keytab -OutputPath .\merged.keytab -Force
$cmp = Compare-Keytab -ReferencePath .\a.keytab -CandidatePath .\b.keytab -IgnoreTimestamp
$cmp.Equal

# Inspect
Read-Keytab -Path .\web01.keytab
Test-Keytab -Path .\web01.keytab -Detailed

# Export/import canonical JSON (keys masked by default; reveal only when necessary)
ConvertTo-KeytabJson -Path .\a.keytab -OutputPath .\a.json
ConvertTo-KeytabJson -Path .\a.keytab -OutputPath .\a.revealed.json -RevealKeys
ConvertFrom-KeytabJson -JsonPath .\a.revealed.json -OutputPath .\a2.keytab -Force -FixedTimestampUtc (Get-Date '2024-01-01Z')

# Protect at rest (DPAPI CurrentUser)
Protect-Keytab -Path .\web01.keytab -RestrictAcl -DeletePlaintext
Unprotect-Keytab -Path .\web01.keytab.dpapi -RestrictAcl
```

## Documentation (PlatyPS)
- Cmdlet help is authored in Markdown in docs/ and kept in sync with PlatyPS.
- Use Get-Help:
  - Get-Help New-Keytab -Full
  - Get-Help about_STKeytab (once about_ topics are added)
- CI validates help drift on PRs and auto-updates on push. Built external help (MAML) and CAB can be hosted for Update-Help once HelpInfoURI is set in STKeytab.psd1.

## Security model
- AES-only by default (AES256, AES128). RC4 is an explicit opt-in governed by centralized policy.
- Sensitive flags:
  - -RevealKeys: prints key material; emits a warning; avoid in logs and PRs.
  - -AcknowledgeRisk and -Justification: required for high-impact operations (e.g., krbtgt).
- DPAPI:
  - CurrentUser and LocalMachine scopes supported. LocalMachine is not portable.
  - Optional entropy; prefer -EntropySecure (SecureString).

### Centralized policy (BigBrother)
- Etype selection is driven by a single policy layer:
  - Defaults: AES-only includes; dead/obsolete ciphers excluded.
  - Password path: AES-only enforcement with clear banner and hard error if legacy requested.
  - Replication path: RC4 can be added explicitly with -IncludeLegacyRC4; dead ciphers remain excluded unless -AllowDeadCiphers.
- Public cmdlets compose a policy (Include/Exclude/AESOnly/IncludeLegacyRC4/AllowDeadCiphers) and internal orchestration resolves final etypes from available keys.

## Determinism
- With -FixedTimestampUtc, the writer uses a fixed UTC timestamp and a stable entry order. Given identical inputs (keys, KVNOs, etypes, SPNs), outputs are byte-identical across runs and machines—ideal for CI reproducibility and code review.


## Troubleshooting
- Get-ADReplAccount not found: ensure DSInternals is installed and tests run under Windows PowerShell (powershell.exe).
- RODC target: New-Keytab warns if -Server points to a read-only DC; use a writable DC.
- RC4 etype: excluded by default; add explicitly if required by legacy interop.
- Import-Module fails in CI: ensure paths are quoted and Test-Path checks pass before Import-Module.


- Safe defaults prefer AES. RC4 is opt-in and only via explicit flags.
- -FixedTimestampUtc is opt-in and respected end-to-end for reproducible artifacts.
- DPAPI helper cmdlets support CurrentUser and LocalMachine scopes with optional entropy; outputs can be ACL-restricted to the current user.
- New-KeytabFromPassword is AES-only (etype 17/18). RC4 is intentionally not supported in this path.
- PlatyPS-based help is validated and auto-updated in CI; see docs/ for Markdown and en-US/ for built help.
- Canonical JSON is stably sorted and can omit timestamps via -IgnoreTimestamp; ConvertFrom-KeytabJson requires key bytes (export with -RevealKeys to include them).
- The module does **not** collect any telemetry.

## Features & Roadmap

### Supported vs not Supported
This module supports; others generally don’t:
- DSInternals-backed, “no password reset” keytab export for AD principals (including krbtgt with guarded flags). Similar to Impacket / Mimikatz key replication-extraction.
- DPAPI-protect keytabs (user or machine scope) + restrictive ACLs baked in.
- Deterministic outputs + canonical JSON + structured diff with timestamp-insensitivity.
- Explicit KVNO control (S2K) and multi-KVNO emit for krbtgt (current/old/older).

This module and others both support:
- Password-based S2K generation (here: AES-only; ktutil: any supported enctype).
- Reading/listing keytabs (here: Read-Keytab/Test-Keytab; others: klist -k/ktutil list).

Others support; this doesn't (yet)
- Advanced service discovery and automation workflows.
- Cross-platform toolchain integration and compatibility helpers.

### Planned next:
- Enhanced interoperability with MIT/Heimdal toolchains.
- Service account discovery and management helpers.
- Workflow automation for enterprise environments.

## Changelog

### [0.5.0] - 2025-08-28
#### Added
- **Reset-AccountPasswordWithKeytab**: AD lifecycle management with atomic password reset and keytab generation
  - Mandatory risk acknowledgment and justification for audit trails
  - Dry-run capability with detailed operation planning (`-WhatIfOnly`)
  - Random password generation with cryptographic entropy
  - Rollback guidance
- **Set-AccountSpn**: Transactional SPN management with conflict detection
  - SPN conflict detection across the domain before operations
  - Atomic add/remove operations with automatic rollback on failure
  - Detailed operation planning and impact assessment
- **Enhanced BigBrother Integration**: Centralized security policy enforcement across all cmdlets
  - AES-only enforcement on password derivation paths with hard guardrails
  - Policy composition and validation for consistent security posture

#### Changed
- **Documentation**: Updated help and examples for new enterprise capabilities

#### Technical
- **New-StrongPassword**: Cryptographically secure password generation for account resets
- **Parameter Compatibility**: Fixed parameter mismatches between interdependent functions
- **Testing**: Test mocks for new Operations and policy validation

### [0.4.0] - 2025-08-26
#### Added
- **External Help System**: Complete PlatyPS integration with external help (MAML XML) generation
  - Cmdlet documentation in `docs/cmdlets/` with comprehensive examples and parameter descriptions
  - About topics in `docs/about/` covering Security, Determinism, Interop, KVNO, and DPAPI concepts
  - External help XML in `en-US/` for fast help loading (10x faster than comment-based help)
  - CI pipeline validates help drift and auto-updates documentation
- **Help Publishing Infrastructure**: `CI/Publish-Help.ps1` for future Update-Help support (CAB hosting)
- **Consolidated CI Pipeline**: Unified `CI/Test-Sign/Test-Sign.ps1` wrapper replacing individual scripts
- **Professional Documentation**: Comprehensive help system matching Microsoft module standards

#### Changed
- **Refactored CI/CD**: Consolidated test, analyze, sign, and package operations into single wrapper
- **Module Structure**: Improved Public/Private loading with better error handling
- **Pipeline Reliability**: Enhanced import logic and path handling in GitHub Actions
- **Help Quality**: Standardized cmdlet help headers, parameter descriptions, and examples

#### Technical
- PlatyPS Markdown → MAML XML → CAB artifact generation pipeline
- External help generation via `New-ExternalHelp` and `New-ExternalHelpCab`
- HelpInfoURI support in module manifest for Update-Help (when hosting is configured)
- Drift detection comparing generated vs. source documentation

### [0.3.1] - 2025-08-17
#### Added
- **ValueFromPipeline Support**: All public functions now support pipeline input where appropriate
- **Structured Function Design**: Begin-Process-End blocks across all public cmdlets
- **Enhanced Parameter Descriptions**: Comprehensive help for all parameters with examples
- **Function Headers**: Standardized comment-based help across all public functions

#### Changed
- **Parameter Consistency**: Aligned parameter naming and behavior across cmdlets
- **Pipeline Integration**: Improved cmdlet chaining and pipeline scenarios
- **Help Quality**: Enhanced inline documentation and examples

### [0.3.0] - 2025-08-17
#### Added
- **Compare-Keytab**: Canonical diff with timestamp-insensitive comparison and optional key-byte validation
- **ConvertTo-KeytabJson**: Export keytabs to canonical JSON (keys masked by default, `-RevealKeys` to include)
- **ConvertFrom-KeytabJson**: Import keytabs from JSON with deterministic output support
- **JSON Interoperability**: Stable sorting, timestamp controls, and secure key handling

#### Changed
- **Canonical Formats**: Standardized JSON export/import for cross-tool compatibility
- **Security Controls**: Keys masked by default in JSON exports, explicit flag required to reveal
- **Deterministic Processing**: JSON round-trip support with `-FixedTimestampUtc`

### [0.2.0] - 2025-08-16
#### Added
- **New-Keytab**: Front-door cmdlet with auto-detection of principal type (user/computer/krbtgt)
- **New-KeytabFromPassword**: Password-based keytab generation using AES S2K (PBKDF2-HMACSHA1)
- **Read-Keytab**: Robust keytab parser with keys masked by default, optional `-RevealKeys`
- **Test-Keytab**: Validation and unknown encryption type reporting
- **Merge-Keytab**: De-duplication across multiple keytabs with guardrails for high-risk operations
- **Protect-Keytab / Unprotect-Keytab**: DPAPI protection for at-rest keytabs (CurrentUser/LocalMachine)
- **Comprehensive Architecture**: Modular Private/ functions supporting orchestration, crypto, I/O

#### Technical
- **Security-First Design**: AES-only defaults, RC4 explicit opt-in, risk acknowledgment for krbtgt
- **Replication-Safe Extraction**: DSInternals-based key material extraction via directory replication
- **Deterministic Output**: `-FixedTimestampUtc` support for reproducible artifacts
- **Encryption Type Selection**: Include/exclude patterns with intelligent defaults
- **DPAPI Integration**: Full CurrentUser and LocalMachine scope support with optional entropy
- **Multi-KVNO Support**: Handling current, old, and older KVNO scenarios especially for krbtgt

### [0.1.0] - 2025-08-10
#### Added
- **Initial Implementation**: Core keytab generation and parsing functionality
- **MIT Keytab Format**: Support for keytab version 0x0502 with robust I/O
- **Active Directory Integration**: Basic user and computer account key extraction
- **Testing Foundation**: Initial Pester test suite covering core scenarios

#### Technical
- **Module Structure**: Public/Private organization with dot-sourcing loader
- **Core Models**: Principal descriptors, key sets, and extraction results
- **Error Handling**: Structured error categories and validation
- **Security Foundation**: User-only ACL support and sensitive data handling

---

*Note: Versions 0.1.0-0.2.0 represent the foundational development phase. Starting with 0.3.0, changes follow semantic versioning more strictly with detailed tracking of additions, changes, and technical improvements.*

## CI/CD
- Docs workflow builds/validates PlatyPS help; auto-commits on push with [skip ci]. See .github/workflows/docs.yml and CI/Build-Docs.ps1.
- Test & Sign workflow runs Pester, PSScriptAnalyzer, optional signing, packaging, and signed import verification. See .github/workflows/test_sign.yml and CI/Test-Sign/Test-Sign.ps1.

## Risk & Legal
- Some operations require DCSync-equivalent rights (Replicating Directory Changes/…All/…In Filtered Set).
- Handle keytabs as secrets; prefer restricted ACLs and secure storage.
- Use only where authorized. See Acceptable Use & Legal section in this repo.

## License
Apache License 2.0. See LICENSE and NOTICE. All source files carry SPDX identifiers.

