## STKeytab

STKeytab is a security-focused PowerShell module that creates and manages MIT Kerberos keytab files (format 0x0502). The module supports two primary workflows:

1. Replication-based extraction: Extract Kerberos keys from Active Directory using DCSync-equivalent permissions via the DSInternals module
2. Password-based derivation: Generate keytabs from passwords using AES string-to-key (PBKDF2-HMACSHA1) with MIT/Heimdal/Windows salt policies

Key Features
- Safe defaults: AES-only encryption (AES256, AES128) by default; RC4 requires explicit opt-in
- Deterministic output: Optional fixed timestamps for byte-identical results across runs
- Security guardrails: Risk acknowledgment required for sensitive operations (krbtgt, merges)
- DPAPI protection: Encrypt keytabs at rest with Windows Data Protection API
- Canonical comparison: Compare keytabs with timestamp-insensitive and key-byte options
- JSON interop: Export/import canonical JSON format for debugging and scripting

Principal Types Supported
- User accounts: Standard domain users with UPN-based principals
- Computer accounts: Machine accounts with HOST/ and service SPNs
- krbtgt accounts: Domain controller service accounts (high-impact, gated operations)

## Table of contents
- Quick start
- Commands
- Documentation (PlatyPS)
- Security model
- Determinism and reproducibility
- Troubleshooting
- Features & Roadmap
- CI/CD
- Changelog
- Acceptable Use & Legal
- License


## Quick start

**Prerequisites:**
- Windows PowerShell 5.1 for Active Directory and DSInternals scenarios, with PowerShell 7+ supported for non-AD workflows
- RSAT Active Directory tools (available through Windows Features) to enable the ActiveDirectory module
- DSInternals module for replication-based key extraction

**Install required modules:**
```powershell
# Windows PowerShell recommended for AD scenarios
Install-Module DSInternals -Scope CurrentUser -Force
Import-Module ActiveDirectory -ErrorAction Stop
```

**Import STKeytab from source:**
```powershell
# From the repository root directory
Import-Module "$PWD\STKeytab.psd1" -Force
```

## Commands

**Core keytab operations:**
- **New-Keytab**: Create keytabs for AD principals via replication with AES-only defaults, RC4 available through explicit policy flags

```powershell
# Computer account with AES-only defaults, including short-host SPNs
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -IncludeShortHost -OutputPath .\web01.keytab -Force -Summary -PassThru

# Restrict to AES256 encryption only
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -IncludeEtype AES256_CTS_HMAC_SHA1_96 -Force

# Create deterministic output for CI/CD reproducibility
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -FixedTimestampUtc (Get-Date '2024-01-01Z')
```

- **New-KeytabFromPassword**: Generate keytabs from passwords using AES S2K (PBKDF2-HMACSHA1)

```powershell
# User principal with AES S2K derivation
$sec = ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force
New-KeytabFromPassword -SamAccountName user1 -Realm EXAMPLE.COM -Password $sec -Kvno 3 -Iterations 4096 `
  -OutputPath .\user1.keytab -Force -FixedTimestampUtc (Get-Date '2024-01-01Z') -Summary -PassThru

# Service principal with Windows-compatible salt handling
New-KeytabFromPassword -Principal 'HTTP/web01.example.com@EXAMPLE.COM' -Realm EXAMPLE.COM -Password $sec `
  -Compatibility Windows -IncludeEtype 18 -OutputPath .\http-web01.keytab -Force
```

---

**AD lifecycle management:**
- **Reset-AccountPasswordWithKeytab**: Atomically reset AD account passwords and generate corresponding keytabs with  rollback support
- **Set-AccountSpn**: Manage service principal names with domain-wide conflict detection and fully transactional operations

```powershell
# Atomic password reset with keytab generation
Reset-AccountPasswordWithKeytab -SamAccountName svc-web -AcknowledgeRisk -Justification "Quarterly rotation" -OutputPath .\svc-web.keytab

# SPN management with conflict detection and dry-run planning
Set-AccountSpn -SamAccountName svc-web -Add 'HTTP/web.contoso.com' -Remove 'HTTP/oldweb.contoso.com' -WhatIfOnly
```

---

**Analysis and manipulation:**
- **Read-Keytab, Test-Keytab**: Parse and validate keytabs with keys masked by default for security
- **Merge-Keytab**: Combine multiple keytabs with intelligent de-duplication and safety guardrails
- **Compare-Keytab**: Perform canonical diffs with timestamp-insensitive comparison and optional key-byte validation

```powershell
# Merge multiple keytabs and perform timestamp-insensitive comparison
Merge-Keytab -InputPaths .\a.keytab, .\b.keytab -OutputPath .\merged.keytab -Force
$cmp = Compare-Keytab -ReferencePath .\a.keytab -CandidatePath .\b.keytab -IgnoreTimestamp

# Inspect keytab contents and validate structure
Read-Keytab -Path .\web01.keytab
Test-Keytab -Path .\web01.keytab -Detailed
```

---

**Security and interoperability:**
- **Protect-Keytab, Unprotect-Keytab**: Apply DPAPI protection for at-rest security with user-restricted ACLs
- **ConvertTo-/ConvertFrom-KeytabJson**: Export and import using canonical JSON format with secure key handling

```powershell
# Secure export/import with canonical JSON format
ConvertTo-KeytabJson -Path .\a.keytab -OutputPath .\a.json  # Keys masked by default
ConvertTo-KeytabJson -Path .\a.keytab -OutputPath .\a.revealed.json -RevealKeys  # Explicit key reveal
ConvertFrom-KeytabJson -JsonPath .\a.revealed.json -OutputPath .\a2.keytab -Force

# DPAPI protection for at-rest security
Protect-Keytab -Path .\web01.keytab -RestrictAcl -DeletePlaintext
Unprotect-Keytab -Path .\web01.keytab.dpapi -RestrictAcl
```

---

## Documentation

This moduke includes comprehensive documentation authored in Markdown and maintained through PlatyPS:

- **Get help**: Use `Get-Help New-Keytab -Full` for detailed cmdlet documentation, or `Get-Help about_STKeytab` for conceptual topics
- **External help system**: Pre-compiled MAML XML provides 10x faster help loading compared to comment-based alternatives
- **Automated maintenance**: CI pipeline validates documentation drift on pull requests and automatically updates help on push commits

## Security model
- **Policy composition**: Public cmdlets compose policies through Include/Exclude/AESOnly/IncludeLegacyRC4/AllowDeadCiphers parameters, with internal orchestration resolving final encryption types from available key material

**Encryption standards:**
- AES256 and AES128 encryption types enabled by default
- RC4 support available only through explicit opt-in with centralized policy governance
- Legacy and obsolete ciphers excluded by default, with override controls for compatibility scenarios

**Sensitive operation controls:**
- `-RevealKeys` flag required for exposing key material, with automatic security warnings to prevent accidental disclosure
- `-AcknowledgeRisk` and `-Justification` parameters mandatory for high-impact operations like krbtgt key extraction
- Comprehensive audit trails with operator attribution and timestamp logging for compliance requirements

**Data protection:**
- DPAPI integration supporting both CurrentUser and LocalMachine scopes for at-rest encryption
- Optional entropy with SecureString support for enhanced protection (LocalMachine scope not portable across systems)
- Automatic ACL restriction to current user for keytab files when using protection feature

This module does **not** collect any telemetry or usage data.

## Determinism and reproducibility

STKeytab provides deterministic keytab generation through the `-FixedTimestampUtc` parameter, ensuring byte-identical outputs across different runs and machines when given identical inputs. This approach is valuable for CI/CD pipelines, code review processes, and audit scenarios where reproducible artifacts are essential.

When using fixed timestamps, the writer applies a stable entry ordering algorithm and uses the specified UTC timestamp consistently throughout the keytab structure. Given identical inputs including keys, KVNOs, encryption types, and SPNs, outputs will be completely reproducible, enabling confident diff-based validation and version control integration.

## Troubleshooting

**Active Directory connectivity:**
- **RODC target warnings**: New-Keytab warns when `-Server` points to a read-only domain controller; redirect operations to a writable DC for proper functionality
- **Permission errors**: Ensure appropriate domain privileges (DCSync) for replication-based extraction and lifecycle management operations


## Features & Roadmap

**Standard capabilities shared with other tools:**
- **Password-based S2K generation**: Similar to ktutil functionality but with AES-only enforcement for enhanced security
- **Keytab reading and validation**: Comparable to klist -k and ktutil list operations with enhanced security masking

**Capabilities provided by other tools but not yet implemented:**
- Advanced service discovery and automation workflows
- Cross-platform toolchain integration and compatibility helpers for mixed Unix/Windows deployments

### Development roadmap

**Next release priorities:**
- Enhanced interoperability with MIT and Heimdal toolchains for cross-platform integration
- Service account discovery and management helpers


## CI/CD
- Docs workflow builds/validates PlatyPS help; auto-commits on push with [skip ci]. See .github/workflows/docs.yml and CI/Build-Docs.ps1.
- Test & Sign workflow runs Pester, PSScriptAnalyzer, optional signing, packaging, and signed import verification. See .github/workflows/test_sign.yml and CI/Test-Sign/Test-Sign.ps1.

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
- **Enhanced Security Integration**: Centralized security policy enforcement across all cmdlets
  - AES-only enforcement on password derivation paths with hard guardrails
  - Policy composition and validation for consistent security posture


### [0.4.0] - 2025-08-26
#### Added
- **External Help System**: Complete PlatyPS integration with external help (MAML XML) generation
  - Cmdlet documentation in `docs/cmdlets/` with comprehensive examples and parameter descriptions
  - About topics in `docs/about/` covering Security, Determinism, Interop, KVNO, and DPAPI concepts
  - External help XML in `en-US/` for fast help loading (10x faster than comment-based help)
  - CI pipeline validates help drift and auto-updates documentation
- **Help Publishing Infrastructure**: `CI/Publish-Help.ps1` for future Update-Help support (CAB hosting)

#### Changed
- **Refactored CI/CD**: Consolidated test, analyze, sign, and package operations into single wrapper

### [0.3.1] - 2025-08-17
#### Added
- **Structured Function Design**: Begin-Process-End blocks and standardized comment-based help across all public functions
- **Enhanced Parameter Descriptions**: Help for all parameters with examples


### [0.3.0] - 2025-08-17
#### Added
- **Compare-Keytab**: Canonical diff with timestamp-insensitive comparison and optional key-byte validation
- **ConvertTo-KeytabJson**: Export keytabs to canonical JSON (keys masked by default, `-RevealKeys` to include)
- **ConvertFrom-KeytabJson**: Import keytabs from JSON with deterministic output support
- **JSON Interoperability**: Stable sorting, timestamp controls, and secure key handling

### [0.2.0] - 2025-08-16
#### Added
- **New-Keytab**: Front-door cmdlet with auto-detection of principal type (user/computer/krbtgt)
- **New-KeytabFromPassword**: Password-based keytab generation using AES S2K (PBKDF2-HMACSHA1)
- **Read-Keytab**: Robust keytab parser with keys masked by default, optional `-RevealKeys`
- **Test-Keytab**: Validation and unknown encryption type reporting
- **Merge-Keytab**: De-duplication across multiple keytabs with guardrails for high-risk operations
- **Protect-Keytab / Unprotect-Keytab**: DPAPI protection for at-rest keytabs (CurrentUser/LocalMachine)
- **Comprehensive Architecture**: Modular Private/ functions supporting orchestration, crypto, I/O


### [0.1.0] - 2025-08-10
#### Added
- **Initial Implementation**: Core keytab generation and parsing functionality
- **MIT Keytab Format**: Support for keytab version 0x0502 with robust I/O
- **Active Directory Integration**: Basic user and computer account key extraction
- **Testing Foundation**: Initial Pester test suite covering core scenarios

---

## Acceptable Use & Legal
This tool is intended for authorized system administration, interoperability testing, and defensive research in environments where you have explicit permission.

Do not use this software to access, extract, or manipulate data without authorization. Doing so may violate computer misuse laws or your employer’s policies.

This project is not affiliated with or endorsed by Microsoft, the MIT Kerberos project, or any other vendor. All trademarks are the property of their respective owners.

## License
This tool is licensed under the Apache License, Version 2.0. See LICENSE and NOTICE for details. All source files carry SPDX-License-Identifiers.

