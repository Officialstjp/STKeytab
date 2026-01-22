# STKeytab

[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/powershell/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![PSGallery](https://img.shields.io/powershellgallery/v/STKeytab.svg)](https://www.powershellgallery.com/packages/STKeytab)
[![Downloads](https://img.shields.io/powershellgallery/dt/STKeytab.svg)](https://www.powershellgallery.com/packages/STKeytab)

A PowerShell module for creating and managing MIT Kerberos keytab files from Active Directory — the modern alternative to `ktpass.exe` that Microsoft forgot to write.

>Note: This module is in active development. Use in production environments only after thorough testing.

---

## What is this?

STKeytab lets you generate keytabs for AD accounts in two ways:

1. **Replication-based extraction** — Pull existing Kerberos keys from AD via DCSync (DSInternals). No password resets, no service interruption.
2. **Password-based derivation** — Generate keytabs from passwords using proper AES string-to-key (PBKDF2) with MIT/Heimdal/Windows salt conventions.

**Why not just use ktpass?**

| ktpass.exe | STKeytab |
|------------|----------|
| Resets passwords by default | Extracts existing keys (replication) |
| RC4 defaults | AES-only by default |
| No AES-SHA2 support | RFC 8009 etypes 19/20 ✓ |
| Minimal output control | Deterministic, reproducible builds |
| No at-rest protection | DPAPI encryption optional |
| "Good luck debugging" | JSON export, comparison tools |

## Features

- **Safe defaults** — AES256/AES128 only; RC4 requires explicit opt-in
- **Modern crypto** — AES-SHA2 (etypes 19/20) via RFC 8009, ahead of Windows tooling
- **Deterministic output** — Fixed timestamps for byte-identical builds across runs
- **DPAPI protection** — Encrypt keytabs at rest with user-scoped ACLs
- **Comparison & merge** — Diff keytabs, merge with deduplication, JSON round-trips
- **AD lifecycle tools** — Password rotation with atomic keytab generation, SPN management with conflict detection

---

## Installation

```powershell
# From PSGallery (when published)
Install-Module STKeytab -Scope CurrentUser

# For AD replication scenarios, also install DSInternals
Install-Module DSInternals -Scope CurrentUser
```

**Or from source:**
```powershell
git clone https://github.com/Officialstjp/STKeytab.git
Import-Module .\STKeytab\STKeytab.psd1 -Force
```

**Requirements:**
- PowerShell 5.1 (Windows PowerShell) or PowerShell 7+
- RSAT AD tools for AD scenarios
- DSInternals module for replication-based extraction

---

## Quick Start

**⚠️ Test in a safe environment first!**

### Core keytab operations:
- **New-Keytab**: Create keytabs for AD principals via replication with AES-only defaults, RC4 available through explicit policy flags

```powershell
# === Computer account with AES-only defaults, including short-host SPNs ===

New-Keytab -SamAccountName WEB01$ `
  -Domain contoso.com `
  -IncludeShortHost -OutputPath `
  .\web01.keytab `
  -Force -Summary -PassThru

# === Restrict to AES256 encryption only ===
New-Keytab -SamAccountName WEB01$`
  -Domain contoso.com `
  -IncludeEtype AES256_CTS_HMAC_SHA1_96 `
  -Force

# === Create deterministic output for CI/CD reproducibility ===
New-Keytab -SamAccountName WEB01$ `
  -Domain contoso.com `
  -FixedTimestampUtc (Get-Date '2024-01-01Z')
```

- **New-KeytabFromPassword**: Generate keytabs from passwords using AES S2K (PBKDF2-HMAC-SHA1/SHA256/SHA384)

```powershell
# === User principal with AES S2K derivation (SHA1) ===

$sec = ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force

New-KeytabFromPassword -SamAccountName user1 `
  -Realm EXAMPLE.COM `
  -Password $sec `
  -Kvno 3 `
  -Iterations 4096 `
  -OutputPath .\user1.keytab `
  -FixedTimestampUtc (Get-Date '2024-01-01Z') `
  -Force -Summary -PassThru

# === Service principal with modern AES-SHA2 encryption (etype 19) ===

New-KeytabFromPassword -Principal 'HTTP/web01.example.com@EXAMPLE.COM' `
  -Realm EXAMPLE.COM `
  -Password $sec `
  -Compatibility Windows `
  -IncludeEtype 19 `
  -OutputPath .\http-web01.keytab `
  -Force
```

---

### AD lifecycle management:
- **Reset-AccountPasswordWithKeytab**: Atomically reset AD account passwords and generate corresponding keytabs with  rollback support
- **Set-AccountSpn**: Manage service principal names with domain-wide conflict detection and fully transactional operations

```powershell
# === Atomic password reset with keytab generation ===

Reset-AccountPasswordWithKeytab -SamAccountName svc-web `
  -AcknowledgeRisk `
  -Justification "Quarterly rotation" `
  -OutputPath .\svc-web.keytab


# === SPN management with conflict detection and dry-run planning ===

Set-AccountSpn -SamAccountName svc-web `
  -Add 'HTTP/web.contoso.com' `
  -Remove 'HTTP/oldweb.contoso.com' `
  -WhatIfOnly
```

---

### Analysis and manipulation:
- **Read-Keytab, Test-Keytab**: Parse and validate keytabs with keys masked by default for security
- **Merge-Keytab**: Combine multiple keytabs with intelligent de-duplication and safety guardrails
- **Compare-Keytab**: Perform canonical diffs with timestamp-insensitive comparison and optional key-byte validation

```powershell
# === Merge multiple keytabs and perform timestamp-insensitive comparison ===

Merge-Keytab -InputPaths .\a.keytab, .\b.keytab `
  -OutputPath .\merged.keytab `
  -Force
$cmp = Compare-Keytab -ReferencePath .\a.keytab -CandidatePath .\b.keytab -IgnoreTimestamp

# === Inspect keytab contents and validate structure ===

Read-Keytab -Path .\web01.keytab

Test-Keytab -Path .\web01.keytab -Detailed
```

---

### Security and interoperability:
- **Protect-Keytab, Unprotect-Keytab**: Apply DPAPI protection for at-rest security with user-restricted ACLs
- **ConvertTo-/ConvertFrom-KeytabJson**: Export and import using canonical JSON format with secure key handling

```powershell
# === Secure export/import with canonical JSON format ===

ConvertTo-KeytabJson -Path .\a.keytab `
  -OutputPath .\a.json  # Keys masked by default

ConvertTo-KeytabJson -Path .\a.keytab `
  -OutputPath .\a.revealed.json `
  -RevealKeys  # Explicit key reveal

ConvertFrom-KeytabJson -JsonPath .\a.revealed.json `
  -OutputPath .\a2.keytab `
  -Force

# === DPAPI protection for at-rest security ===

Protect-Keytab -Path .\web01.keytab `
  -RestrictAcl `
  -DeletePlaintext

Unprotect-Keytab -Path .\web01.keytab.dpapi `
  -RestrictAcl
```

---

## Documentation

This module includes comprehensive help maintained through PlatyPS:

- **Get help**: `Get-Help New-Keytab -Full` or `Get-Help about_STKeytab`
- **External help**: Pre-compiled MAML XML for fast loading
- **About topics**: Security, Determinism, Interop, KVNO, DPAPI concepts in `docs/about/`

---

## Security Model

- **AES-only by default** — RC4 requires `-IncludeLegacyRC4`; dead ciphers require `-AllowDeadCiphers`
- **Gated sensitive ops** — `-RevealKeys` for key material, `-AcknowledgeRisk` + `-Justification` for high-impact actions
- **DPAPI at rest** — `Protect-Keytab` encrypts with CurrentUser or LocalMachine scope
- **No telemetry** — This module collects nothing

Treat krbtgt keytab creation as a last-resort, auditable emergency action.


---

## Determinism

Use `-FixedTimestampUtc` for byte-identical outputs across runs — useful for CI/CD, testing, and reproducible builds.

---

## Troubleshooting

- **RODC warnings** — `New-Keytab` warns if `-Server` points to a read-only DC; use a writable DC
- **Permission errors** — Replication-based extraction requires DCSync-equivalent permissions

---

## How did we get here?
The core _need_ for STKeytab started with notice of a certain issue in mid-2025:

Windows Server 2025 Domain Controllers caused trust-relationship breakage with pre-24H2 Windows clients due to malfunctioning machine password-rotations.

This we believe is caused by a change in core kerberos functionality:

Windows Server 2025 DCs send the `key-expiration` attribute in `encASRepPart` messages as a time set in 2100, which presumably causes older clients to reject the ticket due to `key-expiration` being out of range at FILETIME-parsing, resulting in a corrupted timestamp in Windows Kerberos processing.

Presumably, as Microsoft has not publicly noted specific details of this change or its resolution, though it has been resolved in ~ July 2025 updates for Windows clients.

Debugging this issue required generating keytabs for various accounts to live-analyze the Kerberos exchanges. Notably, the need for deterministic Keytab-Generation without password resets was paramount, for which no modern tool existed.

Inspired by that lack, STKeytab evolved into a tool for secure, reliable, and auditable keytab management in Active Directory environments. Leveraging community-driven projects like DSInternals, this module aims to fill the gap left by legacy tools, providing system administrators and security professionals with a robust alternative.

---


## Roadmap

- MIT/Heimdal interop helpers (ktutil script generation, Wireshark env writer)
- Service account discovery and management

---

## Contributing

See [CHANGELOG.md](CHANGELOG.md) for version history. PRs / Issues welcome!

---

## Legal

**Acceptable Use:** This tool is for authorized system administration and defensive research only. Unauthorized access to systems or data may violate computer misuse laws.

**Trademarks:** Not affiliated with Microsoft or MIT Kerberos project.

**License:** [Apache 2.0](LICENSE) — see [NOTICE](NOTICE) for attributions.

