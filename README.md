## STKeytab

A focused PowerShell toolkit for generating and working with MIT keytabs (0x0502) using replication-based key extraction. The module favors safe defaults, deterministic outputs when requested, and minimal dependencies.

### Documentation
Cmdlet help is maintained in Markdown using [PlatyPS](https://github.com/PowerShell/platyPS) and (not yet) built into external help (MAML XML) for offline use. The CI pipeline validates help drift and auto-updates docs on push. See `docs/` for source and `en-US/` for built help.

### Requirements
Requires Modules:
- ActiveDirectory
- DSInternals

Requires AD - Privileges:
 - DCSync-equivalent (Replicating Directory Changes, ...All, and ...In Filtered Set) on the domain NC

Supports Powershell versions 5.1 and 7+

### CI/CD
Includes a self-hosted docs job that validates and auto-updates PlatyPS help. See `.github/workflows/docs.yml` and `CI/Build-Docs.ps1`.

### Import
```powershell
Import-Module "$PWD\STKeytab\STKeytab.psd1" -Force
```

### Commands
- New-Keytab: Create a keytab for an Active Directory principal via AD replication.
- New-KeytabFromPassword: Generate a keytab from a password (no replication) using AES string-to-key (PBKDF2-HMACSHA1) with MIT/Heimdal/Windows salt policies.
- Read-Keytab: Parse a keytab to structured entries (keys masked by default).
- Test-Keytab: Quick structural validation and unknown etype listing.
- Merge-Keytab: Merge multiple keytabs with de-duplication and guardrails.
- Protect-Keytab / Unprotect-Keytab: DPAPI protect/unprotect keytab files.
- Compare-Keytab: Canonical diff of two keytabs with optional timestamp-insensitive and key-byte comparison.
- ConvertTo-KeytabJson / ConvertFrom-KeytabJson: Canonical JSON export/import (keys masked by default on export).

### Usage
```powershell
# Computer account with SPNs, AES-only default (AES256, AES128). Optional RC4 via IncludeEtype.
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -Credential (Get-Credential) -Summary -PassThru

# Include short host variants for SPNs
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -IncludeShortHost -OutputPath C:\temp\web01.keytab -Force

# Restrict to AES256
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -IncludeEtype AES256_CTS_HMAC_SHA1_96 -Force -PassThru

# Exclude RC4 explicitly
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -ExcludeEtype ARCFOUR_HMAC -Summary

# Deterministic output
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -FixedTimestampUtc (Get-Date '2024-01-01Z')

# Merge two keytabs
Merge-Keytab -InputPaths .\a.keytab, .\b.keytab -OutputPath .\merged.keytab -Force

# Protect at rest (CurrentUser scope)
Protect-Keytab -Path .\web01.keytab -RestrictAcl -DeletePlaintext
Unprotect-Keytab -Path .\web01.keytab.dpapi -RestrictAcl

# Inspect
Read-Keytab -Path .\web01.keytab
Test-Keytab -Path .\web01.keytab -Detailed

# Password-based (no replication) — AES S2K (PBKDF2-HMACSHA1)
$sec = ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force

# User principal; AES256 then AES128 (default IncludeEtype); KVNO 3; deterministic timestamp
New-KeytabFromPassword -SamAccountName user1 -Realm EXAMPLE.COM -Password $sec -Kvno 3 -Iterations 4096 -OutputPath .\user1.keytab -Force -FixedTimestampUtc (Get-Date '2024-01-01Z') -Summary -PassThru

# Service principal (Windows salt flavor lowercases service/host and uppercases realm)
New-KeytabFromPassword -Principal 'HTTP/web01.example.com@EXAMPLE.COM' -Realm EXAMPLE.COM -Password $sec -Compatibility Windows -IncludeEtype 18 -OutputPath .\http-web01.keytab -Force

# Compare keytabs (ignore timestamps by default)
$cmp = Compare-Keytab -ReferencePath .\a.keytab -CandidatePath .\b.keytab -IgnoreTimestamp
$cmp.Equal

# Show differing key bytes in output (does not change comparison semantics)
Compare-Keytab -ReferencePath .\a.keytab -CandidatePath .\b.keytab -IgnoreTimestamp -RevealKeys | Format-List

# Export/import canonical JSON
ConvertTo-KeytabJson -Path .\a.keytab -OutputPath .\a.json              # keys masked by default
ConvertTo-KeytabJson -Path .\a.keytab -OutputPath .\a.revealed.json -RevealKeys
ConvertFrom-KeytabJson -JsonPath .\a.revealed.json -OutputPath .\a2.keytab -Force -FixedTimestampUtc (Get-Date '2024-01-01Z')
```

### Notes
- Safe defaults prefer AES. RC4 is opt-in.
- -FixedTimestampUtc is opt-in and respected end-to-end for reproducible artifacts.
- DPAPI helper cmdlets support CurrentUser and LocalMachine scopes with optional entropy; outputs can be ACL-restricted to the current user.
- New-KeytabFromPassword is AES-only (etype 17/18). RC4 is intentionally not supported in this path.
 - New-KeytabFromPassword is AES-only (etype 17/18). RC4 is intentionally not supported in this path.
 - PlatyPS-based help is validated and auto-updated in CI; see docs/ for Markdown and en-US/ for built help.
- Canonical JSON is stably sorted and can omit timestamps via -IgnoreTimestamp; ConvertFrom-KeytabJson requires key bytes (export with -RevealKeys to include them).
- The module does **not** collect any telemetry.

### Roadmap
- Reset-AccountPasswordWithKeytab workflow with dry-run and rollback.
- Set-AccountSpn cmdlets with conflict detection and transactional behavior.
- Interop helpers (Wireshark config, ktutil scripts) and CI/signing polish.

### Recent Changes
- Hardened module loader and CI import logic
- Comfort/security pass: warnings for -RevealKeys, DPAPI entropy, OutputPath optionality, AES/RC4 policy
- PlatyPS help: Markdown sources, CI drift validation and auto-update

## Risk & Privileges


- Some operations (e.g., replication-based key export) require **DCSync-equivalent** privileges
  (Replicating Directory Changes / …All / …In Filtered Set) on the domain.
- Keytab files are **sensitive**: if they contain `krbtgt` keys, they may enable ticket forgery.
- Use on hardened admin hosts only; store artifacts with restrictive ACLs; enable PowerShell logging.

## Acceptable Use & Legal

This tool is intended for authorized system administration, interoperability testing,
and defensive research in environments where you have explicit permission.

Do **not** use this software to access, extract, or manipulate data without authorization.
Doing so may violate computer misuse laws or your employer’s policies.

This project is not affiliated with or endorsed by Microsoft, the MIT Kerberos project,
or any other vendor. All trademarks are the property of their respective owners.

## License
This tool is licensed under the Apache License, Version 2.0. See LICENSE and NOTICE for details.
All source files carry SPDX-License-Identifiers.

## Warranty & Liability
This software is provided **“AS IS”**, without warranties or conditions of any kind, express or implied.
In no event shall the authors or contributors be liable for any claim, damages, or other liability arising from or in connection with the software or its use.
See LICENSE for full terms.

