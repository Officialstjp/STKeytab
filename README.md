## STkrbKeytab

A focused PowerShell toolkit for generating and working with MIT keytabs (0x0502) using replication-based key extraction. The module favors safe defaults, deterministic outputs when requested, and minimal dependencies.

### Import
```powershell
Import-Module "$PWD\STkrbKeytab\STkrbKeytab.psd1" -Force
```

### Commands
- New-Keytab: Create a keytab for user, computer, or krbtgt via AD replication.
- New-KeytabFromPassword: Generate a keytab from a password (no replication) using AES string-to-key (PBKDF2-HMACSHA1) with MIT/Heimdal/Windows salt policies.
- Read-Keytab: Parse a keytab to structured entries (keys masked by default).
- Test-Keytab: Quick structural validation and unknown etype listing.
- Merge-Keytab: Merge multiple keytabs with de-duplication and guardrails.
- Protect-Keytab / Unprotect-Keytab: DPAPI protect/unprotect keytab files.

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

# krbtgt (requires acknowledgement) with current and previous KVNOs
New-Keytab -SamAccountName krbtgt -Domain contoso.com -IncludeOldKvno -AcknowledgeRisk -Summary

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
```

### Notes
- Safe defaults prefer AES. RC4 is opt-in.
- -FixedTimestampUtc is opt-in and respected end-to-end for reproducible artifacts.
- DPAPI helper cmdlets support CurrentUser and LocalMachine scopes with optional entropy; outputs can be ACL-restricted to the current user.
- New-KeytabFromPassword is AES-only (etype 17/18). RC4 is intentionally not supported in this path.

### Security
Keytabs are sensitive. Store on trusted hosts, keep lifetimes short, and remove artifacts when no longer needed.

### Roadmap
- Reset-AccountPasswordWithKeytab workflow with dry-run and rollback.
- Set-AccountSpn cmdlets with conflict detection and transactional behavior.
- Compare-Keytab and ConvertTo/From-KeytabJson helpers.
- Interop helpers (Wireshark config, ktutil scripts) and CI/signing polish.