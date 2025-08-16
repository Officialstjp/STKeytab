## STkrbKeytab

A focused PowerShell toolkit for generating and working with MIT keytabs (0x0502) using replication-based key extraction. The module favors safe defaults, deterministic outputs when requested, and minimal dependencies.

### Import
```powershell
Import-Module "$PWD\STkrbKeytab\STkrbKeytab.psd1" -Force
```

### Commands
- New-Keytab: Create a keytab for user, computer, or krbtgt via AD replication.
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
```

### Notes
- Safe defaults prefer AES. RC4 is opt-in.
- -FixedTimestampUtc is opt-in and respected end-to-end for reproducible artifacts.
- DPAPI helper cmdlets support CurrentUser and LocalMachine scopes with optional entropy; outputs can be ACL-restricted to the current user.

### Security
Keytabs are sensitive. Store on trusted hosts, keep lifetimes short, and remove artifacts when no longer needed.

### Roadmap
- Password-based keytab path (MIT AES string-to-key) and parity with ktpass flows.
- SPN management cmdlets with dry-run and rollback.
- Interop helpers and CI/signing polish.