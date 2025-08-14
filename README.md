# STCrypt.STkrbKeytab (Preview)

Generate MIT keytab (`0x0502`) files for Windows **computer accounts** without password resets by DCSync-reading Kerberos long‑term keys via **DSInternals**. Useful for:
- Wireshark / NetMon decryption (add keytab under Protocol Preferences > Kerberos)
- Lab troubleshooting of service tickets
- Offline protocol analysis / reproductions

> Only computer accounts are targeted (SAM name like `WEB01$`). User-account support is intentionally omitted.

## Module Import

```powershell
Import-Module "$PWD\STkrbKeytab\STkrbKeytab.psd1" -Force
```

Dependencies (`ActiveDirectory`, `DSInternals`) are auto-installed (CurrentUser scope) if missing unless you specify `-SkipDependencyCheck` on `New-ComputerKeytab`.

## Core Cmdlets
| Cmdlet | Purpose |
| ------ | ------- |
| `New-ComputerKeytab` | Build a keytab for a computer account (DCSync). |
| `Test-Keytab` | Lightweight structural validation of a keytab file. |

## Common Usage Patterns

```powershell
# 1. Basic (auto SPNs, default etypes AES256/AES128/RC4, JSON summary optional)
New-ComputerKeytab -ComputerName WEB01 -Domain contoso.com -Credential (Get-Credential) -Summary -PassThru

# 2. Include short host variants (adds host/web01@REALM for each FQDN)
New-ComputerKeytab -ComputerName WEB01 -Domain contoso.com -IncludeShortHost -OutputPath C:\temp\web01.keytab -Force

# 3. Restrict to only AES256
New-ComputerKeytab -ComputerName WEB01 -Domain contoso.com -IncludeEtype AES256_CTS_HMAC_SHA1_96 -Force -PassThru

# 4. Exclude RC4
New-ComputerKeytab -ComputerName WEB01 -Domain contoso.com -ExcludeEtype ARCFOUR_HMAC -Summary

# 5. Custom principals only (skip domain SPN enumeration)
New-ComputerKeytab -ComputerName WEB01 -Domain contoso.com -AllSpn:$false `
		-Principal 'host/web01.contoso.com','cifs/web01.contoso.com' -Force

# 6. Override KVNO (e.g. replay older key version for test)
New-ComputerKeytab -ComputerName WEB01 -Domain contoso.com -Kvno 42 -PassThru

# 7. Use .env file for credentials
New-ComputerKeytab -ComputerName WEB01 -Domain contoso.com -EnvFile .\.env -IncludeShortHost

# 8. Quick verification
Test-Keytab -Path .\WEB01.keytab
```

### .env File Format
```
STCRYPT_DSYNC_USERNAME=CONTOSO\\krbreader
STCRYPT_DCSYNC_PASSWORD=SuperSecretPassword!
```

## Parameter Highlights
| Parameter | Default | Notes |
| --------- | ------- | ----- |
| `IncludeEtype` | 18,17,23 | Names or IDs. Filtered against available keys. |
| `ExcludeEtype` | (none) | Applied after include selection. |
| `AllSpn` | `$true` | Enumerate all current SPNs for the computer. Set `-AllSpn:$false` to use only `-Principal`. |
| `Principal` | (none) | One or more `service/host` or `service/host@REALM`. Can override realm (must be consistent). |
| `IncludeShortHost` | off | Adds short host variants (e.g. `host/web01`). |
| `Kvno` | AD value | Override key version number in entries + JSON summary. |
| `RestrictAcl` | on | Replaces file ACL with current user only (keytab + summary). |
| `Summary` | off | Emit JSON sidecar (auto included when `-PassThru`). |
| `PassThru` | off | Returns an object (metadata, principals, paths). |
| `SkipDependencyCheck` | off | Testing/offline use; skips importing/auto-install *but still needs functions mocked*. |

## Output Artifacts
| File | Description |
| ---- | ----------- |
| `*.keytab` | MIT keytab, entries per (principal × enctype). |
| `*.json` | (Optional) Summary: etypes, principals, kvno, timestamp. |

## JSON Summary Fields (excerpt)
```json
{
	"Computer": "WEB01",
	"Realm": "CONTOSO.COM",
	"Kvno": 7,
	"EncryptionTypes": [ "AES256_CTS_HMAC_SHA1_96", "AES128_CTS_HMAC_SHA1_96", "ARCFOUR_HMAC" ],
	"Principals": [ "host/web01.contoso.com@CONTOSO.COM", "cifs/web01.contoso.com@CONTOSO.COM" ]
}
```

## Security Notes
Treat keytabs like password equivalents:
* Store only on secure, short‑lived analysis hosts.
* Prefer minimal required etypes (drop RC4 if not needed).
* Remove the file after decryption tasks: `Remove-Item .\WEB01.keytab -Force`.

## Testing
Pester tests (module path adjusted):
```powershell
Invoke-Pester -Path .\src\STCrypt.Powershell\STkrbKeytab\tests\New-ComputereKeytab.Tests.ps1
```
Some tests mock AD/DSInternals; use `-SkipDependencyCheck` to avoid network / installation during those.

## Troubleshooting
| Symptom | Tip |
| ------- | --- |
| No principals error | Supply `-Principal` or allow SPN enumeration (omit `-AllSpn:$false`). |
| Missing etype warnings | AD lacks those key algorithms; ensure account has requested encryption types enabled. |
| Keytab rejected by tool | Validate with `Test-Keytab`; confirm header bytes 0x05 0x02. |

## License / Preview
Preview quality; API surface may change. Use at your own risk.