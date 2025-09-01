# STKeytab_Interop
## about_STKeytab_Interop

# SHORT DESCRIPTION
Interoperability notes for MIT Kerberos, Heimdal, Windows implementations, and cross-platform keytab usage.

# LONG DESCRIPTION
The STKeytab module generates MIT keytab format (0x0502) files compatible with various Kerberos implementations. Understanding the differences between platforms helps ensure successful interoperability.

## Salt Policy Differences
Different Kerberos implementations use varying salt policies for string-to-key operations:

### MIT Kerberos (Default)
- User principals: REALM + SamAccountName (e.g., EXAMPLE.COMuser1)
- Service principals: REALM + service + host (e.g., EXAMPLE.COMhttpweb01.example.com)
- Case preservation: Maintains original case from principal specification

### Heimdal
- Similar to MIT with slight variations in specific scenarios
- Generally compatible with MIT-generated keytabs

### Windows Active Directory
- User principals: REALM + SamAccountName (uppercase realm)
- Service principals: REALM + lowercase(service) + lowercase(host)
- Case normalization: Service and host components are lowercased, realm is uppercased

The New-KeytabFromPassword command supports compatibility modes:

```
New-KeytabFromPassword -Principal 'HTTP/web01.example.com@EXAMPLE.COM' -Compatibility Windows
```

This applies Windows salt policy rules for maximum compatibility with AD-issued tickets.

## Encryption Type Compatibility
Modern Kerberos implementations support different encryption types with varying degrees of compatibility:

### Universally Supported (Recommended)
- AES256-CTS-HMAC-SHA1-96 (etype 18): Best compatibility and security
- AES128-CTS-HMAC-SHA1-96 (etype 17): Good compatibility, adequate security

### Modern Standards (RFC 8009)
- AES256-CTS-HMAC-SHA384-192 (etype 20): Enhanced security, limited platform support
- AES128-CTS-HMAC-SHA256-128 (etype 19): Enhanced security, limited platform support
- Note: AES-SHA2 types require newer Kerberos implementations (MIT 1.15+, Windows Server 2019+)

### Legacy Support Only
- RC4-HMAC (etype 23): Deprecated, cryptographically weak
- DES-based etypes: Obsolete, not supported by this module

### Cross-Platform Recommendations
- Use AES256-SHA1 and AES128-SHA1 for compatibility
- Use AES-SHA2 types when all systems support RFC 8009
- Include RC4 only when required for legacy system compatibility
- Test keytabs against target systems before production deployment

## KVNO Handling Across Platforms
Key Version Number (KVNO) handling varies between implementations:

### Active Directory
- KVNO increments on password changes
- Stored in msDS-KeyVersionNumber attribute
- Replication-based extraction preserves AD KVNO values

### MIT/Heimdal
- KVNO may be managed differently depending on KDC implementation
- Some environments use KVNO 1 for all keys
- Password-based generation allows explicit KVNO specification

### Cross-Realm Scenarios
- KVNO values should match between client and server expectations
- Use Compare-Keytab to verify KVNO consistency across environments
- Test authentication flows after keytab deployment

## Principal Naming Conventions
Different platforms have varying conventions for principal names:

### User Principals
- Windows AD: user@REALM.COM or REALM\user
- MIT/Heimdal: user@REALM.COM
- Keytab format: Always uses user@REALM.COM format

### Service Principals
- Format: service/hostname@REALM.COM
- Service names: http, host, ldap, etc. (lowercase recommended)
- Hostname: FQDN preferred for cross-realm scenarios

### Computer Account Handling
Windows computer accounts (ending in $) are treated as service principals with HOST/ service type in keytab generation.

# EXAMPLES
## Example 1: Windows-Compatible Service Keytab
```
New-KeytabFromPassword -Principal 'HTTP/web01.example.com@EXAMPLE.COM' -Realm EXAMPLE.COM -Password $pwd -Compatibility Windows -OutputPath .\http-web01.keytab -Force
```

Generates a keytab using Windows salt policy for maximum AD compatibility.

## Example 2: Cross-Platform User Keytab
```
New-KeytabFromPassword -SamAccountName user1 -Realm EXAMPLE.COM -Password $pwd -IncludeEtype 18,17 -OutputPath .\user1.keytab -Force
```

Creates a user keytab with AES encryption types supported across platforms.

## Example 3: Legacy System Compatibility
```
New-Keytab -SamAccountName service$ -Domain contoso.com -IncludeLegacyRC4 -OutputPath .\legacy-compat.keytab -Force
```

Includes RC4 encryption for compatibility with older systems that don't support AES.

## Example 4: KVNO Verification
```
$keytab1 = Read-Keytab -Path .\server1.keytab
$keytab2 = Read-Keytab -Path .\server2.keytab
Compare-Object $keytab1.Entries.Kvno $keytab2.Entries.Kvno
```

Compares KVNO values between keytabs to identify mismatches.

# NOTE
Always test keytabs in the target environment before production deployment. Different Kerberos implementations may have subtle compatibility requirements not covered by standard specifications.

The module defaults to MIT-compatible behavior, which works well with most modern Kerberos implementations including Windows AD when proper salt policies are applied.

# TROUBLESHOOTING
## Common Interoperability Issues

"Authentication fails with new keytab": Verify encryption type compatibility between client and server. Use Test-Keytab -Detailed to examine available etypes.

"Principal name format errors": Ensure principal names follow the target system's expected format. Windows expects FQDN hostnames for service principals.

"KVNO mismatch errors": Use Compare-Keytab to verify KVNO values match between keytab and KDC expectations.

"Salt mismatch in password derivation": Use the appropriate -Compatibility setting (Windows, MIT, Heimdal) for the target environment.

"RC4 authentication works but AES fails": Verify the target system supports AES encryption types and that they're enabled in Kerberos policy.

# SEE ALSO
- about_STKeytab
- about_STKeytab_KVNO
- New-KeytabFromPassword
- Compare-Keytab
- Test-Keytab

# KEYWORDS
- MIT Kerberos
- Heimdal
- Windows Active Directory
- Salt policy
- Cross-platform
- Encryption types
- KVNO compatibility
- Principal names
- Service principals
