# STKeytab_Crypto
## about_STKeytab_Crypto

# SHORT DESCRIPTION
Cryptographic algorithms, encryption types, and string-to-key implementations supported by STKeytab.

# LONG DESCRIPTION
The STKeytab module implements modern cryptographic standards for Kerberos key derivation and keytab generation, with support for both legacy and modern encryption types considered.

## Supported Encryption Types
STKeytab supports the following encryption types (etypes):

### AES-SHA1 (RFC 3962)
- **AES128-CTS-HMAC-SHA1-96 (etype 17)**: 128-bit AES with SHA1-based HMAC
- **AES256-CTS-HMAC-SHA1-96 (etype 18)**: 256-bit AES with SHA1-based HMAC
- **Key derivation**: PBKDF2-HMAC-SHA1 with 4,096 iterations (default)
- **Compatibility**: Universal support across all modern Kerberos implementations

### AES-SHA2 (RFC 8009)
- **AES128-CTS-HMAC-SHA256-128 (etype 19)**: 128-bit AES with SHA256-based HMAC
- **AES256-CTS-HMAC-SHA384-192 (etype 20)**: 256-bit AES with SHA384-based HMAC
- **Key derivation**: PBKDF2-HMAC-SHA256/SHA384 with 32,768 iterations (default)
- **Compatibility**: Requires modern implementations (MIT 1.15+, Windows Server 2019+)

### Legacy Support
- **RC4-HMAC (etype 23)**: 128-bit RC4 with MD4-based key derivation
- **Availability**: Parse-only by default, write requires explicit `-IncludeLegacyRC4`
- **Security warning**: Cryptographically weak, use only for legacy interoperability

## String-to-Key (S2K) Implementation
The module implements RFC-compliant string-to-key derivation for password-based keytab generation:

### PBKDF2 Implementation
- **Algorithm**: Password-Based Key Derivation Function 2 (RFC 2898)
- **Hash functions**: SHA1, SHA256, SHA384 support
- **Iteration counts**: Configurable with secure defaults per RFC recommendations
- **Salt handling**: MIT, Heimdal, and Windows compatibility modes

### Salt Policy Differences
Different Kerberos implementations use varying salt construction:

```powershell
# MIT/Heimdal: REALM + principal components (case-preserved)
Get-DefaultSalt -Compatibility MIT -PrincipalDescriptor $desc

# Windows: Uppercase realm, lowercase service/host for SPN entries
Get-DefaultSalt -Compatibility Windows -PrincipalDescriptor $desc
```

## Algorithm Selection
The module uses intelligent algorithm selection based on etype:

### Automatic Selection
```powershell
# Derives AES128 key using PBKDF2-HMAC-SHA1, 4096 iterations
Derive-AesKeyWithPbkdf2 -Etype 17 -PasswordPlain "password" -SaltBytes $salt

# Derives AES256 key using PBKDF2-HMAC-SHA384, 32768 iterations
Derive-AesKeyWithPbkdf2 -Etype 20 -PasswordPlain "password" -SaltBytes $salt
```

### Manual Override
```powershell
# Custom iteration count
New-KeytabFromPassword -Iterations 100000 -IncludeEtype 19,20
```

## Examples

### Basic AES-SHA1 Usage
```powershell
$password = ConvertTo-SecureString "MyPassword123!" -AsPlainText -Force
New-KeytabFromPassword -SamAccountName user1 -Realm EXAMPLE.COM -Password $password
```

### Modern AES-SHA2 Usage
```powershell
$password = ConvertTo-SecureString "MyPassword123!" -AsPlainText -Force
New-KeytabFromPassword -SamAccountName user1 -Realm EXAMPLE.COM -Password $password `
  -IncludeEtype 19,20 -Iterations 32768
```

### Windows Compatibility Mode
```powershell
New-KeytabFromPassword -Principal "HTTP/web01.example.com@EXAMPLE.COM" `
  -Password $password -Compatibility Windows -IncludeEtype 18
```

# SEE ALSO
- about_STKeytab_Security
- about_STKeytab_Interop
- New-KeytabFromPassword
- RFC 3962 (AES-SHA1)
- RFC 8009 (AES-SHA2)
- RFC 2898 (PBKDF2)
