# STKeytab_Security
## about_STKeytab_Security

# SHORT DESCRIPTION
Security model, encryption defaults, risk controls, and access requirements for the STKeytab module.

# LONG DESCRIPTION
The STKeytab module implements a security-first approach with safe defaults, explicit risk acknowledgment for sensitive operations, and strong encryption preferences.

## Encryption Defaults
The module defaults to AES-only encryption for maximum security:

- AES256-CTS-HMAC-SHA1-96 (etype 18): Primary encryption type
- AES128-CTS-HMAC-SHA1-96 (etype 17): Secondary encryption type
- RC4-HMAC (etype 23): Excluded by default, requires explicit opt-in

RC4 encryption is considered legacy and cryptographically weak. It is only included when explicitly requested via -IncludeLegacyRC4 switch or -IncludeEtype parameter to support legacy interoperability scenarios.

## Sensitive Operation Controls
Several operations handle sensitive data or have high security impact:

### RevealKeys Flag
Commands that can expose key material mask key bytes by default. The -RevealKeys parameter displays actual key material and emits a warning about sensitive data exposure.

### Risk Acknowledgment Gates
High-impact operations require explicit acknowledgment:
- krbtgt operations require -AcknowledgeRisk and -Justification
- Merge operations with krbtgt keys require risk acknowledgment

## Access Requirements
Replication-based extraction requires DCSync-equivalent permissions:
- Replicating Directory Changes
- Replicating Directory Changes All
- Replicating Directory Changes In Filtered Set

## DPAPI AT REST
The module supports protecting keytabs using Windows Data Protection API:
- CurrentUser vs LocalMachine scopes; portability considerations
- Optional entropy via -EntropySecure parameter for additional security
- ACL hardening with -RestrictAcl for user-only file permissions

## PRACTICES
Best practices for secure keytab handling:
- Store keytabs with restrictive file permissions
- Avoid including -RevealKeys output in logs or source control
- Use DPAPI protection for at-rest encryption
- Follow privileged access management policies for DCSync permissions

# EXAMPLES
## Example 1: AES-Only Generation
```
New-Keytab -SamAccountName WEB01$ -Domain contoso.com -OutputPath .\web01.keytab -Force
```

Generates keytab with AES256 and AES128 encryption only (default behavior).

## Example 2: Secure Protection
```
Protect-Keytab -Path .\web01.keytab -RestrictAcl -DeletePlaintext -EntropySecure (Read-Host -AsSecureString "Entropy")
```

Protects keytab with DPAPI using secure entropy and restricted ACLs.

# NOTE
Keytab files contain sensitive cryptographic material equivalent to passwords. Store them securely with appropriate file system permissions and consider DPAPI protection.

# TROUBLESHOOTING NOTE
"RC4 not included in output": This is expected behavior. Use -IncludeLegacyRC4 if RC4 support is required.

"Access denied for replication": Verify DCSync permissions are granted on the domain naming context.

## SEE ALSO
- about_STKeytab_DPAPI
- about_STKeytab
- Protect-Keytab
- Unprotect-Keytab
- New-Keytab

# KEYWORDS
- AES encryption
- RC4 legacy
- DCSync permissions
- DPAPI protection
- Risk acknowledgment
- Sensitive data
- krbtgt security
