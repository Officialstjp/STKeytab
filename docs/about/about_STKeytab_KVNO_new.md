# STKeytab_KVNO
## about_STKeytab_KVNO

# SHORT DESCRIPTION
Key Version Number (KVNO) handling, discovery, and multi-version scenarios in keytab generation.

# LONG DESCRIPTION
Key Version Number (KVNO) is a critical component of Kerberos authentication that tracks the version of cryptographic keys for a principal. The STKeytab module handles KVNO in different ways depending on the generation method and principal type.

## What is KVNO
KVNO serves several important purposes in Kerberos:

- Version tracking: Identifies which version of a principal's key is being used
- Cache invalidation: Helps clients detect when cached credentials are stale
- Key rollover: Enables graceful transitions during password/key changes
- Replay protection: Prevents reuse of old authentication material

## KVNO Discovery Methods
The module uses different approaches to determine KVNO values:

### Replication-Based Discovery (New-Keytab)
When extracting keys via Active Directory replication:

- Current KVNO: Retrieved from msDS-KeyVersionNumber attribute
- Automatic detection: No manual KVNO specification required
- Multi-version support: Can include previous KVNO values for compatibility

### Caller-Specified (New-KeytabFromPassword)
When generating from passwords:

- Explicit specification: Caller provides KVNO via -Kvno parameter
- Default value: Uses KVNO 1 when not specified
- Manual control: Full control over versioning for testing scenarios

## krbtgt Special Handling
The krbtgt account requires special KVNO considerations:

### Multi-KVNO Support
krbtgt keys may need multiple KVNO values for compatibility:

- Current keys: Active KVNO for new ticket issuance
- Previous keys: KVNO-1 for validating recently issued tickets
- Older keys: KVNO-2 for extended compatibility windows

### Include Flags
- -IncludeOldKvno: Includes KVNO-1 keys
- -IncludeOlderKvno: Includes KVNO-2 keys
- Risk gates: Requires -AcknowledgeRisk due to security implications

## KVNO in Different Scenarios
Understanding when and how KVNO changes helps predict authentication behavior:

### User Account Password Changes
- KVNO increments when password is changed via AD tools
- Old KVNO values become invalid for new authentication
- Existing tickets remain valid until expiration

### Computer Account Password Changes
- Automatic changes: AD changes computer passwords automatically (usually every 30 days)
- Manual changes: May occur during domain join or administrative actions
- Service impact: Services using old keytabs will fail authentication

### Service Account Management
- Managed Service Accounts: KVNO changes managed automatically by AD
- Manual service accounts: KVNO changes when administrator changes password
- Coordination required: Keytab deployment must match password changes

## RISKS
KVNO mismatches can cause authentication failures and security issues:

### Common KVNO Problems
- Stale keytabs: Keytab KVNO doesn't match current AD value
- Cache poisoning: Clients cache wrong KVNO information
- Race conditions: Password changes during keytab generation
- Rollback scenarios: Restoring old KVNO values inadvertently

### Mitigation Strategies
- Test authentication after keytab deployment
- Monitor authentication logs for KVNO-related errors
- Coordinate password changes with keytab updates
- Use Compare-Keytab to verify KVNO consistency

# EXAMPLES
## Example 1: Current KVNO Discovery
```
New-Keytab -SamAccountName service$ -Domain contoso.com -OutputPath .\current.keytab -PassThru
```

Extracts current KVNO from Active Directory automatically.

## Example 2: Multi-KVNO krbtgt Keytab
```
New-Keytab -SamAccountName krbtgt -Domain contoso.com -IncludeOldKvno -IncludeOlderKvno -AcknowledgeRisk -Justification "DC migration compatibility" -OutputPath .\krbtgt-multi.keytab -Force
```

Creates krbtgt keytab with current, previous, and older KVNO values.

## Example 3: Explicit KVNO Control
```
New-KeytabFromPassword -SamAccountName testuser -Realm LAB.LOCAL -Password $pwd -Kvno 5 -OutputPath .\test-kvno5.keytab -Force
```

Generates keytab with specific KVNO value for testing.

## Example 4: KVNO Comparison
```
$keytab1 = Read-Keytab -Path .\server1.keytab
$keytab2 = Read-Keytab -Path .\server2.keytab
$keytab1.Entries | Group-Object Kvno | Select-Object Name, Count
$keytab2.Entries | Group-Object Kvno | Select-Object Name, Count
```

Analyzes KVNO distribution across keytab entries.

# NOTE
KVNO values in Active Directory typically start at 1 and increment with each password change. The module preserves AD KVNO values during replication-based extraction to maintain authentication compatibility.

For password-based generation, choose KVNO values that match the target environment's expectations. Some systems expect KVNO 1, while others may have specific versioning schemes.

# TROUBLESHOOTING NOTE
"Authentication fails with correct password": Check for KVNO mismatch between keytab and current AD value using Get-ADObject with msDS-KeyVersionNumber property.

"krbtgt authentication intermittent": Ensure keytab includes sufficient KVNO versions (-IncludeOldKvno) to handle tickets issued before key changes.

"KVNO rollback detected": This may indicate AD restoration or replication issues. Verify domain controller consistency and replication health.

"Multiple KVNO values in single keytab": This is normal for krbtgt and during transition periods. Use Read-Keytab to examine KVNO distribution.

# SEE ALSO
- about_STKeytab
- about_STKeytab_Interop
- New-Keytab
- New-KeytabFromPassword
- Read-Keytab
- Compare-Keytab

# KEYWORDS
- Key Version Number
- KVNO
- Password changes
- krbtgt multi-version
- Authentication compatibility
- Cache invalidation
- Key rollover
- Version tracking
