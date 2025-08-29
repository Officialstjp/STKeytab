---
external help file: STKeytab-help.xml
Module Name: STKeytab
online version:
schema: 2.0.0
---

# Reset-AccountPasswordWithKeytab

## SYNOPSIS
Reset an AD account password and generate a corresponding keytab in one atomic operation.

## SYNTAX

```
Reset-AccountPasswordWithKeytab [-SamAccountName] <String> [-Realm <String>] [-NewPassword <SecureString>]
 [-Kvno <Int32>] [-Compatibility <String>] [-IncludeEtype <Object[]>] [-ExcludeEtype <Object[]>]
 [-OutputPath <String>] [-Domain <String>] [-Server <String>] [-Credential <PSCredential>] [-AcknowledgeRisk]
 -Justification <String> [-WhatIfOnly] [-UpdateSupportedEtypes <Int32[]>] [-AESOnly] [-IncludeLegacyRC4]
 [-AllowDeadCiphers] [-RestrictAcl] [-Force] [-JsonSummaryPath <String>] [-Summary] [-PassThru]
 [-FixedTimestampUtc <DateTime>] [-SuppressWarnings] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION
Securely rotates an account's password to a strong random value, updates Active Directory,
derives the corresponding Kerberos keys using the new password, and produces a keytab file.
This ensures the keytab matches the account's actual password state without manual coordination.
Only supports user accounts.

Uses BigBrother policy for etype selection with AES-only enforcement on the password derivation path.
Requires explicit risk acknowledgment due to the high-impact nature of password changes.

## EXAMPLES

### EXAMPLE 1
```
Reset-AccountPasswordWithKeytab -SamAccountName svc-web -AcknowledgeRisk -Justification "Quarterly rotation" -OutputPath .\svc-web.keytab
```

Resets the password for svc-web and generates a corresponding keytab.

### EXAMPLE 2
```
Reset-AccountPasswordWithKeytab -SamAccountName svc-app -WhatIfOnly -AcknowledgeRisk -Justification "Planning rotation"
```

Shows what would be done without making changes.

## PARAMETERS

### -SamAccountName
The account's sAMAccountName to reset password for.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Realm
Kerberos realm name.
If omitted, derives from the domain.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NewPassword
Specific password to set.
If omitted, generates a cryptographically strong random password.

```yaml
Type: SecureString
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Kvno
Key version number to use in the keytab.
If omitted, predicts the post-reset KVNO.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -Compatibility
Salt generation policy: MIT, Heimdal, or Windows (default).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: Windows
Accept pipeline input: False
Accept wildcard characters: False
```

### -IncludeEtype
Encryption types to include.
Default: AES256, AES128.

```yaml
Type: Object[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: @(18,17)
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludeEtype
Encryption types to exclude.

```yaml
Type: Object[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OutputPath
Path for the generated keytab file.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Domain
Domain to target for AD operations.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Server
Specific domain controller to use.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
Alternate credentials for AD operations.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AcknowledgeRisk
Required acknowledgment that this operation changes the account password.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Justification
Required justification for audit logging.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIfOnly
Show operation plan without executing changes.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -UpdateSupportedEtypes
Update the account's msDS-SupportedEncryptionTypes attribute.

```yaml
Type: Int32[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AESOnly
Restrict to AES encryption types only.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -IncludeLegacyRC4
Include RC4 encryption type (not applicable for password path - AES only).

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -AllowDeadCiphers
Allow obsolete encryption types (not applicable for password path - AES only).

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -RestrictAcl
Apply user-only ACL to output files.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force
Overwrite existing output files.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -JsonSummaryPath
{{ Fill JsonSummaryPath Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Summary
Generate JSON summary file.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -PassThru
Return operation result object.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -FixedTimestampUtc
Use fixed timestamp for deterministic output.

```yaml
Type: DateTime
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SuppressWarnings
{{ Fill SuppressWarnings Description }}

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
{{ Fill ProgressAction Description }}

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
