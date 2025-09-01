---
external help file: STKeytab-help.xml
Module Name: STKeytab
online version:
schema: 2.0.0
---

# New-Keytab

## SYNOPSIS
Create a keytab for an AD user, computer, or krbtgt using replication-safe key extraction.

## SYNTAX

```
New-Keytab [-SamAccountName] <String> [[-Type] <String>] [[-Domain] <String>] [[-IncludeEtype] <Object[]>]
 [[-ExcludeEtype] <Object[]>] [[-OutputPath] <String>] [[-SummaryPath] <String>] [[-Server] <String>]
 [[-Justification] <String>] [[-Credential] <PSCredential>] [[-EnvFile] <String>] [-RestrictAcl] [-Force]
 [-PassThru] [-Summary] [-AcknowledgeRisk] [-VerboseDiagnostics] [-SuppressWarnings]
 [[-FixedTimestampUtc] <DateTime>] [-IncludeShortHost] [[-AdditionalSpn] <String[]>] [-IncludeLegacyRC4]
 [-AESOnly] [-AllowDeadCiphers] [-ModernCrypto] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION
Front-door cmdlet that discovers principal type and extracts Kerberos keys via directory replication.
Defaults to AES-only encryption types.
Deterministic output is available when -FixedTimestampUtc is
provided.
Supports JSON summaries and PassThru.
krbtgt extractions are gated and require -AcknowledgeRisk
with a documented justification.

## EXAMPLES

### EXAMPLE 1
```
New-Keytab -SamAccountName web01$ -Type Computer -OutputPath .\web01.keytab -IncludeShortHost -Summary
Create a computer keytab including short HOST/ SPNs and write a summary JSON.
```

### EXAMPLE 2
```
New-Keytab -SamAccountName user1 -IncludeEtype 18,17 -ExcludeEtype 23 -OutputPath .\user1.keytab -FixedTimestampUtc (Get-Date '2020-01-01Z')
Create a deterministic user keytab with AES types only.
```

### EXAMPLE 3
```
New-Keytab -SamAccountName web01$ -Type Computer -ModernCrypto -OutputPath .\web01-modern.keytab -Summary
Create a computer keytab with modern AES-SHA2 encryption types and write a summary JSON.
```

## PARAMETERS

### -SamAccountName
The account's sAMAccountName (user, computer$, or krbtgt).

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Type
Principal type.
Auto infers from name; User or Computer can be forced.
krbtgt is detected automatically.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: Auto
Accept pipeline input: False
Accept wildcard characters: False
```

### -Domain
Domain NetBIOS or FQDN.
When omitted, attempts discovery.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -IncludeEtype
Encryption type IDs to include.
Default: 18,17 (AES-256, AES-128).
RC4 (23) is not included by default and
must be explicitly opted-in when legacy compatibility is required.

```yaml
Type: System.Object[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: @(18,17)
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -ExcludeEtype
Encryption type IDs to exclude.

```yaml
Type: System.Object[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -OutputPath
Path to write the keytab file.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -SummaryPath
Optional path to write a JSON summary.
Defaults next to OutputPath when summaries are requested.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: JsonSummaryPath

Required: False
Position: 7
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Server
Domain Controller to target for replication (optional).

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 8
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Justification
Free-text justification string for auditing high-risk operations.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 9
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Credential
Alternate credentials to access AD/replication.

```yaml
Type: System.Management.Automation.PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 10
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -EnvFile
Optional .env file to load credentials from.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 11
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -RestrictAcl
Apply a user-only ACL to outputs.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force
Overwrite existing OutputPath.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -PassThru
Return a small object summary in addition to writing files.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Summary
Write a JSON summary file.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -AcknowledgeRisk
{{ Fill AcknowledgeRisk Description }}

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -VerboseDiagnostics
Emit additional diagnostics during extraction.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -SuppressWarnings
Suppress risk warnings.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -FixedTimestampUtc
Use a fixed timestamp for deterministic output.
Determinism is opt-in and not auto-populated.

```yaml
Type: System.DateTime
Parameter Sets: (All)
Aliases:

Required: False
Position: 12
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IncludeShortHost
For computer accounts, include HOST/shortname SPN.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -AdditionalSpn
Additional SPNs (service/host) to include for computer accounts.

```yaml
Type: System.String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 13
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IncludeLegacyRC4
Includes the RC4 encryption type (23).

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -AESOnly
Restrict to AES encryption types only (18,17).

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -AllowDeadCiphers
Allow the use of deprecated or weak encryption types (other than 17,18,19,20,23).
No support guaranteed.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ModernCrypto
Include modern AES-SHA2 encryption types (19,20) in addition to defaults.
Requires newer Kerberos implementations.

```yaml
Type: System.Management.Automation.SwitchParameter
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
Type: System.Management.Automation.SwitchParameter
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
Type: System.Management.Automation.SwitchParameter
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
Type: System.Management.Automation.ActionPreference
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

### System.String (SamAccountName) via property name.
## OUTPUTS

### System.String (OutputPath) or summary object when -PassThru.
## NOTES

## RELATED LINKS
