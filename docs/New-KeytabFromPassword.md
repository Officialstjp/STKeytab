---
external help file: STKeytab-help.xml
Module Name: STKeytab
online version:
schema: 2.0.0
---

# New-KeytabFromPassword

## SYNOPSIS
Generate a keytab from a password using MIT/Heimdal/Windows salt policies (AES only).

## SYNTAX

### User (Default)
```
New-KeytabFromPassword [-Realm] <String> [-SamAccountName] <String> [[-Password] <SecureString>]
 [-Credential <PSCredential>] [[-Compatibility] <String>] [[-IncludeEtype] <Object[]>]
 [[-ExcludeEtype] <Object[]>] [[-OutputPath] <String>] [[-JsonSummaryPath] <String>] [[-Kvno] <Int32>]
 [[-Iterations] <Int32>] [-RestrictAcl] [-Force] [-Summary] [-PassThru] [-IncludeLegacyRC4]
 [-FixedTimestampUtc <DateTime>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Principal
```
New-KeytabFromPassword [-Realm] <String> [-Principal] <String> [[-Compatibility] <String>]
 [[-IncludeEtype] <Object[]>] [[-ExcludeEtype] <Object[]>] [[-OutputPath] <String>]
 [[-JsonSummaryPath] <String>] [[-Kvno] <Int32>] [[-Iterations] <Int32>] [-RestrictAcl] [-Force] [-Summary]
 [-PassThru] [-IncludeLegacyRC4] [-FixedTimestampUtc <DateTime>] [-ProgressAction <ActionPreference>] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Derives AES keys (etype 17/18) via PBKDF2-HMACSHA1 and writes a MIT v0x0502 keytab.
Defaults to AES-only, safe salt policy and supports deterministic timestamps for tests.

## EXAMPLES

### EXAMPLE 1
```
New-KeytabFromPassword -Realm CONTOSO.COM -SamAccountName user1 -Password (Read-Host -AsSecureString) -OutputPath .\user1.keytab
Generate a user keytab from a password with default AES types.
```

### EXAMPLE 2
```
New-KeytabFromPassword -Realm CONTOSO.COM -Principal http/web01.contoso.com@CONTOSO.COM -Credential (Get-Credential) -IncludeEtype 18 -Kvno 3 -OutputPath .\http.keytab
Generate a service keytab with AES-256 only and KVNO 3.
```

## PARAMETERS

### -Realm
Kerberos realm (usually the AD domain in uppercase) (Pos 1).

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SamAccountName
Account name when deriving a user or computer principal (use Principal for service names) (Pos 2).

```yaml
Type: System.String
Parameter Sets: User
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Principal
Full principal (e.g., http/web01.contoso.com@CONTOSO.COM) for service principals (Pos 2).

```yaml
Type: System.String
Parameter Sets: Principal
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Password
SecureString password to derive keys from.
Alternatively use -Credential (Pos 3).

```yaml
Type: System.Security.SecureString
Parameter Sets: User
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
PSCredential; the password part is used if -Password not provided.

```yaml
Type: System.Management.Automation.PSCredential
Parameter Sets: User
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Compatibility
Salt policy for string-to-key: MIT, Heimdal, or Windows (Pos 4).

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: Comp

Required: False
Position: 4
Default value: MIT
Accept pipeline input: False
Accept wildcard characters: False
```

### -IncludeEtype
Encryption types to include.
Defaults to AES-256 and AES-128 (18,17) (Pos 5).

```yaml
Type: System.Object[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludeEtype
Encryption types to exclude from selection (Pos 6).

```yaml
Type: System.Object[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OutputPath
Path to write the generated keytab (Pos 7).

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -JsonSummaryPath
Path to write a JSON summary; defaults next to OutputPath when -Summary or -PassThru is specified (Pos 8).

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 8
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Kvno
Key Version Number to stamp into entries (default 1) (Pos 9).

```yaml
Type: System.Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 9
Default value: 1
Accept pipeline input: False
Accept wildcard characters: False
```

### -Iterations
PBKDF2 iteration count (default 4096) (Pos 10).

```yaml
Type: System.Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 10
Default value: 4096
Accept pipeline input: False
Accept wildcard characters: False
```

### -RestrictAcl
Apply a user-only ACL on outputs.

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
Overwrite OutputPath if it exists.

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
Emit a JSON summary file.

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
Return a summary object in addition to writing files.

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

### -FixedTimestampUtc
Use a fixed timestamp for deterministic output.

```yaml
Type: System.DateTime
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
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

### None. Parameters are bound by name.
## OUTPUTS

### System.String (OutputPath) or summary object when -PassThru.
## NOTES

## RELATED LINKS
