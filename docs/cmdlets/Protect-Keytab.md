---
external help file: STKeytab-help.xml
Module Name: STKeytab
online version:
schema: 2.0.0
---

# Protect-Keytab

## SYNOPSIS
Protect a keytab file at rest using Windows DPAPI.

## SYNTAX

```
Protect-Keytab [-InputPath] <String> [[-OutputPath] <String>] [-Scope <String>] [-Entropy <String>]
 [-EntropySecure <SecureString>] [-Force] [-DeletePlaintext] [-RestrictAcl]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Uses DPAPI (CurrentUser or LocalMachine scope) to encrypt a keytab file.
Optional
additional entropy can be provided.
Can restrict ACL on the output and delete the
plaintext original after successful protection.

## EXAMPLES

### EXAMPLE 1
```
Protect-Keytab -Path .\user.keytab -OutputPath .\user.keytab.dpapi -Scope CurrentUser -RestrictAcl
Protect a keytab with DPAPI in the current-user scope and set a restrictive ACL.
```

## PARAMETERS

### -InputPath
{{ Fill InputPath Description }}

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: Path, In, FullName, FilePath

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -OutputPath
Destination path for the protected file.
Defaults to \<Path\>.dpapi (Pos 2).

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: Out, Output, OutFile

Required: False
Position: 2
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Scope
DPAPI scope: CurrentUser (default) or LocalMachine.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: CurrentUser
Accept pipeline input: False
Accept wildcard characters: False
```

### -Entropy
Optional additional entropy string to bind to the protection.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EntropySecure
{{ Fill EntropySecure Description }}

```yaml
Type: System.Security.SecureString
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
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

### -DeletePlaintext
Remove the original plaintext file after successful protection.

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

### -RestrictAcl
Apply a user-only ACL to the output file.

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

### System.String (file path) or objects with FilePath/FullName properties.
## OUTPUTS

### System.String. Returns the OutputPath written.
## NOTES

## RELATED LINKS
