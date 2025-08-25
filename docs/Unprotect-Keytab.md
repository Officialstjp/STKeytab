---
external help file: STKeytab-help.xml
Module Name: Stkeytab
online version:
schema: 2.0.0
---

# Unprotect-Keytab

## SYNOPSIS
Decrypt a DPAPI-protected keytab file.

## SYNTAX

```
Unprotect-Keytab [-Path] <String> [-OutputPath] <String> [-Scope <String>] [-Entropy <String>] [-Force]
 [-RestrictAcl] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Uses DPAPI to decrypt a previously protected keytab file.
Defaults output name by
stripping .dpapi suffix when present.
Can restrict ACL on the output.

## EXAMPLES

### EXAMPLE 1
```
Unprotect-Keytab -Path .\user.keytab.dpapi -OutputPath .\user.keytab -Scope CurrentUser
Decrypt a DPAPI-protected keytab into a plaintext keytab.
```

## PARAMETERS

### -Path
Path to the DPAPI-protected input file (Pos 1).

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: In, FullName, FilePath

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -OutputPath
Destination for the decrypted keytab.
Defaults to removing .dpapi extension (Pos 2).

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: Out, Output, OutFile

Required: True
Position: 2
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Scope
DPAPI scope used for decryption: CurrentUser (default) or LocalMachine.

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
Additional entropy string that was used during protection (if any).

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
