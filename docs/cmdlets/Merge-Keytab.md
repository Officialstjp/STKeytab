---
external help file: STKeytab-help.xml
Module Name: STKeytab
online version:
schema: 2.0.0
---

# Merge-Keytab

## SYNOPSIS
Merge multiple keytabs into a single file with de-duplication and safety checks.

## SYNTAX

```
Merge-Keytab [[-InputPaths] <String[]>] [[-OutputPath] <String>] [-Force] [-RestrictAcl] [-AcknowledgeRisk]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Reads input keytabs, de-duplicates entries across KVNO and encryption types, and
writes a consolidated keytab.
Blocks merges containing krbtgt entries unless
-AcknowledgeRisk is provided.

## EXAMPLES

### EXAMPLE 1
```
Merge-Keytab -InputPaths a.keytab,b.keytab -OutputPath merged.keytab -Force
Merge two keytabs into a single file, overwriting the destination if present.
```

## PARAMETERS

### -InputPaths
One or more paths to input keytabs to merge.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: Input, In

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -OutputPath
Destination path of the merged keytab.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Output, Out

Required: False
Position: 2
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Force
Overwrite OutputPath if it exists.

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
Apply a user-only ACL on the merged output file.

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

### -AcknowledgeRisk
Required to proceed when krbtgt entries are detected in inputs.

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

### System.String[] (file paths) or objects with Input/Output properties.
## OUTPUTS

### System.String. Returns the OutputPath written.
## NOTES

## RELATED LINKS
