---
external help file: STKeytab-help.xml
Module Name: STKeytab
online version:
schema: 2.0.0
---

# ConvertFrom-KeytabJson

## SYNOPSIS
Convert canonical JSON back into a keytab file (requires key bytes).

## SYNTAX

```
ConvertFrom-KeytabJson [-JsonPath] <String> [-OutputPath <String>] [-Force] [-FixedTimestampUtc <DateTime>]
 [-RestrictAcl] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Reads canonical JSON as produced by ConvertTo-KeytabJson -RevealKeys and reconstructs
a MIT v0x0502 keytab.
Requires key bytes to be present in JSON.
Can restrict ACL on
output and support deterministic timestamps for reproducible builds.

## EXAMPLES

### EXAMPLE 1
```
ConvertFrom-KeytabJson -JsonPath .\entry.json -OutputPath .\out.keytab -Force
Reconstruct a keytab from JSON, overwriting the destination if present.
```

## PARAMETERS

### -JsonPath
Path to the canonical JSON file.

```yaml
Type: String
Parameter Sets: (All)
Aliases: FullName, FilePath, PSPath

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -OutputPath
Output keytab path to write.

```yaml
Type: String
Parameter Sets: (All)
Aliases: OutFile, Out

Required: False
Position: Named
Default value: None
Accept pipeline input: False
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

### -FixedTimestampUtc
Use a fixed timestamp for written entries for deterministic output.

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

### -RestrictAcl
Apply a user-only ACL on the output file.

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

### System.String (file path) or objects with FilePath/FullName properties.
## OUTPUTS

### System.String. Returns the OutputPath written.
## NOTES

## RELATED LINKS
