---
external help file: STKeytab-help.xml
Module Name: STKeytab
online version:
schema: 2.0.0
---

# ConvertTo-KeytabJson

## SYNOPSIS
Convert a keytab file to canonical JSON (keys masked by default).

## SYNTAX

```
ConvertTo-KeytabJson [-Path] <String> [-OutputPath <String>] [-RevealKeys] [-IgnoreTimestamp]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Parses a keytab and emits a canonical JSON representation for diffs and tooling.
Keys are masked by default; pass -RevealKeys to include raw key bytes.
Use
-IgnoreTimestamp to omit timestamp variance from the model.

## EXAMPLES

### EXAMPLE 1
```
ConvertTo-KeytabJson -Path .\in.keytab -OutputPath .\in.json
Write canonical JSON to a file.
```

### EXAMPLE 2
```
ConvertTo-KeytabJson -Path .\in.keytab -RevealKeys | Out-File .\in.revealed.json
Output JSON with key material to the pipeline and save to a file.
```

## PARAMETERS

### -Path
Path to the input keytab file.

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
Path to write the resulting JSON.
If omitted, JSON is written to the pipeline.

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

### -RevealKeys
Include raw key bytes in the JSON.
Sensitive-avoid in source control.

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

### -IgnoreTimestamp
Exclude timestamps from the canonical model.

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

### System.String (OutputPath) when -OutputPath is provided, otherwise JSON text.
## NOTES

## RELATED LINKS
