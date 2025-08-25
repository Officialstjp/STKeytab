---
external help file: STKeytab-help.xml
Module Name: Stkeytab
online version:
schema: 2.0.0
---

# Test-Keytab

## SYNOPSIS
Validate a keytab file and report stats.

## SYNTAX

```
Test-Keytab [-Path] <String> [-Detailed] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Lightweight validation that counts entries and flags unknown encryption types.

## EXAMPLES

### EXAMPLE 1
```
Test-Keytab -Path .\user.keytab
Returns $true when the keytab parses successfully.
```

## PARAMETERS

### -Path
Path to the keytab file (Pos 1).

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: FullName, PSPath, FilePath

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Detailed
Return a detailed object with counts and warnings instead of a boolean.

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

### System.Boolean by default; PSCustomObject with details when -Detailed.
## NOTES

## RELATED LINKS
