---
external help file: STKeytab-help.xml
Module Name: STKeytab
online version:
schema: 2.0.0
---

# Read-Keytab

## SYNOPSIS
Parse a keytab file into structured entries.

## SYNTAX

```
Read-Keytab [-Path] <String> [-RevealKeys] [-MaxKeyHex <Int32>] [-ProgressAction <ActionPreference>]
 [<CommonParameters>]
```

## DESCRIPTION
Robust parser for MIT keytab v0x0502.
Can reveal raw key bytes for merge scenarios.

## EXAMPLES

### EXAMPLE 1
```
Read-Keytab -Path .\user.keytab
Parse a keytab and return entries.
```

## PARAMETERS

### -Path
Path to the keytab file (Pos 1).

```yaml
Type: String
Parameter Sets: (All)
Aliases: FullName, PSPath, FilePath

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -RevealKeys
Include raw key bytes in each entry's RawKey property (sensitive).

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

### -MaxKeyHex
Max length of the displayed hex string for masked key preview.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 64
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

### System.Object[]. Array of parsed entry objects.
## NOTES

## RELATED LINKS
