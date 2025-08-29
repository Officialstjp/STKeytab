---
external help file: STKeytab-help.xml
Module Name: STKeytab
online version:
schema: 2.0.0
---

# Compare-Keytab

## SYNOPSIS
Compare two keytab files with optional timestamp-insensitive and key-byte comparisons.

## SYNTAX

```
Compare-Keytab [-ReferencePath] <String> [-CandidatePath] <String> [-IgnoreTimestamp] [-IgnoreKeyBytes]
 [-RevealKeys] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Reads both keytabs, canonicalizes their entries (optionally ignoring timestamps),
and compares structure and, by default, key bytes.
Returns an object with an
Equal flag and a Differences collection describing any mismatches.
Use -IgnoreKeyBytes
for structure-only comparisons.
Use -RevealKeys to include sensitive key bytes in the
diff details (disabled by default for safety).

## EXAMPLES

### EXAMPLE 1
```
Compare-Keytab -ReferencePath .\tests\output\user.keytab -CandidatePath .\tests\output\roundtrip.keytab -IgnoreTimestamp
Compare two keytabs while ignoring timestamps.
```

### EXAMPLE 2
```
Compare-Keytab -ReferencePath a.keytab -CandidatePath b.keytab -IgnoreKeyBytes
Perform a structure-only comparison (no key-byte check).
```

## PARAMETERS

### -ReferencePath
Path to the baseline (reference) keytab.

```yaml
Type: String
Parameter Sets: (All)
Aliases: FullNameRef, FilePathRef

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -CandidatePath
Path to the candidate keytab to compare against the reference.

```yaml
Type: String
Parameter Sets: (All)
Aliases: FullNameCand, FilePathCand

Required: True
Position: 2
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -IgnoreTimestamp
Ignore per-entry timestamps when comparing (useful for reproducible checks).

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

### -IgnoreKeyBytes
Only compare structure (principal, name type, encryption type, KVNO).
Do not compare key bytes.

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

### -RevealKeys
Include raw key bytes in difference output.
Sensitive-avoid in shared logs.

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

### System.String (file paths) or objects with FilePathRef/FilePathCand properties.
## OUTPUTS

### PSCustomObject with properties Equal (bool) and Differences (collection).
## NOTES

## RELATED LINKS
