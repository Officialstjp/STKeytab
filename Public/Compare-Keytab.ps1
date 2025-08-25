<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Compare-Keytab {
    <#
    .SYNOPSIS
    Compare two keytab files with optional timestamp-insensitive and key-byte comparisons.

    .DESCRIPTION
    Reads both keytabs, canonicalizes their entries (optionally ignoring timestamps), and compares
    structure and key bytes (by default). Returns an object with an Equal flag and a Differences
    collection describing mismatches. Use -IgnoreKeyBytes for structure-only comparisons. Use
    -RevealKeys to include sensitive key bytes in the diff (avoid in logs and CI artifacts).

        .PARAMETER ReferencePath
        Path to the baseline (reference) keytab.

        .PARAMETER CandidatePath
        Path to the candidate keytab to compare against the reference.

        .PARAMETER IgnoreTimestamp
        Ignore per-entry timestamps when comparing (useful for reproducible checks).

        .PARAMETER IgnoreKeyBytes
        Only compare structure (principal, name type, encryption type, KVNO). Do not compare key bytes.

        .PARAMETER RevealKeys
        Include raw key bytes in difference output. Sensitive—avoid in shared logs.

        .INPUTS
        System.String (file paths) or objects with FilePathRef/FilePathCand properties.

        .OUTPUTS
        PSCustomObject with properties Equal (bool) and Differences (collection).

        .EXAMPLE
        Compare-Keytab -ReferencePath .\tests\output\user.keytab -CandidatePath .\tests\output\roundtrip.keytab -IgnoreTimestamp
        Compare two keytabs while ignoring timestamps.

        .EXAMPLE
        Compare-Keytab -ReferencePath a.keytab -CandidatePath b.keytab -IgnoreKeyBytes
        Perform a structure-only comparison (no key-byte check).

        .NOTES
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position=0)]
        [Alias('FullNameRef','FilePathRef')]
        [ValidateNotNullOrEmpty()]
        [string]$ReferencePath,

        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position=1)]
        [Alias('FullNameCand','FilePathCand')]
        [ValidateNotNullOrEmpty()]
        [string]$CandidatePath,

        [switch]$IgnoreTimestamp,
        [switch]$IgnoreKeyBytes,   # structure-only compare
        [switch]$RevealKeys        # controls whether key bytes are included in diff output
    )
    begin {
        Set-StrictMode -Version Latest
        if ($RevealKeys) { Write-Warning 'RevealKeys is sensitive: raw key bytes may appear in differences.' }

        function New-JoinKey {
            param([pscustomobject]$E)
            '{0}|{1}|{2}|etype={3}|kvno={4}' -f $E.Realm, ($E.Components -join '/'), $E.NameType, $E.Etype, $E.Kvno
        }
        function Sanitize-ForOutput {
            param([pscustomobject]$E, [bool]$IncludeKeys)
            if ($IncludeKeys) { return $E }
            # Return a copy without Key bytes
            [pscustomobject]@{
                Realm        = $E.Realm
                Components   = @($E.Components)
                NameType     = $E.NameType
                Kvno         = $E.Kvno
                Etype        = $E.Etype
                TimestampUtc = $E.TimestampUtc
                Key          = $null
            }
        }
    }
    process {
        $readKeys = -not $IgnoreKeyBytes
        $refParsed  = Read-Keytab -Path $ReferencePath -RevealKeys:$readKeys
        $candParsed = Read-Keytab -Path $CandidatePath  -RevealKeys:$readKeys
        $refEntries  = if ($refParsed -is [System.Array]) { $refParsed } elseif ($refParsed.Entries) { $refParsed.Entries } else { @($refParsed) }
        $candEntries = if ($candParsed -is [System.Array]) { $candParsed } elseif ($candParsed.Entries) { $candParsed.Entries } else { @($candParsed) }

        $ref  = ConvertEntriesTo-KeytabCanonicalModel -Entries $refEntries  -IgnoreTimestamp:$IgnoreTimestamp
        $cand = ConvertEntriesTo-KeytabCanonicalModel -Entries $candEntries -IgnoreTimestamp:$IgnoreTimestamp

        $mapRef  = @{}; foreach ($e in $ref)  { $mapRef[(New-JoinKey $e)] = $e }
        $mapCand = @{}; foreach ($e in $cand) { $mapCand[(New-JoinKey $e)] = $e }

        $allKeys = @($mapRef.Keys + $mapCand.Keys | Sort-Object -Unique)
        $diffs = New-Object System.Collections.Generic.List[object]

        $allKeys = @($mapRef.Keys + $mapCand.Keys | Sort-Object -Unique)
        $diffs = New-Object System.Collections.Generic.List[object]

        foreach ($k in $allKeys) {
            $a = $mapRef[$k]; $b = $mapCand[$k]
            if ($null -eq $a -and $null -ne $b) {
                $diffs.Add([pscustomobject]@{
                    Key     =$k
                    Status  ='OnlyInCandidate'
                    Detail  =(Sanitize-ForOutput -E $b -IncludeKeys:$RevealKeys)
                }) | Out-Null; continue
            }
            if ($null -eq $b -and $null -ne $a) {
                $diffs.Add([pscustomobject]@{
                    Key     =$k
                    Status  ='OnlyInReference'
                    Detail  =(Sanitize-ForOutput -E $a -IncludeKeys:$RevealKeys)
                }) | Out-Null; continue
            }

            if (-not $IgnoreKeyBytes) {
                $ka = $a.Key; $kb = $b.Key
                $eq = ($null -ne $ka -and $null -ne $kb -and $ka.Length -eq $kb.Length -and [System.Linq.Enumerable]::SequenceEqual([byte[]]$ka, [byte[]]$kb)) # throws an exception when the two arguments are different types
                if (-not $eq) {
                    $diffs.Add([pscustomobject]@{
                        Key       = $k
                        Status    = 'KeyMismatch'
                        Reference = (Sanitize-ForOutput -E $a -IncludeKeys:$RevealKeys)
                        Candidate = (Sanitize-ForOutput -E $b -IncludeKeys:$RevealKeys)
                    }) | Out-Null
                }
            }
        }
    }
    end {
        return [pscustomobject]@{
            Equal       = ($diffs.Count -eq 0)
            Differences = $diffs
        }
    }
}
