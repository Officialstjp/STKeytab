<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Merge-Keytab {
    <#
    .SYNOPSIS
    Merge multiple keytabs into a single file with de-duplication and safety checks.

    .DESCRIPTION
    Reads input keytabs (with key material), de-duplicates entries across principal, KVNO,
    and encryption types, and writes a consolidated keytab. Merges containing krbtgt entries
    are blocked unless -AcknowledgeRisk is provided. Inputs must carry key bytes (e.g., from
    Read-Keytab -RevealKeys) to produce a valid merged output.

        .PARAMETER InputPaths
        One or more paths to input keytabs to merge. Inputs must include key material.

        .PARAMETER OutputPath
        Destination path of the merged keytab.

        .PARAMETER Force
        Overwrite OutputPath if it exists.

        .PARAMETER RestrictAcl
        Apply a user-only ACL on the merged output file.

        .PARAMETER AcknowledgeRisk
        Required to proceed when krbtgt entries are detected in inputs.

        .INPUTS
        System.String[] (file paths) or objects with Input/Output properties.

        .OUTPUTS
        System.String. Returns the OutputPath written.

        .EXAMPLE
        Merge-Keytab -InputPaths a.keytab,b.keytab -OutputPath merged.keytab -Force
        Merge two keytabs into a single file, overwriting the destination if present.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param(
        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [Alias('Input','In')]
        [ValidateNotNullOrEmpty()]
        [string[]]$InputPaths,

        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1)]
        [Alias('Output','Out')]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [switch]$Force,
        [switch]$RestrictAcl,
        [switch]$AcknowledgeRisk
    )
    begin {
        if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
        throw "Output file '$OutputPath' already exists. Use -Force to overwrite."
        }
        $entries = New-Object System.Collections.Generic.List[object]
        $krbtgtPresent = $false
    }
    process {
        if ($PSCmdlet.ShouldProcess("Merging keytabs: $($InputPaths -join ', ')")) {
            foreach ($p in $InputPaths) {
                $parsed = Read-Keytab -Path $p -RevealKeys
                foreach ($entry in $parsed) {
                if ($entry.Components.Count -ge 1 -and $entry.Components[0].ToUpperInvariant() -eq 'KRBTGT') {
                    $krbtgtPresent = $true
                }
                $entries.Add($entry)
                }
            }

            if ($krbtgtPresent -and -not $AcknowledgeRisk) {
                throw "Merged set contains krbtgt entries; re-run with -AcknowledgeRisk to proceed."
            }

            # Deduplicate on (Realm|ComponentsJoined|NameType|Kvno|EtypeId|KeyLength|KeyHex)
            $dedup = @{}
            foreach ($entry in $entries) {
                $compJoin = ($entry.Components -join '/')
                $keyHex = if ($entry.RawKey) { ($entry.RawKey | ForEach-Object { $_.ToString('x2') }) -join '' } else { $entry.Key }
                $key = "$($entry.Realm)|$compJoin|$($entry.NameType)|$($entry.Kvno)|$($entry.EtypeId)|$($entry.KeyLength)|$keyHex"
                if (-not $dedup.ContainsKey($key)) { $dedup[$key] = $entry }
            }

            # Reconstruct into writer inputs
            $principalDescriptors = New-Object System.Collections.Generic.List[object]
            $principalMap = @{}
            $kvGroups = @{}
            foreach ($v in $dedup.Values) {
                $descKey = "$($v.Realm)|$($v.Components -join '/')|$($v.NameType)"
                if (-not $principalMap.ContainsKey($descKey)) {
                $pd = New-PrincipalDescriptor -Components $v.Components -Realm $v.Realm -NameType $v.NameType -Tags @('Merged')
                $principalMap[$descKey] = $pd
                $principalDescriptors.Add($pd) | Out-Null
                }
                $kvk = "$($v.Kvno)"
                if (-not $kvGroups.ContainsKey($kvk)) { $kvGroups[$kvk] = @{} }
                if (-not $v.RawKey) { throw "Cannot merge masked keys. Ensure inputs were parsed with -RevealKeys support." }
                if ($kvGroups[$kvk].ContainsKey($v.EtypeId)) {
                # Detect conflicting key material for same kvno/etype (likely different principals) and stop.
                $existing = $kvGroups[$kvk][$v.EtypeId]
                if ($existing.Length -ne $v.RawKey.Length -or ($existing | Compare-Object -ReferenceObject $v.RawKey -SyncWindow 0)) {
                    throw "Conflicting key material detected for KVNO=$($v.Kvno), etype=$($v.EtypeId). Merge only keytabs for the same principal/account."
                }
                } else {
                $kvGroups[$kvk][$v.EtypeId] = $v.RawKey
                }
            }

            $keySets = New-Object System.Collections.Generic.List[object]
            foreach ($kv in ($kvGroups.Keys | Sort-Object {[int]$_})) {
                $keySets.Add([pscustomobject]@{ Kvno = [int]$kv; Keys = $kvGroups[$kv] }) | Out-Null
            }

            # Write merged keytab
            $null = New-KeytabFile -Path $OutputPath -PrincipalDescriptors $principalDescriptors -KeySets $keySets -RestrictAcl:$RestrictAcl
        }
    }
    end {
        $OutputPath
    }
}
