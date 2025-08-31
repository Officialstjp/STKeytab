<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function ConvertFrom-KeytabJson {
    <#
    .SYNOPSIS
    Convert canonical JSON back into a keytab file (requires key bytes).

    .DESCRIPTION
    Reads canonical JSON as produced by ConvertTo-KeytabJson -RevealKeys and reconstructs
    a MIT v0x0502 keytab. Requires key bytes to be present in JSON. Can restrict ACL on
    output and supports deterministic timestamps for reproducible builds.

        .PARAMETER JsonPath
        Path to the canonical JSON file.

        .PARAMETER OutputPath
        Output keytab path to write. Defaults to <JsonPath>.keytab when not specified.

        .PARAMETER Force
        Overwrite OutputPath if it exists.

        .PARAMETER FixedTimestampUtc
        Use a fixed timestamp for written entries for deterministic output.

        .PARAMETER RestrictAcl
        Apply a user-only ACL on the output file.

        .INPUTS
        System.String (file path) or objects with FilePath/FullName properties.

        .OUTPUTS
        System.String. Returns the OutputPath written.

        .EXAMPLE
        ConvertFrom-KeytabJson -JsonPath .\entry.json -OutputPath .\out.keytab -Force
        Reconstruct a keytab from JSON, overwriting the destination if present.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position=0)]
        [Alias('FullName','FilePath','PSPath')]
        [ValidateNotNullOrEmpty()]
        [string]$JsonPath,

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position=1)]
        [Alias('OutFile', 'Out')]
        [string]$OutputPath,

        [switch]$Force,
        [datetime]$FixedTimestampUtc,
        [switch]$RestrictAcl
    )
    begin {
        $in = Resolve-PathUniversal -Path $JsonPath -Purpose Input
        if ($OutputPath) {
            $out = Resolve-PathUniversal -Path $OutputPath -Purpose Output
        } else {
            $out = Resolve-OutputPath -InputPath $in -Extension '.keytab' -CreateDirectory
        }
    }
    process {
        $entries = Get-Content -LiteralPath $in -Raw | ConvertFrom-Json
        if (-not $entries) { throw "No entries found in JSON '$in'."}

        # Group into principal descriptors and key sets
        $byPrincipal = $entries | Group-Object { '{0}|{1}|{2}' -f $_.Realm, ($_.Components -join '/'), $_.NameType }
        $principalDescriptors = @()
        $keySetsByPrincipal = @()

        foreach ($g in $byPrincipal) {
            $first = $g.Group[0]
            $princDesc = [pscustomobject]@{
                Components    = @($first.Components)
                Realm         = $first.Realm
                NameType      = [int]$first.NameType
                Display       = ('{0}@{1}' -f ($first.Components -join '/'), $first.Realm)
            }
            $principalDescriptors += $princDesc

            $kvGroups = $g.Group | Group-Object Kvno
            $keySetSets = foreach ($kv in $kvGroups) {
                $keys = @{}
                foreach ($entry in $kv.Group)  {
                    if ($null -eq $entry.Key) { throw "Key bytes missing in JSON; cannot rebuild keytab."}
                    $keys[[int]$entry.Etype] = [byte[]]$entry.Key
                }
                [pscustomobject]@{
                    Kvno        = [int]$kv.Name
                    Keys        = $keys
                    Source      = 'Json'
                    RetrievedAt = (Get-Date).ToUniversalTime()
                }
            }
            $keySetsByPrincipal += $keySetSets
        }

        if ((Test-Path -LiteralPath $out) -and -not $Force) { throw "Output exists. Use -force to overwrite"}

        $tsArg = @{}
        if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) {
            $tsArg.FixedTimestampUtc = $FixedTimestampUtc
        }
        if ($PSCmdlet.ShouldProcess($out, "Write keytab from JSON")) {
            New-KeytabFile -Path $out -PrincipalDescriptors $principalDescriptors -KeySets ($keySetsByPrincipal | Select-Object -First 1) -RestrictAcl:$RestrictAcl @tsArg
        }
    }
    end {
        return $out
    }
}
