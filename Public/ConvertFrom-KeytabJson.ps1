function ConvertFrom-KeytabJson {
    <#
    .SYNOPSIS
    Convert canonical JSON back into a keytab file (requires key bytes).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$JsonPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$Force,
        [datetime]$FixedTimestampUtc,
        [switch]$RestrictAcl
    )

    $entries = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json
    if (-not $entries) { throw "No entries found in JSON '$jsonPath'."}

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

    if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) { throw "Output exists. Use -force to overwrite"}

    $tsArg = @{} 
    if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) { 
        $tsArg.FixedTimestampUtc = $FixedTimestampUtc 
    }
    if ($PSCmdlet.ShouldProcess($OutputPath, "Write keytab from JSON")) {
        New-KeytabFile -Path $OutputPath -PrincipalDescriptors $principalDescriptors -KeySets ($keySetsByPrincipal | Select-Object -First 1) -RestrictAcl:$RestrictAcl @tsArg
    }
}