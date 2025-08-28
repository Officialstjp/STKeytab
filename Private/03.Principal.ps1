<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


#region Principal Modeling
# ---------------------------------------------------------------------- #
#
#                           Principal Modeling
#
# ---------------------------------------------------------------------- #

function New-PrincipalDescriptor {
    <#
        .SYNOPSIS
        Create a principal descriptor (components, realm, name-type) used by the writer.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Components,
        [Parameter(Mandatory)][string]$Realm,
        [Parameter(Mandatory)][int]$NameType,
        [string[]]$Tags
    )

    $Tags = $Tags -join ','
    [pscustomobject]@{
        Components  = $Components
        Realm       = $Realm
        NameType    = $NameType
        Tags        = $Tags
        Display     = ("{0}@{1}" -f ($Components -join '/'), $Realm)
    }
}

function Get-ComputerPrincipalDescriptors {
    <#
        .SYNOPSIS
        Build principal descriptors from a computer account's SPNs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$DomainFQDN,
        [switch]$IncludeShortHost
    )

    $adComp = Get-ADComputer -Identity $ComputerName -Properties servicePrincipalName -Server $DomainFQDN -ErrorAction Stop

    $realm = $DomainFQDN.ToUpperInvariant()
    $set = New-Object System.Collections.Generic.List[object]
    $spns = @()

    if ($adComp.servicePrincipalName) { $spns = $adComp.servicePrincipalName | Sort-Object -Unique }

    foreach ($spn in $spns) {
        if ($spn -notmatch '/') { continue }

        $parts = $spn.Split('/',2)
        $svc = $parts[0].ToLowerInvariant()
        $right = $parts[1].Split(':')[0].Split('/')[0].ToLowerInvariant()

        if (-not $right) { continue }

        $comp = New-PrincipalDescriptor -Components @($svc, $right) -Realm $realm -NameType $script:NameTypes.KRB_NT_SRV_HST -Tags @('SPN')
        $set.Add($comp)
        if ($IncludeShortHost) {
            $short = $right.Split('.')[0]

            if ($short -and $short -ne $right) {
                $set.Add( (New-PrincipalDescriptor -Components @($svc, $short) -Realm $realm -NameType $script:NameTypes.KRB_NT_SRV_HST -Tags @('SPN','ShortHost')) )
            }
        }
    }

  # Deduplicate
  $unique = @{}
  foreach ($principal in $set) {
    $key = "$($principal.Components -join '|')|$($principal.Realm)|$($principal.NameType)"
    if (-not $unique.ContainsKey($key)) {
      $unique[$key] = $principal
    }
  }
  $unique.Values
}

function Get-UserPrincipalDescriptor {
    <#
        .SYNOPSIS
        Build a user principal descriptor from sAMAccountName and realm.
    #>
    param(
        [Parameter(Mandatory)][string]$SamAccountName,
        [Parameter(Mandatory)][string]$Realm
    )
    $base = $SamAccountName.TrimEnd('$')
    New-PrincipalDescriptor -Components @($base) -Realm $Realm -NameType $script:NameTypes.KRB_NT_PRINCIPAL -Tags @('User')
}

function Get-KrbtgtPrincipalDescriptor {
    <#
        .SYNOPSIS
        Build the krbtgt principal descriptor for a realm.
    #>
    param(
        [Parameter(Mandatory)][string]$Realm
    )
    New-PrincipalDescriptor -Components @('krbtgt') -Realm $Realm -NameType $script:NameTypes.KRB_NT_PRINCIPAL -Tags @('Krbtgt')
}

function Get-RiskLevelForPrincipal {
    <#
        .SYNOPSIS
        Compute a coarse risk level for a principal (for UX warnings).
    #>
    param(
        [string]$SamAccountName,
        [string]$PrincipalType,
        [boolean]$isDC
    )

    if ($SamAccountname -eq 'KRBTGT') { return 'krbtgt' }
    if ($PrincipalType -eq 'Computer' -and $isDC) { return 'High' }
    if ($PrincipalType -eq 'Computer') { return 'Medium' }
    if ($PrincipalType -eq 'User') { return 'Medium' }
    if ($PrincipalType -eq 'Krbtgt') { return 'krbtgt' }
    return 'Medium'
}

#endregion

