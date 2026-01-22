<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


#region Replication & Domain Helpers
# ---------------------------------------------------------------------- #
#
#                      Replication & Domain Helpers
#
# ---------------------------------------------------------------------- #

function Get-ADReplAccount {
    <#
        .SYNOPSIS
        Internal wrapper to allow mocking Get-ADReplAccount in tests.

        .DESCRIPTION
        This wrapper ensures a stable symbol exists in the module scope so that
        Pester can mock it even when DSInternals is not installed on the CI runner.
        In real execution it delegates to DSInternals\Get-ADReplAccount.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SamAccountName,
        [string]$Domain,
        [string]$Server,
        [pscredential]$Credential
    )
    # If tests mock this function, the body will not run.
    # Otherwise, delegate to DSInternals if available.
    $mod = Get-Module -Name DSInternals -ListAvailable | Select-Object -First 1
    if (-not $mod) {
        throw "DSInternals module not found. Install 'DSInternals' or run in an environment where tests mock Get-ADReplAccount."
    }
    if (-not (Get-Module -Name DSInternals)) {
        Import-Module -Name DSInternals -ErrorAction Stop | Out-Null
    }
    $replParams = @{
        SamAccountName = $SamAccountName
    }
    if ($Domain) { $replParams.Domain = $Domain }
    if ($Server) { $replParams.Server = $Server }
    if ($Credential) { $replParams.Credential = $Credential }
    return DSInternals\Get-ADReplAccount @replParams -ErrorAction Stop
}

function Resolve-DomainContext {
  <#
        .SYNOPSIS
        Resolve the domain FQDN from explicit input or environment/AD.
    #>
    param(
        [string]$Domain
    )
    if ($Domain) { return $Domain }
    $d = $env:USERDNSDOMAIN
    if (-not $d) {
        try {
            $d = (Get-ADDomain).DNSRoot
        } catch {
            Write-Verbose "Failed to resolve domain FQDN; using USERDNSDOMAIN."
            $d = $env:USERDNSDOMAIN
        }
    }
    if (-not $d) { throw "Unable to resolve domain; specify -Domain."}
    $d
}

function ConvertTo-NetBIOSIfFqdn {
    <#
        .SYNOPSIS
        Convert a domain FQDN to NetBIOS name when possible.
    #>
    param(
        [string]$Domain
    )
    if ($Domain -notmatch '\.') { return $Domain }
    try {
        $ad = Get-ADDomain -Identity $Domain -ErrorAction Stop
        if ($ad.NetBIOSName) { return $ad.NetBIOSName }
    } catch {
        Write-Verbose "Failed to resolve NetBIOS name for '$Domain'; using FQDN."
    }
    return ($Domain.Split('.')[0]).ToUpperInvariant()
}

function Get-ReplicatedAccount {
    <#
        .SYNOPSIS
        Use DSInternals to replicate account secrets for offline key extraction.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SamAccountName,
        [Parameter(Mandatory)][string]$DomainFQDN,
        [string]$Server,
        [pscredential]$Credential
    )

    $netbios = ConvertTo-NetBIOSIfFqdn $DomainFQDN
    if ($Server) {
        $repl = @{
            SamAccountName = $SamAccountName
            Domain         = $netbios
            Server         = $Server
        }
    } else {
        $repl = @{
            SamAccountName = $SamAccountName
            Domain         = $netbios
            Server         = $DomainFQDN
        }
    }

    if ($Credential) { $repl.Credential = $Credential }
    try {
        Get-ADReplAccount @repl -ErrorAction Stop
    } catch {
        throw "Replication (Get-ADReplAccount) failed for '$SamAccountName' in domain '$DomainFqdn'. $($_.Exception.Message)"
    }
}

#endregion


#region Key Extractions
# ---------------------------------------------------------------------- #
#
#                              Key Extractions
#
# ---------------------------------------------------------------------- #

function Get-KerberosKeyMaterialFromAccount {
    <#
        .SYNOPSIS
        Extract Kerberos key material (etype->key) and KVNO sets from a replicated account.

        .DESCRIPTION
        This function utilizes the Get-ADReplAccount cmdlet from the DSInternals module to extract Kerberos key material from a replicated account.
        Both KerberosNew and KerberosKey Attributes are queried.
        The resulting object is deduplicated and includes a risk-level for later security-related processing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Account,
        [Parameter(Mandatory)][string]$SamAccountName,
        [string]$Server,
        [switch]$IsKrbtgt
    )

    $diag = [System.Collections.Generic.List[string]]::new()
    $supp = $null
    if ($Account -and $Account.PSObject.Properties.Name -contains 'SupplementalCredentials') {
        $supp = $Account.SupplementalCredentials
    }
    $keySets = New-Object System.Collections.Generic.List[object]
    $kvno = $null
    $principalType = if ($IsKrbtgt) { 'Krbtgt' } elseif ($SamAccountName -match '\$$') { 'Computer' } else { 'User' }

    # Get current KVNO (msDS-KeyVersionNumber)
    try {
        if ($principalType -eq 'Computer') {
        $params = @{ Identity = $SamAccountName.TrimEnd('$'); Properties = 'DistinguishedName','msDS-KeyVersionNumber'; ErrorAction = 'Stop' }
        if ($Server) { $params.Server = $Server }
        $obj = Get-ADComputer @params
        $kvAttr = $obj.'msDS-KeyVersionNumber'
        } else {
        $params = @{ Identity = $Account.DistinguishedName; Properties = 'DistinguishedName','msDS-KeyVersionNumber'; ErrorAction = 'Stop' }
        if ($Server) { $params.Server = $Server }
        $obj = Get-ADObject @params
        $kvAttr = $obj.'msDS-KeyVersionNumber'
        }
        if ($kvAttr) { $kvno = [int]$kvAttr; $diag.Add("Resolved KVNO=$kvno from msDS-KeyVersionNumber") }
    } catch {
        $diag.Add("KVNO lookup failed: $($_.Exception.Message)")
    }

    $addKeySet = {
        param(
            $kvnoVal,
            [hashtable]$etypeMapLocal,
            $sourceLabel
        )

        if (-not $kvnoVal) { return }
        if (-not $etypeMapLocal -or $etypeMapLocal.Count -eq 0) { return }
        $keySets.Add([PSCustomObject]@{
        Kvno        = [int]$kvnoVal
        Keys        = $etypeMapLocal
        Source      = $sourceLabel
        RetrievedAt = (Get-Date).ToUniversalTime()
        })
    }

    if ($supp -and $supp.PSObject.Properties.Name -contains 'KerberosNew' -and $supp.KerberosNew) {
        $kerb = $supp.KerberosNew

        $diag.Add("Using KerberosNew structure")
        $groups = @(
        @{ Name='Credentials';            Data=$kerb.Credentials }
        @{ Name='ServiceCredentials';     Data=$kerb.ServiceCredentials }
        @{ Name='OldCredentials';         Data=$kerb.OldCredentials }
        @{ Name='OlderCredentials';       Data=$kerb.OlderCredentials }
        )

        foreach ($g in $groups) {
            $arr = $g.Data
            if (-not $arr) { continue }

            $etypeMapLocal = @{}

            foreach ($entry in $arr) {
                if (-not $entry) { continue }

                if ($entry.PSObject.Properties.Name -notcontains 'Key' -or
                    $entry.PSObject.Properties.Name -notcontains 'KeyType') { continue }

                $keyBytes = $entry.Key
                $etypeId  = $null
                $rawKT = $entry.KeyType

                if ($rawKT -is [int]) { $etypeId = $rawKT }
                elseif ($rawKT -is [enum]) { $etypeId = [int]$rawKT }
                elseif ($rawKT -is [string]) { [int]$tmp=0; if ([int]::TryParse($rawKT,[ref]$tmp)) { $etypeId=$tmp } }
                elseif ($rawKT -and ($rawKT.PSObject.Properties.Name -contains 'Value')) { try { $etypeId = [int]$rawKT.Value } catch { Write-Verbose "Failed to resolve encryption type ID." } }

                if ($keyBytes -and $etypeId) {
                    if (-not $etypeMapLocal.ContainsKey($etypeId)) { $etypeMapLocal[$etypeId] = $keyBytes }
                }
            }
            if ($etypeMapLocal.Count -gt 0) {
                # determine kvno for set
                $kvForSet = $kvno
                if ($IsKrbtgt) {
                    switch ($g.Name) {
                        'Credentials'         { $kvForSet = $kvno }
                        'ServiceCredentials'  { $kvForSet = $kvno }
                        'OldCredentials'      { if ($kvno -gt 0) { $kvForSet = $kvno - 1 } }
                        'OlderCredentials'    { if ($kvno -gt 1) { $kvForSet = $kvno - 2 } }
                    }
                }
                & $addKeySet $kvForSet $etypeMapLocal $g.Name
            }
        }
    } elseif ($Account -and $Account.PSObject.Properties.Name -contains 'KerberosKeys' -and $Account.KerberosKeys) {
        # legacy
        $etypeMapLocal = @{}
        foreach ($k in $Account.KerberosKeys) {
            if (-not $k) { continue }
            $etype = $k.EncryptionType
            $bytes = $k.key
            $id = Get-EtypeIdFromInput $etype
            if ($null -ne $id -and -not $etypeMapLocal.ContainsKey($id)) { $etypeMapLocal[$id] = $bytes}
        }
        & $addKeySet $kvno $etypeMapLocal 'KerberosKeys'
    } else {
        $diag.Add("No recognizable Kerberos credential structure present.")
    }

    if ($keySets.Count -eq 0) {
        throw "No Kerberos key material extracted for '$SamAccountName'."
    }

    # Deduplicate KeySets by (Kvno, Etype)
    $dedup = @{}
    foreach ($ks in $keySets) {
        $kKey = "$($ks.Kvno)"
        if (-not $dedup.ContainsKey($kKey)) {
            $dedup[$kKey] = @{}
        }
        foreach ($etype in $ks.Keys.Keys) {
            if (-not $dedup[$kKey].ContainsKey($etype)) {
                $dedup[$kKey][$etype] = $ks.Keys[$etype]
            }
        }
    }
    $finalSets = New-Object System.Collections.Generic.List[object]
    foreach ($kvKey in ($dedup.Keys | Sort-Object {[int]$_})) {
        $finalSets.Add([pscustomobject]@{
            Kvno        = [int]$kvKey
            Keys        = $dedup[$kvKey]
            Source      = 'Merged'
            RetrievedAt = (Get-Date).ToUniversalTime()
        })
    }
    $isDC = $false
    try {
        $dn = $Account.DistinguishedName
        if ($dn) {
            $upperDn = $dn.ToUpperInvariant()
            if ($upperDn -like '*OU=DOMAIN CONTROLLERS*' -or $upperDn -like '*CN=DOMAIN CONTROLLERS*') { $isDC = $true }
        }
    } catch {
        Write-Verbose "Failed to resolve distinguished name; assuming user account."
        $upperDn = $null
    }

    # Determine privileged user membership (Domain Admins, Enterprise Admins, Schema Admins, Administrators)
    $isPrivileged = $false
    if ($principalType -eq 'User' -and -not $IsKrbtgt) {
        try {
            $isPrivileged = Test-IsPrivilegedUser -Identity $SamAccountName -Server $Server
        } catch {
            Write-Verbose ("Privilege check failed: {0}" -f $_.Exception.Message)
        }
    }

    [pscustomobject]@{
        SamAccountName = $SamAccountName
        PrincipalType  = $principalType
        KeySets        = $finalSets
        Diagnostics    = $diag
        RiskLevel      = if ($SamAccountName.ToUpperInvariant() -eq 'KRBTGT') { 'Critical' }
                        elseif ($principalType -eq 'Computer' -and $isDC) { 'High' }
                        elseif ($principalType -eq 'User' -and $isPrivileged) { 'High' }
                        else { 'Medium' }
    }
}

#endregion


#region Privilege Helpers
function Test-IsPrivilegedUser {
    <#
        .SYNOPSIS
        Checks if a user is a member (directly or transitively) of high-privilege groups.

        .DESCRIPTION
        Uses Get-ADPrincipalGroupMembership to resolve transitive group membership and flags
        membership in Domain Admins, Enterprise Admins, Schema Admins, or Administrators.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [string]$Server,
        [pscredential]$Credential
    )

    $params = @{ Identity = $Identity; ErrorAction = 'Stop' }
    if ($Server) { $params.Server = $Server }
    if ($Credential) { $params.Credential = $Credential }

    try {
        $groups = Get-ADPrincipalGroupMembership @params
    } catch {
        Write-Verbose ("Get-ADPrincipalGroupMembership failed for '{0}': {1}" -f $Identity, $_.Exception.Message)
        return $false
    }
    if (-not $groups) { return $false }

    $highNames = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators')
    foreach ($g in $groups) {
        $name = if ($null -ne $g.SamAccountName) { $g.SamAccountName } else { $g.Name }
        if ($name -and ($name -in $highNames)) { return $true }
        # also check some well-known RIDs where possible
        if ($g.ObjectSID) {
            $sidText = $g.ObjectSID.Value
            if ($sidText -match '-512$' -or $sidText -match '-519$' -or $sidText -match '-518$' -or $sidText -match '-544$') { return $true }
        }
    }
    return $false
}
#endregion
