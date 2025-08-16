#region Replication & Domain Helpers
# ---------------------------------------------------------------------- #
#
#                      Replication & Domain Helpers
#
# ---------------------------------------------------------------------- #

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
    try { $d = (Get-ADDomain).DNSRoot } catch {}
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
  } catch {}
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
  $repl = @{
    SamAccountName = $SamAccountName
    Domain         = $netbios
    # Many mocks (and some environments) expect -Server; default to DomainFQDN when not supplied
    Server         = ($Server ? $Server : $DomainFQDN)
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
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Account,
    [Parameter(Mandatory)][string]$SamAccountName,
    [Parameter(Mandatory)][string]$DomainFqdn,
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
        elseif ($rawKT -and ($rawKT.PSObject.Properties.Name -contains 'Value')) { try { $etypeId = [int]$rawKT.Value } catch {} }

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

  if ($keySets.Count -eq 0)  {
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
    RetrievedAt = (Get-Date).ToUniversalTime() })
  }
  $isDC = $false
  try {
    $dn = $Account.DistinguishedName
    if ($dn) {
      $upperDn = $dn.ToUpperInvariant()
      if ($upperDn -like '*OU=DOMAIN CONTROLLERS*' -or $upperDn -like '*CN=DOMAIN CONTROLLERS*') { $isDC = $true }
    }
  } catch {}

  [pscustomobject]@{
    SamAccountName = $SamAccountName
    PrincipalType  = $principalType
    KeySets        = $finalSets
    Diagnostics    = $diag
  RiskLevel      = (Get-RiskLevelForPrincipal -SamAccountName $SamAccountName -PrincipalType $principalType -isDC $isDC)
  }
}

#endregion