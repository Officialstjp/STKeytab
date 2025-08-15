<#
.SYNOPSIS
  Kerberos keytab toolkit (extraction, creation, validation, parsing) for AD principals (computer, user, krbtgt).
.DESCRIPTION
  Designed for controlled generation of keytab files from a Domain Controller (or account with DCSync rights).
  Supports multi‑KVNO (krbtgt), principal abstraction, risk classification, JSON summaries, parsing and merging.
.NOTES

==================================================
                 SECURITY WARNING 
==================================================                 

Possession of produced keytabs grants impersonation and decryption. 
Treat outputs as Tier‑0 secrets. 
High/Critical (krbtgt, DC) require explicit acknowledgement.

========================================================


.Change Log
  Date        Version       Notes
  10.08.2025  0.1.0         Initial release, New-ComputerKeytab POC
  15.08.2025  1.0.0         V1 update with new features, Generalized Keytab Creation, 
                            generalized writer, `Read-Keytab`, `Merge-Keytab`, extended `Test-Keytab`
                            justification, high-impact warnings, DPAPI protect option, reproducible timestamp flag


#>
$script:ErrorActionPreference = 'Stop'

#region Global Maps / Constants
# ---------------------------------------------------------------------- #
#
#                    Global Maps / Constants
#
# ---------------------------------------------------------------------- #

# Encryption type names -> numeric IDs (subset + extended)
$script:etypeMap = [ordered]@{
  DSA_SHA1_CMS                = 9
  MD5_RSA_CMS                 = 10
  SHA1_RSA_CMS                = 11
  RC2_CBC_ENV                 = 12
  RSA_ENV                     = 13
  RSA_ES_OAEP_ENV             = 14
  DES3_CBC_ENV                = 15
  DES3_CBC_SHA1               = 16
  AES128_CTS_HMAC_SHA1_96     = 17
  AES256_CTS_HMAC_SHA1_96     = 18
  AES128_CTS_HMAC_SHA256_128  = 19
  AES256_CTS_HMAC_SHA384_192  = 20
  ARCFOUR_HMAC                = 23
  ARCFOUR_HMAC_EXP            = 24
  CAMELLIA128_CTS_CMAC        = 25
  CAMELLIA256_CTS_CMAC        = 26
  UNKNOWN                     = 511
}
$script:ReverseEtypeMap = @{}
foreach ($kv in $script:etypeMap.GetEnumerator()) { $script:ReverseEtypeMap[[int]$kv.Value] = $kv.Key }

$script:NameTypes = @{
  KRB_NT_PRINCIPAL  = 1
  KRB_NT_SRV_HST    = 3
}

$script:HighImpactPrincipals = @{ 'KRBTGT' = $true }

#endregion


# region Utility & Dependency
# ---------------------------------------------------------------------- #
#
#                       Utility & Dependency
#
# ---------------------------------------------------------------------- #

function Get-RequiredModule {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [switch]$AutoInstall
  )
  if (Get-Module -ListAvailable -Name $Name) { return }

  if (-not $AutoInstall) { throw "Required module '$Name' not installed." }

  Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
}

function Get-CredentialFromEnv {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory)][string]$EnvFile
    )

    if (-not (Test-Path -LiteralPath $EnvFile)) {
      throw "Env file '$EnvFile' not found."
    }

    $pairs = @{}
    Get-Content -LiteralPath $EnvFile | Foreach-Object {
      if ($_ -match '^\s*(#|$)') { return }

      $kv = $_ -split '=',2
      if ($kv.Count -eq 2) { $pairs[$kv[0].Trim()] = $kv[1].Trim() }
    }

    $u = $pairs['STCRYPT_DCSYNC_USERNAME']
    $p = $pairs['STCRYPT_DCSYNC_PASSWORD']
    if (-not $u) { $u = $pairs['STCRYPT_DSYNC_USERNAME'] }     # legacy typo support
    if (-not $p) { $p = $pairs['STCRYPT_DSYNC_PASSWORD'] }     # legacy typo support

    if (-not $u -or -not $p) { 
      throw "Env file missing STCRYPT_DCSYNC_USERNAME/STCRYPT_DCSYNC_PASSWORD (or legacy STCRYPT_DSYNC_USERNAME/STCRYPT_DSYNC_PASSWORD)."
    }

    $sec = ConvertTo-SecureString $p -AsPlainText -Force
    [pscredential]::new($u,$sec)
}

function Get-EtypeIdFromInput {
  param(
    [Parameter(Mandatory)][object]$Value
  )

  if ($null -eq $Value) { return $null }
  if ($Value -is [int]) { return [int]$Value }
  if ($Value -is [string]) {
    $s = $Value.Trim()

    [int]$tmp = 0
    if ([int]::TryParse($s,[ref]$tmp)) { 
      return $tmp 
    }

    if ($script:etypeMap.Contains($s)) { 
      return [int]$script:etypeMap[$s] 
    }

    return $null
  }
  try { 
    return [int]$Value 
  } catch { 
    return $null 
  }
}

function Get-EtypeNameFromId {
  param(
    [Parameter(Mandatory)][int]$Id
    )
  if ($script:ReverseEtypeMap.ContainsKey($Id)) { return $script:ReverseEtypeMap[$Id] }
    return "ETYPE_$Id"
}

function Resolve-EtypeSelection {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][int[]]$AvailableIds,
    [object[]]$Include,
    [object[]]$Exclude
  )

  $available = [System.Collections.Generic.HashSet[int]]::new()
  $AvailableIds | Foreach-Object { [void]$available.Add($_) }
  
  $included          = New-Object System.Collections.Generic.List[int]
  $missing           = New-Object System.Collections.Generic.List[int]
  $unknownIncluded   = New-Object System.Collections.Generic.List[object]
  $excluded          = New-Object System.Collections.Generic.List[int]
  $unknownExcluded   = New-Object System.Collections.Generic.List[object]

  if ($Include) {
    foreach ($raw in $Include) {
      $id = Get-EtypeIdFromInput $raw
      if ($null -ne $id) {
        if ($available.Contains($id)) { $included.Add($id) } else { $missing.Add($id) }
      } else { $unknownIncluded.Add($raw) }
    }
  }

  if ($Exclude) {
    foreach ($raw in $Exclude) {
      $id = Get-EtypeIdFromInput $raw
      if ($null -ne $id) { $excluded.Add($id) } else { $unknownExcluded.Add($raw) } 
    } 
  }

  $selected = if ($included.Count -gt 0) { $included } else { $available }

  if ($excluded.Count -gt 0) {
    $excludedSet = [System.Collections.Generic.HashSet[int]]::new()
    $excluded | ForEach-Object { [void]$excludedSet.Add($_) }
    $selected = @($selected | Where-Object { -not $excludedSet.Contains($_) })
  }

  [pscustomobject]@{
    Selected       = ([int[]]$selected | Sort-Object -Unique)
    Missing        = $missing
    UnknownInclude = $unknownIncluded
    UnknownExclude = $unknownExcluded
  }
}
# ---------------------------------------------------------------------- #
#  Security / Risk Warning Presentation
# ---------------------------------------------------------------------- #
# Design notes:
#  - Public entry point: Write-STSecurityWarning
#  - RiskLevel values currently produced: 'krbtgt','High','Medium'
#  - Enables opt-out via:  -Suppress  or env var STCRYPT_SUPPRESS_SECURITY_WARNING=1
#  - Tries to stay pure (no Write-Host) unless -AsString:$false (default) for visibility.
#  - Returns the composed banner text (always) so callers can log it.
# ---------------------------------------------------------------------- #

function Write-EmptyBannerLine {
  param(
    [int]$Width = 82,
    [ConsoleColor]$Color = 'Red'
  )
  $inner = ' ' * ($Width)
  Write-Host ("|{0}|" -f $inner) -ForegroundColor $Color
}

function Write-BannerText {
  param(
    [Parameter(Mandatory)][string]$Message,
    [int]$Width = 82,
    [switch]$Centered,
    [ConsoleColor]$Color = 'Red'
  )
  # Width = inner content width (excluding the two border pipes)
  $lines = $Message -split "(`r`n|`n)"
  foreach ($l in $lines) {
  if (-not $l) { Write-EmptyBannerLine -Width $Width -Color $Color; continue }
    # Break long lines into chunks
    $remaining = $l
    while ($remaining.Length -gt 0) {
      $chunkSize = [Math]::Min($Width, $remaining.Length)
      $chunk = $remaining.Substring(0,$chunkSize)
      $remaining = if ($remaining.Length -gt $chunkSize) { $remaining.Substring($chunkSize) } else { '' }

      $padLeft = 0
      $padRight = 0
      if ($Centered) {
        $padLeft  = [Math]::Floor(($Width - $chunk.Length)/2)
        $padRight = $Width - $chunk.Length - $padLeft
      } else {
        $padLeft  = 0
        $padRight = $Width - $chunk.Length
      }
      $line = '|' + (' ' * $padLeft) + $chunk + (' ' * $padRight) + '|'
      Write-Host $line -ForegroundColor $Color
    }
  }
}

function New-SecurityBannerContent {
  param(
    [Parameter(Mandatory)][string]$RiskLevel,
    [Parameter(Mandatory)][string]$SamAccountName
  )
  switch ($RiskLevel.ToLowerInvariant()) {
    'krbtgt' {
      @(
        'SECURITY WARNING',
        '',
        'You are exporting / handling KRBTGT key material.',
        'Possession enables forging (Golden Tickets) & global Kerberos decryption across the forest.',
        '',
        'Treat as a Tier-0 secret. Strongly restrict storage, transport and lifetime.',
        'Perform ONLY in a controlled (lab / IR / recovery) scenario with explicit approval.',
        '',
        'Existence of this file is itself a critical risk indicator.'
      )
    }
    'high' {
      @(
        'HIGH RISK KEYTAB',
        '',
        "Account: $SamAccountName",
        'Domain Controller or high-impact service account keys allow lateral movement, ticket forging for that host / services, and decryption of its Kerberos traffic.',
        '',
        'Handle under change control. Limit distribution. Consider immediate secure deletion after use.'
      )
    }
    default {
      @(
        'SENSITIVE MATERIAL',
        '',
        "Account: $SamAccountName",
        'Keytab grants impersonation for this principal and decryption of its Kerberos traffic.',
        'Store minimally, transmit over secure channels, and purge after intended use.'
      )
    }
  }
}

function Write-SecurityWarning {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RiskLevel,
    [Parameter(Mandatory)][string]$SamAccountName,
    [int]$Width = 80,
    [switch]$Suppress,
    [switch]$AsString,
    [switch]$NoColor
  )

  if ($Suppress -or ($env:STCRYPT_SUPPRESS_SECURITY_WARNING -eq '1')) {
    return ""
  }

  # Normalize internal width (content width inside borders)
  if ($Width -lt 40) { $Width = 40 }
  $contentWidth = $Width - 2  # account for border pipes

  $lines = New-SecurityBannerContent -RiskLevel $RiskLevel -SamAccountName $SamAccountName
  $borderLine = '+' + ('\' * ($contentWidth)) + '+'
  $stringBuilder = [System.Text.StringBuilder]::new()
  [void]$stringBuilder.AppendLine($borderLine)
  foreach ($l in $lines) {
    # Manual line wrapping consistent with Write-STBannerText
    $remaining = $l
    if (-not $remaining) {
      [void]$stringBuilder.AppendLine('|' + (' ' * $contentWidth) + '|')
      continue
    }
    while ($remaining.Length -gt 0) {
      $chunkSize = [Math]::Min($contentWidth, $remaining.Length)
      $chunk = $remaining.Substring(0,$chunkSize)
      $remaining = if ($remaining.Length -gt $chunkSize) { $remaining.Substring($chunkSize) } else { '' }
      $padRight = $contentWidth - $chunk.Length
      [void]$stringBuilder.AppendLine('|' + $chunk + (' ' * $padRight) + '|')
    }
  }
  [void]$stringBuilder.AppendLine($borderLine)

  $bannerText = $stringBuilder.ToString().TrimEnd()

  if ($AsString) { return $bannerText }

  $color = if ($NoColor) { $null } elseif ($RiskLevel -eq 'krbtgt') { 'Red' } elseif ($RiskLevel -eq 'High') { 'Yellow' } else { 'DarkYellow' }

  if ($color) {
    foreach ($outLine in ($bannerText -split "`r?`n")) {
      Write-Host $outLine -ForegroundColor $color
    }
  } else {
    Write-Host $bannerText
  }

  return $bannerText
}


#endregion
      

#region Replication & Domain Helpers
# ---------------------------------------------------------------------- #
#
#                      Replication & Domain Helpers
#
# ---------------------------------------------------------------------- #

function Resolve-DomainContext {
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
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Account,
    [Parameter(Mandatory)][string]$SamAccountName,
    [Parameter(Mandatory)][string]$DomainFqdn,
    [string]$Server,
    [switch]$IsKrbtgt
  )
  $diag = [System.Collections.Generic.List[string]]::new()
  $supp = $Account.SupplementalCredentials
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
  } elseif ($Account.PSObject.Properties.Name -contains 'KerberosKeys' -and $Account.KerberosKeys) {
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

function Get-RiskLevelForPrincipal {
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


#region Principal Modeling
# ---------------------------------------------------------------------- #
#
#                           Principal Modeling
#
# ---------------------------------------------------------------------- #

function New-PrincipalDescriptor {
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
  param(
    [Parameter(Mandatory)][string]$SamAccountName,
    [Parameter(Mandatory)][string]$Realm
  )
  $base = $SamAccountName.TrimEnd('$')
  New-PrincipalDescriptor -Components @($base) -Realm $Realm -NameType $script:NameTypes.KRB_NT_PRINCIPAL -Tags @('User')
}

function Get-KrbtgtPrincipalDescriptor {
  param(
    [Parameter(Mandatory)][string]$Realm
  )
  New-PrincipalDescriptor -Components @('krbtgt') -Realm $Realm -NameType $script:NameTypes.KRB_NT_PRINCIPAL -Tags @('Krbtgt')
}

#endregion


#region Keytab Writer / Parser
# ---------------------------------------------------------------------- #
#
#                           Keytab Writer / Parser
#
# ---------------------------------------------------------------------- #

function Write-UInt16BE([IO.BinaryWriter]$binaryWriter,[int]$Value) { 
  [byte[]]$b = [BitConverter]::GetBytes([uint16]$Value)
  if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
  $binaryWriter.Write($b,0,2)
}

function Write-UInt32BE([IO.BinaryWriter]$binaryWriter,[System.UInt32]$Value) {
  [byte[]]$b = [BitConverter]::GetBytes([uint32]$Value)
  if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
  $binaryWriter.Write($b,0,4)
}

function Write-Int32BE([IO.BinaryWriter]$BinaryWriter,[int]$Value) {
    Write-UInt32BE $BinaryWriter ([System.UInt32]$Value)
}

function ReadUInt16([byte[]]$bytes,[ref]$i) {
  $idx = [int]$i.Value
  [byte[]]$b = $bytes[$idx..($idx+1)]
  if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
  $i.Value = $idx + 2
  return [uint16]([BitConverter]::ToUInt16($b,0))
}

function ReadUInt32([byte[]]$bytes,[ref]$i) {
  $idx = [int]$i.Value
  [byte[]]$b = $bytes[$idx..($idx+3)]
  if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
  $i.Value = $idx + 4
  return [uint32]([BitConverter]::ToUInt32($b,0))
}


function New-KeytabEntry {
  param(
    [Parameter(Mandatory)][object]$PrincipalDescriptor,
    [Parameter(Mandatory)][int]$EncryptionType,
    [Parameter(Mandatory)][byte[]]$Key,
    [Parameter(Mandatory)][int]$Kvno,
    [int]$Timestamp = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  )

  $enc = [Text.Encoding]::ASCII
  $realmBytes = $enc.GetBytes($PrincipalDescriptor.Realm)

  $memStream    = New-Object IO.MemoryStream
  $binaryWriter = New-Object IO.BinaryWriter($memStream)

  Write-UInt16BE $binaryWriter $PrincipalDescriptor.Components.Count
  # realm
  Write-UInt16BE $binaryWriter $realmBytes.Length; $BinaryWriter.Write($realmBytes)
  #components
  foreach ($comp in $PrincipalDescriptor.Components) {
    [byte[]]$compBytes = $enc.GetBytes($comp)
    Write-UInt16BE $binaryWriter $compBytes.Length
    $binaryWriter.Write($compBytes)
  }

  Write-UInt32BE $binaryWriter ([uint32]$PrincipalDescriptor.NameType)
  Write-UInt32BE $binaryWriter ([uint32]$Timestamp)
  $binaryWriter.Write([byte]($Kvno -band 0xFF))
  Write-UInt16BE $binaryWriter $EncryptionType
  Write-UInt16BE $binaryWriter $Key.Length
  $binaryWriter.Write($Key)
  # 32 bit kvno extension
  Write-UInt32BE $binaryWriter ([uint32]$Kvno)

  $binaryWriter.Flush()
  $memStream.ToArray()
}


function New-KeytabFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][object[]]$PrincipalDescriptors,
    [Parameter(Mandatory)][object[]]$KeySets, # list of {Kvno: Keys}
    [int[]]$EtypeFilter,
    [switch]$RestrictAcl,
    [datetime]$FixedTimestampUtc
  )

  $full = if ([IO.Path]::IsPathRooted($Path)) { [IO.Path]::GetFullPath($Path) } else { [IO.Path]::GetFullPath((Join-Path (Get-Location) $Path)) }
  $tmp = "$full.tmp"
  if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }

  $memStream = New-Object IO.MemoryStream
  $binaryWriter = New-Object IO.BinaryWriter($memStream)
  $entryCount = 0

  try {
    # keytab v2 header
    $binaryWriter.Write([byte]0x05)
    $binaryWriter.Write([byte]0x02)
    $tsArg = @{}
    $timestampSec =
      if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) {
        [int][DateTimeOffset]::new(($FixedTimestampUtc.ToUniversalTime())).ToUnixTimeSeconds()
      } else {
        [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
      }

    if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) {
      $tsArg = @{ Timestamp = $timestampSec }
    }

    foreach ($keySet in $KeySets | Sort-Object Kvno) {
      foreach ($etype in ($keySet.Keys.Keys | Sort-Object)) {
        if ($EtypeFilter -and ($EtypeFilter -notcontains $etype)) { continue }
        [byte[]]$bytes = $keySet.Keys[$etype]
        foreach ($pd in $PrincipalDescriptors) {
          [byte[]]$entryBytes = New-KeytabEntry -PrincipalDescriptor $pd -EncryptionType $etype -Key $bytes -Kvno $keySet.Kvno @tsArg
          Write-Int32BE $binaryWriter $entryBytes.Length
          $binaryWriter.Write($entryBytes, 0, $entryBytes.Length)
          $entryCount++
        }
      }
    }
    
    $binaryWriter.Flush(); 
    Write-Verbose "[Keytab] entries=$entryCount length=$($memStream.Length) file=$tmp"
  } finally {
    $binaryWriter.Dispose()
  }

  [IO.File]::WriteAllBytes($tmp, $memStream.ToArray())
  Move-Item -LiteralPath $tmp -Destination $full -Force
  if ($RestrictAcl) { Set-UserOnlyAcl -Path $full }
  $full
}

function Read-Keytab {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$RevealKeys,
    [int]$MaxKeyHex = 64
  )

  if (-not (Test-Path -LiteralPath $Path)) { throw "File '$Path' not found" }

  $bytes = [IO.File]::ReadAllBytes($Path)

  if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x05 -or $bytes[1] -ne 0x02) { throw "'$Path' is not a valid keytab (expected 0x05 0x02 at start)" }

  $pos = 2
  $list = New-Object System.Collections.Generic.List[object]
  while ($pos -lt $bytes.Length) {
    if ($pos + 4 -gt $bytes.Length) { throw "Unexpected end of file at position $pos in '$Path'" }
    $entryLength = [int](
      ($bytes[$pos]      -shl 24)   -bor
      ($bytes[$pos+1]    -shl 16)   -bor
      ($bytes[$pos+2]    -shl 8)    -bor
      ($bytes[$pos+3])
    )

    $pos += 4
    if ($entryLength -lt 0) { $entryLength = -$entryLength } # MIT quirk
    if ($entryLength -lt 0) { throw "Invalid entry length at position $pos in '$Path'" }
    if ($pos + $entryLength -gt $bytes.Length) { 
      $misMatchLength = $entryLength - ($bytes.Length - $pos)
      throw "Declared entry exceeds file length by $misMatchLength bytes at position $pos in '$Path'" 
    }

    $entry = $bytes[$pos..($pos+$entryLength-1)]
    $pos += $entryLength

    # Use a single cursor ($iref.Value) for all reads to avoid desync
    $index = 0
    $iref  = [ref]$index

    # compCount, realm length, realm
    $compCount   = ReadUInt16 $entry $iref
    $realmLength = ReadUInt16 $entry $iref
    $idx         = [int]$iref.Value
    [byte[]]$realmBytesSlice = $entry[$idx..($idx+$realmLength-1)]
    $realm       = [Text.Encoding]::ASCII.GetString($realmBytesSlice)
    $iref.Value  = $idx + $realmLength

    # components (repeat compCount times)
    $components = @()
    for ($c = 0; $c -lt $compCount; $c++) {
    $len = ReadUInt16 $entry $iref
    $idx = [int]$iref.Value
    [byte[]]$compSlice = $entry[$idx..($idx+$len-1)]
    $components += ,([Text.Encoding]::ASCII.GetString($compSlice))
      $iref.Value  = $idx + $len
    }

    # nameType, timestamp
    $nameType  = ReadUInt32 $entry $iref
    $timestamp = ReadUInt32 $entry $iref

    # kvno8 (1 byte)
    $idx   = [int]$iref.Value
    $kvno8 = [int]$entry[$idx]
    $idx++
    $iref.Value = $idx
        
    # etype (UInt16), keyLength (UInt16), key bytes
    $etype     = ReadUInt16 $entry $iref
    $keyLength = ReadUInt16 $entry $iref
    $idx       = [int]$iref.Value
    $keyBytes  = $entry[$idx..($idx+$keyLength-1)]
    $iref.Value = $idx + $keyLength

    # optional kvno32 (UInt32); prefer over kvno8 if present and non-zero
    $kvno32 = $null
    if ($iref.Value + 4 -le $entry.Length) {
      $kvno32 = ReadUInt32 $entry $iref
    }
    $kvnoEffective = if ($kvno32 -and $kvno32 -ne 0) { [int]$kvno32 } else { $kvno8 }

    # build display values and add entry
    $keyHexFull = ($keyBytes | ForEach-Object { $_.ToString('x2') }) -join ''
    $keyDisplay = if ($RevealKeys) {
      if ($keyHexFull.Length -gt $MaxKeyHex) { $keyHexFull.Substring(0,$MaxKeyHex) + '...' } else { $keyHexFull }
    } else {
      if ($keyHexFull.Length -le 16) { $keyHexFull } else { $keyHexFull.Substring(0,8) + '...' + $keyHexFull.Substring($keyHexFull.Length-8,8) }
    }

    $rawKey = if ($RevealKeys) { $keyBytes } else { $null }
    $list.Add([pscustomobject]@{
      Realm      = $realm
      Components = $components
      NameType   = [int]$nameType
      TimestampUtc = ([DateTimeOffset]::FromUnixTimeSeconds([int]$timestamp).UtcDateTime)
      Kvno       = $kvnoEffective
      EtypeId    = $etype
      EtypeName  = Get-EtypeNameFromId $etype
      KeyLength  = $keyLength
      Key        = $keyDisplay
      RawKey     = $rawKey
    })
  }
  $list
}

#endregion



#region Other Helpers
# ---------------------------------------------------------------------- #
#
#                           Other Helpers
#
# ---------------------------------------------------------------------- #

function Set-UserOnlyAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path
  )

  try {
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $isDir = $false
  try { $isDir = (Get-Item -LiteralPath $Path -Force).PSIsContainer } catch {}
  $inheritFlags = if ($isDir) { 'ContainerInherit, ObjectInherit' } else { 'None' }
  $propFlags    = 'None'
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl',$inheritFlags,$propFlags,'Allow')
  $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
  } catch {
    Write-Warning "ACL restriction failed for '$Path': $($_.Exception.Message)"
  }
}

function Select-CombinedEtypes {
  param(
    [object[]]$KeySets
  )
  $set = New-Object System.Collections.Generic.HashSet[int]
  foreach ($keySet in $keySets) {
    foreach ($key in $keySet.Keys.Keys) { [void]$set.Add([int]$key) }
  }
  @($set)
}

#endregion


#region Core Creation Orchestration
# ---------------------------------------------------------------------- #
#
#                      Core Creation Orchestration
#
# ---------------------------------------------------------------------- #

function New-PrincipalKeytabInternal {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$SamAccountName,
    [Parameter(Mandatory)][string]$Domain,
    [string]$Server,
    [pscredential]$Credential,
    [string]$OutputPath,
    [object[]]$IncludeEtype,
    [object[]]$ExcludeEtype,
    [switch]$RestrictAcl,
    [switch]$Force,
    [string]$JsonSummaryPath,
    [string]$Justification,
    [switch]$PassThru,
    [switch]$Summary,
    [switch]$IsKrbtgt,
    [switch]$IncludeOldKvno,
    [switch]$IncludeOlderKvno,
    [object[]]$PrincipalDescriptorsOverride,
    [switch]$VerboseDiagnostics,
    [switch]$SuppressWarnings,
    [datetime]$FixedTimestampUtc
  )

  if (-not $OutputPath) {
    $base = $SamAccountName.TrimEnd('$')
    $OutputPath = Join-Path (Get-Location) "$base.keytab"
  }
  if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
      throw "Output file '$OutputPath' already exists. Use -Force to overwrite."
    }
  $domainFQDN = Resolve-DomainContext -Domain $Domain
  $realm = $DomainFQDN.ToUpperInvariant()

  $acct = Get-ReplicatedAccount -SamAccountName $SamAccountName -DomainFQDN $domainFQDN -Server $Server -Credential $Credential
  $material = Get-KerberosKeyMaterialFromAccount -Account $acct -SamAccountName $SamAccountName -DomainFQDN $domainFQDN -Server $Server -IsKrbtgt:$IsKrbtgt
  if ($VerboseDiagnostics) { $material.Diagnostics | Foreach-Object { Write-Verbose $_ } }

  # Filter Kvno sets if krbtgt and old kvnos and explicitly requested
  $keySets = @($material.KeySets | Sort-Object -Property Kvno -Descending)
  if ($IsKrbtgt) {
    $wanted = @()
    foreach ($keySet in $keySets) {
      if ($keySet.Kvno -eq $keySets[0].Kvno) { $wanted += $keySet; continue }
      if ($IncludeOldKvno   -and $keySet.Kvno -eq ($keySets[0].Kvno - 1)) { $wanted += $keySet; continue }
      if ($IncludeOlderKvno -and $keySet.Kvno -eq ($keySets[0].Kvno - 2)) { $wanted += $keySet; continue }
    }
    $keySets = $wanted
    if ($keySets.Count -eq 0) { throw "No key sets selected for krbtgt after KVNO filtering" }
  }

  $allEtypes = Select-CombinedEtypes -KeySets $keySets
  $selection = Resolve-EtypeSelection -AvailableIds ([int[]]$allEtypes) -Include $IncludeEtype -Exclude $ExcludeEtype
  if ($selection.UnknownInclude.Count -gt 0) { Write-Warning "Unknown IncludeEtype: $($selection.UnknownInclude -join ', ')" }
  if ($selection.UnknownExclude.Count -gt 0) { Write-Warning "Unknown ExcludeEtype: $($selection.UnknownExclude -join ', ')" }
  if ($selection.Missing.Count -gt 0) { Write-Warning "Requested Etypes not present: $($selection.Missing -join ', ')" }
  if ($selection.Selected.Count -eq 0) { throw "No encryption types selected. " }

  # Principal Descriptors
  $principalDescriptors = if ($PrincipalDescriptorsOverride) { $PrincipalDescriptorsOverride } else {
    if ($material.PrincipalType -eq 'User') {
      ,(Get-UserPrincipalDescriptor -SamAccountName $SamAccountName -Realm $realm)
    } elseif ($material.PrincipalType -eq 'Computer') {
      ,(Get-UserPrincipalDescriptor -SamAccountName $SamAccountName -Realm $realm)
    } elseif ($IsKrbtgt) {
      ,(Get-KrbtgtPrincipalDescriptor -Realm $realm)
    } else {
      throw "Unable to build principals for type '$($material.PrincipalType)'."
    }
  }

  $risk = $material.RiskLevel
  if ($IsKrbtgt -and -not $PSBoundParameters.ContainsKey('IncludeOldKvno')) {
    Write-Verbose "krbtgt: only current KVNO included (use -IncludeOldKvno / -IncludeOlderKvno to extend)."
  }
  if ($PSBoundParameters.ContainsKey('FixedTimestampUtc')) {
    $finalPath = New-KeytabFile -Path $OutputPath -PrincipalDescriptors $principalDescriptors -KeySets $keySets -EtypeFilter $selection.Selected -RestrictAcl:$RestrictAcl -FixedTimestampUtc $FixedTimestampUtc
  } else {
    $finalPath = New-KeytabFile -Path $OutputPath -PrincipalDescriptors $principalDescriptors -KeySets $keySets -EtypeFilter $selection.Selected -RestrictAcl:$RestrictAcl
  }

  Write-Host "Keytab written: $finalPath"
  # Summary
  if (-not $JsonSummaryPath) { $JsonSummaryPath = [IO.Path]::ChangeExtension($finalPath,'.json') }
  if ($Summary -or $PassThru) {
    $etypeNames = @($selection.Selected | ForEach-Object { Get-EtypeNameFromId $_ })
    $kvnos = @($keySets | Select-Object -ExpandProperty Kvno | Sort-Object -Unique)
    $generatedAt = if ($PSBoundParameters.ContainsKey('FixedTimestampUtc')) { $FixedTimestampUtc.ToUniversalTime().ToString('o') } else { (Get-Date).ToUniversalTime().ToString('o') }
    $summaryObj = [ordered]@{
      SamAccountName   = $SamAccountName
      PrincipalType    = $material.PrincipalType
      DomainFqdn       = $domainFqdn
      Realm            = $realm
      RiskLevel        = $risk
      Kvnos            = $kvnos
      Etypes           = $selection.Selected
      EncryptionTypes  = $etypeNames
      PrincipalCount   = $principalDescriptors.Count
      Principals       = @($principalDescriptors | ForEach-Object { $_.Display })
      OutputPath       = (Resolve-Path -LiteralPath $finalPath).Path
      GeneratedAtUtc   = $generatedAt
      Justification    = $Justification
      IncludeOldKvno   = [bool]$IncludeOldKvno
      IncludeOlderKvno = [bool]$IncludeOlderKvno
      HighImpact       = ($risk -in @('High','Critical'))
    }
    $summaryObj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonSummaryPath -Encoding UTF8
    if ($RestrictAcl) { Set-UserOnlyAcl -Path $JsonSummaryPath }
  }

  if ($PassThru) {
    [pscustomobject]@{
      SamAccountName  = $SamAccountName
      PrincipalType   = $material.PrincipalType
      RiskLevel       = $risk
      OutputPath      = $finalPath
      Etypes          = $selection.Selected
      Kvnos           = @($keySets.Kvno)
      PrincipalCount  = $principalDescriptors.Count
      SummaryPath     = $JsonSummaryPath
    }
  }
}

#endregion


#region Public Cmdlets
# ---------------------------------------------------------------------- #
#
#                           Public Cmdlets
#
# ---------------------------------------------------------------------- #

# Unified front-door with parameter sets for better UX
function New-Keytab {
  [CmdletBinding(DefaultParameterSetName='Auto', SupportsShouldProcess)]
  param(
    # Common
    [Parameter(Mandatory, ParameterSetName='Auto')]
    [Parameter(Mandatory, ParameterSetName='User')]
    [Parameter(Mandatory, ParameterSetName='Computer')]
    [Parameter(Mandatory, ParameterSetName='Krbtgt')]
    [string]$SamAccountName,

    [Parameter(ParameterSetName='Auto')]
    [ValidateSet('Auto','User','Computer','Krbtgt')]
    [string]$Type = 'Auto',

    [string]$Domain,
    [string]$Server,
    [pscredential]$Credential,
    [string]$EnvFile,
    [string]$OutputPath,
    [object[]]$IncludeEtype = @(18,17,23),
    [object[]]$ExcludeEtype,
    [switch]$RestrictAcl,
    [switch]$Force,
    [string]$JsonSummaryPath,
    [switch]$PassThru,
    [switch]$Summary,
    [string]$Justification,
    [switch]$IncludeOldKvno,
    [switch]$IncludeOlderKvno,
    [switch]$AcknowledgeRisk,
    [switch]$VerboseDiagnostics,
    [switch]$SuppressWarnings,
    [datetime]$FixedTimestampUtc,

    # Computer-only extras
    [Parameter(ParameterSetName='Auto')]
    [Parameter(ParameterSetName='Computer')]
    [switch]$IncludeShortHost,
    [Parameter(ParameterSetName='Auto')]
    [Parameter(ParameterSetName='Computer')]
    [string[]]$AdditionalSpn
  )
  #Get-RequiredModule -Name ActiveDirectory
  #Get-RequiredModule -Name DSInternals

  if (-not $Credential -and $EnvFile) { $Credential = Get-CredentialFromEnv -EnvFile $EnvFile }

  if (-not $fixedTimestampUtc ) { $fixedTimestampUtc = [datetime]::UtcNow }

  $type = $PSCmdlet.ParameterSetName
  $norm = $SamAccountName.ToUpperInvariant()
  if ($type -eq 'Auto') {
    if ($norm -eq 'KRBTGT') { $type = 'Krbtgt' }
    elseif ($SamAccountName -match '\$$') { $type = 'Computer' }
    else { $type = 'User' }
  }

  switch ($type) {
    'Krbtgt' {
      if (-not $AcknowledgeRisk) { throw "Extraction of krbtgt is High/Critical impact. Re-run with -AcknowledgeRisk after justification review." }
      if ($PSCmdlet.ShouldProcess('krbtgt',"Create krbtgt keytab (multi-KVNO possible)")) {
        if (-not $SuppressWarnings.IsPresent) { try { Write-SecurityWarning -RiskLevel 'krbtgt' -SamAccountName 'krbtgt' | Out-Null } catch {} }
        return New-PrincipalKeytabInternal -SamAccountName 'krbtgt' -Domain $Domain -Server $Server -Credential $Credential `
                                           -OutputPath $OutputPath -IncludeEtype $IncludeEtype -ExcludeEtype $ExcludeEtype -IsKrbtgt `
                                           -IncludeOldKvno:$IncludeOldKvno -IncludeOlderKvno:$IncludeOlderKvno -RestrictAcl:$RestrictAcl -Force:$Force `
                                           -JsonSummaryPath $JsonSummaryPath -PassThru:$PassThru -Summary:$Summary -Justification $Justification `
                                           -VerboseDiagnostics:$VerboseDiagnostics -FixedTimestampUtc $FixedTimestampUtc
      }
    }
    'Computer' {
      $domainFqdn = Resolve-DomainContext -Domain $Domain
      $realm = $domainFqdn.ToUpperInvariant()
      $compName = $SamAccountName.TrimEnd('$')

      $desc = Get-ComputerPrincipalDescriptors -ComputerName $compName -DomainFqdn $domainFqdn -IncludeShortHost:$IncludeShortHost
      if ($AdditionalSpn) {
        foreach ($p in $AdditionalSpn) {
          if ($p -notmatch '/') { continue }
          $parts = $p.Split('/',2)
          $svc = $parts[0]; $ihost = $parts[1]
          $desc += ,(New-PrincipalDescriptor -Components @($svc.ToLowerInvariant(),$ihost.ToLowerInvariant()) -Realm $realm -NameType $script:NameTypes.KRB_NT_SRV_HST -Tags @('Explicit'))
        }
      }
      if ($desc.Count -eq 0) { throw "No SPN principals resolved for computer '$compName'." }

      if ($PSCmdlet.ShouldProcess($compName,"Create computer keytab")) {
        if (-not $SuppressWarnings.IsPresent) { try { Write-SecurityWarning -RiskLevel 'High' -SamAccountName ("{0}$" -f $compName) | Out-Null } catch {} }
        return New-PrincipalKeytabInternal -SamAccountName ("{0}$" -f $compName) -Domain $domainFqdn -Server $Server -Credential $Credential `
                                           -OutputPath $OutputPath -IncludeEtype $IncludeEtype -ExcludeEtype $ExcludeEtype -RestrictAcl:$RestrictAcl -Force:$Force `
                                           -JsonSummaryPath $JsonSummaryPath -PassThru:$PassThru -Summary:$Summary -Justification $Justification `
                                           -PrincipalDescriptorsOverride $desc -VerboseDiagnostics:$VerboseDiagnostics -FixedTimestampUtc $FixedTimestampUtc
      }
    }
    'User' {
      $userName = $SamAccountName
      if ($PSCmdlet.ShouldProcess($userName,"Create user keytab")) {
        if (-not $SuppressWarnings.IsPresent) { try { Write-SecurityWarning -RiskLevel 'Medium' -SamAccountName $userName | Out-Null } catch {} }
        return New-PrincipalKeytabInternal -SamAccountName $userName -Domain $Domain -Server $Server -Credential $Credential `
                                           -OutputPath $OutputPath -IncludeEtype $IncludeEtype -ExcludeEtype $ExcludeEtype `
                                           -RestrictAcl:$RestrictAcl -Force:$Force -JsonSummaryPath $JsonSummaryPath -PassThru:$PassThru `
                                           -Summary:$Summary -Justification $Justification -VerboseDiagnostics:$VerboseDiagnostics -FixedTimestampUtc $FixedTimestampUtc
      }
    }
  }
}

function Merge-Keytab {
  [CmdletBinding()]
  param(
  [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][string[]]$InputPaths,
    [Parameter(Mandatory)][string]$OutputPath,
    [switch]$Force,
    [switch]$RestrictAcl,
    [switch]$AcknowledgeRisk
  )

  if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
    throw "Output file '$OutputPath' already exists. Use -Force to overwrite."
  }
  $entries = New-Object System.Collections.Generic.List[object]
  $krbtgtPresent = $false
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
  $OutputPath
}

function Test-Keytab {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$Detailed
  )
  if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
  $result = @{
    IsValid = $false
    EntryCount = 0
    UnknownEtypes = @()
    Warnings = New-Object System.Collections.Generic.List[string]
  }
  try {
    $parsed = Read-Keytab -Path $Path
    $result.EntryCount = $parsed.Count
    $unknown = @()
    foreach ($e in $parsed) {
      if (-not $script:ReverseEtypeMap.ContainsKey($e.EtypeId)) {
        if ($unknown -notcontains $e.EtypeId) { $unknown += $e.EtypeId }
      }
    }
    $result.UnknownEtypes = $unknown
    $result.IsValid = $true
  } catch {
    $result.Warnings.Add($_.Exception.Message)
    $result.IsValid = $false
  }
  if ($Detailed) { 
    return [pscustomobject]$result 
  } else { 
    return $result.IsValid 
  }
}

function Protect-Keytab {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$OutputPath,
    [Validateset('CurrentUser','LocalMachine')][string]$Scope = 'CurrentUser',
    [string]$Entropy,
    [switch]$Force,
    [switch]$DeletePlaintext,
    [switch]$RestrictAcl
  )

  if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
  if (-not $OutputPath) { $OutputPath = "$Path.dpapi" }
  if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
    throw "Output file '$OutputPath' already exists. Use -Force to overwrite."
  }

  $bytes = [IO.File]::ReadAllBytes($Path)
  $entropyBytes = if ($Entropy) { [Text.Encoding]::UTF8.GetBytes($Entropy) } else { $null }
  $scopeEnum = if ($Scope -eq 'LocalMachine') { 
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine 
  } else { 
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser 
  }

  try {
    $protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $entropyBytes, $scopeEnum)
    [IO.File]::WriteAllBytes($OutputPath, $protected)
    if ($RestrictAcl) { Set-UserOnlyAcl -Path $OutputPath }
  } finally {
    if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    if ($protected) { [Array]::Clear($protected, 0, $protected.Length) }
    if ($entropyBytes) { [Array]::Clear($entropyBytes, 0, $entropyBytes.Length) }
  }

  if ($DeletePlainText) {
    try { Remove-Item -LiteralPath $Path -Force } catch { Write-Warning "Failed to delete plaintext '$Path': $($_.Exception.Message)" }
  }
  $OutputPath
}

function Unprotect-Keytab {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$OutputPath,
    [ValidateSet('CurrentUser','LocalMachine')][string]$Scope = 'CurrentUser',
    [string]$Entropy,
    [switch]$Force,
    [switch]$RestrictAcl
  )
  if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
  if (-not $OutputPath) {
    if ($Path -like '*.dpapi') { $OutputPath = $Path.Substring(0, $Path.Length - 6) } else { $OutputPath = "$Path.unprotected.keytab" }
  }
  if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
    throw "Output file '$OutputPath' already exists. Use -Force to overwrite."
  }

  $bytes = [IO.File]::ReadAllBytes($Path)
  $entropyBytes = if ($Entropy) { [Text.Encoding]::UTF8.GetBytes($Entropy) } else { $null }
  $scopeEnum = if ($Scope -eq 'LocalMachine') {
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
  } else {
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
  }

  try {
    $plain = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropyBytes, $scopeEnum)
    [IO.File]::WriteAllBytes($OutputPath, $plain)
    if ($RestrictAcl) { Set-UserOnlyAcl -Path $OutputPath }
  } finally {
    if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
    if ($entropyBytes) { [Array]::Clear($entropyBytes, 0, $entropyBytes.Length) }
  }
  $OutputPath
}

Export-ModuleMember -Function `
  New-Keytab, `
  Merge-Keytab, `
  Test-Keytab, `
  Read-Keytab, `
  # Dev / Unit Testing
  Protect-Keytab, `
  Unprotect-Keytab, `
  Get-EtypeIdFromInput, `
  Get-EtypeNameFromId, `
  Resolve-EtypeSelection, `
  New-PrincipalDescriptor, `
  Write-SecurityWarning, `
  Select-CombinedEtypes, `
  Set-UserOnlyAcl, `
  Resolve-DomainContext, `
  ConvertTo-NetBIOSIfFqdn, `
  Get-KerberosKeyMaterialFromAccount, `
  New-KeytabFile
#endregion