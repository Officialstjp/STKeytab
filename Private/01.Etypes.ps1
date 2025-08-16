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

function Get-EtypeIdFromInput {
  <#
    .SYNOPSIS
    Normalize an encryption type input (name or id) to an integer id.
  #>
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
  <#
    .SYNOPSIS
    Get the Kerberos encryption type name for an integer id.
  #>
  param(
    [Parameter(Mandatory)][int]$Id
    )
  if ($script:ReverseEtypeMap.ContainsKey($Id)) { return $script:ReverseEtypeMap[$Id] }
    return "ETYPE_$Id"
}

function Resolve-EtypeSelection {
  <#
    .SYNOPSIS
    Compute final etype selection from available, include, and exclude lists.
  #>
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
    Selected       = @([int[]]$selected | Sort-Object -Unique)
    Missing        = $missing
    UnknownInclude = $unknownIncluded
    UnknownExclude = $unknownExcluded
  }
}

function Select-CombinedEtypes {
  <#
    .SYNOPSIS
    Return the set of unique etype ids present across key sets.
  #>
  param(
    [object[]]$KeySets
  )
  $set = New-Object System.Collections.Generic.HashSet[int]
  foreach ($keySet in $keySets) {
    foreach ($key in $keySet.Keys.Keys) { [void]$set.Add([int]$key) }
  }
  @($set)
}
