function Test-Keytab {
  <#
    .SYNOPSIS
    Validate a keytab file and report stats.

    .DESCRIPTION
    Lightweight validation that counts entries and flags unknown encryption types.
  #>
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