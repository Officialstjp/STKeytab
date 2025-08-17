<#
.SYNOPSIS
This module provides functions for managing Kerberos keytabs.

.CHANGE LOG
Date       Auth           Ver       Change
---------- -------------- -------- ------------------------------------------------
10.08.     Stjp           1.0      Initial version
16.08.     Stjp           1.1      Refactor, Add New-Keytab, New-KeytabFromPassword, Read-Keytab, Test-Keytab, Merge-Keytab, Protect-Keytab / Unprotect-Keytab
17.08.     Stjp           1.2      Add Compare-Keytab, ConvertTo-KeytabJson, ConvertFrom-KeytabJson

#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

# Private first (sorted; allow 00., 10., … prefixes)
Get-ChildItem "$here/Private" -Filter *.ps1 | Sort-Object Name |
  ForEach-Object { . (Join-Path $here "Private/$($_.Name)") }

# Public next
$pub = Get-ChildItem "$here/Public" -Filter *.ps1 | Sort-Object Name
$pub | ForEach-Object { 
  try {
    . (Join-Path $here "Public/$($_.Name)") 
  } catch {
    Write-Error "Failed to dot-source Public/$($_.Name): $_"
  }
  
}

# Export public only (filename == function name)
Export-ModuleMember -Function $pub.BaseName

