<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


<#
.SYNOPSIS
This module provides functions for managing Kerberos keytabs.

.CHANGE LOG
Date       Auth           Ver       Change
---------- -------------- -------- ------------------------------------------------
10.08.25   Stjp           1.0      Initial version
16.08.25   Stjp           1.1      Refactor, Add New-Keytab, New-KeytabFromPassword, Read-Keytab, Test-Keytab, Merge-Keytab, Protect-Keytab / Unprotect-Keytab
17.08.25   Stjp           1.2      Add Compare-Keytab, ConvertTo-KeytabJson, ConvertFrom-KeytabJson
17.08.25   Stjp           1.2.1    Add headers across all functions, parameter descriptions and Valuefrompipeline support,
                                   begin - process - end structure for all public functions
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
if (!$here) {
    $here = Split-Path -Parent $PSCommandPath
    if (!$here) {
        $here = Get-Location
        if (!$here) {
            Write-Error "[!!] Unable to determine script location."
            exit 1
        }
    }
}

# Private first (sorted; allow 00., 10., … prefixes)
$privateDir = Join-Path $here 'Private'
if (Test-Path -LiteralPath $privateDir) {
  Get-ChildItem -LiteralPath $privateDir -Filter *.ps1 -File | Sort-Object Name |
    ForEach-Object {
      try {
        . $_.FullName
      } catch {
        Write-Error "Failed to dot-source Private/$($_.Name): $_"
      }
    }
}



# Public next
$publicDir = Join-Path $here 'Public'
$publicScripts = @()
if (Test-Path -LiteralPath $publicDir) {
  $publicScripts = Get-ChildItem -LiteralPath $publicDir -Filter *.ps1 -File | Sort-Object Name
  foreach ($file in $publicScripts) {
    try {
      . $file.FullName
    } catch {
      Write-Error "Failed to dot-source Public/$($file.Name): $_"
    }
  }
}

# Export public only (filename == function name)
if ($publicScripts) {
  $exportNames = $publicScripts | Select-Object -ExpandProperty BaseName
  Export-ModuleMember -Function $exportNames
} else {
  Export-ModuleMember # Export nothing explicitly if no public scripts found
}
