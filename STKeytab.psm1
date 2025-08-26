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
10.08.25   Stjp           0.1      Initial version
16.08.25   Stjp           0.2      Refactor, Add New-Keytab, New-KeytabFromPassword, Read-Keytab, Test-Keytab, Merge-Keytab, Protect-Keytab / Unprotect-Keytab
17.08.25   Stjp           0.32     Add Compare-Keytab, ConvertTo-KeytabJson, ConvertFrom-KeytabJson
17.08.25   Stjp           0.3.1    Add headers across all functions, parameter descriptions and Valuefrompipeline support,
                                   begin - process - end structure for all public functions
26.08.25   Stjp           0.4      Add external help generation, add cmdlet help docs,..
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
    $privateScripts = Get-ChildItem -LiteralPath $privateDir -Filter *.ps1 -File | Sort-Object Name
    foreach ($script in $privateScripts) {
        try {
            $scriptPath = if ($script.PSIsContainer -or -not $script.FullName) { $script } else { $script.FullName }
            . $scriptPath
        } catch {
            $fileName = if ($script -is [System.IO.FileInfo]) { $script.Name } else { $script }
            Write-Error "Failed to dot-source Private/$fileName`: $_"
        }
    }
}


# Public next
$publicDir = Join-Path $here 'Public'

$publicScripts = @()
if (Test-Path -LiteralPath $publicDir) {
    $publicScripts = Get-ChildItem -LiteralPath $publicDir -Filter *.ps1 -File | Sort-Object Name
    foreach ($script in $publicScripts) {
        try {
            $scriptPath = if ($script.PSIsContainer -or -not $script.FullName) { $script } else { $script.FullName }
            . $scriptPath
        } catch {
            $fileName = if ($script -is [System.IO.FileInfo]) { $script.Name } else { $script }
            Write-Error "Failed to dot-source Public/$fileName`: $_"
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
