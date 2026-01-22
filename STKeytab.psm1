<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


<#
.SYNOPSIS
Main import-orchestrator for the STKeytab module.

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

# Unblock module files (useful when downloaded from internet)
try {
    $moduleFiles = @(
        Get-ChildItem -Path $here -Include '*.ps1', '*.psm1', '*.psd1' -Recurse -File |
        Where-Object { $_.FullName -like "$here*" }
    )

    if ($moduleFiles.Count -gt 0) {
        $moduleFiles | Unblock-File -ErrorAction SilentlyContinue
    }
} catch {
    # Unblock-File may fail on non-Windows or restricted environments; safe to ignore
    Write-Verbose "Unblock-File skipped: $($_.Exception.Message)"
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
