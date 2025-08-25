<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


<#
.SYNOPSIS
Builds and validates module documentation using PlatyPS.
Supports drift detection, in-place updates, external help (MAML) generation,
CAB packaging, and optional auto-commit on self-hosted runners.
#>
[CmdletBinding()]
param(
    [ValidateSet('Validate','Update')]
    [string]$Mode = 'Validate',
    [switch]$FailOnDrift = $true,
    [switch]$AutoCommit,
    [string]$CommitMessage = 'docs: update generated help',
    [string]$Locale = 'en-US',
    [string]$ArtifactsDir = 'artifacts/docs'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot   = Split-Path -Parent $ScriptRoot
Push-Location $repoRoot
try {
    Import-Module PlatyPS -ErrorAction Stop

    $ModuleManifest = Join-Path $repoRoot 'STKeytab.psd1'
    $ModuleName     = 'STKeytab'
    $DocsPath       = Join-Path $repoRoot 'docs'
    # External help location in repo (standard PowerShell layout)
    $OutHelpPath    = Join-Path $repoRoot $Locale

    if (-not (Test-Path $ModuleManifest)) { throw "Module manifest not found: $ModuleManifest" }
    if (-not (Test-Path $DocsPath)) { throw "Documentation folder not found: $DocsPath" }
    if (-not (Test-Path $OutHelpPath)) { New-Item -ItemType Directory -Path $OutHelpPath | Out-Null }

    Import-Module $ModuleManifest -Force -ErrorAction Stop

    Write-Host "Validating markdown help in '$DocsPath'"
    Test-MarkdownHelp -Path $DocsPath -ErrorAction Stop

    $docsChanged = $false
    switch ($Mode) {
        'Update' {
            Write-Host "Updating markdown help in-place (docs/) ..."
            Update-MarkdownHelp -Module $ModuleName -OutputFolder $DocsPath -Force -ErrorAction Stop | Out-Null
            $docsChanged = $true
        }
        'Validate' {
            if ($FailOnDrift) {
                $TempDocs = Join-Path $repoRoot 'temp\docs-generated'
                if (Test-Path $TempDocs) { Remove-Item $TempDocs -Recurse -Force }
                New-Item -ItemType Directory -Path $TempDocs | Out-Null

                Write-Host "Checking for help drift (Update-MarkdownHelp -> temp)..."
                Update-MarkdownHelp -Module $ModuleName -OutputFolder $TempDocs -Force -ErrorAction Stop | Out-Null

                # compare with current docs (using git if available)
                $diffCount = 0
                if (Get-Command git -ErrorAction SilentlyContinue) {
                    $null = Start-Process git -ArgumentList @('--no-pager','diff','--no-index','--name-only',"$DocsPath","$TempDocs") -PassThru -NoNewWindow -Wait
                    $diffOutput = & git --no-pager diff --no-index --name-only "$DocsPath" "$TempDocs"
                    $diffCount = ($diffOutput | Where-Object { $_ -ne '' }).Count
                } else {
                    # Fallback: Compare file hashes
                    function Get-FileHashMap ($root) {
                        Get-ChildItem -Path $root -Recurse -File | ForEach-Object {
                            [pscustomobject]@{
                                Rel = $_.FullName.Substring($root.Length).TrimStart('\\','/')
                                Hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
                            }
                        }
                    }
                    $a = Get-FileHashMap $DocsPath
                    $b = Get-FileHashMap $TempDocs
                    $cmp = Compare-Object -ReferenceObject $a -DifferenceObject $b -Property Rel, Hash
                    $diffCount = ($cmp | Measure-Object).Count
                }

                if ($diffCount -gt 0) {
                    Write-Error "Docs drift detected. Run 'Update-MarkdownHelp -Module $ModuleName -OutputFolder docs -Force' locally and commit."
                } else {
                    Write-Host "No docs drift detected."
                }
            }
        }
    }

    # Generate external help (MAML XML) always
    Write-Host "Generating external help to '$OutHelpPath'..."
    New-ExternalHelp -Path $DocsPath -OutputPath $OutHelpPath -Force | Out-Null

    # Build CAB for help distribution
    $Artifacts = Join-Path $repoRoot $ArtifactsDir
    if (-not (Test-Path $Artifacts)) { New-Item -ItemType Directory -Path $Artifacts | Out-Null }

    $manifest = Test-ModuleManifest -Path $ModuleManifest
    $version  = $manifest.Version.ToString()

    Write-Host "Creating external help CAB..."
    New-ExternalHelpCab `
        -ExternalHelpPath $OutHelpPath `
        -CabOutputPath $Artifacts `
        -Locale $Locale `
        -Module $ModuleName `
        -Version $version | Out-Null

    Write-Host "Artifacts ready in '$Artifacts'."

    # Auto-commit updated docs/en-US if requested
    if ($AutoCommit) {
        if (Get-Command git -ErrorAction SilentlyContinue) {
            # Stage only if there are changes
            $status = & git status --porcelain
            if ($status) {
                & git add --all -- docs $Locale 2>$null
                & git config user.name  "s-githa"
                & git config user.email "s-githa@local.local"
                & git commit -m $CommitMessage
                Write-Host "Committed documentation updates."
            } else {
                Write-Host "No changes to commit."
            }
        } else {
            Write-Warning "git not available; skipping AutoCommit."
        }
    }
}
finally {
    Pop-Location
}
