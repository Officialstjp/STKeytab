<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

<#
.SYNOPSIS
Publishes external help artifacts to GitHub Releases for Update-Help support.

.DESCRIPTION
Creates a GitHub release tagged for help distribution and uploads the CAB and
HelpInfo.xml files. Updates module manifest HelpInfoURI to point to the release.

.PARAMETER Version
The version tag for the help release (e.g., "help-v1.2.0").

.PARAMETER ArtifactsPath
Path to the artifacts directory containing CAB and HelpInfo.xml files.

.PARAMETER UpdateManifest
Whether to update the module manifest with the new HelpInfoURI.

.PARAMETER DryRun
Show what would be done without making changes.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$Version,

    [string]$ArtifactsPath = 'artifacts/docs',

    [switch]$UpdateManifest,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptRoot = Split-Path -Parent $PSCommandPath
$RepoRoot = Split-Path -Parent $ScriptRoot
$ManifestPath = Join-Path $RepoRoot 'STKeytab.psd1'
$ArtifactsFullPath = Join-Path $RepoRoot $ArtifactsPath

# Validate inputs
if (-not (Test-Path $ArtifactsFullPath)) {
    throw "Artifacts path not found: $ArtifactsFullPath"
}

$helpFiles = @(
    Get-ChildItem -Path $ArtifactsFullPath -Filter "*_HelpInfo.xml"
    Get-ChildItem -Path $ArtifactsFullPath -Filter "*_HelpContent.cab"
)

if ($helpFiles.Count -eq 0) {
    throw "No help files found in $ArtifactsFullPath. Run './CI/Build-Docs.ps1 -Mode Update' first."
}

Write-Host "Found help files:" -ForegroundColor Green
$helpFiles | ForEach-Object { Write-Host "  $($_.Name)" }

# Check if gh CLI is available
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI (gh) not found. Install from https://cli.github.com/"
}

# Determine the release URL
$repoInfo = & gh repo view --json owner,name | ConvertFrom-Json
$helpUri = "https://github.com/$($repoInfo.owner.login)/$($repoInfo.name)/releases/download/$Version/"

Write-Host "Target HelpInfoURI: $helpUri" -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "[DRY RUN] Would create release: $Version" -ForegroundColor Yellow
    Write-Host "[DRY RUN] Would upload files:" -ForegroundColor Yellow
    $helpFiles | ForEach-Object { Write-Host "  [DRY RUN] $($_.FullName)" -ForegroundColor Yellow }

    if ($UpdateManifest) {
        Write-Host "[DRY RUN] Would update manifest HelpInfoURI to: $helpUri" -ForegroundColor Yellow
    }
    return
}

# Create the release if it doesn't exist
$existingRelease = & gh release view $Version 2>$null
if (-not $existingRelease) {
    if ($PSCmdlet.ShouldProcess("GitHub", "Create release $Version")) {
        Write-Host "Creating release: $Version" -ForegroundColor Green
        & gh release create $Version --title "Help Content $Version" --notes "External help files for Update-Help support."
    }
} else {
    Write-Host "Release $Version already exists." -ForegroundColor Yellow
}

# Upload the help files
if ($PSCmdlet.ShouldProcess("GitHub release $Version", "Upload help artifacts")) {
    Write-Host "Uploading help files to release..." -ForegroundColor Green
    $helpFiles | ForEach-Object {
        Write-Host "  Uploading $($_.Name)..."
        & gh release upload $Version $_.FullName --clobber
    }
}

# Update module manifest if requested
if ($UpdateManifest -and $PSCmdlet.ShouldProcess($ManifestPath, "Update HelpInfoURI")) {
    Write-Host "Updating module manifest HelpInfoURI..." -ForegroundColor Green

    $manifestContent = Get-Content $ManifestPath -Raw
    $newContent = $manifestContent -replace 'HelpInfoURI\s*=\s*[''"][^''"]*[''"]', "HelpInfoURI = '$helpUri'"

    Set-Content -Path $ManifestPath -Value $newContent -Encoding UTF8
    Write-Host "Updated HelpInfoURI to: $helpUri" -ForegroundColor Green
}

Write-Host "`nHelp publishing complete!" -ForegroundColor Green
Write-Host "Users can now run: Update-Help -Module STKeytab" -ForegroundColor Cyan
