<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


<#
.SYNOPSIS
Consolidates CI actions: setup, tests, script analyzer, import signing cert, sign, package, and test signed module.
Reuses local utilities in CI\Test-Sign\*.ps1.
#>
[CmdletBinding()]
param(
    [ValidateSet('Setup','Test','Analyze','ImportCert','Sign','Package','TestSigned','All')]
    [Parameter(Mandatory)][string]$Step,

    [string]$CertificateBase64,
    [string]$SigningCertPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $PSCommandPath
$RepoRoot   = Split-Path -Parent $scriptRoot

function Write-Log {
    param (
        [string]$Message,
        [string]$level = "INFO"
    )
    $prefix = switch ($level) {
        'INFO' { '[+]' }
        'WARNING' { '[~]' }
        'ERROR' { '[!!]' }
        default { '[*]' }
    }
    Write-Host "$prefix $Message"
}

function Add-GitHubEnv {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    if ($env:GITHUB_ENV) {
        Add-Content -Path $env:GITHUB_ENV -Value "$Name=$Value"
    } else {
        Write-Log "GITHUB_ENV not set; skipping env export of $Name" 'WARNING'
    }
}

function Add-GithubOutput {
    param (
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    if ($env:GITHUB_OUTPUT) {
        Add-Content -Path $env:GITHUB_OUTPUT -Value "$Name=$Value"
    } else {
        Write-Log "GITHUB_OUTPUT not set; skipping output export of $Name" 'WARNING'
    }
}

function Ensure-Modules {
    Write-Log "Ensuring modules..."
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    If (-not (Get-Module -Name PSScriptAnalyzer -ListAvailable)) {
        Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
    }
    If (-not (Get-Module -Name Pester -ListAvailable)) {
        Install-Module -Name Pester -Force -Scope CurrentUser
    }
    Import-Module Pester -ErrorAction Stop
}

function Invoke-PesterTests {
    Write-Log "Running Pester tests..."
    $config = New-PesterConfiguration
    $config.Run.Path = Join-Path $RepoRoot 'tests'
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputFormat = 'NUnitXml'
    $config.TestResult.OutputPath = Join-Path $RepoRoot 'TestResults.xml'
    $config.Output.Verbosity = 'Detailed'
    Push-Location $RepoRoot
    try {
        Invoke-Pester -Configuration $config
        Add-GithubEnv -Name "TEST_RESULTS_PATH" -Value $config.TestResult.OutputPath
    } finally {
        Pop-Location
    }
}

function Invoke-CiScriptAnalyzer {
    Write-Log "Running PSScriptAnalyzer..."
    $script = Join-Path $RepoRoot 'CI\Test-Sign\Run-PSScriptAnalyzer.ps1'
    if (-not (Test-Path $script)) {
        throw "PSScriptAnalyzer helper not found: $script"
    }
    Push-Location $RepoRoot
    try {
        & $script
    } finally {
        Pop-Location
    }
}

function Import-SigningCert {
    param(
        [string]$CertificateBase64,
        [string]$SigningCertPassword
    )
    if ([string]::IsNullOrWhitespace($CertificateBase64)) {
        Write-Log "No signing certificate provided. Signing will be skipped." 'WARNING'
        Add-GithubEnv -Name "SKIP_SIGNING" -Value "true"
        return
    }
    if ([string]::IsNullOrWhiteSpace($SigningCertPassword)) {
        throw "No signing certificate password provided (empty). Ensure the workflow passes a non-empty value to -SigningCertPassword."
    }
    $import = Join-Path $RepoRoot 'CI\Test-Sign\Import-SigningCert.ps1'
    if (-not (Test-Path $import)) { throw "Import-SigningCert helper not found: $import" }
    $thumb = & $import -CertificateBase64 $CertificateBase64 -Password $SigningCertPassword
    if (-not $thumb) { throw "Failed to import signing certificate." }
    Add-GitHubEnv -Name "CERT_THUMBPRINT" -Value $thumb
    Write-Log "Imported signing cert. Thumbprint: $thumb"
}

function Sign-ModuleFiles {
    $thumb = $env:CERT_THUMBPRINT
    if ([string]::IsNullOrWhiteSpace($thumb)) {
    Write-Log "CERT_THUMBPRINT not set; skipping signing." 'WARNING'
        Add-GitHubEnv -Name "SKIP_SIGNING" -Value "true"
        return
    }
    $signer = Join-Path $RepoRoot 'CI\Test-Sign\Sign-Module.ps1'
    if (-not (Test-Path $signer)) { throw "Sign-Module helper not found: $signer" }
    Write-Log "Signing module files with $thumb ..."
    & $signer -CertificateThumbprint $thumb -Verify -ModulePath $RepoRoot
}

function Package-Module  {
    Push-Location $RepoRoot
    try {
        $manifestPath = Join-Path $RepoRoot 'STKeytab.psd1'
        $manifest = Import-PowerShellDataFile -Path $manifestPath
        $version = $manifest.ModuleVersion
        $signedSuffix = if ($env:SKIP_SIGNING) { 'Unsigned' } else { 'Signed' }
        $packageName = "STKeytab-v$version-$signedSuffix"
        Write-Log "Creating package: $packageName"

        $packageDir = ".\package\STKeytab"
        if (Test-Path .\package) { Remove-Item .\package -Recurse -Force }
        New-Item -ItemType Directory -Path $packageDir -Force | Out-Null

        Copy-Item -Path @(".\STKeytab.psd1", ".\STKeytab.psm1") -Destination $packageDir -Force -Verbose
        Copy-Item -Path @("Public", "Private") -Destination $packageDir -Recurse -Force -Verbose
        foreach ($doc in @("README.md","LICENSE","NOTICE")) {
            if (Test-Path $doc) { Copy-Item -Path $doc -Destination $packageDir -Force -Verbose }
        }

        $archivePath = "$packageName.zip"
        Compress-Archive -Path "$packageDir\*" -DestinationPath $archivePath -Force

        $packageInfo = @{
            PackageName = $packageName
            Version     = $version
            ArchivePath = (Resolve-Path $archivePath).Path
            CreatedAt   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss\Z")
            Signed      = $env:SKIP_SIGNING -ne 'true'
            CommitHash  = ($env:GITHUB_SHA ?? '') -replace '^(.{0,8}).*$', '$1'
            Branch      = $env:GITHUB_REF_NAME
        }
        $packageInfo | ConvertTo-Json -Depth 2 | Set-Content "package-info.json"

        Add-GitHubEnv -Name "PACKAGE_NAME" -Value $packageName
        Add-GitHubEnv -Name "PACKAGE_PATH" -Value $archivePath
        Add-GitHubEnv -Name "MODULE_VERSION" -Value $version

        Write-Log "Package created successfully: $archivePath"
    } finally {
        Pop-Location
    }
}

function Test-SignedModule {
    if ($env:SKIP_SIGNING -eq 'true') {
    Write-Log "Signing skipped; not testing signed module." 'WARNING'
        return
    }

    Push-Location $RepoRoot
    try {
        $modulePath = ".\package\STKeytab\STKeytab.psd1"
        if (-not (Test-Path -LiteralPath $modulePath)) { throw "Module manifest not found at $modulePath" }
        Write-Log "Importing module: $modulePath"
        Import-Module -Name $modulePath -Force -ErrorAction Stop
        $commands = Get-Command -Module STKeytab
        Write-Log "Packaged module loaded successfully with $($commands.Count) commands"

        # Verify signatures
        $moduleFiles = Get-ChildItem .\package\STKeytab -Recurse -Include "*.ps1","*.psm1","*.psd1"
        $signedCount = 0
        foreach ($file in $moduleFiles) {
            $sig = Get-AuthenticodeSignature -FilePath $file.FullName
            if ($sig.Status -eq 'Valid') { $signedCount++ }
        }
        Write-Log "Verified $signedCount/$($moduleFiles.Count) files are properly signed"
    } finally {
        Pop-Location
    }
}

switch ($Step) {
    'Setup'      { Ensure-Modules }
    'Test'       { Invoke-PesterTests }
    'Analyze'    { Invoke-CiScriptAnalyzer }
    'ImportCert' { Import-SigningCert -CertificateBase64 $CertificateBase64 -SigningCertPassword $SigningCertPassword }
    'Sign'       { Sign-ModuleFiles }
    'Package'    { Package-Module }
    'TestSigned' { Test-SignedModule }
    'All'        {
        Ensure-Modules
        Invoke-PesterTests
        Invoke-CiScriptAnalyzer
        Import-SigningCert -CertificateBase64 $CertificateBase64 -SigningCertPassword $SigningCertPassword
        Sign-ModuleFiles
        Package-Module
        Test-SignedModule
    }
    default { throw "Unknown step: $Step" }
}
