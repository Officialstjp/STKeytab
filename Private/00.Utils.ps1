<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


# region Constants
# Kerberos principal name types used by the keytab writer and principal helpers
$script:NameTypes = @{
    KRB_NT_PRINCIPAL = 1  # Named user or krbtgt principal
    KRB_NT_SRV_HST   = 3  # Service with host name as instance (e.g., host/fqdn)
}

# Coarse classification for special/high-impact principals
$script:HighImpactPrincipals = @{ 'KRBTGT' = $true }


#endregion

# region Utility & Dependency
# ---------------------------------------------------------------------- #
#
#                       Utility & Dependency
#
# ---------------------------------------------------------------------- #

function Get-RequiredModule {
    <#
        .SYNOPSIS
        Ensure a PowerShell module is installed.
    #>
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
    <#
    .SYNOPSIS
    Get a PSCredential object from environment variables.
    #>
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

function New-StrongPassword {
    <#
    .SYNOPSIS
    Generate a cryptographically strong random password.
    #>
    [CmdletBinding()]
    param (
        [int]$Length = 64
    )

    # Character sets for pw generation
    $uppercase =  'ABCDEFGHJKLMNPQRSTUVWXYZ' #excluding I, O for readability
    $lowercase =  'abcdefghijkmnopqrstuvwxyz' # excluding l for readability
    $numbers   =  '0123456789'
    $special   =  '!@#$%^&*()-_=+[]{};:,.<>?'

    $allChars = $uppercase + $lowercase + $numbers + $special

    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::New()
    try {
        $bytes = New-Object byte[] $Length
        $rng.GetBytes($bytes)

        $password = ""
        for ($i = 0; $i -lt $Length; $i++) {
            $password += $allChars[$bytes[$i] % $allChars.Length]
        }

        # Ensure complexity requirements are met
        $hasUpper = $password -cmatch '[A-Z]'
        $hasLower = $password -cmatch '[a-z]'
        $hasNumber = $password -cmatch '[0-9]'
        $hasSymbol = $password -cmatch '[^A-Za-z0-9]'

        if (-not ($hasUpper -and $hasLower -and $hasNumber -and $hasSymbol)) {
            # Regenerate if complexity requirements not met
            return New-StrongPassword -Length $Length
        }

        return ConvertTo-SecureString $password -AsPlainText -Force

    } finally {
        $rng.Dispose()
    }
}

function Resolve-PathUniversal {
    <#
    .SYNOPSIS
    REsolve a FileSystem path to an aboslute path, handling relative paths and UNC.

    .DESCRIPTION
    - For existing paths, return the provider-resolved absolute path.
    - For non-existing paths, resolves against a base directory (current location by default).
    - Errors on non-FileSystem providers (e.g. HKLM:\)

        .PARAMETER PATH
        The path to resolve.

        .PARAMETER Purpose
        'Input' (default) implies MustExist unless overridden; 'Output' implies MustNotExist.

        .PARAMETER MustExist
        Explicitly require existence

        .PARAMETER BaseDirectory
        Base to resolve relative paths when the leaf does not yet exist. Defaults to Get-Location.

        .OUTPUTS
        System.String absolute FileSystem path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Input','Output')]
        [string]$Purpose = 'Input',
        [switch]$MustExist,
        [string]$BaseDirectory = ((Get-Location).Path)
    )

    # Default MustExist by purpose
    if (-not $PSBoundParameters.ContainsKey('MustExist')) {
        $MustExist = ($Purpose -eq 'Input')
    }

    # Normalize base directory
    $baseDir = if ($BaseDirectory) { [System.IO.Path]::GetFullPath($BaseDirectory) } else { [System.IO.Directory]::GetCurrentDirectory() }

    # If the path exists, return its absolute filesystem path without using Resolve-Path (avoid mocked cmdlets)
    if (Test-Path -LiteralPath $Path) {
        if ([System.IO.Path]::IsPathRooted($Path)) { return [System.IO.Path]::GetFullPath($Path) }
        return [System.IO.Path]::GetFullPath( (Join-Path -Path $baseDir -ChildPath $Path) )
    }

    # Non-existing leaf (e.g., Output). Build from parent/leaf
    $parent = Split-Path -Path $Path -Parent
    $leaf = Split-Path -Path $Path -Leaf

    if ([string]::IsNullOrWhiteSpace($parent)) {
        # relative leaf only
        return [System.IO.Path]::GetFullPath( (Join-Path -Path $baseDir -ChildPath $leaf) )
    }

    # Parent provided
    $parentAbs = if ([System.IO.Path]::IsPathRooted($parent)) {
        [System.IO.Path]::GetFullPath($parent)
    } else {
        [System.IO.Path]::GetFullPath( (Join-Path -Path $baseDir -ChildPath $parent) )
    }

    if ((-not (Test-Path -LiteralPath $parentAbs)) -and $MustExist) {
        throw "Path not found: '$Path' (parent '$parent' does not exist)"
    }

    return [System.IO.Path]::GetFullPath( (Join-Path -Path $parentAbs -ChildPath $leaf) )

}

function Resolve-OutputPath {
    <#
    .SYNOPSIS
    Derive an absolute output file path from inputs and options.

        .PARAMETER OutputPath
        Optional explicit output. If provided, returns its absolute path (creating parent when -CreateDirectory).

        .PARAMETER InputPath
        Optional input file (absolute or relative). When OutputPath is omitted, its directory and basename guide defaults.

        .PARAMETER BaseName
        Optional base file name (without extension). If omitted and InputPath present, uses its basename.

        .PARAMETER Extension
        Desired output extension, like '.keytab' or '.json'. If omitted, keeps BaseName as-is.

        .PARAMETER Directory
        Optional directory to place the output in. Defaults to InputPath’s directory or current location.

        .PARAMETER AppendExtension
        Append Extension instead of replacing (e.g., file.keytab + '.dpapi' -> file.keytab.dpapi).

        .PARAMETER CreateDirectory
        Create the parent directory when it does not exist.

        .OUTPUTS
        System.String absolute FileSystem path.
    #>

    [CmdletBinding()]
    param(
        [string]$OutputPath,
        [string]$InputPath,
        [string]$BaseName,
        [string]$Extension,
        [string]$Directory,
        [switch]$AppendExtension,
        [switch]$CreateDirectory
    )

    if ($OutputPath) {
        $abs = Resolve-PathUniversal -Path $OutputPath -Purpose Output
        $parent = Split-Path -Path $abs -Parent
        if ($CreateDirectory -and -not (Test-Path -Path $parent)) {
            New-Item -Path $parent -ItemType Directory -Force | Out-Null
        }
        return $abs
    }

    $inAbs = $null
    if ($InputPath) { $inAbs = Resolve-PathUniversal -Path $InputPath -Purpose Input }

    $dir = if ($Directory) {
        (Resolve-PathUniversal -Path $Directory -Purpose Output)
    } elseif ($inAbs) {
        Split-Path -Path $inAbs -Parent
    } else {
        (Get-Location).Path
    }

    # determine basename
    $name = if ($BaseName) {
        $BaseName
    } elseif ($inAbs) {
        [System.IO.Path]::GetFileNameWithoutExtension($inAbs)
    } else {
        'output'
    }

    $name = (Sanitize-FileName -Name $name)

    $fileName =
        if ($Extension) {
            if ($AppendExtension) {
                $name + $Extension
            } else {
                [System.IO.Path]::GetFileName( [System.IO.Path]::ChangeExtension($name, $Extension))
            }
        } else {
            $name
        }

    $candidate = Join-Path $dir $fileName
    $absOut = [System.IO.Path]::GetFullPath($candidate)

    if ($CreateDirectory) {
        $parent = Split-Path -Path $absOut -Parent
        if (-not (Test-Path -Path $parent)) {
            New-Item -Path $parent -ItemType Directory -Force | Out-Null
        }
    }
    return $absOut
}

function New-MergeOutputFileName {
    <#
    .SYNOPSIS
    Build a deterministic merged file name from multiple input paths.

        .PARAMETER InputPaths
        Array of input file paths (absolute or relative).

        .PARAMETER Suffix
        Suffix to append (default 'merged').

        .PARAMETER Extension
        Output extension including dot (e.g., '.keytab').

        .PARAMETER MaxParts
        Limit number of basenames included to keep file name readable (default 5).

        .PARAMETER MaxLength
        Maximum final file name length before a hash tail is added (default 120 chars).

        .OUTPUTS
        System.String file name only (no directory).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$InputPaths,
        [string]$Suffix = 'merged',
        [Parameter(Mandatory)][string]$Extension,
        [int]$MaxParts = 5,
        [int]$MaxLength = 120
    )

    $bases = @()
    foreach ($p in $InputPaths) {
        $abs = Resolve-PathUniversal -Path $p -Purpose Input
        $bases += [System.IO.Path]::GetFileNameWithoutExtension($abs)
    }
    if ($bases.Count -gt $MaxParts) {
        $bases = $bases[0..($MaxParts - 1)]
    }

    $safeParts = $bases | ForEach-Object { Sanitize-FileName -Name $_ }
    $joined = ($safeParts -join '_')

    if ($Suffix) { $joined = "$($joined)_$(Sanitize-FileName -Name $Suffix)" }

    # Enforce max length
    $finalStem = $joined
    if ($finalStem.Length -gt $MaxLength) {
        $hash = Get-ShortHash -Text $joined
        $keep = [Math]::Max(1, $MaxLength - 9) # leave room for ~ + 8 hex
        $finalStem = $finalStem.Substring(0, $keep) + '~' + $hash
    }

    return "$($finalStem)$($Extension)"
}

function Sanitize-FileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name
    )
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Name.ToCharArray()) {
        if ($invalid -contains $ch) { [void]$sb.Append('_') }
        else { [void]$sb.Append($ch) }
    }

    # avoid trailing/leading spaces and dots on Windows
    $out = $sb.ToString().Trim()
    while ($out.EndsWith('.')) { $out = $out.TrimEnd('.') }
    if ([string]::IsNullOrWhiteSpace($out)) { $out = 'file' }
    return $out
}

function Get-ShortHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        # 8 hex chars tail
        return ($hash | Select-Object -First 4 | ForEach-Object { $_.ToString('x2') }) -join ''
    } finally {
        $sha.Dispose()
    }
}
#endregion
