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
#endregion
