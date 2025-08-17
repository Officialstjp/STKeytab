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

#endregion
