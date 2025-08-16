# region Utility & Dependency
# ---------------------------------------------------------------------- #
#
#                       Utility & Dependency
#
# ---------------------------------------------------------------------- #

function Get-RequiredModule {
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