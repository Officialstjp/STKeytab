function Protect-Keytab {
  <#
    .SYNOPSIS
    Protect a keytab file at rest using Windows DPAPI.

    .DESCRIPTION
    Uses DPAPI (CurrentUser or LocalMachine scope) to encrypt a keytab file. Optional
    additional entropy can be provided. Can restrict ACL on the output and delete the
    plaintext original after successful protection.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$OutputPath,
    [Validateset('CurrentUser','LocalMachine')][string]$Scope = 'CurrentUser',
    [string]$Entropy,
    [switch]$Force,
    [switch]$DeletePlaintext,
    [switch]$RestrictAcl
  )

  if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
  if (-not $OutputPath) { $OutputPath = "$Path.dpapi" }
  if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
    throw "Output file '$OutputPath' already exists. Use -Force to overwrite."
  }

  $bytes = [IO.File]::ReadAllBytes($Path)
  $entropyBytes = if ($Entropy) { [Text.Encoding]::UTF8.GetBytes($Entropy) } else { $null }
  $scopeEnum = if ($Scope -eq 'LocalMachine') { 
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine 
  } else { 
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser 
  }

  try {
    $protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $entropyBytes, $scopeEnum)
    [IO.File]::WriteAllBytes($OutputPath, $protected)
    if ($RestrictAcl) { Set-UserOnlyAcl -Path $OutputPath }
  } finally {
    if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    if ($protected) { [Array]::Clear($protected, 0, $protected.Length) }
    if ($entropyBytes) { [Array]::Clear($entropyBytes, 0, $entropyBytes.Length) }
  }

  if ($DeletePlaintext) {
    try { Remove-Item -LiteralPath $Path -Force } catch { Write-Warning "Failed to delete plaintext '$Path': $($_.Exception.Message)" }
  }
  $OutputPath
}

