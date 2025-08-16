function Unprotect-Keytab {
  <#
    .SYNOPSIS
    Decrypt a DPAPI-protected keytab file.

    .DESCRIPTION
    Uses DPAPI to decrypt a previously protected keytab file. Defaults output name by
    stripping .dpapi suffix when present. Can restrict ACL on the output.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$OutputPath,
    [ValidateSet('CurrentUser','LocalMachine')][string]$Scope = 'CurrentUser',
    [string]$Entropy,
    [switch]$Force,
    [switch]$RestrictAcl
  )
  
  if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
  if (-not $OutputPath) {
    if ($Path -like '*.dpapi') { $OutputPath = $Path.Substring(0, $Path.Length - 6) } else { $OutputPath = "$Path.unprotected.keytab" }
  }
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
    $plain = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropyBytes, $scopeEnum)
    [IO.File]::WriteAllBytes($OutputPath, $plain)
    if ($RestrictAcl) { Set-UserOnlyAcl -Path $OutputPath }
  } finally {
    if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
    if ($entropyBytes) { [Array]::Clear($entropyBytes, 0, $entropyBytes.Length) }
  }
  $OutputPath
}