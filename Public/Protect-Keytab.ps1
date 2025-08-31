<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Protect-Keytab {
    <#
    .SYNOPSIS
    Protect a keytab file at rest using Windows DPAPI.

    .DESCRIPTION
    Uses DPAPI (CurrentUser or LocalMachine scope) to encrypt a keytab file. Optional
    additional entropy can be provided. Can restrict ACL on the output and delete the
    plaintext original after successful protection. LocalMachine scope is not portable
    across machines.

        .PARAMETER Path
        Path to the plaintext keytab file to protect.

        .PARAMETER OutputPath
        Destination path for the protected file. Defaults to <Path>.dpapi when not specified.

        .PARAMETER Scope
        DPAPI scope: CurrentUser (default) or LocalMachine. LocalMachine scope binds decryption to the computer and is not portable.

        .PARAMETER Entropy
        Optional additional entropy string to bind to the protection.

        .PARAMETER Force
        Overwrite OutputPath if it exists.

        .PARAMETER DeletePlaintext
        Remove the original plaintext file after successful protection.

        .PARAMETER RestrictAcl
        Apply a user-only ACL to the output file.

        .INPUTS
        System.String (file path) or objects with FilePath/FullName properties.

        .OUTPUTS
        System.String. Returns the OutputPath written.

        .EXAMPLE
        Protect-Keytab -Path .\user.keytab -OutputPath .\user.keytab.dpapi -Scope CurrentUser -RestrictAcl
        Protect a keytab with DPAPI in the current-user scope and set a restrictive ACL.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position=0)]
        [Alias('Path','In','FullName','FilePath')]
        [ValidateNotNullOrEmpty()]
        [string]$InputPath,

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position=1)]
        [Alias('Out','Output', 'OutFile')]
        [string]$OutputPath,

        [Validateset('CurrentUser','LocalMachine')]
        [string]$Scope = 'CurrentUser',

        [string]$Entropy,
        [SecureString]$EntropySecure,
        [switch]$Force,
        [switch]$DeletePlaintext,
        [switch]$RestrictAcl
    )
    begin {
        $in = Resolve-PathUniversal -Path $InputPath -Purpose Input
        if ($OutputPath) {
            $out = Resolve-PathUniversal -Path $OutputPath -Purpose Output
        } else {
            $out = Resolve-OutputPath -InputPath $in -Extension '.dpapi' -AppendExtension -CreateDirectory
        }
    }
    process {
        if ($PSCmdlet.ShouldProcess($in, 'Protect keytab (DPAPI)')) {
            if ((Test-Path -LiteralPath $out) -and -not $Force) {
                throw "Output already exists: '$out'. Use -Force to overwrite."
            }
            $bytes = [IO.File]::ReadAllBytes($in)
            $entropyBytes = $null
            try {
                if ($EntropySecure) {
                    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($EntropySecure)
                    try {
                        $plainEntropy = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                        if ($plainEntropy) { $entropyBytes = [Text.Encoding]::UTF8.GetBytes($plainEntropy) }
                    } finally {
                        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
                    }
                } elseif ($Entropy) {
                    $entropyBytes = [Text.Encoding]::UTF8.GetBytes($Entropy)
                }
            } catch {
                Write-Warning ("Failed to materialize entropy: {0}" -f $_.Exception.Message)
            }
            $scopeEnum = if ($Scope -eq 'LocalMachine') {
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            } else {
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            }

            try {
                $protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $entropyBytes, $scopeEnum)
                [IO.File]::WriteAllBytes($out, $protected)
                if ($RestrictAcl) { Set-UserOnlyAcl -Path $out }
            } finally {
                if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
                if ($protected) { [Array]::Clear($protected, 0, $protected.Length) }
                if ($entropyBytes) { [Array]::Clear($entropyBytes, 0, $entropyBytes.Length) }
            }
        }
    }
    end {
        if ($DeletePlaintext) {
            try { Remove-Item -LiteralPath $in -Force } catch { Write-Warning "Failed to delete plaintext '$in': $($_.Exception.Message)" }
        }
        return $out
    }
}

