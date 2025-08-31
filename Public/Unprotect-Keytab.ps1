<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Unprotect-Keytab {
    <#
    .SYNOPSIS
    Decrypt a DPAPI-protected keytab file.

    .DESCRIPTION
    Uses DPAPI to decrypt a previously protected keytab file. Defaults output name by
    stripping the .dpapi suffix when present. If additional entropy was used during protection,
    the same Entropy value must be provided for decryption. Can restrict ACL on the output.

       .PARAMETER Path
        Path to the DPAPI-protected input file.

        .PARAMETER OutputPath
        Destination for the decrypted keytab. Defaults to removing the .dpapi extension when not specified.

        .PARAMETER Scope
        DPAPI scope used for decryption: CurrentUser (default) or LocalMachine.

        .PARAMETER Entropy
        Additional entropy string that was used during protection (if any).

        .PARAMETER Force
        Overwrite OutputPath if it exists.

        .PARAMETER RestrictAcl
        Apply a user-only ACL to the output file.

        .INPUTS
        System.String (file path) or objects with FilePath/FullName properties.

        .OUTPUTS
        System.String. Returns the OutputPath written.

        .EXAMPLE
        Unprotect-Keytab -Path .\user.keytab.dpapi -OutputPath .\user.keytab -Scope CurrentUser
        Decrypt a DPAPI-protected keytab into a plaintext keytab.
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

        [ValidateSet('CurrentUser','LocalMachine')]
        [string]$Scope = 'CurrentUser',

        [string]$Entropy,
        [SecureString]$EntropySecure,
        [switch]$Force,
        [switch]$RestrictAcl
    )
    begin {
        $in = Resolve-PathUniversal -Path $InputPath -Purpose Input
        $base = [IO.Path]::GetFileName($in)
        if ($OutputPath) {
            $out = Resolve-PathUniversal -Path $OutputPath -Purpose Output
        } else {
            if ($base -like '*.dpapi') { $ext = $null; $baseName = $base.Substring(0, $base.Length - 6) }
            $out = Resolve-OutputPath -InputPath $in -BaseName $baseName -CreateDirectory
        }
        $plain = $null
    }
    process {
        if ($PSCmdlet.ShouldProcess($in, 'Unprotecting keytab (DPAPI)')) {
            if ((Test-Path -LiteralPath $out) -and -not $Force) {
                throw "Output file '$out' already exists. Use -Force to overwrite."
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
                $plain = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropyBytes, $scopeEnum)
                [IO.File]::WriteAllBytes($out, $plain)
                if ($RestrictAcl) { Set-UserOnlyAcl -Path $out }
            } finally {
                if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
                if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
                if ($entropyBytes) { [Array]::Clear($entropyBytes, 0, $entropyBytes.Length) }
            }
        }
    }
    end {
        return $out
    }
}
