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
        stripping .dpapi suffix when present. Can restrict ACL on the output.

        .PARAMETER Path
        Path to the DPAPI-protected input file (Pos 1).

        .PARAMETER OutputPath
        Destination for the decrypted keytab. Defaults to removing .dpapi extension (Pos 2).

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
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position=0)]
        [Alias('In','FullName','FilePath')]
        [string]$Path,

        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position=1)]
        [Alias('Out','Output', 'OutFile')]
        [string]$OutputPath,

        [ValidateSet('CurrentUser','LocalMachine')]
        [string]$Scope = 'CurrentUser',

        [string]$Entropy,
        [switch]$Force,
        [switch]$RestrictAcl
    )
    begin {
        if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
        if (-not $OutputPath) {
            if ($Path -like '*.dpapi') { $OutputPath = $Path.Substring(0, $Path.Length - 6) } else { $OutputPath = "$Path.unprotected.keytab" }
        }
    }
    process {
        if ($PSCmdlet.ShouldProcess($Path, 'Unprotecting keytab (DPAPI)')) {
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
            if ($RestrictAcl) {
                Set-UserOnlyAcl -Path $OutputPath
            }
        }
    }
    end {
        return $OutputPath
    }
}
