<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Test-Keytab {
    <#
    .SYNOPSIS
    Validate a keytab file and report stats.

    .DESCRIPTION
    Lightweight validation that counts entries and flags unknown encryption types. Returns
    $true/$false by default. With -Detailed, returns an object containing IsValid, EntryCount,
    UnknownEtypes, and Warnings.

        .PARAMETER Path
        Path to the keytab file (Pos 1).

        .PARAMETER Detailed
        Return a detailed object with counts and warnings instead of a boolean.

        .INPUTS
        System.String (file path) or objects with FilePath/FullName properties.

        .OUTPUTS
        System.Boolean by default; PSCustomObject with details when -Detailed.

        .EXAMPLE
        Test-Keytab -Path .\user.keytab
        Returns $true when the keytab parses successfully.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position=0)]
        [Alias('FullName','PSPath','FilePath')]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        [switch]$Detailed
    )
    begin {
        $in = Resolve-PathUniversal -Path $Path -Purpose Input
        $result = @{
            IsValid       = $false
            EntryCount    = 0
            UnknownEtypes = @()
            Warnings      = New-Object System.Collections.Generic.List[string]
        }
    }
    process {
        try {
            $parsed = Read-Keytab -Path $in
            $result.EntryCount = $parsed.Count
            $unknown = @()
            foreach ($e in $parsed) {
                if (-not $script:ReverseEtypeMap.ContainsKey($e.EtypeId)) {
                    if ($unknown -notcontains $e.EtypeId) { $unknown += $e.EtypeId }
                }
            }
            $result.UnknownEtypes = $unknown
            $result.IsValid = $true
        } catch {
            $result.Warnings.Add($_.Exception.Message)
            $result.IsValid = $false
        }
    }
    end {
        if ($Detailed) {
            return [pscustomobject]$result
        } else {
            return $result.IsValid
        }
    }
}
