<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function ConvertTo-KeytabJson {
    <#
    .SYNOPSIS
    Convert a keytab file to canonical JSON (keys masked by default).

    .DESCRIPTION
    Parses a keytab and emits a canonical JSON representation for diffs and tooling.
    Keys are masked by default; pass -RevealKeys to include raw key bytes (sensitive).
    Use -IgnoreTimestamp to omit timestamp variance from the model.

        .PARAMETER Path
        Path to the input keytab file.

    .PARAMETER OutputPath
    Path to write the resulting JSON. If omitted, JSON text is written to the pipeline.

        .PARAMETER RevealKeys
        Include raw key bytes in the JSON. Sensitive—avoid in source control.

        .PARAMETER IgnoreTimestamp
        Exclude timestamps from the canonical model.

        .INPUTS
        System.String (file path) or objects with FilePath/FullName properties.

        .OUTPUTS
        System.String (OutputPath) when -OutputPath is provided, otherwise JSON text.

        .EXAMPLE
        ConvertTo-KeytabJson -Path .\in.keytab -OutputPath .\in.json
        Write canonical JSON to a file.

        .EXAMPLE
        ConvertTo-KeytabJson -Path .\in.keytab -RevealKeys | Out-File .\in.revealed.json
        Output JSON with key material to the pipeline and save to a file.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position=0)]
        [Alias('FullName','FilePath','PSPath')]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [Alias('OutFile', 'Out')]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [switch]$RevealKeys,
        [switch]$IgnoreTimestamp
    )
    begin {
        if ($RevealKeys) { Write-Warning 'RevealKeys is sensitive: raw key bytes will be included in JSON output.' }
    }
    process {
        if ($PSCmdlet.ShouldProcess($Path, 'Converting keytab to JSON')) {
            $parsed  = Read-Keytab -Path $Path -RevealKeys:$RevealKeys
            $entries = if ($parsed -is [System.Array]) { $parsed } elseif ($parsed.Entries) { $parsed.Entries } else { @($parsed) }
            $canon   = ConvertEntriesTo-KeytabCanonicalModel -Entries $entries -IgnoreTimestamp:$IgnoreTimestamp

            if (-not $RevealKeys) {
                foreach ($e in $canon) { $e.PSObject.Properties.Remove('Key') | Out-Null }
            }
            $json = $canon | ConvertTo-Json -Depth 6
            if ($OutputPath) {
                $json | Set-Content -LiteralPath $OutputPath -Encoding UTF8
                return $OutputPath
            }
        }
    }
    end {
        return $json
    }
}
