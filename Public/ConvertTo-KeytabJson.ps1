function ConvertTo-KeytabJson {
    <#
    .SYNOPSIS
    Convert a keytab file to canonical JSON (keys masked by default).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$OutputPath,
        [switch]$RevealKeys,
        [switch]$IgnoreTimestamp
    )

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
    $json
}
