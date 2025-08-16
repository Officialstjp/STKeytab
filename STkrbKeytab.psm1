Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

function .source([string]$rel) { . (Join-Path $here $rel) } # imports dont work this way

# Private first (sorted; allow 00., 10., … prefixes)
Get-ChildItem "$here/Private" -Filter *.ps1 | Sort-Object Name |
  ForEach-Object { . (Join-Path $here "Private/$($_.Name)") }
                # { .source "Private/$($_.Name)" }

# Public next
$pub = Get-ChildItem "$here/Public" -Filter *.ps1 | Sort-Object Name
$pub | ForEach-Object { . (Join-Path $here "Public/$($_.Name)") }
                # { .source "Public/$($_.Name)" }

# Export public only (filename == function name)
Export-ModuleMember -Function $pub.BaseName
