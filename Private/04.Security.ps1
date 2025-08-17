<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


<#
.SYNOPSIS
Write a security warning banner based on risk level.

.DESCRIPTION
Notes:
 - Public entry point: Write-SecurityWarning
 - RiskLevel values currently produced: 'krbtgt','High','Medium'
 - Enables opt-out via:  -Suppress  or env var STCRYPT_SUPPRESS_SECURITY_WARNING=1
 - Tries to stay pure (no Write-Host) unless -AsString:$false (default) for visibility.
 - Returns the composed banner text (always) so callers can log it.
#
#>


#region Security / Risk Warning Presentation
# ---------------------------------------------------------------------- #
#
#                     Security / Risk Warning Presentation
#
# ---------------------------------------------------------------------- #
function Write-EmptyBannerLine {
    <#
        .SYNOPSIS
        Write an empty banner line with a specific width and color.
    #>
    param(
        [int]$Width = 82,
        [ConsoleColor]$Color = 'Red'
    )
    $inner = ' ' * ($Width)
    Write-Host ("|{0}|" -f $inner) -ForegroundColor $Color
}

function Write-BannerText {
    <#
        .SYNOPSIS
        Write a banner text with optional centering and color.
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [int]$Width = 82,
        [switch]$Centered,
        [ConsoleColor]$Color = 'Red'
    )
    # Width = inner content width (excluding the two border pipes)
    $lines = $Message -split "(`r`n|`n)"
    foreach ($l in $lines) {
        if (-not $l) { Write-EmptyBannerLine -Width $Width -Color $Color; continue }
        # Break long lines into chunks
        $remaining = $l
        while ($remaining.Length -gt 0) {
            $chunkSize = [Math]::Min($Width, $remaining.Length)
            $chunk = $remaining.Substring(0,$chunkSize)
            $remaining = if ($remaining.Length -gt $chunkSize) { $remaining.Substring($chunkSize) } else { '' }

            $padLeft = 0
            $padRight = 0
            if ($Centered) {
                $padLeft  = [Math]::Floor(($Width - $chunk.Length)/2)
                $padRight = $Width - $chunk.Length - $padLeft
            } else {
                $padLeft  = 0
                $padRight = $Width - $chunk.Length
            }
            $line = '|' + (' ' * $padLeft) + $chunk + (' ' * $padRight) + '|'
            Write-Host $line -ForegroundColor $Color
        }
    }
}

function New-SecurityBannerContent {
    <#
        .SYNOPSIS
        Create the content for a security warning banner based on risk level.
    #>
    param(
        [Parameter(Mandatory)][string]$RiskLevel,
        [Parameter(Mandatory)][string]$SamAccountName
    )
    switch ($RiskLevel.ToLowerInvariant()) {
        'krbtgt' {
            @(
                'SECURITY WARNING',
                '',
                'You are exporting / handling KRBTGT key material.',
                'Possession enables forging (Golden Tickets) & global Kerberos decryption across the forest.',
                '',
                'Treat as a Tier-0 secret. Strongly restrict storage, transport and lifetime.',
                'Perform ONLY in a controlled (lab / IR / recovery) scenario with explicit approval.',
                '',
                'Existence of this file is itself a critical risk indicator.'
            )
        }
        'high' {
            @(
                'HIGH RISK KEYTAB',
                '',
                "Account: $SamAccountName",
                'Domain Controller or high-impact service account keys allow lateral movement, ticket forging for that host / services, and decryption of its Kerberos traffic.',
                '',
                'Handle under change control. Limit distribution. Consider immediate secure deletion after use.'
            )
        }
        default {
            @(
                'SENSITIVE MATERIAL',
                '',
                "Account: $SamAccountName",
                'Keytab grants impersonation for this principal and decryption of its Kerberos traffic.',
                'Store minimally, transmit over secure channels, and purge after intended use.'
            )
        }
    }
}

function Write-SecurityWarning {
    <#
        .SYNOPSIS
        Write a security warning banner based on risk level.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RiskLevel,
        [Parameter(Mandatory)][string]$SamAccountName,
        [int]$Width = 80,
        [switch]$Suppress,
        [switch]$AsString,
        [switch]$NoColor
    )

    if ($Suppress -or ($env:STCRYPT_SUPPRESS_SECURITY_WARNING -eq '1')) {
        return ""
    }

    # Normalize internal width (content width inside borders)
    if ($Width -lt 40) { $Width = 40 }
    $contentWidth = $Width - 2  # account for border pipes

    $lines = New-SecurityBannerContent -RiskLevel $RiskLevel -SamAccountName $SamAccountName
    $borderLine = '+' + ('\' * ($contentWidth)) + '+'
    $stringBuilder = [System.Text.StringBuilder]::new()
    [void]$stringBuilder.AppendLine($borderLine)
    foreach ($l in $lines) {
        # Manual line wrapping consistent with Write-STBannerText
        $remaining = $l
        if (-not $remaining) {
            [void]$stringBuilder.AppendLine('|' + (' ' * $contentWidth) + '|')
            continue
        }
        while ($remaining.Length -gt 0) {
            $chunkSize = [Math]::Min($contentWidth, $remaining.Length)
            $chunk = $remaining.Substring(0,$chunkSize)
            $remaining = if ($remaining.Length -gt $chunkSize) { $remaining.Substring($chunkSize) } else { '' }
            $padRight = $contentWidth - $chunk.Length
            [void]$stringBuilder.AppendLine('|' + $chunk + (' ' * $padRight) + '|')
        }
    }
    [void]$stringBuilder.AppendLine($borderLine)

    $bannerText = $stringBuilder.ToString().TrimEnd()

    if ($AsString) { return $bannerText }

    $color = if ($NoColor) { $null } elseif ($RiskLevel -eq 'krbtgt') { 'Red' } elseif ($RiskLevel -eq 'High') { 'Yellow' } else { 'DarkYellow' }

    if ($color) {
        foreach ($outLine in ($bannerText -split "`r?`n")) {
            Write-Host $outLine -ForegroundColor $color
        }
    } else {
        Write-Host $bannerText
    }

    return $bannerText
}

#endregion
