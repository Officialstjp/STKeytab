<#
.SYNOPSIS
Convert Markdown about topics to PowerShell help text format.

.DESCRIPTION
This script converts about_*.md files from the docs\about folder to the .help.txt format (not perfect)
required by PowerShell help system in the en-US folder.

.PARAMETER SourcePath
Path to the docs\about folder containing .md files.

.PARAMETER DestinationPath
Path to the en-US folder where .help.txt files should be created.

.PARAMETER Force
Overwrite existing .help.txt files.

.EXAMPLE
.\Convert-AboutTopics.ps1 -SourcePath ".\docs\about" -DestinationPath ".\en-US" -Force
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SourcePath,

    [Parameter(Mandatory)]
    [string]$DestinationPath,

    [switch]$Force
)

function Convert-MarkdownToHelpText {
    param(
        [string]$MarkdownContent,
        [string]$TopicName
    )

    # Basic conversion - this would need refinement for full automation
    $lines = $MarkdownContent -split "`n"
    $helpText = @()

    $inCodeBlock = $false
    $inExample = $false

    foreach ($line in $lines) {
        # Skip front matter and initial header
        if ($line -match '^#\s+' -and $line -match $TopicName) {
            continue
        }
        if ($line -match '^##\s+about_') {
            continue
        }

        # Handle code blocks
        if ($line -match '^```') {
            $inCodeBlock = -not $inCodeBlock
            if ($inCodeBlock -and $line -match 'powershell') {
                # Start of PowerShell code block
                continue
            } elseif (-not $inCodeBlock) {
                # End of code block
                continue
            }
        }

        # Handle headers
        if ($line -match '^#\s+(.+)$' -and -not $inCodeBlock) {
            $headerText = $matches[1].Trim()
            $helpText += ""
            $helpText += "    $headerText"
            continue
        }

        # Handle examples
        if ($line -match '^##\s+Example') {
            $inExample = $true
        }

        # Add content with appropriate indentation
        if ($inCodeBlock) {
            $helpText += "        $line"
        } elseif ($line.Trim() -eq '') {
            $helpText += ""
        } else {
            $helpText += "    $line"
        }
    }

    return $helpText -join "`n"
}

# Get all .md files in source path
$mdFiles = Get-ChildItem -Path $SourcePath -Filter "about_*.md"

foreach ($mdFile in $mdFiles) {
    $topicName = [System.IO.Path]::GetFileNameWithoutExtension($mdFile.Name)
    $outputFile = Join-Path $DestinationPath "$topicName.help.txt"

    if ((Test-Path $outputFile) -and -not $Force) {
        Write-Warning "File $outputFile already exists. Use -Force to overwrite."
        continue
    }

    Write-Host "Converting $($mdFile.Name) to $([System.IO.Path]::GetFileName($outputFile))"

    $content = Get-Content -Path $mdFile.FullName -Raw

    # Create basic help text structure
    $helpContent = @"
TOPIC
    $topicName

SHORT DESCRIPTION
    [Generated from $($mdFile.Name) - needs manual review]

LONG DESCRIPTION
    [This file was auto-converted from Markdown and requires manual editing]

$content

"@

    Set-Content -Path $outputFile -Value $helpContent -Encoding UTF8
}

Write-Host "Conversion complete. Please review and manually edit the generated .help.txt files."
Write-Host "Key areas to review:"
Write-Host "- SHORT DESCRIPTION section"
Write-Host "- Code block formatting"
Write-Host "- Proper indentation (4 spaces for paragraphs, 8 spaces for code)"
Write-Host "- EXAMPLES section formatting"
Write-Host "- SEE ALSO and KEYWORDS sections"
