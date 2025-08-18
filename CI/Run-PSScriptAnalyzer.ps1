Write-Host "=== PSScriptAnalyzer Analysis ===" -ForegroundColor Cyan

$allIssues = @()
$folders = @(
    @{ Path = "Public"; Name = "Public Functions" },
    @{ Path = "Private"; Name = "Private Functions" },
    @{ Path = "tests"; Name = "Test Files" },
    @{ Path = "STKeytab.psm1"; Name = "Module Manifest" },
    @{ Path = "STKeytab.psd1"; Name = "Module Data" }
)

foreach ($folder in $folders) {
    if (Test-Path $folder.Path) {
        Write-Host "`n--- Analyzing $($folder.Name) ---" -ForegroundColor Yellow

        # Use settings file if it exists
        $analyzerParams = @{
        Path = $folder.Path
        Recurse = $true
        Severity = 'Warning'
        }

        if (Test-Path ".\CI\PSScriptAnalyzerSettings.psd1") {
            $analyzerParams.Settings = ".\CI\PSScriptAnalyzerSettings.psd1"
        }

        $results = Invoke-ScriptAnalyzer @analyzerParams

        if ($results) {
        Write-Host "Found $($results.Count) issue(s):" -ForegroundColor Red

        # Show detailed results with full messages
        foreach ($issue in $results) {
            Write-Host "" # Empty line for readability
            Write-Host "[$($issue.Severity)] $($issue.RuleName)" -ForegroundColor Red
            Write-Host "  File: $($issue.ScriptName):$($issue.Line)" -ForegroundColor Yellow
            Write-Host "  Message: $($issue.Message)" -ForegroundColor White
            if ($issue.SuggestedCorrections) {
            Write-Host "  Suggestion: $($issue.SuggestedCorrections[0].Description)" -ForegroundColor Cyan
            }
        }

        $allIssues += $results
        } else {
        Write-Host "[+] No issues found" -ForegroundColor Green
        }
    } else {
        Write-Host "[~] Path not found: $($folder.Path)" -ForegroundColor DarkYellow
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
if ($allIssues.Count -gt 0) {
    Write-Host "Total issues found: $($allIssues.Count)" -ForegroundColor Red

    # Group by severity
    $bySeverity = $allIssues | Group-Object Severity
    foreach ($group in $bySeverity) {
        Write-Host "  $($group.Name): $($group.Count)" -ForegroundColor Yellow
    }

    # Group by rule
    Write-Host "`nTop issues by rule:" -ForegroundColor Yellow
    $byRule = $allIssues | Group-Object RuleName | Sort-Object Count -Descending | Select-Object -First 5
    foreach ($rule in $byRule) {
        Write-Host "  $($rule.Name): $($rule.Count)" -ForegroundColor White
    }

    Write-Error "PSScriptAnalyzer found $($allIssues.Count) total issues"
} else {
    Write-Host "[+] All scans completed successfully - no issues found!" -ForegroundColor Green
}
