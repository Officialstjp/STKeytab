<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

<#
.SYNOPSIS
Sign all Powershell files in the module with a specified certificate thumbprint
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]$CertificateThumbprint,
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]$ModulePath,
    [switch]$Verify
)

function Find-CodeSigningCertificate {
    [CmdletBinding()]
    param (
        [string]$Thumbprint
    )

    if ($Thumbprint) {
        $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $Thumbprint }
        if ($cert) { return $cert }
        else {
            $cert = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Thumbprint -eq $Thumbprint }
            if (-not $cert) { throw "Certificate with thumbprint '$Thumbprint' not found or missing private key" }
        }
    }

    # Auto-discover: find code signing cert with "Stjp" in subject
    $certs = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
        $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.3" -and  # Code Signing EKU
        $_.Subject -like "*Stjp*" -and
        $_.HasPrivateKey -and
        $_.NotAfter -gt (Get-Date)
    }
    if (-not $certs) {
        $certs = Get-ChildItem Cert:\CurrentUser\Root | Where-Object {
            $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.3" -and  # Code Signing EKU
            $_.Subject -like "*Stjp*" -and
            $_.HasPrivateKey -and
            $_.NotAfter -gt (Get-Date)
        }
    }

    if ($certs.Count -eq 0) { throw "No valid Stjp code signing certificates found" }
    if ($certs.Count -gt 1) {
        Write-Warning "Multiple certificates found. Using newest: $($certs[0].Subject)"
    }

    return $certs | Sort-Object NotAfter -Descending | Select-Object -First 1
}

function Get-PowerShellFiles {
    [CmdletBinding()]
    param([string]$Path)

    Get-ChildItem -Path $Path -Recurse -Include "*.ps1", "*.psm1", "*.psd1" | Where-Object {
        # Skip test files and temporary files
        $_.FullName -notmatch '\\tests\\' -and
        $_.FullName -notmatch '\\temp\\' -and
        $_.FullName -notmatch '\\secret\\' -and
        $_.FullName -notmatch '\\archive\\' -and
        $_.Name -ne 'Sign-Module.ps1'
    }
}

# Main execution
try {
    $cert = Find-CodeSigningCertificate -Thumbprint $CertificateThumbprint
    Write-Host "Using certificate: $($cert.Subject) (expires $($cert.NotAfter))" -ForegroundColor Green

    $files = Get-PowerShellFiles -Path $ModulePath
    Write-Host "Found $($files.Count) PowerShell files to sign" -ForegroundColor Cyan

    $results = @{
        Signed = @()
        Failed = @()
        Verified = @()
        VerifyFailed = @()
    }
    if ($PSCmdlet.ShouldProcess($files -join (', ')), 'Sign files') {
        foreach ($file in $files) {
            try {
                Write-Host "Signing: $($file.Name)" -ForegroundColor Yellow
                $signature = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $cert -TimestampServer "http://timestamp.digicert.com"

                if ($signature.Status -eq 'Valid') {
                    $results.Signed += $file.FullName
                    Write-Host "  [+] Signed successfully" -ForegroundColor Green
                } else {
                    $results.Failed += "$($file.FullName): $($signature.StatusMessage)"
                    Write-Host "  [!] Failed: $($signature.StatusMessage)" -ForegroundColor Red
                }

                # Verify signature if requested
                if ($Verify) {
                    $verification = Get-AuthenticodeSignature -FilePath $file.FullName
                    if ($verification.Status -eq 'Valid') {
                        $results.Verified += $file.FullName
                        Write-Host "  [+] Signature verified" -ForegroundColor Green
                    } else {
                        $results.VerifyFailed += "$($file.FullName): $($verification.StatusMessage)"
                        Write-Host "  [!] Verification failed: $($verification.StatusMessage)" -ForegroundColor Red
                    }
                }
            }
            catch {
                $results.Failed += "$($file.FullName): $($_.Exception.Message)"
                Write-Host "  [!] Exception: $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        # Summary
        Write-Host "`n=== Signing Summary ===" -ForegroundColor Magenta
        Write-Host " [+] Successfully signed: $($results.Signed.Count)" -ForegroundColor Green
        Write-Host " [-] Failed to sign: $($results.Failed.Count)" -ForegroundColor Red

        if ($Verify) {
            Write-Host "[+] Verified: $($results.Verified.Count)" -ForegroundColor Green
            Write-Host "[-] Verification failed: $($results.VerifyFailed.Count)" -ForegroundColor Red
        }

        if ($results.Failed.Count -gt 0) {
            Write-Host "`n[!] Failures:" -ForegroundColor Red
            $results.Failed | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
            exit 1
        }

        Write-Host "`n [++] All files signed successfully!" -ForegroundColor Green
    }
}
catch {
    Write-Error " [!!] Signing process failed: $($_.Exception.Message)"
    exit 1
}
