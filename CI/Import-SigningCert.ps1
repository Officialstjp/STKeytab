<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$CertificateBase64,

    [Parameter(Mandatory)]
    [string]$Password,

    [string]$Subject = "*Stjp*"
)

try {
    # Decode certificate
    $certBytes = [Convert]::FromBase64String($CertificateBase64)
    $tempPath = [IO.Path]::GetTempFileName() + ".pfx"
    [IO.File]::WriteAllBytes($tempPath, $certBytes)

    # Import with secure password
    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $cert = Import-PfxCertificate -FilePath $tempPath -CertStoreLocation Cert:\CurrentUser\My -Password $securePassword -Exportable

    # Validate certificate
    if (-not $cert.HasPrivateKey) { throw "Certificate has no private key" }
    if ($cert.NotAfter -lt (Get-Date)) { throw "Certificate has expired" }
    if ($cert.EnhancedKeyUsageList.ObjectId -notcontains "1.3.6.1.5.5.7.3.3") {
        throw "Certificate is not valid for code signing"
    }

    Write-Host "Certificate imported successfully:" -ForegroundColor Green
    Write-Host "  Subject: $($cert.Subject)" -ForegroundColor Gray
    Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
    Write-Host "  Expires: $($cert.NotAfter)" -ForegroundColor Gray

    return $cert.Thumbprint

} catch {
    Write-Error "Failed to import certificate: $($_.Exception.Message)"
    exit 1
} finally {
    # Clean up temporary file
    if ($tempPath -and (Test-Path $tempPath)) {
        Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
    }
}
