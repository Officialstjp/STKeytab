<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Reset-AccountPasswordWithKeytab {
   <#
    .SYNOPSIS
    Reset an AD account password and generate a corresponding keytab in one atomic operation.

    .DESCRIPTION
    Securely rotates an account's password to a strong random value, updates Active Directory,
    derives the corresponding Kerberos keys using the new password, and produces a keytab file.
    This ensures the keytab matches the account's actual password state without manual coordination.
    Only supports user accounts.

    Requires explicit risk acknowledgment due to the high-impact nature of password changes.

        .PARAMETER SamAccountName
        The account's sAMAccountName to reset password for.

        .PARAMETER Realm
        Kerberos realm name. If omitted, derives from the domain.

        .PARAMETER NewPassword
        Specific password to set. If omitted, generates a cryptographically strong random password.

        .PARAMETER Kvno
        Key version number to use in the keytab. If omitted, predicts the post-reset KVNO.

        .PARAMETER Compatibility
        Salt generation policy: MIT, Heimdal, or Windows (default).

        .PARAMETER IncludeEtype
        Encryption types to include. Default: AES256, AES128.

        .PARAMETER ExcludeEtype
        Encryption types to exclude.

        .PARAMETER OutputPath
        Path for the generated keytab file.

        .PARAMETER Domain
        Domain to target for AD operations.

        .PARAMETER Server
        Specific domain controller to use.

        .PARAMETER Credential
        Alternate credentials for AD operations.

        .PARAMETER AcknowledgeRisk
        Required acknowledgment that this operation changes the account password.

        .PARAMETER Justification
        Required justification for audit logging.

        .PARAMETER WhatIfOnly
        Show operation plan without executing changes.

        .PARAMETER UpdateSupportedEtypes
        Update the account's msDS-SupportedEncryptionTypes attribute.

        .PARAMETER AESOnly
        Restrict to AES encryption types only.

        .PARAMETER IncludeLegacyRC4
        Include RC4 encryption type (not applicable for password path - AES only).

        .PARAMETER AllowDeadCiphers
        Allow obsolete encryption types (not applicable for password path - AES only).

        .PARAMETER RestrictAcl
        Apply user-only ACL to output files.

        .PARAMETER Force
        Overwrite existing output files.

        .PARAMETER Summary
        Generate JSON summary file.

        .PARAMETER PassThru
        Return operation result object.

        .PARAMETER FixedTimestampUtc
        Use fixed timestamp for deterministic output.

        .EXAMPLE
        Reset-AccountPasswordWithKeytab -SamAccountName svc-web -AcknowledgeRisk -Justification "Quarterly rotation" -OutputPath .\svc-web.keytab

        Resets the password for svc-web and generates a corresponding keytab.

        .EXAMPLE
        Reset-AccountPasswordWithKeytab -SamAccountName svc-app -WhatIfOnly -AcknowledgeRisk -Justification "Planning rotation"

        Shows what would be done without making changes.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$SamAccountName,

        [string]$Realm,
        [securestring]$NewPassword,
        [int]$Kvno,
        [ValidateSet('MIT','Heimdal','Windows')]
        [string]$Compatibility = 'Windows',

        [object[]]$IncludeEtype = @(18,17),
        [object[]]$ExcludeEtype,

        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        # AD Integration
        [string]$Domain,
        [string]$Server,
        [pscredential]$Credential,

        # Safety & Policy
        [switch]$AcknowledgeRisk,
        [string]$Justification,

        [switch]$WhatIfOnly,
        [int[]]$UpdateSupportedEtypes,

        # BigBrother integration
        [switch]$AESOnly,
        [switch]$IncludeLegacyRC4,
        [switch]$AllowDeadCiphers,

        # Output options
        [switch]$RestrictAcl,
        [switch]$Force,
        [string]$JsonSummaryPath,
        [switch]$Summary,
        [switch]$PassThru,
        [datetime]$FixedTimestampUtc,
        [switch]$SuppressWarnings
    )

    begin {
        Get-RequiredModule -Name 'ActiveDirectory'
        $ErrorActionPreference = 'Stop'

        # Validate required risk acknowledgment (explicit check for better error messages)
        if (-not $AcknowledgeRisk) {
            throw "This operation requires explicit risk acknowledgment. Use -AcknowledgeRisk to proceed."
        }
        if (-not $Justification) {
            throw "This operation requires a justification. Use -Justification to provide one."
        }

        # Compose policy for password path (enforce AES-only)
        try {
            $policy = Get-PolicyIntent -IncludeEtype $IncludeEtype -ExcludeEtype $ExcludeEtype `
                                      -AESOnly:$AESOnly -IncludeLegacyRC4:$IncludeLegacyRC4 `
                                      -AllowDeadCiphers:$AllowDeadCiphers -PathKind 'Password'
        } catch {
            throw "Policy composition failed: $($_.Exception.Message)"
        }

        # Validate password path compatibility (enforc AES-only)
        Validate-PasswordPathCompatibility -Policy $policy -SuppressWarnings:$SuppressWarnings

        # Security warning for high-impact operation
        if (-not $SuppressWarnings) {
            Write-SecurityWarning -RiskLevel 'High' -SamAccountName $SamAccountName | Out-Null
        }

        if (-not $OutputPath) {
            $OutputPath = Join-Path (Get-Location) "$SamAccountName.keytab"
        }
    }

    process {
        try {
            # 1. Discover account and current state
            $domainFQDN = Resolve-DomainContext -Domain $Domain
            if (-not $Realm) {
                $Realm = $domainFQDN.ToUpperInvariant()
            }

            $getParams = @{
                Identity = $SamAccountName
                Properties = 'msDS-KeyVersionNumber', 'msDS-SupportedEncryptionTypes'
            }

            if ($Server) { $getParams.Server = $Server }
            if ($Credential) { $getParams.Credential = $Credential }

            $account = Get-ADUser @getParams
            $currentKvno = $account.'msDS-KeyVersionNumber'
            if (-not $currentKvno) {
                if ($Kvno) { $Kvno }
                else { throw "Unable to determine key version number from Active Directory and no Kvno specified. Please provide a -Kvno value." }
            } else { $currentKvno + 1 }

            $predictedKvno = if ($Kvno) { $Kvno } else { $currentKvno + 1 }

            # 2. Generate password if not provided
            if (-not $NewPassword) {
                $NewPassword = New-StrongPassword -Length 64 # tbi
            }

            # 3. build operation plan
            $etypeSelection = Resolve-EtypeSelection -AvailableIds $policy.IncludeIds -Policy $policy

            $plan = [ordered]@{
                Operation = 'Reset-AccountPasswordWithKeytab'
                SamAccountName = $SamAccountName
                Domain = $domainFqdn
                Realm = $Realm
                CurrentKvno = $currentKvno
                PredictedKvno = $predictedKvno
                SelectedEtypes = $etypeSelection.Selected
                EtypeNames = @($etypeSelection.Selected | ForEach-Object { Get-EtypeNameFromId $_ })
                OutputPath = (Resolve-Path -Path (Split-Path $OutputPath -Parent)).Path + '\' + (Split-Path $OutputPath -Leaf) # resolve to ensure path
                UpdateSupportedEtypes = $UpdateSupportedEtypes
                Justification = $Justification
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                Rollback = @{
                    Note = 'Password reset is one-way - cannot restore original password'
                    OriginalKvno = $currentKvno
                    OriginalSupportedEtypes = $account.'msDS-SupportedEncryptionTypes'
                }
            }

            if ($WhatIfOnly) {
                Write-Host "=== Operation Plan ===" -ForeGroundColor Cyan
                $plan | Format-List
                return $plan
            }

            if ($PSCmdlet.ShouldProcess($SamAccountName, "Reset password and generate keytab")) {
                # 4. execute password reset
                 Write-Verbose "Resetting password for $SamAccountName"

                $setParams = @{
                    Identity = $account
                    NewPassword = $NewPassword
                    Reset = $true
                }
                if ($Server) { $setParams.Server = $Server }
                if ($Credential) { $setParams.Credential = $Credential }

                Set-ADAccountPassword @setParams

                # 5. Update supported encryption types if requested
                if ($UpdateSupportedEtypes) {
                    Write-Verbose "Updating msDS-SupportedEncryptionTypes"
                    $etypeSum = ($UpdateSupportedEtypes | Measure-Object -Sum).Sum

                    $replaceParams = @{
                        Identity = $account
                        Replace = @{'msDS-SupportedEncryptionTypes' = $etypeSum}
                    }
                    if ($Server) { $replaceParams.Server = $Server }
                    if ($Credential) { $replaceParams.Credential = $Credential }

                    Set-ADObject @replaceParams
                }

                # 6. Generate keytab from new password
                Write-Verbose "Generating keytab with new Password for $SamAccountName"

                $keytabParams = @{
                    SamAccountName  = $SamAccountName
                    Realm           = $Realm
                    Password        = $NewPassword
                    Kvno            = $predictedKvno
                    Compatibility   = $Compatibility
                    IncludeEtype    = $etypeSelection.Selected
                    OutputPath      = $OutputPath
                    RestrictAcl     = $RestrictAcl
                    Force           = $Force
                    Summary         = $Summary
                    PassThru        = $true
                }

                if ($FixedTimestampUtc) {
                    $keytabParams.FixedTimestampUtc = $FixedTimestampUtc
                }

                if ($JsonSummaryPath) {
                    $keytabParams.SummaryPath = $JsonSummaryPath
                }

                $keytabResult = New-KeytabFromPassword @keytabParams

                # 7. Compile final result
                $result = [ordered]@{
                    Operation = 'Reset-AccountPasswordWithKeytab'
                    SamAccountName = $SamAccountName
                    Domain = $domainFqdn
                    Realm = $Realm
                    Success = $true
                    OldKvno = $currentKvno
                    NewKvno = $predictedKvno
                    Etypes = $keytabResult.Etypes
                    EtypeNames = @($keytabResult.Etypes | ForEach-Object { Get-EtypeNameFromId $_ })
                    OutputPath = $keytabResult.OutputPath
                    SummaryPath = $keytabResult.SummaryPath
                    Justification = $Justification
                    Operator = [Environment]::UserName
                    Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                }

                Write-Host "Password reset completed successfully for $SamAccountName" -ForegroundColor Green
                Write-Host "New KVNO: $predictedKvno" -ForegroundColor Green
                Write-Host "Keytab: $($keytabResult.OutputPath)" -ForegroundColor Green

                if ($PassThru) {
                    return $result
                }
            }

        } catch {
            Write-Error "Password reset operation failed for ${SamAccountName}: $($_.Exception.Message)"
            Write-Warning "The account password may have been changed. Manual verification recommended."
            throw
        }
    }
}
