<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Set-AccountSpn {
    <#
    .SYNOPSIS
    Safely manage Service Principal Names (SPNs) for Active Directory accounts.

    .DESCRIPTION
    Add, remove, or list SPNs on AD accounts with built-in conflict detection, dry-run capabilities
    and automatic rollback on failure. Provides transactional behaviour to ensure consistent state even if operations fail partway through.

        .PARAMETER SamAccountName
        The account's sAMAccountName to modify SPNs for.

        .PARAMETER Add
        SPNs to add to the account.

        .PARAMETER Remove
        SPNs to remove from the account.

        .PARAMETER List
        List current SPNs on the account.

        .PARAMETER WhatIfOnly
        Show operation plan without making changes.

        .PARAMETER Domain
        Domain to target for AD operations.

        .PARAMETER Server
        Specific domain controller to use.

        .PARAMETER Credential
        Alternate credentials for AD operations.

        .PARAMETER Force
        Proceed even if some validations fail.

        .PARAMETER IgnoreConflicts
        Proceed even if SPN conflicts are detected.

        .PARAMETER JsonSummaryPath
        Path to write operation summary JSON.

        .PARAMETER PassThru
        Return detailed operation results.

        .EXAMPLE
        Set-AccountSpn -SamAccountName svc-web -Add 'HTTP/web.contoso.com', 'HTTP/web' -List

        Adds HTTP SPNs to svc-web and shows the final SPN list.

        .EXAMPLE
        Set-AccountSpn -SamAccountName svc-old -Remove 'HTTP/oldserver.contoso.com' -WhatIfOnly

        Shows what would be removed without making changes.

        .EXAMPLE
        Set-AccountSpn -SamAccountName svc-app -List

        Lists all current SPNs for svc-app.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$SamAccountName,

        [string[]]$Add,
        [string[]]$Remove,
        [switch]$List,
        [switch]$WhatIfOnly,

        # AD Integration
        [string]$Domain,
        [string]$Server,
        [pscredential]$Credential,

        # Safety & Control
        [switch]$Force,
        [switch]$IgnoreConflicts,
        [string]$JsonSummaryPath,
        [switch]$PassThru
    )

    begin {
        Get-RequiredModule -Name 'ActiveDirectory'

        if (-not ($Add -or $Remove -or $List)) {
            throw "Must specifiy at least one of: -Add, -Remove, or -List"
        }

        # Normalize inputs
        $spnsToAdd = @($Add | Where-Object { $_ })
        $spnsToRemove = @($Remove | Where-Object { $_ })
    }

    process {
        try {
            # 1. Discover current accoutn state
            $domainFQDN = Resolve-DomainContext -Domain $domain

            $getParams = @{
                Identity   = $SamAccountName
                Properties = @('ServicePrincipalNames')
            }
            if ($Server) { $getParams.Server = $Server }
            if ($Credential) { $getParams.Credential = $Credential }

            $account = Get-ADUser @getParams
            $currentSpns = $account.ServicePrincipalNames
            if (-not $currentSpns) { $currentSpns = @() }

            if ($List) {
                Write-Host "Current SPNs for $SamAccountName`:" -ForegroundColor Cyan
                if ($currentSpns.Count -eq 0) {
                    Write-Host "    (None)" -Foregroundcolor yellow
                } else {
                    $currentSpns | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
                }
                return $currentSpns
            }

            # 2. Plan operations
            $actualSpnsToAdd = @($spnsToAdd | Where-Object { $_ -notin $currentSpns })
            $actualSpnsToRemove = @($spnsToRemove | Where-Object { $_ -in $currentSpns })
            $finalSpns = @(($currentSpns + $actualSpnsToAdd) | Where-Object { $_ -notin $actualSpnsToRemove })

            # Report no-ops
            $skipAdd = @($spnsToAdd | Where-Object { $_ -in $currentSpns })
            $skipRemove = @($spnsToRemove | Where-Object { $_ -notin $currentSpns })

            if ($skipAdd) {
                Write-Warning "Already present (skipping add): $($skipAdd -join ', ')"
            }
            if ($skipRemove) {
                Write-Warning "Not present (skipping remove): $($skipRemove -join ', ')"
            }

            # 3. Conflict detection for SPNs being added
            $conflicts = @()
            if ($actualSpnsToAdd) {
                Write-Verbose "Checking for SPN conflicts..."

                foreach ($spn in $actualSpnsToAdd) {
                    $searchParams = @{
                        Filter = "servicePrincipalName -eq '$spn'"
                        Properties = 'SamAccountName'
                    }
                    if ($Server) { $searchParams.Server = $Server }
                    if ($Credential) { $searchParams.Credential = $Credential }

                    $existingAccounts = @(Get-ADUser @searchParams)
                    $conflictingAccount = $existingAccounts | Where-Object { $_.SamAccountName -ne $SamAccountName } | Select-Object -First 1

                    if ($conflictingAccount) {
                        $conflicts += [ordered]@{
                            SPN = $spn
                            ConflictingAccount = $conflictingAccount.SamAccountName
                            ConflictingDN = $conflictingAccount.DistinguishedName
                        }
                    }
                }
            }

            if ($conflicts -and -not $IgnoreConflicts) {
                $conflictList = ($conflicts | ForEach-Object { "$($_.SPN) (on $($_.ConflictingAccount))" }) -join ', '
                throw "SPN conflicts detected: $conflictList. Use -IgnoreConflicts to override or resolve conflicts first."
            }

            # 4. Build operation plan
            $plan = [ordered]@{
                Operation = 'Set-AccountSpn'
                SamAccountName = $SamAccountName
                Domain = $domainFqdn
                CurrentSpns = $currentSpns
                SpnsToAdd = $actualSpnsToAdd
                SpnsToRemove = $actualSpnsToRemove
                FinalSpns = $finalSpns
                Conflicts = $conflicts
                SkippedAdd = $skipAdd
                SkippedRemove = $skipRemove
                ChangeCount = $actualSpnsToAdd.Count + $actualSpnsToRemove.Count
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                Rollback = @{
                    OriginalSpns = $currentSpns
                }
            }

            if ($WhatIfOnly) {
                Write-Host "=== SPN Operation Plan ===" -ForegroundColor Cyan
                Write-Host "Account: $SamAccountName" -ForegroundColor White
                Write-Host "Current SPNs ($($currentSpns.Count)):" -ForegroundColor Yellow
                $currentSpns | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

                if ($actualSpnsToAdd) {
                    Write-Host "Will ADD ($($actualSpnsToAdd.Count)):" -ForegroundColor Green
                    $actualSpnsToAdd | ForEach-Object { Write-Host "  + $_" -ForegroundColor Green }
                }

                if ($actualSpnsToRemove) {
                    Write-Host "Will REMOVE ($($actualSpnsToRemove.Count)):" -ForegroundColor Red
                    $actualSpnsToRemove | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
                }

                if ($conflicts) {
                    Write-Host "CONFLICTS DETECTED:" -ForegroundColor Magenta
                    $conflicts | ForEach-Object { Write-Host "  ! $($_.SPN) conflicts with $($_.ConflictingAccount)" -ForegroundColor Magenta }
                }

                Write-Host "Final SPNs ($($finalSpns.Count)):" -ForegroundColor Cyan
                $finalSpns | ForEach-Object { Write-Host "  $_" -ForegroundColor White }

                return $plan
            }

            if ($plan.ChangeCount -eq 0) {
                Write-Host "No changes needed for $SamAccountName" -ForegroundColor Green
                if ($PassThru) {
                    $plan.Success = $true
                    return $plan
                }
                return $currentSpns
            }

            # Bypass confirmation if Force is specified
            $shouldProceed = $Force -or $PSCmdlet.ShouldProcess($SamAccountName, "Modify SPNs (Add: $($actualSpnsToAdd.Count), Remove: $($actualSpnsToRemove.Count))")

            if ($shouldProceed) {

                # 5. Execute operations with transactional behavior
                $rollbackNeeded = $false
                $operationsCompleted = @()

                try {
                    # Remove SPNs first (safer order - removes unused before adding potentially conflicting)
                    foreach ($spn in $actualSpnsToRemove) {
                        Write-Verbose "Removing SPN: $spn"

                        $removeParams = @{
                            Identity = $account
                            Remove = @{servicePrincipalName = $spn}
                        }
                        if ($Server) { $removeParams.Server = $Server }
                        if ($Credential) { $removeParams.Credential = $Credential }

                        Set-ADObject @removeParams
                        $rollbackNeeded = $true
                        $operationsCompleted += "Remove: $spn"
                    }

                    # Add SPNs second
                    foreach ($spn in $actualSpnsToAdd) {
                        Write-Verbose "Adding SPN: $spn"

                        $addParams = @{
                            Identity = $account
                            Add = @{servicePrincipalName = $spn}
                        }
                        if ($Server) { $addParams.Server = $Server }
                        if ($Credential) { $addParams.Credential = $Credential }

                        Set-ADObject @addParams
                        $rollbackNeeded = $true
                        $operationsCompleted += "Add: $spn"
                    }

                    # 6. Verify final state
                    Write-Verbose "Verifying final SPN state..."
                    $updatedAccount = Get-ADUser @getParams
                    $actualFinalSpns = @($updatedAccount.servicePrincipalName)
                    if (-not $actualFinalSpns) { $actualFinalSpns = @() }

                    # 7. Compile results
                    $result = [ordered]@{
                        Operation = 'Set-AccountSpn'
                        SamAccountName = $SamAccountName
                        Domain = $domainFqdn
                        Success = $true
                        OriginalSpns = $currentSpns
                        FinalSpns = $actualFinalSpns
                        Added = $actualSpnsToAdd
                        Removed = $actualSpnsToRemove
                        Conflicts = $conflicts
                        OperationsCompleted = $operationsCompleted
                        Operator = [Environment]::UserName
                        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                    }

                    if ($JsonSummaryPath) {
                        $result | ConvertTo-Json -Depth 3 | Set-Content -Path $JsonSummaryPath -Encoding UTF8
                    }

                    Write-Host "SPN operations completed successfully for $SamAccountName" -ForegroundColor Green
                    Write-Host "Final SPN count: $($actualFinalSpns.Count)" -ForegroundColor Green

                    if ($PassThru) {
                        return $result
                    }
                    return $actualFinalSpns

                } catch {
                    # 7. Rollback on failure
                    if ($rollbackNeeded) {
                        Write-Warning "SPN operation failed: $($_.Exception.Message)"
                        Write-Warning "Attempting to rollback changes..."
                        Write-Verbose "Operations completed before failure: $($operationsCompleted -join '; ')"

                        try {
                            $rollbackParams = @{
                                Identity = $account
                                Replace = @{servicePrincipalName = $currentSpns}
                            }
                            if ($Server) { $rollbackParams.Server = $Server }
                            if ($Credential) { $rollbackParams.Credential = $Credential }

                            Set-ADObject @rollbackParams
                            Write-Warning "Rollback completed successfully. SPNs restored to original state."
                        } catch {
                            Write-Error "Rollback failed: $($_.Exception.Message). Manual intervention required to restore SPNs."
                            Write-Host "Original SPNs were: $($currentSpns -join ', ')" -ForegroundColor Yellow
                        }
                    }
                    throw
                }
            }

        } catch {
            Write-Error "SPN operation failed for ${SamAccountName}: $($_.Exception.Message)"
            throw
        }
    }
}
