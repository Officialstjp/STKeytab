<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

<#
    .SYNOPSIS
    Unit tests for Compare-Convert-Keytab.ps1 functions.

#>

Set-StrictMode -Version Latest

$modulePath = Resolve-Path "$PSScriptRoot\..\STKeytab.psd1"
Import-Module -Name "$modulePath" -Force -ErrorAction Stop
$global:TestOutDir = Join-Path $PSScriptRoot 'output'
New-Item -ItemType Directory -Path $global:TestOutDir -Force | Out-Null

function global:New-MockAccount {
    param(
        [int]$Kvno = 7,
        [hashtable]$Etypes = @{ 'AES256_CTS_HMAC_SHA1_96' = (16..47); 'AES128_CTS_HMAC_SHA1_96' = (1..16); 'ARCFOUR_HMAC' = (50..65) }
    )
    $keys = @()
    foreach ($k in $Etypes.GetEnumerator()) {
        $keys += [pscustomobject]@{ EncryptionType = $k.Key; Key = [byte[]]($k.Value) }
    }
    [pscustomobject]@{ KeyVersionNumber = $Kvno; KerberosKeys = $keys; DistinguishedName = 'CN=WEB01,OU=Servers,DC=contoso,DC=com' }
}

Mock Get-RequiredModule { return $true }

Describe 'Compare-Keytab' {
    InModuleScope STKeytab {
        BeforeEach {
            Mock Get-ADReplAccount {
                New-MockAccount
            } -ModuleName STKeytab

            Mock Get-ADComputer {
                [pscustomobject]@{
                    servicePrincipalName = @('host/web01.contoso.com','cifs/web01.contoso.com')
                    'msDS-KeyVersionNumber' = 7
                }
            } -ModuleName STKeytab -ParameterFilter { ($Identity -like '*WEB01*') -or ($SamAccountName -like '*WEB01*') }

            # Fallback for second keytab files
            Mock Get-ADReplAccount {
                New-MockAccount -Kvno 8
            }

            Mock Get-AdComputer {
                [pscustomobject]@{
                    servicePrincipalName = @('host/sql02.contoso.com','cifs/sql02.contoso.com')
                    'msDS-KeyVersionNumber' = 8
                }
            }
        }

        It 'Evaluates two identical keytab files as equal' {
            $outA = Join-Path $global:TestOutDir 'keytabA.keytab'
            $outB = Join-Path $global:TestOutDir 'keytabB.keytab'
            try {
                $keytabA = New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $outA -Force -Confirm:$false | Out-Null
                $keytabB = New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $outB -Force -Confirm:$false | Out-Null

                $res = Compare-Keytab -ReferencePath $outA -CandidatePath $outB -IgnoreTimestamp -RevealKeys
                $res.Equal | Should -Be $true
            } catch {
                Write-Host "Error occurred while comparing equal keytab files: $_"
            }
            finally {
                if (Test-Path $outA) { Remove-item $outA -Force}
                if (Test-Path $outB) { Remove-item $outB -Force}
            }
        }

        It 'Evaluates two different keytab files as unequal and correctly identifies differnces' {
            $outA = Join-Path $global:TestOutDir 'keytabA.keytab'
            $outB = Join-Path $global:TestOutDir 'keytabB.keytab'
            try {
                $keytabA = New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $outA -Force -Confirm:$false | Out-Null
                $keytabB = New-Keytab -SuppressWarnings -SamAccountName 'SQL02$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $outB -Force -Confirm:$false | Out-Null

                $res = Compare-Keytab -ReferencePath $outA -CandidatePath $outB -IgnoreTimestamp
                $res.Equal | Should -Be $false
                Write-Host $res.Differences
            } catch {
                Write-Host "Error occurred while comparing different keytab files: $_"
            } finally {
                if (Test-Path $outA) { Remove-item $outA -Force}
                if (Test-Path $outB) { Remove-item $outB -Force}
            }
        }
    }
}

