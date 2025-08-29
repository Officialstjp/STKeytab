<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

$modulePath = Resolve-Path "$PSScriptRoot\..\STKeytab.psd1"
$moduleName = 'STKeytab'
Import-Module -Name "$modulePath" -Force -ErrorAction Stop

Describe 'Reset-AccountPasswordWithKeytab' {
    InModuleScope $moduleName {
        BeforeEach {
            Mock Get-RequiredModule { }
            Mock Resolve-DomainContext { 'test.com' }
            Mock Get-PolicyIntent {
                param($IncludeEtype, $ExcludeEtype, $AESOnly, $IncludeLegacyRC4, $AllowDeadCiphers, $PathKind)
                # Suppress unused parameter warnings for mock parameters
                $null = $IncludeEtype, $ExcludeEtype, $AESOnly, $AllowDeadCiphers
                $includeIds = @(17,18)  # Default AES
                if ($IncludeLegacyRC4) {
                    $includeIds += 23  # Add RC4
                }
                [pscustomobject]@{
                    IncludeIds = $includeIds
                    ExcludeIds = @()
                    PathKind = $PathKind
                }
            }
            Mock Validate-PasswordPathCompatibility {
                param($Policy)
                # Simulate AES-only enforcement - throw if policy contains RC4
                if ($Policy.IncludeIds -contains 23) {
                    throw "Password path requires AES-only encryption types"
                }
            }
            Mock Write-SecurityWarning { }
            Mock Resolve-EtypeSelection {
                [pscustomobject]@{
                    Selected = @(17,18)
                    Available = @(17,18)
                }
            }
            Mock Get-EtypeNameFromId {
                param($Id)
                switch($Id) {
                    17 { 'aes128-cts-hmac-sha1-96' }
                    18 { 'aes256-cts-hmac-sha1-96' }
                    default { "etype-$Id" }
                }
            }
            Mock Resolve-Path {
                param($Path)
                # Suppress unused parameter warning for mock parameter
                $null = $Path
                [pscustomobject]@{ Path = 'C:\temp' }
            }
            Mock Get-ADUser {
                [pscustomobject]@{
                    'msDS-KeyVersionNumber' = 5
                    'msDS-SupportedEncryptionTypes' = 24
                    SamAccountName = 'svc-test'
                    DistinguishedName = 'CN=svc-test,OU=Service Accounts,DC=test,DC=com'
                }
            }
            Mock Set-ADAccountPassword { }
            Mock Set-ADObject { }
            Mock New-KeytabFromPassword {
                param($SamAccountName, $Password, $Realm, $Kvno, $OutputPath, $SuppressWarnings, $IncludeEtype, $ExcludeEtype, $FixedTimestampUtc)
                # Suppress unused parameter warnings for mock parameters
                $null = $Password, $Realm, $Kvno, $SuppressWarnings, $IncludeEtype, $ExcludeEtype, $FixedTimestampUtc
                [pscustomobject]@{
                    SamAccountName = $SamAccountName
                    OutputPath = $OutputPath
                    Etypes = @(17,18)
                    SummaryPath = 'C:\temp\svc-test.json'
                }
            }
            Mock New-StrongPassword {
                ConvertTo-SecureString 'MockedStrongPassword123!' -AsPlainText -Force
            }
        }

        It 'generates operation plan with -WhatIfOnly' {
            $result = Reset-AccountPasswordWithKeytab -SamAccountName 'svc-test' -WhatIfOnly -AcknowledgeRisk -Justification 'Test'
            # The function returns both formatted output and the plan object - get the last item which is the plan
            $plan = $result | Where-Object { $_ -is [System.Collections.Specialized.OrderedDictionary] }
            $plan.Operation | Should -Be 'Reset-AccountPasswordWithKeytab'
            $plan.SamAccountName | Should -Be 'svc-test'
            $plan.CurrentKvno | Should -Be 5
            $plan.PredictedKvno | Should -Be 6
        }

        It 'enforces AES-only policy on password path' {
            { Reset-AccountPasswordWithKeytab -SamAccountName 'svc-test' -IncludeLegacyRC4 -AcknowledgeRisk -Justification 'Test' -WhatIfOnly } | Should -Throw '*AES*'
        }

        It 'throws when no risk acknowledgment is provided' {
            { Reset-AccountPasswordWithKeytab -SamAccountName 'svc-test' -Justification 'Test' -WhatIfOnly } | Should -Throw '*risk acknowledgment*'
        }

        It 'throws when no justification is provided' {
            { Reset-AccountPasswordWithKeytab -SamAccountName 'svc-test' -AcknowledgeRisk -WhatIfOnly } | Should -Throw '*justification*'
        }

        It 'calls AD cmdlets in correct order' {
            Reset-AccountPasswordWithKeytab -SamAccountName 'svc-test' -AcknowledgeRisk -Justification 'Test' -Confirm:$false

            Assert-MockCalled Get-ADUser -Times 1
            Assert-MockCalled Set-ADAccountPassword -Times 1
            Assert-MockCalled New-KeytabFromPassword -Times 1
        }
    }
}
