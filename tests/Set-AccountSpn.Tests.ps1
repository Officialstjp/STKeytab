<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

$modulePath = Resolve-Path "$PSScriptRoot\..\STKeytab.psd1"
$moduleName = 'STKeytab'
Import-Module -Name "$modulePath" -Force -ErrorAction Stop

Describe 'Set-AccountSpn' {
    InModuleScope $moduleName {
        BeforeEach {
            Mock Get-RequiredModule { }
            Mock Resolve-DomainContext { 'test.com' }
            Mock Get-ADUser {
                [pscustomobject]@{
                    ServicePrincipalNames = @('HTTP/web.test.com', 'HTTP/web')
                    servicePrincipalName = @('HTTP/web.test.com', 'HTTP/web')
                    SamAccountName = 'svc-web'
                    DistinguishedName = 'CN=svc-web,OU=Service Accounts,DC=test,DC=com'
                }
            }
            Mock Set-ADObject { }
        }

        It 'lists current SPNs' {
            $spns = Set-AccountSpn -SamAccountName 'svc-web' -List
            $spns | Should -Contain 'HTTP/web.test.com'
            $spns | Should -Contain 'HTTP/web'
        }

        It 'detects SPN conflicts' {
            Mock Get-ADUser {
                param($Identity, $Filter, $Properties)
                if ($Filter) {
                    # Conflict search - return an account that has the conflicting SPN
                    @([pscustomobject]@{
                        SamAccountName = 'other-account'
                        DistinguishedName = 'CN=other,DC=test,DC=com'
                        ServicePrincipalNames = @('HTTP/conflict.test.com')
                        servicePrincipalName = @('HTTP/conflict.test.com')
                    })
                } else {
                    # Original account lookup
                    [pscustomobject]@{
                        ServicePrincipalNames = @('HTTP/web.test.com')
                        servicePrincipalName = @('HTTP/web.test.com')
                        SamAccountName = 'svc-web'
                        DistinguishedName = 'CN=svc-web,OU=Service Accounts,DC=test,DC=com'
                    }
                }
            }

            { Set-AccountSpn -SamAccountName 'svc-web' -Add 'HTTP/conflict.test.com' -WhatIfOnly } | Should -Throw '*conflict*'
        }

        It 'provides detailed plan with -WhatIfOnly' {
            $plan = Set-AccountSpn -SamAccountName 'svc-web' -Add 'HTTP/new.test.com' -Remove 'HTTP/web' -WhatIfOnly
            $plan.Operation | Should -Be 'Set-AccountSpn'
            $plan.SpnsToAdd | Should -Contain 'HTTP/new.test.com'
            $plan.SpnsToRemove | Should -Contain 'HTTP/web'
        }

        It 'skips no-op operations' {
            # Try to add existing SPN
            $warnings = @()
            Set-AccountSpn -SamAccountName 'svc-web' -Add 'HTTP/web.test.com' -WhatIfOnly -WarningVariable warnings
            $warnings | Should -Match 'Already present'
        }

        It 'calls Set-ADObject for actual changes' {
            Set-AccountSpn -SamAccountName 'svc-web' -Add 'HTTP/new.test.com' -Confirm:$false
            Assert-MockCalled Set-ADObject -Times 1
        }
    }
}
