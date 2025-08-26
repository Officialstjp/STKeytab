<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

<#
    .SYNOPSIS
    dedicated Unit tests for the Set-UserOnlyAcl helper

#>

Set-StrictMode -Version Latest

$modulePath = Resolve-Path "$PSScriptRoot\..\STKeytab.psd1"
$moduleName = 'STKeytab'
$TestOutDir = Join-Path $PSScriptRoot 'output'
Import-Module -Name "$modulePath" -Force -ErrorAction Stop

if (-not (Test-Path $TestOutDir)) { New-Item -ItemType Directory -Path $TestOutDir -Force | Out-Null }

Describe 'Set-UserOnlyAcl'{
    InModuleScope $moduleName {
        It 'sets only current user with FullControl and no inheritance on a file' {
            $tmp = New-Item -Type File -Path (Join-Path $TestOutDir ([guid]::NewGuid()))
            try {
                $acl = Set-UserOnlyAcl -Path $tmp.FullName
                $CurrUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

                $acl.AreAccessRulesProtected    | Should -BeTrue
                $acl.Owner                      | Should -Be $CurrUser
                $aces = $acl.Access
                Write-Host "Count: $($aces | Measure-Object).Count"
                $($aces | Measure-Object).Count | Should -BeExactly 1
                $aces.FileSystemRights          | Should -Be "FullControl"
                $aces.AccessControlType         | Should -Be "Allow"
                $aces.IsInherited               | Should -Be "False"
                $aces.InheritanceFlags          | Should -Be "None"
                $aces.PropagationFlags          | Should -Be "None"

            } finally { Remove-Item $tmp.FullName -Force -ErrorAction SilentlyContinue }
        }
    }
}
