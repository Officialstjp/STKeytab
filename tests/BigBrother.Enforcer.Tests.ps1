<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

<#
    .SYNOPSIS
    Unit tests for BigBrother.Enforcer policy helpers and guards.

    .DESCRIPTION
    These tests validate:
    - Get-PolicyIntent defaults and quick flags
    - Validate-PasswordPathCompatibility (AES-only enforcement)
    - Resolve-EtypeSelection with -Policy
    - Select-CombinedEtypes aggregation contract
#>

Set-StrictMode -Version Latest

$modulePath = Resolve-Path "$PSScriptRoot\..\STKeytab.psd1"
$moduleName = 'STKeytab'
Import-Module -Name "$modulePath" -Force -ErrorAction Stop

Describe 'Get-PolicyIntent' {
    InModuleScope $moduleName {
        It 'defaults to AES-only includes and excludes dead ciphers (replication path)' {
            $p = Get-PolicyIntent -PathKind Replication
            $p.PathKind | Should -Be 'Replication'
            $p.IncludeIds | Should -Be @(17,18)
            $p.AESOnly | Should -BeFalse
            $p.IncludeLegacyRC4 | Should -BeFalse
            $p.AllowDeadCiphers | Should -BeFalse
        }

        It 'honors -AESOnly and can add RC4 when -IncludeLegacyRC4 is used' {
            $p = Get-PolicyIntent -AESOnly -IncludeLegacyRC4 -PathKind Replication
            ($p.IncludeIds | Sort-Object) | Should -Be @(17,18,23)
            $p.AESOnly | Should -BeTrue
            $p.IncludeLegacyRC4 | Should -BeTrue
        }
    }
}

Describe 'Validate-PasswordPathCompatibility' {
    InModuleScope $moduleName {
        It 'throws when non-AES etypes are requested on the password path' {
            $p = Get-PolicyIntent -IncludeLegacyRC4 -PathKind Password
            { Validate-PasswordPathCompatibility -Policy $p -SuppressWarnings } | Should -Throw -Because 'Password S2K path is AES-only'
        }

        It 'does not throw for AES-only includes on password path' {
            $p = Get-PolicyIntent -IncludeEtype 17,18 -PathKind Password
            { Validate-PasswordPathCompatibility -Policy $p -SuppressWarnings } | Should -Not -Throw
        }
    }
}

Describe 'Resolve-EtypeSelection with -Policy' {
    InModuleScope $moduleName {
        It 'selects from AvailableIds and applies exclude from policy' {
            $p = Get-PolicyIntent -IncludeEtype 17,23 -ExcludeEtype 17 -PathKind Replication
            $sel = Resolve-EtypeSelection -AvailableIds ([int[]]@(17,18,23)) -Policy $p
            $sel.Selected | Should -Be @(23) -Because 'Include 17+23 then exclude 17 leaves only 23; no fallback expansion is applied.'
        }

        It 'falls back to all available when include ids are empty and carries UnknownInclude' {
            $p = Get-PolicyIntent -IncludeEtype 'FOO' -PathKind Replication
            $sel = Resolve-EtypeSelection -AvailableIds ([int[]]@(17,18,23)) -Policy $p
            ($sel.Selected | Sort-Object) | Should -Be @(17,18,23)
            $sel.UnknownInclude.Count | Should -Be 1
            $sel.UnknownInclude[0] | Should -Be 'FOO'
        }
    }
}

# DRY: Select-CombinedEtypes is already covered in STkeytab.Tests.ps1
