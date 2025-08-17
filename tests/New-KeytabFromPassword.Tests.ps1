<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

<#
    .SYNOPSIS
    Pester tests for the New-KeytabFromPassword cmdlet.

    .DESCRIPTION
    These tests validate:
    - PBKDF2 equivalence with Rfc2898DeriveBytes
    - Salt casing policy
    - Deterministic keytab write/read behavior
#>


$modulePath = Resolve-Path "$PSScriptRoot\..\STkrbKeytab.psd1"
$moduleName = 'STkrbKeytab'
$TestOutDir = Join-Path $PSScriptRoot 'output'
Import-Module -Name "$modulePath" -Force -ErrorAction Stop

if (-not (Test-Path $TestOutDir)) { New-Item -ItemType Directory -Path $TestOutDir -Force | Out-Null }


Describe 'New-KeytabFromPassword - PBKDF2 custom vs Rfc2898DeriveBytes' {
    InModuleScope $ModuleName {
        It 'matches Rfc2898 for AES128 and AES256' {
            $passwd = 'Pr4t3rSt*rn'
            $salt = [Text.Encoding]::UTF8.GetBytes('EXAMPLE.COMuser') # MIT-style salt for user@example.com
            $iter = 4096

            # custom
            $key128 = Invoke-PBKDF2HmacSha1 -PasswordBytes ([Text.Encoding]::UTF8.GetBytes($passwd)) -SaltBytes $salt -Iterations $iter -DerivedKeyLength 16
            $key256 = Invoke-PBKDF2HmacSha1 -PasswordBytes ([Text.Encoding]::UTF8.GetBytes($passwd)) -SaltBytes $salt -Iterations $iter -DerivedKeyLength 32

            # Rfc2898DeriveBytes
            $p1 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes ($passwd, $salt, $iter, [System.Security.Cryptography.HashAlgorithmName]::SHA1)
            $ref128 = $p1.GetBytes(16)
            $p1 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes ($passwd, $salt, $iter, [System.Security.Cryptography.HashAlgorithmName]::SHA1)
            $ref256 = $p1.GetBytes(32)

            # Validate
            ($key128 -join ',') | Should -BeExactly ($ref128 -join ',')
            ($key256 -join ',') | Should -BeExactly ($ref256 -join ',')
        }
    }
}

Describe 'New-KeytabFromPassword - salt policy' {
    InModuleScope $ModuleName {
        It 'Windows compatibility uppercases realm and lowercases service/host' {
            $princDesc = [pscustomobject]@{
                Components=@('HTTP','WebSrv01')
                Realm='example.com'
                NameType=3
            }
            $salt = Get-DefaultSalt -Compatibility Windows -PrincipalDescriptor $princDesc
            $str = [Text.Encoding]::UTF8.GetString($salt)
            $str | Should -Be 'EXAMPLE.COMhttpwebsrv01'
        }
    }
}

Describe 'New-KeytabFromPassword -write/read determinism' {
    InModuleScope $ModuleName {
        It 'produces a readably keytab with fixed timestamp' {
            $out = Join-Path $TestOutDir 'passwd-user.keytab'
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
            $fixed = [datetime]::Parse('2020-01-01T00:00:00Z')
            $sec = ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force
            $res = New-KeytabFromPassword -SamAccountName 'user1' -Realm 'EXAMPLE.COM' `
                                            -Password $sec -IncludeEtype 18,17 -Kvno 3 -Iterations 4096 `
                                            -OutputPath $out -Force -FixedTimestampUtc $fixed -Summary -Passthru
            Test-Path -LiteralPath $res.OutputPath | Should -Be $true
            $parsed = Read-Keytab -Path $res.OutputPath
            ($parsed | Select-Object -ExpandProperty EtypeId | Sort-Object Unique) | Should -Be @(17,18)
        }
    }
}
