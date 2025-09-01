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


$modulePath = Resolve-Path "$PSScriptRoot\..\STKeytab.psd1"
$moduleName = 'STKeytab'
$TestOutDir = Join-Path $PSScriptRoot 'output'
Import-Module -Name "$modulePath" -Force -ErrorAction Stop

if (-not (Test-Path $TestOutDir)) { New-Item -ItemType Directory -Path $TestOutDir -Force | Out-Null }


Describe 'New-KeytabFromPassword - PBKDF2 custom vs Rfc2898DeriveBytes' {
    InModuleScope $ModuleName {
        It 'matches Rfc2898 for AES128 and AES256' {
            $passwd = 'Pr4t3rSt*rn'
            $salt = [Text.Encoding]::UTF8.GetBytes('EXAMPLE.COMuser') # MIT-style salt for user@example.com
            $iter = 4096

            $passBytes1 = [Text.Encoding]::UTF8.GetBytes($passwd)
            $passBytes2 = [Text.Encoding]::UTF8.GetBytes($passwd)

            $hmac = [System.Security.Cryptography.HMACSHA1]::New()
            $hmac.Key = $passBytes1

            $hmac2 = [System.Security.Cryptography.HMACSHA1]::New()
            $hmac2.Key = $passBytes2

            # custom
            $key128Sha1 = Invoke-PBKDF2Hmac -PasswordBytes $passBytes1 -SaltBytes $salt -Iterations $iter -DerivedKeyLength 16 -HmacAlgorithm $hmac
            $key256Sha1 = Invoke-PBKDF2Hmac -PasswordBytes $passBytes2 -SaltBytes $salt -Iterations $iter -DerivedKeyLength 32 -HmacAlgorithm $hmac2

            # Rfc2898DeriveBytes
            $p1 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes ($passwd, $salt, $iter, [System.Security.Cryptography.HashAlgorithmName]::SHA1)
            $ref128 = $p1.GetBytes(16)
            $p1 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes ($passwd, $salt, $iter, [System.Security.Cryptography.HashAlgorithmName]::SHA1)
            $ref256 = $p1.GetBytes(32)

            # Validate
            ($key128Sha1 -join ',') | Should -BeExactly ($ref128 -join ',')
            ($key256Sha1 -join ',') | Should -BeExactly ($ref256 -join ',')
        }
    }
    InModuleScope $ModuleName {
        It 'matches Rfc8009 for AES-SHA2' {
            $passwd = 'Pr4t3rSt*rn'
            $salt = [Text.Encoding]::UTF8.GetBytes('EXAMPLE.COMuser') # MIT-style salt for user@example.com
            $iter = 32768

            $passBytes1 = [System.Text.Encoding]::UTF8.GetBytes($passwd)
            $passBytes2 = [System.Text.Encoding]::UTF8.GetBytes($passwd)

            $hmac = [System.Security.Cryptography.HMACSHA256]::New()
            $hmac.Key = $passBytes1

            $hmac2 = [System.Security.Cryptography.HMACSHA384]::New()
            $hmac2.Key = $passBytes2

            # custom
            $key256Sha2 = Invoke-PBKDF2Hmac -PasswordBytes $passBytes1 -SaltBytes $salt -Iterations $iter -DerivedKeyLength 16 -HmacAlgorithm $hmac
            $key384Sha2 = Invoke-PBKDF2Hmac -PasswordBytes $passBytes2 -SaltBytes $salt -Iterations $iter -DerivedKeyLength 32 -HmacAlgorithm $hmac2

            $pS1 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes ($passwd, $salt, $iter, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
            $ref256Sha2 = $pS1.GetBytes(16)
            $pS1 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes ($passwd, $salt, $iter, [System.Security.Cryptography.HashAlgorithmName]::SHA384)
            $ref384Sha2 = $pS1.GetBytes(32)

            # Validate
            ($key256Sha2 -join ',') | Should -BeExactly ($ref256Sha2 -join ',')
            ($key384Sha2 -join ',') | Should -BeExactly ($ref384Sha2 -join ',')
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
            $TestOutDir = Join-Path $PSScriptRoot 'output'
            if (-not (Test-Path $TestOutDir)) { New-Item -ItemType Directory -Path $TestOutDir -Force | Out-Null }
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
