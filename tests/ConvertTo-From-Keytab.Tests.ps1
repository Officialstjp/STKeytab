<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

<#
    .SYNOPSIS
    Unit tests for ConvertTo- and ConvertFrom-KeytabJson functions.
#>

Set-StrictMode -Version Latest

$modulePath = Resolve-Path "$PSScriptRoot\..\STkrbKeytab.psd1"
$moduleName = 'STkrbKeytab'
$TestOutDir = Join-Path $PSScriptRoot 'output'
Import-Module -Name "$modulePath" -Force -ErrorAction Stop

if (-not (Test-Path $TestOutDir)) { New-Item -ItemType Directory -Path $TestOutDir -Force | Out-Null }

Describe 'ConvertTo-/ConvertFrom-Json' {
    InModuleScope $moduleName {
        It 'converts keytab to JSON without keys by default' {
            $princDesc = New-PrincipalDescriptor -Components @('svc-app') -Realm 'EXAMPLE.COM' -NameType 1 -Tags @('User')
            $key18 = 0..31 | Foreach-Object { [byte]$_ }
            $key17 = 100..131 | Foreach-Object { [byte]$_ }
            $keyset = ([pscustomobject]@{
                Kvno    = 7
                Keys    = @{ 18 = $key18; 17 = $key17}
            })
            $keytab = Join-Path $TestOutDir 'json-a.keytab'
            $json = Join-Path $TestOutDir 'json-a.json'
            New-KeytabFile -Path $keytab -PrincipalDescriptors @($princDesc) -KeySets $keySet | Out-Null

            ConvertTo-KeytabJson -Path $keytab -OutputPath $json | Out-Null
            $entries = Get-Content -Raw -LiteralPath $json | ConvertFrom-Json
            foreach ($e in $entries) { $e.PSObject.Properties['Key'] | Should -BeNullOrEmpty }
        }

        It 'round-trips via JSON with keys and yiels equivalent keytab (ignoring timestamps)' {
            $princDesc = New-PrincipalDescriptor -Components @('svc-app') -Realm 'EXAMPLE.COM' -NameType 1 -Tags @('User')
            $key18 = 10..41 | Foreach-Object { [byte]$_ }
            $key17 = 200..231 | Foreach-Object { [byte]$_ }
            $keyset = ([pscustomobject]@{
                Kvno    = 5
                Keys    = @{ 18 = $key18; 17 = $key17}
            })
            $keytab1 = Join-Path $TestOutDir 'json-b1.keytab'
            $keytab2 = Join-Path $TestOutDir 'json-b2.keytab'
            $json = Join-Path $TestOutDir 'json-b.json'

            $fixed = [datetime]::SpecifyKind((Get-Date '2021-02-03T04:05:06Z'), 'Utc')

            New-KeytabFile -Path $keytab1 -PrincipalDescriptors @($princDesc) -KeySets $keySet -FixedTimestampUtc $fixed | Out-Null

            ConvertTo-KeytabJson -Path $keytab1 -OutputPath $json -RevealKeys | Out-Null
            ConvertFrom-KeytabJson -JsonPath $json -OutputPath $keytab2 -Force -FixedTimestampUtc $fixed | Out-Null

            $cmp = Compare-Keytab -ReferencePath $keytab1 -CandidatePath $keytab2 -IgnoreTimestamp
            $cmp.Equal | Should -BeTrue
        }
    }
}
