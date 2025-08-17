<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

<#
    .SYNOPSIS
    Unit tests for the STkrbKeytab module.

    .DESCRIPTION
    - Unit tests: mapping and selection helpers
        - Get-EtypeIdFromInput: verify handling for int, string-number, name (AES256_CTS_HMAC_SHA1_96), unknowns.
        - Get-EtypeNameFromId: verify known and unknown id mapping.
        - Resolve-EtypeSelection: verify include-only, exclude-only, include+exclude, missing, unknown include/exclude.

    - Unit tests: byte operations via keytab roundtrip
        - Build one or more PrincipalDescriptor objects (user/service).
        - Build simple key sets with Kvno and keys for etypes 18 and 17.
        - New-KeytabFile to a temp file.
        - Read-Keytab with and without -RevealKeys; verify realm, components, nameType, Kvno, EtypeId, KeyLength, EtypeName, masked/unmasked key behavior, and TimestampUtc with FixedTimestampUtc.
        - Read-Keytab: invalid header throws.

    - Unit tests: banner
        - Write-SecurityWarning -AsString for krbtgt/high/medium; verify content contains key phrases and width.
        - Suppression via env var returns empty string.

    - Unit tests: misc helpers
        - Select-CombinedEtypes returns unique int array from multiple key sets.
        - Set-UserOnlyAcl: mock Set-Acl; ensure called with FileSecurity.

    - Unit tests: domain helpers
        - Resolve-DomainContext returns env:USERDNSDOMAIN when Domain not provided.
        - Resolve-DomainContext falls back to Get-ADDomain.DNSRoot when env not set.
        - ConvertTo-NetBIOSIfFqdn returns NetBIOSName from Get-ADDomain; default to first label upper-cased otherwise.

    - Unit tests: key material extraction (mocked AD/DSInternals)
        - Mock Get-ADObject / Get-ADComputer to return msDS-KeyVersionNumber.
        - Build fake Account with SupplementalCredentials.KerberosNew groups:
            - Credentials (current), OldCredentials (kvno-1), OlderCredentials (kvno-2) containing entries with Key and various forms of KeyType (int/string/object.Value).
        - Call Get-KerberosKeyMaterialFromAccount for user and for krbtgt; verify PrincipalType, KeySets deduped by kvno/etype, and kvno assignment per group.

    - Integration tests: New-Keytab orchestration (mocked dependencies)
        - Mock Get-RequiredModule to no-op and Get-ADReplAccount to return fake Account.
        - New-Keytab for:
            - User principal: verify output keytab file exists and Test-Keytab returns true; Summary JSON content fields.
            - Computer principal: mock Get-ADComputer servicePrincipalName; pass AdditionalSpn; verify principal descriptors count and output exists.
            - Krbtgt with -IncludeOldKvno: verify multiple kvnos present; requires -AcknowledgeRisk.

    - Integration tests: Merge-Keytab
        - Create two keytabs for same principal/kvno/etype with same key; merge and verify dedup and output file exists.
        - Create conflicting keytabs (same kvno/etype; different key); verify throws conflict.

    - Integration tests: Test-Keytab unknown etype
        keytab with a non-mapped etype (e.g., 4095); Test-Keytab -Detailed returns unknown etype list containing 4095.

    - Integration tests: Protect/Unprotect (Windows-only)
        - Protect-Keytab with entropy; verify .dpapi file exists.
        - Unprotect-Keytab; verify unprotected bytes equal original; cleanup.

    .TIPS
    Follow structure:
    Describe 'Something' {
        It 'does something' {
            # Arrange
            # Act
            # Assert
        }
    }

    Public functions are imported at startup.
    To use private functions from the module:
    Describe 'Something' {
        InModuleScope $ModuleName {
            It 'does something' {
                # Arrange
                # Act
                # Assert
            }
        }
    }
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Resolve-Path "$PSScriptRoot\..\STkrbKeytab.psd1"
$moduleName = 'STkrbKeytab'
$TestOutDir = Join-Path $PSScriptRoot 'output'
Import-Module -Name "$modulePath" -Force -ErrorAction Stop

if (-not (Test-Path $TestOutDir)) { New-Item -ItemType Directory -Path $TestOutDir -Force | Out-Null }

# clear all files in the test directory
try { Get-ChildItem -Path $TestOutDir -File | Remove-Item -Force } catch {
    Write-Warning "Failed to clear test output directory: $_"
}

Describe 'Etype mapping and selection helpers' {
    InModuleScope $ModuleName {
        It 'Get-EtypeIdFromInput maps int/string/name and returns $null for unknown' {
            Get-EtypeIdFromInput 18 | Should -Be 18
            Get-EtypeIdFromInput '18' | Should -Be 18
            Get-EtypeIdFromInput 'AES256_CTS_HMAC_SHA1_96' | Should -Be 18
            Get-EtypeIdFromInput 'nonexistent' | Should -BeNullOrEmpty
        }

        It 'Get-EtypeNameFromId resolves known and unknown ids' {
            Get-EtypeNameFromId 18 | Should -Be 'AES256_CTS_HMAC_SHA1_96'
            Get-EtypeNameFromId 4095 | Should -Be 'ETYPE_4095'
        }

        It 'Resolve-EtypeSelection handles include/exclude/missing/unknown' {
            $avail = @(18,17,23)
            $sel = Resolve-EtypeSelection -AvailableIds $avail -Include @('18','AES128_CTS_HMAC_SHA1_96') -Exclude @(23,'bad')
            $sel.Selected | Sort-Object | Should -Be @(17,18)
            $sel.Missing | Sort-Object | Should -Be @()
            $sel.UnknownExclude | Should -Contain 'bad'
            $sel.UnknownInclude | Should -Be @()
            # Missing case
            $sel2 = Resolve-EtypeSelection -AvailableIds $avail -Include @(26,18)
            $sel2.Selected | Sort-Object | Should -Be @(18)
            $sel2.Missing | Should -Contain 26
        }
    }
}


Describe 'Keytab write/read roundtrip' {
    InModuleScope $ModuleName {
        It 'New-KeytabFile + Read-Keytab roundtrip with fixed timestamp and etype filter' {
            $pd = New-PrincipalDescriptor -Components @('user') -Realm 'EXAMPLE.COM' -NameType 1 -Tags @('User')
            $key18 = 0..31 | ForEach-Object { [byte]$_ }
            $key17 = 100..131 | ForEach-Object { [byte]$_ }
            $keySets = @(
                [pscustomobject]@{ Kvno = 7; Keys = @{ 18 = $key18; 17 = $key17 } }
            )
            $out = Join-Path $TestOutDir 'roundtrip.keytab'
            $fixed = [datetime]::SpecifyKind((Get-Date '2020-01-02T03:04:05Z'), 'Utc')
            $null = New-KeytabFile -Path $out -PrincipalDescriptors @($pd) -KeySets $keySets -EtypeFilter @(18,17) -FixedTimestampUtc $fixed
            Test-Path $out | Should -BeTrue

            $parsed = Read-Keytab -Path $out -RevealKeys
            $parsed.Count | Should -Be 2
            $parsed[0].Realm | Should -Be 'EXAMPLE.COM'
            $parsed[0].Components | Should -Be @('user')
            $parsed[0].NameType | Should -Be 1
            $parsed | ForEach-Object { $_.Kvno } | Select-Object -Unique | Should -Be @(7)
            ($parsed | Where-Object EtypeId -eq 18).KeyLength | Should -Be 32
            ($parsed | Where-Object EtypeId -eq 18).RawKey | Should -Be $key18
            ($parsed | Select-Object -First 1).TimestampUtc | Should -Be $fixed
        }

        It 'Read-Keytab rejects invalid header' {
            $bad = Join-Path $TestOutDir 'bad.keytab'
            [IO.File]::WriteAllBytes($bad, [byte[]](0x01,0x02,0x03))
            { Read-Keytab -Path $bad } | Should -Throw "*not a valid keytab*"
        }
    }
}

Describe 'Security banner' {
    InModuleScope $ModuleName {
        It 'Write-SecurityWarning returns krbtgt banner string unless suppressed' {
            $txt = Write-SecurityWarning -RiskLevel 'krbtgt' -SamAccountName 'krbtgt' -AsString
            $txt | Should -Match 'KRBTGT'
            $txt | Should -Match 'SECURITY WARNING'
            # Suppress via env
            $old = $env:STCRYPT_SUPPRESS_SECURITY_WARNING
            try {
                $env:STCRYPT_SUPPRESS_SECURITY_WARNING = '1'
                $txt2 = Write-SecurityWarning -RiskLevel 'High' -SamAccountName 'X' -AsString
                $txt2 | Should -Be ""
            } finally {
                $env:STCRYPT_SUPPRESS_SECURITY_WARNING = $old
            }
        }
    }
}

Describe 'Other helpers' {
    InModuleScope $ModuleName {
        It 'Select-CombinedEtypes returns unique set' {
            $ks = @(
                [pscustomobject]@{ Kvno=1; Keys = @{ 18 = @(0..1); 17 = @(2..3) } },
                [pscustomobject]@{ Kvno=2; Keys = @{ 23 = @(4..5); 18 = @(6..7) } }
            )
            ($r = Select-CombinedEtypes -KeySets $ks) | Out-Null
            @($r | Sort-Object) | Should -Be @(17,18,23)
            }

        It 'Set-UserOnlyAcl attempts to set restrictive ACL' {
            Mock -CommandName Set-Acl -MockWith { } -Verifiable
            $p = Join-Path $TestOutDir 'file.dat'
            Set-Content -LiteralPath $p -Value 'x'
            Set-UserOnlyAcl -Path $p
            Assert-MockCalled -CommandName Set-Acl -Times 1
        }
    }
}

Describe 'Domain helpers' {
    InModuleScope $ModuleName {
        It 'Resolve-DomainContext uses env var or Get-ADDomain' {
            $old = $env:USERDNSDOMAIN
            try {
                $env:USERDNSDOMAIN = 'example.com'
                (Resolve-DomainContext) | Should -Be 'example.com'
                $env:USERDNSDOMAIN = $null
                Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'contoso.local' } }
                (Resolve-DomainContext) | Should -Be 'contoso.local'
            } finally {
                $env:USERDNSDOMAIN = $old
            }
        }

        It 'ConvertTo-NetBIOSIfFqdn prefers AD NetBIOSName then first label upper' {
            Mock Get-ADDomain { [pscustomobject]@{ NetBIOSName = 'CONTOSO' } }
            (ConvertTo-NetBIOSIfFqdn -Domain 'contoso.local') | Should -Be 'CONTOSO'
            # No NetBIOSName -> fallback
            Mock Get-ADDomain { throw 'no ad' } -Verifiable -ParameterFilter { $true }
            (ConvertTo-NetBIOSIfFqdn -Domain 'child.domain.tld') | Should -Be 'CHILD'
        }
    }
}

Describe 'Key material extraction (mocked AD/DSInternals)' {
    InModuleScope $ModuleName {
        BeforeEach {
            # default KVNO from AD
            Mock Get-ADObject { [pscustomobject]@{ 'msDS-KeyVersionNumber' = 9; DistinguishedName = 'CN=User,DC=x,DC=y' } } -ModuleName STkrbKeytab
            Mock Get-ADComputer { [pscustomobject]@{ 'msDS-KeyVersionNumber' = 12; DistinguishedName = 'CN=PC,OU=Domain Controllers,DC=x,DC=y' } } -ModuleName STkrbKeytab
        }

        It 'Extracts KerberosNew groups and maps kvno for krbtgt' {
            $entryInt = [pscustomobject]@{ Key = (1..16 | ForEach-Object {[byte]$_}); KeyType = 18 }
            $entryStr = [pscustomobject]@{ Key = (21..36 | ForEach-Object {[byte]$_}); KeyType = '17' }
            $entryObj = [pscustomobject]@{ Key = (41..56 | ForEach-Object {[byte]$_}); KeyType = [pscustomobject]@{ Value = 23 } }
            $account = [pscustomobject]@{
                DistinguishedName = 'CN=krbtgt,DC=example,DC=com'
                SupplementalCredentials = [pscustomobject]@{
                KerberosNew = [pscustomobject]@{
                    Credentials        = @($entryInt)
                    ServiceCredentials = @()
                    OldCredentials     = @($entryStr)
                    OlderCredentials   = @($entryObj)
                }
            }
            }
            $res = Get-KerberosKeyMaterialFromAccount -Account $account -SamAccountName 'krbtgt' -IsKrbtgt
            $res.PrincipalType | Should -Be 'Krbtgt'
            ($res.KeySets | Sort-Object Kvno | Select-Object -ExpandProperty Kvno) | Should -Be @(7,8,9)
            ($res.KeySets | Where-Object Kvno -eq 9).Keys.Keys | Should -Contain 18
            ($res.KeySets | Where-Object Kvno -eq 8).Keys.Keys | Should -Contain 17
            ($res.KeySets | Where-Object Kvno -eq 7).Keys.Keys | Should -Contain 23
        }

        It 'Extracts legacy KerberosKeys for computer and detects DC' {
            $kerbKeys = @(
                [pscustomobject]@{ EncryptionType = 18; key = (1..32 | ForEach-Object {[byte]$_}) },
                [pscustomobject]@{ EncryptionType = 17; key = (101..132 | ForEach-Object {[byte]$_}) }
            )
            $account = [pscustomobject]@{
                DistinguishedName = 'CN=PC1,OU=Domain Controllers,DC=e,DC=f'
                KerberosKeys = $kerbKeys
            }
            $res = Get-KerberosKeyMaterialFromAccount -Account $account -SamAccountName 'PC1$'
            $res.PrincipalType | Should -Be 'Computer'
            $res.KeySets.Count | Should -Be 1
            $res.KeySets[0].Keys.Keys | Sort-Object | Should -Be @(17,18)
            $res.RiskLevel | Should -Be 'High'
        }
    }
}

Describe 'New-Keytab orchestration (mocked dependencies)' {
    InModuleScope $ModuleName {
        BeforeEach {
            Mock Get-RequiredModule { } -ModuleName STkrbKeytab # avoid touching actual modules
            # Fake account with KerberosNew current only
            $script:fakeEntry = [pscustomobject]@{ Key = (11..42 | ForEach-Object {[byte]$_}); KeyType = 18 }
            $script:fakeAcct = [pscustomobject]@{
                DistinguishedName = 'CN=User,DC=ex,DC=com'
                SupplementalCredentials = [pscustomobject]@{
                    KerberosNew = [pscustomobject]@{
                        Credentials        = @($script:fakeEntry)
                        ServiceCredentials = @()
                        OldCredentials     = @()
                        OlderCredentials   = @()
                    }
                }
            }

            Mock Get-ADReplAccount { $script:fakeAcct } -ModuleName STkrbKeytab
            Mock Get-ADObject { [pscustomobject]@{ 'msDS-KeyVersionNumber' = 3; DistinguishedName = 'CN=User,DC=ex,DC=com' } } -ModuleName STkrbKeytab
            Mock Get-ADComputer { [pscustomobject]@{ 'msDS-KeyVersionNumber' = 4; DistinguishedName = 'CN=PC,OU=Computers,DC=ex,DC=com'; servicePrincipalName = @('host/pc.ex.com','cifs/pc.ex.com') } } -ModuleName STkrbKeytab
            Mock Get-ADDomain { [pscustomobject]@{ DNSRoot='ex.com'; NetBIOSName='EX' } } -ModuleName STkrbKeytab
        }

        It 'Creates user keytab and summary' {
            $out = Join-Path $TestOutDir 'user.keytab'
            $json = Join-Path $TestOutDir 'user.json'
            $r = New-Keytab -SuppressWarnings -SamAccountName 'svc-app' -Type User -Domain 'ex.com' -OutputPath $out -JsonSummaryPath $json -PassThru -Confirm:$false
            Test-Path $out | Should -BeTrue
            Test-Path $json | Should -BeTrue
            (Test-Keytab -Path $out) | Should -BeTrue
            $j = Get-Content -Raw -LiteralPath $json | ConvertFrom-Json
            $j.SamAccountName | Should -Be 'svc-app'
            $j.EncryptionTypes | Should -Contain 'AES256_CTS_HMAC_SHA1_96'
        }

        It 'Creates computer keytab with SPNs (including AdditionalSpn)' {
            $out = Join-Path $TestOutDir 'pc.keytab'
            $r = New-Keytab -SuppressWarnings -SamAccountName 'PC$' -Type Computer -Domain 'ex.com' -OutputPath $out -AdditionalSpn 'http/pc.ex.com' -IncludeShortHost -Confirm:$false
            Test-Path $out | Should -BeTrue
            (Test-Keytab -Path $out) | Should -BeTrue
        }

        It 'Creates krbtgt keytab with IncludeOldKvno when acknowledged' {
            Mock Get-ADObject { [pscustomobject]@{ 'msDS-KeyVersionNumber' = 5; DistinguishedName = 'CN=krbtgt,DC=ex,DC=com' } } -ModuleName STkrbKeytab
            $old = [pscustomobject]@{ Key = (51..82 | ForEach-Object {[byte]$_}); KeyType = 18 }
            $acct = [pscustomobject]@{
                DistinguishedName = 'CN=krbtgt,DC=ex,DC=com'
                SupplementalCredentials = [pscustomobject]@{
                    KerberosNew = [pscustomobject]@{
                        Credentials        = @($script:fakeEntry)
                        OldCredentials     = @($old)
                        ServiceCredentials = @()
                        OlderCredentials   = @()
                    }
                }
            }
            Mock Get-ADReplAccount { $acct } -ModuleName STkrbKeytab
            $out = Join-Path $TestOutDir 'krbtgt.keytab'
            $r = New-Keytab -SuppressWarnings -SamAccountName 'krbtgt' -Type Krbtgt -Domain 'ex.com' -OutputPath $out -IncludeOldKvno -AcknowledgeRisk -Confirm:$false
            Test-Path $out | Should -BeTrue
            $parsed = Read-Keytab -Path $out
            ($parsed | Select-Object -ExpandProperty Kvno | Sort-Object -Unique) | Should -Be @(4,5)
        }

        It 'Uses FixedTimestampUtc for entries and summary' {
            $fixed = [datetime]::SpecifyKind((Get-Date '2021-02-03T04:05:06Z'), 'Utc')
            $out = Join-Path $TestOutDir 'fixed.keytab'
            $json = Join-Path $TestOutDir 'fixed.json'
            $r = New-Keytab -SuppressWarnings -SamAccountName 'svc-app' -Type User -Domain 'ex.com' -OutputPath $out -JsonSummaryPath $json -FixedTimestampUtc $fixed -PassThru -Confirm:$false
            $parsed = Read-Keytab -Path $out
            ($parsed | Select-Object -First 1).TimestampUtc | Should -Be $fixed
            ((Get-Content -Raw -LiteralPath $json | ConvertFrom-Json).GeneratedAtUtc) | Should -Be $fixed
        }
    }
}

Describe 'Merge-Keytab' {
    InModuleScope $ModuleName {
        It 'Merges two keytabs for same principal (dedup) and detects conflicts' {
            $pd = New-PrincipalDescriptor -Components @('user') -Realm 'EXAMPLE.COM' -NameType 1 -Tags @('User')

            $k1 = 10..41 | ForEach-Object {[byte]$_}
            $k2same = 10..41 | ForEach-Object {[byte]$_}
            $k2diff = 11..42 | ForEach-Object {[byte]$_}
            $ks1 = ,([pscustomobject]@{ Kvno=1; Keys=@{ 18 = $k1 } })
            $ks2 = ,([pscustomobject]@{ Kvno=1; Keys=@{ 18 = $k2same } })
            $ks2c = ,([pscustomobject]@{ Kvno=1; Keys=@{ 18 = $k2diff } })
            $f1 = Join-Path $TestOutDir 'm1.keytab'
            $f2 = Join-Path $TestOutDir 'm2.keytab'
            $f2c= Join-Path $TestOutDir 'm2c.keytab'

            New-KeytabFile -Path $f1 -PrincipalDescriptors @($pd) -KeySets $ks1 | Out-Null
            New-KeytabFile -Path $f2 -PrincipalDescriptors @($pd) -KeySets $ks2 | Out-Null
            New-KeytabFile -Path $f2c -PrincipalDescriptors @($pd) -KeySets $ks2c | Out-Null

            $merged = Join-Path $TestOutDir 'merged.keytab'
            (Merge-Keytab -InputPaths @($f1,$f2) -OutputPath $merged -Force -AcknowledgeRisk) | Out-Null
            Test-Path $merged | Should -BeTrue
            # Conflict case
            $merged2 = Join-Path $TestOutDir 'merged-conflict.keytab'
            { Merge-Keytab -InputPaths @($f1,$f2c) -OutputPath $merged2 -Force -AcknowledgeRisk } | Should -Throw "*Conflicting key material*"
        }
    }
}

Describe 'Test-Keytab unknown etype and validity' {
    InModuleScope $ModuleName {
        It 'Reports unknown etype ids' {
            $pd = New-PrincipalDescriptor -Components @('user') -Realm 'EXAMPLE.COM' -NameType 1 -Tags @('User')
            $k = 1..16 | ForEach-Object {[byte]$_}
            $ks = ,([pscustomobject]@{ Kvno=2; Keys=@{ 4095 = $k } })
            $f = Join-Path $TestOutDir 'unknownetype.keytab'
            New-KeytabFile -Path $f -PrincipalDescriptors @($pd) -KeySets $ks | Out-Null
            $d = Test-Keytab -Path $f -Detailed
            $d.IsValid | Should -BeTrue
            $d.UnknownEtypes | Should -Be @(4095)
        }
    }
}

$onWindows = $PSVersionTable.Platform -eq 'Win32NT'
Describe 'Protect/Unprotect roundtrip (Windows only)' -Skip:(-not $onWindows) {
    It 'Protects and unprotects with DPAPI CurrentUser scope' {
        $f = Join-Path $TestOutDir 'prot.keytab'
        [IO.File]::WriteAllBytes($f, (0..63 | ForEach-Object {[byte]$_}))

        $dpapi = "$f.dpapi"
        Protect-Keytab -Path $f -OutputPath $dpapi -Entropy 'pepper' -Force | Out-Null

        Test-Path $dpapi | Should -BeTrue
        $unp = Join-Path $TestOutDir 'unprot.keytab'

        Unprotect-Keytab -Path $dpapi -OutputPath $unp -Entropy 'pepper' -Force | Out-Null
        [IO.File]::ReadAllBytes($unp) | Should -Be ([IO.File]::ReadAllBytes($f))
    }

    It 'DeletePlaintext removes the original file after protection' {
        $f = Join-Path $TestOutDir 'prot2.keytab'
        [IO.File]::WriteAllBytes($f, (0..31 | ForEach-Object {[byte]$_}))

        $dpapi = "$f.dpapi"
        Protect-Keytab -Path $f -OutputPath $dpapi -DeletePlaintext -Force | Out-Null

        Test-Path $f | Should -BeFalse
        Test-Path $dpapi | Should -BeTrue
    }
}

