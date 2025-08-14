<#
        Pester tests updated for the consolidated New-Keytab cmdlet.
        These tests mock AD/DCSync calls and validate:
            - Header & structural integrity via Test-Keytab
            - Include / Exclude etype filtering
            - Principal collection for Computer type (IncludeShortHost, AdditionalSpn)
            - JSON summary contents
            - Force / WhatIf behaviors
            - Warning on unknown/missing requested etypes
            - Corrupted header detection
 #>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Helper function available to all tests
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


Import-Module -Name "$PSScriptRoot\..\STkrbKeytab.psd1" -Force
Mock Get-RequiredModule { return $true } -ModuleName STkrbKeytab
Describe 'New-Keytab (Computer) basic header' {
    BeforeEach {
        Mock Get-ADReplAccount { New-MockAccount } -ModuleName STkrbKeytab
        Mock Get-ADComputer { 
            [pscustomobject]@{ servicePrincipalName = @('host/web01.contoso.com','cifs/web01.contoso.com'); 'msDS-KeyVersionNumber' = 7 } } -ModuleName STkrbKeytab
    }
    
    It 'writes a keytab with correct 0x0502 header' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $out -Force -Confirm:$false -RestrictAcl:$false | Out-Null
            $bytes = [IO.File]::ReadAllBytes($out)
            $bytes[0] | Should -Be 0x05
            $bytes[1] | Should -Be 0x02
            Test-Keytab -Path $out | Should -BeTrue
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
    
    It 'detects a corrupted header' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $out -Force -Confirm:$false -RestrictAcl:$false | Out-Null
            $b = [IO.File]::ReadAllBytes($out)
            $b[0] = 0x06 # corrupt major byte
            [IO.File]::WriteAllBytes($out,$b)
            Test-Keytab -Path $out | Should -BeFalse
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
        }
    }
}

Describe 'Principal handling' {
    BeforeEach {
        Mock Get-ADReplAccount { New-MockAccount } -ModuleName STkrbKeytab
        Mock Get-ADComputer { [pscustomobject]@{ servicePrincipalName = @('host/web01.contoso.com','cifs/web01.contoso.com'); 'msDS-KeyVersionNumber' = 7 } } -ModuleName STkrbKeytab
    }
    
    It 'includes short host variants when -IncludeShortHost specified' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            # Omit -Type to let parameter set 'Computer' resolve when using Computer-only extras git 
            New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Domain contoso.com -Server dc01.contoso.com -OutputPath $out -Force -IncludeShortHost -Summary -Confirm:$false -RestrictAcl:$false | Out-Null
            $json = [IO.Path]::ChangeExtension($out,'json')
            Test-Path $json | Should -BeTrue
            $content = Get-Content $json | ConvertFrom-Json

             # Ensure both FQDN and short-host principals exist
            $content.Principals | Should -Contain 'host/web01.contoso.com@CONTOSO.COM'
            $content.Principals | Should -Contain 'host/web01@CONTOSO.COM'

            $content.PrincipalCount | Should -BeGreaterThan 1
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
}

Describe 'Encryption type filtering' {
    BeforeEach {
        Mock Get-ADReplAccount { New-MockAccount } -ModuleName STkrbKeytab
        Mock Get-ADComputer { [pscustomobject]@{ servicePrincipalName = @('host/web01.contoso.com'); 'msDS-KeyVersionNumber' = 7 } } -ModuleName STkrbKeytab
    }
    
    It 'filters to only requested encryption types' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -IncludeEtype 'AES256_CTS_HMAC_SHA1_96' -OutputPath $out -Force -Summary -Confirm:$false -RestrictAcl:$false | Out-Null
            $json = [IO.Path]::ChangeExtension($out,'json')
            $content = Get-Content $json | ConvertFrom-Json
            $content.EncryptionTypes | Should -Be @('AES256_CTS_HMAC_SHA1_96')
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
    
    It 'excludes unwanted encryption types' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -ExcludeEtype 'ARCFOUR_HMAC' -OutputPath $out -Force -Summary -Confirm:$false -RestrictAcl:$false | Out-Null
            $json = [IO.Path]::ChangeExtension($out,'json')
            $content = Get-Content $json | ConvertFrom-Json
            $content.EncryptionTypes | Should -Not -Contain 'ARCFOUR_HMAC'
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
    
    It 'warns when requested etype is not available' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            $warnings = @()
            New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -IncludeEtype 'UNKNOWN_ETYPE' -OutputPath $out -Force -WarningVariable warnings -Confirm:$false -RestrictAcl:$false | Out-Null
            ($warnings -join ' ') | Should -Match 'Unknown IncludeEtype'
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
}

Describe 'Advanced options' {
    BeforeEach {
        Mock Get-ADReplAccount { New-MockAccount } -ModuleName STkrbKeytab
        Mock Get-ADComputer { [pscustomobject]@{ servicePrincipalName = @('host/web01.contoso.com'); 'msDS-KeyVersionNumber' = 7 } } -ModuleName STkrbKeytab
    }
    
    It 'respects -WhatIf without creating files' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $out -WhatIf -Confirm:$false -RestrictAcl:$false | Out-Null
        Test-Path $out | Should -BeFalse
    }
    
    It 'creates JSON summary when requested' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $out -Force -Summary -Confirm:$false -RestrictAcl:$false | Out-Null
            $json = [IO.Path]::ChangeExtension($out,'json')
            Test-Path $json | Should -BeTrue
            $content = Get-Content $json | ConvertFrom-Json
            $content.Principals | Should -Not -BeNullOrEmpty
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
}

Describe 'Etype filtering' {
    BeforeEach {
        Mock Get-ADComputer { [pscustomobject]@{ servicePrincipalName = @('host/web01.contoso.com'); 'msDS-KeyVersionNumber' = 7 } } -ModuleName STkrbKeytab
        Mock Get-ADReplAccount { New-MockAccount -Etypes @{ 'AES256_CTS_HMAC_SHA1_96' = (1..32); 'AES128_CTS_HMAC_SHA1_96' = (1..16); 'ARCFOUR_HMAC' = (1..16) } } -ModuleName STkrbKeytab
    }
    It 'includes only requested etypes via -IncludeEtype' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            $obj = New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $out -Force -IncludeEtype 18 -PassThru -Confirm:$false -RestrictAcl:$false
            $obj.Etypes | Should -Be @(18)
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
    It 'excludes specified etypes via -ExcludeEtype' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            $obj = New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $out -Force -ExcludeEtype 18 -PassThru -Confirm:$false -RestrictAcl:$false
            $obj.Etypes | Should -Not -Contain 18
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
    It 'warns for missing requested etypes' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            $warnings = @()
            New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $out -Force -IncludeEtype 18,999 -WarningVariable warnings -WarningAction Continue -Confirm:$false -RestrictAcl:$false | Out-Null
            (($warnings -join ' ') -match 'Requested Etypes not present') | Should -BeTrue
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
}

Describe 'Kvno & summary' {
    BeforeEach {
        Mock Get-ADComputer { [pscustomobject]@{ servicePrincipalName = @('host/web01.contoso.com'); 'msDS-KeyVersionNumber' = 4 } } -ModuleName STkrbKeytab
        Mock Get-ADReplAccount { New-MockAccount -Kvno 4 } -ModuleName STkrbKeytab
    }
    It 'writes JSON summary including kvno when requested' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            $null = New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $out -Force -Summary -Confirm:$false -RestrictAcl:$false
            $jsonPath = [IO.Path]::ChangeExtension($out,'json')
            Test-Path $jsonPath | Should -BeTrue
            $j = Get-Content -Raw -LiteralPath $jsonPath | ConvertFrom-Json
            $j.Kvnos | Should -Contain 4
            $j.PrincipalCount | Should -BeGreaterThan 0
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
}

Describe 'Force & WhatIf behavior' {
    BeforeEach {
        Mock Get-ADComputer { [pscustomobject]@{ servicePrincipalName = @('host/web01.contoso.com'); 'msDS-KeyVersionNumber' = 7 } } -ModuleName STkrbKeytab
        Mock Get-ADReplAccount { New-MockAccount } -ModuleName STkrbKeytab
    }
    It 'does not create file when -WhatIf used' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $out -WhatIf -Confirm:$false -RestrictAcl:$false | Out-Null
            Test-Path $out | Should -BeFalse
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
    It 'throws if output exists without -Force' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            Set-Content -LiteralPath $out -Value 'dummy'
            { New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $out -Confirm:$false -RestrictAcl:$false } | Should -Throw "Output file '$out' already exists. Use -Force to overwrite."
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
}

Describe 'PassThru object contract' {
    BeforeEach {
        Mock Get-ADComputer { [pscustomobject]@{ servicePrincipalName = @('host/web01.contoso.com'); 'msDS-KeyVersionNumber' = 7 } } -ModuleName STkrbKeytab
        Mock Get-ADReplAccount { New-MockAccount } -ModuleName STkrbKeytab
    }
    It 'returns expected PassThru members' {
        $out = Join-Path $env:TEMP ("ktest_{0}.keytab" -f ([guid]::NewGuid().ToString('N')))
        try {
            $obj = New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $out -Force -PassThru -Confirm:$false -RestrictAcl:$false
            $obj | Get-Member -Name SamAccountName | Should -Not -BeNullOrEmpty
            $obj | Get-Member -Name OutputPath | Should -Not -BeNullOrEmpty
            $obj.Etypes | Should -Contain 18
            $obj.Kvnos | Should -Contain 7
        } finally {
            if (Test-Path $out) { Remove-Item $out -Force }
            $json = [IO.Path]::ChangeExtension($out,'json')
            if (Test-Path $json) { Remove-Item $json -Force }
        }
    }
}
