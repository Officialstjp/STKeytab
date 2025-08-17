<#
.SYNOPSIS
Unit tests for Compare-Convert-Keytab.ps1 functions.

#>

Set-StrictMode -Version Latest

$modulePath = Resolve-Path "$PSScriptRoot\..\STkrbKeytab.psm1"
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

Mock Get-RequiredModule { return $true } -ModuleName STkrbKeytab

Describe 'Compare-Keytab' {
    BeforeEach {
        Mock Get-ADReplAccount { 
            New-MockAccount 
        } -ModuleName STkrbKeytab

        Mock Get-ADComputer { 
            [pscustomobject]@{ 
                servicePrincipalName = @('host/web01.contoso.com','cifs/web01.contoso.com') 
                'msDS-KeyVersionNumber' = 7 
            } 
        } -ModuleName STkrbKeytab -ParameterFilter { ($Identity -like '*WEB01*') -or ($SamAccountName -like '*WEB01*') }

        # Fallback for second keytab files
        Mock Get-ADReplAccount { 
            New-MockAccount -Kvno 8 
        } -ModuleName STkrbKeytab 

        Mock Get-AdComputer {
            [pscustomobject]@{
                servicePrincipalName = @('host/sql02.contoso.com','cifs/sql02.contoso.com')
                'msDS-KeyVersionNumber' = 8
            }
        } -ModuleName STkrbKeytab
    }

    It 'Evaluates two identical keytab files as equal' {
        $outA = Join-Path $global:TestOutDir 'keytabA.keytab'
        $outB = Join-Path $global:TestOutDir 'keytabB.keytab'
        try {
            $keytabA = New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $outA -Force -Confirm:$false | Out-Null
            $keytabB = New-Keytab -SuppressWarnings -SamAccountName 'WEB01$' -Type Computer -Domain contoso.com -Server dc01.contoso.com -OutputPath $outB -Force -Confirm:$false | Out-Null

            $res = Compare-Keytab -ReferencePath $outA -CandidatePath $outB -IgnoreTimestamp -RevealKeys
            $res.Equal | Should -Be $true
        } finally {
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
        } finally {
            if (Test-Path $outA) { Remove-item $outA -Force}
            if (Test-Path $outB) { Remove-item $outB -Force}
        }
    }
}