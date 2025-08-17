<#
.SYNOPSIS
dedicated Unit tests for the Set-UserOnlyAcl helper

#>

Set-StrictMode -Version Latest

$modulePath = Resolve-Path "$PSScriptRoot\..\STkrbKeytab.psd1"
$moduleName = 'STkrbKeytab'
$TestOutDir = Join-Path $PSScriptRoot 'output'
Import-Module -Name "$modulePath" -Force -ErrorAction Stop

if (-not (Test-Path $TestOutDir)) { New-Item -ItemType Directory -Path $TestOutDir -Force | Out-Null }

Describe 'Set-UserOnlyAcl'{
    InModuleScope $moduleName {
        It 'sets only current user with FullControl and no inheritance on a file' {
            $tmp = New-Item -Type File -Path (Join-Path $TestOutDir ([guid]::NewGuid()))
            try {
                $acl = Set-UserOnlyAcl -Path $tmp.FullName
                $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

                $acl.AreAccessRulesProtected    | Should -BeTrue
                $acl.Sddl                       | Should -Be "O:$($sid)G:$($sid)D:PAI(A;;FA;;;$($sid))"
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