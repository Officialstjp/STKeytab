<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


@{
    RootModule           = 'STKeytab.psm1'
    ModuleVersion        = '0.6.1'
    GUID                 = 'c5a6e3a4-c5a6-7b8e-9a0b-f1d9e3f4e5b1'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    Author               = 'Stefan Ploch'
    Copyright            = '(c) 2025 Stefan Ploch. License: Apache 2.0.'
    Description          = 'Kerberos keytab toolkit for AD: replication-safe extraction, password S2K (AES), robust writer/parser, compare/JSON, and DPAPI protect/unprotect.'
    FunctionsToExport = @(
        'Compare-Keytab',
        'ConvertFrom-KeytabJson',
        'ConvertTo-KeytabJson',
        'Merge-Keytab',
        'New-Keytab',
        'New-KeytabFromPassword',
        'Protect-Keytab',
        'Read-Keytab',
        'Reset-AccountPasswordWithKeytab',
        'Set-AccountSpn',
        'Test-Keytab',
        'Unprotect-Keytab'
)
    CmdletsToExport   = @()
    AliasesToExport   = @()

    # HelpInfoURI for Update-Help support
    # Uses stable 'help' release tag - assets are updated on each release
    HelpInfoURI = 'https://github.com/Officialstjp/STKeytab/releases/download/help/'

    PrivateData = @{
        PSData = @{
            Tags         = @('Kerberos', 'Keytab', 'ActiveDirectory', 'Security', 'DPAPI', 'AES', 'MIT', 'RFC8009')
            ProjectUri   = 'https://github.com/Officialstjp/STKeytab'
            LicenseUri   = 'https://github.com/Officialstjp/STKeytab/blob/main/LICENSE'
            ReleaseNotes = 'See CHANGELOG.md for full release notes.'
            # IconUri    = 'https://raw.githubusercontent.com/Officialstjp/STKeytab/main/icon.png'
        }
    }
}
