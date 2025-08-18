<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


@{
  RootModule        = 'STKeytab.psm1'
  ModuleVersion     = '1.2.0'
  GUID              = 'c5a6e3a4-c5a6-7b8e-9a0b-f1d9e3f4e5b1'
  PowerShellVersion = '5.1'
  CompatiblePSEditions = @('Desktop','Core')
  Author            = 'Stefan Ploch'
  Description       = 'Kerberos keytab toolkit for AD: replication-safe extraction, password S2K (AES), robust writer/parser, compare/JSON, and DPAPI protect/unprotect.'
  FunctionsToExport = @(
    'Compare-Keytab',
    'ConvertFrom-KeytabJson',
    'ConvertTo-KeytabJson',
    'Merge-Keytab',
    'New-Keytab',
    'New-KeytabFromPassword',
    'Protect-Keytab',
    'Read-Keytab',
    'Test-Keytab',
    'Unprotect-Keytab'
  )
  CmdletsToExport   = @()
  AliasesToExport   = @()
  PrivateData = @{
    PSData = @{
      Tags        = @('Kerberos','Keytab','ActiveDirectory','Security','DPAPI','AES')
      ProjectUri  = 'https://github.com/Officialstjp/STKeytab'
      LicenseUri  = 'https://github.com/Officialstjp/STKeytab/blob/main/LICENSE'
      ReleaseNotes= 'v1.2.0: Added password-based keytab generation (AES PBKDF2), Compare-Keytab and ConvertTo/From-KeytabJson; parser hardening; DPAPI polish; deterministic outputs via -FixedTimestampUtc.'
    }
  }
}
