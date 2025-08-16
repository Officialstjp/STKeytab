@{
  RootModule        = 'STkrbKeytab.psm1'
  ModuleVersion     = '1.0.0'
  GUID              = 'c5a6e3a4-c5a6-7b8e-9a0b-f1d9e3f4e5b1'
  PowerShellVersion = '5.1'
  CompatiblePSEditions = @('Desktop','Core')
  Author            = 'Stefan Ploch'
  Description       = 'Kerberos keytab toolkit (replication + password S2K), writer/parser/merge, DPAPI.'
  FunctionsToExport = '*'
  CmdletsToExport   = @()
  AliasesToExport   = @()
  PrivateData = @{
    PSData = @{
      Tags        = @('Kerberos','Keytab','ActiveDirectory','Security')
      ProjectUri  = 'https://example.invalid/STCrypt'
      ReleaseNotes= 'Initial preview.'
    }
  }
}