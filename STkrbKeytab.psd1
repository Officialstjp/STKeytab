@{
    RootModule = 'STkrbKeytab.psm1'

    ModuleVersion = '1.0.0'
    GUID = 'c5a6e3a4-c5a6-7a8e-9a0b-f1d9e3f4e5b1'
    Author = 'Stefan Ploch'
    CompanyName = ''
    Copyright = '(c) 2025 Stefan Ploch. All rights reserved.'
    
    PowerShellVersion = '5.1'

    Description = 'Generate MIT keytabs for Windows computer accounts (read-only, DCSync-based) + helpers.'
    
    FunctionsToExport = @('New-Keytab', 'Test-Keytab', 'Merge-Keytab', 'Read-Keytab')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags = @('Kerberos', 'Keytab', 'DSInternals', 'STCrypt')
            ProjectUri = 'https://example.invalid/STCrypt'  # placeholder
            ReleaseNotes = 'Initial preview.'
        }
    }
}