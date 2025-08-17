<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function New-Keytab {
    <#
        .SYNOPSIS
        Create a keytab for an AD user, computer, or krbtgt using replication-safe extraction.

        .DESCRIPTION
        Front-door cmdlet that discovers principal type, selects safe encryption types by default (AES),
        and writes a deterministic keytab when -FixedTimestampUtc is provided. Supports summary JSON and
        pass-thru. Use -AcknowledgeRisk for krbtgt extractions.

        .PARAMETER SamAccountName
        The account's sAMAccountName (user, computer$, or krbtgt) (Pos 1).

        .PARAMETER Type
        Principal type. Auto infers from name; User, Computer, or Krbtgt can be forced.

        .PARAMETER Domain
        Domain NetBIOS or FQDN. When omitted, attempts discovery (Pos 2).

        .PARAMETER IncludeEtype
        Encryption type IDs to include. Default: 18,17,23 (AES-256, AES-128, RC4 opt-in) (Pos 3).

        .PARAMETER ExcludeEtype
        Encryption type IDs to exclude. (Pos 4).

        .PARAMETER OutputPath
        Path to write the keytab file (Pos 5).

        .PARAMETER JsonSummaryPath
        Optional path to write a JSON summary. Defaults next to OutputPath. (Pos 6)

        .PARAMETER Server
        Domain Controller to target for replication (optional) (Pos 7).

        .PARAMETER Justification
        Free-text justification string for auditing high-risk operations (Pos 8).

        .PARAMETER Credential
        Alternate credentials to access AD/replication (Pos 9).

        .PARAMETER EnvFile
        Optional .env file to load credentials from (Pos 10).

        .PARAMETER RestrictAcl
        Apply a user-only ACL to outputs.

        .PARAMETER Force
        Overwrite existing OutputPath.

        .PARAMETER PassThru
        Return a small object summary in addition to writing files.

        .PARAMETER Summary
        Write a JSON summary file.

        .PARAMETER IncludeOldKvno
        Include previous KVNO keys when available.

        .PARAMETER IncludeOlderKvno
        Include older KVNO keys (krbtgt scenarios).

        .PARAMETER AcknowledgeRisk
        Required for krbtgt extraction.

        .PARAMETER VerboseDiagnostics
        Emit additional diagnostics during extraction.

        .PARAMETER SuppressWarnings
        Suppress risk warnings.

        .PARAMETER FixedTimestampUtc
        Use a fixed timestamp for deterministic output.

        .PARAMETER IncludeShortHost
        For computer accounts, include HOST/shortname SPN.

        .PARAMETER AdditionalSpn
        Additional SPNs (service/host) to include for computer accounts.

        .INPUTS
        System.String (SamAccountName) via property name.

        .OUTPUTS
        System.String (OutputPath) or summary object when -PassThru.

        .EXAMPLE
        New-Keytab -SamAccountName web01$ -Type Computer -OutputPath .\web01.keytab -IncludeShortHost -Summary
        Create a computer keytab including short HOST/ SPNs and write a summary JSON.

        .EXAMPLE
        New-Keytab -SamAccountName user1 -IncludeEtype 18,17 -ExcludeEtype 23 -OutputPath .\user1.keytab -FixedTimestampUtc (Get-Date '2020-01-01Z')
        Create a deterministic user keytab with AES types only.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # Common
        [Parameter(Position=0, Mandatory, ValueFromPipelineByPropertyName=$true)]
        [string]$SamAccountName,

        [ValidateSet('Auto','User','Computer','Krbtgt')]
        [string]$Type = 'Auto',

        [Parameter(Position=1, ValueFromPipelineByPropertyName)][string]$Domain,
        [Parameter(Position=2, ValueFromPipelineByPropertyName)][object[]]$IncludeEtype = @(18,17,23),
        [Parameter(Position=3, ValueFromPipelineByPropertyName)][object[]]$ExcludeEtype,

        [Parameter(Position=4, ValueFromPipelineByPropertyName)][string]$OutputPath,
        [Parameter(Position=5, ValueFromPipelineByPropertyName)][string]$JsonSummaryPath,
        [Parameter(Position=6, ValueFromPipelineByPropertyName)][string]$Server,
        [Parameter(Position=7, ValueFromPipelineByPropertyName)][string]$Justification,
        [Parameter(Position=8, ValueFromPipelineByPropertyName)][pscredential]$Credential,
        [Parameter(Position=9, ValueFromPipelineByPropertyName)][string]$EnvFile,

        [switch]$RestrictAcl,
        [switch]$Force,
        [switch]$PassThru,
        [switch]$Summary,
        [switch]$IncludeOldKvno,
        [switch]$IncludeOlderKvno,
        [switch]$AcknowledgeRisk,
        [switch]$VerboseDiagnostics,
        [switch]$SuppressWarnings,

        [datetime]$FixedTimestampUtc,

        # Computer-only extras
        [switch]$IncludeShortHost,
        [string[]]$AdditionalSpn
    )

    begin {
        Get-RequiredModule -Name ActiveDirectory
        Get-RequiredModule -Name DSInternals

        if (-not $Credential -and $EnvFile) { $Credential = Get-CredentialFromEnv -EnvFile $EnvFile }

        $type = $Type
        if ($type -eq 'Auto') {
        $norm = $SamAccountName.ToUpperInvariant()
        if ($norm -eq 'KRBTGT') { $type = 'Krbtgt' }
        elseif ($SamAccountName -match '\$$') { $type = 'Computer' }
        else { $type = 'User' }
        }
    }
    process {
        switch ($type) {
            'Krbtgt' {
                if (-not $AcknowledgeRisk) { throw "Extraction of krbtgt is High/Critical impact. Re-run with -AcknowledgeRisk after justification review." }
                if ($PSCmdlet.ShouldProcess('krbtgt',"Create krbtgt keytab (multi-KVNO possible)")) {
                    if (-not $SuppressWarnings.IsPresent) { Write-SecurityWarning 'krbtgt' -SamAccountName 'krbtgt' | Out-Null }
                $extra = @{}
                if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) { $extra.FixedTimestampUtc = $FixedTimestampUtc }
                return New-PrincipalKeytabInternal -SamAccountName 'krbtgt' -Domain $Domain -Server $Server -Credential $Credential `
                                                        -OutputPath $OutputPath -IncludeEtype $IncludeEtype -ExcludeEtype $ExcludeEtype -IsKrbtgt `
                                                        -IncludeOldKvno:$IncludeOldKvno -IncludeOlderKvno:$IncludeOlderKvno -RestrictAcl:$RestrictAcl -Force:$Force `
                                                        -JsonSummaryPath $JsonSummaryPath -PassThru:$PassThru -Summary:$Summary -Justification $Justification `
                                                        -VerboseDiagnostics:$VerboseDiagnostics @extra
                }
            }
            'Computer' {
                $domainFqdn = Resolve-DomainContext -Domain $Domain
                $realm = $domainFqdn.ToUpperInvariant()
                $compName = $SamAccountName.TrimEnd('$')

                $desc = Get-ComputerPrincipalDescriptors -ComputerName $compName -DomainFqdn $domainFqdn -IncludeShortHost:$IncludeShortHost
                if ($AdditionalSpn) {
                    foreach ($p in $AdditionalSpn) {
                        if ($p -notmatch '/') { continue }
                        $parts = $p.Split('/',2)
                        $svc = $parts[0]; $ihost = $parts[1]
                        $desc += ,(New-PrincipalDescriptor -Components @($svc.ToLowerInvariant(),$ihost.ToLowerInvariant()) -Realm $realm -NameType $script:NameTypes.KRB_NT_SRV_HST -Tags @('Explicit'))
                    }
                }
                if ($desc.Count -eq 0) { throw "No SPN principals resolved for computer '$compName'." }

                if ($PSCmdlet.ShouldProcess($compName,"Create computer keytab")) {
                    if (-not $SuppressWarnings.IsPresent) { Write-SecurityWarning -RiskLevel 'High' -SamAccountName ("{0}$" -f $compName) | Out-Null }
                    $extra = @{}
                    if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) { $extra.FixedTimestampUtc = $FixedTimestampUtc }
                    return New-PrincipalKeytabInternal -SamAccountName ("{0}$" -f $compName) -Domain $domainFqdn -Server $Server -Credential $Credential `
                                                    -OutputPath $OutputPath -IncludeEtype $IncludeEtype -ExcludeEtype $ExcludeEtype -RestrictAcl:$RestrictAcl -Force:$Force `
                                                    -JsonSummaryPath $JsonSummaryPath -PassThru:$PassThru -Summary:$Summary -Justification $Justification `
                                                    -PrincipalDescriptorsOverride $desc -VerboseDiagnostics:$VerboseDiagnostics @extra
                }
            }
            'User' {
                $userName = $SamAccountName
                if ($PSCmdlet.ShouldProcess($userName,"Create user keytab")) {
                    if (-not $SuppressWarnings.IsPresent) { Write-SecurityWarning -RiskLevel 'Medium' -SamAccountName $userName | Out-Null }
                    $extra = @{}
                    if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) { $extra.FixedTimestampUtc = $FixedTimestampUtc }
                    return New-PrincipalKeytabInternal -SamAccountName $userName -Domain $Domain -Server $Server -Credential $Credential `
                                                    -OutputPath $OutputPath -IncludeEtype $IncludeEtype -ExcludeEtype $ExcludeEtype `
                                                    -RestrictAcl:$RestrictAcl -Force:$Force -JsonSummaryPath $JsonSummaryPath -PassThru:$PassThru `
                                                    -Summary:$Summary -Justification $Justification -VerboseDiagnostics:$VerboseDiagnostics @extra
                }
            }
        }
    }
}
