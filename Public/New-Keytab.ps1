<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function New-Keytab {
    <#
    .SYNOPSIS
    Create a keytab for an AD user, computer, or krbtgt using replication-safe key extraction.

    .DESCRIPTION
    Front-door cmdlet that discovers principal type and extracts Kerberos keys via directory replication.
    Defaults to AES-only encryption types. Deterministic output is available when -FixedTimestampUtc is
    provided. Supports JSON summaries and PassThru. krbtgt extractions are gated and require -AcknowledgeRisk
    with a documented justification.

        .PARAMETER SamAccountName
        The account's sAMAccountName (user, computer$, or krbtgt).

        .PARAMETER Type
    Principal type. Auto infers from name; User or Computer can be forced. krbtgt is detected automatically.

        .PARAMETER Domain
        Domain NetBIOS or FQDN. When omitted, attempts discovery.

        .PARAMETER IncludeEtype
        Encryption type IDs to include. Default: 18,17 (AES-256, AES-128). RC4 (23) is not included by default and
        must be explicitly opted-in when legacy compatibility is required.

        .PARAMETER ExcludeEtype
        Encryption type IDs to exclude.

        .PARAMETER IncludeLegacyRC4
        Includes the RC4 encryption type (23).

        .PARAMETER OutputPath
        Path to write the keytab file.

        .PARAMETER Server
        Domain Controller to target for replication (optional).

        .PARAMETER Justification
        Free-text justification string for auditing high-risk operations.

        .PARAMETER Credential
        Alternate credentials to access AD/replication.

        .PARAMETER EnvFile
        Optional .env file to load credentials from.

        .PARAMETER RestrictAcl
        Apply a user-only ACL to outputs.

        .PARAMETER Force
        Overwrite existing OutputPath.

        .PARAMETER PassThru
        Return a small object summary in addition to writing files.

        .PARAMETER Summary
        Write a JSON summary file.

        .PARAMETER SummaryPath
        Optional path to write a JSON summary. Defaults next to OutputPath when summaries are requested.

        .PARAMETER IncludeOldKvno
        Include previous KVNO keys when available.

        .PARAMETER IncludeOlderKvno
        Include older KVNO keys (krbtgt scenarios).


        .PARAMETER VerboseDiagnostics
        Emit additional diagnostics during extraction.

        .PARAMETER SuppressWarnings
        Suppress risk warnings.

        .PARAMETER FixedTimestampUtc
        Use a fixed timestamp for deterministic output. Determinism is opt-in and not auto-populated.

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
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param(
        # Common
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SamAccountName,

        [ValidateSet('Auto','User','Computer')]
        [string]$Type = 'Auto',

        [Parameter(ValueFromPipelineByPropertyName)][string]$Domain,
        [Parameter(ValueFromPipelineByPropertyName)][object[]]$IncludeEtype = @(18,17),
        [Parameter(ValueFromPipelineByPropertyName)][object[]]$ExcludeEtype,

        [Parameter(ValueFromPipelineByPropertyName)][ValidateNotNullOrEmpty()][string]$OutputPath,
        [Parameter(ValueFromPipelineByPropertyName)][Alias('JsonSummaryPath')][string]$SummaryPath,
        [Parameter(ValueFromPipelineByPropertyName)][string]$Server,
        [Parameter(ValueFromPipelineByPropertyName)][string]$Justification,
        [Parameter(ValueFromPipelineByPropertyName)][pscredential]$Credential,
        [Parameter(ValueFromPipelineByPropertyName)][string]$EnvFile,

        [switch]$RestrictAcl,
        [switch]$Force,
        [switch]$PassThru,
        [switch]$Summary,
        [switch]$AcknowledgeRisk,
        [switch]$VerboseDiagnostics,
        [switch]$SuppressWarnings,
        [datetime]$FixedTimestampUtc,

        # Computer-only extras
        [switch]$IncludeShortHost,
        [string[]]$AdditionalSpn,

        # Quick settings
        [switch]$IncludeLegacyRC4,
        [switch]$AESOnly,
        [switch]$AllowDeadCiphers
    )

    begin {
        # Firstly, check if the parameters specified make sense
        if (($AESOnly.IsPresent) -and ($IncludeLegacyRC4.IsPresent -or $AllowDeadCiphers.IsPresent)) {
            throw "-AESOnly cannot be defined with -IncludeLegacyRC4 or -AllowDeadCiphers."
        }

        # Then, compose policy intent for replication path; orchestration can use it to resolve final etypes (BigBrother)
        try {
            $script:__nk_policy = Get-PolicyIntent -IncludeEtype $IncludeEtype -ExcludeEtype $ExcludeEtype -AESOnly:$AESOnly `
                                                  -IncludeLegacyRC4:$IncludeLegacyRC4 -AllowDeadCiphers:$AllowDeadCiphers -PathKind 'Replication'
        } catch {
            Write-Verbose ("Policy composition failed: {0}" -f $_.Exception.Message)
        }

        # Surface unknown include/exclude early for better UX (availability warnings are handled later)
        if ($script:__nk_policy) {
            if ($script:__nk_policy.UnknownInclude -and $script:__nk_policy.UnknownInclude.Count -gt 0) {
                Write-Warning ("Unknown IncludeEtype: {0}" -f ($script:__nk_policy.UnknownInclude -join ', '))
            }
            if ($script:__nk_policy.UnknownExclude -and $script:__nk_policy.UnknownExclude.Count -gt 0) {
                Write-Warning ("Unknown ExcludeEtype: {0}" -f ($script:__nk_policy.UnknownExclude -join ', '))
            }
        }

        if ($Server) {
            $dcCmd = Get-Command -Name Get-ADDomainController -ErrorAction SilentlyContinue
            if ($dcCmd) {
                try {
                    $dc = Get-ADDomainController -Server $Server -ErrorAction Stop
                    if ($dc.IsReadOnly) { Write-Warning ("Target DC '{0}' is read-only (RODC); replication-based extraction may fail." -f $Server) }
                } catch {
                    if (-not $SuppressWarnings.IsPresent) { Write-Warning ("Unable to query domain controller '{0}': {1}" -f $Server, $_.Exception.Message) }
                }
            } else {
                Write-Verbose ("-Server specified ('{0}'); ensure it is a writable DC." -f $Server)
            }
        }

        if ($OutputPath) {
            $out = Resolve-PathUniversal -Path $OutputPath -Purpose Output
        } else {
            $out = Resolve-OutputPath -Directory (Get-Location).Path -BaseName ($SamAccountName.TrimEnd('$')) -Extension '.keytab' -CreateDirectory
        }

        $type = $Type
        if ($type -eq 'Auto') {
            $norm = $SamAccountName.ToUpperInvariant()
            if ($SamAccountName -match '\$$') { $type = 'Computer' } else { $type = 'User' }
        }
    }
    process {
        switch ($type) {
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
                    $extra = @{}
                    if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) { $extra.FixedTimestampUtc = $FixedTimestampUtc }
                    $inc = ($script:__nk_policy ? $script:__nk_policy.IncludeIds : $IncludeEtype)
                    $exc = ($script:__nk_policy ? $script:__nk_policy.ExcludeIds : $ExcludeEtype)
                    $result = New-PrincipalKeytabInternal -SamAccountName ("{0}$" -f $compName) -Domain $domainFqdn -Server $Server -Credential $Credential `
                                                    -OutputPath $out -IncludeEtype $inc -ExcludeEtype $exc -Policy $script:__nk_policy -RestrictAcl:$RestrictAcl -Force:$Force `
                                                    -JsonSummaryPath $SummaryPath -PassThru:$PassThru -Summary:$Summary -Justification $Justification -AcknowledgeRisk:$AcknowledgeRisk `
                                                    -PrincipalDescriptorsOverride $desc -VerboseDiagnostics:$VerboseDiagnostics @extra
                    return $result
                }
            }
            'User' {
                $userName = $SamAccountName
                if ($PSCmdlet.ShouldProcess($userName,"Create user keytab")) {
                    $extra = @{}
                    if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) { $extra.FixedTimestampUtc = $FixedTimestampUtc }
                    $inc = ($script:__nk_policy ? $script:__nk_policy.IncludeIds : $IncludeEtype)
                    $exc = ($script:__nk_policy ? $script:__nk_policy.ExcludeIds : $ExcludeEtype)
                    $result = New-PrincipalKeytabInternal -SamAccountName $userName -Domain $Domain -Server $Server -Credential $Credential `
                                                    -OutputPath $out -IncludeEtype $inc -ExcludeEtype $exc -Policy $script:__nk_policy `
                                                    -RestrictAcl:$RestrictAcl -Force:$Force -JsonSummaryPath $SummaryPath -PassThru:$PassThru -AcknowledgeRisk:$AcknowledgeRisk `
                                                    -Summary:$Summary -Justification $Justification -VerboseDiagnostics:$VerboseDiagnostics @extra
                    return $result
                }
            }
        }
    }
}
