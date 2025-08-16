# Unified front-door with parameter sets for better UX
function New-Keytab {
  <#
    .SYNOPSIS
    Create a keytab for an AD user, computer, or krbtgt using replication-safe extraction.

    .DESCRIPTION
    Front-door cmdlet that discovers principal type, selects safe encryption types by default (AES),
    and writes a deterministic keytab when -FixedTimestampUtc is provided. Supports summary JSON and
    pass-thru. Use -AcknowledgeRisk for krbtgt extractions.
  #>
  [CmdletBinding(DefaultParameterSetName='Auto', SupportsShouldProcess)]
  param(
    # Common
    [Parameter(Mandatory, ParameterSetName='Auto')]
    [Parameter(Mandatory, ParameterSetName='User')]
    [Parameter(Mandatory, ParameterSetName='Computer')]
    [Parameter(Mandatory, ParameterSetName='Krbtgt')]
    [string]$SamAccountName,

    [Parameter(ParameterSetName='Auto')]
    [ValidateSet('Auto','User','Computer','Krbtgt')]
    [string]$Type = 'Auto',

    [string]$Domain,
    [string]$Server,
    [pscredential]$Credential,
    [string]$EnvFile,
    [string]$OutputPath,
    [object[]]$IncludeEtype = @(18,17,23),
    [object[]]$ExcludeEtype,
    [switch]$RestrictAcl,
    [switch]$Force,
    [string]$JsonSummaryPath,
    [switch]$PassThru,
    [switch]$Summary,
    [string]$Justification,
    [switch]$IncludeOldKvno,
    [switch]$IncludeOlderKvno,
    [switch]$AcknowledgeRisk,
    [switch]$VerboseDiagnostics,
  [switch]$SuppressWarnings,
  [datetime]$FixedTimestampUtc,

    # Computer-only extras
    [Parameter(ParameterSetName='Auto')]
    [Parameter(ParameterSetName='Computer')]
    [switch]$IncludeShortHost,
    [Parameter(ParameterSetName='Auto')]
    [Parameter(ParameterSetName='Computer')]
    [string[]]$AdditionalSpn
  )
  #Get-RequiredModule -Name ActiveDirectory
  #Get-RequiredModule -Name DSInternals

  if (-not $Credential -and $EnvFile) { $Credential = Get-CredentialFromEnv -EnvFile $EnvFile }

  # Don't auto-populate FixedTimestampUtc; determinism only when explicitly provided.

  $type = $PSCmdlet.ParameterSetName
  $norm = $SamAccountName.ToUpperInvariant()
  if ($type -eq 'Auto') {
    if ($norm -eq 'KRBTGT') { $type = 'Krbtgt' }
    elseif ($SamAccountName -match '\$$') { $type = 'Computer' }
    else { $type = 'User' }
  }

  switch ($type) {
    'Krbtgt' {
      if (-not $AcknowledgeRisk) { throw "Extraction of krbtgt is High/Critical impact. Re-run with -AcknowledgeRisk after justification review." }
      if ($PSCmdlet.ShouldProcess('krbtgt',"Create krbtgt keytab (multi-KVNO possible)")) {
        if (-not $SuppressWarnings.IsPresent) { try { Write-SecurityWarning -RiskLevel 'krbtgt' -SamAccountName 'krbtgt' | Out-Null } catch {} }
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
        if (-not $SuppressWarnings.IsPresent) { try { Write-SecurityWarning -RiskLevel 'High' -SamAccountName ("{0}$" -f $compName) | Out-Null } catch {} }
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
        if (-not $SuppressWarnings.IsPresent) { try { Write-SecurityWarning -RiskLevel 'Medium' -SamAccountName $userName | Out-Null } catch {} }
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