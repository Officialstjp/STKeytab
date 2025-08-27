<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


# ---------------------------------------------------------------------- #
#
#                      Core Creation Orchestration
#
# ---------------------------------------------------------------------- #

function New-PrincipalKeytabInternal {
	<#
		.SYNOPSIS
		Internal orchestrator for creating a keytab for a given AD account.

		.DESCRIPTION
		Resolves domain context, replicates AD account secret material, selects encryption
		types, builds principal descriptors, and writes the keytab (with optional deterministic
		timestamps). Produces an optional JSON summary and can return a pass-thru object.
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$SamAccountName,
		[Parameter(Mandatory)][string]$Domain,
		[string]$Server,
		[pscredential]$Credential,
		[string]$OutputPath,
		[object[]]$IncludeEtype,
		[object[]]$ExcludeEtype,
		[psobject]$Policy,
		[switch]$RestrictAcl,
		[switch]$Force,
		[string]$JsonSummaryPath,
		[string]$Justification,
		[switch]$PassThru,
		[switch]$Summary,
		[switch]$IsKrbtgt,
		[switch]$IncludeOldKvno,
		[switch]$IncludeOlderKvno,
		[object[]]$PrincipalDescriptorsOverride,
		[switch]$VerboseDiagnostics,
		[switch]$SuppressWarnings,
		[datetime]$FixedTimestampUtc
	)

	if (-not $OutputPath) {
		$base = $SamAccountName.TrimEnd('$')
		$OutputPath = Join-Path (Get-Location) "$base.keytab"
	}
	if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
		throw "Output file '$OutputPath' already exists. Use -Force to overwrite."
	}
	$domainFQDN = Resolve-DomainContext -Domain $Domain
	$realm = $DomainFQDN.ToUpperInvariant()

	$acct = Get-ReplicatedAccount -SamAccountName $SamAccountName -DomainFQDN $domainFQDN -Server $Server -Credential $Credential
	$material = Get-KerberosKeyMaterialFromAccount -Account $acct -SamAccountName $SamAccountName -Server $Server -IsKrbtgt:$IsKrbtgt
	if ($VerboseDiagnostics) { $material.Diagnostics | ForEach-Object { Write-Verbose $_ } }

	# Filter Kvno sets if krbtgt and old kvnos when explicitly requested
	$keySets = @($material.KeySets | Sort-Object -Property Kvno -Descending)
	if ($IsKrbtgt) {
		$wanted = @()
		foreach ($keySet in $keySets) {
			if ($keySet.Kvno -eq $keySets[0].Kvno) { $wanted += $keySet; continue }
			if ($IncludeOldKvno   -and $keySet.Kvno -eq ($keySets[0].Kvno - 1)) { $wanted += $keySet; continue }
			if ($IncludeOlderKvno -and $keySet.Kvno -eq ($keySets[0].Kvno - 2)) { $wanted += $keySet; continue }
		}
		$keySets = $wanted
		if ($keySets.Count -eq 0) { throw "No key sets selected for krbtgt after KVNO filtering" }
	}

	$allEtypes = Select-CombinedEtypes -KeySets $keySets
	if ($PSBoundParameters.ContainsKey('Policy') -and $Policy) {
		$selection = Resolve-EtypeSelection -AvailableIds ([int[]]$allEtypes) -Policy $Policy
	} else {
		$selection = Resolve-EtypeSelection -AvailableIds ([int[]]$allEtypes) -Include $IncludeEtype -Exclude $ExcludeEtype
	}

	if ($selection.UnknownInclude.Count -gt 0) { Write-Warning "Unknown IncludeEtype: $($selection.UnknownInclude -join ', ')" }
	if ($selection.UnknownExclude.Count -gt 0) { Write-Warning "Unknown ExcludeEtype: $($selection.UnknownExclude -join ', ')" }
	if ($selection.Missing.Count -gt 0) { Write-Warning "Requested Etypes not present: $($selection.Missing -join ', ')" }
	if ($selection.Selected.Count -eq 0) { throw "No encryption types selected." }

	# Principal Descriptors
	$principalDescriptors = if ($PrincipalDescriptorsOverride) { @($PrincipalDescriptorsOverride) } else {
		if ($material.PrincipalType -eq 'User') {
			,(Get-UserPrincipalDescriptor -SamAccountName $SamAccountName -Realm $realm)
		} elseif ($material.PrincipalType -eq 'Computer') {
			# Build from SPNs for the computer; default includes FQDN forms
			@((Get-ComputerPrincipalDescriptors -ComputerName ($SamAccountName.TrimEnd('$')) -DomainFqdn $domainFQDN))
		} elseif ($IsKrbtgt) {
			,(Get-KrbtgtPrincipalDescriptor -Realm $realm)
		} else {
			throw "Unable to build principals for type '$($material.PrincipalType)'."
		}
	}

	$risk = $material.RiskLevel
	if ($IsKrbtgt -and -not $PSBoundParameters.ContainsKey('IncludeOldKvno')) {
		Write-Verbose "krbtgt: only current KVNO included (use -IncludeOldKvno / -IncludeOlderKvno to extend)."
	}
	if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) {
		$finalPath = New-KeytabFile -Path $OutputPath -PrincipalDescriptors $principalDescriptors -KeySets $keySets -EtypeFilter $selection.Selected -RestrictAcl:$RestrictAcl -FixedTimestampUtc $FixedTimestampUtc
	} else {
		$finalPath = New-KeytabFile -Path $OutputPath -PrincipalDescriptors $principalDescriptors -KeySets $keySets -EtypeFilter $selection.Selected -RestrictAcl:$RestrictAcl
	}

	Write-Host "Keytab written: $finalPath"
	# Summary
	if (-not $JsonSummaryPath) { $JsonSummaryPath = [IO.Path]::ChangeExtension($finalPath,'.json') }
	if ($Summary -or $PassThru) {
		$etypeNames = @($selection.Selected | ForEach-Object { Get-EtypeNameFromId $_ })
		$kvnos = @($keySets | Select-Object -ExpandProperty Kvno | Sort-Object -Unique)
		$generatedAt = if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) { $FixedTimestampUtc.ToUniversalTime().ToString('o') } else { (Get-Date).ToUniversalTime().ToString('o') }
		$summaryObj = [ordered]@{
			SamAccountName   = $SamAccountName
			PrincipalType    = $material.PrincipalType
			DomainFqdn       = $domainFQDN
			Realm            = $realm
			RiskLevel        = $risk
			Kvnos            = $kvnos
			Etypes           = $selection.Selected
			EncryptionTypes  = $etypeNames
			PrincipalCount   = $principalDescriptors.Count
			Principals       = @($principalDescriptors | ForEach-Object { $_.Display })
			OutputPath       = (Resolve-Path -LiteralPath $finalPath).Path
			GeneratedAtUtc   = $generatedAt
			Justification    = $Justification
			IncludeOldKvno   = [bool]$IncludeOldKvno
			IncludeOlderKvno = [bool]$IncludeOlderKvno
			HighImpact       = ($risk -in @('High','Critical'))
		}
		$summaryObj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonSummaryPath -Encoding UTF8
		if ($RestrictAcl) { Set-UserOnlyAcl -Path $JsonSummaryPath }
	}

	if ($PassThru) {
		[pscustomobject]@{
			SamAccountName  = $SamAccountName
			PrincipalType   = $material.PrincipalType
			RiskLevel       = $risk
			OutputPath      = $finalPath
			Etypes          = $selection.Selected
			Kvnos           = @($keySets.Kvno)
			PrincipalCount  = $principalDescriptors.Count
			SummaryPath     = $JsonSummaryPath
		}
	}
}

#endregion
