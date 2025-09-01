<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


<#
.SYNOPSIS
Big Brother Enforcer - security related policies and logic for the module.

.DESCRIPTION
This module provides cmdlets for managing and enforcing security related policies and logic
in the Module.
#>


#region Etype Handling
# -------------------------------------------------------------------------
#
#                              Etype Handling
#
# -------------------------------------------------------------------------


$script:etypeMap = [ordered]@{
    DSA_SHA1_CMS                = 9
    MD5_RSA_CMS                 = 10
    SHA1_RSA_CMS                = 11
    RC2_CBC_ENV                 = 12
    RSA_ENV                     = 13
    RSA_ES_OAEP_ENV             = 14
    DES3_CBC_ENV                = 15
    DES3_CBC_SHA1               = 16
    AES128_CTS_HMAC_SHA1_96     = 17
    AES256_CTS_HMAC_SHA1_96     = 18
    AES128_CTS_HMAC_SHA256_128  = 19
    AES256_CTS_HMAC_SHA384_192  = 20
    ARCFOUR_HMAC                = 23
    ARCFOUR_HMAC_EXP            = 24
    CAMELLIA128_CTS_CMAC        = 25
    CAMELLIA256_CTS_CMAC        = 26
    UNKNOWN                     = 511
}
$script:ReverseEtypeMap = @{}
foreach ($kv in $script:etypeMap.GetEnumerator()) { $script:ReverseEtypeMap[[int]$kv.Value] = $kv.Key }

$script:SupportedEtypes = @(17,18,19,20,23)

# Categorization helpers
$script:AesEtypes       = @(17,18)      # Traditional AES-SHA1 (compatible)
$script:ModernAesEtypes = @(17,18,19,20) # All AES including SHA2 (modern)
$script:AllAesEtypes    = @(17,18,19,20) # Alias for convenience
$script:DeadEtypes = @(1,2,3,5,6,7,8,9,10,11,12,13,14,15,16,21,22,24,25,26,27,28,29,30)

function Get-EtypeIdFromInput {
    <#
        .SYNOPSIS
        Normalize an encryption type input (name or id) to an integer id.
    #>
    param(
        [Parameter(Mandatory)][object]$Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [int]) { return [int]$Value }
    if ($Value -is [string]) {
        $s = $Value.Trim()

        [int]$tmp = 0
        if ([int]::TryParse($s,[ref]$tmp)) {
        return $tmp
        }

        if ($script:etypeMap.Contains($s)) {
        return [int]$script:etypeMap[$s]
        }

        return $null
    }
    try {
        return [int]$Value
    } catch {
        return $null
    }
}

function Get-EtypeNameFromId {
    <#
        .SYNOPSIS
        Get the Kerberos encryption type name for an integer id.
    #>

    param(
        [Parameter(Mandatory)][int]$Id
    )
    if ($script:ReverseEtypeMap.ContainsKey($Id)) { return $script:ReverseEtypeMap[$Id] }
    return "ETYPE_$Id"
}

function Get-DeadEtypes {
    <#
        .SYNOPSIS
        Return the list of etype IDs considered obsolete/broken ("dead").
    #>
    [OutputType([int[]])]
    param()
    return $script:DeadEtypes
}

function Resolve-EtypeSelection {
    <#
        .SYNOPSIS
        Compute final etype selection from available, include, and exclude lists.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int[]]$AvailableIds,
        [object[]]$Include,
        [object[]]$Exclude,
        [psobject]$Policy
    )

    $available = [System.Collections.Generic.HashSet[int]]::new()
    $AvailableIds | Foreach-Object { [void]$available.Add($_) }

    $included          = New-Object System.Collections.Generic.List[int]
    $missing           = New-Object System.Collections.Generic.List[int]
    $unknownIncluded   = New-Object System.Collections.Generic.List[object]
    $excluded          = New-Object System.Collections.Generic.List[int]
    $unknownExcluded   = New-Object System.Collections.Generic.List[object]

    if ($PSBoundParameters.ContainsKey('Policy') -and $Policy) {
        # Use pre-normalized ids; unknowns carried from policy
        if ($Policy.IncludeIds) {
            foreach ($id in $Policy.IncludeIds) {
                if ($available.Contains([int]$id)) { $included.Add([int]$id) } else { $missing.Add([int]$id) }
            }
        }
        if ($Policy.ExcludeIds) {
            foreach ($id in $Policy.ExcludeIds) { $excluded.Add([int]$id) }
        }
        foreach ($u in $Policy.UnknownInclude) { $unknownIncluded.Add($u) }
        foreach ($u in $Policy.UnknownExclude) { $unknownExcluded.Add($u) }
    } else {
        if ($Include) {
            foreach ($raw in $Include) {
                $id = Get-EtypeIdFromInput $raw
                if ($null -ne $id) {
                    if ($available.Contains($id)) { $included.Add($id) } else { $missing.Add($id) }
                } else { $unknownIncluded.Add($raw) }
            }
        }

        if ($Exclude) {
            foreach ($raw in $Exclude) {
                $id = Get-EtypeIdFromInput $raw
                if ($null -ne $id) { $excluded.Add($id) } else { $unknownExcluded.Add($raw) }
            }
        }
    }

    $selected = if ($included.Count -gt 0) { $included } else { $available }

    if ($excluded.Count -gt 0) {
        $excludedSet = [System.Collections.Generic.HashSet[int]]::new()
        $excluded | ForEach-Object { [void]$excludedSet.Add($_) }
        $selected = @($selected | Where-Object { -not $excludedSet.Contains($_) })
    }

    [pscustomobject]@{
        Selected       = @([int[]]$selected | Sort-Object -Unique)
        Missing        = $missing
        UnknownInclude = $unknownIncluded
        UnknownExclude = $unknownExcluded
    }
}

function Get-PolicyIntent {
    <#
        .SYNOPSIS
        Compose an etype policy intent from user parameters and path kind.
    #>
    [CmdletBinding()]
    param(
        [object[]]$IncludeEtype,
        [object[]]$ExcludeEtype,
        [switch]$AESOnly,
        [switch]$IncludeLegacyRC4,
        [switch]$AllowDeadCiphers,
        [ValidateSet('Password','Replication')][string]$PathKind = 'Replication'
    )

    # Normalize includes/excludes
    $incNorm = @()
    if ($null -ne $IncludeEtype) { $incNorm = @($IncludeEtype) }
    $excNorm = @()
    if ($null -ne $ExcludeEtype) { $excNorm = @($ExcludeEtype) }

    # Apply quick flags
    if ($AESOnly.IsPresent) { $incNorm = $script:AesEtypes }
    if ($IncludeLegacyRC4.IsPresent -and ($incNorm -notcontains 23)) { $incNorm += 23 }
    if (-not $AllowDeadCiphers.IsPresent) { $excNorm += $script:DeadEtypes }

    # Defaults if user did not specify include and AESOnly not set explicitly
    if (-not $PSBoundParameters.ContainsKey('IncludeEtype') -and -not $AESOnly.IsPresent) {
        $incNorm = $script:AesEtypes
    }

    # Materialize to int after name resolution (keep raw for unknown reporting later)
    $includeIds = @()
    $unknownInc = New-Object System.Collections.Generic.List[object]
    foreach ($i in $incNorm) {
        $id = Get-EtypeIdFromInput $i
        if ($null -ne $id) { $includeIds += [int]$id } else { $unknownInc.Add($i) }
    }

    $excludeIds = @()
    $unknownExc = New-Object System.Collections.Generic.List[object]
    foreach ($e in $excNorm) {
        $id = Get-EtypeIdFromInput $e
        if ($null -ne $id) { $excludeIds += [int]$id } else { $unknownExc.Add($e) }
    }

    [pscustomobject]@{
        PathKind        = $PathKind
        AESOnly         = [bool]$AESOnly
        IncludeLegacyRC4= [bool]$IncludeLegacyRC4
        AllowDeadCiphers= [bool]$AllowDeadCiphers
        IncludeIds      = @($includeIds)
        ExcludeIds      = @($excludeIds)
        UnknownInclude  = $unknownInc
        UnknownExclude  = $unknownExc
    }
}

function Validate-PasswordPathCompatibility {
    <#
        .SYNOPSIS
        Ensure password S2K path only requests AES etypes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Policy,
        [switch]$SuppressWarnings
    )

    if ($Policy.PathKind -ne 'Password') { return }

    # Any non-AES in IncludeIds is invalid for S2K at present
    $nonAes = @($Policy.IncludeIds | Where-Object { $_ -notin $script:AllAesEtypes })
    if ($nonAes.Count -gt 0 -or $Policy.IncludeLegacyRC4 -or $Policy.AllowDeadCiphers) {
        try {
            Write-SecurityWarning -RiskLevel 'High' -SamAccountName 'Password-S2K' -Suppress:$SuppressWarnings.IsPresent | Out-Null
        } catch {
            Write-Error "Failed to write security warning: $_"
        }
        $names = ($nonAes | ForEach-Object { Get-EtypeNameFromId $_ }) -join ', '
        $hint  = 'Password derivation supports AES only (17,18,19,20).' +
                 ' Remove legacy etypes or use the replication path if you must include RC4/DES.'
        if ([string]::IsNullOrWhiteSpace($names)) { throw "EtypeUnsupportedForPath: Non-AES requested. $hint" }
        throw "EtypeUnsupportedForPath: Non-AES requested (${names}). $hint"
    }
}

function Select-CombinedEtypes {
    <#
        .SYNOPSIS
        Return the set of unique etype ids present across key sets.
    #>
    param(
        [object[]]$KeySets
    )
    $set = New-Object System.Collections.Generic.HashSet[int]
    foreach ($keySet in $keySets) {
        foreach ($key in $keySet.Keys.Keys) { [void]$set.Add([int]$key) }
    }
    @($set)
}

#endregion


#region Acl Helpers
# ---------------------------------------------------------------------- #
#
#                           Acl Helpers
#
# ---------------------------------------------------------------------- #


function Set-UserOnlyAcl {
    <#
        .SYNOPSIS
        Set a user-only ACL on a file or directory.

        .DESCRIPTION
        This function sets the access control list (ACL) of a file or directory to allow only the current user full control.
        The current owner will also be set Owner of the file.
        Inheritance is dropped unless explicitly kept.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName','LiteralPath')]
        [string]$Path,

        [switch]$KeepInheritance
    )

    process {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Path not found: $Path"
        }

        $isDir  = Test-Path -LiteralPath $Path -PathType Container
        $sid    = [System.Security.Principal.WindowsIdentity]::GetCurrent().User

        $inheritFlags = if ($isDir) {
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        } else {
            [System.Security.AccessControl.InheritanceFlags]::None
        }
        $propFlags = [System.Security.AccessControl.PropagationFlags]::None

        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritFlags,
            $propFlags,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $acl = if ($isDir) {
            New-Object System.Security.AccessControl.DirectorySecurity
        } else {
            New-Object System.Security.AccessControl.FileSecurity
        }

        # !important: protect DACL; drop inheritance unless explicitly kept
        $preserveInheritance = $KeepInheritance.IsPresent
        $acl.SetAccessRuleProtection($true, $preserveInheritance)

        # Set owner first; may requite TakeOwnership privilege
        try {
            $acl.SetOwner($sid)
        } catch {
            throw "Failed to set owner on '$Path (need SeTakeOwnership?): $($_.Exception.Message)"
        }

        # Replace DACL with a single allow for the owner
        $null = $acl.SetAccessRule($rule)

        if ($PSCmdlet.ShouldProcess($Path, 'Set user-only ACL')) {
            Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
        }
        # output for assertions/pipeline
        Get-Acl -LiteralPath $Path
    }
}
#endregion
