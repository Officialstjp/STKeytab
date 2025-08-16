<#
.SYNOPSIS
Generate a keytab from a password using MIT/Heimdal/Windows salt policies (AES oly)

.DESCRIPTION
Derives AES keys (etype 17/18) via PBKDF2-HMACSHA1 and writes a MIT v0x0502 keytab.
Defaults to AES-only, safe salt policy and supports deterministic timestamps for tests.
#>
function New-KeytabFromPassword {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'User')]
    param(
        # Identity
        [Parameter(ParameterSetName='User', Mandatory)][string]$SamAccountName,
        [Parameter(ParameterSetName='Principal', Mandatory)][string]$Principal,
        [Parameter(Mandatory)][string]$Realm,

        # Secret
        [Parameter(ParameterSetName='User', Mandatory)][SecureString]$Password,
        [Parameter(ParameterSetName='User')][pscredential]$Credential,

        # Options
        [Alias('Comp')][ValidateSet('MIT','Heimdal','Windows')][string]$Compatibility = 'MIT',
        [object[]]$IncludeEtype,
        [object[]]$ExcludeEtype,
        [int]$Kvno = 1,
        [int]$Iterations = 4096,
        [string]$OutputPath,
        [switch]$RestrictAcl,
        [switch]$Force,
        [string]$JsonSummaryPath,
        [switch]$Summary,
        [switch]$PassThru,
        [datetime]$FixedTimestampUtc
    )

    begin {
        # Default AES preference if none provided
        if (-not $PSBoundParameters.ContainsKey('IncludeEtype')) {
            $IncludeEtype = @(18,17) # AES 256, AES 128
        }
    }
    process {
        if ($Credential -and -not $Password) { $Password = $Credential.GetNetworkCredential().SecurePassword }
        if (-not $Password) { throw "Password (or PSCredential) is required." }
        if ($Iterations -lt 1) { throw "Iterations must be at least 1." }

        # Principal descriptor
        $princDesc = 
            if ($PSCmdlet.ParameterSetName -eq 'Principal') {
                if ($Principal -notmatch '@') { throw "Principal must include realm (e.g. user@<realm>)"}
                $split = $Principal.Split('@',2)
                $left,$prRealm = $split[0],$split[1]
                if ($prRealm -ne $Realm) { throw "Realm mismatch: -Realm '$Realm' vs principal '@$prRealm'"}
                if ($left -match '/') {
                    $svcHost = $left.Split('/',2)
                    [pscustomObject]@{
                        Components = @($svcHost[0], $svcHost[1])
                        Realm      = $Realm
                        NameType   = 3
                        Display    = ("{0}@{1}" -f $left, $Realm)
                    }
                } else {
                    [pscustomObject]@{
                        Components = @($left)
                        Realm      = $Realm
                        NameType   = 1
                        Display    = ("{0}@{1}" -f $left, $Realm)
                    }
                }
            } else {
                $base = $SamAccountName.TrimEnd('$')
                [pscustomobject]@{
                    Components = @($base)
                    Realm      = $Realm
                    NameType   = 1
                    Display    = ("{0}@{1}" -f $base, $Realm)
                }
            }

        # Etype selection 
        $available = @(17,18)
        $selection = Resolve-EtypeSelection -AvailableIds $available -Include $IncludeEtype -Exclude $ExcludeEtype
        if ($selection.Selected.Count -eq 0) { throw "No Encryption types selected."}
        if ($selection.UnknownInclude.Count -gt 0) { Write-Warning "Unknown IncludeEtype: " + ($selection.UnknownInclude -join ', ')}
        if ($selection.UnknownExclude.Count -gt 0) { Write-Warning "Unknown ExcludeEtype: " + ($selection.UnknownExclude -join ', ')}
        if ($selection.Missing.Count -gt 0) { Write-Warning "Requested Etype not present: " + ($selection.Missing -join ', ') }

        # Derive

        $plain = ConvertFrom-SecureStringToPlain -Secure $Password
        try {
            $saltBytes = Get-DefaultSalt -Compatibility $Compatibility -PrincipalDescriptor $princDesc
            $keys = @{}
            foreach ($etype in $selection.Selected) {
                if ($etype -notin 17,18) { throw "Only AES etypes (17,18) supported in this path."}
                $key = Derive-AesKeyWithPbkdf2 -Etype $etype -PasswordPlain $plain -SaltBytes $saltBytes -Iterations $Iterations
                $keys[$etype] = $key
            }
        } finally {
            if ($plain) {
                $pad = New-Object string (' ', $plain.Length)
                $plain = $pad; $plain = $null
            }
            if ($saltBytes) { [Array]::Clear($saltBytes, 0, $saltBytes.Length) }
        }

        $keySet = [pscustomobject]@{
            Kvno        =  [int]$Kvno
            Keys        = $keys    
            Source      = "PasswordS2K:$Compatibility/PBDKDF2-SHA1($Iterations)"
            RetrievedAt = (Get-Date).ToUniversalTime()
        }

        $tsArg = @{}
        if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) {
            $tsArg.FixedTimestampUtc = $FixedTimestampUtc
        }

        # Write file via keytab writer
        $writer = Get-Command -Name New-KeytabFile -ErrorAction Stop
        if (-not $writer) {
            Write-Verbose "New-KeytabFile not found; returning structure."
            $out = [pscustomobject]@{
            PrincipalDescriptors = @($princDesc)
            KeySets              = @($keySet)
            SelectedEtypes       = $selection.Selected
            Compatibility        = $Compatibility
            Iterations           = $Iterations
            }
            if ($PassThru) { return $out } else { $out; return }
        }

        if (-not $OutputPath) {
            $base = ($princDesc.Components -join '_')
            $OutputPath = Join-Path -Path $PSScriptRoot -ChildPath ("{0}.keytab" -f $base)
        }
        if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) { throw "Output file '$OutputPath' exists. Use -Force." }

        if ($PSCmdlet.ShouldProcess($princDesc.Display, "Create password-derived keytab file '$OutputPath'")) {
            $final = New-KeytabFile -Path $OutputPath -PrincipalDescriptors @($princDesc) -KeySets @($keySet) -RestrictAcl:$RestrictAcl @tsArg

            if ($summary -or $PassThru) {
                if (-not $JsonSummaryPath) { $JsonSummaryPath = [IO.Path]::ChangeExtension($final,'.json') }
                $etypeNames = @($selection.Selected | ForEach-Object { if ($_ -eq 17) { 'AES128_CTS_HMAC_SHA1_96' } elseif ($_ -eq 18) { 'AES256_CTS_HMAC_SHA1_96' } else { "ETYPE_$_" } })
                $summaryObj = [ordered]@{
                    Principal       = $princDesc.Display
                    Realm           = $princDesc.Realm
                    Compatibility   = $Compatibility
                    Iterations      = $Iterations
                    Kvno            = $Kvno
                    Etypes          = $selection.Selected
                    EncryptionTypes = $etypeNames
                    OutputPath      = (Resolve-Path -LiteralPath $final).Path
                    GeneratedAtUtc  = ( ($tsArg.FixedTimestampUtc) ? $tsArg.FixedTimestampUtc.ToUniversalTime().ToString('o') : (Get-Date).ToUniversalTime().ToString('o') )
                }
                $summaryObj | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $JsonSummaryPath -Encoding UTF8
                if ($RestrictAcl) {
                    if (Get-Command -Name Set-UserOnlyAcl -ErrorAction SilentlyContinue) { Set-UserOnlyAcl -Path $JsonSummaryPath }
                }
            }

            if ($PassThru) {
                [pscustomobject]@{
                    Principal   = $princDesc.Display
                    Kvno        = $Kvno
                    Iterations  = $Iterations
                    Etypes      = $selection.Selected
                    SummaryPath = $JsonSummaryPath
                    OutputPath  = $final
                }
            } else {
            $final
            }
        }
    }
}