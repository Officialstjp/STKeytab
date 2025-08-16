# AES S2K for MIT/Heimdal/Windows salt policies using custom PDKDF2-HMACSHA1.

# salt normalization for compatibility flavors
function Normalize-PrincipalForSalt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('MIT','Heimdal','Windows')] [string]$Compatibility,
        [Parameter(Mandatory)][object]$PrincipalDescriptor # { Components, Realm, NameType }
    )

    $realm = if ($Compatibility -eq 'Windows') { 
        $PrincipalDescriptor.Realm.ToUpperInvariant() 
    } else { 
        $PrincipalDescriptor.Realm 
    }
    $components = [string[]]$PrincipalDescriptor.Components.Clone()
    
    # KRB_NT_SRV_HST (3): lowercase service and host for Windows flavor
    if ($Compatibility -eq 'Windows' -and $PrincipalDescriptor.NameType -eq 3) {
        if ($components.Count -ge 1) { $components[0] = $components[0].ToLowerInvariant() }
        if ($components.Count -ge 2) { $components[1] = $components[1].ToLowerInvariant() }
    }

    [pscustomobject]@{
        Components = $components
        Realm      = $realm
        NameType   = $PrincipalDescriptor.NameType
    }
}

function Get-DefaultSalt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Mit','Heimdal','Windows')] [string]$Compatibility,
        [Parameter(Mandatory)][object]$PrincipalDescriptor
    )

    $principal = Normalize-PrincipalForSalt -Compatibility $Compatibility -PrincipalDescriptor $PrincipalDescriptor
    $saltStr = $principal.Realm + ($principal.Components -join '')
    [Text.Encoding]::UTF8.GetBytes($saltStr)
}

function Get-AesKeyLengthForEtype {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Etype
    )
    switch ($Etype) {
        17 { 16 } # AES128_CTS_HMAC_SHA1_96
        18 { 32 } # AES256_CTS_HMAC_SHA1_96
        default { throw "Unsupported Etype: $Etype"}
    }
}

function ConvertTo-BigEndianUint32Bytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint32]$Value
    )

    $bytes = [BitConverter]::GetBytes([uint32]$Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    $bytes
}

function Invoke-PBKDF2HmacSha1 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$PasswordBytes,
        [Parameter(Mandatory)][byte[]]$SaltBytes,
        [Parameter(Mandatory)][int]$Iterations,
        [Parameter(Mandatory)][int]$DerivedKeyLength
    )

    if ($Iterations -lt 1) { throw "PDKDF2 iterations must be >= 1" }

    $hashlength     = 20
    $blocks         = [math]::Ceiling($DerivedKeyLength / [double]$hashlength)
    $derivedKey     = New-Object byte[]($DerivedKeyLength)
    $offset         = 0
    $hmac           = [System.Security.Cryptography.HMACSHA1]::new($PasswordBytes)
    try {
        for ($i = 1; $i -le $blocks; $i++) {                                # for every block
            $iterBytes = ConvertTo-BigEndianUint32Bytes -Value $i           # Block index (1-based)
            $msg = New-Object byte[] ($SaltBytes.Length +4)                 # Salt + Block index
            [Array]::Copy($SaltBytes, 0, $msg, 0, $SaltBytes.Length)        # Copy SaltBytes to <msg>
            [Array]::Copy($iterBytes, 0, $msg, $SaltBytes.Length, 4)        # Copy Block index to <msg>
            $curIter = $hmac.ComputeHash($msg)                              # Compute initial hash
            $curIterHash = [byte[]]$curIter.Clone()                         # Clone initial hash
            for ($j = 2; $j -le $Iterations; $j++) {                        # for each iteration
                $curIter = $hmac.ComputeHash($curIter)                      # Compute subsequent hash
                for ($k = 0; $k -lt $curIterHash.Length; $k++) {            # for each byte in the hash
                    $curIterHash[$k] = $curIterHash[$k] -bxor $curIter[$k]  # XOR with current iteration
                }
            }
            $cpyBytes = [Math]::Min($hashLength, $DerivedKeyLength - $offset)   # copy bytes of current block
            [Array]::Copy($curIterHash, 0, $derivedKey, $offset, $cpyBytes)     # to <derivedKey>
            $offset += $cpyBytes
            [Array]::Clear($msg, 0, $msg.Length)                                # Clear message buffer
            [Array]::Clear($iterBytes, 0, $iterBytes.Length)                    # Clear iteration bytes
            [Array]::Clear($curIterHash, 0, $curIterHash.Length)                # Clear current iteration hash
            [Array]::Clear($curIter, 0, $curIter.Length)                        # Clear current iteration
        }
    } finally { try { $hmac.Dispose() } catch {} }
    [Array]::Clear($PasswordBytes, 0, $PasswordBytes.Length)
    $derivedKey
}

function ConvertFrom-SecureStringToPlain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][SecureString]$Secure
    )

    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { if ($ptr -ne [intPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) } }
}

function Derive-AesKeyWithPbkdf2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Etype,
        [Parameter(Mandatory)][string]$PasswordPlain,
        [Parameter(Mandatory)][byte[]]$SaltBytes,
        [int]$Iterations = 4096
    )
    
    $keyLength = Get-AesKeyLengthForEtype -Etype $Etype
    $passBytes = [Text.Encoding]::UTF8.GetBytes($PasswordPlain)
    $saltLocal = [byte[]]$SaltBytes.Clone()

    try { 
        Invoke-PBKDF2HmacSha1 -PasswordBytes $passBytes -SaltBytes $saltLocal -Iterations $Iterations -DerivedKeyLength $keyLength
    }
    finally {
        if ($saltLocal) { [Array]::Clear($saltLocal, 0, $saltLocal.Length) }
        if ($passBytes) { [Array]::Clear($passBytes, 0, $passBytes.Length)}
    }
}