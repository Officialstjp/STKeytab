<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


#region AES S2K for MIT/Heimdal/Windows salt policies
# ---------------------------------------------------------------------- #
#                   AES S2K for MIT/Heimdal/Windows salt policies
#                       using custom PDKDF2-HMACSHA1.
#
# ---------------------------------------------------------------------- #

function Normalize-PrincipalForSalt {
    <#
        .SYNOPSIS
        Normalize a principal descriptor for use as a salt in key derivation.
    #>
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
    <#
    .SYNOPSIS
    Get the default salt for a given principal descriptor and compatibility.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Mit','Heimdal','Windows')] [string]$Compatibility,
        [Parameter(Mandatory)][object]$PrincipalDescriptor
    )

    $principal = Normalize-PrincipalForSalt -Compatibility $Compatibility -PrincipalDescriptor $PrincipalDescriptor
    $saltStr = $principal.Realm + ($principal.Components -join '')
    [Text.Encoding]::UTF8.GetBytes($saltStr)
}

function ConvertTo-BigEndianUint32Bytes {
    <#
    .SYNOPSIS
    Convert a 32-bit unsigned integer to a big-endian byte array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint32]$Value
    )

    $bytes = [BitConverter]::GetBytes([uint32]$Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    $bytes
}

function Invoke-PBKDF2Hmac {
    <#
    .SYNOPSIS
    Invoke PBKDF2-HMAC-SHA1 key derivation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$PasswordBytes,
        [Parameter(Mandatory)][byte[]]$SaltBytes,
        [Parameter(Mandatory)][int]$Iterations,
        [Parameter(Mandatory)][int]$DerivedKeyLength,
        [Parameter(Mandatory)][System.Security.Cryptography.HMAC]$HmacAlgorithm
    )

    if ($Iterations -lt 1) { throw "PDKDF2 iterations must be >= 1" }

    # Set HMAC key from password bytes
    $HmacAlgorithm.Key = $PasswordBytes

    $hashlength     = $HmacAlgorithm.HashSize / 8 # bits to bytes
    $blocks         = [math]::Ceiling($DerivedKeyLength / [double]$hashlength)
    $derivedKey     = New-Object byte[]($DerivedKeyLength)
    $offset         = 0

    try {
        for ($i = 1; $i -le $blocks; $i++) {                                # for every block
            $iterBytes = ConvertTo-BigEndianUint32Bytes -Value $i           # Block index (1-based)
            $msg = New-Object byte[] ($SaltBytes.Length +4)                 # Salt + Block index
            [Array]::Copy($SaltBytes, 0, $msg, 0, $SaltBytes.Length)        # Copy SaltBytes to <msg>
            [Array]::Copy($iterBytes, 0, $msg, $SaltBytes.Length, 4)        # Copy Block index to <msg>

            $curIter = $HmacAlgorithm.ComputeHash($msg)                     # Compute initial hash
            $curIterHash = [byte[]]$curIter.Clone()                         # Clone initial hash

            for ($j = 2; $j -le $Iterations; $j++) {                        # for each iteration
                $curIter = $HmacAlgorithm.ComputeHash($curIter)             # Compute subsequent hash
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
    } finally { }
    $derivedKey
}

function ConvertFrom-SecureStringToPlain {
    <#
    .SYNOPSIS
    Convert a SecureString to a plain text string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][SecureString]$Secure
    )

    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { if ($ptr -ne [intPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) } }
}

function Derive-AesKeyWithPbkdf2 {
    <#
    .SYNOPSIS
    Derive an AES key using PBKDF2 with HMAC-SHA1.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Etype,
        [Parameter(Mandatory)][string]$PasswordPlain,
        [Parameter(Mandatory)][byte[]]$SaltBytes,
        [int]$Iterations
    )

    switch ($Etype) {
        17 { # AES-128_CTS_HMAC_SHA1_96
            $keyLength = 16
            $hmac = [System.Security.Cryptography.HMACSHA1]::New()
            if (-not $Iterations) { $Iterations = 4096 } # RFC 2898
        }
        18 { # AES-256_CTS_HMAC_SHA1_96
            $keyLength = 32
            $hmac = [System.Security.Cryptography.HMACSHA1]::New()
            if (-not $Iterations) { $Iterations = 4096 } # RFC 2898
        }
        19 { # AES-128_CTS_HMAC_SHA256_128
            $keyLength = 16
            $hmac = [System.Security.Cryptography.HMACSHA256]::New()
            if (-not $Iterations) { $Iterations = 32768 } # RFC 8009
        }
        20 { # AES-256_CTS_HMAC_SHA384_192
            $keyLength = 32
            $hmac = [System.Security.Cryptography.HMACSHA384]::New()
            if (-not $Iterations) { $Iterations = 32768 } # RFC 8009
        }
        default { throw "Unsupported Etype: $Etype" }
    }

    $passBytes = [Text.Encoding]::UTF8.GetBytes($PasswordPlain)
    $saltLocal = [byte[]]$SaltBytes.Clone()

    try {
        return Invoke-PBKDF2Hmac -PasswordBytes $passBytes -SaltBytes $saltLocal -Iterations $Iterations -DerivedKeyLength $keyLength -HmacAlgorithm $hmac
    }
    finally {
        if ($hmac) { $hmac.Dispose() }
        if ($saltLocal) { [Array]::Clear($saltLocal, 0, $saltLocal.Length) }
        if ($passBytes) { [Array]::Clear($passBytes, 0, $passBytes.Length)}
    }
}
#endregion
