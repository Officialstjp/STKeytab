

function Read-Keytab {
  <#
    .SYNOPSIS
    Parse a keytab file into structured entries.

    .DESCRIPTION
    Robust parser for MIT keytab v0x0502. Can reveal raw key bytes for merge scenarios.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$RevealKeys,
    [int]$MaxKeyHex = 64
  )

  if (-not (Test-Path -LiteralPath $Path)) { throw "File '$Path' not found" }

  $bytes = [IO.File]::ReadAllBytes($Path)

  if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x05 -or $bytes[1] -ne 0x02) { throw "'$Path' is not a valid keytab (expected 0x05 0x02 at start)" }

  $pos = 2
  $list = New-Object System.Collections.Generic.List[object]
  while ($pos -lt $bytes.Length) {
    if ($pos + 4 -gt $bytes.Length) { throw "Unexpected end of file at position $pos in '$Path'" }
    $entryLength = [int](
      ($bytes[$pos]      -shl 24)   -bor
      ($bytes[$pos+1]    -shl 16)   -bor
      ($bytes[$pos+2]    -shl 8)    -bor
      ($bytes[$pos+3])
    )

    $pos += 4
    if ($entryLength -lt 0) { $entryLength = -$entryLength } # MIT quirk
    if ($entryLength -lt 0) { throw "Invalid entry length at position $pos in '$Path'" }
    if ($pos + $entryLength -gt $bytes.Length) { 
      $misMatchLength = $entryLength - ($bytes.Length - $pos)
      throw "Declared entry exceeds file length by $misMatchLength bytes at position $pos in '$Path'" 
    }

    $entry = $bytes[$pos..($pos+$entryLength-1)]
    $pos += $entryLength

    # Use a single cursor ($iref.Value) for all reads to avoid desync
    $index = 0
    $iref  = [ref]$index

    # compCount, realm length, realm
    $compCount   = ReadUInt16 $entry $iref
    $realmLength = ReadUInt16 $entry $iref
    $idx         = [int]$iref.Value
    [byte[]]$realmBytesSlice = $entry[$idx..($idx+$realmLength-1)]
    $realm       = [Text.Encoding]::ASCII.GetString($realmBytesSlice)
    $iref.Value  = $idx + $realmLength

    # components (repeat compCount times)
    $components = @()
    for ($c = 0; $c -lt $compCount; $c++) {
    $len = ReadUInt16 $entry $iref
    $idx = [int]$iref.Value
    [byte[]]$compSlice = $entry[$idx..($idx+$len-1)]
    $components += ,([Text.Encoding]::ASCII.GetString($compSlice))
      $iref.Value  = $idx + $len
    }

    # nameType, timestamp
    $nameType  = ReadUInt32 $entry $iref
    $timestamp = ReadUInt32 $entry $iref

    # kvno8 (1 byte)
    $idx   = [int]$iref.Value
    $kvno8 = [int]$entry[$idx]
    $idx++
    $iref.Value = $idx
        
    # etype (UInt16), keyLength (UInt16), key bytes
    $etype     = ReadUInt16 $entry $iref
    $keyLength = ReadUInt16 $entry $iref
    $idx       = [int]$iref.Value
    $keyBytes  = $entry[$idx..($idx+$keyLength-1)]
    $iref.Value = $idx + $keyLength

    # optional kvno32 (UInt32); prefer over kvno8 if present and non-zero
    $kvno32 = $null
    if ($iref.Value + 4 -le $entry.Length) {
      $kvno32 = ReadUInt32 $entry $iref
    }
    $kvnoEffective = if ($kvno32 -and $kvno32 -ne 0) { [int]$kvno32 } else { $kvno8 }

    # build display values and add entry
    $keyHexFull = ($keyBytes | ForEach-Object { $_.ToString('x2') }) -join ''
    $keyDisplay = if ($RevealKeys) {
      if ($keyHexFull.Length -gt $MaxKeyHex) { $keyHexFull.Substring(0,$MaxKeyHex) + '...' } else { $keyHexFull }
    } else {
      if ($keyHexFull.Length -le 16) { $keyHexFull } else { $keyHexFull.Substring(0,8) + '...' + $keyHexFull.Substring($keyHexFull.Length-8,8) }
    }

    $rawKey = if ($RevealKeys) { $keyBytes } else { $null }
    $list.Add([pscustomobject]@{
      Realm      = $realm
      Components = $components
      NameType   = [int]$nameType
      TimestampUtc = ([DateTimeOffset]::FromUnixTimeSeconds([int]$timestamp).UtcDateTime)
      Kvno       = $kvnoEffective
      EtypeId    = $etype
      EtypeName  = Get-EtypeNameFromId $etype
      KeyLength  = $keyLength
      Key        = $keyDisplay
      RawKey     = $rawKey
    })
  }
  $list
}

