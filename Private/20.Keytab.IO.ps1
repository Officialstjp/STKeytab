#region Keytab Writer / Parser
# ---------------------------------------------------------------------- #
#
#                           Keytab Writer / Parser
#
# ---------------------------------------------------------------------- #

function Write-UInt16BE([IO.BinaryWriter]$binaryWriter,[int]$Value) { 
  [byte[]]$b = [BitConverter]::GetBytes([uint16]$Value)
  if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
  $binaryWriter.Write($b,0,2)
}

function Write-UInt32BE([IO.BinaryWriter]$binaryWriter,[System.UInt32]$Value) {
  [byte[]]$b = [BitConverter]::GetBytes([uint32]$Value)
  if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
  $binaryWriter.Write($b,0,4)
}

function Write-Int32BE([IO.BinaryWriter]$BinaryWriter,[int]$Value) {
    Write-UInt32BE $BinaryWriter ([System.UInt32]$Value)
}

function ReadUInt16([byte[]]$bytes,[ref]$i) {
  $idx = [int]$i.Value
  [byte[]]$b = $bytes[$idx..($idx+1)]
  if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
  $i.Value = $idx + 2
  return [uint16]([BitConverter]::ToUInt16($b,0))
}

function ReadUInt32([byte[]]$bytes,[ref]$i) {
  $idx = [int]$i.Value
  [byte[]]$b = $bytes[$idx..($idx+3)]
  if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
  $i.Value = $idx + 4
  return [uint32]([BitConverter]::ToUInt32($b,0))
}


function New-KeytabEntry {
  <#
    .SYNOPSIS
    Builds a single MIT keytab entry bytes for a principal/etype/kvno.

    .DESCRIPTION
    Encodes realm, components, name type, timestamp, kvno (8/32-bit), and key material
    into the on-disk keytab entry format. Used internally by New-KeytabFile.
  #>
  param(
    [Parameter(Mandatory)][object]$PrincipalDescriptor,
    [Parameter(Mandatory)][int]$EncryptionType,
    [Parameter(Mandatory)][byte[]]$Key,
    [Parameter(Mandatory)][int]$Kvno,
    [int]$Timestamp = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  )

  $enc = [Text.Encoding]::ASCII
  $realmBytes = $enc.GetBytes($PrincipalDescriptor.Realm)

  $memStream    = New-Object IO.MemoryStream # write in memory first, then to disk when done
  $binaryWriter = New-Object IO.BinaryWriter($memStream)

  Write-UInt16BE $binaryWriter $PrincipalDescriptor.Components.Count
  # realm
  Write-UInt16BE $binaryWriter $realmBytes.Length; $BinaryWriter.Write($realmBytes)
  #components
  foreach ($comp in $PrincipalDescriptor.Components) {
    [byte[]]$compBytes = $enc.GetBytes($comp)
    Write-UInt16BE $binaryWriter $compBytes.Length
    $binaryWriter.Write($compBytes)
  }

  Write-UInt32BE $binaryWriter ([uint32]$PrincipalDescriptor.NameType)
  Write-UInt32BE $binaryWriter ([uint32]$Timestamp)
  $binaryWriter.Write([byte]($Kvno -band 0xFF))
  Write-UInt16BE $binaryWriter $EncryptionType
  Write-UInt16BE $binaryWriter $Key.Length
  $binaryWriter.Write($Key)
  # 32 bit kvno extension
  Write-UInt32BE $binaryWriter ([uint32]$Kvno)

  $binaryWriter.Flush()
  $memStream.ToArray()
}


function New-KeytabFile {
  <#
    .SYNOPSIS
    Writes a complete MIT keytab file (v0x0502) from principal descriptors and key sets.

    .DESCRIPTION
    Iterates key sets (by KVNO) and encryption types, generating entries for each principal.
    Supports deterministic timestamps via -FixedTimestampUtc and optionally restricts ACLs
    to the current user.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][object[]]$PrincipalDescriptors,
    [Parameter(Mandatory)][object[]]$KeySets, # list of {Kvno: Keys}
    [int[]]$EtypeFilter,
    [switch]$RestrictAcl,
    [datetime]$FixedTimestampUtc
  )

  $full = if ([IO.Path]::IsPathRooted($Path)) { [IO.Path]::GetFullPath($Path) } else { [IO.Path]::GetFullPath((Join-Path (Get-Location) $Path)) }
  $tmp = "$full.tmp"
  if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }

  $memStream = New-Object IO.MemoryStream
  $binaryWriter = New-Object IO.BinaryWriter($memStream)
  $entryCount = 0

  try {
    # keytab v2 header
    $binaryWriter.Write([byte]0x05)
    $binaryWriter.Write([byte]0x02)
    $tsArg = @{}
    $timestampSec =
      if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) {
        [int][DateTimeOffset]::new(($FixedTimestampUtc.ToUniversalTime())).ToUnixTimeSeconds()
      } else {
        [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
      }

    if ($PSBoundParameters.ContainsKey('FixedTimestampUtc') -and $FixedTimestampUtc) {
      $tsArg = @{ Timestamp = $timestampSec }
    }

    foreach ($keySet in $KeySets | Sort-Object Kvno) {
      foreach ($etype in ($keySet.Keys.Keys | Sort-Object)) {
        if ($EtypeFilter -and ($EtypeFilter -notcontains $etype)) { continue }
        [byte[]]$bytes = $keySet.Keys[$etype]
        foreach ($pd in $PrincipalDescriptors) {
          [byte[]]$entryBytes = New-KeytabEntry -PrincipalDescriptor $pd -EncryptionType $etype -Key $bytes -Kvno $keySet.Kvno @tsArg
          Write-Int32BE $binaryWriter $entryBytes.Length
          $binaryWriter.Write($entryBytes, 0, $entryBytes.Length)
          $entryCount++
        }
      }
    }
    
    $binaryWriter.Flush(); 
    Write-Verbose "[Keytab] entries=$entryCount length=$($memStream.Length) file=$tmp"
  } finally {
    $binaryWriter.Dispose()
  }

  [IO.File]::WriteAllBytes($tmp, $memStream.ToArray())
  Move-Item -LiteralPath $tmp -Destination $full -Force
  if ($RestrictAcl) { Set-UserOnlyAcl -Path $full }
  $full
}
#endregion
