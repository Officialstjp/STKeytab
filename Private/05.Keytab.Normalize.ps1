<#
.SYNOPSIS
Helper for normalizing Keytab entries, primarily those parsed by Read-Keytab.

#>

Set-StrictMode -Version Latest

function Normalize-KeytabEntry {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][pscustomobject]$Entry,
    [switch]$IgnoreTimestamp
  )
  $etype = if ($Entry.PSObject.Properties['EtypeId']) { [int]$Entry.EtypeId }
          elseif ($Entry.PSObject.Properties['Etype']) { [int]$Entry.Etype }
          else { throw "Entry missing Etype/EtypeId" }

  [pscustomobject]@{
    Realm        = $Entry.Realm
    Components   = @($Entry.Components)
    NameType     = [int]$Entry.NameType
    Kvno         = [int]$Entry.Kvno
    Etype        = $etype
    TimestampUtc = if ($IgnoreTimestamp) { $null } else { $Entry.TimestampUtc }
    Key          = $Entry.RawKey  # bytes when Read-Keytab -RevealKeys, else $null
  }
}

function ConvertEntriesTo-KeytabCanonicalModel {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object[]]$Entries,
    [switch]$IgnoreTimestamp
  )
  $canon = foreach ($e in $Entries) {
    Normalize-KeytabEntry -Entry $e -IgnoreTimestamp:$IgnoreTimestamp
  }
  $canon | Sort-Object Realm, @{e={$_.Components -join '/'}}, NameType, Kvno, Etype
}