#region Other Helpers
# ---------------------------------------------------------------------- #
#
#                           Acl Helpers
#
# ---------------------------------------------------------------------- #

function Set-UserOnlyAcl {
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