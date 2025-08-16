#region Other Helpers
# ---------------------------------------------------------------------- #
#
#                           Acl Helpers
#
# ---------------------------------------------------------------------- #

function Set-UserOnlyAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path
  )

  try {
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $isDir = $false
  try { $isDir = (Get-Item -LiteralPath $Path -Force).PSIsContainer } catch {}
  $inheritFlags = if ($isDir) { 'ContainerInherit, ObjectInherit' } else { 'None' }
  $propFlags    = 'None'
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl',$inheritFlags,$propFlags,'Allow')
  $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
  } catch {
    Write-Warning "ACL restriction failed for '$Path': $($_.Exception.Message)"
  }
}

#endregion