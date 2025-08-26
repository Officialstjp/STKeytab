# PowerShell Help System Integration Guide

## How PowerShell Help Resolution Works

When a user runs `Get-Help New-Keytab`, PowerShell searches in this order:

### 1. External Help (MAML XML) - FASTEST
- **Location**: `ModuleBase\en-US\STKeytab-help.xml`
- **Source**: Generated from `docs/cmdlets/*.md` via PlatyPS
- **Performance**: Pre-compiled, instant loading
- **Shipping**: Ships with your module in the `en-US/` folder

### 2. Comment-Based Help - SLOWER
- **Location**: Inside your `.ps1` function files
- **Source**: Your `<# .SYNOPSIS ... #>` blocks
- **Performance**: Parsed at runtime (slower)
- **Fallback**: Used when MAML not available

### 3. Online Help - REQUIRES INTERNET 
- **Trigger**: `Get-Help New-Keytab -Online`
- **Source**: Opens browser to URL in `.LINK` or HelpUri parameter
- **Use**: For latest docs or detailed web-based help

## Update-Help System

### User Experience
```powershell
# User installs your module
Install-Module STKeytab

# User updates help (downloads latest)
Update-Help -Module STKeytab

# Now Get-Help shows the latest version
Get-Help New-Keytab -Full
```

### Behind the Scenes
1. **PowerShell reads HelpInfoURI** from your module manifest
2. **Downloads HelpInfo.xml** from that URL to check version
3. **Compares versions** with locally cached help
4. **Downloads CAB file** if newer version available
5. **Extracts help** to user's help cache directory

### What You Need to Host

Upload these to your `HelpInfoURI` location:
- `STKeytab_c5a6e3a4-c5a6-7b8e-9a0b-f1d9e3f4e5b1_HelpInfo.xml`
- `STKeytab_c5a6e3a4-c5a6-7b8e-9a0b-f1d9e3f4e5b1_en-US_HelpContent.cab`

## GitHub Releases Hosting Example

### 1. Upload to GitHub Releases
```bash
# Create a help release
gh release create help-v1.2.0 \
  ./artifacts/docs/*.xml \
  ./artifacts/docs/*.cab
```

### 2. Update Module Manifest
```powershell
# STKeytab.psd1
HelpInfoURI = 'https://github.com/Officialstjp/STKeytab/releases/download/help-v1.2.0/'
```

### 3. User Experience
```powershell
# User gets newer help
Update-Help -Module STKeytab
# Downloads from GitHub releases automatically
```

## File Naming Convention

PowerShell expects specific naming:
- **HelpInfo**: `{ModuleName}_{GUID}_HelpInfo.xml`
- **Help CAB**: `{ModuleName}_{GUID}_{Culture}_HelpContent.cab`

The GUID comes from your module manifest and ensures uniqueness.

## Integration with CI/CD

### Automated Help Publishing
```yaml
# .github/workflows/help-publish.yml
- name: Build Help
  run: |
    ./CI/Build-Docs.ps1 -Mode Update

- name: Upload to Release
  run: |
    gh release create help-v${{ env.VERSION }} \
      ./artifacts/docs/*.xml \
      ./artifacts/docs/*.cab
```

## About Topics Integration

Your `docs/about/*.md` files become available via:
```powershell
Get-Help about_STKeytab
Get-Help about_STKeytab_Security
Get-Help about_STKeytab_DPAPI
```

They're included in the MAML generation automatically.

## Performance Impact

- **Comment-based**: ~50-200ms (parses .ps1 files)
- **MAML XML**: ~5-15ms (pre-compiled)
- **About topics**: Always use MAML for best performance

## Debugging Help Issues

```powershell
# Check what help source is being used
Get-Help New-Keytab -ShowWindow

# Force regenerate external help
Remove-Item $pshome\Modules\STKeytab\en-US -Recurse -Force
Import-Module STKeytab -Force

# Check help file location
(Get-Module STKeytab).ModuleBase + '\en-US'
```
