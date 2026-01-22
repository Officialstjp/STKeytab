<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

@{
    # PSScriptAnalyzer settings for the STKeytab module
    # Ref: https://github.com/PowerShell/PSScriptAnalyzer/blob/master/docs/Cmdlets/Invoke-ScriptAnalyzer.md

    IncludeDefaultRules = $true

    ExcludeRules = @(
        # === Intentional Design Decisions ===
        'PSAvoidUsingWriteHost'                         # Used for security banners and user feedback (colored output)
        'PSAvoidUsingPlainTextForPassword'              # Internal crypto functions need plaintext for S2K derivation
        'PSAvoidUsingConvertToSecureStringWithPlainText' # Test helpers and password utilities (acceptable in context)

        # === Naming Conventions (Intentional) ===
        'PSUseApprovedVerbs'                            # Internal helpers use descriptive verbs (Normalize, Derive)
        'PSUseSingularNouns'                            # Some concepts are inherently plural (Etypes, Descriptors, Bytes)

        # === Cross-Platform / Encoding ===
        'PSUseBOMForUnicodeEncodedFile'                 # BOM causes issues with cross-platform tooling

        # === Architecture (Handled at Public Layer) ===
        'PSUseShouldProcessForStateChangingFunctions'   # Internal New-* functions don't need ShouldProcess
        'PSUseProcessBlockForPipelineCommand'           # Some cmdlets do batch processing

        # === Test File Patterns ===
        'PSAvoidGlobalVars'                             # Test files use $global:TestOutDir legitimately
        'PSUseDeclaredVarsMoreThanAssignments'          # Test variables assigned for pipeline assertions

        # === CI Scripts ===
        'PSAvoidOverwritingBuiltInCmdlets'              # Write-Log helper in CI scripts is intentional
    )

    Rules = @{
        # Review but don't fail on unused parameters (some are for future use or API consistency)
        PSReviewUnusedParameter = @{
            Enable = $true
        }

        # Empty catch blocks should still be flagged in new code
        PSAvoidUsingEmptyCatchBlock = @{
            Enable = $true
        }
    }
}
