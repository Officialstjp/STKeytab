<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

@{
    # PSScriptAnalyzer settings for STkrbKeytab module

    IncludeDefaultRules = $true

    # Suppress rules that are acceptable or don't apply to this module type
    ExcludeRules = @(
        # === Test File Suppressions ===
        'PSAvoidGlobalVars',                        # Test files legitimately use global test variables
        'PSUseDeclaredVarsMoreThanAssignments',     # Test variables used in assertions, not traditional assignments

        # === Security Module Suppressions ===
        'PSAvoidUsingWriteHost',                    # Acceptable for security warnings and user feedback
        'PSAvoidUsingPlainTextForPassword',         # Required for cryptographic string-to-key functions

        # === Helper Function Suppressions ===
        'PSUseApprovedVerbs',                       # Internal helper functions use descriptive verbs (Sanitize, Normalize, Derive)
        'PSUseSingularNouns',                       # Some concepts are inherently plural (Etypes, Descriptors)

        # === Cross-Platform Suppressions ===
        'PSUseBOMForUnicodeEncodedFile',           # BOM conflicts with cross-platform compatibility

        # === Architecture Suppressions ===
        'PSUseShouldProcessForStateChangingFunctions', # Many internal functions don't need ShouldProcess (handled at public layer)
        'PSUseProcessBlockForPipelineCommand'          # Some cmdlets handle pipeline differently (batch processing)
    )

    # Custom rule configurations
    Rules = @{
        # Only enforce empty catch blocks in Public functions
        PSAvoidUsingEmptyCatchBlock = @{
            Enable = $true
        }

        # Review unused parameters but don't fail build
        PSReviewUnusedParameter = @{
            Enable = $true
        }
    }
}
