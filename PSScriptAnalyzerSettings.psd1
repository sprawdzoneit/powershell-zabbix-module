@{
    # Use all default rules from PSScriptAnalyzer
    IncludeDefaultRules = $true

    # Rules to exclude project-wide
    ExcludeRules        = @(
        # smoke-test.ps1 uses Write-Host deliberately for colored console UX
        'PSAvoidUsingWriteHost'

        # Set-ZbxMaintenance is state-changing but doesn't yet implement
        # SupportsShouldProcess. That's on the v1.1.0 roadmap (Faza 10).
        'PSUseShouldProcessForStateChangingFunctions'
    )

    # Rule-specific configuration
    Rules               = @{
        # Verify the module parses on Windows PowerShell 5.1 and PowerShell 7+
        PSUseCompatibleSyntax      = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.4')
        }

        # Consistent 4-space indentation, no tabs
        PSUseConsistentIndentation = @{
            Enable          = $true
            Kind            = 'space'
            IndentationSize = 4
        }
    }
}
