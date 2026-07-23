@{
    # Script module or binary module file associated with this manifest.
    RootModule           = 'psZBX.psm1'

    # Version number of this module.
    ModuleVersion        = '1.0.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module - DO NOT CHANGE between releases
    GUID                 = '7504bb1b-99a1-4900-af80-a1e907c8bccb'

    # Author of this module
    Author               = 'Lukasz Huk'

    # Company or vendor of this module
    CompanyName          = 'sprawdzone.it'

    # Copyright statement for this module
    Copyright            = '(c) 2026 Lukasz Huk. All rights reserved.'

    # Description of the functionality provided by this module
    Description          = 'PowerShell module for querying Zabbix server via REST API. Provides cmdlets for problems, events, hosts and maintenance windows. Compatible with Zabbix 6.4+ (uses Bearer token authentication).'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion    = '5.1'

    # Functions to export from this module - explicit list (no wildcards)
    FunctionsToExport    = @(
        'Connect-ZbxServer',
        'Disconnect-ZbxServer',
        'Get-ZbxProblem',
        'Get-ZbxEvent',
        'Get-ZbxHost',
        'Get-ZbxMaintenance',
        'Set-ZbxMaintenance'
    )

    # Cmdlets to export from this module
    CmdletsToExport      = @()

    # Variables to export from this module
    VariablesToExport    = @()

    # Aliases to export. Only renames that differ in more than letter-case
    # are kept as aliases - for case-only renames PowerShell's case-insensitive
    # command resolution handles backward compatibility automatically without
    # an alias (and registering one would collide with the function).
    AliasesToExport      = @(
        'Get-ZBXhostinfo',
        'Get-ZBXmaint',
        'Set-ZBXmaint'
    )

    # Private data to pass to the module specified in RootModule.
    # PSData is used by PowerShell Gallery.
    PrivateData          = @{
        PSData = @{
            # Tags applied to this module. Help in module discovery in online galleries.
            Tags         = @(
                'Zabbix',
                'Monitoring',
                'API',
                'REST',
                'SprawdzoneIT',
                'PSEdition_Core',
                'PSEdition_Desktop'
            )

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/sprawdzoneit/PowerShell-Zabbix-Module/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/sprawdzoneit/PowerShell-Zabbix-Module'

            # A URL to an icon representing this module.
            # IconUri    = 'https://sprawdzone.it/assets/zbx-icon.png'

            # ReleaseNotes of this module
            ReleaseNotes = @'
1.0.0 - Initial public release
- Connect-ZbxServer / Disconnect-ZbxServer
- Get-ZbxProblem, Get-ZbxEvent, Get-ZbxHost
- Get-ZbxMaintenance, Set-ZbxMaintenance
- Bearer token authentication (Zabbix 6.4+ / 7.2+ compatible)
- SecureString token handling throughout
- Aliases kept for legacy pre-1.0.0 function names
'@
        }
    }
}
