#Requires -Version 5.1
<#
.SYNOPSIS
    psZBX - PowerShell module for querying Zabbix server via REST API.
.DESCRIPTION
    Loader for the psZBX module. Dot-sources all function files
    from Public/ and Private/ subfolders, then exports public functions and
    backward-compatibility aliases.

    Compatible with Zabbix 6.4+ - uses HTTP Bearer token authentication, the
    mechanism required by Zabbix 7.2+ which removed the legacy 'auth' field
    from JSON-RPC requests.
.NOTES
    Author:  Lukasz Huk / sprawdzone.it
    Website: https://sprawdzone.it
    GitHub:  https://github.com/sprawdzoneit/PowerShell-Zabbix-Module
    License: MIT
#>

# Dot-source all private (internal) and public (exported) function files
$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private" -Filter '*.ps1' -ErrorAction SilentlyContinue)
$Public  = @(Get-ChildItem -Path "$PSScriptRoot\Public"  -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($Private + $Public)) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import function file '$($file.FullName)': $_"
    }
}

# Module-level connection state. Shared across all dot-sourced functions
# via $script: scope. Stores SecureString token, URL and connection flag.
$script:ZabbixConnection = @{
    Token     = $null
    Url       = $null
    Connected = $false
}

# Backward-compatibility aliases for pre-1.0.0 function names where the
# rename is more than a case change. Aliases whose name differs from the
# new function only by letter-case (e.g. 'Connect-ZBXserver' vs
# 'Connect-ZbxServer') are intentionally NOT registered: PowerShell command
# resolution is case-insensitive, so the old call sites resolve to the new
# function automatically. Registering a case-only alias collides with the
# function and breaks command resolution for both names.
Set-Alias -Name 'Get-ZBXhostinfo' -Value 'Get-ZbxHost'        -Scope Script
Set-Alias -Name 'Get-ZBXmaint'    -Value 'Get-ZbxMaintenance' -Scope Script
Set-Alias -Name 'Set-ZBXmaint'    -Value 'Set-ZbxMaintenance' -Scope Script

Export-ModuleMember -Function $Public.BaseName -Alias *
