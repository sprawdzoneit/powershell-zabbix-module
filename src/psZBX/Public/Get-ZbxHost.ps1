function Get-ZbxHost {
    <#
    .SYNOPSIS
        Gets host information from Zabbix server.
    .DESCRIPTION
        Queries Zabbix API for host details including templates, groups,
        interfaces, description, and tags. Returns comprehensive host
        configuration information useful for inventory and auditing.
    .PARAMETER Name
        Host name to search for. Use * to list all hosts. Supports partial
        matching with wildcards. This parameter is mandatory.
    .PARAMETER Enabled
        Filter by host enabled status. Default is $true (only enabled hosts).
        Set to $false to show disabled hosts.
    .PARAMETER Group
        Filter hosts by group name. Must be exact group name.
    .EXAMPLE
        Get-ZbxHost -Name 'app01.example.com'

        Gets detailed information about specific host (exact match).
    .EXAMPLE
        Get-ZbxHost -Name *

        Lists all enabled hosts in Zabbix.
    .EXAMPLE
        Get-ZbxHost -Name * -Enabled $false

        Lists all disabled hosts.
    .EXAMPLE
        Get-ZbxHost -Name 'web*'

        Gets hosts with names starting with 'web' (partial match).
    .EXAMPLE
        Get-ZbxHost -Name * -Group 'Linux servers'

        Lists all enabled hosts in 'Linux servers' group.
    .EXAMPLE
        Get-ZbxHost -Name * | Where-Object { $_.Templates -eq 'None' }

        Finds hosts without any templates assigned.
    .EXAMPLE
        Get-ZbxHost -Name * | Where-Object { $_.Tags -like '*environment=production*' }

        Finds all production hosts by tag.
    .OUTPUTS
        PSCustomObject[] with one object per host.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter()]
        [bool]$Enabled = $true,

        [Parameter()]
        [string]$Group
    )

    # Build API parameters
    $apiParams = @{
        output                = @('hostid', 'host', 'name', 'status', 'description')
        selectTemplates       = 'extend'
        selectParentTemplates = 'extend'
        selectGroups          = @('groupid', 'name')
        selectHostGroups      = @('groupid', 'name')
        selectInterfaces      = @('interfaceid', 'ip', 'port', 'type', 'main')
        selectTags            = @('tag', 'value')
    }

    # Host name filter
    if ($Name -ne '*') {
        if ($Name -match '\*') {
            $searchName = $Name -replace '\*', ''
            $apiParams['search'] = @{ host = $searchName }
            $apiParams['searchWildcardsEnabled'] = $true
        }
        else {
            $apiParams['filter'] = @{ host = $Name }
        }
    }

    # Enabled filter (status: 0 = enabled, 1 = disabled)
    if (-not $apiParams.ContainsKey('filter')) {
        $apiParams['filter'] = @{}
    }
    $apiParams['filter']['status'] = if ($Enabled) { 0 } else { 1 }

    # Group filter
    if ($Group) {
        $groupParams = @{
            output = @('groupid', 'name')
            filter = @{ name = $Group }
        }
        $groupResult = Invoke-ZabbixAPI -Method 'hostgroup.get' -Params $groupParams

        if ($groupResult -and $groupResult.Count -gt 0) {
            $apiParams['groupids'] = @($groupResult[0].groupid)
        }
        else {
            Write-Warning "Group '$Group' not found."
            return
        }
    }

    try {
        $hosts = Invoke-ZabbixAPI -Method 'host.get' -Params $apiParams

        if (-not $hosts -or $hosts.Count -eq 0) {
            Write-Verbose "No hosts found matching the specified criteria."
            return
        }

        foreach ($zbxHost in $hosts) {
            $enabledStatus = $zbxHost.status -eq '0'

            # Templates - prefer parentTemplates, fall back to templates
            $templateList = @()
            if ($null -ne $zbxHost.parentTemplates -and $zbxHost.parentTemplates.Count -gt 0) {
                $templateList = $zbxHost.parentTemplates
            }
            elseif ($null -ne $zbxHost.templates -and $zbxHost.templates.Count -gt 0) {
                $templateList = $zbxHost.templates
            }
            $templates = if ($templateList.Count -gt 0) {
                ($templateList | ForEach-Object { $_.name }) -join ', '
            } else { 'None' }

            # Groups - prefer hostgroups (6.2+), fall back to groups
            $groupList = @()
            if ($null -ne $zbxHost.hostgroups -and $zbxHost.hostgroups.Count -gt 0) {
                $groupList = $zbxHost.hostgroups
            }
            elseif ($null -ne $zbxHost.groups -and $zbxHost.groups.Count -gt 0) {
                $groupList = $zbxHost.groups
            }
            $groups = if ($groupList.Count -gt 0) {
                ($groupList | ForEach-Object { $_.name }) -join ', '
            } else { 'None' }

            # Interfaces
            $interfaces = if ($zbxHost.interfaces -and $zbxHost.interfaces.Count -gt 0) {
                ($zbxHost.interfaces | ForEach-Object {
                    $interfaceType = switch ($_.type) {
                        '1'     { 'Agent' }
                        '2'     { 'SNMP' }
                        '3'     { 'IPMI' }
                        '4'     { 'JMX' }
                        default { 'Unknown' }
                    }
                    "$($_.ip):$($_.port) ($interfaceType)"
                }) -join '; '
            } else { 'None' }

            # Tags
            $tags = if ($zbxHost.tags -and $zbxHost.tags.Count -gt 0) {
                ($zbxHost.tags | ForEach-Object { "$($_.tag)=$($_.value)" }) -join ', '
            } else { 'None' }

            [PSCustomObject]@{
                PSTypeName  = 'psZBX.Host'
                HostName    = $zbxHost.host
                VisibleName = $zbxHost.name
                Enabled     = $enabledStatus
                Templates   = $templates
                Groups      = $groups
                Interfaces  = $interfaces
                Description = if ([string]::IsNullOrWhiteSpace($zbxHost.description)) { 'None' } else { $zbxHost.description }
                Tags        = $tags
                HostID      = $zbxHost.hostid
            }
        }
    }
    catch {
        throw "Failed to get host information: $_"
    }
}
