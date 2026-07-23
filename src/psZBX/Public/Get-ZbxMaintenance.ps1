function Get-ZbxMaintenance {
    <#
    .SYNOPSIS
        Gets maintenance windows from Zabbix server.
    .DESCRIPTION
        Queries Zabbix API (maintenance.get) for maintenance windows. Returns
        rich PSCustomObject results in both default and detailed modes - the
        default returns a compact view (Name, Active since, Active till, State),
        while -Details additionally includes time periods, host groups, hosts
        and description.

        Both modes return objects that flow through the pipeline (suitable for
        Where-Object / Export-Csv / Format-Table etc.). The State column is
        calculated locally: Active (now between Active since and Active till),
        Expired (now past Active till), or Approaching (now before Active since).

        Objects carry the type name 'psZBX.Maintenance' so a
        custom Format.ps1xml can later style the State column (colors etc.).
    .PARAMETER Name
        Filter by maintenance name. Use * for all maintenances. Supports
        partial matching with wildcards. Default is * (all maintenances).
    .PARAMETER Details
        Return full maintenance information including time periods, host
        groups, hosts and description.
    .EXAMPLE
        Get-ZbxMaintenance

        Lists all maintenance windows (compact view).
    .EXAMPLE
        Get-ZbxMaintenance | Format-Table -AutoSize

        Same as above, explicitly formatted as a table.
    .EXAMPLE
        Get-ZbxMaintenance -Name 'Weekly Patching'

        Gets a specific maintenance window (exact match).
    .EXAMPLE
        Get-ZbxMaintenance -Name 'Patch*'

        Lists maintenance windows with names starting with 'Patch'.
    .EXAMPLE
        Get-ZbxMaintenance -Details

        Lists all maintenance windows with full details.
    .EXAMPLE
        Get-ZbxMaintenance -Details | Where-Object { $_.'Host groups' -like '*Linux*' }

        Finds maintenance windows applying to Linux host groups.
    .EXAMPLE
        Get-ZbxMaintenance | Where-Object { $_.State -eq 'Active' }

        Lists only currently active maintenance windows.
    .EXAMPLE
        # Manual colored output if desired
        Get-ZbxMaintenance | ForEach-Object {
            $color = switch ($_.State) {
                'Active'      { 'Green' }
                'Expired'     { 'Red' }
                'Approaching' { 'DarkYellow' }
                default       { 'Gray' }
            }
            Write-Host ('{0,-30} {1,-19} {2,-19} {3}' -f $_.Name, $_.'Active since', $_.'Active till', $_.State) -ForegroundColor $color
        }

        Replicates the legacy colored output from pre-1.0.0 versions.
    .OUTPUTS
        PSCustomObject[] with one object per maintenance window.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Name = '*',

        [Parameter()]
        [switch]$Details
    )

    $apiParams = @{
        output            = 'extend'
        selectTimeperiods = 'extend'
        selectHosts       = @('hostid', 'host', 'name')
        selectHostGroups  = @('groupid', 'name')
        selectGroups      = @('groupid', 'name')
        sortfield         = @('name')
        sortorder         = 'ASC'
    }

    # Name filter
    if ($Name -ne '*') {
        if ($Name -match '\*') {
            $searchName = $Name -replace '\*', ''
            $apiParams['search'] = @{ name = $searchName }
            $apiParams['searchWildcardsEnabled'] = $true
        }
        else {
            $apiParams['filter'] = @{ name = $Name }
        }
    }

    try {
        $maintenances = Invoke-ZabbixAPI -Method 'maintenance.get' -Params $apiParams

        if (-not $maintenances -or $maintenances.Count -eq 0) {
            Write-Verbose "No maintenance windows found matching the specified criteria."
            return
        }

        $now = Get-Date

        foreach ($maint in $maintenances) {
            $activeSince = Convert-UnixTimestamp -Timestamp $maint.active_since
            $activeTill  = Convert-UnixTimestamp -Timestamp $maint.active_till

            $state = if ($now -lt $activeSince) {
                'Approaching'
            }
            elseif ($now -le $activeTill) {
                'Active'
            }
            else {
                'Expired'
            }

            if ($Details) {
                # Human-readable period descriptions
                $periodsText = if ($maint.timeperiods -and $maint.timeperiods.Count -gt 0) {
                    $periodsList = foreach ($period in $maint.timeperiods) {
                        $periodType = switch ($period.timeperiod_type) {
                            '0'     { 'One-time' }
                            '2'     { 'Daily' }
                            '3'     { 'Weekly' }
                            '4'     { 'Monthly' }
                            default { 'Unknown' }
                        }

                        $durSec = [int]$period.period
                        $durStr = if ($durSec -ge 86400) {
                            "{0}d {1}h" -f [int]($durSec / 86400), [int](($durSec % 86400) / 3600)
                        }
                        elseif ($durSec -ge 3600) {
                            "{0}h {1}m" -f [int]($durSec / 3600), [int](($durSec % 3600) / 60)
                        }
                        else {
                            "{0}m" -f [int]($durSec / 60)
                        }

                        if ($period.timeperiod_type -eq '0') {
                            $startDate = Convert-UnixTimestamp -Timestamp $period.start_date
                            "$periodType at $($startDate.ToString('yyyy-MM-dd HH:mm')) for $durStr"
                        }
                        else {
                            $startSec = [int]$period.start_time
                            $hr = [int]($startSec / 3600)
                            $mn = [int](($startSec % 3600) / 60)
                            "$periodType at $('{0:00}:{1:00}' -f $hr, $mn) for $durStr"
                        }
                    }
                    $periodsList -join '; '
                }
                else { 'None' }

                # Host groups - prefer hostgroups (6.2+), fall back to groups
                $groupList = @()
                if ($null -ne $maint.hostgroups -and $maint.hostgroups.Count -gt 0) {
                    $groupList = $maint.hostgroups
                }
                elseif ($null -ne $maint.groups -and $maint.groups.Count -gt 0) {
                    $groupList = $maint.groups
                }
                $hostGroupsText = if ($groupList.Count -gt 0) {
                    ($groupList | ForEach-Object { $_.name }) -join ', '
                } else { 'None' }

                $hostsText = if ($maint.hosts -and $maint.hosts.Count -gt 0) {
                    ($maint.hosts | ForEach-Object { $_.name }) -join ', '
                } else { 'None' }

                [PSCustomObject]@{
                    PSTypeName     = 'psZBX.Maintenance'
                    Name           = $maint.name
                    'Active since' = $activeSince.ToString('yyyy-MM-dd HH:mm:ss')
                    'Active till'  = $activeTill.ToString('yyyy-MM-dd HH:mm:ss')
                    State          = $state
                    Periods        = $periodsText
                    'Host groups'  = $hostGroupsText
                    Hosts          = $hostsText
                    Description    = if ([string]::IsNullOrWhiteSpace($maint.description)) { 'None' } else { $maint.description }
                }
            }
            else {
                [PSCustomObject]@{
                    PSTypeName     = 'psZBX.Maintenance'
                    Name           = $maint.name
                    'Active since' = $activeSince.ToString('yyyy-MM-dd HH:mm:ss')
                    'Active till'  = $activeTill.ToString('yyyy-MM-dd HH:mm:ss')
                    State          = $state
                }
            }
        }
    }
    catch {
        throw "Failed to get maintenance information: $_"
    }
}
