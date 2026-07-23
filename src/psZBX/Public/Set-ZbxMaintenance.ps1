function Set-ZbxMaintenance {
    <#
    .SYNOPSIS
        Updates the active window of an existing maintenance in Zabbix.
    .DESCRIPTION
        Quickly modifies an existing maintenance window's active period.
        Looks up the maintenance by exact name, updates its ActiveSince and
        ActiveTill timestamps, and regenerates time-periods as a single
        one-time entry that matches the new active window. Hosts, host groups,
        name, description and maintenance type are preserved from the existing
        maintenance configuration.

        Designed for the common "quick reschedule" scenario where you need to
        shift, extend or trigger an existing maintenance window without
        opening the Zabbix UI. For complex recurring period configurations
        (daily/weekly/monthly schedules) please use the Zabbix UI instead.
    .PARAMETER Name
        Exact name of the existing maintenance window to update. Mandatory.
    .PARAMETER ActiveSince
        New start time of the maintenance window in format 'yyyy-MM-dd HH:mm'.
        Defaults to current date and time when the cmdlet is invoked.
    .PARAMETER ActiveTill
        New end time of the maintenance window in format 'yyyy-MM-dd HH:mm'.
        Defaults to ActiveSince + 1 hour when not specified.
    .EXAMPLE
        Set-ZbxMaintenance -Name 'Weekly Patching'

        Updates 'Weekly Patching' to start now and end 1 hour later.
        Useful for triggering a pre-configured maintenance immediately.
    .EXAMPLE
        Set-ZbxMaintenance -Name 'Emergency Window' -ActiveTill '2026-05-20 22:00'

        Updates maintenance to start now and end at the specified time.
    .EXAMPLE
        Set-ZbxMaintenance -Name 'DB Migration' -ActiveSince '2026-05-25 18:00' -ActiveTill '2026-05-26 06:00'

        Schedules maintenance for a specific 12-hour window in the future.
    .EXAMPLE
        # Extend a currently active maintenance by 2 more hours
        $maint   = Get-ZbxMaintenance -Name 'Server Patch' -Details
        $newTill = ([DateTime]$maint.'Active till').AddHours(2).ToString('yyyy-MM-dd HH:mm')
        Set-ZbxMaintenance -Name 'Server Patch' -ActiveSince $maint.'Active since' -ActiveTill $newTill

        Reads the current window and extends Active till by 2 hours.
    .NOTES
        Time-periods design choice:
        Set-ZbxMaintenance intentionally does NOT expose Zabbix's full
        time-period configuration (timeperiod_type, every, dayofweek, month,
        day, start_time). Instead it always generates a single ONE-TIME period
        that spans the entire ActiveSince -> ActiveTill window. This matches
        the "quick set" use case and keeps the cmdlet simple.

        IMPORTANT: Existing time-periods on the maintenance are replaced by
        the generated one-time period. If the maintenance had recurring
        (daily/weekly/monthly) periods configured, they will be lost after
        running Set-ZbxMaintenance. Use the Zabbix UI for maintenances that
        must keep their recurring schedule.
    .OUTPUTS
        PSCustomObject describing the updated maintenance window.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [string]$ActiveSince = (Get-Date -Format 'yyyy-MM-dd HH:mm'),

        [Parameter()]
        [string]$ActiveTill
    )

    # Parse ActiveSince (accepts 'yyyy-MM-dd HH:mm' primarily, falls back to general parse)
    $sinceDate = $null
    try   { $sinceDate = [DateTime]::ParseExact($ActiveSince, 'yyyy-MM-dd HH:mm', $null) }
    catch {
        try   { $sinceDate = [DateTime]::Parse($ActiveSince) }
        catch { throw "Invalid ActiveSince date format: '$ActiveSince'. Expected format: yyyy-MM-dd HH:mm" }
    }

    # Resolve ActiveTill: default to ActiveSince + 1 hour when not provided
    $tillDate = $null
    if ([string]::IsNullOrWhiteSpace($ActiveTill)) {
        $tillDate = $sinceDate.AddHours(1)
    }
    else {
        try   { $tillDate = [DateTime]::ParseExact($ActiveTill, 'yyyy-MM-dd HH:mm', $null) }
        catch {
            try   { $tillDate = [DateTime]::Parse($ActiveTill) }
            catch { throw "Invalid ActiveTill date format: '$ActiveTill'. Expected format: yyyy-MM-dd HH:mm" }
        }
    }

    if ($tillDate -le $sinceDate) {
        throw "ActiveTill ($($tillDate.ToString('yyyy-MM-dd HH:mm'))) must be later than ActiveSince ($($sinceDate.ToString('yyyy-MM-dd HH:mm'))). Provide a wider window."
    }

    # Look up the existing maintenance by exact name
    $lookupParams = @{
        output           = 'extend'
        selectHosts      = @('hostid')
        selectHostGroups = @('groupid')
        selectGroups     = @('groupid')
        filter           = @{ name = $Name }
    }
    $existing = Invoke-ZabbixAPI -Method 'maintenance.get' -Params $lookupParams

    if (-not $existing -or $existing.Count -eq 0) {
        throw "Maintenance '$Name' not found in Zabbix."
    }
    if ($existing.Count -gt 1) {
        throw "Multiple maintenances found with name '$Name'. Cannot update reliably - please ensure unique names."
    }

    $maint = $existing[0]

    # Convert parsed local times to Unix timestamps (UTC seconds since epoch)
    $epoch     = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $sinceUnix = [int64](($sinceDate.ToUniversalTime() - $epoch).TotalSeconds)
    $tillUnix  = [int64](($tillDate.ToUniversalTime()  - $epoch).TotalSeconds)
    $periodSec = $tillUnix - $sinceUnix

    # Preserve existing hosts and host groups - if not re-supplied, Zabbix may clear them
    $groupRefs = @()
    if ($maint.hostgroups -and $maint.hostgroups.Count -gt 0) {
        $groupRefs = @($maint.hostgroups | ForEach-Object { @{ groupid = $_.groupid } })
    }
    elseif ($maint.groups -and $maint.groups.Count -gt 0) {
        $groupRefs = @($maint.groups | ForEach-Object { @{ groupid = $_.groupid } })
    }

    $hostRefs = @()
    if ($maint.hosts -and $maint.hosts.Count -gt 0) {
        $hostRefs = @($maint.hosts | ForEach-Object { @{ hostid = $_.hostid } })
    }

    if ($groupRefs.Count -eq 0 -and $hostRefs.Count -eq 0) {
        throw "Maintenance '$Name' has no hosts or host groups assigned. At least one is required by Zabbix."
    }

    # Build update payload with a single one-time period that matches the new window
    $updateParams = @{
        maintenanceid = $maint.maintenanceid
        active_since  = $sinceUnix
        active_till   = $tillUnix
        timeperiods   = @(
            @{
                timeperiod_type = 0          # 0 = one-time
                start_date      = $sinceUnix
                period          = $periodSec
            }
        )
    }

    if ($groupRefs.Count -gt 0) { $updateParams['groups'] = $groupRefs }
    if ($hostRefs.Count -gt 0)  { $updateParams['hosts']  = $hostRefs  }

    try {
        $result = Invoke-ZabbixAPI -Method 'maintenance.update' -Params $updateParams

        # Human-readable duration
        $durStr = if ($periodSec -ge 86400) {
            "{0}d {1}h" -f [int]($periodSec / 86400), [int](($periodSec % 86400) / 3600)
        }
        elseif ($periodSec -ge 3600) {
            "{0}h {1}m" -f [int]($periodSec / 3600), [int](($periodSec % 3600) / 60)
        }
        else {
            "{0}m" -f [int]($periodSec / 60)
        }

        [PSCustomObject]@{
            PSTypeName     = 'psZBX.MaintenanceUpdate'
            Name           = $Name
            MaintenanceID  = $result.maintenanceids[0]
            'Active since' = $sinceDate.ToString('yyyy-MM-dd HH:mm:ss')
            'Active till'  = $tillDate.ToString('yyyy-MM-dd HH:mm:ss')
            Duration       = $durStr
            Status         = 'Updated'
        }
    }
    catch {
        throw "Failed to update maintenance '$Name': $_"
    }
}
