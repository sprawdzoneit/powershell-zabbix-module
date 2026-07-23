function Get-ZbxProblem {
    <#
    .SYNOPSIS
        Gets current active problems from Zabbix server.
    .DESCRIPTION
        Queries Zabbix API (method problem.get) for active/unresolved problems
        with various filtering options including severity, acknowledgement
        status, host name and count limits. For historical/resolved events use
        Get-ZbxEvent instead.

        Each result includes a LastValue field with the current value of the
        trigger's first item (the value behind '{ITEM.LASTVALUE}' macro) - the
        same number you see in the "Operational data" column of the Zabbix
        Monitoring -> Problems view when the default opdata template is used.

        Each result also includes a URL field with a direct link to the event
        detail page in the Zabbix web UI (/tr_events.php), useful for clicking
        through from the console.
    .PARAMETER Severity
        Problem severity level. Valid values: disaster, high, average, warning,
        information, "not classified", or * for all. Default is "disaster".
    .PARAMETER HostName
        Filter by host name. Use * for all hosts. Supports partial matching with wildcards.
        Default is * (all hosts).
    .PARAMETER ACK
        Filter by acknowledgement status. Valid values: Acknowledged,
        Unacknowledged, or * for both. Default is *.
    .PARAMETER Last
        Limit results to last N problems. Use * for all. Default is *.
    .PARAMETER ShowSuppressed
        Include suppressed problems in results. By default suppressed problems
        are hidden.
    .EXAMPLE
        Get-ZbxProblem

        Gets all disaster-level active problems (default severity).
    .EXAMPLE
        Get-ZbxProblem -Severity high -Last 5

        Gets last 5 high severity problems.
    .EXAMPLE
        Get-ZbxProblem -Severity disaster -HostName 'webserver01.example.com'

        Gets disaster-level problems for specific host (exact match).
    .EXAMPLE
        Get-ZbxProblem -Severity * -HostName 'web*'

        Gets all problems for hosts matching pattern 'web*' (partial match).
    .EXAMPLE
        Get-ZbxProblem -Severity disaster -ACK Unacknowledged

        Gets only unacknowledged disaster problems (require attention).
    .EXAMPLE
        Get-ZbxProblem -Severity * -ShowSuppressed

        Gets all problems including suppressed (maintenance/silenced) ones.
    .EXAMPLE
        Get-ZbxProblem -Severity disaster | Export-Csv -Path 'problems.csv' -NoTypeInformation

        Exports disaster problems to CSV file.
    .EXAMPLE
        $critical = Get-ZbxProblem -Severity disaster -ACK Unacknowledged
        if ($critical) {
            Write-Host "ALERT: $($critical.Count) unacknowledged disaster problems!" -ForegroundColor Red
            $critical | Format-Table EventTime, HostName, Problem -AutoSize
        }

        Script example for monitoring unacknowledged critical issues.
    .EXAMPLE
        Get-ZbxProblem -Severity disaster -ACK Unacknowledged | ForEach-Object { Start-Process $_.URL }

        Opens every unacknowledged disaster problem in the default web browser.
    .OUTPUTS
        PSCustomObject[] with one object per problem.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('disaster', 'high', 'average', 'warning', 'information', 'not classified', '*')]
        [string]$Severity = 'disaster',

        [Parameter()]
        [string]$HostName = '*',

        [Parameter()]
        [ValidateSet('Acknowledged', 'Unacknowledged', '*')]
        [string]$ACK = '*',

        [Parameter()]
        [string]$Last = '*',

        [Parameter()]
        [switch]$ShowSuppressed
    )

    # Resolve host name to host IDs (if filtering by host)
    $hostIds = Resolve-ZbxHostId -NamePattern $HostName
    if ($hostIds -is [array] -and $hostIds.Count -eq 0) {
        Write-Warning "No hosts found matching '$HostName'."
        return
    }

    # Build API parameters
    $apiParams = @{
        output                = 'extend'
        selectTags            = 'extend'
        selectAcknowledges    = 'extend'
        selectSuppressionData = 'extend'
        sortfield             = @('eventid')
        sortorder             = 'DESC'
        recent                = $true
    }

    if ($hostIds) { $apiParams['hostids'] = $hostIds }

    # Severity filter
    if ($Severity -ne '*') {
        $severityCode = Get-SeverityCode -SeverityName $Severity
        if ($severityCode -ge 0) {
            $apiParams['severities'] = @($severityCode)
        }
    }

    # ACK filter
    if ($ACK -eq 'Acknowledged')   { $apiParams['acknowledged'] = $true  }
    if ($ACK -eq 'Unacknowledged') { $apiParams['acknowledged'] = $false }

    # Suppressed filter
    if (-not $ShowSuppressed) { $apiParams['suppressed'] = $false }

    # Limit
    if ($Last -ne '*' -and $Last -match '^\d+$') {
        $apiParams['limit'] = [int]$Last
    }

    try {
        $problems = Invoke-ZabbixAPI -Method 'problem.get' -Params $apiParams

        if (-not $problems -or $problems.Count -eq 0) {
            Write-Verbose "No problems found matching the specified criteria."
            return
        }

        # Collect unique trigger IDs to fetch host info, maintenance status and last values
        $objectIds = $problems |
            Where-Object { $_.source -eq '0' } |
            ForEach-Object { $_.objectid } |
            Select-Object -Unique

        $hostLookup        = @{}
        $maintenanceLookup = @{}
        $lastValueLookup   = @{}

        if ($objectIds -and $objectIds.Count -gt 0) {
            # selectItems="extend" returns each trigger's items so we can expose
            # the first item's lastvalue, matching the Zabbix UI "Operational data"
            # column with the default '{ITEM.LASTVALUE}' opdata template.
            $triggerParams = @{
                triggerids  = $objectIds
                output      = @('triggerid')
                selectHosts = @('hostid', 'host', 'name', 'maintenance_status', 'maintenance_from')
                selectItems = 'extend'
            }
            $triggers = Invoke-ZabbixAPI -Method 'trigger.get' -Params $triggerParams

            foreach ($trigger in $triggers) {
                if ($trigger.hosts -and $trigger.hosts.Count -gt 0) {
                    $hostLookup[$trigger.triggerid] = $trigger.hosts[0].name
                    $maintenanceLookup[$trigger.triggerid] = @{
                        InMaintenance   = $trigger.hosts[0].maintenance_status -eq '1'
                        MaintenanceFrom = $trigger.hosts[0].maintenance_from
                    }
                }
                if ($trigger.items -and $trigger.items.Count -gt 0) {
                    $firstItem = $trigger.items[0]
                    if ($null -ne $firstItem.lastvalue) {
                        $lastValueLookup[$trigger.triggerid] = [string]$firstItem.lastvalue
                    }
                }
            }
        }

        # Build Zabbix UI base URL once for the per-event hyperlinks
        $baseUrl = $script:ZabbixConnection.Url -replace '/api_jsonrpc\.php/?$', ''

        foreach ($problem in $problems) {
            $eventTime = Convert-UnixTimestamp -Timestamp $problem.clock
            $duration  = Get-DurationString -StartTime $eventTime

            $problemHostName = if ($hostLookup.ContainsKey($problem.objectid)) {
                $hostLookup[$problem.objectid]
            } else { 'Unknown' }

            $ackStatus = if ($problem.acknowledged -eq '1') { 'Acknowledged' } else { 'Unacknowledged' }

            $problemStatus = if ($problem.r_eventid -and $problem.r_eventid -ne '0') {
                'RESOLVED'
            } else { 'PROBLEM' }

            # Suppressed status, with end-time if available
            $suppressedInfo = 'No'
            if ($problem.suppressed -eq '1') {
                $suppressedInfo = 'Yes'
                if ($problem.suppression_data -and $problem.suppression_data.Count -gt 0) {
                    $suppData = $problem.suppression_data | Select-Object -First 1
                    if ($suppData.suppress_until -and $suppData.suppress_until -ne '0') {
                        $suppressUntil = Convert-UnixTimestamp -Timestamp $suppData.suppress_until
                        $suppressedInfo = "Yes (till: $($suppressUntil.ToString('yyyy-MM-dd HH:mm')))"
                    }
                }
            }

            # Maintenance status, with start-time if available
            $maintenanceInfo = 'No'
            if ($maintenanceLookup.ContainsKey($problem.objectid)) {
                $maintData = $maintenanceLookup[$problem.objectid]
                if ($maintData.InMaintenance) {
                    $maintenanceInfo = 'Yes'
                    if ($maintData.MaintenanceFrom -and $maintData.MaintenanceFrom -ne '0') {
                        $maintFrom = Convert-UnixTimestamp -Timestamp $maintData.MaintenanceFrom
                        $maintenanceInfo = "Yes (since: $($maintFrom.ToString('yyyy-MM-dd HH:mm')))"
                    }
                }
            }

            $problemUrl = "$baseUrl/tr_events.php?triggerid=$($problem.objectid)&eventid=$($problem.eventid)"

            $lastValue = if ($lastValueLookup.ContainsKey($problem.objectid)) {
                $lastValueLookup[$problem.objectid]
            } else { '' }

            [PSCustomObject]@{
                PSTypeName  = 'psZBX.Problem'
                EventTime   = $eventTime.ToString('yyyy-MM-dd HH:mm:ss')
                HostName    = $problemHostName
                Problem     = $problem.name
                LastValue   = $lastValue
                Severity    = Get-SeverityName -SeverityCode $problem.severity
                Status      = $problemStatus
                ACK         = $ackStatus
                Duration    = $duration
                Suppressed  = $suppressedInfo
                Maintenance = $maintenanceInfo
                EventID     = $problem.eventid
                URL         = $problemUrl
            }
        }
    }
    catch {
        throw "Failed to get problems: $_"
    }
}
