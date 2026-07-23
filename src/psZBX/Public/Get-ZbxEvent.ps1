function Get-ZbxEvent {
    <#
    .SYNOPSIS
        Gets historical events from Zabbix server.
    .DESCRIPTION
        Queries Zabbix API (event.get) for historical trigger events including
        both active (PROBLEM) and resolved (RESOLVED) events. For current
        active problems only, use Get-ZbxProblem instead.

        Each result includes a URL field with a direct link to the event detail
        page in the Zabbix web UI (/tr_events.php), useful for clicking through
        from the console.
    .PARAMETER Severity
        Event severity level. Valid values: disaster, high, average, warning,
        information, "not classified", or * for all. Default is "disaster".
    .PARAMETER HostName
        Filter by host name. Use * for all hosts. Supports partial matching with wildcards.
        Default is * (all hosts).
    .PARAMETER Last
        Limit results to last N events. Use * for all. Default is *.
    .EXAMPLE
        Get-ZbxEvent

        Gets all disaster-level historical events (default severity).
    .EXAMPLE
        Get-ZbxEvent -Severity high -Last 10

        Gets last 10 high severity events.
    .EXAMPLE
        Get-ZbxEvent -Severity * -HostName 'web*' -Last 100

        Gets last 100 events for hosts matching 'web*' pattern.
    .EXAMPLE
        Get-ZbxEvent -Severity disaster -Last 50 | Where-Object { $_.Value -eq 'RESOLVED' }

        Gets last 50 disaster events and filters only resolved ones.
    .EXAMPLE
        Get-ZbxEvent -Severity * -Last 100 | Group-Object Value | Select-Object Name, Count

        Gets event statistics showing count of PROBLEM vs RESOLVED events.
    .EXAMPLE
        Get-ZbxEvent -Severity disaster -Last 1000 | Export-Csv -Path 'event_history.csv' -NoTypeInformation

        Exports disaster event history to CSV file for analysis.
    .OUTPUTS
        PSCustomObject[] with one object per event.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('disaster', 'high', 'average', 'warning', 'information', 'not classified', '*')]
        [string]$Severity = 'disaster',

        [Parameter()]
        [string]$HostName = '*',

        [Parameter()]
        [string]$Last = '*'
    )

    # Resolve host name to host IDs
    $hostIds = Resolve-ZbxHostId -NamePattern $HostName
    if ($hostIds -is [array] -and $hostIds.Count -eq 0) {
        Write-Warning "No hosts found matching '$HostName'."
        return
    }

    # Build API parameters for event.get (source=0/object=0 = trigger events)
    $apiParams = @{
        output      = 'extend'
        source      = 0
        object      = 0
        selectHosts = @('host', 'name')
        sortfield   = @('eventid')
        sortorder   = 'DESC'
    }

    if ($hostIds) { $apiParams['hostids'] = $hostIds }

    # Severity filter
    if ($Severity -ne '*') {
        $severityCode = Get-SeverityCode -SeverityName $Severity
        if ($severityCode -ge 0) {
            $apiParams['severities'] = @($severityCode)
        }
    }

    # Limit
    if ($Last -ne '*' -and $Last -match '^\d+$') {
        $apiParams['limit'] = [int]$Last
    }

    try {
        $events = Invoke-ZabbixAPI -Method 'event.get' -Params $apiParams

        if (-not $events -or $events.Count -eq 0) {
            Write-Verbose "No events found matching the specified criteria."
            return
        }

        # Build Zabbix UI base URL once for the per-event hyperlinks
        $baseUrl = $script:ZabbixConnection.Url -replace '/api_jsonrpc\.php/?$', ''

        foreach ($zbxEvent in $events) {
            $eventTime = Convert-UnixTimestamp -Timestamp $zbxEvent.clock
            $duration  = Get-DurationString -StartTime $eventTime

            $eventHostName = if ($zbxEvent.hosts -and $zbxEvent.hosts.Count -gt 0) {
                $zbxEvent.hosts[0].name
            } else { 'Unknown' }

            # event.value: 0 = OK/Resolved, 1 = Problem
            $eventValue = if ($zbxEvent.value -eq '1') { 'PROBLEM' } else { 'RESOLVED' }

            $eventUrl = "$baseUrl/tr_events.php?triggerid=$($zbxEvent.objectid)&eventid=$($zbxEvent.eventid)"

            [PSCustomObject]@{
                PSTypeName = 'psZBX.Event'
                EventTime  = $eventTime.ToString('yyyy-MM-dd HH:mm:ss')
                HostName   = $eventHostName
                Event      = $zbxEvent.name
                Severity   = Get-SeverityName -SeverityCode $zbxEvent.severity
                Value      = $eventValue
                Duration   = $duration
                EventID    = $zbxEvent.eventid
                URL        = $eventUrl
            }
        }
    }
    catch {
        throw "Failed to get events: $_"
    }
}
