#Requires -Version 5.1
<#
.SYNOPSIS
    PowerShell module for querying Zabbix server via API.
.DESCRIPTION
    This module provides cmdlets to connect to Zabbix server and query
    problems, events, and host information using Zabbix API.
.NOTES
    Author: Łukasz Huk  / sprawdzone.it
    Website: https://sprawdzone.it
    GitHub: https://github.com/sprawdzoneit/PowerShell-Zabbix-Module
    Version: 1.0.0
#>

# Module-level variables to store connection info
$script:ZabbixConnection = @{
    Token     = $null
    Url       = $null
    Connected = $false
}

#region Helper Functions

function Invoke-ZabbixAPI {
    <#
    .SYNOPSIS
        Internal helper function to make Zabbix API calls.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Method,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Params = @{}
    )
    
    if (-not $script:ZabbixConnection.Connected) {
        throw "Not connected to Zabbix server. Use Connect-ZBXserver first."
    }
    
    $body = @{
        jsonrpc = "2.0"
        method  = $Method
        params  = $Params
        auth    = $script:ZabbixConnection.Token
        id      = 1
    } | ConvertTo-Json -Depth 10
    
    try {
        $response = Invoke-RestMethod -Uri $script:ZabbixConnection.Url -Method Post -Body $body -ContentType "application/json-rpc"
        
        if ($response.error) {
            throw "Zabbix API Error: $($response.error.message) - $($response.error.data)"
        }
        
        return $response.result
    }
    catch {
        throw "Failed to call Zabbix API: $_"
    }
}

function Convert-UnixTimestamp {
    <#
    .SYNOPSIS
        Internal helper function to convert Unix timestamp to DateTime.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Timestamp
    )
    
    $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    return $epoch.AddSeconds([int64]$Timestamp).ToLocalTime()
}

function Get-DurationString {
    <#
    .SYNOPSIS
        Internal helper function to calculate duration from timestamp to now and returns formatted string.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [DateTime]$StartTime
    )
    
    $duration = (Get-Date) - $StartTime
    
    if ($duration.TotalDays -ge 1) {
        return "{0}d {1}h {2}m" -f [int]$duration.TotalDays, $duration.Hours, $duration.Minutes
    }
    elseif ($duration.TotalHours -ge 1) {
        return "{0}h {1}m" -f [int]$duration.TotalHours, $duration.Minutes
    }
    else {
        return "{0}m {1}s" -f [int]$duration.TotalMinutes, $duration.Seconds
    }
}

function Get-SeverityName {
    <#
    .SYNOPSIS
        Internal helper function to convert severity number to name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SeverityCode
    )
    
    switch ($SeverityCode) {
        "0" { return "Not classified" }
        "1" { return "Information" }
        "2" { return "Warning" }
        "3" { return "Average" }
        "4" { return "High" }
        "5" { return "Disaster" }
        default { return "Unknown" }
    }
}

function Get-SeverityCode {
    <#
    .SYNOPSIS
        Internal helper function to convert severity name to code.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SeverityName
    )
    
    switch ($SeverityName.ToLower()) {
        "not classified" { return 0 }
        "notclassified" { return 0 }
        "information" { return 1 }
        "warning" { return 2 }
        "average" { return 3 }
        "high" { return 4 }
        "disaster" { return 5 }
        default { return -1 }
    }
}

#endregion

#region Public Functions

function Connect-ZBXserver {
    <#
    .SYNOPSIS
        Connects to a Zabbix server using API token.
    .DESCRIPTION
        Establishes connection to Zabbix server and validates the API token.
        Connection information is stored for subsequent API calls.
    .PARAMETER Token
        Zabbix API token for authentication.
    .PARAMETER Url
        Zabbix API URL endpoint.
    .EXAMPLE
        Connect-ZBXserver
        
        Connects using default token and URL (zbx.sprawdzone.it).
        Returns connection status and Zabbix version.
    .EXAMPLE
        
    
        $token = "be7122ff61d8ccacb2dd2b26c427fe30740145eed45f2b4b1673cfe55869t653"
        $Url "https://zabbix.sprawdzone.it/api_jsonrpc.php"
        Connect-ZBXserver -Token $token -Url $url
        Connects to custom Zabbix server with variables.

        Connect-ZBXserver -Token "be7122ff61d8ccacb2dd2b26c427fe30740145eed45f2b4b1673cfe55869t653" -Url "https://zabbix.sprawdzone.it/api_jsonrpc.php"
        Connects to custom Zabbix server with specified API token.

        Connect-ZBXserver
        Connects to default Zabbix server with hardcoded token and URL in THIS MODULE file

    .EXAMPLE
        $connection = Connect-ZBXserver
        if ($connection.Connected) {
            Write-Host "Connected to Zabbix $($connection.ZabbixVersion)"
        }
        
        Connects and checks connection status programmatically.
    .EXAMPLE
        Connect-ZBXserver | Format-List
        
        Connected     : True
        Url           : https://zabbix.sprawdzone.it/api_jsonrpc.php
        ZabbixVersion : 7.0.0
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Token = 'be7122ff61d8ccacb2dd2b26c427fe30740145eed45f2b4b1673cfe55869t653',
        
        [Parameter(Mandatory = $false)]
        [string]$Url = 'https://zbx.it-partner.pl/api_jsonrpc.php'
    )
    
    # Store connection info temporarily
    $script:ZabbixConnection.Token = $Token
    $script:ZabbixConnection.Url = $Url
    $script:ZabbixConnection.Connected = $true
    
    # Test connection by calling api.version (doesn't require auth but validates URL)
    # Then validate token with a simple authenticated call
    $body = @{
        jsonrpc = "2.0"
        method  = "apiinfo.version"
        params  = @{}
        id      = 1
    } | ConvertTo-Json
    
    try {
        $versionResponse = Invoke-RestMethod -Uri $Url -Method Post -Body $body -ContentType "application/json-rpc"
        
        if ($versionResponse.error) {
            $script:ZabbixConnection.Connected = $false
            [PSCustomObject]@{
                Connected = $false
                Url       = $Url
                Message   = "API Error: $($versionResponse.error.message)"
            }
            return
        }
        
        # Validate token with authenticated call
        $authBody = @{
            jsonrpc = "2.0"
            method  = "host.get"
            params  = @{
                limit  = 1
                output = @("hostid")
            }
            auth    = $Token
            id      = 2
        } | ConvertTo-Json
        
        $authResponse = Invoke-RestMethod -Uri $Url -Method Post -Body $authBody -ContentType "application/json-rpc"
        
        if ($authResponse.error) {
            $script:ZabbixConnection.Connected = $false
            [PSCustomObject]@{
                Connected = $false
                Url       = $Url
                Message   = "Authentication failed: $($authResponse.error.message)"
            }
            return
        }
        
        [PSCustomObject]@{
            Connected     = $true
            Url           = $Url
            ZabbixVersion = $versionResponse.result
        }
    }
    catch {
        $script:ZabbixConnection.Connected = $false
        [PSCustomObject]@{
            Connected = $false
            Url       = $Url
            Message   = "Connection failed: $_"
        }
    }
}

function Disconnect-ZBXserver {
    <#
    .SYNOPSIS
        Disconnects from a Zabbix server.
    .DESCRIPTION
        The Disconnect-ZBXserver function clears the local session information
        and optionally sends a logout request to the Zabbix server API.
        Note: API token-based authentication doesn't require server-side logout,
        but this function clears local session data.
    .EXAMPLE
        Disconnect-ZBXserver
        
        Disconnects from the current Zabbix server session.
    .EXAMPLE
        Disconnect-ZBXserver | Format-List
        
        Disconnected : True
        Url          : https://zbx.sprawdzone.it/api_jsonrpc.php
        Message      : Successfully disconnected from Zabbix server
    .EXAMPLE
        # Full session workflow
        Connect-ZBXserver
        Get-ZBXproblem -Severity disaster -Last 5
        Disconnect-ZBXserver
        
        Connects, retrieves problems, then disconnects cleanly.
    .EXAMPLE
        # Verify disconnection
        Disconnect-ZBXserver
        Get-ZBXproblem  # This will throw error: "Not connected to Zabbix server"
        
        After disconnect, all queries require reconnection.
    .INPUTS
        This function requires no inputs.
    .OUTPUTS
        Returns disconnection status object with Disconnected, Url, and Message properties.
    #>
    [CmdletBinding()]
    param()
    
    if (-not $script:ZabbixConnection.Connected) {
        Write-Warning "No active Zabbix session found."
        [PSCustomObject]@{
            Disconnected = $false
            Message      = "No active session to disconnect"
        }
        return
    }
    
    $previousUrl = $script:ZabbixConnection.Url
    
    # Clear session data
    $script:ZabbixConnection.Token = $null
    $script:ZabbixConnection.Url = $null
    $script:ZabbixConnection.Connected = $false
    
    [PSCustomObject]@{
        Disconnected = $true
        Url          = $previousUrl
        Message      = "Successfully disconnected from Zabbix server"
    }
}

function Get-ZBXproblem {
    <#
    .SYNOPSIS
        Gets current active problems from Zabbix server.
    .DESCRIPTION
        Queries Zabbix API (method problem.get) for active/unresolved problems with various 
        filtering options including severity, acknowledgement status, and count limits.
        For historical/resolved events use Get-ZBXevent instead.
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
        Get-ZBXproblem
        
        Gets all disaster-level active problems (default severity).
    .EXAMPLE
        Get-ZBXproblem -Severity high -Last 5
        
        Gets last 5 high severity problems.
    .EXAMPLE
        Get-ZBXproblem -Severity * -Last 10
        
        Gets last 10 problems of any severity level.
    .EXAMPLE
        Get-ZBXproblem -Severity disaster -HostName "webserver01.domain.local"
        
        Gets disaster-level problems for specific host (exact match).
    .EXAMPLE
        Get-ZBXproblem -Severity * -HostName "web*"
        
        Gets all problems for hosts matching pattern "web*" (partial match).
    .EXAMPLE
        Get-ZBXproblem -Severity * -HostName "*prod*"
        
        Gets all problems for hosts containing "prod" in name.
    .EXAMPLE
        Get-ZBXproblem -Severity disaster -ACK Unacknowledged
        
        Gets only unacknowledged disaster problems (require attention).
    .EXAMPLE
        Get-ZBXproblem -Severity * -ACK Acknowledged -Last 20
        
        Gets last 20 acknowledged problems of any severity.
    .EXAMPLE
        Get-ZBXproblem -Severity * -ShowSuppressed
        
        Gets all problems including suppressed (maintenance/silenced) ones.
    .EXAMPLE
        Get-ZBXproblem -Severity disaster -ShowSuppressed | Where-Object { $_.Suppressed -like "Yes*" }
        
        Gets only suppressed disaster problems.
    .EXAMPLE
        Get-ZBXproblem -Severity * | Format-Table -AutoSize
        
        Gets all problems and displays in table format.
    .EXAMPLE
        Get-ZBXproblem -Severity disaster | Export-Csv -Path "problems.csv" -NoTypeInformation
        
        Exports disaster problems to CSV file.
    .EXAMPLE
        # Monitor critical problems
        $critical = Get-ZBXproblem -Severity disaster -ACK Unacknowledged
        if ($critical) {
            Write-Host "ALERT: $($critical.Count) unacknowledged disaster problems!" -ForegroundColor Red
            $critical | Format-Table EventTime, HostName, Problem -AutoSize
        }
        
        Script example for monitoring unacknowledged critical issues.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("disaster", "high", "average", "warning", "information", "not classified", "*")]
        [string]$Severity = "disaster",
        
        [Parameter(Mandatory = $false)]
        [string]$HostName = "*",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Acknowledged", "Unacknowledged", "*")]
        [string]$ACK = "*",
        
        [Parameter(Mandatory = $false)]
        [string]$Last = "*",
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowSuppressed
    )
    
    if (-not $script:ZabbixConnection.Connected) {
        throw "Not connected to Zabbix server. Use Connect-ZBXserver first."
    }
    
    # If hostname filter specified, get host IDs first
    $hostIds = $null
    if ($HostName -ne "*") {
        $hostParams = @{
            output = @("hostid")
        }
        
        # Check if it's a wildcard search or exact match
        if ($HostName -match '\*') {
            # Wildcard search - use search with partial matching
            $searchName = $HostName -replace '\*', ''
            $hostParams["search"] = @{ host = $searchName }
        }
        else {
            # Exact match
            $hostParams["filter"] = @{ host = $HostName }
        }
        
        $hostsResult = Invoke-ZabbixAPI -Method "host.get" -Params $hostParams
        if ($hostsResult -and $hostsResult.Count -gt 0) {
            $hostIds = $hostsResult | ForEach-Object { $_.hostid }
        }
        else {
            Write-Host "No hosts found matching '$HostName'." -ForegroundColor Yellow
            return
        }
    }
    
    # Build API parameters
    $apiParams = @{
        output                = "extend"
        selectTags            = "extend"
        selectAcknowledges    = "extend"
        selectSuppressionData = "extend"
        sortfield             = @("eventid")
        sortorder             = "DESC"
        recent                = $true
    }
    
    # Add host filter if specified
    if ($hostIds) {
        $apiParams["hostids"] = $hostIds
    }
    
    # Severity filter
    if ($Severity -ne "*") {
        $severityCode = Get-SeverityCode -SeverityName $Severity
        if ($severityCode -ge 0) {
            $apiParams["severities"] = @($severityCode)
        }
    }
    
    # ACK filter
    if ($ACK -eq "Acknowledged") {
        $apiParams["acknowledged"] = $true
    }
    elseif ($ACK -eq "Unacknowledged") {
        $apiParams["acknowledged"] = $false
    }
    
    # Suppressed filter
    if (-not $ShowSuppressed) {
        $apiParams["suppressed"] = $false
    }
    
    # Limit results
    if ($Last -ne "*" -and $Last -match '^\d+$') {
        $apiParams["limit"] = [int]$Last
    }
    
    try {
        $problems = Invoke-ZabbixAPI -Method "problem.get" -Params $apiParams
        
        if (-not $problems -or $problems.Count -eq 0) {
            Write-Host "No problems found matching the specified criteria." -ForegroundColor Green
            return
        }
        
        # Collect unique object IDs (triggers) to get host information
        $objectIds = $problems | Where-Object { $_.source -eq "0" } | ForEach-Object { $_.objectid } | Select-Object -Unique
        
        # Get triggers with host information including maintenance status
        $hostLookup = @{}
        $maintenanceLookup = @{}
        if ($objectIds -and $objectIds.Count -gt 0) {
            $triggerParams = @{
                triggerids  = $objectIds
                output      = @("triggerid")
                selectHosts = @("hostid", "host", "name", "maintenance_status", "maintenance_from")
            }
            $triggers = Invoke-ZabbixAPI -Method "trigger.get" -Params $triggerParams
            
            foreach ($trigger in $triggers) {
                if ($trigger.hosts -and $trigger.hosts.Count -gt 0) {
                    $hostLookup[$trigger.triggerid] = $trigger.hosts[0].name
                    # maintenance_status: 0 = no maintenance, 1 = in maintenance
                    $maintenanceLookup[$trigger.triggerid] = @{
                        InMaintenance   = $trigger.hosts[0].maintenance_status -eq "1"
                        MaintenanceFrom = $trigger.hosts[0].maintenance_from
                    }
                }
            }
        }
        
        # Build results
        $results = foreach ($problem in $problems) {
            $eventTime = Convert-UnixTimestamp -Timestamp $problem.clock
            $duration = Get-DurationString -StartTime $eventTime
            
            # Get host name from lookup
            $problemHostName = if ($hostLookup.ContainsKey($problem.objectid)) {
                $hostLookup[$problem.objectid]
            }
            else {
                "Unknown"
            }
            
            # Get acknowledgement status
            $ackStatus = if ($problem.acknowledged -eq "1") {
                "Acknowledged"
            }
            else {
                "Unacknowledged"
            }
            
            # Get problem status
            $problemStatus = if ($problem.r_eventid -and $problem.r_eventid -ne "0") {
                "RESOLVED"
            }
            else {
                "PROBLEM"
            }
            
            # Get suppressed status with details
            $suppressedInfo = "No"
            if ($problem.suppressed -eq "1") {
                $suppressedInfo = "Yes"
                # Check suppression data for end time
                if ($problem.suppression_data -and $problem.suppression_data.Count -gt 0) {
                    $suppData = $problem.suppression_data | Select-Object -First 1
                    if ($suppData.suppress_until -and $suppData.suppress_until -ne "0") {
                        $suppressUntil = Convert-UnixTimestamp -Timestamp $suppData.suppress_until
                        $suppressedInfo = "Yes (till: $($suppressUntil.ToString('yyyy-MM-dd HH:mm')))"
                    }
                }
            }
            
            # Get maintenance status
            $maintenanceInfo = "No"
            if ($maintenanceLookup.ContainsKey($problem.objectid)) {
                $maintData = $maintenanceLookup[$problem.objectid]
                if ($maintData.InMaintenance) {
                    $maintenanceInfo = "Yes"
                    if ($maintData.MaintenanceFrom -and $maintData.MaintenanceFrom -ne "0") {
                        $maintFrom = Convert-UnixTimestamp -Timestamp $maintData.MaintenanceFrom
                        $maintenanceInfo = "Yes (since: $($maintFrom.ToString('yyyy-MM-dd HH:mm')))"
                    }
                }
            }
            
            [PSCustomObject]@{
                EventTime   = $eventTime.ToString("yyyy-MM-dd HH:mm:ss")
                HostName    = $problemHostName
                Problem     = $problem.name
                Severity    = Get-SeverityName -SeverityCode $problem.severity
                Status      = $problemStatus
                ACK         = $ackStatus
                Duration    = $duration
                Suppressed  = $suppressedInfo
                Maintenance = $maintenanceInfo
                EventID     = $problem.eventid
            }
        }
        
        return $results
    }
    catch {
        throw "Failed to get problems: $_"
    }
}

function Get-ZBXevent {
    <#
    .SYNOPSIS
        Gets historical events from Zabbix server.
    .DESCRIPTION
        Queries Zabbix API (event.get) for historical trigger events including 
        both active (PROBLEM) and resolved (RESOLVED) events. For current active 
        problems only, use Get-ZBXproblem instead.
        
        Unlike Get-ZBXproblem, this function shows complete event history including
        when problems were resolved.
    .PARAMETER Severity
        Event severity level. Valid values: disaster, high, average, warning, 
        information, "not classified", or * for all. Default is "disaster".
    .PARAMETER HostName
        Filter by host name. Use * for all hosts. Supports partial matching with wildcards.
        Default is * (all hosts).
    .PARAMETER Last
        Limit results to last N events. Use * for all. Default is *.
    .EXAMPLE
        Get-ZBXevent
        
        Gets all disaster-level historical events (default severity).
    .EXAMPLE
        Get-ZBXevent -Severity high -Last 10
        
        Gets last 10 high severity events.
    .EXAMPLE
        Get-ZBXevent -Severity * -Last 50
        
        Gets last 50 events of all severity levels.
    .EXAMPLE
        Get-ZBXevent -Severity disaster -HostName "dbserver01.domain.local" -Last 20
        
        Gets last 20 disaster events for specific host.
    .EXAMPLE
        Get-ZBXevent -Severity * -HostName "web*" -Last 100
        
        Gets last 100 events for hosts matching "web*" pattern.
    .EXAMPLE
        Get-ZBXevent -Severity * -HostName "*prod*"
        
        Gets all events for hosts containing "prod" in name.
    .EXAMPLE
        Get-ZBXevent -Severity disaster -Last 50 | Where-Object { $_.Value -eq "RESOLVED" }
        
        Gets last 50 disaster events and filters only resolved ones.
    .EXAMPLE
        Get-ZBXevent -Severity * -Last 100 | Group-Object Value | Select-Object Name, Count
        
        Gets event statistics showing count of PROBLEM vs RESOLVED events.
    .EXAMPLE
        Get-ZBXevent -Severity * -Last 100 | Format-Table -AutoSize
        
        Gets last 100 events and displays in table format.
    .EXAMPLE
        Get-ZBXevent -Severity disaster -Last 1000 | Export-Csv -Path "event_history.csv" -NoTypeInformation
        
        Exports disaster event history to CSV file for analysis.
    .EXAMPLE
        # Compare active vs resolved events for a host
        $events = Get-ZBXevent -Severity * -HostName "server01" -Last 50
        $problems = $events | Where-Object { $_.Value -eq "PROBLEM" }
        $resolved = $events | Where-Object { $_.Value -eq "RESOLVED" }
        Write-Host "Problems: $($problems.Count), Resolved: $($resolved.Count)"
        
        Script example for analyzing event history.
    .EXAMPLE
        # Daily event report
        $today = Get-ZBXevent -Severity disaster -Last 100
        $today | Group-Object HostName | Sort-Object Count -Descending | 
            Select-Object Name, Count | Format-Table -AutoSize
        
        Shows which hosts had most disaster events.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("disaster", "high", "average", "warning", "information", "not classified", "*")]
        [string]$Severity = "disaster",
        
        [Parameter(Mandatory = $false)]
        [string]$HostName = "*",
        
        [Parameter(Mandatory = $false)]
        [string]$Last = "*"
    )
    
    if (-not $script:ZabbixConnection.Connected) {
        throw "Not connected to Zabbix server. Use Connect-ZBXserver first."
    }
    
    # If hostname filter specified, get host IDs first
    $hostIds = $null
    if ($HostName -ne "*") {
        $hostParams = @{
            output = @("hostid")
        }
        
        # Check if it's a wildcard search or exact match
        if ($HostName -match '\*') {
            # Wildcard search - use search with partial matching
            $searchName = $HostName -replace '\*', ''
            $hostParams["search"] = @{ host = $searchName }
        }
        else {
            # Exact match
            $hostParams["filter"] = @{ host = $HostName }
        }
        
        $hostsResult = Invoke-ZabbixAPI -Method "host.get" -Params $hostParams
        if ($hostsResult -and $hostsResult.Count -gt 0) {
            $hostIds = $hostsResult | ForEach-Object { $_.hostid }
        }
        else {
            Write-Host "No hosts found matching '$HostName'." -ForegroundColor Yellow
            return
        }
    }
    
    # Build API parameters for event.get
    $apiParams = @{
        output      = "extend"
        source      = 0           # Trigger events
        object      = 0           # Triggers
        selectHosts = @("host", "name")
        sortfield   = @("eventid")
        sortorder   = "DESC"
    }
    
    # Add host filter if specified
    if ($hostIds) {
        $apiParams["hostids"] = $hostIds
    }
    
    # Severity filter
    if ($Severity -ne "*") {
        $severityCode = Get-SeverityCode -SeverityName $Severity
        if ($severityCode -ge 0) {
            $apiParams["severities"] = @($severityCode)
        }
    }
    
    # Limit results
    if ($Last -ne "*" -and $Last -match '^\d+$') {
        $apiParams["limit"] = [int]$Last
    }
    
    try {
        $events = Invoke-ZabbixAPI -Method "event.get" -Params $apiParams
        
        if (-not $events -or $events.Count -eq 0) {
            Write-Host "No events found matching the specified criteria." -ForegroundColor Green
            return
        }
        
        # Build results
        $results = foreach ($event in $events) {
            $eventTime = Convert-UnixTimestamp -Timestamp $event.clock
            $duration = Get-DurationString -StartTime $eventTime
            
            # Get host name
            $eventHostName = if ($event.hosts -and $event.hosts.Count -gt 0) {
                $event.hosts[0].name
            }
            else {
                "Unknown"
            }
            
            # Get event value (0 = OK/Resolved, 1 = Problem)
            $eventValue = if ($event.value -eq "1") {
                "PROBLEM"
            }
            else {
                "RESOLVED"
            }
            
            [PSCustomObject]@{
                EventTime = $eventTime.ToString("yyyy-MM-dd HH:mm:ss")
                HostName  = $eventHostName
                Event     = $event.name
                Severity  = Get-SeverityName -SeverityCode $event.severity
                Value     = $eventValue
                Duration  = $duration
                EventID   = $event.eventid
            }
        }
        
        return $results
    }
    catch {
        throw "Failed to get events: $_"
    }
}

function Get-ZBXhostinfo {
    <#
    .SYNOPSIS
        Gets host information from Zabbix server.
    .DESCRIPTION
        Queries Zabbix API for host details including templates, groups,
        interfaces, description, and tags. Returns comprehensive host configuration
        information useful for inventory and auditing.
    .PARAMETER Name
        Host name to search for. Use * to list all hosts. Supports partial matching
        with wildcards. This parameter is mandatory.
    .PARAMETER Enabled
        Filter by host enabled status. Default is $true (only enabled hosts).
        Set to $false to show disabled hosts.
    .PARAMETER Group
        Filter hosts by group name. Must be exact group name.
    .EXAMPLE
        Get-ZBXhostinfo -Name "app01.sprawdzone.it"
        
        Gets detailed information about specific host (exact match).
    .EXAMPLE
        Get-ZBXhostinfo -Name *
        
        Lists all enabled hosts in Zabbix.
    .EXAMPLE
        Get-ZBXhostinfo -Name * -Enabled $false
        
        Lists all disabled hosts.
    .EXAMPLE
        Get-ZBXhostinfo -Name "web*"
        
        Gets hosts with names starting with "web" (partial match).
    .EXAMPLE
        Get-ZBXhostinfo -Name "*prod*"
        
        Gets hosts containing "prod" in name.
    .EXAMPLE
        Get-ZBXhostinfo -Name * -Group "Linux servers"
        
        Lists all enabled hosts in "Linux servers" group.
    .EXAMPLE
        Get-ZBXhostinfo -Name "db*" -Group "Databases" -Enabled $true
        
        Gets enabled hosts starting with "db" in "Databases" group.
    .EXAMPLE
        Get-ZBXhostinfo -Name * | Format-Table HostName, Enabled, Templates -AutoSize
        
        Lists all hosts showing name, status and templates in table format.
    .EXAMPLE
        Get-ZBXhostinfo -Name * | Where-Object { $_.Templates -eq "None" }
        
        Finds hosts without any templates assigned.
    .EXAMPLE
        Get-ZBXhostinfo -Name * | Where-Object { $_.Interfaces -like "*SNMP*" }
        
        Finds hosts with SNMP interfaces configured.
    .EXAMPLE
        Get-ZBXhostinfo -Name * | Select-Object HostName, Groups | Export-Csv -Path "host_groups.csv" -NoTypeInformation
        
        Exports host-to-group mapping to CSV file.
    .EXAMPLE
        Get-ZBXhostinfo -Name "dc01" | Format-List
        
        HostName    : web01.domain.local
        VisibleName : Production web servere 01
        Enabled     : True
        Templates   : Linux by Zabbix agent, ICMP Ping
        Groups      : Linux servers, Production
        Interfaces  : 192.168.1.10:10050 (Agent); 192.168.1.10:161 (SNMP)
        Description : Main production server
        Tags        : environment=production, owner=ops-team
        HostID      : 10084
    .EXAMPLE
        # Host inventory report
        $hosts = Get-ZBXhostinfo -Name *
        Write-Host "Total hosts: $($hosts.Count)"
        $hosts | Group-Object Enabled | Select-Object @{N='Status';E={if($_.Name){'Enabled'}else{'Disabled'}}}, Count
        
        Generates host inventory summary.
    .EXAMPLE
        # Find hosts by tag
        Get-ZBXhostinfo -Name * | Where-Object { $_.Tags -like "*environment=production*" }
        
        Finds all production hosts by tag.
    .EXAMPLE
        # Audit template usage
        Get-ZBXhostinfo -Name * | ForEach-Object {
            $_.Templates -split ", " | ForEach-Object { $_ }
        } | Group-Object | Sort-Object Count -Descending | Select-Object Name, Count
        
        Shows template usage statistics across all hosts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [bool]$Enabled = $true,
        
        [Parameter(Mandatory = $false)]
        [string]$Group
    )
    
    if (-not $script:ZabbixConnection.Connected) {
        throw "Not connected to Zabbix server. Use Connect-ZBXserver first."
    }
    
    # Build API parameters
    $apiParams = @{
        output                = @("hostid", "host", "name", "status", "description")
        selectTemplates       = "extend"
        selectParentTemplates = "extend"
        selectGroups          = @("groupid", "name")
        selectHostGroups      = @("groupid", "name")
        selectInterfaces      = @("interfaceid", "ip", "port", "type", "main")
        selectTags            = @("tag", "value")
    }
    
    # Host name filter
    if ($Name -ne "*") {
        if ($Name -match '\*') {
            # Wildcard search - convert to Zabbix search format
            $searchName = $Name -replace '\*', ''
            $apiParams["search"] = @{ host = $searchName }
            $apiParams["searchWildcardsEnabled"] = $true
        }
        else {
            $apiParams["filter"] = @{ host = $Name }
        }
    }
    
    # Enabled filter (status: 0 = enabled, 1 = disabled)
    if ($Enabled) {
        if (-not $apiParams.ContainsKey("filter")) {
            $apiParams["filter"] = @{}
        }
        $apiParams["filter"]["status"] = 0
    }
    else {
        if (-not $apiParams.ContainsKey("filter")) {
            $apiParams["filter"] = @{}
        }
        $apiParams["filter"]["status"] = 1
    }
    
    # Group filter
    if ($Group) {
        # First get the group ID
        $groupParams = @{
            output = @("groupid", "name")
            filter = @{ name = $Group }
        }
        
        $groupResult = Invoke-ZabbixAPI -Method "hostgroup.get" -Params $groupParams
        
        if ($groupResult -and $groupResult.Count -gt 0) {
            $apiParams["groupids"] = @($groupResult[0].groupid)
        }
        else {
            Write-Warning "Group '$Group' not found."
            return
        }
    }
    
    try {
        $hosts = Invoke-ZabbixAPI -Method "host.get" -Params $apiParams
        
        if (-not $hosts -or $hosts.Count -eq 0) {
            Write-Host "No hosts found matching the specified criteria." -ForegroundColor Yellow
            return
        }
        
        # Build results
        $results = foreach ($zbxHost in $hosts) {
            # Get enabled status (0 = enabled, 1 = disabled)
            $enabledStatus = $zbxHost.status -eq "0"
            
            # Get templates (try both parentTemplates and templates for compatibility)
            $templateList = @()
            if ($null -ne $zbxHost.parentTemplates -and $zbxHost.parentTemplates.Count -gt 0) {
                $templateList = $zbxHost.parentTemplates
            }
            elseif ($null -ne $zbxHost.templates -and $zbxHost.templates.Count -gt 0) {
                $templateList = $zbxHost.templates
            }
            
            $templates = if ($templateList.Count -gt 0) {
                ($templateList | ForEach-Object { $_.name }) -join ", "
            }
            else {
                "None"
            }
            
            # Get groups (try both groups and hostgroups for compatibility)
            $groupList = @()
            if ($null -ne $zbxHost.hostgroups -and $zbxHost.hostgroups.Count -gt 0) {
                $groupList = $zbxHost.hostgroups
            }
            elseif ($null -ne $zbxHost.groups -and $zbxHost.groups.Count -gt 0) {
                $groupList = $zbxHost.groups
            }
            
            $groups = if ($groupList.Count -gt 0) {
                ($groupList | ForEach-Object { $_.name }) -join ", "
            }
            else {
                "None"
            }
            
            # Get interfaces with details
            $interfaces = if ($zbxHost.interfaces -and $zbxHost.interfaces.Count -gt 0) {
                $zbxHost.interfaces | ForEach-Object {
                    $interfaceType = switch ($_.type) {
                        "1" { "Agent" }
                        "2" { "SNMP" }
                        "3" { "IPMI" }
                        "4" { "JMX" }
                        default { "Unknown" }
                    }
                    "$($_.ip):$($_.port) ($interfaceType)"
                }
                $interfaces -join "; "
            }
            else {
                "None"
            }
            
            # Get tags
            $tags = if ($zbxHost.tags -and $zbxHost.tags.Count -gt 0) {
                ($zbxHost.tags | ForEach-Object { "$($_.tag)=$($_.value)" }) -join ", "
            }
            else {
                "None"
            }
            
            [PSCustomObject]@{
                HostName    = $zbxHost.host
                VisibleName = $zbxHost.name
                Enabled     = $enabledStatus
                Templates   = $templates
                Groups      = $groups
                Interfaces  = $interfaces
                Description = if ([string]::IsNullOrWhiteSpace($zbxHost.description)) { "None" } else { $zbxHost.description }
                Tags        = $tags
                HostID      = $zbxHost.hostid
            }
        }
        
        return $results
    }
    catch {
        throw "Failed to get host information: $_"
    }
}

#endregion

# Export public functions
Export-ModuleMember -Function @(
    'Connect-ZBXserver',
    'Disconnect-ZBXserver',
    'Get-ZBXproblem',
    'Get-ZBXevent',
    'Get-ZBXhostinfo'
)
