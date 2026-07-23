function Disconnect-ZbxServer {
    <#
    .SYNOPSIS
        Disconnects from the current Zabbix server session.
    .DESCRIPTION
        Clears the locally cached connection information (URL and token).
        Token-based authentication doesn't require any server-side logout
        call - this cmdlet only scrubs the in-memory session state.
    .EXAMPLE
        Disconnect-ZbxServer

        Disconnects from the current Zabbix server session.
    .EXAMPLE
        Connect-ZbxServer -Url $url -Token $token
        Get-ZbxProblem -Severity disaster -Last 5
        Disconnect-ZbxServer

        Connects, retrieves problems, then disconnects cleanly.
    .OUTPUTS
        PSCustomObject with properties Disconnected, Url and Message.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:ZabbixConnection.Connected) {
        Write-Warning "No active Zabbix session found."
        return [PSCustomObject]@{
            Disconnected = $false
            Message      = "No active session to disconnect"
        }
    }

    $previousUrl = $script:ZabbixConnection.Url

    # Clear session data
    $script:ZabbixConnection.Token     = $null
    $script:ZabbixConnection.Url       = $null
    $script:ZabbixConnection.Connected = $false

    return [PSCustomObject]@{
        Disconnected = $true
        Url          = $previousUrl
        Message      = "Successfully disconnected from Zabbix server"
    }
}
