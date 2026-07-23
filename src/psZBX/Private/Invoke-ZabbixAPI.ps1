function Invoke-ZabbixAPI {
    <#
    .SYNOPSIS
        Internal helper - makes an authenticated Zabbix API call.
    .DESCRIPTION
        Uses HTTP Bearer token authentication via the 'Authorization' header.
        Compatible with Zabbix 6.4+ and required by Zabbix 7.2+ (which removed
        the legacy JSON-RPC 'auth' body field).

        The SecureString token is decrypted only for the duration of the HTTP
        request and the plaintext copy is cleared from memory in the finally
        block.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter()]
        [hashtable]$Params = @{}
    )

    if (-not $script:ZabbixConnection.Connected) {
        throw "Not connected to Zabbix server. Use Connect-ZbxServer first."
    }

    $body = @{
        jsonrpc = "2.0"
        method  = $Method
        params  = $Params
        id      = 1
    } | ConvertTo-Json -Depth 10

    # Decrypt token to plaintext just in time for the request.
    # NetworkCredential trick works on Windows PowerShell 5.1 AND PowerShell 7+.
    $plainToken = $null
    try {
        $plainToken = [System.Net.NetworkCredential]::new(
            '', $script:ZabbixConnection.Token
        ).Password

        $headers = @{
            'Authorization' = "Bearer $plainToken"
        }

        $response = Invoke-RestMethod `
            -Uri $script:ZabbixConnection.Url `
            -Method Post `
            -Body $body `
            -ContentType 'application/json-rpc' `
            -Headers $headers

        if ($response.error) {
            throw "Zabbix API Error: $($response.error.message) - $($response.error.data)"
        }

        return $response.result
    }
    catch {
        throw "Failed to call Zabbix API: $_"
    }
    finally {
        # Best-effort scrub of plaintext token from memory
        $plainToken = $null
    }
}
