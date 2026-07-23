function Connect-ZbxServer {
    <#
    .SYNOPSIS
        Connects to a Zabbix server using an API token.
    .DESCRIPTION
        Establishes a connection to the Zabbix server, validates the API
        endpoint and authenticates with the supplied token. Connection
        information (URL and token) is stored in module-scope state for use
        by subsequent cmdlets.

        Both -Url and -Token are mandatory and have no default values. The
        token is accepted as SecureString and is decrypted only at the
        moment of each HTTP call.

        Authentication uses HTTP 'Authorization: Bearer <token>' header,
        compatible with Zabbix 6.4+ and required by Zabbix 7.2+.
    .PARAMETER Url
        Zabbix API URL endpoint, typically ending with '/api_jsonrpc.php'.
    .PARAMETER Token
        Zabbix API token as SecureString. Use Read-Host -AsSecureString or
        retrieve from a secret store (SecretManagement is recommended).
    .EXAMPLE
        $token = Read-Host -AsSecureString "Enter Zabbix API token"
        Connect-ZbxServer -Url 'https://zabbix.example.com/api_jsonrpc.php' -Token $token

        Connects after prompting interactively for the token.
    .EXAMPLE
        $token = ConvertTo-SecureString $env:ZBX_TOKEN -AsPlainText -Force
        Connect-ZbxServer -Url $env:ZBX_URL -Token $token

        Connects using token from environment variable.
    .EXAMPLE
        $token = Get-Secret -Name 'ZabbixApiToken'  # SecretManagement module
        Connect-ZbxServer -Url 'https://zabbix.example.com/api_jsonrpc.php' -Token $token

        Connects using token retrieved from a secret vault.
    .EXAMPLE
        $connection = Connect-ZbxServer -Url $url -Token $token
        if ($connection.Connected) {
            Write-Host "Connected to Zabbix $($connection.ZabbixVersion)"
        }

        Connects and checks connection status programmatically.
    .OUTPUTS
        PSCustomObject with properties Connected, Url and either
        ZabbixVersion (on success) or Message (on failure).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [securestring]$Token
    )

    # Provisionally store connection info - will be rolled back on failure
    $script:ZabbixConnection.Token     = $Token
    $script:ZabbixConnection.Url       = $Url
    $script:ZabbixConnection.Connected = $true

    $plainToken = $null
    try {
        # Step 1: validate the URL points at a real Zabbix API endpoint.
        # apiinfo.version does not require authentication.
        $versionBody = @{
            jsonrpc = "2.0"
            method  = "apiinfo.version"
            params  = @{}
            id      = 1
        } | ConvertTo-Json

        $versionResponse = Invoke-RestMethod `
            -Uri $Url `
            -Method Post `
            -Body $versionBody `
            -ContentType 'application/json-rpc'

        if ($versionResponse.error) {
            $script:ZabbixConnection.Connected = $false
            return [PSCustomObject]@{
                Connected = $false
                Url       = $Url
                Message   = "API Error: $($versionResponse.error.message)"
            }
        }

        # Guard against URLs that return HTML (e.g. missing /api_jsonrpc.php) -
        # those have no .error AND no .result, so version comes back empty.
        if ([string]::IsNullOrWhiteSpace($versionResponse.result) -or
            $versionResponse.result -notmatch '^\d+\.\d+') {
            $script:ZabbixConnection.Connected = $false
            return [PSCustomObject]@{
                Connected = $false
                Url       = $Url
                Message   = "Invalid API endpoint: apiinfo.version did not return a valid Zabbix version. Verify the URL ends with '/api_jsonrpc.php'."
            }
        }

        # Step 2: validate the token with an authenticated call using Bearer header.
        $plainToken = [System.Net.NetworkCredential]::new('', $Token).Password
        $headers = @{ 'Authorization' = "Bearer $plainToken" }

        $authBody = @{
            jsonrpc = "2.0"
            method  = "host.get"
            params  = @{
                limit  = 1
                output = @("hostid")
            }
            id      = 2
        } | ConvertTo-Json

        $authResponse = Invoke-RestMethod `
            -Uri $Url `
            -Method Post `
            -Body $authBody `
            -ContentType 'application/json-rpc' `
            -Headers $headers

        if ($authResponse.error) {
            $script:ZabbixConnection.Connected = $false
            return [PSCustomObject]@{
                Connected = $false
                Url       = $Url
                Message   = "Authentication failed: $($authResponse.error.message)"
            }
        }

        return [PSCustomObject]@{
            Connected     = $true
            Url           = $Url
            ZabbixVersion = $versionResponse.result
        }
    }
    catch {
        $script:ZabbixConnection.Connected = $false
        return [PSCustomObject]@{
            Connected = $false
            Url       = $Url
            Message   = "Connection failed: $_"
        }
    }
    finally {
        $plainToken = $null
    }
}
