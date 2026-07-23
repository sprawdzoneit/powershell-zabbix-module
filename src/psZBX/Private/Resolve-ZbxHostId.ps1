function Resolve-ZbxHostId {
    <#
    .SYNOPSIS
        Internal helper - resolves a host name pattern to a list of host IDs.
    .DESCRIPTION
        Returns:
        - $null       - pattern is '*' (no filter required, caller should not
                        constrain by hostids)
        - empty array - pattern was specific but matched no hosts (caller
                        should short-circuit and return no results)
        - array       - one or more matching host IDs

        Supports exact match ('webserver01') and partial match with wildcards
        ('web*', '*prod*').
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string]$NamePattern
    )

    if ($NamePattern -eq '*') { return $null }

    $hostParams = @{ output = @('hostid') }

    if ($NamePattern -match '\*') {
        # Wildcard search - strip stars, use partial matching
        $hostParams['search'] = @{ host = ($NamePattern -replace '\*', '') }
    }
    else {
        # Exact match
        $hostParams['filter'] = @{ host = $NamePattern }
    }

    $hostsResult = Invoke-ZabbixAPI -Method 'host.get' -Params $hostParams

    if (-not $hostsResult -or $hostsResult.Count -eq 0) {
        return @()
    }

    return @($hostsResult | ForEach-Object { $_.hostid })
}
