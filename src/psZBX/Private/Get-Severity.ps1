$script:SeverityNameMap = @{
    '0' = 'Not classified'
    '1' = 'Information'
    '2' = 'Warning'
    '3' = 'Average'
    '4' = 'High'
    '5' = 'Disaster'
}

$script:SeverityCodeMap = @{
    'not classified' = 0
    'notclassified'  = 0
    'information'    = 1
    'warning'        = 2
    'average'        = 3
    'high'           = 4
    'disaster'       = 5
}

function Get-SeverityName {
    <#
    .SYNOPSIS
        Internal helper - converts Zabbix severity number (0-5) to its name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$SeverityCode
    )

    if ($script:SeverityNameMap.ContainsKey($SeverityCode)) {
        return $script:SeverityNameMap[$SeverityCode]
    }
    return 'Unknown'
}

function Get-SeverityCode {
    <#
    .SYNOPSIS
        Internal helper - converts severity name to its Zabbix code (0-5).
        Returns -1 for unknown names.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [string]$SeverityName
    )

    $key = $SeverityName.ToLower()
    if ($script:SeverityCodeMap.ContainsKey($key)) {
        return $script:SeverityCodeMap[$key]
    }
    return -1
}
