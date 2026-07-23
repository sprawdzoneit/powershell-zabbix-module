function Convert-UnixTimestamp {
    <#
    .SYNOPSIS
        Internal helper - converts a Unix timestamp to local DateTime.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Timestamp
    )

    $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    return $epoch.AddSeconds([int64]$Timestamp).ToLocalTime()
}
