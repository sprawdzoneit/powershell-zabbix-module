function Get-DurationString {
    <#
    .SYNOPSIS
        Internal helper - calculates duration from a given time to now and
        returns it as a human-readable string (e.g. '2d 4h 17m').
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
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
