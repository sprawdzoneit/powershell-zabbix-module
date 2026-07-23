#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for private helper functions.
.DESCRIPTION
    Private functions are not exported from the module, so we use
    InModuleScope to reach inside the module scope and call them directly.
#>

BeforeAll {
    $ModuleRoot = Resolve-Path "$PSScriptRoot\..\src\psZBX"
    Get-Module psZBX | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module "$ModuleRoot\psZBX.psd1" -Force
}

AfterAll {
    Get-Module psZBX | Remove-Module -Force -ErrorAction SilentlyContinue
}

Describe 'Get-SeverityName / Get-SeverityCode round-trip' {
    It 'Maps each numeric code back to the same string and vice versa' -ForEach @(
        @{ Code = '0'; Name = 'Not classified' }
        @{ Code = '1'; Name = 'Information' }
        @{ Code = '2'; Name = 'Warning' }
        @{ Code = '3'; Name = 'Average' }
        @{ Code = '4'; Name = 'High' }
        @{ Code = '5'; Name = 'Disaster' }
    ) {
        InModuleScope psZBX -Parameters @{ Code = $Code; Name = $Name } {
            param($Code, $Name)
            Get-SeverityName -SeverityCode $Code                     | Should -Be $Name
            Get-SeverityCode -SeverityName $Name                     | Should -Be ([int]$Code)
            Get-SeverityCode -SeverityName $Name.ToUpper()           | Should -Be ([int]$Code)
        }
    }

    It 'Returns Unknown for an out-of-range code' {
        InModuleScope psZBX {
            Get-SeverityName -SeverityCode '99' | Should -Be 'Unknown'
        }
    }

    It 'Returns -1 for an unknown severity name' {
        InModuleScope psZBX {
            Get-SeverityCode -SeverityName 'NopeSeverity' | Should -Be -1
        }
    }
}

Describe 'Convert-UnixTimestamp' {
    It 'Converts the Unix epoch start to 1970-01-01 UTC' {
        InModuleScope psZBX {
            $dt = Convert-UnixTimestamp -Timestamp '0'
            $dt.ToUniversalTime() | Should -Be ([DateTime]::new(1970,1,1,0,0,0,[DateTimeKind]::Utc))
        }
    }

    It 'Converts 1700000000 to 2023-11-14 22:13:20 UTC' {
        InModuleScope psZBX {
            $dt = Convert-UnixTimestamp -Timestamp '1700000000'
            $dt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2023-11-14 22:13:20'
        }
    }
}

Describe 'Get-DurationString' {
    It 'Formats short durations as minutes and seconds' {
        InModuleScope psZBX {
            $start = (Get-Date).AddMinutes(-5).AddSeconds(-10)
            Get-DurationString -StartTime $start | Should -Match '^\d+m \d+s$'
        }
    }

    It 'Formats hour-scale durations as hours and minutes' {
        InModuleScope psZBX {
            $start = (Get-Date).AddHours(-3).AddMinutes(-15)
            Get-DurationString -StartTime $start | Should -Match '^\d+h \d+m$'
        }
    }

    It 'Formats day-scale durations as days, hours and minutes' {
        InModuleScope psZBX {
            $start = (Get-Date).AddDays(-2).AddHours(-4)
            Get-DurationString -StartTime $start | Should -Match '^\d+d \d+h \d+m$'
        }
    }
}
