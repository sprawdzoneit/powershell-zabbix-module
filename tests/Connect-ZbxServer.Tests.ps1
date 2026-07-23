#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for Connect-ZbxServer.
.DESCRIPTION
    Demonstrates the mocking pattern for module-internal Invoke-RestMethod
    calls. The Mock command uses -ModuleName so that the mock intercepts
    calls made FROM inside the psZBX module (not just the test scope).
#>

BeforeAll {
    $ModuleRoot = Resolve-Path "$PSScriptRoot\..\src\psZBX"
    Get-Module psZBX | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module "$ModuleRoot\psZBX.psd1" -Force
}

AfterAll {
    Get-Module psZBX | Remove-Module -Force -ErrorAction SilentlyContinue
}

Describe 'Connect-ZbxServer' {
    Context 'When the server returns a valid version and accepts the token' {
        BeforeAll {
            Mock -ModuleName psZBX Invoke-RestMethod -MockWith {
                $bodyObj = $Body | ConvertFrom-Json
                switch ($bodyObj.method) {
                    'apiinfo.version' { return @{ result = '7.0.0' } }
                    'host.get'        { return @{ result = @(@{ hostid = '1' }) } }
                    default           { return @{ result = $null } }
                }
            }
        }

        It 'Returns Connected = $true' {
            $token = ConvertTo-SecureString 'faketoken' -AsPlainText -Force
            $result = Connect-ZbxServer -Url 'https://test.example.com/api_jsonrpc.php' -Token $token
            $result.Connected | Should -BeTrue
        }

        It 'Returns the Zabbix version reported by the server' {
            $token = ConvertTo-SecureString 'faketoken' -AsPlainText -Force
            $result = Connect-ZbxServer -Url 'https://test.example.com/api_jsonrpc.php' -Token $token
            $result.ZabbixVersion | Should -Be '7.0.0'
        }

        It 'Sends Bearer authorization header on the authenticated call' {
            $token = ConvertTo-SecureString 'faketoken' -AsPlainText -Force
            Connect-ZbxServer -Url 'https://test.example.com/api_jsonrpc.php' -Token $token | Out-Null

            Should -Invoke -ModuleName psZBX -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Headers -and $Headers['Authorization'] -eq 'Bearer faketoken'
            }
        }
    }

    Context 'When the URL is not a valid Zabbix endpoint' {
        BeforeAll {
            Mock -ModuleName psZBX Invoke-RestMethod -MockWith {
                # Simulate an HTML response - apiinfo.version returns empty/null result
                return @{ result = $null }
            }
        }

        It 'Returns Connected = $false with a helpful message' {
            $token = ConvertTo-SecureString 'faketoken' -AsPlainText -Force
            $result = Connect-ZbxServer -Url 'https://test.example.com/wrong-endpoint' -Token $token
            $result.Connected | Should -BeFalse
            $result.Message   | Should -Match 'Invalid API endpoint'
        }
    }

    Context 'When the token is rejected by Zabbix' {
        BeforeAll {
            Mock -ModuleName psZBX Invoke-RestMethod -MockWith {
                $bodyObj = $Body | ConvertFrom-Json
                if ($bodyObj.method -eq 'apiinfo.version') {
                    return @{ result = '7.0.0' }
                }
                return @{ error = @{ message = 'Not authorised'; data = 'Token invalid' } }
            }
        }

        It 'Returns Connected = $false with an authentication failure message' {
            $token = ConvertTo-SecureString 'badtoken' -AsPlainText -Force
            $result = Connect-ZbxServer -Url 'https://test.example.com/api_jsonrpc.php' -Token $token
            $result.Connected | Should -BeFalse
            $result.Message   | Should -Match 'Authentication failed'
        }
    }
}
