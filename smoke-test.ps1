#Requires -Version 5.1
<#
.SYNOPSIS
    Smoke test for the psZBX module.
.DESCRIPTION
    Verifies that:
    1. Module manifest parses correctly
    2. Module imports without errors
    3. All public functions are exported
    4. All backward-compatibility aliases are exported
    5. Help is available for each public function
    Does NOT connect to any Zabbix server.
.EXAMPLE
    .\smoke-test.ps1
#>

$ErrorActionPreference = 'Stop'
$ManifestPath = Join-Path $PSScriptRoot 'src\psZBX\psZBX.psd1'

Write-Host "`n=== psZBX smoke test ===" -ForegroundColor Cyan

# 1. Manifest parses
Write-Host "`n[1/5] Testing manifest..." -ForegroundColor Yellow
$manifest = Test-ModuleManifest -Path $ManifestPath
Write-Host "  OK - Module: $($manifest.Name) v$($manifest.Version)" -ForegroundColor Green

# 2. Module imports cleanly
Write-Host "`n[2/5] Importing module..." -ForegroundColor Yellow
Get-Module psZBX | Remove-Module -Force -ErrorAction SilentlyContinue
Import-Module $ManifestPath -Force
Write-Host "  OK - Module imported" -ForegroundColor Green

# 3. Expected public functions
$expectedFunctions = @(
    'Connect-ZbxServer',
    'Disconnect-ZbxServer',
    'Get-ZbxProblem',
    'Get-ZbxEvent',
    'Get-ZbxHost',
    'Get-ZbxMaintenance',
    'Set-ZbxMaintenance'
)

Write-Host "`n[3/5] Checking exported functions..." -ForegroundColor Yellow
$actualFunctions = (Get-Command -Module psZBX -CommandType Function).Name
$missing = $expectedFunctions | Where-Object { $_ -notin $actualFunctions }
$extra   = $actualFunctions   | Where-Object { $_ -notin $expectedFunctions }

if ($missing) { Write-Host "  FAIL - Missing functions: $($missing -join ', ')" -ForegroundColor Red; exit 1 }
if ($extra)   { Write-Host "  WARN - Unexpected functions: $($extra -join ', ')" -ForegroundColor Yellow }
Write-Host "  OK - All $($expectedFunctions.Count) public functions exported" -ForegroundColor Green

# 4. Expected backward-compat aliases (only for renames beyond case change)
$expectedAliases = @(
    'Get-ZBXhostinfo',
    'Get-ZBXmaint',
    'Set-ZBXmaint'
)

Write-Host "`n[4/5] Checking backward-compat aliases..." -ForegroundColor Yellow
$actualAliases = (Get-Command -Module psZBX -CommandType Alias).Name
$missingAliases = $expectedAliases | Where-Object { $_ -notin $actualAliases }
if ($missingAliases) { Write-Host "  FAIL - Missing aliases: $($missingAliases -join ', ')" -ForegroundColor Red; exit 1 }
Write-Host "  OK - All $($expectedAliases.Count) aliases exported" -ForegroundColor Green

# 5. Help is available for each public function
Write-Host "`n[5/5] Checking comment-based help..." -ForegroundColor Yellow
foreach ($fn in $expectedFunctions) {
    $help = Get-Help $fn -ErrorAction SilentlyContinue
    if (-not $help.Synopsis -or $help.Synopsis -match '^\s*$') {
        Write-Host "  FAIL - $fn has no .SYNOPSIS" -ForegroundColor Red
        exit 1
    }
    if (-not $help.Examples) {
        Write-Host "  WARN - $fn has no .EXAMPLE" -ForegroundColor Yellow
    }
}
Write-Host "  OK - All public functions have help" -ForegroundColor Green

Write-Host "`n=== Smoke test PASSED ===`n" -ForegroundColor Green
