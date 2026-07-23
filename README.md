# psZBX

A PowerShell module for querying Zabbix server via the REST API. Provides
ergonomic cmdlets for the most common day-to-day operations: looking up
problems, browsing event history, inspecting hosts and managing maintenance
windows — all without leaving your terminal.

Built for **Zabbix 6.4+** (uses Bearer token authentication required by
Zabbix 7.2+).

## Features

- 🔐 **Secure by default** — tokens handled as `SecureString`, never written to disk
- 🌐 **Bearer-token auth** — compatible with current and future Zabbix releases
- 📊 **Pipeline-friendly** — every cmdlet returns rich PSCustomObjects
- 🏢 **Cross-edition** — works on Windows PowerShell 5.1 and PowerShell 7+

## Requirements

- PowerShell 5.1 (Windows) or PowerShell 7+ (cross-platform)
- Zabbix Server 6.4 or newer
- Zabbix API token with appropriate permissions

## Installation

```powershell
Install-PSResource -Name psZBX -Repository PSGallery
```

Or with legacy PowerShellGet:

```powershell
Install-Module -Name psZBX -Repository PSGallery
```

## Quick Start

```powershell
Import-Module psZBX

# Connect — both Url and Token are mandatory and never stored in code
$token = Read-Host -AsSecureString "Enter Zabbix API token"
Connect-ZbxServer -Url 'https://zabbix.example.com/api_jsonrpc.php' -Token $token

# Or pull the token from an environment variable / secret store:
$token = ConvertTo-SecureString $env:ZBX_TOKEN -AsPlainText -Force
Connect-ZbxServer -Url $env:ZBX_URL -Token $token

# Browse current problems
Get-ZbxProblem -Severity disaster -Last 10

# Look at recent event history
Get-ZbxEvent -Severity high -Last 50 | Format-Table -AutoSize

# Inspect a host
Get-ZbxHost -Name 'webserver01.example.com'

# Check maintenance windows
Get-ZbxMaintenance

# Reschedule a maintenance window
Set-ZbxMaintenance -Name 'Weekly Patching' `
                   -ActiveSince '2026-05-20 18:00' `
                   -ActiveTill '2026-05-20 22:00'

# Always disconnect when finished
Disconnect-ZbxServer
```

## Cmdlets

| Cmdlet                 | Purpose                                              |
| ---------------------- | ---------------------------------------------------- |
| `Connect-ZbxServer`    | Open a Zabbix session (validates URL and token)      |
| `Disconnect-ZbxServer` | Close the local session and clear cached token       |
| `Get-ZbxProblem`       | List active problems (filter by severity/host/ack)   |
| `Get-ZbxEvent`         | Browse historical events (PROBLEM and RESOLVED)      |
| `Get-ZbxHost`          | Get host configuration (templates, groups, ifaces)   |
| `Get-ZbxMaintenance`   | List maintenance windows with state (Active/Expired) |
| `Set-ZbxMaintenance`   | Reschedule an existing maintenance window            |

Run `Get-Help <cmdlet> -Full` for parameter details and examples.

## Backward compatibility

Functions from pre-1.0.0 internal builds (`Get-ZBXproblem`, `Set-ZBXmaint`,
etc.) are exposed as aliases and will continue to work, but new scripts
should use the PascalCase names above.

## Security notes

- **Never** hardcode tokens in scripts. Use `Read-Host -AsSecureString`,
  `SecretManagement` (recommended), or environment variables.
- The module stores the token in memory as a `SecureString` for the duration
  of the session; it is decrypted only at the moment of each HTTP call.
- API tokens in Zabbix can (and should) be scoped to the minimum required
  permission set. For read-only monitoring use a viewer-role token.

## Authentication mechanism

The module uses **HTTP `Authorization: Bearer <token>`** for all API calls.
This is the auth mechanism mandated by Zabbix 7.2+ (the legacy `auth` field
in the JSON-RPC body was removed in that release). Bearer auth is supported
back to Zabbix 6.4, so this module supports any current LTS release.

If you need to talk to a Zabbix server older than 6.4, pin to an older
version of this module — but ideally, upgrade your Zabbix.

## Reporting issues / contributing

Issues and pull requests welcome at:
<https://github.com/sprawdzoneit/PowerShell-Zabbix-Module>

## License

Released under the [MIT License](LICENSE). If you build on this module,
please keep the copyright notice in derivative works — that's all the
attribution this license asks for.

## Author

Łukasz Huk · [sprawdzone.it](https://sprawdzone.it)
