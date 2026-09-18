#requires -Version 5.1
<#
  BatonPass Windows installer. Idempotent: safe to re-run.

  Registers a logon task rather than a Windows service. A service runs in
  session 0, where clipboard calls SUCCEED against a window station no user can
  see - measured, see spikes/s3-windows-clipboard/FINDINGS.md.
#>
[CmdletBinding()]
param(
    [string]$RelayHost,
    [string]$Group = "home",
    [uint32]$SenderId = 2,
    [string]$InstallDir = "C:\BatonPass"
)

$ErrorActionPreference = "Stop"

function Say  { param($m) Write-Host $m }
function Ok   { param($m) Write-Host "  [ok] $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Bad  { param($m) Write-Host "  [x]  $m" -ForegroundColor Red }
function Die  { param($m) Bad $m; exit 1 }

Say ""
Say "BatonPass - Windows install"
Say ""

# ------------------------------------------------------------------ 1. Session
Say "1. Session"
$sessionId = (Get-Process -Id $PID).SessionId
if ($sessionId -eq 0) {
    Die @"
Running in session 0 (a service or SSH session).

The agent must run in your interactive desktop session. Clipboard calls in
session 0 succeed against a clipboard nobody can see, which is worse than
failing. Run this from a normal PowerShell window while logged in.
"@
}
Ok "interactive session $sessionId"

# ---------------------------------------------------------------- 2. Tailscale
Say ""
Say "2. Tailscale"

$ts = Get-Command tailscale.exe -ErrorAction SilentlyContinue
if (-not $ts) {
    $candidate = "C:\Program Files\Tailscale\tailscale.exe"
    if (Test-Path $candidate) { $ts = $candidate } else { $ts = $null }
} else { $ts = $ts.Source }

if (-not $ts) {
    Bad "Tailscale is not installed."
    Say ""
    Say "  BatonPass carries API keys and TOTP codes between your machines and has"
    Say "  no transport of its own: it relies on the tailnet for encryption and for"
    Say "  device identity."
    Say ""
    Say "    winget install tailscale.tailscale"
    Say "    or https://tailscale.com/download/windows"
    Say ""
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $reply = Read-Host "  Install via winget now? [y/N]"
        if ($reply -match '^[Yy]$') {
            winget install --id tailscale.tailscale --accept-source-agreements --accept-package-agreements
            $ts = "C:\Program Files\Tailscale\tailscale.exe"
        }
    }
    if (-not (Test-Path $ts)) { Die "Install Tailscale, then re-run this script." }
}
Ok "found at $ts"

& $ts status 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Warn "Tailscale is installed but not connected."
    Say "    Run:  & '$ts' up"
    $reply = Read-Host "  Run 'tailscale up' now? [y/N]"
    if ($reply -match '^[Yy]$') { & $ts up } else { Die "Connect Tailscale, then re-run." }
}
Ok "connected"

$selfIp = (& $ts ip -4 2>$null | Select-Object -First 1)
$whois = & $ts whois --json $selfIp 2>$null | ConvertFrom-Json
$stableId = $whois.Node.StableID
$selfName = $whois.Node.Name
if (-not $stableId) { Die "Could not resolve this machine's tailnet identity." }
Ok "this machine is $selfName ($selfIp)"
Ok "StableID $stableId"

# -------------------------------------------------------------------- 3. Relay
Say ""
Say "3. Relay"
if (-not $RelayHost) { $RelayHost = Read-Host "  Relay host:port (e.g. 100.64.0.20:4000)" }
if (-not $RelayHost) { Die "No relay host given." }

$parts = $RelayHost.Split(":")
if (Test-NetConnection -ComputerName $parts[0] -Port ([int]$parts[1]) -InformationLevel Quiet -WarningAction SilentlyContinue) {
    Ok "reachable at $RelayHost"
} else {
    Warn "cannot reach $RelayHost right now (the agent retries)"
    Say "    Check the relay is running and that this StableID is on its allowlist:"
    Say "      $stableId"
}

# --------------------------------------------------------------------- 4. Agent
Say ""
Say "4. Agent"
$exe = Join-Path $InstallDir "batonpass-agent.exe"
if (-not (Test-Path $exe)) {
    Die "batonpass-agent.exe not found at $exe. Copy the published build there first."
}
Ok "found $exe"

# ----------------------------------------------------------------------- 5. Key
Say ""
Say "5. Group key"
$configured = $false
try {
    $status = & $exe status 2>&1 | Out-String
    if ($status -notmatch "no key|not configured") { $configured = $true }
} catch { }

if ($configured) {
    Ok "key already stored (DPAPI, under C:\ProgramData\BatonPass)"
} else {
    Warn "no group key on this machine"
    Say ""
    Say "  Import the key from a device that already has it:"
    Say "    $exe import-key --key <64-hex> --relay ws://$RelayHost/socket/websocket?vsn=2.0.0 --group $Group --sender-id $SenderId"
    Say ""
    Say "  Type it in by hand. Never send the key through BatonPass itself: it would"
    Say "  be encrypted under the old key and delivered to every enrolled device,"
    Say "  including one you may be trying to revoke."
    Say ""
    $keyHex = Read-Host "  Paste the 64-hex key now (or press Enter to skip)"
    if ($keyHex -and $keyHex.Length -eq 64) {
        & $exe import-key --key $keyHex --relay "ws://$RelayHost/socket/websocket?vsn=2.0.0" --group $Group --sender-id $SenderId --epoch 1
        Ok "key imported"
    } else {
        Warn "skipped - the agent will not start until a key is present"
    }
}

# ----------------------------------------------------------------- 6. Autostart
Say ""
Say "6. Autostart"

$taskName = "BatonPass"
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Interactive logon token: the task must land in the user's own session so the
# clipboard it touches is the one the user can see.
$action    = New-ScheduledTaskAction -Execute $exe -Argument "run" -WorkingDirectory $InstallDir
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
                -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings | Out-Null
Ok "logon task registered"

Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 2
$state = (Get-ScheduledTask -TaskName $taskName).State
Ok "task state: $state"

Say ""
Say "Done."
Say ""
Say "  Enroll this machine on the relay by adding its StableID to the allowlist:"
Say "      $stableId   ($selfName)"
Say ""
Say "  Status:  $exe status"
Say "  Stop:    Stop-ScheduledTask -TaskName BatonPass"
Say "  Start:   Start-ScheduledTask -TaskName BatonPass"
Say "  Remove:  Unregister-ScheduledTask -TaskName BatonPass -Confirm:`$false"
Say ""
Say "  Note: Windows Clipboard History (Win+V) retains clipboard items independently."
Say "  The agent marks its own writes as excluded, but items you copy yourself are"
Say "  still retained. Disable it in Settings > System > Clipboard if that matters."
Say ""
