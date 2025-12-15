#requires -Version 5.1
<#
  Installs/updates WoW Watchdog as a Windows Service using NSSM.
  - Creates service WoWWatchdog
  - Sets Automatic startup
  - Captures stdout/stderr to ProgramData logs
  - Starts the service

  Usage (elevated):
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-service.ps1

  Silent/unattended:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-service.ps1 -Silent
#>

param(
  [switch]$Silent
)

$ErrorActionPreference = "Stop"

function Write-Info($m) { if (-not $Silent) { Write-Host $m } }

# ---- Constants ----
$ServiceName = "WoWWatchdog"
$DisplayName = "WoW Watchdog"
$Description = "Monitors and restarts WoW server processes (MySQL/Authserver/Worldserver) and sends NTFY alerts."

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$NssmPath    = Join-Path $ScriptDir "nssm.exe"
$WatchdogPs1 = Join-Path $ScriptDir "watchdog.ps1"

if (-not (Test-Path $NssmPath))  { throw "nssm.exe not found at: $NssmPath" }
if (-not (Test-Path $WatchdogPs1)) { throw "watchdog.ps1 not found at: $WatchdogPs1" }

# Logs under ProgramData (writable by service account)
$LogRoot = Join-Path $env:ProgramData "WoWWatchdog"
if (-not (Test-Path $LogRoot)) { New-Item -ItemType Directory -Path $LogRoot | Out-Null }

$Stdout = Join-Path $LogRoot "service-stdout.log"
$Stderr = Join-Path $LogRoot "service-stderr.log"

# PowerShell host used by NSSM
$PsExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"

# NSSM arguments
# -NoProfile: consistent runtime
# -ExecutionPolicy Bypass: avoids local policy breaking startup
# -File: run watchdog script
$PsArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$WatchdogPs1`""

# ---- Admin check ----
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Please run this script as Administrator."
}

# ---- Install or update service ----
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
  Write-Info "Installing service $ServiceName..."
  & $NssmPath install $ServiceName $PsExe $PsArgs | Out-Null
} else {
  Write-Info "Service already exists; updating config..."
  try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
}

# Core metadata
& $NssmPath set $ServiceName DisplayName $DisplayName | Out-Null
& $NssmPath set $ServiceName Description $Description | Out-Null

# Startup
& $NssmPath set $ServiceName Start SERVICE_AUTO_START | Out-Null

# Working directory (so relative paths in watchdog.ps1 work as expected)
& $NssmPath set $ServiceName AppDirectory $ScriptDir | Out-Null

# Output capture
& $NssmPath set $ServiceName AppStdout $Stdout | Out-Null
& $NssmPath set $ServiceName AppStderr $Stderr | Out-Null
& $NssmPath set $ServiceName AppStdoutCreationDisposition 4 | Out-Null  # OPEN_ALWAYS
& $NssmPath set $ServiceName AppStderrCreationDisposition 4 | Out-Null  # OPEN_ALWAYS

# Restart behavior
& $NssmPath set $ServiceName AppExit Default Restart | Out-Null
& $NssmPath set $ServiceName AppRestartDelay 5000 | Out-Null

# Stop behavior
& $NssmPath set $ServiceName AppStopMethodSkip 0 | Out-Null
& $NssmPath set $ServiceName AppKillProcessTree 1 | Out-Null

Write-Info "Starting service..."
Start-Service -Name $ServiceName

# Quick status
$svc = Get-Service -Name $ServiceName
Write-Info ("Service status: {0}" -f $svc.Status)
Write-Info ("Logs: {0}" -f $LogRoot)
