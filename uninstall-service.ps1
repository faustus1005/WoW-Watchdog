#requires -Version 5.1
<#
  Uninstalls WoWWatchdog service installed with NSSM.

  Usage (elevated):
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall-service.ps1
#>

$ErrorActionPreference = "Stop"

$ServiceName = "WoWWatchdog"
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$NssmPath    = Join-Path $ScriptDir "nssm.exe"

if (-not (Test-Path $NssmPath)) { throw "nssm.exe not found at: $NssmPath" }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Please run this script as Administrator."
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
  try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
  & $NssmPath remove $ServiceName confirm | Out-Null
  Write-Host "Removed service: $ServiceName"
} else {
  Write-Host "Service not found: $ServiceName"
}
