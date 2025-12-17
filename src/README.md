# WoW Watchdog (Windows) – Service + GUI
<p align="left"> <img src="https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell&style=flat-square"/> <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-lightgrey?logo=windows&style=flat-square"/> <img src="https://img.shields.io/badge/Status-Stable-success?style=flat-square"/> <img src="https://img.shields.io/badge/Notifications-NTFY-orange?style=flat-square"/> </p>

WoW Watchdog is a Windows PowerShell watchdog that monitors key WoW server processes (MySQL/Authserver/Worldserver) and can send NTFY notifications on state changes.  
This package includes:
- `watchdog.ps1` (headless watchdog, intended to run as a Windows Service)
- `WoWWatcherGUI.ps1` (management GUI)
- NSSM-based Windows Service installation scripts
- Optional installer (Inno Setup)

## Features
- Runs at boot as a Windows Service (recommended)
- GUI management panel with live status indicators and NTFY configuration
- Per-service notification toggles and priority overrides
- Service-first behavior: GUI starts/stops the service when installed
- Logs written to `C:\ProgramData\WoWWatchdog\` (service stdout/stderr)

## Requirements
- Windows 10/11 or Windows Server
- PowerShell 5.1
- Administrator privileges (for service install/uninstall)
- NSSM (`nssm.exe`) included in the installer/package

## Installation (Recommended – Service via NSSM)

### Using the installer
1. Run `WoWWatchdog-Setup.exe` as Administrator.
2. The installer copies files to:
   `C:\Program Files\WoWWatchdog`
3. The installer installs and starts the `WoWWatchdog` Windows Service.

### Manual install (zip deployment)
1. Copy the folder to a permanent location (e.g. `C:\WoWWatchdog`).
2. Open an elevated PowerShell.
3. Run:
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-service.ps1
