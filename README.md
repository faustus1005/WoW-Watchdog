# WoW-Watchdog

<p align="center">
  <img src="https://github.com/user-attachments/assets/a48882ba-a573-4765-9ef3-d49404111a5b" alt="WoW Watchdog logo" />
</p>

<p align="center"> <img src="https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell&style=flat-square"/> <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-lightgrey?logo=windows&style=flat-square"/> <img src="https://img.shields.io/badge/Android-8.0+-3DDC84?logo=android&style=flat-square"/> <img src="https://img.shields.io/badge/Service-NSSM-success?style=flat-square"/> <img src="https://img.shields.io/badge/GUI-WPF-blueviolet?style=flat-square"/> <img src="https://img.shields.io/badge/Notifications-NTFY-orange?style=flat-square"/> <img src="https://img.shields.io/badge/Status-Stable-success?style=flat-square"/> </p>

## 📖 Overview

WoW-Watchdog is a robust PowerShell-based application designed to monitor the status of your favorite World of Warcraft private servers. WoW-Watchdog provides timely notifications, ensuring you're always informed using NTFY integration.

This tool runs quietly in the background, periodically checking specified servers and alerting you to changes such as a server going offline, or optionally, when the server is back online. An **Android companion app** lets you monitor and control your server from your phone via the built-in REST API.

It is geared mostly towards the SPP Legion Repack, so many of the features will not work with other repacks without modification, but the core feature of starting/stopping/notifying should work for most WoW Private servers.

## Features

### Watchdog & Service Control
- GUI-based watchdog for WoW server stacks (World/Auth/DB)
- Runs as a Windows Service via **NSSM**
- Process alias detection (e.g., `authserver` / `bnetserver`, `mysqld`/MariaDB variants)
- Crash-loop protection with restart cooldowns
- Reliable stop/start behavior (no unintended immediate restarts)
- Graceful shutdown preserved when stopping via the app or Windows Services

### Monitoring & Live Operations
- Service status + health indicators (GUI ↔ service heartbeat)
- Online player count (when DB is configured/reachable; safe fallback when not)
- CPU/Memory usage snapshots (periodic refresh)
- Worldserver console integration (RA):
  - Connect/configure RA console
  - View console output in-app
  - Send commands from the launcher
- Live log viewing of your servers various log files

### REST API & Android Companion App
- Built-in REST API for remote monitoring and control (disabled by default)
- API key authentication with rate limiting and IP lockout
- **Android companion app** (Kotlin / Jetpack Compose):
  - Real-time dashboard with service status cards
  - Start, stop, restart, and hold individual services or all at once
  - Worldserver RA console access from your phone
  - Live log viewer
  - NTFY push notification configuration
  - Configurable polling interval and expansion-themed UI
  - Requires Android 8.0+ (API 26)

### Notifications & Security
- **NTFY** notifications with:
  - Basic auth (username/password)
  - Token auth
  - Auth mode selector with dynamic fields
- Sensitive values stored encrypted in `secrets.json` (auto-used on reload)

### Updates
- Check for and update to the latest **GitHub Release** from within the app
- Update workflow stops the watchdog safely and maintains graceful shutdown behavior
- Handles SPP Legion Repack update process with graceful shutdown, backup, update, and restart behaviors

### Backup & Restore
- Database backup/restore:
  - Select destination
  - ZIP compression by default
  - Retention policy (default 14 days)
  - Restore from `.sql` or `.zip`
- Full server/repack backup:
  - Graceful stop order: **World → Auth → DB**
  - ZIP the entire repack folder
  - Restart order: **DB → Auth → World**
- Option to back up only Auth/World configuration files
- Backup destinations support **UNC paths** (e.g., `\\server\share\folder`)

### Tools
- Integrated tooling tab for companion utilities
- SPP V2 Legion Management app support (managed install/launch)
- Battle Shop Editor support (installed/managed under ProgramData)

### Deployment & Portability
- Standard installer via **Inno Setup**
- ProgramData-based config/logs/tools layout for consistent machine-wide storage
- **Portable mode** supported (no installer required)

![Main](https://github.com/user-attachments/assets/e68bba5b-968a-458c-b74c-0d757a77ca78)
![Conf](https://github.com/user-attachments/assets/045be4d1-a628-4623-9ba6-46896a797c72)
![Tools](https://github.com/user-attachments/assets/1485eb82-eddc-4219-9555-3e31f8bcffdb)
![WorldserverConsole](https://github.com/user-attachments/assets/676e162a-486b-4660-8a2b-b98fcabbd8cc)
![Updates](https://github.com/user-attachments/assets/51757596-6baf-4370-8ff3-f93c251c0f79)

## 🚀 Quick Start

Need more detail? Check out the dedicated getting started guide: [docs/getting-started.md](docs/getting-started.md).

### Prerequisites

*   **PowerShell**: Windows PowerShell 5.1 (or newer)
*   **Android app** (optional): Android 8.0+ (API 26) and network access to the watchdog host

### Installation

1. **Download the [Latest Release](https://github.com/faustus1005/WoW-Watchdog-SPP-Legion/releases/latest).**
2. **Run the installer.** Admin rights are required to install the Windows service.
3. **Launch the app** from the new "WoW Watchdog" desktop shortcut. The service starts automatically after installation.
4. **Configure the watchdog server paths.**
   1. Use the **Browse** buttons in the top-right of the GUI to point to your MySQL/Auth/Worldserver executables or scripts.
   2. This lets the watchdog know how to start and monitor your services.
5. **Optional: Configure NTFY notifications.**
   1. Select your expansion from the dropdown, or choose **Custom** and fill out the label. This only affects notifications.
   2. Fill out the NTFY server information and update the topic/tags as required.
   3. Select your auth mode (Basic or Token). For Basic, enter a username and password; for Token, paste your token.
   4. Click **Save Config** to persist settings for the next launch.
6. **Optional: Enable the REST API for the Android companion app.**
   1. Set `"Enabled": true` in the `API` section of `config.json`.
   2. Restart the watchdog service. An API key is generated automatically and saved to `api.secrets.json`.
   3. Install the Android app, enter your server's IP, port (default `8099`), and the API key from `api.secrets.json`.
   4. Tap **Test Connection** to verify. See [docs/getting-started.md](docs/getting-started.md) for full details.

##  License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

##  Support & Contact

*   🐛 Issues: [GitHub Issues](https://github.com/faustus1005/WoW-Watchdog-SPP-Legion/issues)
    
*   💬 Discussions: [GitHub Discussions](https://github.com/faustus1005/WoW-Watchdog-SPP-Legion/discussions)
    

**⭐ Star this repo if you find it helpful!**

Made by faustus1005
