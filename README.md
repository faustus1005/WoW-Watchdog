WoW Watchdog (Windows)
<p align="left"> <img src="https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell&style=flat-square"/> <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-lightgrey?logo=windows&style=flat-square"/> <img src="https://img.shields.io/badge/Service-NSSM-success?style=flat-square"/> <img src="https://img.shields.io/badge/GUI-WPF-blueviolet?style=flat-square"/> <img src="https://img.shields.io/badge/Notifications-NTFY-orange?style=flat-square"/> <img src="https://img.shields.io/badge/Status-Stable-success?style=flat-square"/> </p>

![Screen](https://github.com/user-attachments/assets/9f43b9eb-f17e-45b4-b3b2-b99599a25caf)

WoW Watchdog is a robust Windows watchdog service and modern WPF GUI designed to reliably manage and protect World of Warcraft private server stacks.

It monitors and manages common WoW services including:

MySQL / MariaDB

Authserver (authserver, bnetserver, realmd, etc.)

Worldserver

The system is built around:

A PowerShell watchdog service (managed by NSSM)

A modern WPF GUI (compiled via PS2EXE)

A heartbeat + status channel that keeps GUI and service fully synchronized

✨ Features
Core

🧠 Intelligent process detection (supports common WoW variants)

🔁 Automatic restarts with configurable cooldowns

🚫 Crash-loop protection for worldserver

📁 UAC-safe storage under C:\ProgramData\WoWWatchdog

🔧 Windows service (auto-start on boot)

📦 One-click installer (Inno Setup + NSSM)

GUI ↔ Service Integration

❤️ Heartbeat-based runtime detection (no fragile service polling)

📊 JSON status telemetry (watchdog.status.json)

📜 Live log viewer (auto-refresh, independent scroll)

🟢 Real-time LED indicators for MySQL / Auth / World

Manual Control (New)

▶️ Start / Stop MySQL, Authserver, and Worldserver individually

🔼 Ordered startup: Database → Auth → World

🔽 Graceful shutdown with configurable delays

🔐 Safe coexistence with watchdog auto-restart logic

Notifications

🔔 NTFY integration

🎯 Per-service enable/disable

🚦 Priority overrides

📤 Send on UP / DOWN events

🧪 Test notification button in GUI

Reliability Improvements

🧾 Config reload without restart

🧠 State-change logging (prevents log spam)

🛑 Graceful watchdog shutdown via GUI

🪪 Service-safe PowerShell (no console, no UI dependencies)

🚀 Quick Start (Recommended)
1. Download

Grab the latest installer from GitHub Releases:

➡️ WoWWatchdog-Setup.exe

2. Install

Run installer as Administrator

The Windows service is installed automatically

Watchdog is configured to start on boot

3. Configure

Launch WoW Watchdog from the Start Menu or Desktop shortcut.

Set:

MySQL start script (.bat)

Authserver executable

Worldserver executable

Configuration is stored at:

C:\ProgramData\WoWWatchdog\config.json


Changes are picked up automatically — no service restart required.

4. Use

Let the watchdog manage everything automatically
or

Use the GUI buttons to start/stop services manually
or

Combine both — the watchdog respects manual actions

🛠️ Supported Process Detection
Database

mysqld

mysqld-nt

mysqld-opt

mariadbd

Auth

authserver

bnetserver

realmd

logonserver

auth

World

worldserver

⚙️ Architecture Notes

Watchdog runs as LocalSystem

Managed by NSSM for crash recovery

GUI ↔ service sync via:

watchdog.heartbeat

watchdog.status.json

Logging is state-aware to prevent spam

Designed for long-running uptime scenarios

📦 Building From Source
Requirements

PowerShell 5.1+

PS2EXE (GUI compilation)

NSSM

Inno Setup

High-Level Build Flow

Compile GUI using PS2EXE

Bundle:

watchdog.ps1

nssm.exe

Build installer using WoWWatchdog.iss

⚠️ Disclaimer

This project is not affiliated with Blizzard Entertainment.
It is intended for educational, development, and private server environments only.
