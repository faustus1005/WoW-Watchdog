# WoW Watchdog (Windows)
<p align="left"> <img src="https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell&style=flat-square"/> <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-lightgrey?logo=windows&style=flat-square"/> <img src="https://img.shields.io/badge/Status-Stable-success?style=flat-square"/> <img src="https://img.shields.io/badge/Notifications-NTFY-orange?style=flat-square"/> </p>

**WoW Watchdog** is a lightweight Windows watchdog and GUI designed to keep World of Warcraft private server stacks running reliably.

![Screen](https://github.com/user-attachments/assets/339274bd-48c9-4d97-b12f-260e8298af90)

It monitors and automatically restarts common WoW services such as:
- MySQL / MariaDB
- Authserver (authserver, bnetserver, realmd, etc.)
- Worldserver

The system consists of:
- A modern WPF-based GUI
- A Windows service powered by PowerShell + NSSM
- A heartbeat mechanism to keep GUI and service in sync

---

## ✨ Features

- 🧠 Intelligent process detection (supports common WoW variants)
- 🔁 Automatic restarts with cooldowns
- 🚫 Crash-loop protection for worldserver
- 🖥️ Modern dark-themed GUI
- 🔧 Windows service (auto-start on boot)
- 📁 UAC-safe storage using `C:\ProgramData\WoWWatchdog`
- ❤️ GUI ↔ service heartbeat & live status
- 📜 Live log viewer
- 📦 One-click installer (Inno Setup)

---

## 🚀 Quick Start (Recommended)

### 1. Download
Grab the latest installer from **GitHub Releases**:

➡️ `WoWWatchdog-Setup.exe`

---

### 2. Install
- Run installer **as Administrator**
- Service is installed automatically
- Watchdog starts on boot

---

### 3. Configure
Launch **WoW Watchdog** from Start Menu or Desktop shortcut.

Set:
- MySQL start script (batch file)
- Authserver executable
- Worldserver executable

Configuration is saved to: C:\ProgramData\WoWWatchdog\config.json

### 4. Done
That’s it.  
The watchdog will now keep your server stack alive.

---

## 🛠️ Supported Processes

### Database
- `mysqld`
- `mysqld-nt`
- `mysqld-opt`
- `mariadbd`

### Auth
- `authserver`
- `bnetserver`
- `realmd`
- `logonserver`
- `auth`

### World
- `worldserver`

---

## ⚙️ Advanced Notes

- Service runs as **LocalSystem**
- Uses **NSSM** for reliability
- GUI communicates via heartbeat + JSON status
- Log spam is prevented via state-change detection
- Safe to run on Windows 10 / 11

---

## 📦 Building From Source

### Requirements
- PowerShell 5.1+
- PS2EXE (for GUI build)
- NSSM
- Inno Setup

### Steps
1. Compile GUI with PS2EXE
2. Bundle `watchdog.ps1`, `nssm.exe`
3. Build installer using `WoWWatchdog.iss`

---

## ⚠️ Disclaimer

This project is **not affiliated with Blizzard Entertainment**.  
It is intended for educational, development, and private server environments only.
