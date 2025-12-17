# WoW Watchdog v1.1.0 – Release Notes

## 🎉 Highlights

This release represents a **major reliability and usability upgrade** focused on
long-running uptime, safe automation, and operational visibility.

---

## ✨ New Features

### GUI ↔ Service Heartbeat
- Real-time runtime detection
- No dependency on Windows service state
- Accurate even during NSSM restarts

### Manual Service Controls
- Start / Stop MySQL, Authserver, Worldserver individually
- Ordered startup (DB → Auth → World)
- Graceful shutdown with delays
- Safe coexistence with watchdog logic

### Ordered Autostart
- Database must be running before Authserver
- Authserver must be running before Worldserver
- Prevents partial startup failures

### Live Telemetry
- Structured status JSON
- LED indicators per service
- Crash-loop visibility

---

## 🔧 Reliability Improvements

- State-change logging (prevents spam)
- Safe config reload without restart
- Service-safe PowerShell execution
- Improved NSSM configuration
- Clean shutdown signaling

---

## 🧠 Internal Changes

- Unified ProgramData layout
- Hardened path resolution (service + EXE safe)
- Explicit heartbeat states (`Starting`, `Running`, `Idle`, `Stopping`)
- Improved error isolation

---

## ⚠️ Breaking Changes

- Configuration file is now **authoritative** in `C:\ProgramData\WoWWatchdog`
- GUI no longer starts watchdog scripts directly
- Service ownership is exclusive

---

## ✅ Upgrade Notes

- Existing installs should uninstall first
- Configuration may be reused
- Service will auto-install on first launch

---

## 📦 Files Affected

- `watchdog.ps1`
- GUI executable
- Installer (Inno Setup)
- NSSM service configuration

---

## 🚀 Stability

This version is considered **stable** for continuous operation on
Windows 10 and Windows 11 systems.

---

Thank you for testing and hardening this release.
