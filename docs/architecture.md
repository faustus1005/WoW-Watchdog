# WoW Watchdog – Architecture Overview

This document describes the internal architecture of **WoW Watchdog**, focusing on
the **heartbeat mechanism**, **control flow**, and **GUI ↔ service interaction**.

---

## High-Level Components

WoW Watchdog consists of three primary components:

1. **Watchdog Service**
   - PowerShell script (`watchdog.ps1`)
   - Runs as a Windows service via **NSSM**
   - Owns process monitoring, restart logic, and ordering

2. **WPF GUI**
   - Compiled PowerShell (PS2EXE)
   - User-facing configuration and control interface
   - Does *not* manage services directly

3. **Shared State (ProgramData)**
   - Files under `C:\ProgramData\WoWWatchdog`
   - Used for configuration, logging, heartbeat, and commands

---

## Shared Files

| File | Purpose |
|-----|--------|
| `config.json` | Server paths and notification settings |
| `watchdog.log` | Append-only service log |
| `watchdog.heartbeat` | Last-known heartbeat timestamp |
| `watchdog.status.json` | Rich runtime telemetry |
| `stop_watchdog.txt` | Graceful shutdown signal |

---

## Heartbeat Mechanism

The watchdog writes a **heartbeat file** once per second:

Contents:
- Single ISO-8601 timestamp
- Overwritten on every update

### GUI Interpretation

The GUI determines watchdog state by:

1. Checking if `watchdog.heartbeat` exists
2. Parsing the timestamp
3. Comparing freshness (default ≤ 3 seconds)

| Condition | GUI Status |
|---------|------------|
| Fresh heartbeat | Running |
| Stale heartbeat | Stopped |
| File missing | Not running |

This avoids fragile Windows service polling and works even if NSSM restarts the process.

---

## Status Telemetry (`watchdog.status.json`)

The watchdog optionally writes structured JSON:

```json
{
  "timestamp": "2025-12-16T22:41:07Z",
  "pid": 14596,
  "state": "Running",
  "mysqlRunning": true,
  "authRunning": true,
  "worldRunning": false,
  "worldRestartCount": 1
}

Used by the GUI to:

Update LED indicators
Display internal state
Diagnose crash-loop protection

Watchdog Control Flow:

1. Startup Sequence
2. Service starts via NSSM
3. Watchdog initializes paths + logging
4. Heartbeat enters Starting state
5. config.json is loaded and validated
6. Service enters main loop

Main Loop (1s cadence):

Check stop signal
Reload config if needed
Validate executable paths
Ensure MySQL running
Ensure Authserver running
Ensure Worldserver running
Update heartbeat + status
Sleep

Ordered Startup Logic:

Startup order is strictly enforced:

MySQL
Authserver
Worldserver

Later services will not start unless prerequisites are running

Graceful Shutdown:

Shutdown may be triggered by-

GUI Stop Watchdog button
Uninstall
Manual stop

Mechanism:

GUI writes stop_watchdog.txt
Watchdog detects file
Writes Stopping heartbeat
Exits cleanly
NSSM handles service state

Crash Loop Protection

Worldserver restarts are limited by:

Maximum restart count
Time-based burst window

If exceeded:

Restarts are suppressed
Watchdog remains alive
State is reported to GUI

Security Model

Service runs as LocalSystem
GUI runs as user
Communication is file-based only
No named pipes, sockets, or RPC
UAC-safe by design

Design Goals
 
Stability over cleverness
Deterministic behavior
Clear ownership boundaries
Survives crashes, reboots, and partial failures

