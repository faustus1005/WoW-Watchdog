# Changelog

## v1.0.0 – Initial Public Release
- GUI-based WoW server watchdog
- Windows service via NSSM

## v1.0.5 – Bug fix, logic, and deployment changes.
- GUI-based WoW server watchdog
- Windows service via NSSM
- Process alias detection (authserver / bnetserver / mysqld variants)
- Crash-loop protection and restart cooldowns
- GUI ↔ service heartbeat integration
- ProgramData-based config and logs
- Inno Setup installer
- 
## v1.1.5 – Bug fix, logic, and feature realse
Feature Additions:
- Added basic auth for NTFY (Username and Password field, Token auth in next release)
- Clear log button for the live log window
Bug Fixes:
- The stop logic did not prevent the service from restarting the db/auth/world servers properly, resulting in
  immediate restart of the service, even when not intended. This has been corrected, Stopping a service now
  keeps the service stopped until started via the button, or the watchdog service is restarted.
- Graceful shutdown was *NOT* maintained when stopping the watchdog service. This has been corrected. Stopping
  the service via the button or Windows Services panel should now result in a graceful shutdown of the services.
- Some logs weren't properly logged to the log file, causing them to briefly flash in the console and then disppear
  on the update ticket.
