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

## v1.1.6 – Minor release
Feature Improvements:
- NTFY now supports token authentication in addition to basic auth.
  - Auth Mode is now selected by drop down. Username/Password/Token fields are hidden until the mode is chosen.
- Sensitive data is now stored encrypted in secrets.json, this includes Password/Token currently. 
  At reload of the app, there is no need to fill in the Password/Token fields, though they may display as empty
  the secret is automatically pulled and used from secrets.json.
- Starting window height increased, as it was too short to accomodate all the recent additions

## v1.1.7 – Minor release
Feature Improvements:
- The application has now been split into two tabs, "Main" and "Configuration"
  - Main contains the Control buttons (start/stops) and Status info.
  - Configuration contains all the required config options needed to make the features in Main function.

New Feature:
- There is now a "Online Players" status in the Main page. This will show either a - (if not configured or DB isn't reachable) or a number indicating the online player count.
- In the configuration tab mysql.exe location has been added to Server Paths - this is required at current as it relies on the mysql.exe to gather online player information.
- Database settings, host, user, password, port, DB name, a test DB button, and save DB password button.

## v1.1.8 – Feature Release
- The status info now contains CPU/Memory usage snapshot info. 5s update tick
- Two new tabs have been added: Tools and Updates
  - Tools is currently empty, but will contain useful tools in the next release.
- Updates tab now can check for, and update to the latest GitHub release.
  - Updating will stop the Watchdog. Keep that in mind before running an update.
  
## v1.1.9 – Feature Release
- Tools tab now handled skeezerbean's SPP V2 Legion Management app
 - App will be installed in %appdata%\wowwatchdog if it doesn't already exist there.
 - Once installed, you should use the update feature in the management app, my launcher will *not* update it.
 - If you already use the app, copy your config into the new folder so the launcher installed version has that data. (I may do some form of ingest for this down the road.)
