# Changelog

All notable changes to AutoOpenVPN are documented in this file.

## 2026-09-23 (v0.0.5+)

### Bug Fixes
- **Routes are now restored after an automatic OpenVPN reconnect.**  When the
  connection was dropped and OpenVPN renegotiated it on the same parameters,
  any routes added with `--addroute` / `--routes` were lost from the routing
  table once the tunnel came back up (the tunnel teardown flushes the routes
  that were routed through it).  `autoovpn.py` now watches for every
  `Initialization Sequence Completed` message, including the ones emitted after
  a reconnection, and re-inserts all missing `--addroute` / `--routes` entries
  through the new tunnel.
- Pre-existing routes are still detected and skipped, and are never removed on
  exit (unchanged behavior).  Only the routes actually added by `autoovpn.py`
  are cleaned up, and the PID `.routes` file (used by `--kill`) is kept
  up-to-date after each reconnect.

## 0.0.5 (2026-07-27)

### Features
- Added `--routes FILENAME` option for loading multiple routes
  (`NETWORK/MASK,GATEWAY` per line) instead of repeating `--addroute`.

## 0.0.4 (2026-07-22)

### Features
- Added background (`--daemonize` / `-d`) support to `autoovpn.py`.
- DNS feature added to `ovpnmonitor.py`.

## 0.0.3 (2026-07-13/22)

### Features
- Added multiple local routes support.
- Added public IP address display and Tracert window in the monitor.
- Added `--showip` and `--color` options to `autoovpn.py`.
- Several interface improvements.

## 0.0.2 (2026-06-25)

### Features
- `autoovpn.py`: added `--addroute` option.
- `ovpnmonitor.py`: added Route window and various fixes.

## 0.0.1 (2026-06-25)

### Features
- Initial release: OpenVPN config downloader/runner and companion monitor.