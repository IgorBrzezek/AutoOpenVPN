# AutoOVPN — VPNBook OpenVPN Config Downloader & Runner

**Version:** 0.0.3  
**Author:** Igor Brzezek  
**GitHub:** [https://github.com/IgorBrzezek](https://github.com/IgorBrzezek)  

A Python 3 utility that dynamically scans the [VPNBook](https://www.vpnbook.com/freevpn/openvpn) website for available OpenVPN servers, protocols, and credentials, then downloads ready-to-use `.ovpn` configuration files. It can also directly launch OpenVPN with the downloaded config, manage authentication, inject custom routes, and enforce time-based auto-disconnection.

---

## Table of Contents

1. [Overview](#overview)
2. [Requirements](#requirements)
3. [Quick Start](#quick-start)
4. [Command-Line Options](#command-line-options)
   - [--scan](#--scan)
   - [--get](#--get)
   - [--proto](#--proto)
   - [--port](#--port)
   - [--getlogin](#--getlogin)
   - [--inject, --shortdir, --datadir](#--inject---shortdir---datadir)
   - [--run](#--run)
   - [--dev](#--dev)
   - [--timeout](#--timeout)
   - [--user / --pwd](#--user---pwd)
   - [--datafile](#--datafile)
   - [--addroute](#--addroute)
5. [Examples](#examples)
   - [Scanning Only](#scanning-only)
   - [Downloading Configs](#downloading-configs)
   - [Country Filtering](#country-filtering)
   - [Protocol and Port Filtering](#protocol-and-port-filtering)
   - [Saving Credentials](#saving-credentials)
   - [Injecting Authentication into Configs](#injecting-authentication-into-configs)
   - [Running OpenVPN Directly](#running-openvpn-directly)
   - [Running with Custom Credentials](#running-with-custom-credentials)
   - [Running with an Existing Auth File](#running-with-an-existing-auth-file)
   - [Timeout-Based Auto-Disconnect](#timeout-based-auto-disconnect)
   - [Adding Routes After Connection](#adding-routes-after-connection)
   - [Custom TUN Device Number](#custom-tun-device-number)
6. [The .ovpn Configuration File](#the-ovpn-configuration-file)
7. [The ovpnmonitor.cfg Configuration File](#the-ovpnmonitorcfg-configuration-file)
   - [Section [general]](#section-general)
   - [Section [colors]](#section-colors)
   - [Section [network]](#section-network)
   - [Section [keys]](#section-keys)
   - [Section [addroute]](#section-addroute)
   - [Section [display]](#section-display)
8. [How Dynamic Scanning Works](#how-dynamic-scanning-works)
   - [RSC Payload Extraction](#rsc-payload-extraction)
   - [Server Detection](#server-detection)
   - [Credential Detection](#credential-detection)
   - [Protocol Detection](#protocol-detection)
   - [Fallback Mechanism](#fallback-mechanism)
9. [File Naming Convention](#file-naming-convention)
10. [Architecture Overview](#architecture-overview)
11. [Troubleshooting](#troubleshooting)
12. [Files](#files)
13. [License](#license)

---

## Overview

AutoOVPN automates the entire workflow of obtaining free OpenVPN configuration files from VPNBook:

1. **Scans** the VPNBook website in real time by parsing React Server Component (RSC) payloads embedded in the page HTML.
2. **Extracts** a list of available servers (with hostnames, IP addresses, and country codes), supported protocols (TCP/UDP on various ports), and the current credentials (username/password).
3. **Downloads** `.ovpn` configuration files from the VPNBook API for any combination of server and protocol.
4. **Transforms** the downloaded configs by optionally injecting the `auth-user-pass` directive (pointing to a credentials file), replacing hostnames with IP addresses, and setting a specific TUN device number.
5. **Runs** OpenVPN directly with the downloaded config, managing authentication, adding custom routes, and enforcing time-based auto-disconnection.

If the website cannot be reached or its structure has changed, the program falls back to a built-in static list of 10 servers across 5 countries with 4 protocol variants.

---

## Requirements

| Dependency   | Purpose                                          |
|-------------|--------------------------------------------------|
| Python 3.8+ | Core runtime                                     |
| `openvpn`   | Required for `--run` (OpenVPN client)            |
| `sudo`      | Required for `--run` (privileged tunnel access)  |
| `ip`        | Required for `--addroute` (iproute2 utility)     |

No external Python packages are needed — all imports are from the standard library (`argparse`, `json`, `os`, `re`, `socket`, `subprocess`, `sys`, `signal`, `threading`, `tempfile`, `time`, `urllib.request`, `getpass`).

---

## Quick Start

```bash
# Scan VPNBook and display available servers, protocols, and credentials
python autoovpn.py --scan

# Download all server/protocol combinations
python autoovpn.py --get all

# Download only Canadian servers
python autoovpn.py --get ca

# Download only TCP configs
python autoovpn.py --get all --proto tcp

# Download only port 443 configs
python autoovpn.py --get all --port 443

# Save current login credentials to a file
python autoovpn.py --getlogin myauth.txt

# Download all configs and inject auth-user-pass with full path
python autoovpn.py --get all --inject

# Download all configs and inject with just the filename
python autoovpn.py --get all --inject --shortdir

# Inject with a custom directory path
python autoovpn.py --get all --inject --datadir /etc/openvpn

# Inject with a custom auth filename
python autoovpn.py --get all --inject --getlogin myauth.txt

# Download and immediately run a specific server+protocol combo
python autoovpn.py --run us16,tcp443

# Run a local .ovpn config file
python autoovpn.py --run us16_tcp443_443.ovpn

# Run with custom credentials
python autoovpn.py --run file.ovpn --user vpnbook --pwd secret

# Run with an existing auth file
python autoovpn.py --run file.ovpn --datafile myauth.txt

# Run and add routes after the VPN connects
python autoovpn.py --run us16,tcp443 --addroute 192.168.53.0/24,10.10.10.1 --addroute 10.0.0.0/8,10.8.0.1

# Run with a 1-hour timeout
python autoovpn.py --run us16,tcp443 --timeout 01:00:00

# Display all available --run combinations (without downloading)
python autoovpn.py --run
```

---

## Command-Line Options

### `--scan`

Scan the VPNBook website and display all discovered servers, protocols, and credentials without downloading anything.

```
python autoovpn.py --scan
```

Output example:
```
[*] Scanning VPNBook for available servers and credentials...

============================================================
  VPNBook Scan Results
============================================================

  Credentials:
    Username : vpnbook
    Password : qnd3h2d
    Updated  : June 24, 2026

  OpenVPN Servers (10):
    us16      us16.vpnbook.com
    us178     us178.vpnbook.com
    ca149     ca149.vpnbook.com
    ...

  Protocols (4):
    TCP   443    (tcp443)
    TCP   80     (tcp80)
    UDP   53     (udp53)
    UDP   25000  (udp25000)
```

### `--get`

Download `.ovpn` configuration files. Accepts a country code or `all`.

| Value   | Meaning                                      |
|---------|----------------------------------------------|
| `all`   | Download configs for every detected server   |
| `ca`    | Servers in Canada                            |
| `us`    | Servers in the United States                 |
| `uk`    | Servers in the United Kingdom                |
| `fr`    | Servers in France                            |
| `de`    | Servers in Germany                           |

```
python autoovpn.py --get all        # all servers, all protocols
python autoovpn.py --get ca         # Canadian servers only
python autoovpn.py --get us         # US servers only
```

### `--proto`

Filter by transport protocol when downloading. Works with `--get`.

| Value | Meaning |
|-------|---------|
| `tcp` | TCP only |
| `udp` | UDP only |

```
python autoovpn.py --get all --proto tcp    # TCP configs only
python autoovpn.py --get ca --proto udp     # Canadian UDP configs
```

### `--port`

Filter by port number when downloading. Works with `--get`.

| Value   | Meaning                      |
|---------|------------------------------|
| `443`   | Port 443 (HTTPS)             |
| `80`    | Port 80 (HTTP)               |
| `53`    | Port 53 (DNS)                |
| `25000` | Port 25000                   |

```
python autoovpn.py --get all --port 443     # port 443 only
python autoovpn.py --get us --proto tcp --port 80   # US TCP on port 80
```

### `--getlogin`

Save the scanned (or fallback) username and password to a file, one per line.

```
python autoovpn.py --getlogin myauth.txt
# Creates: myauth.txt containing:
#   vpnbook
#   qnd3h2d
```

When combined with `--inject`, the filename also becomes the reference written into the `auth-user-pass` directive of downloaded `.ovpn` files.

### `--inject`, `--shortdir`, `--datadir`

Modify the `auth-user-pass` directive inside downloaded `.ovpn` configs so that OpenVPN knows where to find the credentials file.

| Flag         | Effect                                                 |
|-------------|--------------------------------------------------------|
| `--inject`  | Add or replace `auth-user-pass /path/to/auth/file` in each `.ovpn` config |
| `--shortdir`| Use only the filename (no directory path) — e.g. `myOvpnBook_data.txt` instead of `/abs/path/myOvpnBook_data.txt` |
| `--datadir` | Specify a custom directory for the auth file path (default: the script's own directory) |

```
# Inject with absolute path (default)
python autoovpn.py --get all --inject
# auth-user-pass /home/user/OpenVPN/myOvpnBook_data.txt

# Inject with filename only
python autoovpn.py --get all --inject --shortdir
# auth-user-pass myOvpnBook_data.txt

# Inject with custom directory
python autoovpn.py --get all --inject --datadir /etc/openvpn
# auth-user-pass /etc/openvpn/myOvpnBook_data.txt

# Inject with custom auth filename
python autoovpn.py --get all --inject --getlogin vpnbook_auth.txt
# auth-user-pass /home/user/OpenVPN/vpnbook_auth.txt
```

When `--inject` is used, the credentials file is automatically created (if it does not already exist) from the scanned credentials.

### `--run`

The most powerful option — download a single config and immediately launch OpenVPN, or run a local `.ovpn` file.

**Usage with server/protocol:**
```
python autoovpn.py --run us16,tcp443
```
This scans VPNBook, downloads the config for `us16` with `tcp443`, optionally modifies it, then runs `sudo openvpn --client --config <file>`.

**Usage with a local `.ovpn` file:**
```
python autoovpn.py --run us16_tcp443_443.ovpn
```

**Display all available combinations (without running):**
```
python autoovpn.py --run
```
This prints a table of all `--run server,protocol` combinations using fallback data.

**Behavior with authentication:**
- If no `--user`/`--pwd` or `--datafile` is given, and the `.ovpn` file already has a valid `auth-user-pass` pointing to an existing file, it is used as-is.
- Otherwise, the program prompts for credentials interactively, creates a temporary auth file, and injects it into the config.
- The temporary auth file is cleaned up when OpenVPN exits.

### `--dev`

Override the TUN device number in the config. The `dev tunX` line is rewritten to `dev tun<N>`. Valid values: `1` through `10`.

```
python autoovpn.py --run us16,tcp443 --dev 3
```

### `--timeout`

Automatically terminate the OpenVPN connection after a specified duration. Format: `HH:MM:SS`.

```
python autoovpn.py --run us16,tcp443 --timeout 02:30:00
# VPN will run for 2 hours and 30 minutes, then disconnect
```

During the countdown, the remaining time is displayed:
```
[*] Time remaining: 02:29:59
```

When the timeout is reached, the program sends `SIGTERM` to the OpenVPN process group, then waits 5 seconds. If the process has not exited, it sends `SIGKILL`.

### `--user`, `--pwd`

Provide VPN credentials directly on the command line. Only valid with `--run`. Both must be specified together.

```
python autoovpn.py --run us16,tcp443 --user vpnbook --pwd qnd3h2d
```

**Security note:** Passing passwords on the command line may expose them to other users on the same system via `/proc` or `ps`. Use `--datafile` or interactive prompt for sensitive environments.

### `--datafile`

Specify a path to an existing authentication file (two lines: username, password). This overrides any `auth-user-pass` already present in the `.ovpn` file. Only valid with `--run`. Mutually exclusive with `--user`/`--pwd`.

```
python autoovpn.py --run us16,tcp443 --datafile /home/user/vpnbook_auth.txt
```

If the `.ovpn` config does not already contain an `auth-user-pass` directive, one is appended.

### `--addroute`

Add one or more network routes through the VPN tunnel after the connection is established. Routes are automatically removed when OpenVPN disconnects. Specify the option multiple times for multiple routes.

Format: `NETWORK/MASK,GATEWAY`

```
# Single route
python autoovpn.py --run us16,tcp443 --addroute 192.168.53.0/24,10.10.10.1

# Multiple routes
python autoovpn.py --run us16,tcp443 \
  --addroute 192.168.53.0/24,10.10.10.1 \
  --addroute 10.0.0.0/8,10.8.0.1
```

The program waits up to 15 seconds for the "Initialization Sequence Completed" message from OpenVPN, then adds each route:
```
sudo ip route add 192.168.53.0/24 via 10.10.10.1
sudo ip route add 10.0.0.0/8 via 10.8.0.1
```

On disconnect (timeout, user interrupt, or OpenVPN exit), routes are cleaned up in reverse order.

When `--addroute` is used, the routes are displayed in the summary before OpenVPN starts:

---

## Examples

### Scanning Only

```
python autoovpn.py --scan
```

Displays the current VPNBook server list, supported protocols, and login credentials. Useful for checking what is available before deciding what to download.

### Downloading Configs

```bash
# Download everything
python autoovpn.py --get all

# Download only Canadian servers
python autoovpn.py --get ca

# Download only UK servers
python autoovpn.py --get uk
```

Files are saved in the same directory as the script, named according to the convention `{server_id}_{protocol_key}_{port}.ovpn` (e.g., `us16_tcp443_443.ovpn`).

### Country Filtering

```bash
# Download all French servers on all protocols/ports
python autoovpn.py --get fr

# Download all German servers on UDP only
python autoovpn.py --get de --proto udp

# Download all US servers on port 443 only
python autoovpn.py --get us --port 443
```

### Protocol and Port Filtering

```bash
# TCP only, all ports
python autoovpn.py --get all --proto tcp

# UDP only, all ports
python autoovpn.py --get all --proto udp

# Port 443 only (both TCP and UDP)
python autoovpn.py --get all --port 443

# TCP on port 80 only
python autoovpn.py --get all --proto tcp --port 80
```

### Saving Credentials

```bash
python autoovpn.py --getlogin vpnbook_credentials.txt
```

This creates (or overwrites) a two-line text file:
```
vpnbook
qnd3h2d
```

### Injecting Authentication into Configs

```bash
# Download all configs with auth injection (absolute path)
python autoovpn.py --get all --inject

# Use filename only in the auth-user-pass directive
python autoovpn.py --get all --inject --shortdir

# Use a custom directory for the auth file path
python autoovpn.py --get all --inject --datadir /etc/openvpn

# Use a custom auth filename
python autoovpn.py --get all --inject --getlogin myvpn.txt
```

Without `--inject`, downloaded `.ovpn` files contain a bare `auth-user-pass` line (with no path), which causes OpenVPN to prompt for credentials interactively.

### Running OpenVPN Directly

```bash
# Download and run a specific server+protocol
python autoovpn.py --run us16,tcp443

# Run a local .ovpn file
python autoovpn.py --run us16_tcp443_443.ovpn
```

When running a local file, if the file does not have a valid `auth-user-pass` directive pointing to an existing file, you will be prompted for credentials.

### Running with Custom Credentials

```bash
# Supply credentials on the command line
python autoovpn.py --run us16,tcp443 --user vpnbook --pwd qnd3h2d

# The auth file is created temporarily and cleaned up on exit
```

### Running with an Existing Auth File

```bash
# First, save credentials to a file
python autoovpn.py --getlogin /etc/openvpn/vpnbook.auth

# Then use it when running
python autoovpn.py --run us16,tcp443 --datafile /etc/openvpn/vpnbook.auth
```

### Timeout-Based Auto-Disconnect

```bash
# Run for exactly 1 hour
python autoovpn.py --run us16,tcp443 --timeout 01:00:00

# Run for 45 minutes
python autoovpn.py --run us16,tcp443 --timeout 00:45:00

# Run for 8 hours
python autoovpn.py --run us16,tcp443 --timeout 08:00:00
```

### Adding Routes After Connection

```bash
# Add a route to a corporate network through the VPN
python autoovpn.py --run us16,tcp443 --addroute 10.0.0.0/8,10.8.0.1

# Add a route to a specific subnet
python autoovpn.py --run us16,tcp443 --addroute 192.168.53.0/24,10.10.10.1

# Add multiple routes (repeat --addroute)
python autoovpn.py --run us16,tcp443 \
  --addroute 192.168.53.0/24,10.10.10.1 \
  --addroute 10.0.0.0/8,10.8.0.1
```

### Custom TUN Device Number

```bash
# Use tun5 instead of the default tun1
python autoovpn.py --run us16,tcp443 --dev 5

# Useful when running multiple VPN instances simultaneously
python autoovpn.py --run us16,tcp443 --dev 1 &
python autoovpn.py --run ca149,tcp80 --dev 2 &
```

---

## The .ovpn Configuration File

The downloaded `.ovpn` files are standard OpenVPN client configurations. A typical file contains:

```
client                    # Operate in client mode
dev tun1                  # Use TUN device tun1
proto tcp                 # Protocol: tcp or udp
remote <ip> <port>        # Server address and port
resolv-retry infinite     # Keep retrying DNS resolution
nobind                    # No local binding
persist-key               # Keep key across restarts
persist-tun               # Keep TUN device across restarts
auth-user-pass <path>     # Credentials file (injected if --inject)
verb 3                    # Verbosity level
cipher AES-256-GCM        # Data channel cipher
auth SHA256               # Authentication algorithm
data-ciphers AES-256-GCM:AES-128-GCM  # Allowed data ciphers
fast-io                   # Optimize I/O
pull                      # Accept pushed options
route-delay 2             # Delay route addition
redirect-gateway          # Redirect all traffic through VPN
<ca>                      # Certificate Authority (PEM)
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</ca>
<cert>                    # Client certificate (PEM)
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</cert>
<key>                     # Client private key (PEM)
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
</key>
```

Key modifications that AutoOVPN applies:
- **`auth-user-pass`**: Injected with an absolute or relative path to the credentials file when `--inject` is used.
- **`remote`**: The hostname is replaced with the IP address to avoid DNS issues (`replace_remote_hostname`).
- **`dev tun<N>`**: The TUN device number is replaced when `--dev` is specified.

---

## The ovpnmonitor.cfg Configuration File

The `ovpnmonitor.cfg` file is an INI-format configuration file used by the companion `ovpnmonitor.py` TUI application. It can also be used by `autoovpn.py` for the `--addroute` setting. Below is a complete reference.

### Section [general]

General application settings.

| Key                 | Default        | Description                                          |
|---------------------|----------------|------------------------------------------------------|
| `app_name`          | OVPNMonitor    | Application name displayed in the top status bar     |
| `version`           | 0.0.3          | Version string                                       |
| `author`            | Igor Brzezek   | Author name                                          |
| `background_char`   | ▒              | Background fill character (e.g. `░`, `▒`, `▓`, `·`, `°`, `#`). Leave empty for solid background. |
| `refresh_interval_s`| 1              | Screen refresh interval in seconds (1–5)             |
| `refresh_interval_ms`| 1000          | Derived from `refresh_interval_s` (milliseconds)     |
| `vpn_interface`     | auto           | VPN interface name. `auto` = auto-detect TAP/TUN adapter |
| `log_file`          | (empty)        | Path to log file. Empty = no logging                 |
| `local_interface`   | (empty)        | Local (physical) interface name. Empty = auto-detect, `all` = all interfaces |
| `pathping_target`   | (empty)        | Target IP for mtr-style path ping monitoring. Empty = disabled |

Example:
```ini
[general]
app_name = MyVPN Monitor
vpn_interface = tun1
background_char = .
refresh_interval_s = 2
pathping_target = 10.8.0.1
```

### Section [colors]

Full color customization for every UI element. Each entry uses the format `foreground,background`.

**Available color names:** `black`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `white`.

| Key                  | Default        | Element                                         |
|----------------------|----------------|-------------------------------------------------|
| `background`         | black          | Screen background color                         |
| `status_bar_top`     | white,blue     | Top status bar (title, version, status)         |
| `status_bar_bottom`  | white,blue     | Bottom status bar (shortcuts, hostname, clock)  |
| `border`             | cyan,black     | Window borders                                  |
| `border_title`       | yellow,black   | Window title text                               |
| `text_normal`        | white,black    | Normal body text                                |
| `text_label`         | cyan,black     | Field labels (e.g. "Public IP:", "Gateway:")    |
| `text_value`         | green,black    | Field values                                    |
| `text_warning`       | yellow,black   | Warning messages and VPN route highlights       |
| `text_error`         | red,black      | Error messages                                  |
| `online`             | green,white    | ONLINE status badge                             |
| `offline`            | red,white      | OFFLINE status badge                            |
| `highlight`          | black,cyan     | Highlighted list items                          |
| `popup_border`       | yellow,black   | Popup window border                             |
| `popup_bg`           | white,black    | Popup interior text                             |
| `window_bgcolor`     | black          | Interior background color for content panels    |
| `ping_ok`            | green,black    | Latency below `ping_ok_ms` threshold            |
| `ping_warn`          | yellow,black   | Latency between ok and warn thresholds          |
| `ping_high`          | yellow,black   | Latency between warn and high thresholds        |
| `ping_bad`           | blue,black     | Latency between high and bad thresholds         |
| `ping_worse`         | magenta,black  | Latency between bad and worse thresholds        |
| `ping_critical`      | red,black      | Latency between worse and critical thresholds   |
| `ping_dead`          | red,black      | Latency above critical or unreachable host      |

Example — cold blue theme:
```ini
[colors]
background = black
status_bar_top = white,blue
status_bar_bottom = white,blue
border = cyan,black
border_title = white,blue
text_label = cyan,black
text_value = white,black
popup_border = cyan,black
popup_bg = white,blue
```

### Section [network]

Network monitoring configuration, including public IP detection, ping targets, and latency thresholds.

| Key                  | Default                        | Description                                      |
|----------------------|--------------------------------|--------------------------------------------------|
| `ip_check_url`       | https://api.ipify.org          | URL for public IP detection                      |
| `ip_check_interval`  | 5                              | Public IP check interval (seconds)               |
| `ping_enabled`       | true                           | Enable or disable all ping monitoring            |
| `ping_target_1`      | gateway,5000                   | First ping target. Format: `address,interval_ms` |
| `ping_target_2`      | 8.8.8.8,5000                   | Second ping target                               |
| `ping_target_3`      | 1.1.1.1,5000                   | Third ping target                                |
| `ping_timeout_ms`    | 2000                           | Ping timeout in milliseconds                     |
| `traffic_interval`   | 1                              | Traffic statistics refresh interval (seconds)    |
| `gateway_interval`   | 1                              | Gateway detection interval (seconds)             |
| `vpn_check_interval` | 1                              | VPN process check interval (seconds)             |
| `int_check_interval` | 1                              | Local interface check interval (seconds)         |
| `ping_ok_ms`         | 25                             | Maximum latency considered "OK" (ms)             |
| `ping_warn_ms`       | 50                             | Warning threshold (ms)                           |
| `ping_high_ms`       | 100                            | High latency threshold (ms)                      |
| `ping_bad_ms`        | 200                            | Bad latency threshold (ms)                       |
| `ping_worse_ms`      | 300                            | Worse latency threshold (ms)                     |
| `ping_critical_ms`   | 500                            | Critical latency threshold (ms)                  |

**Ping target format:** `address,interval_ms`

- `address`: An IP address, hostname, or the special keyword `gateway` (which auto-resolves to the detected VPN gateway).
- `interval_ms`: How often to ping this target, in milliseconds.

Example:
```ini
[network]
ping_enabled = true
ping_target_1 = gateway,3000
ping_target_2 = 8.8.8.8,5000
ping_target_3 = 10.8.0.1,5000
ping_ok_ms = 30
ping_warn_ms = 60
```

### Section [keys]

Customizable keyboard shortcuts for the TUI. Each value is a single character.

| Key            | Default | Action                                         |
|----------------|---------|------------------------------------------------|
| `quit`         | q       | Quit the application                           |
| `help`         | h       | Toggle help popup                              |
| `info`         | i       | Toggle program info popup                      |
| `refresh_ip`   | u       | Force-refresh the public IP address            |
| `toggle_pause` | p       | Pause/resume all data collectors               |
| `toggle_ping`  | n       | Show/hide the ping monitor panel               |
| `show_routes`  | r       | Show the system routing table                  |

Example:
```ini
[keys]
quit = x
toggle_ping = p
show_routes = t
```

### Section [addroute]

Route configuration used by `autoovpn.py --addroute` and the companion monitor.

| Key     | Default | Description                                                |
|---------|---------|------------------------------------------------------------|
| `route` | (empty) | Route to add when VPN connects. Format: `NET/MASK,GATEWAY` |

The route is added after OpenVPN connects and removed on disconnect.

Example:
```ini
[addroute]
route = 192.168.53.0/24,10.10.10.1
```

### Section [display]

Display customization for the TUI.

| Key              | Default | Description                                          |
|------------------|---------|------------------------------------------------------|
| `ping_bar_width` | 25      | Width of the ping latency bar in characters          |
| `border_style`   | double  | Window border style: `single` or `double` (Unicode)  |

Example:
```ini
[display]
ping_bar_width = 30
border_style = single
```

The `double` style uses Unicode double-line box-drawing characters (`╔═╗║╚═╝`). The `single` style uses single-line characters (`┌─┐│└─┘`).

---

## How Dynamic Scanning Works

### RSC Payload Extraction

VPNBook's website is built with Next.js (React Server Components). Server data (servers list, credentials, protocol info) is serialized into JavaScript payloads embedded in the HTML page source. The program extracts these payloads using the regex pattern:

```
self.__next_f.push([1,"<escaped payload>"])
```

Each extracted payload is unescaped and concatenated for analysis.

### Server Detection

**Primary method** (`_scan_servers_rsc`): Searches concatenated RSC payloads for a JSON array labeled `"servers"`. Each server object contains:
- `id`: Short identifier (e.g. `us16`, `ca149`)
- `hostname`: Full hostname (e.g. `us16.vpnbook.com`)
- `ipAddress` (optional): Resolved IP address; if missing, DNS resolution is attempted
- `countryCode`: Two-letter country code

**Fallback method** (`_scan_servers_fallback`): If the JSON array is not found, the program scans payloads with regex for `[a-z]+\d+\.vpnbook\.com` patterns. It deduplicates by server ID and approximates the country code from the ID prefix.

### Credential Detection

**Primary method** (`_scan_credentials_rsc`): Locates the `"VPN Credentials"` section in payloads, then finds the text children immediately after `"Username"` and `"Password"` labels. It also extracts a "Last updated" timestamp.

**Fallback method** (`_scan_credentials_fallback`): If the primary method fails, it searches for `{"text":"..."}` JSON patterns near the Username/Password labels.

### Protocol Detection

The function `_scan_protocols_rsc` verifies that known protocol keys (`tcp443`, `tcp80`, `udp53`, `udp25000`) appear in the payloads, confirming the website is serving the expected protocol set. If confirmed, all four protocol entries are returned with their parsed `proto` (tcp/udp) and `port` values.

### Fallback Mechanism

If scanning fails entirely (network error, changed website structure, no RSC payloads), the program falls back to hardcoded static data:

- **10 servers:** 2 in each of US, CA, UK, DE, FR
- **4 protocols:** TCP 443, TCP 80, UDP 53, UDP 25000
- **Default username:** `vpnbook` (password must be obtained by running `--scan` separately when the website is accessible)

Fallback credentials are displayed with a `*** unknown` placeholder for the password.

---

## File Naming Convention

Downloaded `.ovpn` files follow this naming pattern:

```
{server_id}_{protocol_key}_{port}.ovpn
```

| Component      | Example  | Meaning                     |
|---------------|----------|-----------------------------|
| `server_id`   | `us16`   | Server identifier           |
| `protocol_key`| `tcp443` | Protocol key                |
| `port`        | `443`    | Port number                 |

Full example: `us16_tcp443_443.ovpn`, `ca149_udp53_53.ovpn`, `de20_tcp80_80.ovpn`

All files are saved to the same directory as the `autoovpn.py` script.

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────┐
│  autoovpn.py                                                       │
│                                                                    │
│  ┌─────────────────────┐    ┌─────────────────────────────┐       │
│  │  scan()             │    │  download_config()           │       │
│  │  ┌───────────────┐  │    │  ┌───────────────────────┐  │       │
│  │  │fetch_url()    │  │    │  │urllib → VPNBook API   │  │       │
│  │  │vpnbook.com    │  │    │  │/api/openvpn?hostname= │  │       │
│  │  └───────┬───────┘  │    │  │&protocol=            │  │       │
│  │          │          │    │  └───────────┬───────────┘  │       │
│  │          ▼          │    │              │              │       │
│  │  ┌───────────────┐  │    │              ▼              │       │
│  │  │extract_rsc_   │  │    │  ┌───────────────────────┐  │       │
│  │  │payloads(html) │  │    │  │ Config Transformers   │  │       │
│  │  └───────┬───────┘  │    │  │ inject_auth_user_pass │  │       │
│  │          │          │    │  │ replace_remote_hostname│  │       │
│  │          ▼          │    │  │ replace_dev_tun       │  │       │
│  │  ┌───────────────┐  │    │  └───────────┬───────────┘  │       │
│  │  │scan_servers() │  │    │              │              │       │
│  │  │scan_creds()   │  │    │              ▼              │       │
│  │  │scan_protos()  │  │    │  ┌───────────────────────┐  │       │
│  │  └───────┬───────┘  │    │  │save_config() → .ovpn  │  │       │
│  │          │          │    │  └───────────────────────┘  │       │
│  │          ▼          │    └─────────────────────────────┘       │
│  │  (servers,protocols,┐         ┌───────────────────────┐       │
│  │   credentials)      │         │  _run_openvpn()       │       │
│  └─────────────────────┘         │  sudo openvpn --config│       │
│                                  │  --client             │       │
│  ┌─────────────────────┐         │  + timeout monitoring │       │
│  │  Fallback Data      │         │  + route management   │       │
│  │  (hardcoded)        │         │  + cleanup            │       │
│  └─────────────────────┘         └───────────────────────┘       │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  CLI (argparse) — 16 options                               │  │
│  │  --scan | --get | --proto | --port | --getlogin | --inject │  │
│  │  --shortdir | --datadir | --run | --dev | --timeout        │  │
│  │  --user | --pwd | --datafile | --addroute                  │  │
│  └─────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

The program flow:

1. **CLI Parsing** — `argparse` processes all command-line options and validates combinations.
2. **Scanning** (if needed) — Fetches VPNBook HTML, extracts RSC payloads, parses servers/protocols/credentials.
3. **Fallback** — If scanning fails, hardcoded data is used.
4. **Filtering** — Country, protocol, and port filters are applied.
5. **Authentication Setup** — Credentials are resolved, auth files are created (temp or persistent), and `auth-user-pass` references are computed.
6. **Download Loop** — For each server/protocol combination, the config is fetched from the VPNBook API, transformed (inject auth, replace hostname, replace TUN), and saved.
7. **Run** (if `--run`) — OpenVPN is launched with `sudo`, a background thread reads output, a timer tracks the timeout, and routes are added/removed on connect/disconnect.
8. **Cleanup** — Temporary auth files and config copies are deleted.

---

## Troubleshooting

### "No RSC payloads found"
- VPNBook may have changed its website structure.
- Run `--scan` to see the current state; the program will fall back to hardcoded data.
- The fallback data may be outdated — run with `--scan` periodically to check.

### Download fails for some configs
- The VPNBook API may be temporarily unavailable.
- The specific server/protocol combination may no longer be offered.
- Check your internet connection and try again later.

### OpenVPN fails to start with `--run`
- Ensure `openvpn` and `sudo` are installed.
- Verify you have permission to create TUN/TAP devices.
- Check that the credentials are correct (run `--scan` first).

### "auth-user-pass" errors in OpenVPN
- If using `--inject` without `--shortdir` or `--getlogin`, verify the auth file exists at the absolute path written into the config.
- When moving `.ovpn` files to another machine, either use `--shortdir` and place the auth file next to the config, or use absolute paths.

### Route not added (`--addroute`)
- The program waits up to 15 seconds for OpenVPN to connect. If your connection takes longer, the route may not be added.
- Verify the gateway IP is correct for your VPN tunnel (often the first IP in the VPN subnet, e.g., `10.8.0.1`).
- Run `ip route` after the VPN connects to find the correct gateway.

### Permission denied on temporary auth file
- The program sets permissions to `0o644` (world-readable) so `sudo openvpn` can read it. If this fails, check your `umask` and file system permissions.

### OpenVPN process not found
- The program detects OpenVPN by checking for a running process named `openvpn`. If the binary is installed under a different name, detection may fail.

---

## Files

| File                       | Purpose                                                   |
|----------------------------|-----------------------------------------------------------|
| `autoovpn.py`              | Main script: CLI parser, website scanner, downloader, runner |
| `ovpnmonitor.cfg`          | Configuration file for the companion OVPNMonitor TUI      |
| `ovpnmonitor.py`           | Companion TUI monitor (curses-based real-time dashboard)  |
| `ovpnmonitor_cfg.py`       | Config parser for the companion monitor                  |
| `ovpnmonitor_data.py`      | Data collectors and shared state for the companion monitor|
| `ovpnmonitor_ui.py`        | Curses UI rendering for the companion monitor            |
| `ovpn_data.py`             | Data module for OpenVPN status information               |
| `*.ovpn`                   | Downloaded OpenVPN configuration files                    |

---

## License

MIT
