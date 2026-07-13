# OVPNMonitor

A retro DOS/iptraf-style terminal user interface (TUI) for monitoring
OpenVPN connections in real time. Written in Python with `curses` and
`psutil`, it provides a live dashboard showing VPN status, traffic
statistics, ping latency, routing table, and network interface details.

Designed to work alongside `autoovpn.py` or as a standalone monitor for
any OpenVPN (or WireGuard) connection.

---

## Quick Start

```bash
# Install dependencies
pip install psutil

# Run with default config (auto-detects VPN)
python ovpnmonitor.py

# Run with custom config
python ovpnmonitor.py -c ~/myconfig.cfg

# Run without ping monitoring
python ovpnmonitor.py --noping

# Run with a specific VPN interface
python ovpnmonitor.py --tun tun0

# Show version
python ovpnmonitor.py --version
```

---

## Requirements

| Dependency | Purpose                                     |
|------------|---------------------------------------------|
| Python 3.8+ | Core runtime                               |
| `curses`    | Terminal UI (stdlib on Linux/macOS)        |
| `psutil`    | Network interface, process detection       |
| `windows-curses` | (Windows only) curses for Windows     |

---

## Command-Line Options

### `-c FILE`, `--config FILE`
Path to the configuration file. If omitted, the program looks for
`./ovpnmonitor.cfg` and then `~/.ovpnmonitor.cfg`. If neither exists,
built-in defaults are used.

```bash
python ovpnmonitor.py -c /etc/ovpnmonitor/ovpnmonitor.cfg
```

### `-v`, `--version`
Print the application name, version number and author, then exit.

```bash
python ovpnmonitor.py --version
# OVPNMonitor v0.0.3 by Igor Brzezek
```

### `--pathping IP`
Enable path monitoring (mtr-style traceroute) to the given IP address.
The route is re-checked every 30 seconds; if it changes, the previous
route is shown for comparison.

```bash
python ovpnmonitor.py --pathping 10.8.0.1
```

### `--tun NAME`
Force a specific TUN/TAP interface name. By default the program
auto-detects VPN interfaces. Use this when auto-detection fails.

```bash
python ovpnmonitor.py --tun tap0
```

### `--int NAME`
Force a specific local (physical) interface name for monitoring.
Use `all` to monitor every detected interface.

```bash
python ovpnmonitor.py --int enp0s3
python ovpnmonitor.py --int all
```

### `--noping`
Disable all ping monitoring. Useful on networks that block ICMP or
when you want a quieter display.

```bash
python ovpnmonitor.py --noping
```

---

## TUI Overview

The screen is divided into four areas:

```
┌──────────────────────────────────────────────────────────────┐
│  OVPNMonitor v0.0.3              ONLINE               PAUSED │  ← Top bar
├──────────────────────┬───────────────────────────────────────┤
│  Traffic Statistics  │  Ping Monitor                         │  ← Row 1
│  ── TUN ──           │  gateway   12 ms ████████████▒▒▒ OK   │
│  Intf  ▼    ▲  Tx... │  8.8.8.8   34 ms ██████▒▒▒▒▒▒▒▒ OK   │
│  tun0  1.2  0.8 ...  │                                       │
│  ── Local ──         │                                       │
│  enp0s3  5.1  3.2... │                                       │
├──────────────────────┼───────────────────────────────────────┤
│  OpenVPN Info        │  Local Interfaces                     │  ← Row 2
│  Public IP: 1.2.3.4 │  Interface:  enp0s3                   │
│  VPN Gateway: 10.8..│  MAC:        08:00:27:...             │
│  ...                 │  IPv4/Mask:  10.0.2.15/24 [24]       │
├──────────────────────┴───────────────────────────────────────┤
│  hostname      H:Help I:Info N:Ping R:Routes A:IP T:Trace P:Pause Q:Quit │  ← Bottom bar
└──────────────────────────────────────────────────────────────┘
```

### Top Status Bar
- **Left**: Application name and version.
- **Center**: Connection state — `ONLINE` (green) or `OFFLINE` (red).
- **Right**: Public IP address (toggle with `A` key, configurable color/char).
- **Far Right**: `PAUSED` (blinking) when collectors are paused.

### Bottom Status Bar
- **Left**: Hostname of the machine.
- **Center**: Available keyboard shortcuts (H,I,N,R,A,T,P,Q).
- **Right**: Current date and time.

### Row 1 — Traffic Statistics + Ping Monitor
- **Traffic Statistics**: For each VPN (TUN) and local interface,
  shows download/upload rates (KB/s), total session bytes (Tx/Rx),
  and packet rates (p/s). Use **arrow keys** to scroll when content
  exceeds the panel height; scroll indicators (▲▼) appear in the
  title bar.
- **Ping Monitor**: For each configured target, shows latency in
  milliseconds and a visual bar. Colors indicate severity (green =
  good, yellow = warning, red = critical).

### Row 2 — OpenVPN Info + Local Interfaces
- **OpenVPN Info**: Public IP, VPN gateway, local VPN IP, server
  address, protocol/port, interface name, PID, uptime, and config
  file path.
- **Local Interfaces**: Interface name, MAC address, IPv4 with
  CIDR mask, IPv6, and DHCP status. In multi-interface mode the
  panel is scrollable with **arrow keys** (▲▼ indicator in title).

### Row 3 — Path Ping (if configured)
Shows the traceroute path to the configured target, one hop per line.
If the route changes, the previous route is shown below.

### Traceroute Dialog (T key)
Opens a text input popup where you enter an IP address or hostname.
Press Enter to run a custom traceroute (UDP probes with TTL, no system
tools required). Results are shown hop-by-hop in real time; `*`
indicates a hop that did not respond (ICMP blocked or timeout). Use
**arrow keys**, **Page Up** / **Page Down** to scroll through results.

---

## Keyboard Shortcuts

| Key              | Action                                           |
|------------------|--------------------------------------------------|
| `H` / `F1`       | Toggle help popup                                |
| `I`              | Toggle program info popup                        |
| `N`              | Show/hide the Ping Monitor panel                 |
| `R`              | Show the system routing table                    |
|                  | (VPN routes highlighted in yellow)               |
| `U`              | Force-refresh the public IP address              |
| `A`              | Toggle public IP display in top bar              |
| `T`              | Open traceroute dialog (enter IP/host)           |
| `P`              | Pause/resume all data collectors                 |
| `Q`              | Quit the application                             |
| `ESC`            | Close any open popup                             |
| `▲` / `▼`        | Scroll panels / traceroute results (1 line)      |
| `PgUp` / `PgDn`  | Scroll panels / traceroute results (5 lines)     |

When a popup (Help, Info, Routes) is open, `Q` does not quit —
press `ESC` first or toggle the popup off.

All key bindings are configurable in the `[keys]` section of the
configuration file.

---

## Popup Windows

### Help (H / F1)
Lists all keyboard shortcuts.

### Program Info (I)
Shows meta-information about the program: name, version, author,
detected VPN interface, PID, config file paths.

### Routes Table (R)
Displays the system IPv4 routing table obtained from `ip route show`
(Linux) or `route print` (Windows). Routes that use a VPN interface
(tun/tap/openvpn/vpn/…) are shown in yellow bold text.

The popup has three columns:

```
  Destination           Gateway            Interface
  default               10.0.2.2           enp0s3
  10.8.0.0/24           10.8.0.2           tun0        ← VPN route
  192.168.1.0/24        192.168.1.1        eth0
```

Routes are fetched live each time the popup is opened.

---

## Data Collectors

The program runs several background daemon threads. Each runs at its
own interval (configurable in the config file):

| Collector            | What It Does                                      |
|----------------------|---------------------------------------------------|
| VPNStatusCollector   | Detects `openvpn` process, parses `.ovpn` config, |
|                      | finds TUN/TAP interfaces via `psutil`              |
| TrafficCollector     | Reads per-interface byte/packet counters,          |
|                      | computes rates (bytes/s, packets/s)                |
| LocalTrafficCollector| Same as above but for local (physical) interfaces  |
| IPCollector          | Fetches public IP via `checkip.amazonaws.com`       |
| GatewayCollector     | Reads default + VPN gateway from `/proc/net/route` |
| LocalNetworkCollector| Detects local interfaces, IPs, MAC, DHCP status    |
| PingCollector        | Pings each configured target (one thread per target)|
| PathPingCollector    | Runs `mtr`/`tracert` to the configured target      |

---

## Configuration File

The configuration file uses standard INI format. The program searches
for it in this order:

1. Explicit path passed with `-c`
2. `./ovpnmonitor.cfg` (next to the script)
3. `~/.ovpnmonitor.cfg` (user home directory)

If none is found, all defaults are used.

### Section `[general]`

| Key                 | Default     | Description                                    |
|---------------------|-------------|------------------------------------------------|
| `app_name`          | OVPNMonitor | Name shown in the top status bar               |
| `version`           | 0.0.3        | Version string                                 |
| `author`            | Igor Brzezek| Author name                                    |
| `background_char`   | (space)     | Fill character for the screen background       |
| `refresh_interval_s`| 1           | UI refresh rate in seconds (1-5)               |
| `vpn_interface`     | auto        | VPN interface name or `auto` for auto-detect   |
| `local_interface`   | (empty)     | Local interface name or `all`; empty = auto    |
| `log_file`          | (empty)     | Path to log file (empty = no logging)          |
| `pathping_target`   | (empty)     | Target IP for path ping; empty = disabled      |
| `show_public_ip`    | false       | Show public IP in top bar by default            |

**Example:**
```ini
[general]
app_name = MyVPN Monitor
vpn_interface = tun1
background_char = .
refresh_interval_s = 2
pathping_target = 10.8.0.1
```

### Section `[keys]`

| Key            | Default | Description                     |
|----------------|---------|---------------------------------|
| `quit`         | q       | Quit application                |
| `help`         | h       | Toggle help popup               |
| `info`         | i       | Toggle program info popup       |
| `refresh_ip`   | u       | Force-refresh public IP         |
| `toggle_pause` | p       | Pause/resume collectors         |
| `toggle_ping`  | n       | Show/hide ping monitor panel    |
| `show_routes`  | r       | Show routes table popup         |
| `toggle_ip`    | a       | Toggle public IP in top bar     |
| `traceroute`   | t       | Open traceroute input dialog     |

**Example:**
```ini
[keys]
quit = x
toggle_ping = p
show_routes = t
```

### Section `[network]`

| Key                  | Default                   | Description                            |
|----------------------|---------------------------|----------------------------------------|
| `ip_check_url`       | https://checkip.amazonaws.com | URL for public IP detection        |
| `ip_check_interval`  | 5                         | Public IP check interval (seconds)     |
| `ping_enabled`       | true                      | Enable/disable all pings               |
| `ping_target_1..3`   | gateway,5000 / 8.8.8.8,5000 / 1.1.1.1,5000 | Ping targets with interval |
| `ping_timeout_ms`    | 2000                      | Ping timeout in milliseconds           |
| `traffic_interval`   | 1                         | Traffic stats refresh (seconds)        |
| `gateway_interval`   | 1                         | Gateway detection interval (seconds)   |
| `vpn_check_interval` | 1                         | VPN process check interval (seconds)   |
| `int_check_interval` | 1                         | Local interface check interval (seconds)|
| `ping_ok_ms`         | 25                        | Threshold for OK latency               |
| `ping_warn_ms`       | 50                        | Threshold for warning latency          |
| `ping_high_ms`       | 100                       | Threshold for high latency             |
| `ping_bad_ms`        | 200                       | Threshold for bad latency              |
| `ping_worse_ms`      | 300                       | Threshold for worse latency            |
| `ping_critical_ms`   | 500                       | Threshold for critical latency         |

Ping targets are specified as `address,interval_ms`. The special
address `gateway` resolves to the detected VPN gateway. Up to 3
targets are supported.

**Example:**
```ini
[network]
ping_enabled = true
ping_target_1 = gateway,3000
ping_target_2 = 8.8.8.8,5000
ping_target_3 = 10.8.0.1,5000
ping_ok_ms = 30
ping_warn_ms = 60
```

### Section `[display]`

| Key              | Default | Description                                    |
|------------------|---------|------------------------------------------------|
| `ping_bar_width` | 25      | Width of the ping latency bar in characters     |
| `border_style`   | double  | Window border style: `single` or `double`       |
| `public_ip_char` | ░       | Prefix character before IP in top bar           |
| `traceroute_input_char` | (space)  | Fill character for traceroute input field    |
| `traceroute_input_width` | 17      | Width of the traceroute input field           |

The `double` style uses Unicode double-line characters (╔═╗║╚═╝).
The `single` style uses single-line characters (┌─┐│└─┘) for a
lighter look.

**Example:**
```ini
[display]
ping_bar_width = 30
border_style = single
```

### Section `[colors]`

Every UI element can be customised with `foreground,background` color
pairs. Colors can be specified as names (`black`, `red`, `green`,
`yellow`, `blue`, `magenta`, `cyan`, `white`, `orange`) or as hex
RGB (`#RRGGBB`). On terminals supporting `can_change_color()`, hex
values define custom colors; otherwise the nearest named color is
used as fallback.

| Key                  | Default        | Element                                  |
|----------------------|----------------|------------------------------------------|
| `background`         | black          | Screen background                        |
| `status_bar_top`     | white,blue     | Top status bar                           |
| `status_bar_bottom`  | white,blue     | Bottom status bar                        |
| `border`             | cyan,black     | Window borders                           |
| `border_title`       | yellow,black   | Window title text                        |
| `text_normal`        | white,black    | Normal text                              |
| `text_label`         | cyan,black     | Labels (field names)                     |
| `text_value`         | green,black    | Values (field data)                      |
| `text_warning`       | yellow,black   | Warning messages and VPN route markers   |
| `text_error`         | red,black      | Error messages                           |
| `online`             | green,white    | ONLINE status badge                      |
| `offline`            | red,white      | OFFLINE status badge                     |
| `highlight`          | black,cyan     | Highlighted items                        |
| `popup_border`       | yellow,black   | Popup window border                      |
| `popup_bg`           | white,black    | Popup interior text                      |
| `window_bgcolor`     | black          | Interior fill of content panels          |
| `public_ip_bar`      | white,blue     | Public IP text in top status bar         |
| `traceroute_border`  | yellow,black   | Traceroute popup border                  |
| `traceroute_bg`      | white,black    | Traceroute popup interior                |
| `traceroute_input`   | black,orange   | Traceroute IP input field                |
| `ping_ok`            | green,black    | Latency below ping_ok_ms                 |
| `ping_warn`          | yellow,black   | Latency between ok and warn              |
| `ping_high`          | yellow,black   | Latency between warn and high            |
| `ping_bad`           | blue,black     | Latency between high and bad             |
| `ping_worse`         | magenta,black  | Latency between bad and worse            |
| `ping_critical`      | red,black      | Latency between worse and critical       |
| `ping_dead`          | red,black      | Latency above critical or unreachable    |

**Example:** Cold-blue theme:
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

---

## Architecture

```
┌──────────┐   collectors (threads)   ┌───────────┐
│ psutil / │───────────┬──────────────▶│           │
│ /proc    │           │               │ MonitorState│
│ iproute2 │───┬───────┼──────┬───────▶│ (shared,  │
│ ping     │   │       │      │        │  locked)  │
│ api.ipify│   │       │      │        │           │
│ mtr      │   │       │      │        └─────┬─────┘
└──────────┘   │       │      │              │
               ▼       ▼      ▼              ▼
        ┌─────────────────────────────────────────┐
        │          UIManager (curses)              │
        │   draw()  ←  reads state, renders TUI    │
        │   handle_key()  ←  user input            │
        └─────────────────────────────────────────┘
```

The program uses a shared `MonitorState` object protected by a
`threading.Lock`. Background collector threads write data into
this object. The main thread reads it once per refresh cycle and
renders the display. Collectors can be paused/resumed with `P`.

---

## Troubleshooting

**No VPN interface detected**
- Make sure OpenVPN is running (`ps aux | grep openvpn`).
- Specify the interface manually: `--tun tun0`.
- Install `psutil` (`pip install psutil`).

**No traffic data**
- Traffic is collected only for detected interfaces.
- If no VPN or local interfaces are found, no data appears.

**Ping shows "timeout"**
- The target may be blocking ICMP or is unreachable.
- Check your network connectivity.
- Increase `ping_timeout_ms` in the config.

**Routes popup shows nothing**
- On Linux, `ip route show` must be available.
- On Windows, `route print` must be accessible.

**Curses errors on Windows**
- Install `windows-curses`: `pip install windows-curses`.

---

## Files

| File                  | Purpose                                |
|-----------------------|----------------------------------------|
| `ovpnmonitor.py`      | Entry point, CLI parser, main loop     |
| `ovpnmonitor_cfg.py`  | Config dataclasses, INI parser, colors |
| `ovpnmonitor_data.py` | Monitor state, collectors, utilities   |
| `ovpnmonitor_ui.py`   | Curses UI rendering, popups, input     |
| `ovpnmonitor.cfg`     | Default configuration file             |

---

## Author

Igor Brzezek

---

## License

MIT
