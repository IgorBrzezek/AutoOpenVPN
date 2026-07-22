# OpenVPN Toolkit — autoovpn.py + ovpnmonitor.py + ovpn_data.py

A set of three Python tools for working with free [VPNBook](https://www.vpnbook.com/freevpn/openvpn) OpenVPN servers:

| Tool              | Purpose                                                |
|-------------------|--------------------------------------------------------|
| `autoovpn.py`     | Scan VPNBook, download `.ovpn` configs, run OpenVPN    |
| `ovpnmonitor.py`  | Real-time TUI dashboard for monitoring the VPN tunnel  |
| `ovpn_data.py`    | Fetch VPNBook login credentials and save to a file     |

All three are designed to work independently or together, forming a complete VPN workflow: **get credentials → download config → connect → monitor**.

---

## Quick Overview

```
  ovpn_data.py              autoovpn.py                 ovpnmonitor.py
  ┌──────────────┐          ┌──────────────────┐        ┌──────────────────┐
  │ Fetch        │          │ Scan vpnbook.com │        │ curses TUI       │
  │ credentials  │  ──►     │ Download .ovpn   │  ──►   │ Traffic stats    │
  │ from website │          │ Run OpenVPN      │        │ Ping latency     │
  │ Save to file │          │ Add routes       │        │ VPN info/routes  │
  └──────────────┘          │ Timeout mgmt     │        │ Live dashboard   │
                            └──────────────────┘        └──────────────────┘
                                   │                           │
                                   ▼                           ▼
                            ┌───────────────────────────────────────┐
                            │         OpenVPN Tunnel (tun0)         │
                            └───────────────────────────────────────┘
```

---

## Quick Guide — Connect & Monitor in 2 Minutes

```bash
# 1. Terminal 1: Connect to a US server (auto-downloads config + prompts for credentials)
python autoovpn.py --run us16,tcp443

# 2. Terminal 2: Launch live monitor (auto-detects the VPN tunnel)
python ovpnmonitor.py
```

Your public IP will change once OpenVPN connects. The monitor shows your new IP, traffic, and ping in real time.

**One-liner (single terminal, background monitor):**
```bash
python autoovpn.py --run us16,tcp443 & sleep 5 && python ovpnmonitor.py
```

**With saved credentials (no prompt):**
```bash
# Save credentials first
python ovpn_data.py --get -q -w /tmp/vpn.auth --overwrite
# Connect using the saved file
python autoovpn.py --run us16,tcp443 --datafile /tmp/vpn.auth
```

**Stop:** Press `Ctrl+C` in the autoovpn terminal, or press `Q` in the monitor.

---

## Script-by-Script Description

### autoovpn.py

**File:** `autoovpn.py`  
**Version:** 0.0.3  
**Role:** The main workhorse — scans VPNBook, downloads configs, runs OpenVPN.

- Dynamically scrapes the VPNBook website by parsing React Server Component (RSC) payloads embedded in the page HTML.
- Extracts the server list (10+ servers in US, CA, UK, DE, FR), supported protocols (TCP 443/80, UDP 53/25000), and current credentials.
- Downloads `.ovpn` config files via the VPNBook API, with optional `auth-user-pass` injection, hostname-to-IP replacement, and TUN device override.
- Can directly launch OpenVPN with `--run`, supporting custom credentials, auth files, timeout-based auto-disconnect, and post-connect route injection.
- Falls back to a built-in static server list if the website is unreachable.

**Key commands:**
```bash
python autoovpn.py --scan                          # Scan and display
python autoovpn.py --get all                       # Download all configs
python autoovpn.py --get ca --proto tcp            # Canadian TCP only
python autoovpn.py --run us16,tcp443               # Download & connect
python autoovpn.py --run us16.ovpn --timeout 02:00:00  # Run with timeout
python autoovpn.py --run us16,tcp443 --addroute 192.168.53.0/24,10.10.10.1 --addroute 10.0.0.0/8,10.8.0.1
```

For full documentation, see [README_openvpn.md](README_openvpn.md).

---

### ovpnmonitor.py

**File:** `ovpnmonitor.py` + `ovpnmonitor_cfg.py` + `ovpnmonitor_data.py` + `ovpnmonitor_ui.py`  
**Version:** 0.0.3  
**Role:** Real-time terminal dashboard for monitoring the OpenVPN connection.

A retro DOS/iptraf-style TUI built with Python `curses`. It runs in a terminal and displays:

- **Traffic Statistics** — Download/upload rates (KB/s), total bytes (Tx/Rx), packet rates for both VPN (TUN) and local interfaces.
- **Ping Monitor** — Live latency to configurable targets (VPN gateway, DNS servers, etc.) with color-coded bars.
- **OpenVPN Info** — Public IP, VPN gateway, local VPN IP, server address, protocol/port, PID, uptime, config file path.
- **Local Interfaces** — MAC address, IPv4/IPv6 with CIDR, DHCP status.
- **Routes Table** — System routing table with VPN routes highlighted (toggled with `R`).
- **Path Ping** — Optional mtr-style traceroute to a target (enabled with `--pathping`).

Background collector threads fetch data at configurable intervals and write to a shared, thread-safe `MonitorState` object. The UI reads this object once per refresh cycle.

**Key commands:**
```bash
python ovpnmonitor.py                              # Run with default config
python ovpnmonitor.py -c myconfig.cfg              # Custom config
python ovpnmonitor.py --tun tun0                   # Force specific interface
python ovpnmonitor.py --noping                     # Disable ping monitoring
python ovpnmonitor.py --pathping 10.8.0.1           # Enable path tracing
```

**Keyboard shortcuts:** `Q` quit, `H` help, `I` info, `N` toggle ping, `R` routes, `U` refresh IP, `P` pause.

---

### ovpn_data.py

**File:** `ovpn_data.py`  
**Version:** 0.0.2 (standalone utility)  
**Role:** Fetch VPNBook credentials from the website and optionally save to a file.

A lightweight credential scraper. It fetches the VPNBook freevpn page, parses HTML `<code>` elements with class `font-mono`, identifies the username (`vpnbook`) and the corresponding password, and either displays them or saves to a file.

**Key commands:**
```bash
python ovpn_data.py --get                          # Scrape and display
python ovpn_data.py --get -w                       # Scrape, display, save to ovpn_data.txt
python ovpn_data.py --get -w custom.txt            # Save to custom file
python ovpn_data.py --get -q -w --overwrite        # Quiet, overwrite without prompt
python ovpn_data.py --username vpnbook --password PASSWORD  # Inline, no scraping
```

---

## How They Work Together

### Typical Combined Workflow

```
Step 1: Get credentials ── ovpn_data.py
Step 2: Download config ── autoovpn.py
Step 3: Connect           autoovpn.py --run
Step 4: Monitor       ──  ovpnmonitor.py (in another terminal)
```

### Example Session

```bash
# Terminal 1: Fetch and save credentials
python ovpn_data.py --get -w vpnbook_auth.txt

# Terminal 1: Download configs for all servers
python autoovpn.py --get all --inject --getlogin vpnbook_auth.txt

# Terminal 1: Connect to a VPN server with a 4-hour timeout
python autoovpn.py --run us16,tcp443 --timeout 04:00:00

# Terminal 2 (separate window): Launch the monitor
python ovpnmonitor.py --tun tun0
```

### Data Flow

```
  ovpn_data.py
       │
       │  Saves: vpnbook_auth.txt (username + password)
       ▼
  autoovpn.py --inject ──►  Injects auth-user-pass into .ovpn files
       │
       │  Downloads: us16_tcp443_443.ovpn (and others)
       ▼
  autoovpn.py --run   ──►  sudo openvpn --config us16_tcp443_443.ovpn
       │
       │  Creates: tun0 (TUN interface)
       ▼
  ovpnmonitor.py      ──►  Detects OpenVPN process & tun0 interface
                           Displays live traffic, ping, routing
```

### Credential Sharing

`ovpn_data.py` and `autoovpn.py` both need the VPNBook credentials. The recommended pattern:

```bash
# Use ovpn_data.py to fetch and save
python ovpn_data.py --get -w vpnbook_auth.txt

# Then pass the file to autoovpn.py
python autoovpn.py --run us16,tcp443 --datafile vpnbook_auth.txt

# Or inject it into downloaded configs
python autoovpn.py --get all --inject --getlogin vpnbook_auth.txt
```

---

## Usage Scenarios

### Scenario 1: Separate Terminals (Recommended)

Run `autoovpn.py` in one terminal and `ovpnmonitor.py` in another. This gives you full control over the VPN connection alongside a live dashboard.

**Terminal 1 — Connect:**
```bash
python autoovpn.py --run us16,tcp443
```

**Terminal 2 — Monitor:**
```bash
python ovpnmonitor.py
```

The monitor auto-detects the OpenVPN process and TUN interface, so no configuration is needed.

### Scenario 2: Single Terminal with screen/tmux

Use a terminal multiplexer to split the screen. This is useful on servers or headless machines where you only have one SSH session.

#### Using tmux

```bash
# Start a new tmux session
tmux new -s vpn

# Split vertically: left pane for autoovpn, right for monitor
tmux split-window -h

# Left pane (autoovpn):
python autoovpn.py --run us16,tcp443

# Switch to right pane (Ctrl+B, then arrow right), then:
python ovpnmonitor.py

# Or use Ctrl+B, " to split horizontally instead
```

#### Using screen

```bash
# Start a screen session
screen -S vpn

# Create a horizontal split
Ctrl+A, Shift+S

# Focus the new region
Ctrl+A, Tab

# Create a shell in it
Ctrl+A, Ctrl+C

# Now run autoovpn.py in one region and ovpnmonitor.py in the other

# Switch between regions: Ctrl+A, Tab
# Kill current region: Ctrl+A, X
# Detach: Ctrl+A, D
# Reattach: screen -r vpn
```

#### Using tmux with a script

Create a launcher script `vpn-session.sh`:

```bash
#!/bin/bash
SESSION="vpn"

tmux new-session -d -s "$SESSION" -n "vpn"
tmux send-keys -t "$SESSION" "python autoovpn.py --run us16,tcp443" Enter
tmux split-window -h -t "$SESSION"
tmux send-keys -t "$SESSION" "sleep 5 && python ovpnmonitor.py" Enter
tmux attach -t "$SESSION"
```

### Scenario 3: Automated Pipeline

Use all three tools in sequence for a fully automated session:

```bash
#!/bin/bash
# 1. Fetch credentials
python ovpn_data.py --get -q -w /tmp/vpnbook.auth --overwrite

# 2. Download and connect with a 2-hour timeout
python autoovpn.py --run us16,tcp443 \
  --datafile /tmp/vpnbook.auth \
  --timeout 02:00:00 \
  --addroute 192.168.53.0/24,10.10.10.1 \
  --addroute 10.0.0.0/8,10.8.0.1
```

### Scenario 4: Monitor-Only (Standalone)

If you already have an OpenVPN connection established manually or via another tool, `ovpnmonitor.py` still works:

```bash
# Manually start OpenVPN
sudo openvpn --config /path/to/config.ovpn

# In another terminal, start the monitor
python ovpnmonitor.py --tun tun0
```

### Scenario 5: Credential-Only (Modern Site Scanner)

When you just need the current VPNBook password:

```bash
# Display only
python ovpn_data.py --get

# Save to file for other tools
python ovpn_data.py --get -w /etc/openvpn/auth.txt
```

---

## Configuration File (ovpnmonitor.cfg)

All three tools share the same `ovpnmonitor.cfg` INI file. Key sections relevant to interoperability:

```ini
[addroute]
# autoovpn.py reads this for default routes
route = 192.168.53.0/24,10.10.10.1

[network]
# ovpnmonitor.py uses these for ping monitoring
ping_target_1 = gateway,5000
ping_target_2 = 8.8.8.8,5000
ping_target_3 = 1.1.1.1,5000

[general]
# ovpnmonitor.py auto-detects VPN interface; override if needed
vpn_interface = auto
```

---

## Process Management and Lifecycle

```
  ┌──────────────────────────────────────────────────────────────┐
  │                      User Workflow                           │
  │                                                              │
  │  1. ovpn_data.py ──► fetches credentials (exit)              │
  │  2. autoovpn.py ──► downloads configs, runs OpenVPN          │
  │       │               (blocks until timeout or Ctrl+C)       │
  │       ▼                                                      │
  │  3. ovpnmonitor.py ──► TUI monitor (runs until Q)            │
  │       │               (independent process, reads /proc)     │
  │       ▼                                                      │
  │  4. Both exit when VPN disconnects or user quits             │
  └──────────────────────────────────────────────────────────────┘
```

- `ovpn_data.py` is ephemeral — it fetches and exits.
- `autoovpn.py` with `--run` is a long-lived process — it keeps OpenVPN running and blocks until timeout, user interrupt (`Ctrl+C`), or OpenVPN exit.
- `ovpnmonitor.py` is a long-lived TUI — it polls system state and never writes to the VPN interface, so it can be started/stopped independently.

All three can be safely interrupted with `Ctrl+C`. The monitor also handles terminal resize events.

---

## Dependencies

| Dependency        | autoovpn.py | ovpnmonitor.py | ovpn_data.py |
|-------------------|:-----------:|:--------------:|:------------:|
| Python 3.8+       |      ✓      |       ✓        |      ✓       |
| `curses` (stdlib) |             |       ✓        |              |
| `psutil`          |             |       ✓        |              |
| `openvpn` binary  |   ✓ (--run) |                |              |
| `sudo`            |   ✓ (--run) |                |              |
| `ip` (iproute2)   | ✓ (--addroute)|              |              |

Install monitor dependencies:
```bash
pip install psutil
```

---

## Files

| File                   | Purpose                                            |
|------------------------|----------------------------------------------------|
| `autoovpn.py`          | VPNBook scanner, config downloader, OpenVPN runner |
| `ovpnmonitor.py`       | Curses TUI monitor entry point                     |
| `ovpnmonitor_cfg.py`   | Config dataclasses and INI parser                  |
| `ovpnmonitor_data.py`  | Monitor state, background collectors               |
| `ovpnmonitor_ui.py`    | Curses UI rendering and keyboard handling          |
| `ovpn_data.py`         | VPNBook credential scraper                         |
| `ovpnmonitor.cfg`      | Shared configuration file (INI format)             |
| `README_openvpn.md`    | Full documentation for autoovpn.py                 |
| `README_ovpnmonitor.md`| Full documentation for ovpnmonitor.py              |
| `*.ovpn`               | Downloaded OpenVPN configuration files             |

---

## License

MIT
