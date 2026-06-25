#!/usr/bin/env python3
"""Download VPNBook OpenVPN configs with dynamic website scanning.

Examples:
  autoovpn --scan                     # scan & display only
  autoovpn --get all                  # scan & download all server/protocol combos
  autoovpn --get ca                   # download only Canadian servers
  autoovpn --get all --proto tcp      # TCP only
  autoovpn --get all --port 443       # port 443 only
  autoovpn --getlogin FILE            # save login/password to file
  autoovpn --get all --inject         # inject auth-user-pass with full path
  autoovpn --get all --inject --shortdir   # inject with just filename
  autoovpn --get all --inject --datadir /etc/openvpn  # custom dir in path
  autoovpn --get all --inject --getlogin myauth.txt   # custom auth filename
   autoovpn --run us16,tcp443          # download & run server+protocol combo
   autoovpn --run us16_tcp443_443.ovpn # run a local .ovpn config file
   autoovpn --run file.ovpn --user vpnbook --pwd secret # with custom credentials
   autoovpn --run file.ovpn --datafile myauth.txt   # with existing auth file
   autoovpn --run us16,tcp443 --addroute 192.168.53.0/24,10.10.10.1  # add route after connect
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import signal
import threading
import tempfile
import time
import urllib.request
import getpass


AUTHOR = "Igor Brzezek"
VERSION = "0.0.1"
GITHUB = "https://github.com/IgorBrzezek"

# ---------------------------------------------------------------------------
# Fallback hardcoded data (used when no scan-based option is given)
# ---------------------------------------------------------------------------
FALLBACK_SERVERS = [
    {"id": "us16",  "hostname": "us16.vpnbook.com",        "ip_address": "147.135.15.16",  "country_code": "US"},
    {"id": "us178", "hostname": "us178.vpnbook.com",       "ip_address": "147.135.37.178", "country_code": "US"},
    {"id": "ca149", "hostname": "ca149.vpnbook.com",       "ip_address": "144.217.253.149","country_code": "CA"},
    {"id": "ca196", "hostname": "ca196.vpnbook.com",       "ip_address": "142.4.216.196",  "country_code": "CA"},
    {"id": "uk205", "hostname": "uk205.vpnbook.com",       "ip_address": "145.239.252.205","country_code": "GB"},
    {"id": "uk68",  "hostname": "uk68.vpnbook.com",        "ip_address": "145.239.255.68", "country_code": "GB"},
    {"id": "de20",  "hostname": "de20.vpnbook.com",        "ip_address": "51.75.145.20",   "country_code": "DE"},
    {"id": "de220", "hostname": "de220.vpnbook.com",       "ip_address": "51.75.145.220",  "country_code": "DE"},
    {"id": "fr200", "hostname": "fr200.vpnbook.com",       "ip_address": "5.196.64.200",   "country_code": "FR"},
    {"id": "fr231", "hostname": "fr2311.vpnbook.com",      "ip_address": "5.196.64.231",   "country_code": "FR"},
]

FALLBACK_PROTOCOLS = [
    {"key": "tcp443",   "port": "443",  "proto": "tcp"},
    {"key": "tcp80",    "port": "80",   "proto": "tcp"},
    {"key": "udp53",    "port": "53",   "proto": "udp"},
    {"key": "udp25000", "port": "25000","proto": "udp"},
]

FALLBACK_USERNAME = "vpnbook"
FALLBACK_PASSWORD = ""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def fetch_url(url, timeout=30):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Accept": "*/*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def parse_protocol_key(key):
    m = re.match(r"^(tcp|udp)(\d+)$", key)
    return (m.group(1), m.group(2)) if m else (None, None)


# ---------------------------------------------------------------------------
# RSC (React Server Components) payload extraction
# ---------------------------------------------------------------------------

def extract_rsc_payloads(html):
    pattern = r"self\.__next_f\.push\(\[1,\"((?:[^\"\\]|\\.)*)\"\]\)"
    payloads = []
    for m in re.finditer(pattern, html):
        raw = m.group(1)
        try:
            payloads.append(raw.encode().decode("unicode_escape"))
        except Exception:
            pass
    return payloads


def _resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return hostname


def _scan_servers_rsc(payloads):
    """Extract server list from RSC 'servers' JSON array."""
    for payload in payloads:
        idx = payload.find('"servers":[')
        if idx < 0:
            continue
        decoder = json.JSONDecoder()
        try:
            data, pos = decoder.raw_decode(payload[idx + len('"servers":'):])
            return [{
                "id": s["id"],
                "hostname": s["hostname"],
                "ip_address": s.get("ipAddress", _resolve_ip(s["hostname"])),
                "country_code": s.get("countryCode", ""),
            } for s in data]
        except (json.JSONDecodeError, KeyError):
            continue
    return None


def _scan_servers_fallback(payloads):
    """Fallback: extract hostnames via regex from RSC payloads."""
    seen = set()
    servers = []
    for payload in payloads:
        for m in re.finditer(r'([a-z]+\d+)\.vpnbook\.com', payload):
            hostname = m.group(0)
            sid = m.group(1)
            if sid not in seen:
                seen.add(sid)
                servers.append({"id": sid, "hostname": hostname,
                                "ip_address": _resolve_ip(hostname),
                                "country_code": sid[:2].upper()})
    return servers if servers else None


def scan_servers(payloads):
    result = _scan_servers_rsc(payloads)
    if result:
        return result
    return _scan_servers_fallback(payloads)


def _first_value_after(combined, marker):
    idx = combined.find(marker)
    if idx < 0:
        return None
    rest = combined[idx + len(marker):]
    seen_labels = {"VPN Credentials", "Username", "Password",
                   "Use these credentials for all VPN servers"}
    for m in re.finditer(r'children":"([^"]+)"', rest):
        val = m.group(1)
        if val not in seen_labels:
            return val
    return None


def _scan_credentials_rsc(payloads):
    """Extract username/password from RSC credentials section."""
    combined = " ".join(payloads)
    idx = combined.find('"VPN Credentials"')
    if idx < 0:
        return None, None, None
    section = combined[idx:idx + 2000]
    username = _first_value_after(section, '"children":"Username"')
    password = _first_value_after(section, '"children":"Password"')
    lm = re.search(r'Last updated:\s*([^"]+)', section)
    last_updated = lm.group(1).strip() if lm else None
    return username, password, last_updated


def _scan_credentials_fallback(payloads):
    """Fallback: look for CopyButton text props which mirror the credentials."""
    combined = " ".join(payloads)
    # Find the VPN Credentials section first
    idx = combined.find('"VPN Credentials"')
    if idx < 0:
        return None, None, None
    section = combined[idx:idx + 2000]
    username = None
    password = None
    # Look for {"text":"..."} patterns after "Username"/"Password" labels
    after_u = section.find('"children":"Username"')
    after_p = section.find('"children":"Password"')
    if after_u >= 0:
        m = re.search(r'\{"text":"([^"]+)"\}', section[after_u:after_u + 300])
        if m:
            username = m.group(1)
    if after_p >= 0:
        m = re.search(r'\{"text":"([^"]+)"\}', section[after_p:after_p + 300])
        if m:
            password = m.group(1)
    lm = re.search(r'Last updated:\s*([^"]+)', section)
    last_updated = lm.group(1).strip() if lm else None
    if username and password:
        return username, password, last_updated
    return None, None, None


def scan_credentials(payloads):
    result = _scan_credentials_rsc(payloads)
    if result[0] and result[1]:
        return result
    result = _scan_credentials_fallback(payloads)
    if result[0] and result[1]:
        return result
    return None, None, None


def _scan_protocols_rsc(payloads):
    """Extract protocol keys from combined RSC payload.  Keys are stable
    VPNBook values, but we verify they appear before accepting them."""
    combined = " ".join(payloads)
    if 'tcp443' not in combined or 'udp25000' not in combined:
        return None
    keys = ["tcp443", "tcp80", "udp53", "udp25000"]
    protocols = []
    for key in keys:
        proto, port = parse_protocol_key(key)
        if proto:
            protocols.append({"key": key, "port": port, "proto": proto})
    return protocols if protocols else None


def scan_protocols(payloads):
    return _scan_protocols_rsc(payloads)


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def scan():
    print("[*] Scanning VPNBook for available servers and credentials...\n")
    try:
        html = fetch_url("https://www.vpnbook.com/freevpn/openvpn")
    except Exception as e:
        print(f"  [!] Network error: {e}", file=sys.stderr)
        return None, None, (None, None, None)

    payloads = extract_rsc_payloads(html)
    if not payloads:
        print("  [!] No RSC payloads found — website structure may have changed.", file=sys.stderr)
        return None, None, (None, None, None)

    servers = scan_servers(payloads)
    protocols = scan_protocols(payloads)
    username, password, last_updated = scan_credentials(payloads)

    print("=" * 60)
    print("  VPNBook Scan Results")
    print("=" * 60)

    if username and password:
        print(f"\n  Credentials:")
        print(f"    Username : {username}")
        print(f"    Password : {password}")
        if last_updated:
            print(f"    Updated  : {last_updated}")

    if servers:
        print(f"\n  OpenVPN Servers ({len(servers)}):")
        for s in servers:
            print(f"    {s['id']:8s}  {s['hostname']}")

    if protocols:
        print(f"\n  Protocols ({len(protocols)}):")
        for p in protocols:
            print(f"    {p['proto'].upper():4s}  {p['port']:6s}  ({p['key']})")

    print(f"\n{'=' * 60}\n")

    return servers, protocols, (username, password, last_updated)


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------

def download_config(server, protocol):
    url = (f"https://www.vpnbook.com/api/openvpn"
           f"?hostname={server['hostname']}&protocol={protocol['key']}")
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Accept": "*/*",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except Exception as e:
        print(f"  [!] Failed: {url} - {e}", file=sys.stderr)
        return None


def inject_auth_user_pass(config, auth_ref):
    config = re.sub(r'^auth-user-pass\s*$',
                    f'auth-user-pass {auth_ref}',
                    config, flags=re.MULTILINE)
    config = re.sub(r'^auth-user-pass\s+.*$',
                    f'auth-user-pass {auth_ref}',
                    config, flags=re.MULTILINE)
    return config


def replace_remote_hostname(config, hostname, ip_address):
    """Replace `remote <hostname> ...` with `remote <ip_address> ...`."""
    return re.sub(
        rf'^remote\s+{re.escape(hostname)}\s+',
        f'remote {ip_address} ',
        config,
        flags=re.MULTILINE,
    )


def replace_dev_tun(config, tun_num):
    """Replace `dev tunX` with `dev tun<N>`."""
    return re.sub(r'^dev\s+tun\d+', f'dev tun{tun_num}', config, flags=re.MULTILINE)


def save_config(server, protocol, config):
    filename = f"{server['id']}_{protocol['key']}_{protocol['port']}.ovpn"
    filepath = os.path.join(SCRIPT_DIR, filename)
    with open(filepath, "w") as f:
        f.write(config)
    print(f"  [+] {filename}")
    return filepath


def print_static_options(servers, protocols, username, password):
    """Print available options in --scan format using static fallback data."""
    print("=" * 60)
    print("  VPNBook Scan Results (fallback)")
    print("=" * 60)

    print(f"\n  Credentials:")
    print(f"    Username : {username}")
    pw = password if password else "*** unknown – run --scan separately ***"
    print(f"    Password : {pw}")

    if protocols:
        print(f"\n  Protocols ({len(protocols)}):")
        for p in protocols:
            print(f"    {p['proto'].upper():4s}  {p['port']:6s}  ({p['key']})")

    if servers and protocols:
        print(f"\n  All --run combinations ({len(servers) * len(protocols)} total, by country):\n")
        cc_map = {}
        for s in servers:
            cc = s.get("country_code", "??")
            cc_map.setdefault(cc, []).append(s)
        for cc in sorted(cc_map):
            country_label = {"US": "USA", "CA": "Canada", "GB": "UK",
                             "DE": "Germany", "FR": "France"}.get(cc, cc)
            group = cc_map[cc]
            header = f"  [{country_label} ({cc})]"
            print(f"  {'─' * (len(header) - 2)}")
            print(header)
            print(f"  {'─' * (len(header) - 2)}")
            for s in group:
                for p in protocols:
                    proto_flag = "U" if p["proto"] == "udp" else "T"
                    print(f"    --run {s['id']},{p['key']:12s}  # {proto_flag}:{p['port']}  {s['hostname']}")

    print(f"\n{'=' * 60}\n")


# ---------------------------------------------------------------------------
# OpenVPN runner
# ---------------------------------------------------------------------------

def parse_addroute(value):
    parts = value.split(',')
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(
            "Format must be NETWORK/MASK,GATEWAY (e.g. 192.168.53.0/24,10.10.10.1)")
    network_cidr, gateway = parts[0].strip(), parts[1].strip()
    cidr_parts = network_cidr.split('/')
    if len(cidr_parts) != 2:
        raise argparse.ArgumentTypeError(
            f"Invalid CIDR: '{network_cidr}' (expected NET/MASK)")
    try:
        socket.inet_aton(cidr_parts[0])
        mask = int(cidr_parts[1])
        if mask < 0 or mask > 32:
            raise argparse.ArgumentTypeError(
                f"Invalid mask {mask} (must be 0-32)")
        socket.inet_aton(gateway)
    except (OSError, ValueError) as e:
        raise argparse.ArgumentTypeError(
            f"Invalid --addroute '{value}': {e}")
    return (network_cidr, gateway)


def _add_route(network_cidr, gateway):
    cmd = ["sudo", "ip", "route", "add", network_cidr, "via", gateway]
    print(f"[*] Adding route: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Failed to add route: {result.stderr.strip()}", file=sys.stderr)
        return False
    print(f"[+] Route added: {network_cidr} via {gateway}")
    return True


def _del_route(network_cidr, gateway):
    cmd = ["sudo", "ip", "route", "del", network_cidr, "via", gateway]
    print(f"[*] Removing route: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Failed to remove route: {result.stderr.strip()}", file=sys.stderr)
        return False
    print(f"[-] Route removed: {network_cidr} via {gateway}")
    return True


def _run_openvpn(config_path, timeout_seconds, timeout_str, temp_auth_file=None, addroute=None):
    cmd = ["sudo", "openvpn", "--client", "--config", config_path]
    print(f"[*] Running: {' '.join(cmd)}\n")
    process = None
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            preexec_fn=os.setpgrp, universal_newlines=True, bufsize=1)
    except FileNotFoundError:
        print("[!] 'sudo' or 'openvpn' not found. Install them or check your PATH.",
              file=sys.stderr)
        return

    route_added = False
    connected_event = threading.Event()

    def _output_reader():
        for line in process.stdout:
            print(line, end='', flush=True)
            if 'Initialization Sequence Completed' in line:
                connected_event.set()

    reader = threading.Thread(target=_output_reader, daemon=True)
    reader.start()

    if addroute:
        connected = connected_event.wait(timeout=15)
        if connected:
            route_added = _add_route(*addroute)
        else:
            print("[!] OpenVPN not connected after 15s, route not added.", file=sys.stderr)

    def _kill_pg():
        try:
            pgid = os.getpgid(process.pid)
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    def _kill_pg_hard():
        try:
            pgid = os.getpgid(process.pid)
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    try:
        if timeout_seconds is not None:
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                print(f"\n[*] Timeout reached ({timeout_str}), terminating OpenVPN...")
                _kill_pg()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _kill_pg_hard()
                    process.wait()
        else:
            process.wait()
    except KeyboardInterrupt:
        print("\n[*] OpenVPN terminated by user.")
        _kill_pg()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill_pg_hard()
            process.wait()
    finally:
        if route_added:
            _del_route(*addroute)
        if temp_auth_file and os.path.exists(temp_auth_file.name):
            os.unlink(temp_auth_file.name)
            print(f"[*] Temp auth file {temp_auth_file.name} removed.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=f"Download VPNBook OpenVPN configs.  "
                    f"Author: {AUTHOR}  |  Version: {VERSION}  |  {GITHUB}")
    parser.add_argument("--scan", action="store_true",
                        help="Only scan and display servers, protocols, credentials")
    parser.add_argument("--get", choices=["all", "ca", "us", "uk", "fr", "de"],
                        help="Download configs: all or country code (ca/us/uk/fr/de)")
    parser.add_argument("--proto", choices=["tcp", "udp"],
                        help="Protocol filter (default: all)")
    parser.add_argument("--port", choices=["443", "80", "53", "25000"],
                        help="Port filter (default: all)")
    parser.add_argument("--getlogin", metavar="FILENAME",
                        help="Save login/password to FILENAME (two lines)")
    parser.add_argument("--inject", action="store_true",
                        help="Inject auth-user-pass with file path into ovpn configs")
    parser.add_argument("--shortdir", action="store_true",
                        help="Use filename only (no absolute path) in auth-user-pass")
    parser.add_argument("--datadir", metavar="DIR",
                        help="Directory prepended to auth filename "
                             "(default: script directory)")
    parser.add_argument("--run", metavar="SERVER,PROTOCOL | filename.ovpn", nargs="?",
                        const="", default=None,
                        help="Download & run a single config (server_id,protocol_key) "
                             "or run a local .ovpn file "
                             "(e.g. us16,tcp443 or us16_tcp443_443.ovpn); "
                             "without value shows all options")
    parser.add_argument("--dev", type=int, choices=range(1, 11), metavar="N",
                        default=None,
                        help="TUN device number (1-10) for --run; "
                             "default: from .ovpn file")
    parser.add_argument("--timeout", metavar="HH:MM:SS",
                        help="Automatically stop the VPN after HH:MM:SS "
                             "(e.g. 01:30:00)")
    parser.add_argument("--user", metavar="USERNAME",
                        help="Username for VPN auth (only with --run)")
    parser.add_argument("--pwd", metavar="PASSWD",
                        help="Password for VPN auth (only with --run)")
    parser.add_argument("--datafile", metavar="FILENAME",
                        help="Path to auth file (user/password lines) for --run; "
                             "overrides auth-user-pass in .ovpn, "
                             "exclusive with --user/--pwd")
    parser.add_argument("--addroute", metavar="NET/MASK,GATEWAY", type=parse_addroute,
                        help="Add route NET/MASK via GATEWAY after VPN connects; "
                             "route is removed when VPN disconnects "
                             "(e.g. 192.168.53.0/24,10.10.10.1)")
    args = parser.parse_args()

    timeout_seconds = None
    if args.timeout is not None:
        m = re.match(r"^(\d{2}):(\d{2}):(\d{2})$", args.timeout)
        if not m:
            print("[!] --timeout requires format HH:MM:SS (e.g. 01:30:00)",
                  file=sys.stderr)
            return
        h, mn, s = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if mn >= 60 or s >= 60:
            print("[!] --timeout: minutes and seconds must be less than 60",
                  file=sys.stderr)
            return
        timeout_seconds = h * 3600 + mn * 60 + s
        if timeout_seconds == 0:
            print("[!] --timeout must be greater than 00:00:00", file=sys.stderr)
            return

    # -- --- --user / --pwd / --datafile validation ----------------------------
    if (args.user or args.pwd) and not args.run:
        print("[!] --user/--pwd can only be used with --run", file=sys.stderr)
        return
    if bool(args.user) != bool(args.pwd):
        print("[!] --user and --pwd must be used together", file=sys.stderr)
        return
    if args.datafile and not args.run:
        print("[!] --datafile can only be used with --run", file=sys.stderr)
        return
    if args.datafile and (args.user or args.pwd):
        print("[!] --datafile and --user/--pwd are mutually exclusive",
              file=sys.stderr)
        return
    if args.addroute and not args.run:
        print("[!] --addroute can only be used with --run", file=sys.stderr)
        return

    # -- --- parse --run -------------------------------------------------------
    run_server = None
    run_protocol = None
    run_ovpn_file = None
    if args.run == "":
        print_static_options(FALLBACK_SERVERS, FALLBACK_PROTOCOLS,
                             FALLBACK_USERNAME, FALLBACK_PASSWORD)
        return
    if args.run:
        if args.run.endswith(".ovpn"):
            if not os.path.isfile(args.run):
                print(f"[!] File '{args.run}' not found.", file=sys.stderr)
                return
            run_ovpn_file = os.path.abspath(args.run)
        else:
            parts = args.run.split(",")
            if len(parts) != 2:
                print("[!] --run requires server_id,protocol_key "
                       "(e.g. us16,tcp443) or a .ovpn file path",
                       file=sys.stderr)
                return
            run_server, run_protocol = parts[0].strip(), parts[1].strip()

    # -- --- --run early validation (before scan) ------------------------------
    if run_server:
        matched = [s for s in FALLBACK_SERVERS if s["id"] == run_server]
        if not matched:
            print(f"[!] Server '{run_server}' not found.", file=sys.stderr)
            print(f"[!] Use one of the following:\n", file=sys.stderr)
            print_static_options(FALLBACK_SERVERS, FALLBACK_PROTOCOLS,
                                 FALLBACK_USERNAME, FALLBACK_PASSWORD)
            return

    if run_protocol:
        matched = [p for p in FALLBACK_PROTOCOLS if p["key"] == run_protocol]
        if not matched:
            print(f"[!] Protocol '{run_protocol}' not found.", file=sys.stderr)
            print(f"[!] Use one of the following:\n", file=sys.stderr)
            print_static_options(FALLBACK_SERVERS, FALLBACK_PROTOCOLS,
                                 FALLBACK_USERNAME, FALLBACK_PASSWORD)
            return

    # -- --- --run with .ovpn file: handle auth, --dev, then run ---------------
    if run_ovpn_file:
        with open(run_ovpn_file, 'r') as f:
            config = f.read()

        auth_match = re.search(r'^auth-user-pass(\s+\S+)?', config, re.MULTILINE)
        run_temp_auth = None
        config_was_modified = False
        temp_config_path = None

        # --datafile overrides any existing auth-user-pass in the config
        if args.datafile:
            if not os.path.isfile(args.datafile):
                print(f"[!] Data file '{args.datafile}' not found.",
                      file=sys.stderr)
                return
            datafile_path = os.path.abspath(args.datafile)
            if auth_match:
                config = re.sub(
                    r'^auth-user-pass(\s+\S+)?',
                    f'auth-user-pass {datafile_path}',
                    config, flags=re.MULTILINE)
            else:
                config += f'\nauth-user-pass {datafile_path}\n'
            config_was_modified = True
        else:
            # If auth-user-pass already has a path to an existing file, treat it
            # as a previously inserted link – use it as-is.
            auth_file_ok = True
            if auth_match and auth_match.group(1):
                auth_path = auth_match.group(1).strip()
                if not os.path.isfile(auth_path):
                    auth_file_ok = False

            needs_auth = bool(args.user and args.pwd)
            needs_auth = needs_auth or not auth_match or not auth_file_ok

            if needs_auth:
                if args.user and args.pwd:
                    u, p = args.user, args.pwd
                else:
                    print("[*] Provide credentials for VPN connection:")
                    u = input("Username: ").strip()
                    p = getpass.getpass("Password: ")
                tmp = tempfile.NamedTemporaryFile(
                    mode="w", delete=False, prefix="vpnbook_auth_", suffix=".txt")
                os.chmod(tmp.name, 0o644)
                with open(tmp.name, 'w') as f:
                    f.write(f"{u}\n{p}\n")
                run_temp_auth = tmp
                if auth_match:
                    config = re.sub(
                        r'^auth-user-pass(\s+\S+)?',
                        f'auth-user-pass {tmp.name}',
                        config, flags=re.MULTILINE)
                else:
                    config += f'\nauth-user-pass {tmp.name}\n'
                config_was_modified = True

        if args.dev is not None:
            config = replace_dev_tun(config, args.dev)
            config_was_modified = True

        if config_was_modified:
            if os.access(run_ovpn_file, os.W_OK):
                config_path = run_ovpn_file
                with open(config_path, 'w') as f:
                    f.write(config)
            else:
                # File is read-only – create a timestamped copy
                timestamp = str(int(time.time()))
                config_path = f"{run_ovpn_file}.{timestamp}"
                with open(config_path, 'w') as f:
                    f.write(config)
                temp_config_path = config_path
                print(f"[*] Original file is read-only, using copy: {config_path}")
        else:
            config_path = run_ovpn_file

        _run_openvpn(config_path, timeout_seconds, args.timeout, run_temp_auth, args.addroute)

        # Clean up the temporary config copy if one was created
        if temp_config_path and os.path.exists(temp_config_path):
            os.unlink(temp_config_path)
            print(f"[*] Temporary config copy {temp_config_path} removed.")

        return

    # -- --- decide whether to scan -------------------------------------------
    needs_scan = args.scan or args.get is not None or args.getlogin is not None
    needs_scan = needs_scan or args.proto is not None or args.port is not None
    needs_scan = needs_scan or args.inject or args.run is not None

    servers = None
    protocols = None
    credentials = (None, None, None)

    if needs_scan:
        servers, protocols, credentials = scan()

    if servers is None:
        print("[!] Could not fetch server list from website, "
              "using built-in fallback.", file=sys.stderr)
        servers = FALLBACK_SERVERS
    if protocols is None:
        print("[!] Could not fetch protocol list from website, "
              "using built-in fallback.", file=sys.stderr)
        protocols = FALLBACK_PROTOCOLS

    # -- --- filter by country -------------------------------------------------
    if args.get and args.get != "all":
        cc = args.get.upper()
        servers = [s for s in servers if s.get("country_code", "").upper() == cc]
        if not servers:
            print(f"[!] No servers found for country '{args.get.upper()}'.",
                  file=sys.stderr)
            return

    # -- --- filter by proto / port --------------------------------------------
    if args.proto:
        protocols = [p for p in protocols if p["proto"] == args.proto]
    if args.port:
        protocols = [p for p in protocols if p["port"] == args.port]

    if not protocols:
        print("[!] No matching protocols.", file=sys.stderr)
        return

    # -- --- --run post-scan validation (further filter by live data) ----------
    if run_server:
        servers = [s for s in servers if s["id"] == run_server]
    if run_protocol:
        protocols = [p for p in protocols if p["key"] == run_protocol]

    # -- --- resolve credentials & auth file -----------------------------------
    username, password, _ = credentials
    if not username:
        username = FALLBACK_USERNAME
    if args.run and args.user and args.pwd:
        username, password = args.user, args.pwd

    auth_save_path = None    # where to save the credentials file
    auth_config_ref = None   # what to write into auth-user-pass in .ovpn
    run_temp_auth = None     # temp file handle for --run cleanup

    if args.inject:
        auth_basename = args.getlogin if args.getlogin else "myOvpnBook_data.txt"
        datadir = args.datadir if args.datadir else SCRIPT_DIR
        auth_save_path = os.path.join(datadir, auth_basename)
        auth_config_ref = auth_basename if args.shortdir else auth_save_path
    elif args.getlogin:
        auth_save_path = args.getlogin

    # -- --- for --run: force inject with a temp auth file ---------------------
    if args.run and not auth_config_ref:
        if args.datafile:
            if not os.path.isfile(args.datafile):
                print(f"[!] Data file '{args.datafile}' not found.",
                      file=sys.stderr)
                return
            auth_config_ref = os.path.abspath(args.datafile)
        else:
            tmp = tempfile.NamedTemporaryFile(
                mode="w", delete=False, prefix="vpnbook_auth_", suffix=".txt")
            os.chmod(tmp.name, 0o644)  # readable by root when openvpn runs with sudo
            auth_save_path = tmp.name
            auth_config_ref = tmp.name
            run_temp_auth = tmp

    # -- --- save credentials to auth_save_path if requested -------------------
    if auth_save_path:
        if not password:
            password = FALLBACK_PASSWORD
        if not password:
            password = "*** unknown – run --scan separately ***"
        with open(auth_save_path, "w") as f:
            f.write(f"{username}\n{password}\n")
        print(f"[*] Credentials saved to {auth_save_path}")

    # -- --- decide whether to download ----------------------------------------
    has_download_opt = (args.get is not None or args.proto is not None
                        or args.port is not None or args.inject
                        or args.run is not None)

    if args.scan and not has_download_opt and args.getlogin is None:
        return  # --scan only, no download
    if args.getlogin is not None and not has_download_opt:
        return  # --getlogin only, no download

    # -- --- download loop -----------------------------------------------------
    total = len(servers) * len(protocols)
    ok = 0
    saved_paths = []

    print(f"[*] Downloading {total} config(s) from VPNBook...\n")

    for server in servers:
        for protocol in protocols:
            sid = server["id"]
            port_str = protocol["port"]
            print(f"  [{sid}] [{protocol['proto'].upper()} {port_str}] ",
                  end="", flush=True)

            config = download_config(server, protocol)
            if config is None:
                print("SKIP")
                continue

            if auth_config_ref:
                config = inject_auth_user_pass(config, auth_config_ref)
            config = replace_remote_hostname(
                config, server["hostname"], server["ip_address"])
            if args.dev is not None:
                config = replace_dev_tun(config, args.dev)
            saved_paths.append(save_config(server, protocol, config))
            ok += 1

    print(f"\n[*] Done: {ok}/{total} config(s) downloaded successfully.")
    if ok < total:
        print(f"[!] {total - ok} config(s) failed to download.", file=sys.stderr)

    if username and password:
        print(f"\n[*] VPN credentials:")
        print(f"    Username: {username}")
        print(f"    Password: {password}")

    # -- --- --run: execute openvpn (with sudo) and clean up temp auth file -----
    if args.run and saved_paths:
        _run_openvpn(saved_paths[0], timeout_seconds, args.timeout, run_temp_auth, args.addroute)


if __name__ == "__main__":
    main()
