#!/usr/bin/env python3
"""OVPNMonitor data collectors.

Background daemon threads that collect VPN status, traffic statistics,
public IP, ping latency, and gateway information. Results are stored
in a shared MonitorState object protected by a threading lock.
"""

import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ---------------------------------------------------------------------------
# Monitor state (shared between collectors and UI)
# ---------------------------------------------------------------------------

@dataclass
class PingResult:
    """Result of a single ping to a target."""
    target: str = ""
    latency_ms: float = -1.0      # -1 = unreachable / no data
    reachable: bool = False
    last_check: float = 0.0


@dataclass
class IfaceTrafficData:
    bytes_sent: int = 0
    bytes_recv: int = 0
    bytes_sent_rate: float = 0.0
    bytes_recv_rate: float = 0.0
    packets_sent: int = 0
    packets_recv: int = 0
    packets_sent_rate: float = 0.0
    packets_recv_rate: float = 0.0
    session_bytes_sent: int = 0
    session_bytes_recv: int = 0
    _prev_bytes_sent: int = 0
    _prev_bytes_recv: int = 0
    _prev_packets_sent: int = 0
    _prev_packets_recv: int = 0
    _prev_time: float = 0.0
    _session_base_sent: int = -1
    _session_base_recv: int = -1


@dataclass
class MonitorState:
    """Shared state updated by collector threads, read by UI."""
    lock: threading.Lock = field(default_factory=threading.Lock)

    # VPN status
    vpn_connected: bool = False
    vpn_interface: str = ""
    vpn_process_pid: int = 0
    vpn_server: str = ""
    vpn_protocol: str = ""
    vpn_port: str = ""
    vpn_config_file: str = ""
    vpn_connect_time: float = 0.0     # time.time() when first detected
    vpn_ifaces_info: List[Dict] = field(default_factory=list)

    # Network
    public_ip: str = "detecting..."
    gateway_ip: str = ""
    local_vpn_ip: str = ""
    default_gateway: str = ""

    # Local network
    local_iface: str = ""
    local_ip: str = ""
    local_netmask: str = ""
    local_gateway: str = ""
    local_dns: List[str] = field(default_factory=list)
    local_is_dhcp: bool = True
    local_ifaces_info: List[Dict] = field(default_factory=list)

    # Per-interface traffic statistics (keyed by interface name)
    ifaces_traffic: Dict[str, IfaceTrafficData] = field(default_factory=dict)

    # Ping results: target -> PingResult
    ping_results: Dict[str, PingResult] = field(default_factory=dict)

    # Pathping (traceroute)
    pathping_hops: List[str] = field(default_factory=list)
    pathping_changed: bool = False
    pathping_prev_hops: List[str] = field(default_factory=list)

    # Status flags
    paused: bool = False
    ip_error: str = ""
    last_ip_check: float = 0.0

    # Manual refresh support
    refresh_token: int = 0

    # Collector errors
    errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# VPN status detection
# ---------------------------------------------------------------------------

def detect_openvpn_process() -> Optional[Dict]:
    """Find running openvpn.exe process and extract config details."""
    if not HAS_PSUTIL:
        return None
    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
            name = (proc.info.get("name") or "").lower()
            if "openvpn" in name:
                cmdline = proc.info.get("cmdline") or []
                config_file = ""
                for i, arg in enumerate(cmdline):
                    if arg == "--config" and i + 1 < len(cmdline):
                        config_file = cmdline[i + 1]
                        break
                    if arg.endswith(".ovpn"):
                        config_file = arg
                        break
                return {
                    "pid": proc.info["pid"],
                    "config_file": config_file,
                    "create_time": proc.info.get("create_time", 0),
                    "cmdline": cmdline,
                }
    except (psutil.Error, OSError):
        pass
    return None


def parse_ovpn_config(config_path: str) -> Dict[str, str]:
    """Extract server, protocol, port from .ovpn config file."""
    result = {"server": "", "protocol": "", "port": ""}
    if not config_path or not os.path.isfile(config_path):
        return result
    try:
        with open(config_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        # remote <host> <port>
        m = re.search(r"^remote\s+(\S+)\s+(\d+)", content, re.MULTILINE)
        if m:
            result["server"] = m.group(1)
            result["port"] = m.group(2)
        # proto tcp / proto udp
        m = re.search(r"^proto\s+(tcp|udp)", content, re.MULTILINE | re.IGNORECASE)
        if m:
            result["protocol"] = m.group(1).upper()
    except OSError:
        pass
    return result


def _get_default_iface() -> str:
    """Get the default route interface name from /proc/net/route."""
    try:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                if len(fields) >= 8 and fields[1] == "00000000":
                    return fields[0]
    except OSError:
        pass
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=3,
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "default":
                return parts[4]
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ""


def detect_vpn_interface() -> Tuple[str, str]:
    """Auto-detect VPN TAP/TUN network interface.
    Returns (interface_name, local_ip) or ("", "").
    Uses keyword matching first, then falls back to heuristic
    detection of 10.x.x.x interfaces, finally ip link fallback.
    """
    VPN_KEYWORDS = [
        "tap", "tun", "openvpn", "vpn", "wintun", "wireguard",
        "secureline", "nordlynx", "proton", "mullvad",
    ]
    SKIP_KEYWORDS = [
        "loopback", "vmware", "virtualbox", "vbox", "vmnet",
        "docker", "vethernet", "hyper-v", "bluetooth",
    ]

    if HAS_PSUTIL:
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            default_iface = _get_default_iface()

            # Pass 1: keyword-based detection
            for iface, addr_list in addrs.items():
                iface_lower = iface.lower()
                is_vpn = any(kw in iface_lower for kw in VPN_KEYWORDS)
                if not is_vpn:
                    continue
                if iface in stats and stats[iface].isup:
                    for addr in addr_list:
                        if addr.family == socket.AF_INET:
                            return (iface, addr.address)

            # Pass 2: heuristic — 10.x.x.x, exclude default route interface
            for iface, addr_list in addrs.items():
                iface_lower = iface.lower()
                if any(kw in iface_lower for kw in SKIP_KEYWORDS):
                    continue
                if iface == default_iface:
                    continue
                if iface in stats and stats[iface].isup:
                    for addr in addr_list:
                        if addr.family == socket.AF_INET and addr.address.startswith("10."):
                            return (iface, addr.address)
        except (psutil.Error, OSError):
            pass

    # Pass 3: Linux fallback - find tunN (tun + number) interfaces
    if sys.platform != "win32":
        try:
            out = subprocess.run(
                ["ip", "-o", "link", "show", "type", "tun"],
                capture_output=True, text=True, timeout=3,
            )
            for line in out.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    iface = parts[1].rstrip(":")
                    if re.match(r'^tun\d+$', iface):
                        return (iface, "")
        except (subprocess.TimeoutExpired, OSError):
            pass

    return ("", "")


def detect_vpn_interface_by_config(config_iface: str) -> Tuple[str, str]:
    """Find a specific interface by name from config.
    Returns (interface_name, local_ip).
    """
    if not HAS_PSUTIL or not config_iface:
        return ("", "")
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for iface, addr_list in addrs.items():
            if config_iface.lower() in iface.lower():
                if iface in stats and stats[iface].isup:
                    for addr in addr_list:
                        if addr.family == socket.AF_INET:
                            return (iface, addr.address)
    except (psutil.Error, OSError):
        pass
    return ("", "")


def detect_all_vpn_interfaces() -> List[Tuple[str, str]]:
    """Auto-detect all VPN TAP/TUN network interfaces.
    Returns list of (interface_name, local_ip) tuples.
    """
    VPN_KEYWORDS = [
        "tap", "tun", "openvpn", "vpn", "wintun", "wireguard",
        "secureline", "nordlynx", "proton", "mullvad",
    ]
    results: List[Tuple[str, str]] = []
    if HAS_PSUTIL:
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface, addr_list in addrs.items():
                iface_lower = iface.lower()
                if not any(kw in iface_lower for kw in VPN_KEYWORDS):
                    continue
                if iface not in stats or not stats[iface].isup:
                    continue
                ip = ""
                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        break
                results.append((iface, ip))
        except (psutil.Error, OSError):
            pass
    return results


# ---------------------------------------------------------------------------
# Gateway detection
# ---------------------------------------------------------------------------

def get_gateways() -> Dict[str, str]:
    """Parse routing table to find default gateway and VPN gateway.
    Returns dict with keys: 'default', 'vpn'.
    """
    result = {"default": "", "vpn": ""}
    if sys.platform == "win32":
        try:
            out = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for line in out.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw = parts[2]
                    if not result["default"]:
                        result["default"] = gw
                    elif not result["vpn"]:
                        result["vpn"] = gw
        except (subprocess.TimeoutExpired, OSError):
            pass
    else:
        try:
            with open("/proc/net/route") as f:
                for line in f:
                    fields = line.strip().split()
                    if len(fields) >= 8 and fields[1] == "00000000":
                        gw_hex = fields[2]
                        gw = ".".join(str(int(gw_hex[i:i+2], 16)) for i in range(6, -1, -2))
                        if not result["default"]:
                            result["default"] = gw
                        else:
                            result["vpn"] = gw
        except OSError:
            pass
    return result


# ---------------------------------------------------------------------------
# Local network detection
# ---------------------------------------------------------------------------

def get_default_interface() -> str:
    """Get the name of the network interface used for the default route."""
    if sys.platform == "win32":
        if not HAS_PSUTIL:
            return ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            addrs = psutil.net_if_addrs()
            for iface, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET and addr.address == local_ip:
                        return iface
        except (OSError, psutil.Error):
            pass
        return ""
    try:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                if len(fields) >= 8 and fields[1] == "00000000":
                    return fields[0]
    except OSError:
        pass
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=3,
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "default":
                return parts[4]
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ""


def get_local_ip_netmask(iface: str) -> Tuple[str, str]:
    """Get local IP and netmask for a given interface."""
    if not iface:
        return ("", "")
    if HAS_PSUTIL:
        try:
            addrs = psutil.net_if_addrs()
            if iface in addrs:
                for addr in addrs[iface]:
                    if addr.family == socket.AF_INET:
                        return (addr.address, addr.netmask or "")
        except (psutil.Error, OSError):
            pass
    try:
        out = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=3,
        )
        for line in out.stdout.splitlines():
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if m:
                ip = m.group(1)
                prefix = int(m.group(2))
                mask = socket.inet_ntoa(
                    (0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF).to_bytes(4, 'big')
                )
                return (ip, mask)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ("", "")


def get_dns_servers() -> List[str]:
    """Get DNS server addresses from system."""
    dns_list = []
    if sys.platform == "win32":
        try:
            out = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for line in out.stdout.splitlines():
                m = re.search(r'DNS\s+Servers?[^:]*:\s*(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
                if m:
                    dns_list.append(m.group(1))
        except (subprocess.TimeoutExpired, OSError):
            pass
    else:
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    m = re.search(r'^nameserver\s+(\S+)', line)
                    if m:
                        dns_list.append(m.group(1))
        except OSError:
            pass
    return dns_list


def is_dhcp_interface(iface: str) -> bool:
    """Check if an interface uses DHCP."""
    if sys.platform == "win32":
        try:
            out = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            in_section = False
            for line in out.stdout.splitlines():
                if iface.lower() in line.lower() and "adapter" in line.lower():
                    in_section = True
                elif in_section and line.strip() == "":
                    in_section = False
                elif in_section and "DHCP Enabled" in line:
                    return "Yes" in line
        except (subprocess.TimeoutExpired, OSError):
            pass
        return True
    try:
        result = subprocess.run(
            ["ps", "-eo", "cmd"],
            capture_output=True, text=True, timeout=3,
        )
        for line in result.stdout.splitlines():
            if "dhclient" in line and iface in line:
                return True
            if "dhcpcd" in line and iface in line:
                return True
    except OSError:
        pass
    if os.path.isdir("/var/lib/dhcp"):
        try:
            for f in os.listdir("/var/lib/dhcp"):
                if iface in f and "lease" in f.lower():
                    return True
        except OSError:
            pass
    return False


def get_mac_address(iface: str) -> str:
    """Get MAC address for a given interface."""
    if not iface:
        return ""
    if HAS_PSUTIL:
        try:
            addrs = psutil.net_if_addrs()
            if iface in addrs:
                for addr in addrs[iface]:
                    if addr.family in (socket.AF_PACKET, getattr(psutil, 'AF_LINK', -1)):
                        return addr.address
        except (psutil.Error, OSError):
            pass
    return ""


def get_local_ipv6(iface: str) -> str:
    """Get IPv6 address for a given interface."""
    if not iface:
        return ""
    if HAS_PSUTIL:
        try:
            addrs = psutil.net_if_addrs()
            if iface in addrs:
                for addr in addrs[iface]:
                    if addr.family == socket.AF_INET6:
                        return addr.address.split("%")[0]
        except (psutil.Error, OSError):
            pass
    return ""


def detect_physical_interfaces() -> List[str]:
    """Detect physical network interfaces (eth*, enp*)."""
    ifaces = []
    if HAS_PSUTIL:
        try:
            stats = psutil.net_if_stats()
            for iface in stats:
                if re.match(r'^(eth|enp)\d+', iface):
                    ifaces.append(iface)
        except (psutil.Error, OSError):
            pass
    return sorted(ifaces)


# ---------------------------------------------------------------------------
# Public IP detection
# ---------------------------------------------------------------------------

def get_public_ip(url: str = "https://api.ipify.org", timeout: int = 5) -> str:
    """Fetch public IP address from external service."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "OVPNMonitor/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8").strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------

def ping_host(host: str, timeout_ms: int = 2000) -> float:
    """Ping a host and return latency in ms, or -1 on failure."""
    try:
        if sys.platform == "win32":
            flags = subprocess.CREATE_NO_WINDOW
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        else:
            flags = 0
            timeout_s = max(1, timeout_ms // 1000)
            cmd = ["ping", "-c", "1", "-W", str(timeout_s), host]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_ms / 1000 + 5,
            creationflags=flags,
        )
        if result.returncode == 0:
            m = re.search(r"time[<=]([\d.]+)\s*ms", result.stdout, re.IGNORECASE)
            if m:
                return float(m.group(1))
            m = re.search(r"[<=]([\d.]+)\s*ms", result.stdout, re.IGNORECASE)
            if m:
                return float(m.group(1))
        return -1.0
    except (subprocess.TimeoutExpired, OSError):
        return -1.0


# ---------------------------------------------------------------------------
# Pathping (traceroute)
# ---------------------------------------------------------------------------

def run_traceroute(target: str) -> List[str]:
    """Run traceroute to target, return list of hop IPs (no DNS resolution)."""
    hops: List[str] = []
    try:
        if sys.platform == "win32":
            cmd = ["tracert", "-d", "-h", "30", target]
        else:
            cmd = ["mtr", "-n", "-r", "-c", "1", "-m", "30", target]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        for line in result.stdout.splitlines():
            if sys.platform == "win32":
                m = re.search(r'^\s*\d+\s+.*?(\d+\.\d+\.\d+\.\d+)\s*$', line)
            else:
                m = re.search(r'^\s*\d+\.\|--\s+(\S+)', line)
            if m:
                ip = m.group(1)
                if ip not in hops:
                    hops.append(ip)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return hops


# ---------------------------------------------------------------------------
# Traffic statistics
# ---------------------------------------------------------------------------

def get_interface_traffic(interface: str) -> Optional[Dict]:
    """Get traffic counters for a specific interface."""
    if not HAS_PSUTIL or not interface:
        return None
    try:
        counters = psutil.net_io_counters(pernic=True)
        if interface in counters:
            c = counters[interface]
            return {
                "bytes_sent": c.bytes_sent,
                "bytes_recv": c.bytes_recv,
                "packets_sent": c.packets_sent,
                "packets_recv": c.packets_recv,
            }
    except (psutil.Error, OSError):
        pass
    return None


# ---------------------------------------------------------------------------
# Collector threads
# ---------------------------------------------------------------------------

class CollectorThread(threading.Thread):
    """Base class for data collector threads."""

    def __init__(self, state: MonitorState, interval: float, name: str = ""):
        super().__init__(daemon=True, name=name)
        self.state = state
        self.interval = interval
        self._stop_event = threading.Event()
        self._last_token = 0

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

    def run(self):
        while not self.stopped():
            if not self.state.paused:
                try:
                    self.collect()
                except Exception as e:
                    with self.state.lock:
                        self.state.errors.append(f"{self.name}: {e}")
            # Sleep in small increments to stay responsive to refresh/stop
            deadline = time.time() + self.interval
            while time.time() < deadline:
                if self.stopped():
                    return
                if self.state.refresh_token != self._last_token:
                    self._last_token = self.state.refresh_token
                    deadline = time.time()  # force re-collect
                    break
                time.sleep(0.1)

    def collect(self):
        raise NotImplementedError


class VPNStatusCollector(CollectorThread):
    """Detect OpenVPN process and VPN interface status."""

    def __init__(self, state: MonitorState, interval: float, vpn_iface_config: str = "auto"):
        super().__init__(state, interval, name="VPNStatus")
        self.vpn_iface_config = vpn_iface_config

    def collect(self):
        proc = detect_openvpn_process()
        with self.state.lock:
            if proc:
                self.state.vpn_process_pid = proc["pid"]
                self.state.vpn_config_file = proc["config_file"]
                if not self.state.vpn_connect_time:
                    self.state.vpn_connect_time = proc.get("create_time", time.time())

                # Parse config for server details
                if proc["config_file"] and not self.state.vpn_server:
                    info = parse_ovpn_config(proc["config_file"])
                    self.state.vpn_server = info["server"]
                    self.state.vpn_protocol = info["protocol"]
                    self.state.vpn_port = info["port"]
            else:
                self.state.vpn_process_pid = 0
                self.state.vpn_config_file = ""
                self.state.vpn_connect_time = 0.0
                self.state.vpn_server = ""
                self.state.vpn_protocol = ""
                self.state.vpn_port = ""

            # Detect VPN interfaces
            vpn_info_list = []
            if self.vpn_iface_config == "auto":
                vpn_ifaces = detect_all_vpn_interfaces()
                if not vpn_ifaces:
                    iface, lip = detect_vpn_interface()
                    if iface:
                        vpn_ifaces = [(iface, lip)]
                else:
                    vpn_ifaces = vpn_ifaces
            else:
                iface, lip = detect_vpn_interface_by_config(self.vpn_iface_config)
                vpn_ifaces = [(iface, lip)] if iface else []

            for name, ip in vpn_ifaces:
                vpn_info_list.append({
                    "name": name,
                    "local_ip": ip,
                    "gateway": self.state.gateway_ip,
                })

            self.state.vpn_ifaces_info = vpn_info_list
            if vpn_info_list:
                self.state.vpn_connected = True
                self.state.vpn_interface = vpn_info_list[0]["name"]
                self.state.local_vpn_ip = vpn_info_list[0]["local_ip"]
            else:
                self.state.vpn_connected = bool(proc)
                if not proc:
                    self.state.vpn_interface = ""
                    self.state.local_vpn_ip = ""


class TrafficCollector(CollectorThread):
    """Collect traffic statistics for all VPN interfaces."""

    def collect(self):
        with self.state.lock:
            ifaces = list(self.state.vpn_ifaces_info)

        if not ifaces:
            return

        now = time.time()
        with self.state.lock:
            for info in ifaces:
                name = info["name"]
                traffic = get_interface_traffic(name)
                if traffic is None:
                    continue
                td = self.state.ifaces_traffic.setdefault(name, IfaceTrafficData())
                bs = traffic["bytes_sent"]
                br = traffic["bytes_recv"]
                ps = traffic["packets_sent"]
                pr = traffic["packets_recv"]

                td.bytes_sent = bs
                td.bytes_recv = br
                td.packets_sent = ps
                td.packets_recv = pr

                if td._prev_time > 0:
                    dt = now - td._prev_time
                    if dt > 0:
                        td.bytes_sent_rate = max(0, (bs - td._prev_bytes_sent) / dt)
                        td.bytes_recv_rate = max(0, (br - td._prev_bytes_recv) / dt)
                        td.packets_sent_rate = max(0, (ps - td._prev_packets_sent) / dt)
                        td.packets_recv_rate = max(0, (pr - td._prev_packets_recv) / dt)

                if td._session_base_sent < 0:
                    td._session_base_sent = bs
                    td._session_base_recv = br
                td.session_bytes_sent = bs - td._session_base_sent
                td.session_bytes_recv = br - td._session_base_recv

                td._prev_bytes_sent = bs
                td._prev_bytes_recv = br
                td._prev_packets_sent = ps
                td._prev_packets_recv = pr
                td._prev_time = now


class LocalTrafficCollector(CollectorThread):
    """Collect traffic statistics for all local interfaces."""

    def collect(self):
        with self.state.lock:
            ifaces = list(self.state.local_ifaces_info)

        if not ifaces:
            return

        now = time.time()
        with self.state.lock:
            for info in ifaces:
                name = info["name"]
                traffic = get_interface_traffic(name)
                if traffic is None:
                    continue
                td = self.state.ifaces_traffic.setdefault(name, IfaceTrafficData())
                bs = traffic["bytes_sent"]
                br = traffic["bytes_recv"]
                ps = traffic["packets_sent"]
                pr = traffic["packets_recv"]

                td.bytes_sent = bs
                td.bytes_recv = br
                td.packets_sent = ps
                td.packets_recv = pr

                if td._prev_time > 0:
                    dt = now - td._prev_time
                    if dt > 0:
                        td.bytes_sent_rate = max(0, (bs - td._prev_bytes_sent) / dt)
                        td.bytes_recv_rate = max(0, (br - td._prev_bytes_recv) / dt)
                        td.packets_sent_rate = max(0, (ps - td._prev_packets_sent) / dt)
                        td.packets_recv_rate = max(0, (pr - td._prev_packets_recv) / dt)

                if td._session_base_sent < 0:
                    td._session_base_sent = bs
                    td._session_base_recv = br
                td.session_bytes_sent = bs - td._session_base_sent
                td.session_bytes_recv = br - td._session_base_recv

                td._prev_bytes_sent = bs
                td._prev_bytes_recv = br
                td._prev_packets_sent = ps
                td._prev_packets_recv = pr
                td._prev_time = now


class IPCollector(CollectorThread):
    """Periodically fetch public IP address."""

    def __init__(self, state: MonitorState, interval: float, url: str):
        super().__init__(state, interval, name="IPCollector")
        self.url = url

    def collect(self):
        ip = get_public_ip(self.url)
        with self.state.lock:
            if ip:
                self.state.public_ip = ip
                self.state.ip_error = ""
            else:
                self.state.ip_error = "fetch failed"
            self.state.last_ip_check = time.time()


class PingCollector(CollectorThread):
    """Ping a single target at its own configured interval."""

    def __init__(self, state: MonitorState, target_address: str,
                 interval_ms: int, timeout_ms: int):
        interval_s = max(interval_ms / 1000.0, 1.0)
        super().__init__(state, interval_s, name=f"Ping-{target_address}")
        self.target_address = target_address
        self.timeout_ms = timeout_ms

    def collect(self):
        target = self.target_address
        # Resolve "gateway" to actual gateway IP
        actual_target = target
        if target.lower() == "gateway":
            with self.state.lock:
                actual_target = self.state.gateway_ip or self.state.default_gateway
            if not actual_target:
                with self.state.lock:
                    self.state.ping_results[target] = PingResult(
                        target=target, latency_ms=-1, reachable=False,
                        last_check=time.time()
                    )
                return

        latency = ping_host(actual_target, self.timeout_ms)
        with self.state.lock:
            self.state.ping_results[target] = PingResult(
                target=target,
                latency_ms=latency,
                reachable=(latency >= 0),
                last_check=time.time(),
            )


class GatewayCollector(CollectorThread):
    """Detect default and VPN gateways from routing table."""

    def collect(self):
        gw = get_gateways()
        with self.state.lock:
            self.state.default_gateway = gw.get("default", "")
            if gw.get("vpn"):
                self.state.gateway_ip = gw["vpn"]
            else:
                self.state.gateway_ip = gw.get("default", "")


class LocalNetworkCollector(CollectorThread):
    """Collect local network configuration."""

    def __init__(self, state: MonitorState, interval: float, local_iface_config: str = ""):
        super().__init__(state, interval, name="LocalNetwork")
        self.local_iface_config = local_iface_config

    def collect(self):
        dns = get_dns_servers()
        gw = ""
        with self.state.lock:
            gw = self.state.default_gateway

        if self.local_iface_config:
            ifaces = [self.local_iface_config]
        else:
            ifaces = detect_physical_interfaces()
            if not ifaces:
                ifaces = [get_default_interface()]
        if not ifaces or not ifaces[0]:
            return

        all_info = []
        for iface in ifaces:
            ip, netmask = get_local_ip_netmask(iface)
            mac = get_mac_address(iface)
            ipv6 = get_local_ipv6(iface)
            dhcp = is_dhcp_interface(iface)
            all_info.append({
                "name": iface,
                "ipv4": ip,
                "netmask": netmask,
                "gateway": gw,
                "mac": mac,
                "ipv6": ipv6,
                "is_dhcp": dhcp,
            })

        with self.state.lock:
            self.state.local_ifaces_info = all_info
            if all_info:
                first = all_info[0]
                self.state.local_iface = first["name"]
                self.state.local_ip = first["ipv4"]
                self.state.local_netmask = first["netmask"]
                self.state.local_gateway = gw
                self.state.local_dns = dns
                self.state.local_is_dhcp = first["is_dhcp"]


class PathPingCollector(CollectorThread):
    """Run traceroute to a target IP and track route changes."""

    def __init__(self, state: MonitorState, interval: float, target: str):
        super().__init__(state, interval, name="PathPing")
        self.target = target

    def collect(self):
        if not self.target:
            return
        hops = run_traceroute(self.target)
        if not hops:
            return
        with self.state.lock:
            prev = list(self.state.pathping_hops)
            self.state.pathping_hops = hops
            if prev and prev != hops:
                self.state.pathping_changed = True
                self.state.pathping_prev_hops = prev
            else:
                self.state.pathping_changed = False


# ---------------------------------------------------------------------------
# Collector manager
# ---------------------------------------------------------------------------

def start_collectors(state: MonitorState, cfg) -> List[CollectorThread]:
    """Start all data collector threads. Returns list of threads."""
    nc = cfg.network
    collectors = [
        VPNStatusCollector(state, nc.vpn_check_interval, cfg.vpn_interface),
        TrafficCollector(state, nc.traffic_interval, name="Traffic"),
        IPCollector(state, nc.ip_check_interval, nc.ip_check_url),
        GatewayCollector(state, nc.gateway_interval, name="Gateway"),
        LocalNetworkCollector(state, nc.int_check_interval, cfg.local_interface),
        LocalTrafficCollector(state, nc.traffic_interval, name="LocalTraffic"),
    ]
    # PathPing collector (if target set)
    if cfg.pathping_target:
        collectors.append(PathPingCollector(state, 30.0, cfg.pathping_target))

    # One PingCollector per target, each with its own interval
    if nc.ping_enabled:
        for pt in nc.ping_targets:
            collectors.append(PingCollector(
                state, pt.address, pt.interval_ms, nc.ping_timeout_ms
            ))
    for c in collectors:
        c.start()
    return collectors


def stop_collectors(collectors: List[CollectorThread]) -> None:
    """Signal all collectors to stop and wait for them."""
    for c in collectors:
        c.stop()
    for c in collectors:
        c.join(timeout=3)
