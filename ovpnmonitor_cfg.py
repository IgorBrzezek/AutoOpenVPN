#!/usr/bin/env python3
"""OVPNMonitor configuration parser.

Reads ovpnmonitor.cfg (INI format) and provides typed access
to all settings with sensible defaults.
"""

import configparser
import curses
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Color name mapping
# ---------------------------------------------------------------------------

COLOR_MAP = {
    "black":   curses.COLOR_BLACK,
    "red":     curses.COLOR_RED,
    "green":   curses.COLOR_GREEN,
    "yellow":  curses.COLOR_YELLOW,
    "blue":    curses.COLOR_BLUE,
    "magenta": curses.COLOR_MAGENTA,
    "cyan":    curses.COLOR_CYAN,
    "white":   curses.COLOR_WHITE,
}


# Encode/decode hex RGB colors as negative placeholders (resolved in init_colors)
def _encode_hex(r: int, g: int, b: int) -> int:
    return -(r * 1000000 + g * 1000 + b + 1)

# Add orange as hex-encoded custom color (resolved in init_colors)
COLOR_MAP["orange"] = _encode_hex(255, 119, 0)


def _decode_hex(val: int) -> Optional[Tuple[int, int, int]]:
    if val >= 0:
        return None
    enc = -val - 1
    return (enc // 1000000, (enc % 1000000) // 1000, enc % 1000)

def _find_nearest_color(r: int, g: int, b: int) -> int:
    """Match RGB to nearest standard curses color (fallback)."""
    standards = [
        (curses.COLOR_BLACK, 0, 0, 0),
        (curses.COLOR_RED, 255, 0, 0),
        (curses.COLOR_GREEN, 0, 255, 0),
        (curses.COLOR_YELLOW, 255, 255, 0),
        (curses.COLOR_BLUE, 0, 0, 255),
        (curses.COLOR_MAGENTA, 255, 0, 255),
        (curses.COLOR_CYAN, 0, 255, 255),
        (curses.COLOR_WHITE, 255, 255, 255),
    ]
    # Orange-ish hues: prefer YELLOW over RED for visual appeal
    if r > 200 and g > 50 and g < 200 and b < 50:
        return curses.COLOR_YELLOW
    best = curses.COLOR_WHITE
    best_d = float("inf")
    for cid, cr, cg, cb in standards:
        d = (r - cr) ** 2 + (g - cg) ** 2 + (b - cb) ** 2
        if d < best_d:
            best_d = d
            best = cid
    return best

def _resolve_color(val: int) -> int:
    """Resolve possibly-encoded color to a curses color ID."""
    rgb = _decode_hex(val)
    if rgb is None:
        return val
    r, g, b = rgb
    if curses.can_change_color():
        global _custom_color_counter
        color_id = _custom_color_counter
        _custom_color_counter += 1
        try:
            curses.init_color(color_id, r * 1000 // 255, g * 1000 // 255, b * 1000 // 255)
            return color_id
        except curses.error:
            pass
    return _find_nearest_color(r, g, b)

def _parse_single_color(name: str) -> int:
    """Parse a single color name or hex code."""
    if name in COLOR_MAP:
        return COLOR_MAP[name]
    if name.startswith("#") and len(name) == 7:
        try:
            r = int(name[1:3], 16)
            g = int(name[3:5], 16)
            b = int(name[5:7], 16)
            return _encode_hex(r, g, b)
        except ValueError:
            pass
    return curses.COLOR_WHITE

def parse_color_pair(value: str) -> Tuple[int, int]:
    """Parse 'foreground,background' string into curses color constants.
    Supports named colors and hex RGB (#RRGGBB)."""
    parts = [p.strip().lower() for p in value.split(",")]
    if len(parts) != 2:
        return (curses.COLOR_WHITE, curses.COLOR_BLACK)
    fg = _parse_single_color(parts[0])
    bg = _parse_single_color(parts[1])
    return (fg, bg)


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------

@dataclass
class ColorConfig:
    """Parsed color pairs for each UI element."""
    background: int = curses.COLOR_BLACK
    status_bar_top: Tuple[int, int] = (curses.COLOR_WHITE, curses.COLOR_BLUE)
    status_bar_bottom: Tuple[int, int] = (curses.COLOR_WHITE, curses.COLOR_BLUE)
    border: Tuple[int, int] = (curses.COLOR_CYAN, curses.COLOR_BLACK)
    border_title: Tuple[int, int] = (curses.COLOR_YELLOW, curses.COLOR_BLACK)
    text_normal: Tuple[int, int] = (curses.COLOR_WHITE, curses.COLOR_BLACK)
    text_label: Tuple[int, int] = (curses.COLOR_CYAN, curses.COLOR_BLACK)
    text_value: Tuple[int, int] = (curses.COLOR_GREEN, curses.COLOR_BLACK)
    text_warning: Tuple[int, int] = (curses.COLOR_YELLOW, curses.COLOR_BLACK)
    text_error: Tuple[int, int] = (curses.COLOR_RED, curses.COLOR_BLACK)
    online: Tuple[int, int] = (curses.COLOR_GREEN, curses.COLOR_BLACK)
    offline: Tuple[int, int] = (curses.COLOR_RED, curses.COLOR_BLACK)
    highlight: Tuple[int, int] = (curses.COLOR_BLACK, curses.COLOR_CYAN)
    popup_border: Tuple[int, int] = (curses.COLOR_YELLOW, curses.COLOR_BLACK)
    popup_bg: Tuple[int, int] = (curses.COLOR_WHITE, curses.COLOR_BLACK)
    public_ip_bar: Tuple[int, int] = (curses.COLOR_WHITE, curses.COLOR_BLUE)
    traceroute_border: Tuple[int, int] = (curses.COLOR_YELLOW, curses.COLOR_BLACK)
    traceroute_bg: Tuple[int, int] = (curses.COLOR_WHITE, curses.COLOR_BLACK)
    traceroute_input: Tuple[int, int] = (curses.COLOR_BLACK, curses.COLOR_YELLOW)
    window_bg: int = curses.COLOR_BLACK
    ping_ok: Tuple[int, int] = (curses.COLOR_GREEN, curses.COLOR_BLACK)
    ping_warn: Tuple[int, int] = (curses.COLOR_YELLOW, curses.COLOR_BLACK)
    ping_high: Tuple[int, int] = (curses.COLOR_YELLOW, curses.COLOR_BLACK)
    ping_bad: Tuple[int, int] = (curses.COLOR_BLUE, curses.COLOR_BLACK)
    ping_worse: Tuple[int, int] = (curses.COLOR_MAGENTA, curses.COLOR_BLACK)
    ping_critical: Tuple[int, int] = (curses.COLOR_RED, curses.COLOR_BLACK)
    ping_dead: Tuple[int, int] = (curses.COLOR_RED, curses.COLOR_BLACK)


@dataclass
class KeyConfig:
    """Keyboard shortcuts."""
    quit: str = "q"
    help: str = "h"
    info: str = "i"
    refresh_ip: str = "u"
    toggle_pause: str = "p"
    toggle_ping: str = "n"
    show_routes: str = "r"
    toggle_ip: str = "a"
    traceroute: str = "t"


@dataclass
class PingTarget:
    """A single ping target with its own interval."""
    address: str = "8.8.8.8"
    interval_ms: int = 5000


@dataclass
class NetworkConfig:
    """Network data collection settings."""
    ip_check_url: str = "https://checkip.amazonaws.com"
    ip_check_interval: float = 30.0
    ping_enabled: bool = True
    ping_targets: List[PingTarget] = field(default_factory=lambda: [
        PingTarget("gateway", 5000), PingTarget("8.8.8.8", 5000)
    ])
    ping_timeout_ms: int = 2000
    traffic_interval: float = 1.0
    gateway_interval: float = 10.0
    vpn_check_interval: float = 2.0
    int_check_interval: float = 10.0
    ping_ok_ms: int = 25
    ping_warn_ms: int = 50
    ping_high_ms: int = 100
    ping_bad_ms: int = 200
    ping_worse_ms: int = 300
    ping_critical_ms: int = 500


@dataclass
class DisplayConfig:
    """Window display settings."""
    ping_bar_width: int = 19
    border_style: str = "double"
    public_ip_char: str = "░"
    traceroute_input_char: str = " "
    traceroute_input_width: int = 17


@dataclass
class Config:
    """Complete application configuration."""
    app_name: str = "OVPNMonitor"
    version: str = "0.0.3"
    author: str = "Igor Brzezek"
    refresh_interval_ms: int = 1000
    refresh_interval_s: int = 1
    background_char: str = " "
    vpn_interface: str = "auto"
    local_interface: str = ""
    log_file: str = ""
    pathping_target: str = ""
    config_path: str = ""
    show_public_ip: bool = False
    warnings: List[str] = field(default_factory=list)

    colors: ColorConfig = field(default_factory=ColorConfig)
    keys: KeyConfig = field(default_factory=KeyConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    display: DisplayConfig = field(default_factory=DisplayConfig)

    # Curses color pair IDs (assigned at runtime)
    color_pairs: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Color pair registration
# ---------------------------------------------------------------------------

# Global pair counter
_pair_counter = 1
_custom_color_counter = 100


def register_color_pair(fg: int, bg: int) -> int:
    """Register a curses color pair and return its ID."""
    global _pair_counter
    pair_id = _pair_counter
    _pair_counter += 1
    try:
        curses.init_pair(pair_id, fg, bg)
    except curses.error:
        pass
    return pair_id


def init_colors(cfg: Config) -> None:
    """Initialize all curses color pairs from config.
    Must be called after curses.start_color().
    """
    global _pair_counter, _custom_color_counter
    _pair_counter = 1
    _custom_color_counter = 100

    cc = cfg.colors
    pairs = {}

    # Register background color pair first
    bg = _resolve_color(cc.background)
    pairs["background"] = register_color_pair(curses.COLOR_WHITE, bg)

    color_fields = [
        "status_bar_top", "status_bar_bottom", "border", "border_title",
        "text_normal", "text_label", "text_value", "text_warning",
        "text_error", "online", "offline", "highlight",
        "popup_border", "popup_bg",
        "ping_ok", "ping_warn", "ping_high", "ping_bad",
        "ping_worse", "ping_critical", "ping_dead",
        "public_ip_bar",
        "traceroute_border", "traceroute_bg", "traceroute_input",
    ]

    for name in color_fields:
        fg, bg = getattr(cc, name)
        fg = _resolve_color(fg)
        bg = _resolve_color(bg)
        pairs[name] = register_color_pair(fg, bg)

    wbg = _resolve_color(cc.window_bg)
    pairs["window_bg"] = register_color_pair(curses.COLOR_WHITE, wbg)

    cfg.color_pairs = pairs


def get_attr(cfg: Config, name: str, bold: bool = False) -> int:
    """Get curses attribute for a named color pair."""
    pair_id = cfg.color_pairs.get(name, 0)
    attr = curses.color_pair(pair_id)
    if bold:
        attr |= curses.A_BOLD
    return attr


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _find_config_file(explicit_path: Optional[str] = None) -> Optional[str]:
    """Find the config file in standard locations."""
    if explicit_path and os.path.isfile(explicit_path):
        return explicit_path

    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "ovpnmonitor.cfg"),
        os.path.join(os.path.expanduser("~"), ".ovpnmonitor.cfg"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def load_config(explicit_path: Optional[str] = None) -> Config:
    """Load configuration from file, falling back to defaults."""
    cfg = Config()
    path = _find_config_file(explicit_path)

    if path is None:
        cfg.config_path = "(defaults)"
        return cfg

    cfg.config_path = path
    cp = configparser.ConfigParser()
    cp.read(path, encoding="utf-8")

    # --- [general] ---
    if cp.has_section("general"):
        g = cp["general"]
        cfg.app_name = g.get("app_name", cfg.app_name)
        cfg.version = g.get("version", cfg.version)
        cfg.author = g.get("author", cfg.author)
        cfg.refresh_interval_s = max(1, min(5, g.getint("refresh_interval_s", cfg.refresh_interval_s)))
        cfg.refresh_interval_ms = cfg.refresh_interval_s * 1000
        cfg.background_char = g.get("background_char", cfg.background_char)
        if not cfg.background_char:
            cfg.background_char = " "
        cfg.vpn_interface = g.get("vpn_interface", cfg.vpn_interface)
        cfg.log_file = g.get("log_file", cfg.log_file)
        cfg.show_public_ip = g.getboolean("show_public_ip", cfg.show_public_ip)

    # --- [colors] ---
    if cp.has_section("colors"):
        c = cp["colors"]
        cc = cfg.colors
        if "background" in c:
            cc.background = _parse_single_color(c["background"].strip().lower())
        for field_name in [
            "status_bar_top", "status_bar_bottom", "border", "border_title",
            "text_normal", "text_label", "text_value", "text_warning",
            "text_error", "online", "offline", "highlight",
            "popup_border", "popup_bg", "public_ip_bar",
            "traceroute_border", "traceroute_bg", "traceroute_input",
        ]:
            if field_name in c:
                setattr(cc, field_name, parse_color_pair(c[field_name]))
        if "window_bgcolor" in c:
            cc.window_bg = _parse_single_color(c["window_bgcolor"].strip().lower())

    # --- [network] ---
    if cp.has_section("network"):
        n = cp["network"]
        nc = cfg.network
        nc.ip_check_url = n.get("ip_check_url", nc.ip_check_url)
        nc.ip_check_interval = n.getfloat("ip_check_interval", nc.ip_check_interval)
        # Parse ping targets: ping_target_1 = address,interval_ms
        targets = []
        for key in sorted(n.keys()):
            if key.startswith("ping_target"):
                val = n[key].strip()
                parts = [p.strip() for p in val.split(",")]
                if len(parts) == 2:
                    try:
                        targets.append(PingTarget(parts[0], int(parts[1])))
                    except ValueError:
                        targets.append(PingTarget(parts[0], 5000))
                elif len(parts) == 1 and parts[0]:
                    targets.append(PingTarget(parts[0], 5000))
        if targets:
            if len(targets) > 3:
                cfg.warnings.append(
                    f"Only first 3 ping targets are used, "
                    f"ignoring {len(targets) - 3} additional target(s)."
                )
                targets = targets[:3]
            nc.ping_targets = targets
        nc.ping_enabled = n.getboolean("ping_enabled", nc.ping_enabled)
        nc.ping_timeout_ms = n.getint("ping_timeout_ms", nc.ping_timeout_ms)
        nc.traffic_interval = n.getfloat("traffic_interval", nc.traffic_interval)
        nc.gateway_interval = n.getfloat("gateway_interval", nc.gateway_interval)
        nc.vpn_check_interval = n.getfloat("vpn_check_interval", nc.vpn_check_interval)
        nc.int_check_interval = n.getfloat("int_check_interval", nc.int_check_interval)
        nc.ping_ok_ms = n.getint("ping_ok_ms", nc.ping_ok_ms)
        nc.ping_warn_ms = n.getint("ping_warn_ms", nc.ping_warn_ms)
        nc.ping_high_ms = n.getint("ping_high_ms", nc.ping_high_ms)
        nc.ping_bad_ms = n.getint("ping_bad_ms", nc.ping_bad_ms)
        nc.ping_worse_ms = n.getint("ping_worse_ms", nc.ping_worse_ms)
        nc.ping_critical_ms = n.getint("ping_critical_ms", nc.ping_critical_ms)

    # --- [keys] ---
    if cp.has_section("keys"):
        k = cp["keys"]
        kc = cfg.keys
        kc.quit = k.get("quit", kc.quit)
        kc.help = k.get("help", kc.help)
        kc.info = k.get("info", kc.info)
        kc.refresh_ip = k.get("refresh_ip", kc.refresh_ip)
        kc.toggle_pause = k.get("toggle_pause", kc.toggle_pause)
        kc.toggle_ping = k.get("toggle_ping", kc.toggle_ping)
        kc.show_routes = k.get("show_routes", kc.show_routes)
        kc.toggle_ip = k.get("toggle_ip", kc.toggle_ip)
        kc.traceroute = k.get("traceroute", kc.traceroute)

    # --- [display] ---
    if cp.has_section("display"):
        d = cp["display"]
        dc = cfg.display
        dc.ping_bar_width = d.getint("ping_bar_width", dc.ping_bar_width)
        dc.border_style = d.get("border_style", dc.border_style).strip().lower()
        dc.public_ip_char = d.get("public_ip_char", dc.public_ip_char)
        _tmp = d.get("traceroute_input_char", None)
        if _tmp is not None:
            dc.traceroute_input_char = _tmp if _tmp else " "
        dc.traceroute_input_width = max(10, d.getint("traceroute_input_width", dc.traceroute_input_width))

    if dc.border_style not in ("single", "double"):
        dc.border_style = "double"

    return cfg
