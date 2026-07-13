#!/usr/bin/env python3
"""OVPNMonitor TUI rendering with curses.

DOS/iptraf-style interface with double-bordered windows,
top/bottom status bars, and popup overlays.
"""

import curses
import os
import socket
import struct
import threading
import time
from typing import List, Optional

from ovpnmonitor_cfg import Config, get_attr
from ovpnmonitor_data import MonitorState, custom_traceroute, get_all_routes

# ---------------------------------------------------------------------------
# Unicode box-drawing characters (double line)
# ---------------------------------------------------------------------------
BOX_TL = "\u2554"   # ╔
BOX_TR = "\u2557"   # ╗
BOX_BL = "\u255A"   # ╚
BOX_BR = "\u255D"   # ╝
BOX_H  = "\u2550"   # ═
BOX_V  = "\u2551"   # ║
BOX_LT = "\u2560"   # ╠
BOX_RT = "\u2563"   # ╣
BOX_HT = "\u2566"   # ╦
BOX_HB = "\u2569"   # ╩

# Single-line box characters
BOX_S_TL = "\u250C"  # ┌
BOX_S_TR = "\u2510"  # ┐
BOX_S_BL = "\u2514"  # └
BOX_S_BR = "\u2518"  # ┘
BOX_S_H  = "\u2500"  # ─
BOX_S_V  = "\u2502"  # │

# Global border style toggle
_border_style = "double"

def set_border_style(style: str):
    global _border_style
    _border_style = style

# Block characters for ping bar
BLOCK_FULL = "\u2588"  # █
BLOCK_HALF = "\u2592"  # ▒

# Arrows
ARROW_DOWN = "\u25BC"  # ▼
ARROW_UP   = "\u25B2"  # ▲


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 * 1024 * 1024:
        return f"{n / (1024*1024):.2f} MB"
    else:
        return f"{n / (1024*1024*1024):.2f} GB"


def format_rate(bps: float) -> str:
    if bps < 1024:
        return f"{bps:.0f} B/s"
    elif bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    elif bps < 1024 * 1024 * 1024:
        return f"{bps / (1024*1024):.2f} MB/s"
    else:
        return f"{bps / (1024*1024*1024):.2f} GB/s"


def format_pps(pps: float) -> str:
    if pps < 1000:
        return f"{pps:.0f} p/s"
    elif pps < 1000 * 1000:
        return f"{pps / 1000:.1f} Kp/s"
    else:
        return f"{pps / (1000*1000):.2f} Mp/s"


def format_uptime(seconds: float) -> str:
    if seconds <= 0:
        return "--:--:--"
    h = int(seconds) // 3600
    m = (int(seconds) % 3600) // 60
    s = int(seconds) % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def format_datetime() -> str:
    t = time.localtime()
    return time.strftime("%d:%m:%Y %H:%M", t)


def format_packets(n: int) -> str:
    if n < 1000:
        return str(n)
    elif n < 1_000_000:
        return f"{n:,}".replace(",", ",")
    else:
        return f"{n:,}".replace(",", ",")


# ---------------------------------------------------------------------------
# Drawing primitives
# ---------------------------------------------------------------------------

def safe_addstr(win, y: int, x: int, text: str, attr: int = 0):
    """Write string, silently ignoring curses errors at edges."""
    try:
        h, w = win.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        max_len = w - x - 1
        if max_len <= 0:
            return
        win.addnstr(y, x, text, max_len, attr)
    except curses.error:
        pass


def draw_double_box(win, y: int, x: int, h: int, w: int,
                    title: str = "", attr: int = 0, title_attr: int = 0, fill_attr: int = 0):
    """Draw a bordered box at (y, x) with size h x w.
    Uses double or single lines based on _border_style.
    If fill_attr is nonzero, the interior is filled with that attribute."""
    if h < 2 or w < 4:
        return
    if _border_style == "single":
        tl, tr, bl, br = BOX_S_TL, BOX_S_TR, BOX_S_BL, BOX_S_BR
        hh, vv = BOX_S_H, BOX_S_V
    else:
        tl, tr, bl, br = BOX_TL, BOX_TR, BOX_BL, BOX_BR
        hh, vv = BOX_H, BOX_V
    if fill_attr:
        fill_str = " " * (w - 2)
        for row in range(1, h - 1):
            safe_addstr(win, y + row, x + 1, fill_str, fill_attr)
    safe_addstr(win, y, x, tl, attr)
    safe_addstr(win, y, x + 1, hh * (w - 2), attr)
    safe_addstr(win, y, x + w - 1, tr, attr)
    for row in range(1, h - 1):
        safe_addstr(win, y + row, x, vv, attr)
        safe_addstr(win, y + row, x + w - 1, vv, attr)
    safe_addstr(win, y + h - 1, x, bl, attr)
    safe_addstr(win, y + h - 1, x + 1, hh * (w - 2), attr)
    safe_addstr(win, y + h - 1, x + w - 1, br, attr)
    if title and w > len(title) + 4:
        t = f" {title} "
        tx = x + (w - len(t)) // 2
        safe_addstr(win, y, tx, t, title_attr if title_attr else attr)


def draw_hsep(win, y: int, x: int, w: int, attr: int = 0):
    """Draw horizontal separator across box."""
    if _border_style == "single":
        lt, rt, hh = BOX_S_V, BOX_S_V, BOX_S_H
    else:
        lt, rt, hh = BOX_LT, BOX_RT, BOX_H
    safe_addstr(win, y, x, lt, attr)
    safe_addstr(win, y, x + 1, hh * (w - 2), attr)
    safe_addstr(win, y, x + w - 1, rt, attr)


def draw_label_value(win, y: int, x: int, label: str, value: str,
                     label_attr: int = 0, value_attr: int = 0,
                     width: int = 0):
    """Draw 'Label: Value' pair."""
    safe_addstr(win, y, x, label, label_attr)
    safe_addstr(win, y, x + len(label), value, value_attr)


def draw_ping_bar(win, y: int, x: int, latency: float,
                  max_ms: float = 200.0, bar_width: int = 15,
                  ok_attr: int = 0, warn_attr: int = 0):
    """Draw a visual latency bar."""
    if latency < 0:
        safe_addstr(win, y, x, "?" * bar_width, warn_attr)
        return
    filled = min(bar_width, int((latency / max_ms) * bar_width))
    bar = BLOCK_FULL * filled + BLOCK_HALF * (bar_width - filled)
    attr = warn_attr if latency > 100 else ok_attr
    safe_addstr(win, y, x, bar, attr)


# ---------------------------------------------------------------------------
# UI Panels
# ---------------------------------------------------------------------------

class UIManager:
    """Manages the full TUI layout and rendering."""

    MIN_WIDTH = 60
    MIN_HEIGHT = 20

    def __init__(self, stdscr, cfg: Config, state: MonitorState):
        self.stdscr = stdscr
        self.cfg = cfg
        self.state = state
        self.show_help = False
        self.show_info = False
        self.show_ping = True
        self.show_ip = cfg.show_public_ip
        self.show_warning = bool(self.cfg.warnings)
        self.show_routes = False
        self._routes_cache = []
        self.hostname = socket.gethostname()

        # Traceroute state
        self.traceroute_state = "idle"   # idle | input | running | done
        self.traceroute_buffer = ""
        self.traceroute_results: Optional[List[Optional[str]]] = None
        self.traceroute_thread: Optional[threading.Thread] = None
        self.traceroute_scroll = 0

        # Panel scroll offsets
        self.traffic_scroll = 0
        self.local_scroll = 0

    def get_size(self):
        h, w = self.stdscr.getmaxyx()
        return max(h, self.MIN_HEIGHT), max(w, self.MIN_WIDTH)

    def draw(self):
        """Full screen redraw."""
        self.stdscr.erase()
        h, w = self.get_size()

        # Fill entire screen with background color and character (DOS-style)
        bg_attr = get_attr(self.cfg, "background")
        bg_line = self.cfg.background_char * w
        for row in range(h):
            safe_addstr(self.stdscr, row, 0, bg_line, bg_attr)

        self._draw_top_bar(w)
        self._draw_bottom_bar(h, w)
        self._draw_main_panels(h, w)

        if self.show_help:
            self._draw_help_popup(h, w)
        if self.show_info:
            self._draw_info_popup(h, w)
        if self.show_warning:
            self._draw_warning_popup(h, w)
        if self.show_routes:
            self._draw_routes_popup(h, w)

        if self.traceroute_state == "input":
            self._draw_traceroute_input_popup(h, w)
        elif self.traceroute_state in ("running", "done"):
            # Check if thread finished
            if (self.traceroute_state == "running" and
                self.traceroute_thread and not self.traceroute_thread.is_alive()):
                self.traceroute_state = "done"
            self._draw_traceroute_results_popup(h, w)

        self.stdscr.noutrefresh()
        curses.doupdate()

    # --- Status bars ---

    def _draw_top_bar(self, w: int):
        attr = get_attr(self.cfg, "status_bar_top", bold=True)
        bar = " " * w
        safe_addstr(self.stdscr, 0, 0, bar, attr)

        # Left: app name
        name = f" {self.cfg.app_name} v{self.cfg.version}"
        safe_addstr(self.stdscr, 0, 0, name, attr)

        # Center: ONLINE / OFFLINE
        with self.state.lock:
            connected = self.state.vpn_connected
            paused = self.state.paused
            public_ip = self.state.public_ip

        if connected:
            status_text = " ONLINE "
            status_attr = get_attr(self.cfg, "online", bold=True)
        else:
            status_text = " OFFLINE "
            status_attr = get_attr(self.cfg, "offline", bold=True)

        sx = (w - len(status_text)) // 2
        safe_addstr(self.stdscr, 0, sx, status_text, status_attr | curses.A_REVERSE)

        # Right: public IP (if enabled)
        if self.show_ip and public_ip:
            ip_attr = get_attr(self.cfg, "public_ip_bar", bold=True)
            ip_str = f" {self.cfg.display.public_ip_char} {public_ip} "
            if paused:
                ip_x = w - len(ip_str) - 10
            else:
                ip_x = w - len(ip_str)
            if ip_x > 0:
                safe_addstr(self.stdscr, 0, ip_x, ip_str, ip_attr)

        # Right: paused indicator
        if paused:
            safe_addstr(self.stdscr, 0, w - 10, " PAUSED ", attr | curses.A_BLINK)

    def _draw_bottom_bar(self, h: int, w: int):
        attr = get_attr(self.cfg, "status_bar_bottom", bold=True)
        y = h - 1
        bar = " " * w
        safe_addstr(self.stdscr, y, 0, bar, attr)

        # Left: hostname
        safe_addstr(self.stdscr, y, 1, self.hostname, attr)

        # Center: key hints
        hints = "H:Help  I:Info  N:Ping  R:Routes  A:IP  T:Trace  P:Pause  Q:Quit"
        hx = (w - len(hints)) // 2
        safe_addstr(self.stdscr, y, hx, hints, attr)

        # Right: date/time
        dt = format_datetime()
        safe_addstr(self.stdscr, y, w - len(dt) - 2, dt, attr)

    # --- Main content panels ---

    def _draw_main_panels(self, h: int, w: int):
        border_attr = get_attr(self.cfg, "border")
        title_attr = get_attr(self.cfg, "border_title", bold=True)
        label_attr = get_attr(self.cfg, "text_label")
        value_attr = get_attr(self.cfg, "text_value", bold=True)
        warn_attr = get_attr(self.cfg, "text_warning")
        win_bg_attr = get_attr(self.cfg, "window_bg")
        err_attr = get_attr(self.cfg, "text_error")

        with self.state.lock:
            snap = _snapshot(self.state)

        set_border_style(self.cfg.display.border_style)

        content_y = 2
        content_end = h - 2
        margin = 1
        gap = 1

        with self.state.lock:
            vpn_ifaces = list(self.state.vpn_ifaces_info)
        vpn_has_single = len(vpn_ifaces) == 1
        local_ifaces = snap.get("local_ifaces_info", [])

        ping_results = snap["ping_results"]

        usable_w = w - 2 * margin - 2 * gap

        # Two equal columns for rows 2+
        col_width = (usable_w - gap) // 2
        col1_x = margin
        col2_x = margin + col_width + gap

        # ── Row 1: Traffic (left) + Ping (right) same height ──
        num_tun = len(vpn_ifaces) or 0
        num_loc = len(local_ifaces) or 0
        traffic_content = 4 + max(1, num_tun) + max(1, num_loc)
        traffic_h = max(9, traffic_content + 3)

        if self.cfg.network.ping_enabled:
            num_targets = len(self.cfg.network.ping_targets)
            ping_h = max(6, num_targets * 2 + 4)
            bar_w = max(4, self.cfg.display.ping_bar_width)
            ping_w = min(bar_w + 9, (usable_w - gap) * 2 // 5)
        else:
            ping_h = 0
            ping_w = 0

        avail_h = content_end - content_y
        traffic_h = min(traffic_h, avail_h)
        ping_h = min(ping_h, avail_h)
        row1_h = max(traffic_h, ping_h) if self.cfg.network.ping_enabled else traffic_h
        traffic_w = (usable_w - ping_w - gap) if ping_w > 0 else min(usable_w, 75)

        # ── Row 2: OpenVPN Info (left) + Local Network (right) ──
        row2_y = content_y + row1_h + 1
        if vpn_has_single:
            conn_h = 12
        elif vpn_ifaces:
            conn_h = max(8, len(vpn_ifaces) + 6)
        else:
            conn_h = 6

        has_single_local = len(local_ifaces) == 1
        if has_single_local:
            local_net_h = 10
        elif local_ifaces:
            local_net_h = max(7, len(local_ifaces) + 5)
        else:
            local_net_h = 5

        avail_h2 = content_end - row2_y
        conn_h = min(conn_h, avail_h2)
        local_net_h = min(local_net_h, avail_h2)
        row2_h = max(conn_h, local_net_h)

        # ── Row 3: PathPing ──
        row3_y = row2_y + row2_h + 1

        traffic_x = margin
        ping_x = traffic_x + traffic_w + gap

        # ── Row 1: Traffic (left) ──
        if content_y + row1_h <= content_end:
            lx = traffic_x + 2
            name_w = 6
            cw = traffic_w - 4
            dcw = min(12, max(5, (cw - name_w - 7) // 6))

            lines = []

            # TUN section
            lines.append((f" {BOX_H * 2} TUN {BOX_H * 2}", label_attr | curses.A_BOLD))
            lines.append((" Intf  " + f"{ARROW_DOWN}".rjust(dcw) + " " +
                          f"{ARROW_UP}".rjust(dcw) + " " +
                          "Tx".rjust(dcw) + " Rx".rjust(dcw) + " " +
                          "P↓".rjust(dcw) + " P↑".rjust(dcw), label_attr))
            if vpn_ifaces:
                for iface in vpn_ifaces:
                    name = (iface.get("name", "") or "?")[:name_w].ljust(name_w)
                    td = snap["ifaces_traffic"].get(iface.get("name", ""), {})
                    line = " " + name + " " + \
                           format_rate(td.get("bytes_recv_rate", 0))[:dcw].rjust(dcw) + " " + \
                           format_rate(td.get("bytes_sent_rate", 0))[:dcw].rjust(dcw) + " " + \
                           format_bytes(td.get("session_bytes_sent", 0))[:dcw].rjust(dcw) + " " + \
                           format_bytes(td.get("session_bytes_recv", 0))[:dcw].rjust(dcw) + " " + \
                           format_pps(td.get("packets_recv_rate", 0))[:dcw].rjust(dcw) + " " + \
                           format_pps(td.get("packets_sent_rate", 0))[:dcw].rjust(dcw)
                    lines.append((line, value_attr))
            else:
                lines.append((" No TUN interface", warn_attr))

            # Local section
            lines.append((f" {BOX_H * 2} Local {BOX_H * 2}", label_attr | curses.A_BOLD))
            lines.append((" Intf  " + f"{ARROW_DOWN}".rjust(dcw) + " " +
                          f"{ARROW_UP}".rjust(dcw) + " " +
                          "Tx".rjust(dcw) + " Rx".rjust(dcw) + " " +
                          "P↓".rjust(dcw) + " P↑".rjust(dcw), label_attr))
            if local_ifaces:
                for iface in local_ifaces:
                    name = (iface.get("name", "") or "?")[:name_w].ljust(name_w)
                    td = snap["ifaces_traffic"].get(iface.get("name", ""), {})
                    line = " " + name + " " + \
                           format_rate(td.get("bytes_recv_rate", 0))[:dcw].rjust(dcw) + " " + \
                           format_rate(td.get("bytes_sent_rate", 0))[:dcw].rjust(dcw) + " " + \
                           format_bytes(td.get("session_bytes_sent", 0))[:dcw].rjust(dcw) + " " + \
                           format_bytes(td.get("session_bytes_recv", 0))[:dcw].rjust(dcw) + " " + \
                           format_pps(td.get("packets_recv_rate", 0))[:dcw].rjust(dcw) + " " + \
                           format_pps(td.get("packets_sent_rate", 0))[:dcw].rjust(dcw)
                    lines.append((line, value_attr))
            else:
                lines.append((" No local interface", warn_attr))

            num_lines = len(lines)
            avail_h = traffic_h - 3
            max_scroll = max(0, num_lines - avail_h)
            if self.traffic_scroll > max_scroll:
                self.traffic_scroll = max_scroll

            title = "Traffic Statistics"
            if max_scroll > 0:
                up_arrow = ARROW_UP if self.traffic_scroll > 0 else " "
                dn_arrow = ARROW_DOWN if self.traffic_scroll < max_scroll else " "
                title = f"Traffic Statistics [{up_arrow}{dn_arrow}]"

            draw_double_box(self.stdscr, content_y, traffic_x, row1_h, traffic_w,
                          title, border_attr, title_attr, win_bg_attr)

            start_line = self.traffic_scroll
            end_line = min(start_line + avail_h, num_lines)
            for i in range(start_line, end_line):
                text, attr = lines[i]
                y = content_y + 2 + (i - start_line)
                safe_addstr(self.stdscr, y, lx, text, attr)

        # ── Row 2: OpenVPN Info (left) + Local Network (right) ──
        if row2_y + row2_h <= content_end:
            # OpenVPN Info (left)
            ovpn_border = err_attr if not vpn_ifaces else border_attr
            draw_double_box(self.stdscr, row2_y, col1_x, conn_h, col_width,
                          "OpenVPN Info", ovpn_border, title_attr, win_bg_attr)
            lx = col1_x + 2
            if not vpn_ifaces:
                safe_addstr(self.stdscr, row2_y + 2, lx,
                           " No VPN interface found", err_attr)
                safe_addstr(self.stdscr, row2_y + 3, lx,
                           " Use --tun or start VPN", warn_attr)
            elif vpn_has_single:
                iface = vpn_ifaces[0]
                ip_attr = value_attr if snap["public_ip"] not in ("detecting...", "") else warn_attr
                draw_label_value(self.stdscr, row2_y + 2, lx,
                               " Public IP:    ", snap["public_ip"], label_attr, ip_attr)
                draw_label_value(self.stdscr, row2_y + 3, lx,
                               " VPN Gateway:  ", iface.get("gateway", "") or snap["gateway_ip"] or "N/A", label_attr, value_attr)
                draw_label_value(self.stdscr, row2_y + 4, lx,
                               " Local IP:     ", iface.get("local_ip", "") or "N/A", label_attr, value_attr)
                server_str = snap["vpn_server"] or "N/A"
                if snap["vpn_protocol"] or snap["vpn_port"]:
                    server_str += f" ({snap['vpn_protocol']}/{snap['vpn_port']})"
                draw_label_value(self.stdscr, row2_y + 5, lx,
                               " Server:       ", server_str, label_attr, value_attr)
                uptime_val = 0.0
                if snap["vpn_connect_time"] > 0:
                    uptime_val = time.time() - snap["vpn_connect_time"]
                draw_label_value(self.stdscr, row2_y + 6, lx,
                               " Interface:    ", iface.get("name", "") or "N/A", label_attr, value_attr)
                draw_label_value(self.stdscr, row2_y + 7, lx,
                               " PID:          ", str(snap["vpn_process_pid"]) if snap["vpn_process_pid"] else "N/A", label_attr, value_attr)
                draw_label_value(self.stdscr, row2_y + 8, lx,
                               " Uptime:       ", format_uptime(uptime_val), label_attr, value_attr)

                # Config (last at bottom, with wrapping)
                cfg_val = snap["vpn_config_file"]
                if cfg_val:
                    home_dir = os.path.expanduser("~")
                    if cfg_val.startswith(home_dir):
                        cfg_val = "~" + cfg_val[len(home_dir):]
                else:
                    cfg_val = "N/A"
                cfg_label = " Config:       "
                cfg_row = row2_y + 9
                content_w = col_width - 4
                if len(cfg_label) + len(cfg_val) <= content_w:
                    safe_addstr(self.stdscr, cfg_row, lx, cfg_label, label_attr)
                    safe_addstr(self.stdscr, cfg_row, lx + len(cfg_label), cfg_val, value_attr)
                else:
                    safe_addstr(self.stdscr, cfg_row, lx, cfg_label, label_attr)
                    cfg_row += 1
                    if cfg_row < row2_y + conn_h - 1:
                        safe_addstr(self.stdscr, cfg_row, lx, cfg_val[:content_w], value_attr)
            else:
                ip_attr = value_attr if snap["public_ip"] not in ("detecting...", "") else warn_attr
                draw_label_value(self.stdscr, row2_y + 2, lx,
                               " Public IP:    ", snap["public_ip"], label_attr, ip_attr)
                draw_label_value(self.stdscr, row2_y + 3, lx,
                               " Server:       ", snap["vpn_server"] or "N/A", label_attr, value_attr)
                row = row2_y + 4
                safe_addstr(self.stdscr, row, lx,
                          " Name  Local IP       Uptime", label_attr | curses.A_BOLD)
                row += 1
                safe_addstr(self.stdscr, row, lx,
                          " " + BOX_H * 30, label_attr)
                row += 1
                for iface in vpn_ifaces:
                    if row >= row2_y + conn_h - 1:
                        break
                    name = (iface.get("name", "") or "?")[:6].ljust(6)
                    lip = (iface.get("local_ip", "") or "N/A")[:13].ljust(13)
                    upt = format_uptime(time.time() - snap["vpn_connect_time"]) if snap["vpn_connect_time"] > 0 else "--:--:--"
                    safe_addstr(self.stdscr, row, lx,
                              f" {name} {lip} {upt}", value_attr)
                    row += 1

            # Local Network (right)
            if has_single_local:
                draw_double_box(self.stdscr, row2_y, col2_x, local_net_h, col_width,
                              "Local Interfaces", border_attr, title_attr, win_bg_attr)
                lx = col2_x + 2
                iface = local_ifaces[0]
                ip = iface.get("ipv4", "") or ""
                mask = iface.get("netmask", "") or ""
                ipv4mask = f"{ip}/{mask} [{_mask_to_cidr(mask)}]" if ip and mask else (ip or "N/A")
                net, bcast = _network_broadcast(ip, mask)
                draw_label_value(self.stdscr, row2_y + 2, lx,
                               " Interface:   ", iface.get("name", "") or "N/A", label_attr, value_attr)
                draw_label_value(self.stdscr, row2_y + 3, lx,
                               " MAC:         ", iface.get("mac", "") or "N/A", label_attr, value_attr)
                draw_label_value(self.stdscr, row2_y + 4, lx,
                               " IPv4/Mask:   ", ipv4mask, label_attr, value_attr)
                draw_label_value(self.stdscr, row2_y + 5, lx,
                               " IPv6/Mask:   ", iface.get("ipv6", "") or "N/A", label_attr, value_attr)
                draw_label_value(self.stdscr, row2_y + 6, lx,
                               " Network:     ", net, label_attr, value_attr)
                draw_label_value(self.stdscr, row2_y + 7, lx,
                               " Broadcast:   ", bcast, label_attr, value_attr)
            else:
                local_lines = []
                if local_ifaces:
                    local_lines.append((" Name   MAC               IPv4/Mask          S/D", label_attr | curses.A_BOLD))
                    local_lines.append((" " + BOX_H * 49, label_attr))
                    for iface in sorted(local_ifaces, key=lambda x: x.get("name", "")):
                        name = (iface.get("name", "") or "?")[:6].ljust(6)
                        mac = (iface.get("mac", "") or "N/A")[:17].ljust(17)
                        ipv4 = iface.get("ipv4", "") or ""
                        mask = iface.get("netmask", "") or ""
                        cidr = _mask_to_cidr(mask) if mask else 0
                        ipv4mask = (f"{ipv4}/{cidr}" if ipv4 and mask else (ipv4 or "N/A"))[:18].ljust(18)
                        dhcp_s = "DHCP" if iface.get("is_dhcp") else "S"
                        local_lines.append((f" {name} {mac} {ipv4mask} {dhcp_s}", value_attr))
                else:
                    local_lines.append((" No interface detected", warn_attr))

                num_local = len(local_lines)
                avail_local = local_net_h - 3
                max_scroll = max(0, num_local - avail_local)
                if self.local_scroll > max_scroll:
                    self.local_scroll = max_scroll

                local_title = "Local Interfaces"
                if max_scroll > 0:
                    up_arrow = ARROW_UP if self.local_scroll > 0 else " "
                    dn_arrow = ARROW_DOWN if self.local_scroll < max_scroll else " "
                    local_title = f"Local Interfaces [{up_arrow}{dn_arrow}]"

                draw_double_box(self.stdscr, row2_y, col2_x, local_net_h, col_width,
                              local_title, border_attr, title_attr, win_bg_attr)

                lx = col2_x + 2
                start_line = self.local_scroll
                end_line = min(start_line + avail_local, num_local)
                for i in range(start_line, end_line):
                    text, attr = local_lines[i]
                    safe_addstr(self.stdscr, row2_y + 2 + (i - start_line), lx, text, attr)

        # ── Row 1: Ping (right) ──
        if self.cfg.network.ping_enabled and self.show_ping and content_y + row1_h <= content_end:
            draw_double_box(self.stdscr, content_y, ping_x, row1_h, ping_w,
                          "Ping Monitor", border_attr, title_attr, win_bg_attr)
            lx = ping_x + 2
            row = content_y + 2
            if ping_results:
                for target, pr in ping_results.items():
                    if row >= content_y + row1_h - 2:
                        break
                    lat = pr["latency_ms"]
                    nc = self.cfg.network
                    if lat < nc.ping_ok_ms:
                        color_attr = get_attr(self.cfg, "ping_ok")
                    elif lat < nc.ping_warn_ms:
                        color_attr = get_attr(self.cfg, "ping_warn")
                    elif lat < nc.ping_high_ms:
                        color_attr = get_attr(self.cfg, "ping_high", bold=True)
                    elif lat < nc.ping_bad_ms:
                        color_attr = get_attr(self.cfg, "ping_bad")
                    elif lat < nc.ping_worse_ms:
                        color_attr = get_attr(self.cfg, "ping_worse")
                    elif lat < nc.ping_critical_ms:
                        color_attr = get_attr(self.cfg, "ping_critical")
                    else:
                        color_attr = get_attr(self.cfg, "ping_dead", bold=True)

                    label = f" {target[:7]:<7s}"
                    if pr["reachable"]:
                        val = f"{lat:>5.0f} ms".rjust(max(4, bar_w - 7))
                        safe_addstr(self.stdscr, row, lx, label, label_attr)
                        safe_addstr(self.stdscr, row, lx + len(label), val, color_attr)
                        row += 1
                        if lat >= nc.ping_critical_ms:
                            safe_addstr(self.stdscr, row, lx + 1, "!" * bar_w, color_attr)
                            safe_addstr(self.stdscr, row, lx + 2 + bar_w, " !", color_attr)
                        else:
                            draw_ping_bar(self.stdscr, row, lx + 1, lat,
                                        max_ms=200.0, bar_width=bar_w,
                                        ok_attr=color_attr, warn_attr=color_attr)
                            safe_addstr(self.stdscr, row, lx + 2 + bar_w, " OK", color_attr)
                    else:
                        safe_addstr(self.stdscr, row, lx, label, label_attr)
                        safe_addstr(self.stdscr, row, lx + len(label), " timeout", err_attr)
                        row += 1
                        safe_addstr(self.stdscr, row, lx + 1, "?" * min(bar_w, 8), err_attr)
                    row += 1
            else:
                safe_addstr(self.stdscr, row, lx, " No ping targets", warn_attr)

        # ── Row 3: PathPing (left) ──
        if self.cfg.pathping_target and snap["pathping_hops"]:
            path_hops = snap["pathping_hops"][:10]
            path_extra = 0
            if snap["pathping_changed"]:
                path_extra = 2 + min(len(snap["pathping_prev_hops"]), 3)
            path_h = min(len(path_hops), 10) + 4 + path_extra
            path_h = min(path_h, content_end - row3_y)

            if row3_y + path_h <= content_end:
                draw_double_box(self.stdscr, row3_y, col1_x, path_h, col_width,
                              f" Path to {self.cfg.pathping_target} ", border_attr, title_attr, win_bg_attr)
                lx = col1_x + 2
                row = row3_y + 2
                bx_max = row3_y + path_h - 1
                for i, hop in enumerate(path_hops):
                    if row >= bx_max:
                        break
                    safe_addstr(self.stdscr, row, lx,
                               f" {i+1:2d}  {hop}", value_attr)
                    row += 1
                if snap["pathping_changed"]:
                    if row < bx_max:
                        safe_addstr(self.stdscr, row, lx, " Route changed!  ", warn_attr)
                        row += 1
                    if row < bx_max:
                        safe_addstr(self.stdscr, row, lx, " Was:", warn_attr)
                        row += 1
                    for i, hop in enumerate(snap["pathping_prev_hops"][:3]):
                        if row >= bx_max:
                            break
                        safe_addstr(self.stdscr, row, lx,
                                  f" {i+1:2d}  {hop}", label_attr)
                        row += 1

    # --- Popups ---

    def _draw_popup_box(self, h: int, w: int, ph: int, pw: int, title: str):
        """Draw a centered popup with double border. Returns (y, x)."""
        py = (h - ph) // 2
        px = (w - pw) // 2
        border_attr = get_attr(self.cfg, "popup_border", bold=True)
        title_attr = get_attr(self.cfg, "border_title", bold=True)
        bg_attr = get_attr(self.cfg, "popup_bg")

        # Fill background
        for row in range(py, py + ph):
            safe_addstr(self.stdscr, row, px, " " * pw, bg_attr)

        draw_double_box(self.stdscr, py, px, ph, pw, title, border_attr, title_attr)
        return py, px

    def _draw_warning_popup(self, h: int, w: int):
        msgs = self.cfg.warnings
        if not msgs:
            return
        pw = min(60, w - 6)
        ph = len(msgs) + 4
        py, px = self._draw_popup_box(h, w, ph, pw, "Warning")
        warn_attr = get_attr(self.cfg, "text_warning", bold=True)
        for i, msg in enumerate(msgs):
            safe_addstr(self.stdscr, py + 2 + i, px + 3, f"  {msg}", warn_attr)

    def _draw_help_popup(self, h: int, w: int):
        pw = min(50, w - 6)
        lines = [
            ("H / F1", "Toggle this help"),
            ("I",      "Toggle connection info"),
            ("N",      "Toggle ping monitor"),
            ("R",      "Show routes table"),
            ("U",      "Refresh public IP now"),
            ("A",      "Toggle public IP in top bar"),
            ("T",      "Traceroute to IP/host"),
            ("P",      "Pause/resume collectors"),
            ("Q",      "Quit application"),
            ("ESC",    "Close popup"),
        ]
        ph = len(lines) + 4
        py, px = self._draw_popup_box(h, w, ph, pw, "Help — Keyboard Shortcuts")
        label_attr = get_attr(self.cfg, "text_label", bold=True)
        value_attr = get_attr(self.cfg, "popup_bg")

        for i, (key, desc) in enumerate(lines):
            safe_addstr(self.stdscr, py + 2 + i, px + 3, f"  {key:>8s}  ", label_attr)
            safe_addstr(self.stdscr, py + 2 + i, px + 16, desc, value_attr)

    def _draw_info_popup(self, h: int, w: int):
        with self.state.lock:
            snap = _snapshot(self.state)

        home = os.path.expanduser("~")
        cfg_path = self.cfg.config_path
        if cfg_path and cfg_path.startswith(home):
            cfg_path = "~" + cfg_path[len(home):]
        lines = [
            ("App Name:",    self.cfg.app_name),
            ("Version:",     self.cfg.version),
            ("Author:",      self.cfg.author),
            ("",             ""),
            ("VPN Interface:", snap["vpn_interface"] or "(none)"),
            ("VPN PID:",     str(snap["vpn_process_pid"]) if snap["vpn_process_pid"] else "N/A"),
            ("Config:",      snap["vpn_config_file"] or "N/A"),
            ("Hostname:",    self.hostname),
            ("Config File:", ""),
            ("",             cfg_path or "(defaults)"),
        ]
        # Calculate required width dynamically
        max_val = max((len(v) for _, v in lines if v), default=0)
        content_w = max(22 + max_val, 6 + max_val) + 4
        pw = min(content_w, w - 6)
        ph = len(lines) + 4
        py, px = self._draw_popup_box(h, w, ph, pw, "Program Info")
        label_attr = get_attr(self.cfg, "text_label", bold=True)
        value_attr = get_attr(self.cfg, "popup_bg")

        for i, (label, value) in enumerate(lines):
            if label:
                safe_addstr(self.stdscr, py + 2 + i, px + 3, f"  {label:>16s} ", label_attr)
                safe_addstr(self.stdscr, py + 2 + i, px + 22, value, value_attr)
            elif value:
                safe_addstr(self.stdscr, py + 2 + i, px + 3, f"      {value}", value_attr)

    def _draw_routes_popup(self, h: int, w: int):
        self._routes_cache = get_all_routes()
        routes = self._routes_cache

        if not routes:
            pw = min(50, w - 6)
            ph = 5
            py, px = self._draw_popup_box(h, w, ph, pw, "Routes Table")
            safe_addstr(self.stdscr, py + 2, px + 3, " No routes found", get_attr(self.cfg, "text_warning"))
            return

        max_vis = h - 6
        pw = min(70, w - 6)
        ph = min(len(routes) + 4, max(6, h - 4))
        py, px = self._draw_popup_box(h, w, ph, pw, "Routes Table")

        label_attr = get_attr(self.cfg, "text_label", bold=True)
        vpn_attr = get_attr(self.cfg, "text_warning", bold=True)
        norm_attr = get_attr(self.cfg, "text_value")
        header_attr = get_attr(self.cfg, "border_title", bold=True)
        bg_attr = get_attr(self.cfg, "popup_bg")

        # Fill background inside box
        for row in range(1, ph - 1):
            safe_addstr(self.stdscr, py + row, px + 1, " " * (pw - 2), bg_attr)

        # Header
        safe_addstr(self.stdscr, py + 2, px + 2,
                   f"  {'Destination':<22s} {'Gateway':<18s} {'Interface':<12s}", label_attr)

        # Routes
        max_rows = ph - 4
        for i, r in enumerate(routes):
            if i >= max_rows:
                break
            dest = r["destination"][:20].ljust(20)
            gw = r["gateway"][:16].ljust(16) if r["gateway"] else "(none)".ljust(16)
            iface = r["interface"][:10].ljust(10) if r["interface"] else "(none)".ljust(10)
            line = f"  {dest} {gw} {iface}"
            attr = vpn_attr if r["is_vpn"] else norm_attr
            safe_addstr(self.stdscr, py + 3 + i, px + 2, line, attr)

    # --- Traceroute popups ---

    def _draw_traceroute_input_popup(self, h: int, w: int):
        pw = min(60, w - 6)
        ph = 7
        py = (h - ph) // 2
        px = (w - pw) // 2
        border_attr = get_attr(self.cfg, "traceroute_border", bold=True)
        title_attr = get_attr(self.cfg, "border_title", bold=True)
        bg_attr = get_attr(self.cfg, "traceroute_bg")
        label_attr = get_attr(self.cfg, "text_label", bold=True)
        input_attr = get_attr(self.cfg, "traceroute_input", bold=True)
        warn_attr = get_attr(self.cfg, "text_warning")

        # Fill background
        for row in range(py, py + ph):
            safe_addstr(self.stdscr, row, px, " " * pw, bg_attr)
        draw_double_box(self.stdscr, py, px, ph, pw, "Traceroute — Enter target", border_attr, title_attr)

        safe_addstr(self.stdscr, py + 2, px + 3, "  Target IP/host:", label_attr)

        # Fixed-width input field
        fw = self.cfg.display.traceroute_input_width
        fc = self.cfg.display.traceroute_input_char or " "
        buf = self.traceroute_buffer or ""
        filled = (fc * fw)
        ix = px + (pw - fw) // 2
        safe_addstr(self.stdscr, py + 4, ix, filled, input_attr)
        if buf:
            safe_addstr(self.stdscr, py + 4, ix, buf[:fw], input_attr)

        safe_addstr(self.stdscr, py + 5, px + 3, "  Enter=Start  ESC=Cancel", warn_attr)

    def _draw_traceroute_results_popup(self, h: int, w: int):
        results = self.traceroute_results or []
        num_hops = len(results)
        vis_rows = max(3, h - 8)
        ph = min(num_hops + 4, vis_rows + 4) if num_hops else 6
        ph = max(6, ph)
        pw = min(50, w - 6)
        py = (h - ph) // 2
        px = (w - pw) // 2
        border_attr = get_attr(self.cfg, "traceroute_border", bold=True)
        title_attr = get_attr(self.cfg, "border_title", bold=True)
        bg_attr = get_attr(self.cfg, "traceroute_bg")
        value_attr = get_attr(self.cfg, "text_value")
        warn_attr = get_attr(self.cfg, "text_warning")

        # Fill background
        for row in range(py, py + ph):
            safe_addstr(self.stdscr, row, px, " " * pw, bg_attr)

        content_h = ph - 4  # rows available for hop lines
        scrollable = num_hops > content_h
        if self.traceroute_scroll < 0:
            self.traceroute_scroll = 0
        if self.traceroute_scroll > max(0, num_hops - content_h):
            self.traceroute_scroll = max(0, num_hops - content_h)

        title = "Traceroute"
        if self.traceroute_state == "running":
            title += " (running...)"
        if scrollable:
            arrow_up = ARROW_UP if self.traceroute_scroll > 0 else " "
            arrow_dn = ARROW_DOWN if self.traceroute_scroll < num_hops - content_h else " "
            title += f" {arrow_up}{arrow_dn}"
        draw_double_box(self.stdscr, py, px, ph, pw, title, border_attr, title_attr)

        if not results:
            safe_addstr(self.stdscr, py + 2, px + 3, "  No results yet...", warn_attr)
            return

        start = self.traceroute_scroll
        for i in range(min(content_h, num_hops - start)):
            hop = results[start + i]
            hop_num = start + i + 1
            if hop:
                safe_addstr(self.stdscr, py + 2 + i, px + 3, f"  {hop_num:2d}  {hop}", value_attr)
            else:
                safe_addstr(self.stdscr, py + 2 + i, px + 3, f"  {hop_num:2d}  *", warn_attr)

        if self.traceroute_state == "done":
            safe_addstr(self.stdscr, py + ph - 2, px + 3, "  ESC close", warn_attr)

    def _run_traceroute(self, target: str):
        """Run traceroute in a background thread, updating results progressively."""
        results: List[Optional[str]] = []
        self.traceroute_results = results
        def progress(ttl, hop):
            results.append(hop)
        custom_traceroute(target, max_hops=30, timeout=2.0, progress_callback=progress)
        if not results:
            self.traceroute_results = None

    # --- Input handling ---

    def handle_key(self, key: int) -> bool:
        """Handle keypress. Returns False if should quit."""
        # Traceroute input mode — capture text
        if self.traceroute_state == "input":
            if key == 27:  # ESC → cancel
                self.traceroute_state = "idle"
                self.traceroute_buffer = ""
                return True
            if key in (ord("\n"), ord("\r"), curses.KEY_ENTER):  # Enter → start
                target = self.traceroute_buffer.strip()
                self.traceroute_buffer = ""
                if target:
                    self.traceroute_state = "running"
                    self.traceroute_results = None
                    self.traceroute_thread = threading.Thread(
                        target=self._run_traceroute, args=(target,), daemon=True
                    )
                    self.traceroute_thread.start()
                else:
                    self.traceroute_state = "idle"
                return True
            if key in (curses.KEY_BACKSPACE, 127, 8):  # Backspace
                self.traceroute_buffer = self.traceroute_buffer[:-1]
                return True
            if 32 <= key < 127:  # Printable ASCII
                self.traceroute_buffer += chr(key)
                return True
            return True

        # Traceroute results — scrolling + close
        if self.traceroute_state in ("running", "done"):
            if key == 27:
                self.traceroute_state = "idle"
                self.traceroute_results = None
                self.traceroute_thread = None
                self.traceroute_scroll = 0
                return True
            n = len(self.traceroute_results) if self.traceroute_results else 0
            content_h = max(3, self.stdscr.getmaxyx()[0] - 12)
            if key == curses.KEY_UP:
                self.traceroute_scroll = max(0, self.traceroute_scroll - 1)
                return True
            if key == curses.KEY_DOWN:
                self.traceroute_scroll = max(0, min(n - content_h, self.traceroute_scroll + 1))
                return True
            if key == curses.KEY_PPAGE:
                self.traceroute_scroll = max(0, self.traceroute_scroll - content_h)
                return True
            if key == curses.KEY_NPAGE:
                self.traceroute_scroll = max(0, min(n - content_h, self.traceroute_scroll + content_h))
                return True
            return True

        k = self.cfg.keys
        ch = chr(key) if 0 < key < 256 else ""
        ch_lower = ch.lower()

        if ch_lower == k.quit and not self.show_help and not self.show_info and not self.show_routes:
            return False

        if key == 27:  # ESC
            self.show_help = False
            self.show_info = False
            self.show_warning = False
            self.show_routes = False
            return True

        if ch_lower == k.help or key == curses.KEY_F1:
            self.show_help = not self.show_help
            if self.show_help:
                self.show_info = False
                self.show_routes = False
            return True

        if ch_lower == k.info:
            self.show_info = not self.show_info
            if self.show_info:
                self.show_help = False
                self.show_routes = False
            return True

        if ch_lower == k.toggle_pause:
            with self.state.lock:
                self.state.paused = not self.state.paused
            return True

        if ch_lower == k.toggle_ping:
            self.show_ping = not self.show_ping
            return True

        if ch_lower == k.show_routes:
            self.show_routes = not self.show_routes
            if self.show_routes:
                self.show_help = False
                self.show_info = False
            return True

        if ch_lower == k.toggle_ip:
            self.show_ip = not self.show_ip
            if self.show_ip:
                with self.state.lock:
                    self.state.last_ip_check = 0
                    self.state.refresh_token += 1
            return True

        if ch_lower == k.refresh_ip:
            with self.state.lock:
                self.state.public_ip = "refreshing..."
                self.state.last_ip_check = 0
                self.state.refresh_token += 1
            return True

        if ch_lower == k.traceroute:
            self.traceroute_state = "input"
            self.traceroute_buffer = ""
            return True

        # Panel scrolling (when no popup/traceroute is active)
        if key == curses.KEY_UP:
            self.traffic_scroll = max(0, self.traffic_scroll - 1)
            self.local_scroll = max(0, self.local_scroll - 1)
            return True
        if key == curses.KEY_DOWN:
            self.traffic_scroll += 1
            self.local_scroll += 1
            return True
        if key == curses.KEY_PPAGE:
            self.traffic_scroll = max(0, self.traffic_scroll - 5)
            self.local_scroll = max(0, self.local_scroll - 5)
            return True
        if key == curses.KEY_NPAGE:
            self.traffic_scroll += 5
            self.local_scroll += 5
            return True

        return True


def _mask_to_cidr(mask: str) -> int:
    try:
        return sum(bin(b).count("1") for b in socket.inet_aton(mask))
    except OSError:
        return 0


def _network_broadcast(ip: str, mask: str):
    if not ip or not mask:
        return "N/A", "N/A"
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(mask))[0]
        net = socket.inet_ntoa(struct.pack("!I", ip_int & mask_int))
        bcast = socket.inet_ntoa(struct.pack("!I", ip_int | (~mask_int & 0xFFFFFFFF)))
        return net, bcast
    except OSError:
        return "N/A", "N/A"


def _snapshot(state: MonitorState) -> dict:
    """Take a snapshot of state (must be called with lock held)."""
    ping_snap = {}
    for k, v in state.ping_results.items():
        ping_snap[k] = {
            "target": v.target,
            "latency_ms": v.latency_ms,
            "reachable": v.reachable,
        }
    ifaces_traffic = {}
    for name, td in state.ifaces_traffic.items():
        ifaces_traffic[name] = {
            "bytes_sent": td.bytes_sent,
            "bytes_recv": td.bytes_recv,
            "bytes_sent_rate": td.bytes_sent_rate,
            "bytes_recv_rate": td.bytes_recv_rate,
            "session_bytes_sent": td.session_bytes_sent,
            "session_bytes_recv": td.session_bytes_recv,
            "packets_sent_rate": td.packets_sent_rate,
            "packets_recv_rate": td.packets_recv_rate,
        }
    return {
        "vpn_connected": state.vpn_connected,
        "vpn_interface": state.vpn_interface,
        "vpn_process_pid": state.vpn_process_pid,
        "vpn_server": state.vpn_server,
        "vpn_protocol": state.vpn_protocol,
        "vpn_port": state.vpn_port,
        "vpn_config_file": state.vpn_config_file,
        "vpn_connect_time": state.vpn_connect_time,
        "public_ip": state.public_ip,
        "gateway_ip": state.gateway_ip,
        "local_vpn_ip": state.local_vpn_ip,
        "vpn_ifaces_info": list(state.vpn_ifaces_info),
        "local_iface": state.local_iface,
        "local_ip": state.local_ip,
        "local_netmask": state.local_netmask,
        "local_gateway": state.local_gateway,
        "local_dns": list(state.local_dns),
        "local_is_dhcp": state.local_is_dhcp,
        "local_ifaces_info": list(state.local_ifaces_info),
        "ifaces_traffic": ifaces_traffic,
        "ping_results": ping_snap,
        "pathping_hops": list(state.pathping_hops),
        "pathping_changed": state.pathping_changed,
        "pathping_prev_hops": list(state.pathping_prev_hops),
        "paused": state.paused,
    }
