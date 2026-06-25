#!/usr/bin/env python3
"""OVPNMonitor TUI rendering with curses.

DOS/iptraf-style interface with double-bordered windows,
top/bottom status bars, and popup overlays.
"""

import curses
import os
import socket
import struct
import time
from typing import Optional

from ovpnmonitor_cfg import Config, get_attr
from ovpnmonitor_data import MonitorState

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
        self.show_warning = bool(self.cfg.warnings)
        self.hostname = socket.gethostname()

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

        if connected:
            status_text = " ONLINE "
            status_attr = get_attr(self.cfg, "online", bold=True)
        else:
            status_text = " OFFLINE "
            status_attr = get_attr(self.cfg, "offline", bold=True)

        sx = (w - len(status_text)) // 2
        safe_addstr(self.stdscr, 0, sx, status_text, status_attr | curses.A_REVERSE)

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
        hints = "H:Help  I:Info  R:RefreshIP  P:Pause  Q:Quit"
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
            if self.show_ping:
                bar_w = max(4, self.cfg.display.ping_bar_width)
                ping_w = min(bar_w + 9, (usable_w - gap) * 2 // 5)
            else:
                ping_w = 0
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
            draw_double_box(self.stdscr, content_y, traffic_x, row1_h, traffic_w,
                          "Traffic Statistics", border_attr, title_attr, win_bg_attr)
            lx = traffic_x + 2
            name_w = 6
            cw = traffic_w - 4
            dcw = min(12, max(5, (cw - name_w - 7) // 6))
            row = content_y + 2

            # TUN section
            safe_addstr(self.stdscr, row, lx, f" {BOX_H * 2} TUN {BOX_H * 2}", label_attr | curses.A_BOLD)
            row += 1
            safe_addstr(self.stdscr, row, lx,
                       " Intf  " + f"{ARROW_DOWN}".rjust(dcw) + " " +
                       f"{ARROW_UP}".rjust(dcw) + " " +
                       "Tx".rjust(dcw) + " Rx".rjust(dcw) + " " +
                       "P↓".rjust(dcw) + " P↑".rjust(dcw), label_attr)
            row += 1
            if vpn_ifaces:
                for iface in vpn_ifaces:
                    if row >= content_y + traffic_h - 1:
                        break
                    name = (iface.get("name", "") or "?")[:name_w].ljust(name_w)
                    td = snap["ifaces_traffic"].get(iface.get("name", ""), {})
                    line = " " + name + " " + \
                           format_rate(td.get("bytes_recv_rate", 0))[:dcw].rjust(dcw) + " " + \
                           format_rate(td.get("bytes_sent_rate", 0))[:dcw].rjust(dcw) + " " + \
                           format_bytes(td.get("session_bytes_sent", 0))[:dcw].rjust(dcw) + " " + \
                           format_bytes(td.get("session_bytes_recv", 0))[:dcw].rjust(dcw) + " " + \
                           format_pps(td.get("packets_recv_rate", 0))[:dcw].rjust(dcw) + " " + \
                           format_pps(td.get("packets_sent_rate", 0))[:dcw].rjust(dcw)
                    safe_addstr(self.stdscr, row, lx, line, value_attr)
                    row += 1
            else:
                safe_addstr(self.stdscr, row, lx, " No TUN interface", warn_attr)
                row += 1

            # Local section
            if row < content_y + traffic_h - 1:
                safe_addstr(self.stdscr, row, lx, f" {BOX_H * 2} Local {BOX_H * 2}", label_attr | curses.A_BOLD)
                row += 1
                if row < content_y + traffic_h - 1:
                    safe_addstr(self.stdscr, row, lx,
                               " Intf  " + f"{ARROW_DOWN}".rjust(dcw) + " " +
                               f"{ARROW_UP}".rjust(dcw) + " " +
                               "Tx".rjust(dcw) + " Rx".rjust(dcw) + " " +
                               "P↓".rjust(dcw) + " P↑".rjust(dcw), label_attr)
                    row += 1
                if local_ifaces:
                    for iface in local_ifaces:
                        if row >= content_y + traffic_h - 1:
                            break
                        name = (iface.get("name", "") or "?")[:name_w].ljust(name_w)
                        td = snap["ifaces_traffic"].get(iface.get("name", ""), {})
                        line = " " + name + " " + \
                               format_rate(td.get("bytes_recv_rate", 0))[:dcw].rjust(dcw) + " " + \
                               format_rate(td.get("bytes_sent_rate", 0))[:dcw].rjust(dcw) + " " + \
                               format_bytes(td.get("session_bytes_sent", 0))[:dcw].rjust(dcw) + " " + \
                               format_bytes(td.get("session_bytes_recv", 0))[:dcw].rjust(dcw) + " " + \
                               format_pps(td.get("packets_recv_rate", 0))[:dcw].rjust(dcw) + " " + \
                               format_pps(td.get("packets_sent_rate", 0))[:dcw].rjust(dcw)
                        safe_addstr(self.stdscr, row, lx, line, value_attr)
                        row += 1
                else:
                    safe_addstr(self.stdscr, row, lx, " No local interface", warn_attr)
                    row += 1

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
            draw_double_box(self.stdscr, row2_y, col2_x, local_net_h, col_width,
                          "Local Interfaces", border_attr, title_attr, win_bg_attr)
            lx = col2_x + 2
            if has_single_local:
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
            elif local_ifaces:
                row = row2_y + 2
                safe_addstr(self.stdscr, row, lx,
                          " Name   MAC               IPv4/Mask          S/D", label_attr | curses.A_BOLD)
                row += 1
                safe_addstr(self.stdscr, row, lx,
                          " " + BOX_H * 49, label_attr)
                row += 1
                for iface in sorted(local_ifaces, key=lambda x: x.get("name", "")):
                    if row >= row2_y + local_net_h - 1:
                        break
                    name = (iface.get("name", "") or "?")[:6].ljust(6)
                    mac = (iface.get("mac", "") or "N/A")[:17].ljust(17)
                    ipv4 = iface.get("ipv4", "") or ""
                    mask = iface.get("netmask", "") or ""
                    cidr = _mask_to_cidr(mask) if mask else 0
                    ipv4mask = (f"{ipv4}/{cidr}" if ipv4 and mask else (ipv4 or "N/A"))[:18].ljust(18)
                    dhcp_s = "DHCP" if iface.get("is_dhcp") else "S"
                    safe_addstr(self.stdscr, row, lx,
                              f" {name} {mac} {ipv4mask} {dhcp_s}", value_attr)
                    row += 1
            else:
                safe_addstr(self.stdscr, row2_y + 2, lx,
                          " No interface detected", warn_attr)

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
            ("R",      "Refresh public IP now"),
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
        pw = min(55, w - 6)
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
            ("VPN Interface:", snap["vpn_interface"] or "(none)"),
            ("VPN PID:",     str(snap["vpn_process_pid"]) if snap["vpn_process_pid"] else "N/A"),
            ("Config:",      snap["vpn_config_file"] or "N/A"),
            ("Hostname:",    self.hostname),
            ("Config File:", cfg_path or "(defaults)"),
        ]
        ph = len(lines) + 4
        py, px = self._draw_popup_box(h, w, ph, pw, "Program Info")
        label_attr = get_attr(self.cfg, "text_label", bold=True)
        value_attr = get_attr(self.cfg, "popup_bg")

        for i, (label, value) in enumerate(lines):
            safe_addstr(self.stdscr, py + 2 + i, px + 3, f"  {label:>16s} ", label_attr)
            safe_addstr(self.stdscr, py + 2 + i, px + 22, value, value_attr)

    # --- Input handling ---

    def handle_key(self, key: int) -> bool:
        """Handle keypress. Returns False if should quit."""
        k = self.cfg.keys
        ch = chr(key) if 0 < key < 256 else ""
        ch_lower = ch.lower()

        if ch_lower == k.quit and not self.show_help and not self.show_info:
            return False

        if key == 27:  # ESC
            self.show_help = False
            self.show_info = False
            self.show_warning = False
            return True

        if ch_lower == k.help or key == curses.KEY_F1:
            self.show_help = not self.show_help
            if self.show_help:
                self.show_info = False
            return True

        if ch_lower == k.info:
            self.show_info = not self.show_info
            if self.show_info:
                self.show_help = False
            return True

        if ch_lower == k.toggle_pause:
            with self.state.lock:
                self.state.paused = not self.state.paused
            return True

        if ch_lower == k.toggle_ping:
            self.show_ping = not self.show_ping
            return True

        if ch_lower == k.refresh_ip:
            with self.state.lock:
                self.state.public_ip = "refreshing..."
                self.state.last_ip_check = 0
                self.state.refresh_token += 1
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
