#!/usr/bin/env python3
"""OVPNMonitor — OpenVPN Connection Monitor TUI.

A retro DOS/iptraf-style terminal interface for monitoring OpenVPN
connections. Works alongside autoovpn.py or independently.

Usage:
  python ovpnmonitor.py                    # run with default config
  python ovpnmonitor.py -c myconfig.cfg    # use custom config file
  python ovpnmonitor.py --noping           # disable ping monitoring
  python ovpnmonitor.py --help             # show usage

Requirements:
  pip install windows-curses psutil
"""

import argparse
import curses
import sys

from ovpnmonitor_cfg import Config, load_config, init_colors
from ovpnmonitor_data import MonitorState, start_collectors, stop_collectors
from ovpnmonitor_ui import UIManager


def main_loop(stdscr, cfg: Config):
    """Main curses event loop."""
    # Curses setup
    curses.curs_set(0)          # hide cursor
    curses.start_color()
    curses.use_default_colors()
    stdscr.nodelay(False)
    stdscr.timeout(cfg.refresh_interval_ms)

    # Initialize colors
    init_colors(cfg)

    # Shared state and collectors
    state = MonitorState()
    collectors = start_collectors(state, cfg)

    try:
        ui = UIManager(stdscr, cfg, state)

        while True:
            try:
                ui.draw()
            except curses.error:
                pass

            key = stdscr.getch()
            if key == curses.KEY_RESIZE:
                stdscr.clear()
                continue
            if key != -1:
                if not ui.handle_key(key):
                    break
    finally:
        stop_collectors(collectors)


def main():
    parser = argparse.ArgumentParser(
        description="OVPNMonitor — OpenVPN Connection Monitor TUI")
    parser.add_argument("-c", "--config", metavar="FILE",
                        help="Path to configuration file (default: ovpnmonitor.cfg)")
    parser.add_argument("-v", "--version", action="store_true",
                        help="Show version and exit")
    parser.add_argument("--pathping", metavar="IP",
                        help="Target IP for path ping (traceroute)")
    parser.add_argument("--tun", metavar="NAME",
                        help="TUN/TAP interface name (e.g. tun0)")
    parser.add_argument("--int", metavar="NAME", dest="local_int",
                        help="Local interface name or 'all' for all (e.g. enp0s3)")
    parser.add_argument("--noping", action="store_true",
                        help="Disable ping monitoring")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.pathping:
        cfg.pathping_target = args.pathping
    if args.tun:
        cfg.vpn_interface = args.tun
    if args.local_int:
        cfg.local_interface = "" if args.local_int == "all" else args.local_int
    if args.noping:
        cfg.network.ping_enabled = False

    if args.version:
        print(f"{cfg.app_name} v{cfg.version} by {cfg.author}")
        return

    try:
        curses.wrapper(lambda stdscr: main_loop(stdscr, cfg))
    except KeyboardInterrupt:
        pass

    print("\033[2J\033[H", end="")

if __name__ == "__main__":
    main()
