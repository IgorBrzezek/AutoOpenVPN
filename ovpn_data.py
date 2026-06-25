#!/usr/bin/env python3
"""Fetch VPNBook credentials and optionally save to file.

Usage:
  python3 ovpn_data.py --get                            # scrape and display
  python3 ovpn_data.py --get -w                         # scrape, display, save to ovpn_data.txt
  python3 ovpn_data.py --get -w custom.txt              # scrape, display, save to custom.txt
  python3 ovpn_data.py -w                               # interactive, save to ovpn_data.txt
  python3 ovpn_data.py --username vpnbook --password PASSWORD  # inline, save
  python3 ovpn_data.py --get -q -w --overwrite          # quiet, overwrite without asking
"""

import argparse
import os
import re
import urllib.request
import sys

CREDENTIALS_FILE = "ovpn_data.txt"
DEFAULT_USERNAME = "vpnbook"


def scrape_credentials(quiet=False):
    url = "https://www.vpnbook.com/pl/freevpn/openvpn"
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        if not quiet:
            print(f"  [!] Network error: {e}", file=sys.stderr)
        return None, None

    codes = re.findall(
        r'<code[^>]*class="[^"]*font-mono[^"]*"[^>]*>(.*?)</code>',
        html,
    )
    pw = None
    for c in codes:
        txt = re.sub(r'<[^>]+>', '', c).strip()
        if txt and txt == DEFAULT_USERNAME:
            continue
        if txt and len(txt) >= 6:
            pw = txt
            break

    if pw:
        return DEFAULT_USERNAME, pw

    return None, None


def write_credentials(username, password, filepath, quiet=False, overwrite=False):
    if os.path.exists(filepath) and not overwrite:
        if not quiet:
            answer = input(f"  [?] {filepath} exists. Overwrite? [y/N] ").strip().lower()
        else:
            answer = "n"
        if answer != "y":
            if not quiet:
                print("  [!] Skipped.")
            return
    with open(filepath, "w") as f:
        f.write(f"{username}\n{password}\n")
    os.chmod(filepath, 0o600)
    if not quiet:
        print(f"  [+] Saved credentials to {filepath}")


def prompt_credentials():
    print()
    print("VPNBook Credentials")
    print("  View at: https://www.vpnbook.com/pl/freevpn/openvpn")
    print()
    username = input(f"  Username [{DEFAULT_USERNAME}]: ").strip()
    if not username:
        username = DEFAULT_USERNAME
    password = input("  Password: ").strip()
    while not password:
        print("  Password cannot be empty!")
        password = input("  Password: ").strip()
    return username, password


def main():
    parser = argparse.ArgumentParser(description="Fetch VPNBook credentials")
    parser.add_argument("--get", action="store_true",
                        help="Scrape credentials from vpnbook.com and display on screen")
    parser.add_argument("-w", nargs="?", const=CREDENTIALS_FILE, default=None,
                        help=f"Save credentials to file (default: {CREDENTIALS_FILE})")
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite output file without asking")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress all terminal output")
    parser.add_argument("--username", default=None, help="VPN username")
    parser.add_argument("--password", default=None, help="VPN password")
    args = parser.parse_args()

    if args.get:
        if not args.quiet:
            print("[*] Fetching credentials from vpnbook.com...")
        username, password = scrape_credentials(quiet=args.quiet)
        if username and password:
            if not args.quiet:
                print(f"  Username: {username}")
                print(f"  Password: {password}")
            if args.w is not None:
                write_credentials(username, password, args.w,
                                  quiet=args.quiet, overwrite=args.overwrite)
            return
        if args.quiet:
            if not args.w:
                sys.exit(0)
            print("  [!] Scraping failed.", file=sys.stderr)
            sys.exit(1)
        print("  [!] Scraping failed. Falling back to manual input.")

    if args.username and args.password:
        username, password = args.username, args.password
    else:
        if args.quiet:
            print("  [!] Cannot prompt in quiet mode; use --username/--password or --get",
                  file=sys.stderr)
            sys.exit(1)
        username, password = prompt_credentials()

    output = args.w if args.w is not None else CREDENTIALS_FILE
    write_credentials(username, password, output,
                      quiet=args.quiet, overwrite=args.overwrite)


if __name__ == "__main__":
    main()
