#!/usr/bin/env python3
"""
ShareHunter Web — read-only viewer for scans run by sharehunter_scan.py.

This process never scans anything itself. It works purely off the on-disk
loot/sessions/logs folders, lets you pick which scan's data to view (from the
CLI or the in-browser picker), keeps refreshing a still-running session about
once a minute, and separately offers the ManSpider loot-watch mode.

Usage:
  # Start with nothing loaded — pick a session from the browser
  python sharehunter_web.py

  # Load the most recently started scan on startup
  python sharehunter_web.py --latest

  # Load a specific scan on startup
  python sharehunter_web.py --session 20260804_120000
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def banner():
    print(r"""
  _____ _                    _    _             _
 / ____| |                  | |  | |           | |
| (___ | |__   __ _ _ __ ___| |__| |_   _ _ __ | |_ ___ _ __
 \___ \| '_ \ / _` | '__/ _ \  __  | | | | '_ \| __/ _ \ '__|
 ____) | | | | (_| | | |  __/ |  | | |_| | | | | ||  __/ |
|_____/|_| |_|\__,_|_|  \___|_|  |_|\__,_|_| |_|\__\___|_|

        Web viewer — read-only, no scanning capability
""")


def main():
    parser = argparse.ArgumentParser(
        description='ShareHunter Web — read-only viewer for sharehunter_scan.py sessions',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--host', default='127.0.0.1', help='Bind address')
    parser.add_argument('--port', type=int, default=5005, help='Web GUI port')

    session_group = parser.add_mutually_exclusive_group()
    session_group.add_argument('--session', metavar='SCAN_ID',
                                help='Load a specific session on startup')
    session_group.add_argument('--latest', action='store_true',
                                help='Load the most recently started session on startup')

    args = parser.parse_args()

    banner()

    from sharehunter.app import start_gui, load_initial_session

    if args.session or args.latest:
        s = load_initial_session(scan_id=args.session, latest=args.latest)
        if s is None:
            target = args.session or '(latest)'
            print(f"[!] Could not load session {target} — starting with nothing loaded.")
        else:
            print(f"[*] Loaded session {s['scan_id']}  "
                  f"({len(s.get('results', []))} finding(s) so far)")
    else:
        print("[*] No session specified — pick one from the browser.")

    print(f"[*] Web GUI:  http://{args.host}:{args.port}")
    start_gui(host=args.host, port=args.port)


if __name__ == '__main__':
    main()
