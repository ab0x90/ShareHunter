#!/usr/bin/env python3
"""
ShareHunter — Python re-implementation of Snaffler with a real-time web GUI.

Usage:
  # Default: scan + web GUI (results stream at localhost:5005)
  python sharehunter.py -t 192.168.1.0/24 -u admin -p pass -d CORP

  # Enumerate all computers from a DC, then scan all of them
  python sharehunter.py --target-domain dc01.corp.local -u admin -p pass -d CORP

  # Pass-the-hash
  python sharehunter.py -t 10.0.0.1 -u admin --nthash <NT> -d CORP

  # CLI-only (no web GUI)
  python sharehunter.py -t 10.0.0.1 -u admin -p pass -d CORP --nogui

  # Custom log file name
  python sharehunter.py -t 10.0.0.1 -u admin -p pass -d CORP -o /tmp/myscan.log
"""

import argparse
import os
import sys
import threading
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

_LOGS_DIR = os.path.join(os.path.dirname(__file__), 'logs')


def banner():
    print(r"""
  _____ _                     _   _             _
 / ____| |                   | | | |           | |
| (___ | |__   __ _ _ __ ___ | |_| |_   _ _ __ | |_ ___ _ __
 \___ \| '_ \ / _` | '__/ _ \| __| | | | | '_ \| __/ _ \ '__|
 ____) | | | | (_| | | |  __/| |_| | |_| | | | | ||  __/ |
|_____/|_| |_|\__,_|_|  \___| \__|_|\__,_|_| |_|\__\___|_|

        /^\
       ( o )        SMB share triage & credential hunter
      /|( )|\
     / |/ \| \      Scan  →  Triage  →  Loot
    /  |   |  \
   /   |   |   \     \\TARGET\SHARE  [Black] credentials.kdbx
  /___________ _\    \\TARGET\SHARE  [Red]   unattend.xml
  |  _______  |      \\TARGET\SHARE  [Yellow] web.config
  | |       | |
  | |  SMB  | |
  | |_______| |
  |___________|
""")


def _open_log(output_path: str):
    """Open (or create) the log file, return file handle."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    return open(output_path, 'a', encoding='utf-8', buffering=1)


def _default_log_path() -> str:
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    return os.path.join(_LOGS_DIR, f'sharehunter_{ts}.log')


def cli_scan(args, log_path: str):
    from sharehunter.domain_enum import get_domain_computers
    from sharehunter import session as sess

    log_fh = _open_log(log_path)

    colors = {0: '\033[95m', 1: '\033[91m', 2: '\033[93m', 3: '\033[92m'}
    reset  = '\033[0m'
    active_session = [None]

    def result_cb(r):
        line = r.to_snaffler_line()
        c = colors.get(r.rating, '')
        print(f"{c}{line}{reset}")
        log_fh.write(line + '\n')
        if active_session[0] is not None:
            sess.add_result(active_session[0], r.to_dict())

    def log_cb(msg, level='info'):
        # Write all messages to log file (no ANSI codes)
        log_fh.write(msg + '\n')
        if level == 'error':
            print(f"\033[91m{msg}\033[0m", file=sys.stderr)
        elif args.verbose or level != 'result':
            print(f"\033[90m{msg}\033[0m")

    hosts = None
    if args.target_domain:
        print(f"\033[90m[*] Enumerating computers from DC: {args.target_domain}\033[0m")
        hosts = get_domain_computers(
            dc=args.target_domain, username=args.username,
            password=args.password or '', domain=args.domain or '',
            nthash=args.nthash or '', log_callback=log_cb,
        )
        if not hosts:
            print("\033[91m[!] No hosts returned from domain enumeration — aborting.\033[0m",
                  file=sys.stderr)
            log_fh.close()
            sys.exit(1)
        print(f"\033[90m[*] Scanning {len(hosts)} host(s)\033[0m")

    loot_dir = os.path.join(
        os.path.dirname(__file__), 'loot',
        datetime.now().strftime('%Y%m%d_%H%M%S')
    )
    os.makedirs(loot_dir, exist_ok=True)

    creds = {
        'username': args.username,
        'password': args.password or '',
        'domain':   args.domain or '',
        'nthash':   args.nthash or '',
    }
    params = {
        'target':        args.target or '',
        'target_domain': args.target_domain or '',
        'host_threads':  args.host_threads,
        'share_threads': args.share_threads,
        'depth':         args.depth,
    }
    s = sess.new_scan(creds, params, loot_dir, hosts or [args.target or ''])
    active_session[0] = s

    from sharehunter.scanner import ShareHunter
    sn = ShareHunter(
        target=args.target or '', hosts=hosts,
        username=args.username, password=args.password or '',
        domain=args.domain or '', nthash=args.nthash or '',
        host_threads=args.host_threads, share_threads=args.share_threads,
        max_depth=args.depth,
        result_callback=result_cb, log_callback=log_cb,
        session=s,
    )
    try:
        sn.run()
    finally:
        sess.mark_ended(s)
        log_fh.close()


def main():
    banner()
    parser = argparse.ArgumentParser(
        description='ShareHunter — SMB share triage tool with web GUI',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        '-t', '--target',
        help='Target: single IP, CIDR range, hostname, or path to a file of targets',
    )
    target_group.add_argument(
        '--target-domain',
        metavar='DC',
        help='DC hostname/IP — enumerate all computer objects via LDAP and scan them all',
    )

    parser.add_argument('-u', '--username',      default='', help='Username')
    parser.add_argument('-p', '--password',      default='', help='Password')
    parser.add_argument('-d', '--domain',        default='', help='Domain (NETBIOS or FQDN)')
    parser.add_argument('--nthash',              default='', help='NT hash for pass-the-hash')
    parser.add_argument('--host-threads',        type=int, default=5,
                        help='Concurrent hosts to scan at once')
    parser.add_argument('--share-threads',       type=int, default=10,
                        help='Concurrent shares per host')
    parser.add_argument('--depth',               type=int, default=10, help='Max directory depth')
    parser.add_argument('--nogui',               action='store_true',
                        help='Disable web GUI — terminal output only')
    parser.add_argument('--port',                type=int, default=5005, help='Web GUI port')
    parser.add_argument('-v', '--verbose',        action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output',         default='',
                        help='Log file path (default: logs/sharehunter_YYYYMMDD_HHMMSS.log)')
    args = parser.parse_args()

    gui_only = not (args.target or args.target_domain)

    if gui_only and args.nogui:
        parser.error('--nogui requires --target or --target-domain and --username')

    if gui_only and not args.username:
        # No args — just open the GUI so the user can fill in targets from the browser
        from sharehunter.app import start_gui
        print(f"[*] Web GUI:  http://127.0.0.1:{args.port}")
        print(f"[*] No target specified — enter scan details in the browser")
        start_gui(port=args.port)
        return

    if not args.username:
        parser.error('--username is required when --target or --target-domain is specified')

    log_path = args.output.strip() if args.output.strip() else _default_log_path()
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    print(f"[*] Log file: {log_path}")

    if args.nogui:
        cli_scan(args, log_path)
        return

    # GUI + scan mode — scan runs in a background thread, GUI in the main thread
    from sharehunter.app import start_gui, _scan_state, _result_callback, _log_callback, _LOOT_BASE

    print(f"[*] Web GUI:  http://127.0.0.1:{args.port}")

    log_fh = _open_log(log_path)

    # Wrap the app callbacks to also write to the log file
    def result_cb_with_log(result):
        log_fh.write(result.to_snaffler_line() + '\n')
        _result_callback(result)

    def log_cb_with_log(msg, level='info'):
        log_fh.write(msg + '\n')
        _log_callback(msg, level)

    def auto_scan():
        import time
        from sharehunter import session as sess
        time.sleep(1.5)  # let Flask/eventlet start

        scan_ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
        loot_dir = os.path.join(_LOOT_BASE, scan_ts)
        os.makedirs(loot_dir, exist_ok=True)
        creds = {
            'username': args.username,
            'password': args.password or '',
            'domain':   args.domain or '',
            'nthash':   args.nthash or '',
        }
        with _scan_state['lock']:
            _scan_state['creds']    = creds
            _scan_state['loot_dir'] = loot_dir

        hosts = None
        if args.target_domain:
            from sharehunter.domain_enum import get_domain_computers
            log_cb_with_log(f"[*] Enumerating computers from DC: {args.target_domain}", 'info')
            hosts = get_domain_computers(
                dc=args.target_domain, username=args.username,
                password=args.password or '', domain=args.domain or '',
                nthash=args.nthash or '', log_callback=log_cb_with_log,
            )
            if not hosts:
                log_cb_with_log('[!] No hosts returned from domain enumeration', 'error')
                _scan_state['running'] = False
                log_fh.close()
                return
            log_cb_with_log(f"[*] Scanning {len(hosts)} host(s) from domain enumeration", 'info')
        else:
            log_cb_with_log(f"[*] Starting scan against {args.target}", 'info')

        params = {
            'target':        args.target or '',
            'target_domain': args.target_domain or '',
            'host_threads':  args.host_threads,
            'share_threads': args.share_threads,
            'depth':         args.depth,
        }
        s = sess.new_scan(creds, params, loot_dir, hosts or [args.target or ''])
        with _scan_state['lock']:
            _scan_state['session'] = s

        from sharehunter.scanner import ShareHunter
        sn = ShareHunter(
            target=args.target or '', hosts=hosts,
            username=args.username, password=args.password or '',
            domain=args.domain or '', nthash=args.nthash or '',
            host_threads=args.host_threads, share_threads=args.share_threads,
            max_depth=args.depth,
            result_callback=result_cb_with_log,
            log_callback=log_cb_with_log,
            session=s,
        )
        _scan_state['snaffler'] = sn
        _scan_state['running']  = True
        try:
            sn.run()
        finally:
            _scan_state['running']  = False
            _scan_state['snaffler'] = None
            sess.mark_ended(s)
            log_fh.close()

    t = threading.Thread(target=auto_scan, daemon=True)
    t.start()
    start_gui(port=args.port)


if __name__ == '__main__':
    main()
