#!/usr/bin/env python3
"""
ShareHunter Scan — credentialed SMB share triage.

Runs the scan and writes its progress/results to sessions/<scan_id>.session.json
and loot/<scan_id>/ so that `sharehunter_web.py` (a separate process, possibly
on a separate host) can load and display it. This script has no web server
capability of its own.

Usage:
  # Scan a CIDR/host/target-file
  python sharehunter_scan.py -t 192.168.1.0/24 -u admin -p pass -d CORP

  # Enumerate all computers from a DC, then scan all of them
  python sharehunter_scan.py --target-domain dc01.corp.local -u admin -p pass -d CORP

  # Pass-the-hash
  python sharehunter_scan.py -t 10.0.0.1 -u admin --nthash <NT> -d CORP

  # Resume a previous scan's pending (incomplete) hosts
  python sharehunter_scan.py --resume 20260804_120000

  # Unauthenticated (null session) share enumeration against a target file
  # (one IP/hostname/CIDR range per line, # comments allowed)
  python sharehunter_scan.py --unauth -t targets.txt
"""

import argparse
import os
import re
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

from sharehunter import session as sess
from sharehunter.rules import RATING_LABELS, RATING_COLORS

_ROOT       = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR   = os.path.join(_ROOT, 'logs')
_LOOT_BASE  = os.path.join(_ROOT, 'loot')

_CONNECTED_RE = re.compile(r'^\[\+\] Connected to (.+)$')

console = Console()


def banner():
    console.print(r"""
[bold cyan]  _____ _                    _    _             _
 / ____| |                  | |  | |           | |
| (___ | |__   __ _ _ __ ___| |__| |_   _ _ __ | |_ ___ _ __
 \___ \| '_ \ / _` | '__/ _ \  __  | | | | '_ \| __/ _ \ '__|
 ____) | | | | (_| | | |  __/ |  | | |_| | | | | ||  __/ |
|_____/|_| |_|\__,_|_|  \___|_|  |_|\__,_|_| |_|\__\___|_|[/]
[dim]        Scan  →  Search  →  Loot  (scan-only, credentialed)[/]
""")


def _default_log_path() -> str:
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    return os.path.join(_LOGS_DIR, f'sharehunter_{ts}.log')


def _open_log(output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    return open(output_path, 'a', encoding='utf-8', buffering=1)


class Dashboard:
    """Terminal progress state, updated from the scanner's callbacks and
    rendered on a timer via rich.Live. All scanner-facing hooks
    (result_callback/log_callback) are the same extension points the old
    web GUI used — no scanner.py changes needed."""

    def __init__(self, session: dict, hosts_total: list, header_lines: list,
                 log_fh):
        self.session      = session
        self.hosts_total  = hosts_total
        self.header_lines = header_lines
        self.log_fh       = log_fh
        self.start_time   = time.time()

        self.lock       = threading.Lock()
        self.inflight    = {}   # host -> started_at
        self.counts      = {r: 0 for r in RATING_LABELS}
        self.recent      = deque(maxlen=8)
        self.recent_logs = deque(maxlen=6)
        self.stopped     = False

    # ── scanner hooks ────────────────────────────────────────────────────
    def result_callback(self, result):
        self.log_fh.write(result.to_snaffler_line() + '\n')
        sess.add_result(self.session, result.to_dict())
        with self.lock:
            self.counts[result.rating] += 1
            self.recent.appendleft(
                (result.rating_label, result.rule_name,
                 f"\\\\{result.host}\\{result.share}\\{result.path}")
            )

    def log_callback(self, msg: str, level: str = 'info'):
        if level != 'result':
            self.log_fh.write(msg + '\n')
        m = _CONNECTED_RE.match(msg)
        if m:
            with self.lock:
                self.inflight[m.group(1)] = time.time()
        if level == 'error':
            with self.lock:
                self.recent_logs.appendleft(msg)

    # ── rendering ────────────────────────────────────────────────────────
    def _hosts_done(self) -> int:
        return len(self.session.get('hosts_completed', []))

    def render(self):
        done  = self._hosts_done()
        total = max(len(self.hosts_total), 1)
        elapsed = time.time() - self.start_time

        with self.lock:
            completed = set(self.session.get('hosts_completed', []))
            for h in list(self.inflight):
                if h in completed:
                    self.inflight.pop(h, None)
            inflight = list(self.inflight)[:8]
            counts   = dict(self.counts)
            recent   = list(self.recent)
            errors   = list(self.recent_logs)

        # ── header ──
        header = Text()
        for i, line in enumerate(self.header_lines):
            if i:
                header.append('\n')
            header.append(line)

        # ── progress bar + ETA ──
        rate = done / elapsed if elapsed > 0 else 0
        remaining = total - done
        eta = timedelta(seconds=int(remaining / rate)) if rate > 0 else None

        progress = Progress(
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("{task.completed}/{task.total} hosts ({task.percentage:>3.0f}%)"),
            TimeElapsedColumn(),
            TextColumn("ETA: " + (str(eta) if eta else "—")),
        )
        progress.add_task("Scanning", total=total, completed=done)

        # ── findings-by-rating table ──
        findings_tbl = Table.grid(padding=(0, 2))
        for r in sorted(RATING_LABELS):
            label = RATING_LABELS[r]
            color = RATING_COLORS[r]
            findings_tbl.add_row(
                Text(f"● {label}", style=color),
                Text(str(counts.get(r, 0)), style=f"bold {color}"),
            )

        # ── in-flight hosts ──
        inflight_txt = Text('\n'.join(inflight) if inflight else '(none)', style="cyan")

        top = Table.grid(expand=True)
        top.add_column(ratio=2)
        top.add_column(ratio=1)
        top.add_row(
            Panel(findings_tbl, title="Findings", border_style="magenta"),
            Panel(inflight_txt, title=f"In-flight hosts ({len(inflight)})", border_style="cyan"),
        )

        # ── recent findings tail ──
        recent_tbl = Table(show_header=True, header_style="bold", expand=True, box=None)
        recent_tbl.add_column("Rating", width=8)
        recent_tbl.add_column("Rule")
        recent_tbl.add_column("Path", overflow="fold")
        for label, rule, path in recent:
            color = RATING_COLORS[[k for k, v in RATING_LABELS.items() if v == label][0]]
            recent_tbl.add_row(Text(label, style=color), rule, path)
        if not recent:
            recent_tbl.add_row("", "", "(no findings yet)")

        pieces = [
            Panel(header, title="ShareHunter Scan", border_style="blue"),
            progress,
            top,
            Panel(recent_tbl, title="Recent findings", border_style="green"),
        ]
        if errors:
            err_txt = Text('\n'.join(errors), style="red")
            pieces.append(Panel(err_txt, title="Recent errors", border_style="red"))

        return Group(*pieces)

    def print_summary(self):
        elapsed = timedelta(seconds=int(time.time() - self.start_time))
        done  = self._hosts_done()
        total = len(self.hosts_total)
        tbl = Table(title="Scan summary")
        tbl.add_column("Metric")
        tbl.add_column("Value")
        tbl.add_row("Hosts scanned", f"{done}/{total}")
        tbl.add_row("Elapsed", str(elapsed))
        for r in sorted(RATING_LABELS):
            label = RATING_LABELS[r]
            tbl.add_row(f"{label} findings", str(self.counts.get(r, 0)))
        tbl.add_row("Session ID", self.session.get('scan_id', ''))
        tbl.add_row("Loot dir", self.session.get('loot_dir', ''))
        console.print(tbl)


def _heartbeat_loop(session: dict, stop_event: threading.Event):
    while not stop_event.is_set():
        sess.heartbeat(session)
        stop_event.wait(5)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='ShareHunter Scan — credentialed SMB share triage (scan-only, no web GUI)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        '-t', '--target',
        help='Target: single IP, CIDR range, hostname, or path to a file of '
             'targets (one IP/hostname/CIDR range per line, # comments '
             'allowed, CIDR lines expanded to individual hosts)',
    )
    target_group.add_argument(
        '--target-domain', metavar='DC',
        help='DC hostname/IP — enumerate all computer objects via LDAP and scan them all',
    )

    parser.add_argument('-u', '--username', default='', help='Username')
    parser.add_argument('-p', '--password', default='', help='Password')
    parser.add_argument('-d', '--domain',   default='', help='Domain (NETBIOS or FQDN)')
    parser.add_argument('--nthash',         default='', help='NT hash for pass-the-hash')

    auth_group = parser.add_argument_group('Authentication / transport')
    auth_group.add_argument('--ldaps', action='store_true',
                             help='Force LDAPS (port 636, TLS) for domain enumeration.')
    auth_group.add_argument('--kerberos', '-k', action='store_true',
                             help='Use Kerberos for LDAP enumeration and SMB connections.')
    auth_group.add_argument('--aes-key', default='', metavar='HEX',
                             help='AES session key for Kerberos (hex). Implies --kerberos.')
    auth_group.add_argument('--dc-ip', default='', metavar='IP',
                             help='IP address of the Domain Controller.')
    auth_group.add_argument('--unauth', action='store_true',
                             help='Anonymous/null-session SMB enumeration — no username/password '
                                  'required. Falls back to probing common share names when '
                                  'NetShareEnum is blocked. Not compatible with --target-domain.')

    parser.add_argument('--host-threads',  type=int, default=5,  help='Concurrent hosts to scan')
    parser.add_argument('--share-threads', type=int, default=10, help='Concurrent shares per host')
    parser.add_argument('--depth',         type=int, default=10, help='Max directory depth')

    parser.add_argument('--resume', metavar='SCAN_ID',
                         help='Resume a previous session\'s pending (incomplete) hosts')
    parser.add_argument('-o', '--output', default='',
                         help='Log file path (default: logs/sharehunter_YYYYMMDD_HHMMSS.log)')
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.aes_key:
        args.kerberos = True

    banner()

    from sharehunter.scanner import ShareHunter
    from sharehunter.domain_enum import get_domain_computers

    if args.resume:
        session = sess.load(args.resume)
        if not session.get('scan_id'):
            parser.error(f'No session found for scan_id {args.resume}')
        pending = session.get('hosts_pending', [])
        if not pending:
            console.print(f"[yellow]Session {args.resume} has no pending hosts — nothing to resume.[/]")
            return
        creds  = session.get('creds', {})
        params = session.get('scan_params', {})
        loot_dir = session.get('loot_dir') or os.path.join(_LOOT_BASE, session['scan_id'])
        os.makedirs(loot_dir, exist_ok=True)
        hosts_total = session.get('hosts_total', pending)
        hosts = pending
        console.print(f"[*] Resuming session {args.resume} — {len(pending)} host(s) pending\n")
    else:
        if not (args.target or args.target_domain):
            parser.error('one of -t/--target or --target-domain is required')

        if args.unauth:
            if args.target_domain:
                parser.error('--unauth cannot be used with --target-domain '
                             '(LDAP computer enumeration requires authentication)')
            if args.username or args.password or args.nthash or args.kerberos or args.aes_key:
                console.print("[yellow]--unauth set — ignoring supplied credentials, "
                              "using a null SMB session[/]")
        else:
            if not args.username:
                parser.error('-u/--username is required (or use --unauth for anonymous enumeration)')
            if not (args.password or args.nthash or args.kerberos or args.aes_key):
                parser.error('one of -p/--password, --nthash, --kerberos, or --aes-key '
                             'is required (or use --unauth)')

        creds = {
            'username':     '' if args.unauth else args.username,
            'password':     '' if args.unauth else args.password,
            'domain':       '' if args.unauth else args.domain,
            'nthash':       '' if args.unauth else args.nthash,
            'use_kerberos': False if args.unauth else args.kerberos,
            'aes_key':      '' if args.unauth else args.aes_key,
            'dc_ip':        args.dc_ip,
            'unauth':       args.unauth,
        }

        if args.target_domain:
            console.print(f"[*] Enumerating computers from DC: {args.target_domain}")
            hosts = get_domain_computers(
                dc=args.target_domain, username=args.username,
                password=args.password, domain=args.domain,
                nthash=args.nthash, use_ldaps=args.ldaps,
                use_kerberos=args.kerberos, aes_key=args.aes_key,
                log_callback=lambda m, lvl='info': console.print(f"[dim]{m}[/]"),
            )
            if not hosts:
                console.print("[red]No hosts returned from domain enumeration.[/]")
                sys.exit(1)
        else:
            # Expand CIDR/file/single-host up front so progress/ETA reflect the
            # real host count, reusing ShareHunter's own resolver.
            hosts = ShareHunter(username='', password='', target=args.target)._resolve_targets()
            if not hosts:
                console.print("[red]No hosts to scan.[/]")
                sys.exit(1)

        params = {
            'target':        args.target or '',
            'target_domain': args.target_domain or '',
            'unauth':        args.unauth,
            'host_threads':  args.host_threads,
            'share_threads': args.share_threads,
            'depth':         args.depth,
            'use_ldaps':     args.ldaps,
        }

        scan_ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
        loot_dir = os.path.join(_LOOT_BASE, scan_ts)
        os.makedirs(loot_dir, exist_ok=True)
        session = sess.new_scan(creds, params, loot_dir, hosts)
        hosts_total = hosts

    log_path = args.output.strip() if args.output.strip() else _default_log_path()
    log_fh   = _open_log(log_path)
    session['log_path'] = log_path
    sess.save(session)
    console.print(f"[*] Log file: {log_path}")
    console.print(f"[*] Session:  {session['scan_id']}")
    console.print(f"[*] Loot dir: {session.get('loot_dir')}\n")

    user_line = "(unauthenticated / null session)" if creds.get('unauth') \
        else f"{creds.get('username', '')}@{creds.get('domain', '')}"
    header_lines = [
        f"Target:  {params.get('target') or params.get('target_domain', '')}",
        f"User:    {user_line}",
        f"Threads: host={params.get('host_threads')} share={params.get('share_threads')} depth={params.get('depth')}",
        f"Session: {session['scan_id']}",
    ]

    dashboard = Dashboard(session, hosts_total, header_lines, log_fh)

    heartbeat_stop = threading.Event()
    hb_thread = threading.Thread(target=_heartbeat_loop, args=(session, heartbeat_stop), daemon=True)
    hb_thread.start()

    sn = ShareHunter(
        target='', hosts=hosts,
        username=creds.get('username', ''), password=creds.get('password', ''),
        domain=creds.get('domain', ''), nthash=creds.get('nthash', ''),
        use_kerberos=creds.get('use_kerberos', False), aes_key=creds.get('aes_key', ''),
        dc_ip=creds.get('dc_ip', ''), unauth=creds.get('unauth', False),
        host_threads=params.get('host_threads', 5), share_threads=params.get('share_threads', 10),
        max_depth=params.get('depth', 10),
        result_callback=dashboard.result_callback,
        log_callback=dashboard.log_callback,
        session=session,
    )

    scan_thread = threading.Thread(target=sn.run, daemon=True)
    scan_thread.start()

    interrupted = False
    try:
        with Live(dashboard.render(), console=console, refresh_per_second=4, screen=False) as live:
            while scan_thread.is_alive():
                live.update(dashboard.render())
                time.sleep(0.25)
            live.update(dashboard.render())
    except KeyboardInterrupt:
        interrupted = True
        console.print("\n[yellow]Interrupted — stopping gracefully (in-flight hosts will finish)...[/]")
        sn.stop()
        with Live(dashboard.render(), console=console, refresh_per_second=4, screen=False) as live:
            while scan_thread.is_alive():
                live.update(dashboard.render())
                time.sleep(0.25)

    scan_thread.join()
    heartbeat_stop.set()
    sess.mark_ended(session, stopped=interrupted or sn._stop_event.is_set())
    log_fh.close()

    console.print()
    dashboard.print_summary()


if __name__ == '__main__':
    main()
