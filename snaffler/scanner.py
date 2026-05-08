"""
SMB share enumeration and file triage engine.
Uses impacket for SMB/LDAP and applies Snaffler-equivalent rules.
"""

import os
import re
import sys
import time
import queue
import threading
import traceback
from dataclasses import dataclass, field
from typing import Optional, Callable, List
from datetime import datetime

from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_READ_DATA, FILE_LIST_DIRECTORY
from impacket.nmb import NetBIOSError
from impacket.smbconnection import SessionError

from snaffler.rules import (
    FILENAME_RULES, CONTENT_RULES, RATING_LABELS, ALL_RULES, SnaffleRule,
    SKIP_EXTENSIONS, should_skip_path,
)
from snaffler import session as sess

# Max file size to read content from (bytes)
MAX_CONTENT_SIZE = 512 * 1024   # 512 KB

INTERESTING_SHARE_NAMES = re.compile(
    r'(?i)(backup|files?|data|share|users?|home|profiles?|'
    r'deploy|install|software|scripts?|config|admin|it|'
    r'finance|hr|legal|dev|dev(elop(ment)?)?|source|code|'
    r'repos?|archive|transfer|drop|upload|temp|staging|prod(uction)?)',
    re.IGNORECASE
)

SKIP_SHARES = {'IPC$', 'print$', 'prnproc$'}


@dataclass
class SnaffleResult:
    host: str
    share: str
    path: str
    filename: str
    size: int
    modified: str
    rating: int
    rating_label: str
    rule_name: str
    rule_desc: str
    match_type: str
    matched_line: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_snaffler_line(self) -> str:
        """Format output like real Snaffler: [Black|Red|Yellow|Green](Rule){\\\\host\\share\\path}[matchedtext]"""
        bracket = f"[{self.rating_label}]"
        rule    = f"({self.rule_name})"
        unc     = f"{{\\\\{self.host}\\{self.share}\\{self.path}}}"
        match   = f"[{self.matched_line[:200]}]" if self.matched_line else ""
        size    = f"<{self.size}B>"
        return f"{bracket}{rule}{size}{unc}{match}"

    def to_dict(self) -> dict:
        return {
            "host":         self.host,
            "share":        self.share,
            "path":         self.path,
            "filename":     self.filename,
            "size":         self.size,
            "modified":     self.modified,
            "rating":       self.rating,
            "rating_label": self.rating_label,
            "rule_name":    self.rule_name,
            "rule_desc":    self.rule_desc,
            "match_type":   self.match_type,
            "matched_line": self.matched_line,
            "timestamp":    self.timestamp,
            "unc_path":     f"\\\\{self.host}\\{self.share}\\{self.path}",
        }


def _match_filename(filename: str, path: str) -> Optional[SnaffleRule]:
    best = None
    for rule in FILENAME_RULES:
        if rule.match_type == 'extension':
            target = filename
        elif rule.match_type == 'filename':
            target = filename
        elif rule.match_type == 'path':
            target = path
        else:
            continue
        if rule.regex.search(target):
            if best is None or rule.rating < best.rating:
                best = rule
    return best


def _match_content(data: bytes) -> tuple[Optional[SnaffleRule], str]:
    try:
        text = data.decode('utf-8', errors='replace')
    except Exception:
        return None, ""

    best_rule = None
    best_line = ""
    for rule in CONTENT_RULES:
        m = rule.regex.search(text)
        if m:
            if best_rule is None or rule.rating < best_rule.rating:
                best_rule = rule
                # grab surrounding line context
                start = text.rfind('\n', 0, m.start()) + 1
                end   = text.find('\n', m.end())
                if end == -1:
                    end = len(text)
                best_line = text[start:end].strip()[:300]
    return best_rule, best_line


class ShareHunter:
    def __init__(self, username: str, password: str,
                 target: str = '', hosts: Optional[List[str]] = None,
                 domain: str = '', nthash: str = '',
                 host_threads: int = 5, share_threads: int = 10,
                 max_depth: int = 10,
                 result_callback: Optional[Callable] = None,
                 log_callback: Optional[Callable] = None,
                 session: Optional[dict] = None):
        self.target       = target
        self.hosts        = hosts   # pre-resolved list (from --target-domain)
        self.username     = username
        self.password     = password
        self.domain       = domain
        self.nthash       = nthash
        self.host_threads  = host_threads
        self.share_threads = share_threads
        self.max_depth     = max_depth
        self.result_callback = result_callback or (lambda r: None)
        self.log_callback    = log_callback    or (lambda m, lvl='info': None)
        self.session         = session

        self._work_queue: queue.Queue = queue.Queue(maxsize=5000)
        self._stop_event  = threading.Event()
        self._results: List[SnaffleResult] = []
        self._results_lock = threading.Lock()
        self._active_workers = 0
        self._worker_lock = threading.Lock()

    def log(self, msg: str, level: str = 'info'):
        self.log_callback(msg, level)

    # ── Connection helpers ─────────────────────────────────────────────────

    def _connect(self, host: str) -> Optional[SMBConnection]:
        try:
            conn = SMBConnection(host, host, sess_port=445, timeout=10)
            if self.nthash:
                lm = 'aad3b435b51404eeaad3b435b51404ee'
                conn.login(self.username, '', self.domain,
                           lmhash=lm, nthash=self.nthash)
            else:
                conn.login(self.username, self.password, self.domain)
            return conn
        except Exception as e:
            self.log(f"[!] Failed to connect to {host}: {e}", 'error')
            return None

    # ── Share enumeration ──────────────────────────────────────────────────

    def _list_shares(self, conn: SMBConnection, host: str) -> list:
        shares = []
        try:
            for share in conn.listShares():
                name = share['shi1_netname'][:-1]  # strip null terminator
                if name in SKIP_SHARES:
                    continue
                shares.append(name)
        except Exception as e:
            self.log(f"[!] listShares failed on {host}: {e}", 'error')
        return shares

    # ── File walker ────────────────────────────────────────────────────────

    def _walk_share(self, conn: SMBConnection, host: str, share: str):
        self.log(f"[*] Walking \\\\{host}\\{share}", 'info')
        try:
            self._walk_path(conn, host, share, '', 0)
        except Exception as e:
            self.log(f"[!] Error walking \\\\{host}\\{share}: {e}", 'error')

    def _walk_path(self, conn: SMBConnection, host: str, share: str,
                   path: str, depth: int):
        if depth > self.max_depth or self._stop_event.is_set():
            return
        try:
            listing = conn.listPath(share, path + '\\*')
        except SessionError as e:
            return
        except Exception as e:
            return

        for f in listing:
            if self._stop_event.is_set():
                return
            name = f.get_longname()
            if name in ('.', '..'):
                continue

            full_path = (path + '\\' + name).lstrip('\\')
            if should_skip_path(full_path):
                continue
            if f.is_directory():
                self._walk_path(conn, host, share, '\\' + full_path, depth + 1)
            else:
                self._triage_file(conn, host, share, full_path,
                                  f.get_filesize(), f.get_mtime_epoch())

    # ── Triage ────────────────────────────────────────────────────────────

    def _triage_file(self, conn: SMBConnection, host: str, share: str,
                     path: str, size: int, mtime: float):
        filename  = os.path.basename(path)
        ext       = os.path.splitext(filename)[1].lower()

        # Filename/extension match first
        fn_rule = _match_filename(filename, path)

        # Content match + preview for any readable, non-binary file
        content_rule = None
        matched_line = ""
        raw_text = ""
        if ext not in SKIP_EXTENSIONS and size > 0 and size < MAX_CONTENT_SIZE:
            try:
                buf = []
                conn.getFile(share, path, lambda d: buf.append(d))
                data = b''.join(buf)
                content_rule, matched_line = _match_content(data)
                if not matched_line:
                    # No content rule hit — grab first meaningful line as preview
                    raw_text = data.decode('utf-8', errors='replace')
            except Exception:
                pass

        # Pick the best (lowest rating = highest severity) rule
        winner_rule = None
        if fn_rule and content_rule:
            winner_rule = fn_rule if fn_rule.rating <= content_rule.rating else content_rule
            if content_rule.rating >= fn_rule.rating:
                matched_line = ""  # filename rule won; fall through to preview below
        elif fn_rule:
            winner_rule = fn_rule
        elif content_rule:
            winner_rule = content_rule

        # If filename rule won with no content match, show a file preview snippet
        if winner_rule is fn_rule and not matched_line and raw_text:
            for line in raw_text.splitlines():
                stripped = line.strip()
                if stripped:
                    matched_line = stripped[:300]
                    break

        if winner_rule is None:
            return

        modified = datetime.utcfromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S') if mtime else ''

        result = SnaffleResult(
            host         = host,
            share        = share,
            path         = path,
            filename     = filename,
            size         = size,
            modified     = modified,
            rating       = winner_rule.rating,
            rating_label = RATING_LABELS[winner_rule.rating],
            rule_name    = winner_rule.name,
            rule_desc    = winner_rule.description,
            match_type   = winner_rule.match_type,
            matched_line = matched_line,
        )

        with self._results_lock:
            self._results.append(result)

        line = result.to_snaffler_line()
        self.log(line, 'result')
        self.result_callback(result)

    # ── Entry point ────────────────────────────────────────────────────────

    def run(self):
        if self.hosts is not None:
            hosts = self.hosts
            self.log(f"[ShareHunter] Scanning {len(hosts)} host(s) from domain enumeration", 'info')
        else:
            self.log(f"[ShareHunter] Targeting {self.target}", 'info')
            hosts = self._resolve_targets()

        if not hosts:
            self.log("[ShareHunter] No hosts to scan.", 'info')
            return

        self.log(f"[ShareHunter] host_threads={self.host_threads}  share_threads={self.share_threads}  depth={self.max_depth}", 'info')

        host_thread_list = []
        sem = threading.Semaphore(self.host_threads)

        for host in hosts:
            if self._stop_event.is_set():
                break

            def _host_worker(h=host):
                try:
                    self._scan_host(h)
                except Exception as e:
                    self.log(f"[!] Unhandled error scanning {h}: {e}", 'error')
                finally:
                    sem.release()

            sem.acquire()
            if self._stop_event.is_set():
                sem.release()
                break
            t = threading.Thread(target=_host_worker, daemon=True)
            t.start()
            host_thread_list.append(t)

        for t in host_thread_list:
            t.join()

        self.log("[ShareHunter] Scan complete.", 'info')

    def _resolve_targets(self) -> list:
        """Expand CIDR, single IP, hostname, or file of targets."""
        import ipaddress
        targets = []
        entry = self.target.strip()

        if os.path.isfile(entry):
            with open(entry) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
            return targets

        try:
            net = ipaddress.ip_network(entry, strict=False)
            return [str(h) for h in net.hosts()]
        except ValueError:
            return [entry]

    def _scan_host(self, host: str):
        conn = self._connect(host)
        if not conn:
            return

        self.log(f"[+] Connected to {host}", 'info')
        shares = self._list_shares(conn, host)
        self.log(f"[+] Shares on {host}: {shares}", 'info')

        # Prioritise interesting share names
        def share_priority(s):
            return 0 if INTERESTING_SHARE_NAMES.search(s) else 1

        shares.sort(key=share_priority)

        def share_worker(share_name):
            wconn = self._connect(host)
            if not wconn:
                return
            try:
                self._walk_share(wconn, host, share_name)
            except Exception as e:
                self.log(f"[!] Error on \\\\{host}\\{share_name}: {e}", 'error')
            finally:
                try:
                    wconn.logoff()
                except Exception:
                    pass

        share_sem = threading.Semaphore(self.share_threads)

        def bounded_share_worker(share_name):
            try:
                share_worker(share_name)
            finally:
                share_sem.release()

        share_thread_list = []
        for share in shares:
            if self._stop_event.is_set():
                break
            share_sem.acquire()
            t = threading.Thread(target=bounded_share_worker, args=(share,), daemon=True)
            t.start()
            share_thread_list.append(t)

        for t in share_thread_list:
            t.join()

        try:
            conn.logoff()
        except Exception:
            pass

        if self.session is not None:
            sess.mark_host_done(self.session, host)

    def stop(self):
        self._stop_event.set()

    def get_results(self) -> list:
        with self._results_lock:
            return list(self._results)
