"""
ManSpider loot triage — watches a manspider loot directory and applies the
same Snaffler-equivalent rules used for live SMB scans (sharehunter.rules).

manspider (https://github.com/blacklanternsecurity/MANSPIDER) already pulled
the files down over SMB; this module just re-triages what's sitting on disk
so its output lines up with ShareHunter's own scan results in the same GUI.

manspider flattens the UNC path into the loot filename, joining host, share,
and path components with underscores — e.g.:
    192.168.56.11_WebApps_Config_database.conf
There's no reserved separator, so the split back into host/share/path is a
best-effort display convenience, not a reconstruction of the real UNC path.
The first component is always the host (manspider names loot files after the
target it connected to); everything after that is shown as the "share/path".
"""

import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from sharehunter.rules import RATING_LABELS, SKIP_EXTENSIONS
from sharehunter.scanner import _match_filename, _match_content, MAX_CONTENT_SIZE, SnaffleResult

DEFAULT_LOOT_DIR = os.path.expanduser('~/.manspider/loot')
POLL_INTERVAL_SECONDS = 60


def _split_loot_name(fname: str) -> tuple[str, str, str]:
    """Best-effort split of a flattened manspider loot filename into
    (host, share_and_path, filename) for display purposes."""
    parts = fname.split('_')
    host = parts[0] if parts else fname
    rest = parts[1:] if len(parts) > 1 else []
    share = rest[0] if rest else ''
    path = '_'.join(rest[1:]) if len(rest) > 1 else fname
    return host, share, path


class ManSpiderWatcher:
    """Polls a manspider loot directory on an interval, triaging any file
    that's new or changed since the last poll with ShareHunter's rule set."""

    def __init__(self, loot_dir: str = DEFAULT_LOOT_DIR,
                 poll_interval: int = POLL_INTERVAL_SECONDS,
                 result_callback: Optional[Callable] = None,
                 log_callback: Optional[Callable] = None):
        self.loot_dir = os.path.expanduser(loot_dir)
        self.poll_interval = poll_interval
        self.result_callback = result_callback or (lambda r: None)
        self.log_callback = log_callback or (lambda m, lvl='info': None)

        self._stop_event = threading.Event()
        self._seen: dict[str, tuple[float, int]] = {}  # path -> (mtime, size)
        self._results: list[SnaffleResult] = []
        self._results_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def log(self, msg: str, level: str = 'info'):
        self.log_callback(msg, level)

    def get_results(self) -> list:
        with self._results_lock:
            return list(self._results)

    def start(self):
        """Run the poll loop in a background thread (used by the web GUI)."""
        self._thread = threading.Thread(target=self.run_forever, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def run_forever(self):
        """Run the poll loop on the calling thread — blocks until stop() is
        called from another thread (used by --nogui, which has no GUI event
        loop to hand off to)."""
        self.log(f"[ManSpider] Watching {self.loot_dir} (poll every {self.poll_interval}s)", 'info')
        if not os.path.isdir(self.loot_dir):
            self.log(f"[!] Loot directory does not exist: {self.loot_dir}", 'error')
            return

        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as e:
                self.log(f"[!] ManSpider poll error: {e}", 'error')

            # Sleep in short increments so stop() is responsive.
            waited = 0.0
            while waited < self.poll_interval and not self._stop_event.is_set():
                time.sleep(min(1.0, self.poll_interval - waited))
                waited += 1.0

        self.log("[ManSpider] Watch stopped.", 'info')

    def _poll_once(self):
        new_count = 0
        try:
            entries = sorted(os.listdir(self.loot_dir))
        except Exception as e:
            self.log(f"[!] Could not list {self.loot_dir}: {e}", 'error')
            return

        for fname in entries:
            if self._stop_event.is_set():
                return
            fpath = os.path.join(self.loot_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                st = os.stat(fpath)
            except OSError:
                continue

            key = (st.st_mtime, st.st_size)
            if self._seen.get(fpath) == key:
                continue  # already triaged, unchanged since last poll
            self._seen[fpath] = key

            self._triage_file(fname, fpath, st)
            new_count += 1

        if new_count:
            self.log(f"[ManSpider] Triaged {new_count} new/changed file(s)", 'info')

    def _triage_file(self, fname: str, fpath: str, st: os.stat_result):
        host, share, disp_path = _split_loot_name(fname)
        ext = os.path.splitext(fname)[1].lower()

        fn_rule = _match_filename(fname, disp_path)

        content_rule = None
        matched_line = ""
        raw_text = ""
        if ext not in SKIP_EXTENSIONS and 0 < st.st_size < MAX_CONTENT_SIZE:
            try:
                with open(fpath, 'rb') as fh:
                    data = fh.read()
                content_rule, matched_line = _match_content(data)
                if not matched_line:
                    raw_text = data.decode('utf-8', errors='replace')
            except Exception:
                pass

        winner_rule = None
        if fn_rule and content_rule:
            winner_rule = fn_rule if fn_rule.rating <= content_rule.rating else content_rule
            if content_rule.rating >= fn_rule.rating:
                matched_line = ""
        elif fn_rule:
            winner_rule = fn_rule
        elif content_rule:
            winner_rule = content_rule

        if winner_rule is fn_rule and not matched_line and raw_text:
            for line in raw_text.splitlines():
                stripped = line.strip()
                if stripped:
                    matched_line = stripped[:300]
                    break

        if winner_rule is None:
            return

        modified = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

        result = SnaffleResult(
            host=host,
            share=share or 'loot',
            path=disp_path,
            filename=fname,
            size=st.st_size,
            modified=modified,
            rating=winner_rule.rating,
            rating_label=RATING_LABELS[winner_rule.rating],
            rule_name=winner_rule.name,
            rule_desc=winner_rule.description,
            match_type=winner_rule.match_type,
            matched_line=matched_line,
        )

        with self._results_lock:
            self._results.append(result)

        self.log(result.to_snaffler_line(), 'result')
        self.result_callback(result, local_path=fpath)
