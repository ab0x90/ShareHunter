"""
Persistent session store for ShareHunter.

Each scan writes its own JSON file under:
  <project_root>/sessions/<scan_id>.session.json

The session captures:
  - scan metadata (target, creds, timestamps, loot_dir)
  - all results found so far
  - which hosts have been completed / are pending
  - which files have been downloaded (unc_path -> local loot path)
"""

import json
import os
import threading
from datetime import datetime
from typing import Optional

_SESSIONS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'sessions')
_lock = threading.Lock()


def _session_path(scan_id: str) -> str:
    return os.path.join(_SESSIONS_DIR, f'{scan_id}.session.json')


def _default() -> dict:
    return {
        'version':    1,
        'scan_id':    None,
        'started_at': None,
        'ended_at':   None,
        'loot_dir':   None,
        'creds': {
            'username': '',
            'password': '',
            'domain':   '',
            'nthash':   '',
        },
        'scan_params': {},
        'hosts_total':     [],
        'hosts_completed': [],
        'hosts_pending':   [],
        'results':    [],
        'downloads':  {},   # unc_path -> { 'local_path': str, 'ts': str }
    }


def load(scan_id: str) -> dict:
    """Load a specific session by scan_id."""
    path = _session_path(scan_id)
    if not os.path.exists(path):
        return _default()
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        base = _default()
        base.update(data)
        return base
    except Exception:
        return _default()


def load_latest() -> Optional[dict]:
    """Load the most recent session, or None if no sessions exist."""
    sessions = list_sessions()
    if not sessions:
        return None
    return load(sessions[0]['scan_id'])


def save(session: dict):
    """Write session atomically to its per-scan file."""
    scan_id = session.get('scan_id')
    if not scan_id:
        return
    os.makedirs(_SESSIONS_DIR, exist_ok=True)
    path = _session_path(scan_id)
    with _lock:
        tmp = path + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(session, fh, indent=2, default=str)
            os.replace(tmp, path)
        except Exception as e:
            print(f'[session] WARNING: could not save session: {e}')


def list_sessions() -> list:
    """Return summary dicts for all sessions, newest first."""
    if not os.path.isdir(_SESSIONS_DIR):
        return []
    sessions = []
    for fname in os.listdir(_SESSIONS_DIR):
        if not fname.endswith('.session.json'):
            continue
        path = os.path.join(_SESSIONS_DIR, fname)
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            scan_id = data.get('scan_id', fname.replace('.session.json', ''))
            params  = data.get('scan_params', {})
            creds   = data.get('creds', {})
            sessions.append({
                'scan_id':         scan_id,
                'started_at':      data.get('started_at'),
                'ended_at':        data.get('ended_at'),
                'result_count':    len(data.get('results', [])),
                'hosts_completed': len(data.get('hosts_completed', [])),
                'hosts_pending':   len(data.get('hosts_pending', [])),
                'download_count':  len(data.get('downloads', {})),
                'target':          params.get('target') or params.get('target_domain', ''),
                'username':        creds.get('username', ''),
            })
        except Exception:
            continue
    sessions.sort(key=lambda s: s.get('started_at') or '', reverse=True)
    return sessions


def new_scan(creds: dict, params: dict, loot_dir: str, hosts: list) -> dict:
    """Initialise a fresh session for a new scan."""
    session = _default()
    session['scan_id']       = datetime.now().strftime('%Y%m%d_%H%M%S')
    session['started_at']    = datetime.now().isoformat()
    session['ended_at']      = None
    session['loot_dir']      = loot_dir
    session['creds']         = creds
    session['scan_params']   = params
    session['hosts_total']   = list(hosts)
    session['hosts_pending'] = list(hosts)
    session['hosts_completed'] = []
    session['results']       = []
    session['downloads']     = {}
    save(session)
    return session


def add_result(session: dict, result_dict: dict):
    with _lock:
        session['results'].append(result_dict)
    if len(session['results']) % 25 == 0:
        save(session)


def mark_host_done(session: dict, host: str):
    with _lock:
        if host in session['hosts_pending']:
            session['hosts_pending'].remove(host)
        if host not in session['hosts_completed']:
            session['hosts_completed'].append(host)
    save(session)


def mark_downloaded(session: dict, unc_path: str, local_path: str):
    with _lock:
        session['downloads'][unc_path] = {
            'local_path': local_path,
            'ts': datetime.now().isoformat(),
        }
    save(session)


def mark_ended(session: dict):
    session['ended_at'] = datetime.now().isoformat()
    session['hosts_pending'] = []
    save(session)


def exists() -> bool:
    """True if at least one session file exists."""
    return bool(list_sessions())


def session_file_path(scan_id: str) -> str:
    return _session_path(scan_id)
