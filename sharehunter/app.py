"""
Flask + SocketIO web viewer for ShareHunter.

This process never scans anything itself — it only reads what
sharehunter_scan.py has written to disk (sessions/*.session.json,
loot/<scan_id>/, logs/*.log) and lets you browse it. A loaded session is a
static snapshot: whatever was on disk at load time, no auto-refresh — pick a
different (or freshly-started) session from the header dropdown, or reload
the page, to see newer data. The one live activity this process runs
directly is the ManSpider loot-directory watcher, which is a pure filesystem
poller with its own start/stop and live-updating table, independent of
whatever session happens to be loaded.

Tab 1: Live results stream
Tab 2: Filter / search results
"""

import os
import re
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO

from sharehunter.rules import RATING_LABELS
from sharehunter import session as sess

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.config['SECRET_KEY'] = 'sharehunter-gui'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')

# Loot and log base dirs live next to this package
_LOOT_BASE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'loot')
_LOGS_BASE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')

# The currently-loaded session — a static snapshot, read once at load time.
# 'load_id' is a local counter (distinct from the session's own string
# scan_id) so the browser can detect "a different session was just loaded"
# and reset its display.
_view_state = {
    'session':  None,
    'load_id':  0,
    'lock':     threading.Lock(),
}

# Separate state for the ManSpider loot watcher — a live filesystem poller
# that can run independently of (and at the same time as) viewing a session,
# since neither one launches an SMB scan in this process.
_manspider_state = {
    'running':  False,
    'watcher':  None,
    'results':  [],
    'lock':     threading.Lock(),
    'loot_dir': None,
    'scan_id':  0,
}


def _manspider_result_callback(result, local_path=''):
    d = result.to_dict()
    d['local_path'] = local_path
    d['downloaded'] = True  # already sitting on disk — nothing to fetch
    with _manspider_state['lock']:
        _manspider_state['results'].append(d)
    socketio.emit('new_result', d)


def _log_callback(msg: str, level: str = 'info'):
    socketio.emit('log', {'msg': msg, 'level': level})


@app.route('/')
def index():
    return render_template('index.html', rating_labels=RATING_LABELS)


@app.route('/api/session-list')
def api_session_list():
    """Return summary of all saved sessions, newest first."""
    return jsonify(sess.list_sessions())


@app.route('/api/session-load', methods=['POST'])
def api_session_load():
    """Load a session read-only for viewing (no scanning is ever launched).

    POST body: { scan_id: '...' }  (optional — uses latest if omitted)
    """
    data    = request.get_json(force=True) or {}
    scan_id = data.get('scan_id', '').strip()

    if scan_id:
        s = sess.load(scan_id)
        if not s.get('scan_id'):
            return jsonify({'ok': False, 'error': f'Session {scan_id} not found'})
    else:
        s = sess.load_latest()
        if s is None:
            return jsonify({'ok': False, 'error': 'No session files found'})

    with _view_state['lock']:
        _view_state['session'] = s
        _view_state['load_id'] = _view_state['load_id'] + 1
        load_id = _view_state['load_id']

    return jsonify({
        'ok':      True,
        'scan_id': s['scan_id'],
        'load_id': load_id,
        'complete': bool(s.get('ended_at')),
        'target':  s.get('scan_params', {}).get('target')
                   or s.get('scan_params', {}).get('target_domain', ''),
    })


@app.route('/api/results')
def api_results():
    if request.args.get('mode') == 'manspider':
        with _manspider_state['lock']:
            results = list(_manspider_state['results'])
            scan_id = _manspider_state['scan_id']
        return jsonify({'scan_id': scan_id, 'results': results})

    with _view_state['lock']:
        session = _view_state.get('session')
        load_id = _view_state['load_id']
    if session is None:
        return jsonify({'scan_id': load_id, 'results': []})

    downloads = session.get('downloads', {})
    results   = list(session.get('results', []))
    for r in results:
        unc = r.get('unc_path', '')
        if unc in downloads:
            r['downloaded'] = True
            r['local_path'] = downloads[unc].get('local_path', '')
        else:
            r['downloaded'] = False
            r['local_path'] = ''
    return jsonify({'scan_id': load_id, 'results': results})


@app.route('/api/status')
def api_status():
    if request.args.get('mode') == 'manspider':
        with _manspider_state['lock']:
            count   = len(_manspider_state['results'])
            scan_id = _manspider_state['scan_id']
        return jsonify({'running': _manspider_state['running'], 'count': count,
                        'scan_id': scan_id, 'mode': 'manspider',
                        'target': _manspider_state.get('loot_dir', '') or ''})

    with _view_state['lock']:
        session = _view_state.get('session')
        load_id = _view_state['load_id']

    if session is None:
        return jsonify({'count': 0, 'scan_id': load_id,
                        'mode': 'session', 'target': '', 'loaded': False})

    params = session.get('scan_params', {})
    return jsonify({
        'complete':  bool(session.get('ended_at')),
        'count':     len(session.get('results', [])),
        'scan_id':   load_id,
        'mode':      'session',
        'loaded':    True,
        'session_id': session.get('scan_id', ''),
        'target':    params.get('target') or params.get('target_domain', ''),
        'hosts_total':     len(session.get('hosts_total', [])),
        'hosts_completed': len(session.get('hosts_completed', [])),
    })


@app.route('/api/manspider-start', methods=['POST'])
def api_manspider_start():
    """Start (or restart) watching a manspider loot directory.

    POST body: { "loot_dir": "/home/user/.manspider/loot", "poll_interval": 60 }
    """
    from sharehunter.manspider_watch import ManSpiderWatcher, DEFAULT_LOOT_DIR

    if _manspider_state['running']:
        return jsonify({'ok': False, 'error': 'Already watching'})

    data          = request.get_json(force=True) or {}
    loot_dir      = (data.get('loot_dir') or '').strip() or DEFAULT_LOOT_DIR
    loot_dir      = os.path.expanduser(loot_dir)
    poll_interval = int(data.get('poll_interval') or 60)

    if not os.path.isdir(loot_dir):
        return jsonify({'ok': False, 'error': f'Directory not found: {loot_dir}'})

    with _manspider_state['lock']:
        _manspider_state['results']  = []
        _manspider_state['running']  = True
        _manspider_state['loot_dir'] = loot_dir
        _manspider_state['scan_id']  = _manspider_state['scan_id'] + 1

    watcher = ManSpiderWatcher(
        loot_dir=loot_dir,
        poll_interval=poll_interval,
        result_callback=_manspider_result_callback,
        log_callback=_log_callback,
    )
    _manspider_state['watcher'] = watcher
    watcher.start()

    return jsonify({'ok': True, 'loot_dir': loot_dir})


@app.route('/api/manspider-stop', methods=['POST'])
def api_manspider_stop():
    w = _manspider_state.get('watcher')
    if w:
        w.stop()
    _manspider_state['running'] = False
    return jsonify({'ok': True})


@app.route('/api/download', methods=['POST'])
def api_download():
    """
    Fetch a file from a remote SMB share, save it under the loaded session's
    loot directory, and serve it back to the browser as an attachment. Uses
    the credentials sharehunter_scan.py stored in the session file.

    POST body: { "host": "...", "share": "...", "path": "...", "filename": "..." }
    """
    import eventlet.tpool

    with _view_state['lock']:
        session = _view_state.get('session')
    if session is None:
        return jsonify({'ok': False, 'error': 'No session loaded'}), 400

    data     = request.get_json(force=True)
    host     = data.get('host', '').strip()
    share    = data.get('share', '').strip()
    path     = data.get('path', '').strip()
    filename = data.get('filename', '').strip()

    if not all([host, share, path, filename]):
        return jsonify({'ok': False, 'error': 'host, share, path and filename are required'}), 400

    loot_dir = session.get('loot_dir') or os.path.join(_LOOT_BASE, 'manual')
    os.makedirs(loot_dir, exist_ok=True)

    rel_dir   = os.path.dirname(path).lstrip('\\/').replace('\\', os.sep).replace('/', os.sep)
    save_dir  = os.path.join(loot_dir, _sanitise(host), _sanitise(share), rel_dir)
    os.makedirs(save_dir, exist_ok=True)
    save_path = os.path.join(save_dir, _sanitise(filename))

    creds    = session.get('creds', {})
    username = creds.get('username', '')
    password = creds.get('password', '')
    domain   = creds.get('domain', '')
    nthash   = creds.get('nthash', '')

    # impacket getFile requires a leading backslash
    smb_path = path if path.startswith('\\') else '\\' + path

    # Run the blocking SMB fetch in a real OS thread so eventlet's cooperative
    # scheduler is not starved and other requests can proceed concurrently.
    def _fetch_smb():
        from impacket.smbconnection import SMBConnection
        from sharehunter.scanner import _parse_hash
        conn = SMBConnection(host, host, sess_port=445, timeout=15)
        if nthash:
            lm, nt = _parse_hash(nthash)
            conn.login(username, '', domain, lmhash=lm, nthash=nt)
        else:
            conn.login(username, password, domain)
        buf = []
        conn.getFile(share, smb_path, lambda d: buf.append(d))
        conn.logoff()
        return b''.join(buf)

    try:
        file_bytes = eventlet.tpool.execute(_fetch_smb)
    except Exception as e:
        return jsonify({'ok': False, 'error': f'SMB fetch failed: {e}'}), 500

    with open(save_path, 'wb') as fh:
        fh.write(file_bytes)

    _log_callback(f"[LOOT] Saved: {save_path}  ({len(file_bytes)} bytes)", 'info')

    # Record in the session file — note this can race with the scan process's
    # own periodic saves if the scan is still running elsewhere, since both
    # write the whole session.json rather than merging.
    clean_path = path.lstrip('\\')
    unc_path = f"\\\\{host}\\{share}\\{clean_path}"
    sess.mark_downloaded(session, unc_path, save_path)

    return send_file(
        save_path,
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream',
    )


def _sanitise(name: str) -> str:
    """Strip characters that are unsafe in filesystem paths."""
    return re.sub(r'[\\/:*?"<>|]', '_', name)


# ─── Log Viewer ───────────────────────────────────────────────────────────────

@app.route('/log-viewer')
def log_viewer():
    return render_template('log_viewer.html')


@app.route('/api/log-list')
def api_log_list():
    """Return list of log files in the logs directory, newest first."""
    logs = []
    if os.path.isdir(_LOGS_BASE):
        for fn in sorted(os.listdir(_LOGS_BASE), reverse=True):
            if fn.endswith('.log'):
                fp = os.path.join(_LOGS_BASE, fn)
                logs.append({
                    'name': fn,
                    'path': fp,
                    'size': os.path.getsize(fp),
                    'mtime': datetime.fromtimestamp(os.path.getmtime(fp)).strftime('%Y-%m-%d %H:%M:%S'),
                })
    return jsonify(logs)


@app.route('/api/parse-log', methods=['POST'])
def api_parse_log():
    """
    Parse a Snaffler or ShareHunter log file.

    Accepts either:
      - JSON body: { "path": "/absolute/path/to/file.log" }
      - multipart form upload: file field named 'file'

    Returns JSON list of parsed finding objects.
    """
    if request.content_type and 'multipart' in request.content_type:
        f = request.files.get('file')
        if not f:
            return jsonify({'ok': False, 'error': 'No file uploaded'}), 400
        try:
            raw = f.read().decode('utf-8', errors='replace')
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 400
    else:
        data = request.get_json(force=True) or {}
        path = data.get('path', '').strip()
        if not path:
            return jsonify({'ok': False, 'error': 'path is required'}), 400
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                raw = fh.read()
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 400

    findings = _parse_log_text(raw)
    return jsonify({'ok': True, 'findings': findings, 'total': len(findings)})


def _parse_log_text(raw: str) -> list:
    # Parses ShareHunter and Snaffler log formats into structured finding dicts.

    RATING_MAP = {
        'Black': 0, 'black': 0,
        'Red':   1, 'red':   1,
        'Yellow':2, 'yellow':2,
        'Green': 3, 'green': 3,
    }
    RATING_LABELS_LOCAL = {0: 'Black', 1: 'Red', 2: 'Yellow', 3: 'Green'}

    # ── Pattern A: ShareHunter / ShareHunter-compatible Snaffler output ──────
    # [Red](Pass-In-Code)<165B>{\\host\share\path}[matched data]
    PAT_SH = re.compile(
        r'^\[(?P<rating>Black|Red|Yellow|Green)\]'
        r'\((?P<rule>[^)]+)\)'
        r'<(?P<size>\d+)B?>'
        r'\{(?P<unc>[^}]+)\}'
        r'(?:\[(?P<match>.*)\])?',
        re.IGNORECASE
    )

    # ── Pattern B: Real Snaffler TSV/structured output ───────────────────────
    # [2024-01-01 12:00:00Z][Triage][Red][RuleName] {\\host\share\path} [match]
    PAT_SNAF_TS = re.compile(
        r'^\[(?P<ts>[^\]]{10,30})\]'
        r'\[(?:Triage|triage|INFO|WARN|ERROR)?\]'
        r'\[(?P<rating>Black|Red|Yellow|Green)\]'
        r'\[(?P<rule>[^\]]+)\]\s*'
        r'\{(?P<unc>[^}]+)\}'
        r'(?:\s*\[(?P<match>.*)\])?',
        re.IGNORECASE | re.DOTALL
    )

    # ── Pattern C: Real Snaffler plain (no timestamp, bracket-only) ──────────
    # [0m][RuleName]  {\\host\share\path} [match]   — colour-prefix variants
    PAT_SNAF_PLAIN = re.compile(
        r'^\[(?:0m|Black|Red|Yellow|Green|\d+m)\]'
        r'\[(?P<rule>[^\]]+)\]\s*'
        r'\{(?P<unc>[^}]+)\}'
        r'(?:\s*\[(?P<match>.*)\])?',
        re.IGNORECASE | re.DOTALL
    )

    # ── Pattern D: Real Snaffler console output ───────────────────────────────
    # [DOMAIN\user@host] 2026-06-18 15:12:50Z [File] {Red}<RuleName|R|regex|size|date>(\\host\share\path) match
    # Only match [File] lines (not [Share] or [Info])
    PAT_SNAF_REAL = re.compile(
        r'^\[(?P<ctx>[^\]]+)\]\s+'                          # [DOMAIN\user@host]
        r'(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}Z)\s+'  # timestamp
        r'\[File\]\s+'                                       # [File] only
        r'\{(?P<rating>Black|Red|Yellow|Green)\}'            # {Red}
        r'<(?P<rule>[^|>]+)'                                 # <RuleName
        r'(?:\|[^|]*\|[^|]*\|(?P<size>[^|]+)\|[^>]*)?>?'   # |R|regex|size|date> (optional)
        r'\((?P<unc>[^)]+)\)'                                # (\\host\share\path)
        r'(?:\s+(?P<match>.+))?',                            # match text
        re.IGNORECASE
    )

    def _split_unc(unc: str):
        unc = unc.lstrip('\\').lstrip('/')
        parts = re.split(r'[/\\]', unc, maxsplit=2)
        host  = parts[0] if len(parts) > 0 else ''
        share = parts[1] if len(parts) > 1 else ''
        path  = parts[2] if len(parts) > 2 else ''
        filename = path.split('\\')[-1].split('/')[-1] if path else ''
        return host, share, path, filename

    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        m = PAT_SH.match(line)
        if m:
            rating_label = RATING_LABELS_LOCAL.get(RATING_MAP.get(m.group('rating'), 3), 'Green')
            host, share, path, filename = _split_unc(m.group('unc'))
            findings.append({
                'rating':       RATING_MAP.get(m.group('rating'), 3),
                'rating_label': rating_label,
                'rule_name':    m.group('rule'),
                'size':         int(m.group('size')),
                'unc_path':     m.group('unc'),
                'host':         host,
                'share':        share,
                'path':         path,
                'filename':     filename,
                'matched_line': (m.group('match') or '').strip('\ufeff'),
                'timestamp':    '',
                'source':       'sharehunter',
            })
            continue

        m = PAT_SNAF_TS.match(line)
        if m:
            rating_label = RATING_LABELS_LOCAL.get(RATING_MAP.get(m.group('rating'), 3), 'Green')
            host, share, path, filename = _split_unc(m.group('unc'))
            findings.append({
                'rating':       RATING_MAP.get(m.group('rating'), 3),
                'rating_label': rating_label,
                'rule_name':    m.group('rule'),
                'size':         0,
                'unc_path':     m.group('unc'),
                'host':         host,
                'share':        share,
                'path':         path,
                'filename':     filename,
                'matched_line': (m.group('match') or '').strip('\ufeff'),
                'timestamp':    m.group('ts'),
                'source':       'snaffler',
            })
            continue

        m = PAT_SNAF_PLAIN.match(line)
        if m:
            host, share, path, filename = _split_unc(m.group('unc'))
            findings.append({
                'rating':       3,
                'rating_label': 'Green',
                'rule_name':    m.group('rule'),
                'size':         0,
                'unc_path':     m.group('unc'),
                'host':         host,
                'share':        share,
                'path':         path,
                'filename':     filename,
                'matched_line': (m.group('match') or '').strip('\ufeff'),
                'timestamp':    '',
                'source':       'snaffler',
            })
            continue

        m = PAT_SNAF_REAL.match(line)
        if m:
            rating     = RATING_MAP.get(m.group('rating'), 3)
            rating_lbl = RATING_LABELS_LOCAL.get(rating, 'Green')
            size_str   = (m.group('size') or '0').strip()
            # size may be "73MB", "32B", "71.4MB" — convert to bytes int
            try:
                if size_str.upper().endswith('MB'):
                    size = int(float(size_str[:-2]) * 1024 * 1024)
                elif size_str.upper().endswith('KB'):
                    size = int(float(size_str[:-2]) * 1024)
                elif size_str.upper().endswith('B'):
                    size = int(float(size_str[:-1]))
                else:
                    size = int(float(size_str))
            except Exception:
                size = 0
            host, share, path, filename = _split_unc(m.group('unc'))
            findings.append({
                'rating':       rating,
                'rating_label': rating_lbl,
                'rule_name':    m.group('rule'),
                'size':         size,
                'unc_path':     m.group('unc'),
                'host':         host,
                'share':        share,
                'path':         path,
                'filename':     filename,
                'matched_line': (m.group('match') or '').strip(),
                'timestamp':    m.group('ts'),
                'source':       'snaffler',
            })

    return findings


def load_initial_session(scan_id: str = None, latest: bool = False):
    """Called at startup from sharehunter_web.py to honour --session/--latest.

    Resolves once, here, at process startup — --latest picks whatever is
    newest on disk right now, not "whatever is newest at any future point."
    A session started after this process is already running won't appear
    until it's picked from the browser's session dropdown (or the page/
    process is restarted).
    """
    if latest:
        s = sess.load_latest()
    elif scan_id:
        s = sess.load(scan_id)
        if not s.get('scan_id'):
            return None
    else:
        return None
    with _view_state['lock']:
        _view_state['session'] = s
        _view_state['load_id'] = _view_state['load_id'] + 1
    return s


def start_gui(host='127.0.0.1', port=5005, debug=False):
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False)
