"""
Flask + SocketIO web GUI for ShareHunter.
Tab 1: Live results stream
Tab 2: Filter / search results
"""

import os
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, abort
from flask_socketio import SocketIO, emit

from sharehunter.rules import RATING_LABELS, RATING_COLORS
from sharehunter import session as sess

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.config['SECRET_KEY'] = 'sharehunter-gui'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')

# Loot and log base dirs live next to this package
_LOOT_BASE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'loot')
_LOGS_BASE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')

# Shared scan state
_scan_state = {
    'running':   False,
    'snaffler':  None,
    'results':   [],
    'logs':      [],
    'lock':      threading.Lock(),
    'loot_dir':  None,   # set when a scan starts
    'session':   None,   # active session dict
    'scan_id':   0,      # increments each time a new scan starts
}


def _result_callback(result):
    d = result.to_dict()
    with _scan_state['lock']:
        _scan_state['results'].append(d)
    if _scan_state.get('session') is not None:
        sess.add_result(_scan_state['session'], d)
    socketio.emit('new_result', d)


def _log_callback(msg: str, level: str = 'info'):
    entry = {'msg': msg, 'level': level}
    with _scan_state['lock']:
        _scan_state['logs'].append(entry)
        if len(_scan_state['logs']) > 2000:
            _scan_state['logs'] = _scan_state['logs'][-2000:]
    if level != 'result':
        socketio.emit('log', entry)


@app.route('/')
def index():
    return render_template('index.html',
                           rating_labels=RATING_LABELS,
                           rating_colors=RATING_COLORS)


@app.route('/api/session-list')
def api_session_list():
    """Return summary of all saved sessions, newest first."""
    return jsonify(sess.list_sessions())


@app.route('/api/session-resume', methods=['POST'])
def api_session_resume():
    """Load a session and re-launch the scan against any pending hosts.

    POST body: { scan_id: '...' }  (optional — uses latest if omitted)

    If a scan is already running, just returns the live results so the browser
    can sync up without interfering with the active scan.
    """
    from sharehunter.scanner import ShareHunter

    # Scan already running — just hand back live results
    if _scan_state['running']:
        with _scan_state['lock']:
            results   = list(_scan_state['results'])
            downloads = (_scan_state.get('session') or {}).get('downloads', {})
        return jsonify({'ok': True, 'live': True, 'results': results, 'downloads': downloads})

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

    pending = s.get('hosts_pending', [])
    creds   = s.get('creds', {})

    # Load prior results into scan state so /api/results serves them immediately
    with _scan_state['lock']:
        _scan_state['results']  = list(s.get('results', []))
        _scan_state['loot_dir'] = s.get('loot_dir') or _scan_state.get('loot_dir')
        _scan_state['creds']    = creds
        _scan_state['session']  = s
        _scan_state['scan_id']  = _scan_state['scan_id'] + 1

    # Kick off a resumed scan in a background thread if there are pending hosts
    if pending:
        os.makedirs(_LOGS_BASE, exist_ok=True)
        scan_ts  = s.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
        log_path = os.path.join(_LOGS_BASE, f'sharehunter_{scan_ts}_resumed.log')
        log_fh   = open(log_path, 'a', encoding='utf-8', buffering=1)

        def result_cb(result):
            log_fh.write(result.to_snaffler_line() + '\n')
            _result_callback(result)

        def log_cb(msg, level='info'):
            if level != 'result':
                log_fh.write(msg + '\n')
            _log_callback(msg, level)

        def run_resumed():
            log_cb(f"[*] Resuming scan — {len(pending)} host(s) pending", 'info')
            log_cb(f"[*] Log file: {log_path}", 'info')
            try:
                snaffler = ShareHunter(
                    target='', hosts=pending,
                    username=creds.get('username', ''),
                    password=creds.get('password', ''),
                    domain=creds.get('domain', ''),
                    nthash=creds.get('nthash', ''),
                    use_kerberos=creds.get('use_kerberos', False),
                    aes_key=creds.get('aes_key', ''),
                    dc_ip=creds.get('dc_ip', ''),
                    host_threads=s.get('scan_params', {}).get('host_threads', 5),
                    share_threads=s.get('scan_params', {}).get('share_threads', 10),
                    max_depth=s.get('scan_params', {}).get('depth', 10),
                    result_callback=result_cb,
                    log_callback=log_cb,
                    session=s,
                )
                _scan_state['snaffler'] = snaffler
                snaffler.run()
            except Exception as e:
                log_cb(f"[!] Resumed scan error: {e}", 'error')
            finally:
                stopped = snaffler is not None and snaffler._stop_event.is_set()
                _scan_state['running']  = False
                _scan_state['snaffler'] = None
                sess.mark_ended(s, stopped=stopped)
                log_fh.close()
                socketio.emit('scan_done', {'total': len(_scan_state['results'])})

        _scan_state['running'] = True
        t = threading.Thread(target=run_resumed, daemon=True)
        t.start()

    return jsonify({
        'ok':       True,
        'live':     bool(pending),   # tells the browser a scan just started
        'resuming': bool(pending),
        'pending':  len(pending),
        'results':  _scan_state['results'],
        'downloads': s.get('downloads', {}),
    })


@app.route('/api/start', methods=['POST'])
def api_start():
    from sharehunter.scanner import ShareHunter
    from sharehunter.domain_enum import get_domain_computers
    data = request.get_json(force=True)

    cli_creds = _scan_state.get('creds') or {}

    target        = data.get('target', '').strip()
    target_domain = data.get('target_domain', '').strip()
    username      = data.get('username', '').strip()      or cli_creds.get('username', '')
    domain        = data.get('domain', '').strip()        or cli_creds.get('domain', '')
    use_ldaps     = bool(data.get('ldaps', False))
    use_kerberos  = bool(data.get('kerberos', False))     or cli_creds.get('use_kerberos', False)
    aes_key       = data.get('aes_key', '').strip()
    dc_ip         = data.get('dc_ip', '').strip()         or cli_creds.get('dc_ip', '')
    host_threads  = int(data.get('host_threads', 5))
    share_threads = int(data.get('share_threads', 10))
    depth         = int(data.get('depth', 10))

    # '__CLI__' sentinel means "use the value the CLI already loaded server-side"
    raw_pw    = data.get('password', '')
    raw_nh    = data.get('nthash', '').strip()
    password  = cli_creds.get('password', '') if raw_pw    == '__CLI__' else raw_pw
    nthash    = cli_creds.get('nthash', '')   if raw_nh    == '__CLI__' else raw_nh

    if aes_key:
        use_kerberos = True

    if not (target or target_domain) or not username:
        return jsonify({'ok': False, 'error': 'target (or target-domain) and username are required'})

    if _scan_state['running']:
        return jsonify({'ok': False, 'error': 'Scan already running'})

    # Create a timestamped loot directory for this scan
    scan_ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
    loot_dir = os.path.join(_LOOT_BASE, scan_ts)
    os.makedirs(loot_dir, exist_ok=True)

    creds = {
        'username':     username,
        'password':     password,
        'domain':       domain,
        'nthash':       nthash,
        'use_kerberos': use_kerberos,
        'aes_key':      aes_key,
        'dc_ip':        dc_ip,
    }
    params = {
        'target':        target,
        'target_domain': target_domain,
        'use_ldaps':     use_ldaps,
        'host_threads':  host_threads,
        'share_threads': share_threads,
        'depth':         depth,
    }

    # Reset state
    with _scan_state['lock']:
        _scan_state['results']  = []
        _scan_state['logs']     = []
        _scan_state['running']  = True
        _scan_state['loot_dir'] = loot_dir
        _scan_state['creds']    = creds
        _scan_state['scan_id']  = _scan_state['scan_id'] + 1

    def run_scan():
        # Open a log file for this browser-initiated scan
        os.makedirs(_LOGS_BASE, exist_ok=True)
        log_path = os.path.join(_LOGS_BASE, f'sharehunter_{scan_ts}.log')
        log_fh = open(log_path, 'a', encoding='utf-8', buffering=1)

        def result_cb(result):
            log_fh.write(result.to_snaffler_line() + '\n')
            _result_callback(result)

        def log_cb(msg, level='info'):
            if level != 'result':
                log_fh.write(msg + '\n')
            _log_callback(msg, level)

        # Tell the browser where the log file is
        log_cb(f"[*] Log file: {log_path}", 'info')

        try:
            hosts = None
            if target_domain:
                log_cb(f"[*] Enumerating computers from DC: {target_domain}", 'info')
                hosts = get_domain_computers(
                    dc=target_domain, username=username, password=password,
                    domain=domain, nthash=nthash,
                    use_ldaps=use_ldaps,
                    use_kerberos=use_kerberos,
                    aes_key=aes_key,
                    log_callback=log_cb,
                )
                if not hosts:
                    log_cb('[!] No hosts returned from domain enumeration', 'error')
                    return

            # Initialise session after we know the host list
            s = sess.new_scan(creds, params, loot_dir, hosts or [target])
            with _scan_state['lock']:
                _scan_state['session'] = s

            snaffler = ShareHunter(
                target=target, hosts=hosts,
                username=username, password=password,
                domain=domain, nthash=nthash,
                use_kerberos=use_kerberos,
                aes_key=aes_key,
                dc_ip=dc_ip,
                host_threads=host_threads, share_threads=share_threads,
                max_depth=depth,
                result_callback=result_cb,
                log_callback=log_cb,
                session=s,
            )
            _scan_state['snaffler'] = snaffler
            snaffler.run()
        except Exception as e:
            log_cb(f"[!] Scan error: {e}", 'error')
        finally:
            stopped = snaffler is not None and snaffler._stop_event.is_set()
            _scan_state['running'] = False
            _scan_state['snaffler'] = None
            if _scan_state.get('session') is not None:
                sess.mark_ended(_scan_state['session'], stopped=stopped)
            log_fh.close()
            socketio.emit('scan_done', {'total': len(_scan_state['results'])})

    t = threading.Thread(target=run_scan, daemon=True)
    t.start()
    return jsonify({'ok': True})


@app.route('/api/stop', methods=['POST'])
def api_stop():
    sn = _scan_state.get('snaffler')
    if sn:
        sn.stop()
    _scan_state['running'] = False
    return jsonify({'ok': True})


@app.route('/api/results')
def api_results():
    with _scan_state['lock']:
        results  = list(_scan_state['results'])
        scan_id  = _scan_state['scan_id']
    # Annotate each result with its download status from the session
    downloads = {}
    if _scan_state.get('session'):
        downloads = _scan_state['session'].get('downloads', {})
    for r in results:
        unc = r.get('unc_path', '')
        if unc in downloads:
            r['downloaded'] = True
            r['local_path'] = downloads[unc].get('local_path', '')
        else:
            r['downloaded'] = False
            r['local_path'] = ''
    return jsonify({'scan_id': scan_id, 'results': results})


@app.route('/api/status')
def api_status():
    with _scan_state['lock']:
        count   = len(_scan_state['results'])
        scan_id = _scan_state['scan_id']
    return jsonify({'running': _scan_state['running'], 'count': count, 'scan_id': scan_id})


@app.route('/api/prefill')
def api_prefill():
    """Return CLI-supplied credentials and scan params so the GUI can pre-populate its form."""
    creds  = _scan_state.get('creds')  or {}
    params = _scan_state.get('params') or {}
    if not creds and not params:
        return jsonify({'ok': False})
    return jsonify({
        'ok':           True,
        'username':     creds.get('username', ''),
        'domain':       creds.get('domain', ''),
        'has_password': bool(creds.get('password', '')),
        'has_nthash':   bool(creds.get('nthash', '')),
        'use_kerberos': creds.get('use_kerberos', False),
        'dc_ip':        creds.get('dc_ip', ''),
        'target':       params.get('target', ''),
        'target_domain':params.get('target_domain', ''),
        'host_threads': params.get('host_threads', 5),
        'share_threads':params.get('share_threads', 10),
        'depth':        params.get('depth', 10),
        'use_ldaps':    params.get('use_ldaps', False),
    })


@app.route('/api/logs')
def api_logs():
    with _scan_state['lock']:
        logs = list(_scan_state['logs'])
    return jsonify(logs)


@app.route('/api/set-creds', methods=['POST'])
def api_set_creds():
    """Inject credentials into a running session (e.g. CLI-launched scans)."""
    data = request.get_json(force=True)
    scan_ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
    with _scan_state['lock']:
        _scan_state['creds'] = {
            'username': data.get('username', ''),
            'password': data.get('password', ''),
            'domain':   data.get('domain', ''),
            'nthash':   data.get('nthash', ''),
        }
        # Only create a new loot dir if there isn't one already
        if not _scan_state.get('loot_dir'):
            loot_dir = os.path.join(_LOOT_BASE, scan_ts)
            os.makedirs(loot_dir, exist_ok=True)
            _scan_state['loot_dir'] = loot_dir
    return jsonify({'ok': True, 'loot_dir': _scan_state['loot_dir']})


@app.route('/api/download', methods=['POST'])
def api_download():
    """
    Fetch a file from a remote SMB share, save it under the current loot
    directory, and serve it back to the browser as an attachment.

    POST body: { "host": "...", "share": "...", "path": "...", "filename": "..." }
    """
    import eventlet.tpool

    data     = request.get_json(force=True)
    host     = data.get('host', '').strip()
    share    = data.get('share', '').strip()
    path     = data.get('path', '').strip()
    filename = data.get('filename', '').strip()

    if not all([host, share, path, filename]):
        return jsonify({'ok': False, 'error': 'host, share, path and filename are required'}), 400

    loot_dir = _scan_state.get('loot_dir')
    if not loot_dir:
        # Fallback if called outside of an active scan session
        loot_dir = os.path.join(_LOOT_BASE, 'manual')
        os.makedirs(loot_dir, exist_ok=True)

    # Mirror the UNC structure: loot/<ts>/<host>/<share>/<subpath>/
    rel_dir   = os.path.dirname(path).lstrip('\\/').replace('\\', os.sep).replace('/', os.sep)
    save_dir  = os.path.join(loot_dir, _sanitise(host), _sanitise(share), rel_dir)
    os.makedirs(save_dir, exist_ok=True)
    save_path = os.path.join(save_dir, _sanitise(filename))

    creds    = _scan_state.get('creds', {})
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

    # Record in session
    clean_path = path.lstrip('\\')
    unc_path = f"\\\\{host}\\{share}\\{clean_path}"
    if _scan_state.get('session') is not None:
        sess.mark_downloaded(_scan_state['session'], unc_path, save_path)

    return send_file(
        save_path,
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream',
    )


def _sanitise(name: str) -> str:
    """Strip characters that are unsafe in filesystem paths."""
    import re
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
    import re as _re

    # ── Resolve the log file content ────────────────────────────────────────
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
    import re as _re

    RATING_MAP = {
        'Black': 0, 'black': 0,
        'Red':   1, 'red':   1,
        'Yellow':2, 'yellow':2,
        'Green': 3, 'green': 3,
    }
    RATING_LABELS = {0: 'Black', 1: 'Red', 2: 'Yellow', 3: 'Green'}

    # ── Pattern A: ShareHunter / ShareHunter-compatible Snaffler output ──────
    # [Red](Pass-In-Code)<165B>{\\host\share\path}[matched data]
    PAT_SH = _re.compile(
        r'^\[(?P<rating>Black|Red|Yellow|Green)\]'
        r'\((?P<rule>[^)]+)\)'
        r'<(?P<size>\d+)B?>'
        r'\{(?P<unc>[^}]+)\}'
        r'(?:\[(?P<match>.*)\])?',
        _re.IGNORECASE
    )

    # ── Pattern B: Real Snaffler TSV/structured output ───────────────────────
    # [2024-01-01 12:00:00Z][Triage][Red][RuleName] {\\host\share\path} [match]
    PAT_SNAF_TS = _re.compile(
        r'^\[(?P<ts>[^\]]{10,30})\]'
        r'\[(?:Triage|triage|INFO|WARN|ERROR)?\]'
        r'\[(?P<rating>Black|Red|Yellow|Green)\]'
        r'\[(?P<rule>[^\]]+)\]\s*'
        r'\{(?P<unc>[^}]+)\}'
        r'(?:\s*\[(?P<match>.*)\])?',
        _re.IGNORECASE | _re.DOTALL
    )

    # ── Pattern C: Real Snaffler plain (no timestamp, bracket-only) ──────────
    # [0m][RuleName]  {\\host\share\path} [match]   — colour-prefix variants
    PAT_SNAF_PLAIN = _re.compile(
        r'^\[(?:0m|Black|Red|Yellow|Green|\d+m)\]'
        r'\[(?P<rule>[^\]]+)\]\s*'
        r'\{(?P<unc>[^}]+)\}'
        r'(?:\s*\[(?P<match>.*)\])?',
        _re.IGNORECASE | _re.DOTALL
    )

    # ── Pattern D: Real Snaffler console output ───────────────────────────────
    # [DOMAIN\user@host] 2026-06-18 15:12:50Z [File] {Red}<RuleName|R|regex|size|date>(\\host\share\path) match
    # Only match [File] lines (not [Share] or [Info])
    PAT_SNAF_REAL = _re.compile(
        r'^\[(?P<ctx>[^\]]+)\]\s+'                          # [DOMAIN\user@host]
        r'(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}Z)\s+'  # timestamp
        r'\[File\]\s+'                                       # [File] only
        r'\{(?P<rating>Black|Red|Yellow|Green)\}'            # {Red}
        r'<(?P<rule>[^|>]+)'                                 # <RuleName
        r'(?:\|[^|]*\|[^|]*\|(?P<size>[^|]+)\|[^>]*)?>?'   # |R|regex|size|date> (optional)
        r'\((?P<unc>[^)]+)\)'                                # (\\host\share\path)
        r'(?:\s+(?P<match>.+))?',                            # match text
        _re.IGNORECASE
    )

    def _split_unc(unc: str):
        unc = unc.lstrip('\\').lstrip('/')
        parts = _re.split(r'[/\\]', unc, maxsplit=2)
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
            rating_label = RATING_LABELS.get(RATING_MAP.get(m.group('rating'), 3), 'Green')
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
                'matched_line': (m.group('match') or '').strip('﻿'),
                'timestamp':    '',
                'source':       'sharehunter',
            })
            continue

        m = PAT_SNAF_TS.match(line)
        if m:
            rating_label = RATING_LABELS.get(RATING_MAP.get(m.group('rating'), 3), 'Green')
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
                'matched_line': (m.group('match') or '').strip('﻿'),
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
                'matched_line': (m.group('match') or '').strip('﻿'),
                'timestamp':    '',
                'source':       'snaffler',
            })
            continue

        m = PAT_SNAF_REAL.match(line)
        if m:
            rating     = RATING_MAP.get(m.group('rating'), 3)
            rating_lbl = RATING_LABELS.get(rating, 'Green')
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


def start_gui(host='127.0.0.1', port=5005, debug=False):
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False)
