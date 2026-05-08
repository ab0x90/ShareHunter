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

from snaffler.rules import RATING_LABELS, RATING_COLORS
from snaffler import session as sess

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
    from snaffler.scanner import ShareHunter

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
                _scan_state['running']  = False
                _scan_state['snaffler'] = None
                sess.mark_ended(s)
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
    from snaffler.scanner import ShareHunter
    from snaffler.domain_enum import get_domain_computers
    data = request.get_json(force=True)

    target        = data.get('target', '').strip()
    target_domain = data.get('target_domain', '').strip()
    username      = data.get('username', '').strip()
    password      = data.get('password', '')
    domain        = data.get('domain', '').strip()
    nthash        = data.get('nthash', '').strip()
    host_threads  = int(data.get('host_threads', 5))
    share_threads = int(data.get('share_threads', 10))
    depth         = int(data.get('depth', 10))

    if not (target or target_domain) or not username:
        return jsonify({'ok': False, 'error': 'target (or target-domain) and username are required'})

    if _scan_state['running']:
        return jsonify({'ok': False, 'error': 'Scan already running'})

    # Create a timestamped loot directory for this scan
    scan_ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
    loot_dir = os.path.join(_LOOT_BASE, scan_ts)
    os.makedirs(loot_dir, exist_ok=True)

    creds = {
        'username': username,
        'password': password,
        'domain':   domain,
        'nthash':   nthash,
    }
    params = {
        'target':        target,
        'target_domain': target_domain,
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

    def run_scan():
        # Open a log file for this browser-initiated scan
        os.makedirs(_LOGS_BASE, exist_ok=True)
        log_path = os.path.join(_LOGS_BASE, f'sharehunter_{scan_ts}.log')
        log_fh = open(log_path, 'a', encoding='utf-8', buffering=1)

        def result_cb(result):
            log_fh.write(result.to_snaffler_line() + '\n')
            _result_callback(result)

        def log_cb(msg, level='info'):
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
                    domain=domain, nthash=nthash, log_callback=log_cb,
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
            _scan_state['running'] = False
            _scan_state['snaffler'] = None
            if _scan_state.get('session') is not None:
                sess.mark_ended(_scan_state['session'])
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
        results = list(_scan_state['results'])
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
    return jsonify(results)


@app.route('/api/status')
def api_status():
    with _scan_state['lock']:
        count = len(_scan_state['results'])
    return jsonify({'running': _scan_state['running'], 'count': count})


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
        conn = SMBConnection(host, host, sess_port=445, timeout=15)
        if nthash:
            lm = 'aad3b435b51404eeaad3b435b51404ee'
            conn.login(username, '', domain, lmhash=lm, nthash=nthash)
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
    unc_path = f"\\\\{host}\\{share}\\{path.lstrip('\\')}"
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


def start_gui(host='127.0.0.1', port=5005, debug=False):
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False)
