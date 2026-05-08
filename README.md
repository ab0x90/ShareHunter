# ShareHunter

A Python reimplementation of [Snaffler](https://github.com/SnaffCon/Snaffler) with a real-time web GUI. Scans SMB shares across a network or Active Directory domain, triages files by sensitivity, and streams findings to a browser as they are discovered.

---

## Features

- **Real-time web GUI** — findings stream live to the browser via WebSocket with HTTP polling fallback (works over SSH tunnels)
- **Snaffler-compatible output** — log files match the `[Rating](Rule)<Size>{\\UNC\Path}[match]` format and can be grepped/filtered the same way
- **Domain enumeration** — enumerate all computer objects from a DC via LDAP and scan them all automatically
- **Pass-the-hash** — authenticate with an NT hash instead of a password
- **Session persistence** — every scan writes a session file; if the process is killed mid-scan, Resume in the browser reloads prior results and continues scanning pending hosts
- **In-browser file download** — download any finding directly from the SMB share to your loot directory with a single click
- **Filter tab** — search, filter by host/share/rating, sort by any column, export to CSV
- **CLI-only mode** — colourised terminal output with no web server if preferred

---

## Installation

```bash
git clone <repo>
cd sharehunter
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Activate the virtualenv before every use:

```bash
source venv/bin/activate
```

---

## Usage

### GUI only (enter scan details in the browser)

```bash
python sharehunter.py
# Open http://127.0.0.1:5005
```

### Scan a single host or CIDR range

```bash
python sharehunter.py -t 192.168.1.0/24 -u administrator -p 'Password1' -d CORP
python sharehunter.py -t dc01.corp.local -u administrator -p 'Password1' -d CORP
```

### Enumerate all domain computers from a DC and scan them all

```bash
python sharehunter.py --target-domain dc01.corp.local -u administrator -p 'Password1' -d CORP
```

### Pass-the-hash

```bash
python sharehunter.py -t 192.168.1.10 -u administrator --nthash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -d CORP
```

### CLI only (no web GUI)

```bash
python sharehunter.py -t 192.168.1.10 -u administrator -p 'Password1' -d CORP --nogui
```

### Custom log file path

```bash
python sharehunter.py -t 192.168.1.10 -u administrator -p 'Password1' -d CORP -o /tmp/scan.log
```

### All options

```
-t, --target           Target: single IP, CIDR range, hostname, or path to a file of targets
    --target-domain    DC hostname/IP — enumerate all computer objects via LDAP
-u, --username         Username
-p, --password         Password
-d, --domain           Domain (NETBIOS or FQDN)
    --nthash           NT hash for pass-the-hash
    --host-threads     Concurrent hosts to scan at once (default: 5)
    --share-threads    Concurrent shares per host (default: 10)
    --depth            Max directory depth (default: 10)
    --nogui            Disable web GUI — terminal output only
    --port             Web GUI port (default: 5005)
-v, --verbose          Verbose log output
-o, --output           Log file path (default: logs/sharehunter_YYYYMMDD_HHMMSS.log)
```

---

## Web GUI

Open `http://127.0.0.1:5005` in a browser after starting the tool.

### Live Output tab

- Fill in target, credentials, and threading options, then click **Start**
- Findings stream in real time as the scan runs, colour-coded by rating
- Log messages (connection status, errors, share names) appear inline
- **Stop** halts the scan gracefully

### Filter Results tab

- Full-text search across path, filename, matched content, and rule name
- Filter by host, share, and/or rating (Black / Red / Yellow / Green pills)
- Click any column header to sort
- Click any row to open a detail modal with the full UNC path and matched content
- **Download** button fetches the file from the SMB share directly to `loot/<timestamp>/<host>/<share>/` and serves it to the browser
- **CSV export** of the current filtered view

### Session resume

When the tool starts with no active scan and session files exist, a banner appears at the top of the page with a dropdown listing all prior sessions (newest first, showing date, user, target, and result count).

Selecting a session and clicking **Resume**:
1. Loads all prior results into the display immediately
2. Checks which hosts were not completed when the process was killed
3. Relaunches the scan against those pending hosts using the stored credentials
4. New findings stream in on top of the prior results

If the scan was already complete when the session is loaded, results are displayed and no new scan is started.

---

## Output

### Log files

By default a log file is written to `logs/sharehunter_YYYYMMDD_HHMMSS.log` for each scan. Resumed scans append to a separate `sharehunter_<id>_resumed.log`. The format is identical to Snaffler's output:

```
[Black](KeePass-DB)<45056B>{\\dc01.corp.local\IT\credentials.kdbx}
[Red](Unattend-XML)<8192B>{\\fileserver\SYSVOL\unattend.xml}[<Password>hunter2</Password>]
[Yellow](Web-Config)<2048B>{\\webserver\wwwroot\web.config}[connectionString=...]
[Green](LogFiles)<512B>{\\server\logs\app.log}
```

Filter the log the same way as a real Snaffler run:

```bash
grep '^\[Black\]' logs/sharehunter_*.log
grep '^\[Red\]\|\[Black\]' logs/sharehunter_*.log
grep 'password' logs/sharehunter_*.log -i
```

### Loot directory

Downloaded files are saved to `loot/<scan_timestamp>/<host>/<share>/<path>/`. The directory structure mirrors the UNC path so files are easy to locate.

### Session files

Session state is written to `sessions/<scan_id>.session.json` after every 25 results and after each host completes. The file stores credentials, scan parameters, all results, completed/pending hosts, and download records. It is used automatically by the Resume feature.

---

## Detection rules

Rules are modelled after Snaffler's built-in ruleset. Each finding is rated on a four-tier scale:

| Rating | Colour | Meaning |
|--------|--------|---------|
| **Black** | Purple | Almost certainly credential material — KeePass databases, private keys, NTDS.dit, SAM/SYSTEM hives, BitLocker keys, RDP files |
| **Red** | Red | High-confidence secrets — unattend.xml, .env files, password documents, Ansible vaults, Terraform vars, hardcoded credentials in content |
| **Yellow** | Yellow | Likely sensitive — configuration files, connection strings, SSH keys in known paths, IIS/Apache/Tomcat configs, cloud credential files |
| **Green** | Green | Worth reviewing — log files, backup files, scripts, certificate files, Office documents |

Rules match on:
- **Filename** — exact name patterns (e.g. `unattend.xml`, `id_rsa`)
- **Extension** — file extension (e.g. `.kdbx`, `.pfx`, `.rdp`)
- **Content** — regex scan of file contents for passwords, connection strings, API keys, tokens (files up to 512 KB, binary extensions skipped)
- **Path** — directory path patterns

63 filename/extension rules and 49 content rules are included, sourced directly from Snaffler's default ruleset.

---

## Architecture

```
sharehunter.py          Entry point — argument parsing, CLI/GUI mode selection
snaffler/
  app.py               Flask + SocketIO web server, REST API, download handler
  scanner.py           SMB connection, share enumeration, file walker, triage engine
  rules.py             Classification rules (filename, extension, content, path)
  domain_enum.py       LDAP enumeration of AD computer objects
  session.py           Session persistence (sessions/<id>.session.json)
templates/index.html   Single-page web GUI
logs/                  Scan log files (Snaffler format)
loot/                  Downloaded files, mirroring UNC path structure
sessions/              JSON session files for crash recovery
```

The scanner runs in a background thread. Results are pushed to the browser over WebSocket (`socket.io`) and also available via `/api/results` for the polling fallback. All blocking SMB operations run in a real OS thread via `eventlet.tpool` so the cooperative scheduler is never starved.

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | `{ running, count }` |
| GET | `/api/results` | All results for the current scan |
| GET | `/api/logs` | All log messages for the current scan |
| GET | `/api/session-list` | All saved sessions, newest first |
| POST | `/api/start` | Start a scan (JSON body with target/creds/params) |
| POST | `/api/stop` | Stop the running scan |
| POST | `/api/session-resume` | Load a session and resume scanning pending hosts |
| POST | `/api/download` | Fetch a file from SMB and serve it as an attachment |
| POST | `/api/set-creds` | Inject credentials into a running GUI session |

---

## Requirements

- Python 3.10+
- Linux (tested on Kali)
- Network access to port 445 on target hosts
- SMB credentials (password or NT hash) with at least read access to shares

Python dependencies: `flask`, `flask-socketio`, `eventlet`, `impacket`, `ldap3`, `dnspython`

---

## Differences from Snaffler

| | Snaffler | ShareHunter |
|---|---|---|
| Language | C# / .NET | Python |
| GUI | None | Real-time web GUI |
| Output | Terminal + log file | Terminal + log file + web stream |
| Session recovery | No | Yes — resume interrupted scans |
| File download | No | Yes — in-browser, saved to loot dir |
| Platform | Windows (or .NET on Linux) | Linux / any Python 3.10+ host |
| Rule count | ~200+ | 112 (63 filename + 49 content, full default ruleset) |

The log file output format is identical so existing tooling and grep patterns work unchanged.
