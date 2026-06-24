# ShareHunter

A Python reimplementation of [Snaffler](https://github.com/SnaffCon/Snaffler) with a real-time web GUI. Scans SMB shares across a network or Active Directory domain, triages files by sensitivity, and streams findings to a browser as they are discovered.

---

## Features

- **Real-time web GUI** — findings stream live to the browser via WebSocket with HTTP polling fallback (works over SSH tunnels)
- **Snaffler-compatible output** — log files match the `[Rating](Rule)<Size>{\\UNC\Path}[match]` format
- **Domain enumeration** — enumerate all computer objects from a DC via LDAP/LDAPS; auto-falls back to LDAPS if plain LDAP is rejected
- **Kerberos authentication** — full Kerberos support for both LDAP enumeration and SMB connections; obtains a TGT automatically from supplied credentials if no ccache exists
- **Pass-the-hash** — authenticate with an NT hash instead of a password
- **LDAPS / channel binding** — force LDAPS with `--ldaps`, or let the tool auto-detect and fall back
- **Session persistence** — every scan writes a session file; if the process is killed mid-scan, Resume in the browser reloads prior results and continues scanning pending hosts
- **In-browser file download** — download any finding directly from the SMB share to your loot directory with a single click
- **Log viewer** — upload and parse any Snaffler or ShareHunter log file via the browser for offline review
- **Filter tab** — search, filter by host/share/rating, sort by any column, export to CSV
- **CLI-only mode** — colourised terminal output with no web server if preferred
- **SMB connection pooling** — connections are reused across share workers per host, reducing TCP handshake overhead on large scans

---

## Installation

```bash
git clone <repo>
cd ShareHunter
pip install -r requirements.txt
```

---

## Usage

### GUI only (enter scan details in the browser)

```bash
python3 sharehunter.py
# Open http://127.0.0.1:5005
```

### Scan a single host or CIDR range

```bash
python3 sharehunter.py -t 192.168.1.0/24 -u administrator -p 'Password1' -d CORP
python3 sharehunter.py -t dc01.corp.local -u administrator -p 'Password1' -d CORP
```

### Enumerate all domain computers from a DC and scan them all

```bash
python3 sharehunter.py --target-domain dc01.corp.local -u administrator -p 'Password1' -d CORP
# also accepts an IP — tool resolves the DC hostname automatically for Kerberos SPNs
python3 sharehunter.py --target-domain 192.168.56.11 -u administrator -p 'Password1' -d corp.local
```

### Kerberos authentication

```bash
# Use existing ccache (KRB5CCNAME)
python3 sharehunter.py --target-domain dc01.corp.local -u user -d corp.local -k

# Obtain TGT automatically from password
python3 sharehunter.py --target-domain dc01.corp.local -u user -p 'Password1' -d corp.local -k

# AES key (implies --kerberos)
python3 sharehunter.py --target-domain dc01.corp.local -u user --aes-key <hex> -d corp.local

# With a specific DC IP (useful when DNS is unreliable)
python3 sharehunter.py --target-domain dc01.corp.local -u user -p 'Password1' -d corp.local -k --dc-ip 192.168.56.11
```

### Force LDAPS for domain enumeration

```bash
python3 sharehunter.py --target-domain dc01.corp.local -u administrator -p 'Password1' -d CORP --ldaps
```

### Pass-the-hash

```bash
python3 sharehunter.py -t 192.168.1.10 -u administrator --nthash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -d CORP
```

### CLI only (no web GUI)

```bash
python3 sharehunter.py -t 192.168.1.10 -u administrator -p 'Password1' -d CORP --nogui
```

### Custom log file path

```bash
python3 sharehunter.py -t 192.168.1.10 -u administrator -p 'Password1' -d CORP -o /tmp/scan.log
```

### All options

```
positional / targeting:
  -t, --target           Target: single IP, CIDR range, hostname, or path to a file of targets
      --target-domain    DC hostname/IP — enumerate all computer objects via LDAP then scan them

credentials:
  -u, --username         Username
  -p, --password         Password
  -d, --domain           Domain (NETBIOS or FQDN)
      --nthash           NT hash for pass-the-hash (LM:NT or :NT or NT)

authentication / transport:
  -k, --kerberos         Use Kerberos for LDAP enumeration and SMB connections
      --aes-key HEX      AES-128 or AES-256 session key (implies --kerberos)
      --dc-ip IP         Pin a specific DC IP for Kerberos / LDAP
      --ldaps            Force LDAPS (port 636); default: try plain LDAP, auto-fall back

scan tuning:
      --host-threads     Concurrent hosts (default: 5)
      --share-threads    Concurrent shares per host (default: 10)
      --depth            Max directory depth (default: 10)

output:
      --nogui            Disable web GUI — terminal output only
      --port             Web GUI port (default: 5005)
  -v, --verbose          Verbose log output
  -o, --output           Log file path (default: logs/sharehunter_YYYYMMDD_HHMMSS.log)
```

---

## Web GUI

Open `http://127.0.0.1:5005` in a browser after starting the tool.

### Mode toggle

The **Host/CIDR** and **Domain enum** toggle sits in the tab bar and is always visible. Select a mode before starting a scan. The toggle is locked while a scan is running — stop the scan first to switch modes. If the page is refreshed during a scan, the active mode and target are restored automatically.

### Live Output tab

- Fill in target, credentials, and threading options, then click **Start**
- Findings stream in real time as the scan runs, colour-coded by rating
- Log messages (connection status, errors, share names) appear inline
- Credentials supplied via CLI are pre-filled automatically (passwords are masked and sent as a sentinel — never exposed in the page source)
- **Stop** halts the scan gracefully

### Filter Results tab

- Full-text search across path, filename, matched content, and rule name
- Filter by host, share, and/or rating (Black / Red / Yellow / Green)
- Click any column header to sort
- Click any row to open a detail modal with the full UNC path and matched content
- **Download** button fetches the file from the SMB share directly to `loot/<timestamp>/<host>/<share>/` and serves it to the browser
- **CSV export** of the current filtered view

### Log Viewer

Accessible via the **Log Viewer** link in the header. Upload any Snaffler or ShareHunter log file from disk — findings are parsed and displayed in the same filterable table as a live scan. Supports:

- ShareHunter format: `[Red](Rule)<165B>{\\host\share\path}[match]`
- Snaffler console format: `[DOMAIN\user@host] 2026-01-01 12:00:00Z [File] {Red}<Rule|...>(\\host\share\path) match`
- Snaffler structured format: `[timestamp][Triage][Red][Rule] {\\host\share\path} [match]`

### Session resume

When the tool starts with no active scan and session files exist, a banner appears with a dropdown listing all prior sessions (newest first). Selecting a session and clicking **Resume**:

1. Loads all prior results into the display immediately
2. Checks which hosts were not completed when the process was killed
3. Relaunches the scan against those pending hosts using the stored credentials
4. New findings stream in on top of the prior results

---

## Output

### Log files

Written to `logs/sharehunter_YYYYMMDD_HHMMSS.log`. Format is identical to Snaffler:

```
[Black](KeePass-DB)<45056B>{\\dc01.corp.local\IT\credentials.kdbx}
[Red](Unattend-XML)<8192B>{\\fileserver\SYSVOL\unattend.xml}[<Password>hunter2</Password>]
[Yellow](Web-Config)<2048B>{\\webserver\wwwroot\web.config}[connectionString=...]
[Green](LogFiles)<512B>{\\server\logs\app.log}
```

```bash
grep '^\[Black\]' logs/sharehunter_*.log
grep -i 'password' logs/sharehunter_*.log
```

### Loot directory

Downloaded files are saved to `loot/<scan_timestamp>/<host>/<share>/<path>/`, mirroring the UNC path.

### Session files

Written to `sessions/<scan_id>.session.json`. Stores credentials, scan parameters, all results, completed/pending hosts, and download records. Used by the Resume feature. Saves every 50 results and every 10 completed hosts, with a guaranteed final flush on scan completion.

---

## Detection rules

| Rating | Colour | Meaning |
|--------|--------|---------|
| **Black** | Purple | Almost certainly credential material — KeePass databases, private keys, NTDS.dit, SAM/SYSTEM hives, BitLocker keys |
| **Red** | Red | High-confidence secrets — unattend.xml, .env files, Ansible vaults, Terraform vars, hardcoded credentials in content |
| **Yellow** | Yellow | Likely sensitive — config files, connection strings, SSH keys, IIS/Apache/Tomcat configs, cloud credential files |
| **Green** | Green | Worth reviewing — log files, backup files, scripts, certificate files, Office documents |

Rules match on filename, extension, content (files up to 512 KB), and path. 63 filename/extension rules and 49 content rules are included, sourced from Snaffler's default ruleset.

---

## Architecture

```
sharehunter.py          Entry point — argument parsing, CLI/GUI mode selection
sharehunter/
  app.py               Flask + SocketIO web server, REST API, download handler, log parser
  scanner.py           SMB connection pool, share enumeration, file walker, triage engine
  rules.py             Classification rules (filename, extension, content, path)
  domain_enum.py       LDAP/LDAPS enumeration of AD computer objects (NTLM + Kerberos)
  session.py           Session persistence (sessions/<id>.session.json)
templates/
  index.html           Single-page web GUI
  log_viewer.html      Offline log file viewer
logs/                  Scan log files (Snaffler format)
loot/                  Downloaded files, mirroring UNC path structure
sessions/              JSON session files for crash recovery
```

The scanner runs in a background thread. Results are pushed to the browser over WebSocket and also available via `/api/results` for the polling fallback. Per-host, a connection pool is maintained across share workers so SMB sessions are reused rather than re-established for each share.

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | `{ running, count, scan_id, mode, target, target_domain }` |
| GET | `/api/results` | `{ scan_id, results }` — all results for the current scan |
| GET | `/api/logs` | All log messages for the current scan |
| GET | `/api/prefill` | CLI-supplied credentials and params for GUI pre-population |
| GET | `/api/session-list` | All saved sessions, newest first |
| GET | `/api/log-list` | All log files in the logs directory |
| POST | `/api/start` | Start a scan (JSON body with target/creds/params) |
| POST | `/api/stop` | Stop the running scan |
| POST | `/api/session-resume` | Load a session and resume scanning pending hosts |
| POST | `/api/download` | Fetch a file from SMB and serve it as an attachment |
| POST | `/api/parse-log` | Parse a Snaffler/ShareHunter log file (path or file upload) |

---

## Requirements

- Python 3.10+
- Linux (tested on Kali)
- Network access to port 445 on target hosts
- SMB credentials (password, NT hash, or Kerberos) with at least read access to shares
- For Kerberos: DNS must resolve the DC hostname, or use `--dc-ip`

Python dependencies: `flask`, `flask-socketio`, `eventlet`, `impacket`, `ldap3`

---

## Differences from Snaffler

| | Snaffler | ShareHunter |
|---|---|---|
| Language | C# / .NET | Python |
| GUI | None | Real-time web GUI |
| Output | Terminal + log file | Terminal + log file + web stream |
| Session recovery | No | Yes — resume interrupted scans |
| File download | No | Yes — in-browser, saved to loot dir |
| Log viewer | No | Yes — parse any Snaffler/ShareHunter log offline |
| Kerberos | Yes | Yes — auto TGT acquisition, no ccache required |
| LDAPS | Yes | Yes — auto-fallback from plain LDAP |
| Platform | Windows (or .NET on Linux) | Linux / any Python 3.10+ host |
| Rule count | ~200+ | 112 (63 filename + 49 content, full default ruleset) |

The log file output format is identical so existing tooling and grep patterns work unchanged.
