# ShareHunter

A Python reimplementation of [Snaffler](https://github.com/SnaffCon/Snaffler), split into two independent tools: a credentialed CLI scanner with a live terminal dashboard, and a read-only web viewer for browsing the results. Scans SMB shares across a network or Active Directory domain and triages files by sensitivity.

---

## Two tools, one loot folder

- **`sharehunter_scan.py`** does the actual scanning. CLI-only, credentials required, no web server. Shows a live terminal dashboard (progress bar, ETA, hosts in-flight, findings by rating) while it runs, and writes everything to `sessions/<scan_id>.session.json` and `loot/<scan_id>/`.
- **`sharehunter_web.py`** never scans anything. It's a read-only viewer that loads a session from disk (a static snapshot — pick a session, see its results, done) and lets you filter, sort, download findings, and export CSV. It also runs the ManSpider loot-watch mode, which is a live filesystem poller independent of whatever session is loaded.

The two only ever talk to each other through the `sessions/`/`loot/`/`logs/` folders on disk — run the scanner wherever you have network access to the targets, and view the results wherever's convenient (they don't need to be the same host, as long as the folders are shared/synced).

---

## Features

- **Live terminal dashboard while scanning** — progress bar, ETA, hosts completed/in-flight, findings by rating, recent findings/errors, powered by `rich`
- **Snaffler-compatible output** — log files match the `[Rating](Rule)<Size>{\\UNC\Path}[match]` format
- **Domain enumeration** — enumerate all computer objects from a DC via LDAP/LDAPS; auto-falls back to LDAPS if plain LDAP is rejected
- **Kerberos authentication** — full Kerberos support for both LDAP enumeration and SMB connections; obtains a TGT automatically from supplied credentials if no ccache exists
- **Pass-the-hash** — authenticate with an NT hash instead of a password
- **Session persistence + resume** — every scan writes a session file; `--resume <scan_id>` continues scanning any hosts left pending if the process was killed mid-scan
- **In-browser file download** — download any finding directly from the SMB share to your loot directory with a single click
- **Log viewer** — upload and parse any Snaffler or ShareHunter log file via the browser for offline review
- **Filter/sort/search/export** — filter by host/share/rating, sort by any column, full-text search, CSV export
- **ManSpider loot-watch mode** — watch a [ManSpider](https://github.com/blacklanternsecurity/MANSPIDER) loot directory and triage files it's already pulled down, using the same rule set
- **SMB connection pooling** — connections are reused across share workers per host, reducing TCP handshake overhead on large scans

---

## Installation

```bash
git clone <repo>
cd ShareHunter
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
source venv/bin/activate
```

A venv is recommended — `eventlet` (used by the web viewer) can conflict with a system-installed `dnspython`/`trio` combination if installed outside an isolated environment.

---

## Scanning: `sharehunter_scan.py`

Credentials are required — this tool only scans, it doesn't offer a "fill in the browser" flow.

### Scan a single host or CIDR range

```bash
python3 sharehunter_scan.py -t 192.168.1.0/24 -u administrator -p 'Password1' -d CORP
```

### Enumerate all domain computers from a DC and scan them all

```bash
python3 sharehunter_scan.py --target-domain dc01.corp.local -u administrator -p 'Password1' -d CORP
# also accepts an IP — tool resolves the DC hostname automatically for Kerberos SPNs
python3 sharehunter_scan.py --target-domain 192.168.56.11 -u administrator -p 'Password1' -d corp.local
```

### Kerberos authentication

```bash
# Use existing ccache (KRB5CCNAME)
python3 sharehunter_scan.py --target-domain dc01.corp.local -u user -d corp.local -k

# Obtain TGT automatically from password
python3 sharehunter_scan.py --target-domain dc01.corp.local -u user -p 'Password1' -d corp.local -k

# AES key (implies --kerberos)
python3 sharehunter_scan.py --target-domain dc01.corp.local -u user --aes-key <hex> -d corp.local

# With a specific DC IP (useful when DNS is unreliable)
python3 sharehunter_scan.py --target-domain dc01.corp.local -u user -p 'Password1' -d corp.local -k --dc-ip 192.168.56.11
```

### Force LDAPS for domain enumeration

```bash
python3 sharehunter_scan.py --target-domain dc01.corp.local -u administrator -p 'Password1' -d CORP --ldaps
```

### Pass-the-hash

```bash
python3 sharehunter_scan.py -t 192.168.1.10 -u administrator --nthash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -d CORP
```

### Resume an interrupted scan

```bash
python3 sharehunter_scan.py --resume 20260804_120000
```

### Custom log file path

```bash
python3 sharehunter_scan.py -t 192.168.1.10 -u administrator -p 'Password1' -d CORP -o /tmp/scan.log
```

### All options

```
targeting (one required):
  -t, --target           Target: single IP, CIDR range, hostname, or path to a file of targets
      --target-domain    DC hostname/IP — enumerate all computer objects via LDAP then scan them

credentials (username + one of password/nthash/kerberos/aes-key required):
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

resume / output:
      --resume SCAN_ID   Resume a previous session's pending (incomplete) hosts
  -o, --output           Log file path (default: logs/sharehunter_YYYYMMDD_HHMMSS.log)
```

---

## Viewing results: `sharehunter_web.py`

Never scans anything — purely a read-only viewer over the `sessions/`/`loot/` folders.

```bash
# Start with nothing loaded — pick a session from the browser's dropdown
python3 sharehunter_web.py

# Load the most recently *started* session at startup
# (resolves once, at startup — a scan started afterward won't auto-appear;
# pick it from the dropdown, or restart the web viewer)
python3 sharehunter_web.py --latest

# Load a specific session at startup
python3 sharehunter_web.py --session 20260804_120000

# Custom bind address / port
python3 sharehunter_web.py --host 0.0.0.0 --port 8080
```

Open `http://127.0.0.1:5005` (or your chosen host/port) in a browser.

### Session viewing

A session is a **static snapshot** — whatever was on disk the moment it was loaded. There's no auto-refresh; if the scan is still running elsewhere, reselect the session from the header dropdown (or reload the page) to pick up new results. The dropdown lists every session in `sessions/`, newest first, with target/date/result-count and an `[incomplete]` marker if the scan hasn't finished.

From the results table you can:
- Full-text search across path, filename, matched content, and rule name
- Filter by host, share, and/or rating (Black / Red / Yellow / Green)
- Click any column header to sort
- Click any row to open a detail modal with the full UNC path and matched content
- **Get** — fetches the file from the SMB share directly to `loot/<scan_id>/<host>/<share>/` and serves it to the browser, using the credentials stored in that session
- **CSV export** of the current filtered view

### ManSpider Loot mode

Toggle to "ManSpider Loot" to watch a [ManSpider](https://github.com/blacklanternsecurity/MANSPIDER) loot directory (default `~/.manspider/loot`) and triage files it's already pulled down, using the same rule set as a live scan. This is the one part of the web viewer that's genuinely live — new files are picked up and pushed to the browser as they're found, independent of whatever session (if any) is loaded.

### Log Viewer

Accessible via the **Log Viewer** link in the header — a separate, fully offline tool. Upload any Snaffler or ShareHunter log file from disk and its findings are parsed into the same filterable table. Supports:

- ShareHunter format: `[Red](Rule)<165B>{\\host\share\path}[match]`
- Snaffler console format: `[DOMAIN\user@host] 2026-01-01 12:00:00Z [File] {Red}<Rule|...>(\\host\share\path) match`
- Snaffler structured format: `[timestamp][Triage][Red][Rule] {\\host\share\path} [match]`

---

## Output

### Log files

Written to `logs/sharehunter_YYYYMMDD_HHMMSS.log` by `sharehunter_scan.py`. Format is identical to Snaffler:

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

Downloaded files are saved to `loot/<scan_id>/<host>/<share>/<path>/`, mirroring the UNC path.

### Session files

Written to `sessions/<scan_id>.session.json` by `sharehunter_scan.py`. Stores credentials, scan parameters, all results, completed/pending hosts, download records, and a periodic heartbeat timestamp (diagnostic only — a "last seen" marker, not consumed programmatically by the web viewer). Saves every 50 results and every 10 completed hosts, with a guaranteed final flush on scan completion. Used by `--resume`.

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
sharehunter_scan.py      Scan entry point — credentialed CLI, rich terminal dashboard
sharehunter_web.py        Web viewer entry point — read-only, no scanning
sharehunter/
  app.py                 Flask + SocketIO web server backing sharehunter_web.py
  scanner.py              SMB connection pool, share enumeration, file walker, triage engine
  rules.py                 Classification rules (filename, extension, content, path)
  domain_enum.py            LDAP/LDAPS enumeration of AD computer objects (NTLM + Kerberos)
  session.py                 Session persistence (sessions/<id>.session.json)
  manspider_watch.py          Polls a manspider loot dir, triages new/changed files
templates/
  index.html               Web viewer page (results table + ManSpider controls)
  log_viewer.html           Offline log file viewer
logs/                     Scan log files (Snaffler format), written by sharehunter_scan.py
loot/                     Downloaded files, mirroring UNC path structure
sessions/                 JSON session files, written by sharehunter_scan.py
```

`sharehunter_scan.py` and `sharehunter_web.py` are independent processes with no shared runtime state — everything that crosses between them goes through the `sessions/`/`loot/`/`logs/` folders. They can run on different hosts as long as those folders are shared (e.g. an NFS/SMB mount).

---

## API endpoints (sharehunter_web.py)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | `{ loaded, complete, count, scan_id, session_id, target, hosts_total, hosts_completed }` for the loaded session, or `{ running, count, mode: 'manspider' }` with `?mode=manspider` |
| GET | `/api/results` | `{ scan_id, results }` — all results for the loaded session (or `?mode=manspider`) |
| GET | `/api/session-list` | All saved sessions, newest first |
| POST | `/api/session-load` | Load a session read-only for viewing (JSON body: `{ scan_id }`) |
| POST | `/api/download` | Fetch a file from SMB and serve it as an attachment |
| POST | `/api/manspider-start` | Start watching a manspider loot directory |
| POST | `/api/manspider-stop` | Stop the manspider watcher |
| GET | `/api/log-list` | All log files in the logs directory |
| POST | `/api/parse-log` | Parse a Snaffler/ShareHunter log file (path or file upload) — backs the offline Log Viewer |

---

## Requirements

- Python 3.10+
- Linux (tested on Kali)
- Network access to port 445 on target hosts (for `sharehunter_scan.py`)
- SMB credentials (password, NT hash, or Kerberos) with at least read access to shares
- For Kerberos: DNS must resolve the DC hostname, or use `--dc-ip`

Python dependencies: `flask`, `flask-socketio`, `eventlet`, `impacket`, `ldap3`, `rich`

---

## Differences from Snaffler

| | Snaffler | ShareHunter |
|---|---|---|
| Language | C# / .NET | Python |
| Scan progress | Terminal only | Live terminal dashboard (progress bar, ETA, findings by rating) |
| Results viewing | Terminal + log file | Terminal + log file + separate web viewer |
| Session recovery | No | Yes — `--resume` continues an interrupted scan |
| File download | No | Yes — from the web viewer, saved to loot dir |
| Log viewer | No | Yes — parse any Snaffler/ShareHunter log offline |
| Kerberos | Yes | Yes — auto TGT acquisition, no ccache required |
| LDAPS | Yes | Yes — auto-fallback from plain LDAP |
| Platform | Windows (or .NET on Linux) | Linux / any Python 3.10+ host |
| Rule count | ~200+ | 112 (63 filename + 49 content, full default ruleset) |

The log file output format is identical so existing tooling and grep patterns work unchanged.
