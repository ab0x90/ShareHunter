"""
ShareHunter classification rules — faithfully ported from Snaffler's default TOML ruleset.

Rating scale (matches Snaffler exactly):
  0 = Black  — critical, almost certainly credential material
  1 = Red    — high confidence secrets / sensitive data
  2 = Yellow — likely sensitive, worth reviewing
  3 = Green  — possibly interesting

Rules are sourced from:
  https://github.com/SnaffCon/Snaffler/tree/master/Snaffler/SnaffRules/DefaultRules
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SnaffleRule:
    name:        str
    rating:      int          # 0=Black 1=Red 2=Yellow 3=Green
    match_type:  str          # 'filename' | 'extension' | 'path' | 'content'
    pattern:     str
    description: str
    regex: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        self.regex = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)


RATING_LABELS = {0: "Black", 1: "Red", 2: "Yellow", 3: "Green"}
RATING_COLORS = {0: "#1a1a2e", 1: "#e74c3c", 2: "#f39c12", 3: "#27ae60"}

# ── Skip extensions (Snaffler DiscardByFileExtension) ────────────────────────
SKIP_EXTENSIONS = {
    '.bmp', '.eps', '.gif', '.ico', '.jfi', '.jfif', '.jif', '.jpe',
    '.jpeg', '.jpg', '.png', '.psd', '.svg', '.tif', '.tiff', '.webp',
    '.xcf', '.ttf', '.otf', '.lock', '.css', '.less', '.admx', '.adml',
    '.xsd', '.nse', '.xsl',
    # Additional binary formats not worth grepping
    '.exe', '.dll', '.sys', '.mui', '.mp4', '.mp3', '.avi', '.mov',
    '.wmv', '.zip', '.gz', '.tar', '.7z', '.rar', '.iso', '.img',
    '.lnk', '.woff', '.woff2', '.eot', '.msi', '.cab',
}

# ── Skip path fragments (Snaffler DiscardLargeFalsePosDirs) ──────────────────
SKIP_PATH_FRAGMENTS = [
    re.compile(p, re.IGNORECASE) for p in [
        r'\\puppet\\share\\doc',
        r'\\lib\\ruby',
        r'\\lib\\site-packages',
        r'\\usr\\share\\doc',
        r'node_modules',
        r'vendor\\bundle',
        r'vendor\\cache',
        r'\\doc\\openssl',
        r'Anaconda3\\Lib\\test',
        r'WindowsPowerShell\\Modules',
        r'Python\\\d+\\Lib',
        r'Reference Assemblies\\Microsoft\\Framework\\.NETFramework',
        r'dotnet\\sdk',
        r'dotnet\\shared',
        r'Modules\\Microsoft\.PowerShell\.Security',
        r'Windows\\assembly',
    ]
]


def should_skip_path(path: str) -> bool:
    for pat in SKIP_PATH_FRAGMENTS:
        if pat.search(path):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# FILENAME RULES  (match_type = 'filename' | 'extension' | 'path')
# ─────────────────────────────────────────────────────────────────────────────
FILENAME_RULES = [

    # ── BLACK: Password managers (KeepPassMgrsByExtension) ───────────────────
    SnaffleRule("KeePass-DB",        0, "extension", r"\.(kdbx|kdb)$",
                "KeePass database"),
    SnaffleRule("PasswordSafe",      0, "extension", r"\.psafe3$",
                "Password Safe database"),
    SnaffleRule("KWallet",           0, "extension", r"\.kwallet$",
                "KDE Wallet"),
    SnaffleRule("AppleKeychain",     0, "extension", r"\.(keychain|agilekeychain)$",
                "Apple Keychain / 1Password vault"),
    SnaffleRule("CredFile",          0, "extension", r"\.cred$",
                "Credential file"),

    # ── BLACK: SSH keys (KeepSSHFilesByFileName, KeepSSHKeysByFileExtension) ──
    SnaffleRule("SSH-Private-Key",   0, "filename",  r"^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$",
                "SSH private key"),
    SnaffleRule("SSH-PPK",           0, "extension", r"\.ppk$",
                "PuTTY private key"),
    SnaffleRule("SSH-Dir-Files",     0, "path",      r"\\.ssh\\",
                "File inside .ssh directory"),

    # ── BLACK: Cloud API keys (KeepCloudApiKeysByName, KeepCloudApiKeysByPath) ─
    SnaffleRule("Tugboat-Config",    0, "filename",  r"^\.tugboat$",
                "Tugboat cloud API key config"),
    SnaffleRule("AWS-Creds-Dir",     0, "path",      r"\\\.aws\\",
                "File inside .aws credentials directory"),
    SnaffleRule("Doctl-Config",      0, "path",      r"doctl\\config\.yaml$",
                "DigitalOcean CLI config"),

    # ── BLACK: Windows hashes (KeepWinHashesByName) ───────────────────────────
    SnaffleRule("NTDS-DIT",          0, "filename",  r"^NTDS\.DIT$",
                "Active Directory database"),
    SnaffleRule("SAM-Hive",          0, "filename",  r"^(SAM|SYSTEM|SECURITY)$",
                "Windows registry hive (SAM/SYSTEM/SECURITY)"),

    # ── BLACK: Unix hashes (KeepNixLocalHashesByName) ─────────────────────────
    SnaffleRule("Shadow-File",       0, "filename",  r"^(shadow|pwd\.db|passwd)$",
                "Unix password/shadow file"),

    # ── BLACK: Memory dumps (KeepMemDumpByName) ───────────────────────────────
    SnaffleRule("LSASS-Dump",        0, "filename",  r"^(MEMORY\.DMP|hiberfil\.sys|lsass\.dmp|lsass\.exe\.dmp)$",
                "LSASS / full memory dump"),

    # ── BLACK: Network device configs (KeepNetConfigFileByName) ──────────────
    SnaffleRule("Network-Config",    0, "filename",  r"^(running-config(\.cfg)?|startup-config(\.cfg)?)$",
                "Cisco router/switch running or startup config"),

    # ── BLACK: Remote access (KeepRemoteAccessConfByName) ────────────────────
    SnaffleRule("MobaXterm",         0, "filename",  r"^mobaxterm(\.ini| backup\.zip)$",
                "MobaXterm config/backup (stores saved passwords)"),
    SnaffleRule("RDCMan-Config",     0, "filename",  r"^confCons\.xml$",
                "Remote Desktop Connection Manager config"),

    # ── BLACK: CyberArk (KeepCyberArkConfigsByName) ───────────────────────────
    SnaffleRule("CyberArk-Creds",    0, "filename",
                r"^(Psmapp\.cred|psmgw\.cred|backup\.key|MasterReplicationUser\.pass"
                r"|RecPrv\.key|ReplicationUser\.pass|Server\.key|VaultEmergency\.pass"
                r"|VaultUser\.pass|Vault\.ini|PADR\.ini|PARAgent\.ini"
                r"|CACPMScanner\.exe\.config|PVConfiguration\.xml)$",
                "CyberArk PAM credential/config file"),

    # ── BLACK: PFX / PKCS12 certificates with private keys ───────────────────
    SnaffleRule("PKCS12-Cert",       0, "extension", r"\.(pfx|pk12|p12|pkcs12)$",
                "PKCS12 certificate with embedded private key"),

    # ── RED: Password files by exact name (KeepPasswordFilesByName) ──────────
    SnaffleRule("Password-File",     1, "filename",
                r"^(passwords?|pass|accounts?|secrets?|BitlockerLAPSPasswords)"
                r"\.(txt|doc|docx|xls|xlsx|csv)$",
                "File named after passwords/credentials"),

    # ── RED: Git credentials (KeepGitCredsByName) ─────────────────────────────
    SnaffleRule("Git-Credentials",   1, "filename",  r"^\.git-credentials$",
                "Git credential store (plaintext)"),

    # ── RED: FTP client configs (KeepFtpClientByName) ─────────────────────────
    SnaffleRule("FTP-Client-Config", 1, "filename",  r"^(recentservers\.xml|sftp-config\.json)$",
                "FTP/SFTP client saved sessions"),

    # ── RED: FTP server configs (KeepFtpServerConfigByName) ───────────────────
    SnaffleRule("FTP-Server-Config", 1, "filename",  r"^(proftpdpasswd|filezilla\.xml)$",
                "FTP server config with credentials"),

    # ── RED: DB management tools (KeepDbMgtConfigByName) ─────────────────────
    SnaffleRule("DB-Tool-Config",    1, "filename",
                r"^(SqlStudio\.bin|\.mysql_history|\.psql_history|\.pgpass"
                r"|\.dbeaver-data-sources\.xml|credentials-config\.json"
                r"|dbvis\.xml|robomongo\.json)$",
                "Database management tool config/history"),

    # ── RED: Jenkins (KeepJenkinsByName) ──────────────────────────────────────
    SnaffleRule("Jenkins-Creds",     1, "filename",
                r"^(jenkins\.plugins\.publish_over_ssh\.BapSshPublisherPlugin\.xml"
                r"|credentials\.xml)$",
                "Jenkins credential store"),

    # ── RED: Ruby config files (KeepRubyByName) ───────────────────────────────
    SnaffleRule("Ruby-Config",       1, "filename",
                r"^(database\.yml|\.secret_token\.rb|knife\.rb|carrierwave\.rb|omniauth\.rb)$",
                "Ruby/Rails sensitive config"),

    # ── RED: PHP config (KeepPhpByName) ───────────────────────────────────────
    SnaffleRule("PHP-LocalSettings", 1, "filename",  r"^LocalSettings\.php$",
                "MediaWiki LocalSettings.php (contains DB password)"),

    # ── RED: Generic config by exact name (KeepConfigByName) ─────────────────
    SnaffleRule("Htpasswd",          1, "filename",  r"^\.htpasswd$",
                "Apache htpasswd file"),
    SnaffleRule("Accounts-V4",       1, "filename",  r"^accounts\.v4$",
                "Accounts credential store"),

    # ── RED: Memory dump extension (KeepMemDumpByExtension) ───────────────────
    SnaffleRule("Memory-Dump",       1, "extension", r"\.dmp$",
                "Memory dump file"),

    # ── RED: VM disks (KeepVMDisksByExtension) ────────────────────────────────
    SnaffleRule("VM-Disk",           1, "extension", r"\.(vmdk|vdi|vhd|vhdx)$",
                "Virtual machine disk image"),

    # ── RED: Infrastructure-as-code secrets (KeepInfraAsCodeByExtension) ──────
    SnaffleRule("IaC-Config",        1, "extension", r"\.(cscfg|ucs|tfvars)$",
                "Infrastructure-as-code config (Azure .cscfg, Terraform .tfvars)"),

    # ── RED: CyberArk extension-based (KeepCyberArkByExtension) ──────────────
    SnaffleRule("CyberArk-Pass",     1, "extension", r"\.pass$",
                "CyberArk .pass file"),

    # ── RED: RDP files relayed for content check — flag by extension too ──────
    SnaffleRule("RDP-File",          1, "extension", r"\.rdp$",
                "RDP connection file (may contain saved password)"),

    # ── RED: PEM/key files (private key content checked separately) ───────────
    SnaffleRule("PEM-Key",           1, "extension", r"\.(pem|key|der)$",
                "PEM / DER / key file (check for private key content)"),

    # ── RED: Unattend XML (name match — content checked separately) ───────────
    SnaffleRule("Unattend-XML",      1, "filename",  r"^(unattend|Autounattend)\.xml$",
                "Windows unattend.xml (may contain admin password)"),

    # ── RED: SCCM boot variables (KeepSCCMBootVarCredsByPath) ────────────────
    SnaffleRule("SCCM-Variables",    1, "path",
                r"(REMINST\\SMSTemp\\.*\.var|SMS\\data\\Variables\.dat|SMS\\data\\Policy\.xml)",
                "SCCM boot variable file with credentials"),

    # ── RED: Domain join creds by path (KeepDomainJoinCredsByPath) ────────────
    SnaffleRule("MDT-CustomSettings-Path", 1, "path", r"control\\customsettings\.ini",
                "MDT customsettings.ini in deployment share"),

    # ── YELLOW: Remote access config extensions (KeepRemoteAccessConfByExtension) ─
    SnaffleRule("Remote-Access-Conf",2, "extension", r"\.(rdg|rtsz|rtsx|ovpn|tvopt|sdtid)$",
                "Remote access config file"),

    # ── YELLOW: Kerberos credentials (KeepKerberosCredentialsByExtension) ────
    SnaffleRule("Kerberos-Keytab",   2, "extension", r"\.(keytab|CCACHE)$",
                "Kerberos keytab / credential cache"),

    # ── YELLOW: Kerberos ccache files by name (KeepKerberosCredentialsByName) ─
    SnaffleRule("Kerberos-CCache",   2, "filename",  r"^krb5cc_",
                "Kerberos credential cache file"),

    # ── YELLOW: Database files (KeepDatabaseByExtension) ─────────────────────
    SnaffleRule("Database-File",     2, "extension", r"\.(mdf|sdf|sqldump|bak)$",
                "Database or backup file"),

    # ── YELLOW: Packet captures (KeepPcapByExtension) ─────────────────────────
    SnaffleRule("Packet-Capture",    2, "extension", r"\.(pcap|cap|pcapng)$",
                "Packet capture file"),

    # ── YELLOW: Deployment images (KeepDeployImageByExtension) ───────────────
    SnaffleRule("Deploy-Image",      2, "extension", r"\.(wim|ova|ovf)$",
                "Deployment/VM image"),

    # ── YELLOW: Defender config (KeepDefenderConfigByName) ────────────────────
    SnaffleRule("Defender-Config",   2, "filename",  r"^(SensorConfiguration\.json|mdatp_managed\.json)$",
                "Microsoft Defender configuration"),

    # ── YELLOW: MDT domain-join creds by name ─────────────────────────────────
    SnaffleRule("MDT-CustomSettings",2, "filename",  r"^customsettings\.ini$",
                "MDT customsettings.ini (may contain domain join credentials)"),

    # ── GREEN: Files whose names contain password-related words ───────────────
    SnaffleRule("Name-Contains-Pass",3, "filename",  r"passw|secret|credential|thycotic|cyberark",
                "Filename contains password/credential keywords"),

    # ── GREEN: Shell history files (KeepShellHistoryByName) ───────────────────
    SnaffleRule("Shell-History",     3, "filename",
                r"^(\.(bash_history|zsh_history|sh_history|irb_history)|zhistory"
                r"|ConsoleHost_History\.txt|Visual Studio Code Host_history\.txt)$",
                "Shell history file"),

    # ── GREEN: Shell RC / dotfiles (KeepShellRcFilesByName) ──────────────────
    SnaffleRule("Shell-RC",          3, "filename",
                r"^(\.(netrc|_netrc|exports|functions|extra|npmrc|env|bashrc|profile|zshrc))$",
                "Shell RC / dotfile with possible credentials"),

    # ── GREEN: Firefox saved logins (KeepFfLoginsJsonRelay) ───────────────────
    SnaffleRule("Firefox-Logins",    3, "filename",  r"^logins\.json$",
                "Firefox/Thunderbird saved logins (encrypted)"),

    # ── GREEN: Files relayed for content scan — flag by extension ─────────────
    # These extensions get content-scanned; a Green hit means "check contents"
    SnaffleRule("Script-PS",         3, "extension", r"\.(ps1|psm1|psd1)$",
                "PowerShell script"),
    SnaffleRule("Script-Cmd",        3, "extension", r"\.(bat|cmd)$",
                "Batch / CMD script"),
    SnaffleRule("Script-Shell",      3, "extension", r"\.sh$",
                "Shell script"),
    SnaffleRule("Script-VBS",        3, "extension", r"\.(vbs|vbe|wsf|wsc|hta)$",
                "VBScript / WSF / HTA"),
    SnaffleRule("Script-Python",     3, "extension", r"\.py$",
                "Python script"),
    SnaffleRule("Script-Ruby",       3, "extension", r"\.rb$",
                "Ruby script"),
    SnaffleRule("Script-Perl",       3, "extension", r"\.pl$",
                "Perl script"),
    SnaffleRule("Script-PHP",        3, "extension", r"\.(php|phtml|inc|php3|php5|php7)$",
                "PHP script"),
    SnaffleRule("Script-Java",       3, "extension", r"\.(jsp|do|java|cfm)$",
                "Java / ColdFusion source"),
    SnaffleRule("Script-JS",         3, "extension", r"\.(js|cjs|mjs|ts|tsx|ls|es6|es)$",
                "JavaScript / TypeScript"),
    SnaffleRule("Config-Generic",    3, "extension",
                r"\.(yaml|yml|toml|xml|json|config|ini|inf|cnf|conf|properties"
                r"|env|dist|sql|log|sqlite|sqlite3|fdb|tfvars)$",
                "Generic config / data file (content-scanned)"),
    SnaffleRule("CSharp-ASP",        3, "extension", r"\.(aspx|ashx|asmx|asp|cshtml|cs|ascx)$",
                "C# / ASP.NET source (content-scanned)"),
]


# ─────────────────────────────────────────────────────────────────────────────
# CONTENT RULES  (applied to file contents; match_type = 'content')
# ─────────────────────────────────────────────────────────────────────────────
CONTENT_RULES = [

    # ── BLACK / RED: Inline private key (KeepInlinePrivateKey) ───────────────
    SnaffleRule("Private-Key-PEM",   0, "content",
                r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----",
                "PEM private key block"),

    # ── RED: AWS keys (KeepAwsKeysInCode) ─────────────────────────────────────
    SnaffleRule("AWS-Key-Pattern",   1, "content",
                r"aws[_\-\.]?key",
                "AWS key reference in code"),
    SnaffleRule("AWS-Access-Key-ID", 1, "content",
                r"(\s|\'|\"|^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z2-7]{12,16}(\s|\'|\"|$)",
                "AWS access key ID"),

    # ── RED: Slack tokens (KeepSlackTokensInCode) ─────────────────────────────
    SnaffleRule("Slack-Token",       1, "content",
                r"xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}",
                "Slack API token"),
    SnaffleRule("Slack-Webhook",     1, "content",
                r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
                "Slack incoming webhook URL"),

    # ── RED: SQL account creation (KeepSqlAccountCreation) ────────────────────
    SnaffleRule("SQL-Create-User",   1, "content",
                r"CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)",
                "SQL account creation with password"),

    # ── RED: Password/key in code (KeepPassOrKeyInCode) ───────────────────────
    SnaffleRule("Pass-In-Code",      1, "content",
                r"passw?o?r?d\s*=\s*['\"][^'\"]{4,}",
                "Password assignment in code"),
    SnaffleRule("APIKey-In-Code",    1, "content",
                r"api[Kk]ey\s*=\s*['\"][^'\"]{4,}",
                "API key assignment in code"),
    SnaffleRule("Pass-In-XML",       1, "content",
                r"passw?o?r?d>\s*[^\s<]+\s*<",
                "Password value in XML element"),
    SnaffleRule("Pass-In-XML-Block", 1, "content",
                r"passw?o?r?d>.{3,2000}</pass",
                "Password block in XML"),
    SnaffleRule("Pass-CLI-Arg",      1, "content",
                r"[\s]+-passw?o?r?d?",
                "Password flag as CLI argument"),
    SnaffleRule("APIKey-In-XML",     1, "content",
                r"api[kK]ey>\s*[^\s<]+\s*<",
                "API key in XML element"),
    SnaffleRule("OAuth-Token",       1, "content",
                r"[_\-\.]oauth\s*=\s*['\"][^'\"]{4,}",
                "OAuth token assignment"),
    SnaffleRule("Client-Secret",     1, "content",
                r"client_secret\s*=*\s*",
                "Client secret reference"),
    SnaffleRule("VPN-ExtendedAuth",  1, "content",
                r"<ExtendedMatchKey>ClientAuth",
                "VPN extended auth key"),
    SnaffleRule("GI-User-Password",  1, "content",
                r"GIUserPassword",
                "GI user password field"),

    # ── RED: C# SQL connection strings with password (KeepCSharpDbConnStringsRed) ─
    SnaffleRule("MSSQL-ConnStr-Pass",1, "content",
                r"Data Source=.+(;|)Password=.+(;|)",
                "MSSQL connection string with password"),
    SnaffleRule("MSSQL-ConnStr-Pass2",1,"content",
                r"Password=.+(;|)Data Source=.+(;|)",
                "MSSQL connection string with password (alt order)"),

    # ── RED: C# viewstate / machineKey (KeepCSharpViewstateKeys) ──────────────
    SnaffleRule("ASP-Validation-Key",1, "content",
                r"validationkey\s*=\s*['\"][^'\"]{8,}",
                "ASP.NET validation key"),
    SnaffleRule("ASP-Decryption-Key",1, "content",
                r"decryptionkey\s*=\s*['\"][^'\"]{8,}",
                "ASP.NET decryption key"),

    # ── RED: PowerShell credentials (KeepPsCredentials) ───────────────────────
    SnaffleRule("PS-SecureString",   1, "content",
                r"-SecureString",
                "PowerShell SecureString usage"),
    SnaffleRule("PS-AsPlainText",    1, "content",
                r"-AsPlainText",
                "PowerShell ConvertTo-SecureString -AsPlainText"),
    SnaffleRule("PS-NetworkCred",    1, "content",
                r"\[Net\.NetworkCredential\]::new\(",
                "PowerShell NetworkCredential instantiation"),

    # ── RED: CMD / batch credentials (KeepCmdCredentials) ─────────────────────
    SnaffleRule("CMD-Pass-Assign",   1, "content",
                r"passwo?r?d\s*=\s*['\"][^'\"]{4,}",
                "Password assignment in batch/cmd"),
    SnaffleRule("Schtasks-Pass",     1, "content",
                r"schtasks.{1,300}(/rp\s|/p\s)",
                "Schtasks with password flag"),
    SnaffleRule("Net-User",          1, "content",
                r"net user ",
                "net user command (may expose password)"),
    SnaffleRule("PsExec-Pass",       1, "content",
                r"psexec .{0,100} -p ",
                "PsExec with password"),
    SnaffleRule("Net-Use-Creds",     1, "content",
                r"net use .{0,300} /user:",
                "net use with credentials"),
    SnaffleRule("CmdKey",            1, "content",
                r"cmdkey ",
                "cmdkey credential storage command"),

    # ── RED: PHP DB connections (KeepPhpDbConnStrings) ────────────────────────
    SnaffleRule("PHP-MySQL",         1, "content",
                r"mysql_(p)?connect\s*\(.*\$.*\)",
                "PHP MySQL connection with variable"),
    SnaffleRule("PHP-PgSQL",         1, "content",
                r"pg_(p)?connect\s*\(.*\$.*\)",
                "PHP PostgreSQL connection with variable"),
    SnaffleRule("PHP-MySQLUser",     1, "content",
                r"mysql_change_user\s*\(.*\$.*\)",
                "PHP MySQL change user"),

    # ── RED: Python DB connections (KeepPyDbConnStrings) ─────────────────────
    SnaffleRule("Python-MySQL",      1, "content",
                r"mysql\.connector\.connect\(",
                "Python MySQL connection"),
    SnaffleRule("Python-PgSQL",      1, "content",
                r"psycopg2\.connect\(",
                "Python psycopg2 connection"),

    # ── RED: Ruby DB connections (KeepRubyDbConnStrings) ─────────────────────
    SnaffleRule("Ruby-DBI",          1, "content",
                r'DBI\.connect\("',
                "Ruby DBI database connection"),

    # ── RED: Perl DB connections (KeepPerlDbConnStrings) ─────────────────────
    SnaffleRule("Perl-DBI",          1, "content",
                r"DBI\->connect\(",
                "Perl DBI database connection"),

    # ── RED: Java DB connections (KeepJavaDbConnStrings) ─────────────────────
    SnaffleRule("Java-JDBC",         1, "content",
                r"\.getConnection\(\"jdbc:",
                "Java JDBC database connection"),

    # ── RED: Firefox encrypted password (KeepFFRegexRed) ─────────────────────
    SnaffleRule("FF-EncryptedPass",  1, "content",
                r'"encryptedPassword":"[A-Za-z0-9+/=]+"',
                "Firefox/Thunderbird encrypted password entry"),

    # ── RED: RDP saved password (KeepRdpPasswords) ────────────────────────────
    SnaffleRule("RDP-SavedPass",     1, "content",
                r"password 51\:b",
                "RDP saved password blob"),

    # ── RED: Unattend.xml credentials (KeepUnattendXmlRegexRed) ───────────────
    SnaffleRule("Unattend-AdminPass",1, "content",
                r"<AdministratorPassword>.{0,30}<Value>.*</Value>",
                "Administrator password in unattend.xml"),
    SnaffleRule("Unattend-AutoLogon",1, "content",
                r"<AutoLogon>.{0,30}<Value>.*</Value>",
                "AutoLogon password in unattend.xml"),

    # ── RED: Network device credentials (KeepNetConfigCreds) ─────────────────
    SnaffleRule("Cisco-NVRAM",       1, "content",
                r"NVRAM config last updated",
                "Cisco NVRAM config header"),
    SnaffleRule("Cisco-EnablePass",  1, "content",
                r"enable password \.",
                "Cisco enable password"),
    SnaffleRule("Cisco-LDAP",        1, "content",
                r"simple-bind authenticated encrypt",
                "Cisco LDAP bind credential"),
    SnaffleRule("Cisco-PAC-Key",     1, "content",
                r"pac key [0-7] ",
                "Cisco PAC key"),
    SnaffleRule("SNMP-RW",           1, "content",
                r"snmp-server community\s.+\sRW",
                "SNMP read-write community string"),

    # ── YELLOW: C# SQL connection strings (integrated auth / no password) ─────
    SnaffleRule("MSSQL-IntegratedAuth", 2, "content",
                r"Data Source=.+Integrated Security=(SSPI|true)",
                "MSSQL connection string with integrated auth"),

    # ── YELLOW: DB connection string with password keyword (KeepDbConnStringPw) ─
    SnaffleRule("ConnStr-Password",  2, "content",
                r"connectionstring.{1,200}passw",
                "Connection string containing password keyword"),

    # ── YELLOW: S3 URI (KeepS3UriPrefixInCode) ────────────────────────────────
    SnaffleRule("S3-URI",            2, "content",
                r"s3[a]?://[a-zA-Z0-9\-\+/]{2,16}",
                "AWS S3 or Hadoop S3A URI"),
]

ALL_RULES = FILENAME_RULES + CONTENT_RULES
