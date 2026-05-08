"""
Snaffler-equivalent classification rules.
Each rule maps to a Snaffler triage rating: Black (0), Red (1), Yellow (2), Green (3)
Lower number = higher severity.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SnaffleRule:
    name: str
    rating: int          # 0=Black, 1=Red, 2=Yellow, 3=Green
    match_type: str      # 'filename', 'extension', 'content', 'path'
    pattern: str
    description: str
    regex: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        self.regex = re.compile(self.pattern, re.IGNORECASE)


RATING_LABELS = {
    0: "Black",
    1: "Red",
    2: "Yellow",
    3: "Green",
}

RATING_COLORS = {
    0: "#1a1a2e",
    1: "#e74c3c",
    2: "#f39c12",
    3: "#27ae60",
}

# ── Filename / extension rules ─────────────────────────────────────────────
FILENAME_RULES = [
    # Black – credential stores / key material
    SnaffleRule("KeePass-DB",         0, "extension", r"\.kdbx?$",               "KeePass database"),
    SnaffleRule("1Password",          0, "extension", r"\.1pif$|\.opvault$",      "1Password vault"),
    SnaffleRule("PFX-P12",            0, "extension", r"\.(pfx|p12)$",            "PKCS12 certificate with private key"),
    SnaffleRule("PrivateKey",         0, "extension", r"\.(key|pem|ppk|asc)$",    "Private key or PEM file"),
    SnaffleRule("PKCS8",              0, "extension", r"\.pk8$",                  "PKCS8 private key"),
    SnaffleRule("VPN-Config",         0, "extension", r"\.(ovpn|vpn)$",           "VPN configuration"),
    SnaffleRule("BitLocker-Key",      0, "filename",  r"bitlocker.*\.bek$",       "BitLocker recovery key"),
    SnaffleRule("NTDS-DIT",           0, "filename",  r"ntds\.dit$",              "Active Directory database"),
    SnaffleRule("SAM-Hive",           0, "filename",  r"^sam$|sam\.bak$",        "SAM registry hive"),
    SnaffleRule("SYSTEM-Hive",        0, "filename",  r"^system$|system\.bak$",  "SYSTEM registry hive"),
    SnaffleRule("KerberosKeytab",     0, "extension", r"\.keytab$",               "Kerberos keytab"),
    SnaffleRule("RDP-Creds",          0, "extension", r"\.rdg$|\.rdp$",           "RDP credential / gateway file"),

    # Red – secrets-likely
    SnaffleRule("Unattend-XML",       1, "filename",  r"unattend(ed)?\.xml$|sysprep\.xml$", "Windows unattend/sysprep with possible credentials"),
    SnaffleRule("Ansible-Vault",      1, "extension", r"\.vault$",                "Ansible vault encrypted vars"),
    SnaffleRule("TerraformVars",      1, "extension", r"\.tfvars$",               "Terraform variables (may contain secrets)"),
    SnaffleRule("DockerEnv",          1, "filename",  r"^\.env(\.[a-z]+)?$",      ".env file with possible secrets"),
    SnaffleRule("PassFiles",          1, "filename",  r"passwords?\.(txt|csv|xls|xlsx|doc|docx|pdf)$", "Password list file"),
    SnaffleRule("CredFiles",          1, "filename",  r"cred(ential)?s?\.(txt|csv|xls|xlsx|doc|docx)$", "Credentials file"),
    SnaffleRule("SecretFiles",        1, "filename",  r"secret[s_-].*\.(txt|yml|yaml|json|conf|cfg)$", "Secrets config"),
    SnaffleRule("WinSCP-INI",         1, "filename",  r"winscp\.ini$",            "WinSCP saved sessions (plaintext passwords)"),
    SnaffleRule("PuTTY-Private",      1, "extension", r"\.ppk$",                  "PuTTY private key"),
    SnaffleRule("LSASS-Dump",         0, "filename",  r"lsass.*\.(dmp|mdmp|bin)$","LSASS memory dump"),
    SnaffleRule("MiniDump",           1, "extension", r"\.(dmp|mdmp)$",           "Memory dump file"),
    SnaffleRule("DockerCompose",      1, "filename",  r"docker-compose.*\.ya?ml$","Docker compose (may embed creds)"),
    SnaffleRule("KubeConfig",         1, "filename",  r"kubeconfig|kube\.conf$|config\.ya?ml$", "Kubernetes config"),
    SnaffleRule("AWS-Creds",          1, "filename",  r"credentials$|aws_credentials$", "AWS credentials file"),
    SnaffleRule("SSH-Config",         1, "filename",  r"^ssh_config$|sshd_config$", "SSH config"),
    SnaffleRule("NetRC",              1, "filename",  r"^\.netrc$",               "netrc (plaintext creds)"),
    SnaffleRule("GitCredentials",     1, "filename",  r"^\.git-credentials$",     "git credentials store"),

    # Yellow – interesting configs
    SnaffleRule("WebConfig",          2, "filename",  r"web\.config$",            "ASP.NET web.config"),
    SnaffleRule("AppConfig",          2, "filename",  r"app(lication)?\.config$|appsettings.*\.json$", "Application config"),
    SnaffleRule("ConnectionStrings",  2, "filename",  r"connectionstrings?\.(xml|json|config)$", "Connection strings"),
    SnaffleRule("IISConfig",          2, "filename",  r"applicationHost\.config$", "IIS applicationHost.config"),
    SnaffleRule("PhpConfig",          2, "filename",  r"config\.php$|configuration\.php$|settings\.php$", "PHP config"),
    SnaffleRule("DjangoSettings",     2, "filename",  r"settings\.py$",           "Django settings"),
    SnaffleRule("SpringProps",        2, "extension", r"\.(properties|application\.ya?ml)$", "Spring Boot config"),
    SnaffleRule("NginxConf",          2, "filename",  r"nginx\.conf$",            "nginx config"),
    SnaffleRule("ApacheConf",         2, "filename",  r"(httpd|apache2?)\.conf$", "Apache config"),
    SnaffleRule("ShadowFile",         1, "filename",  r"^shadow$|^shadow\-$",     "Unix shadow password file"),
    SnaffleRule("PasswdFile",         2, "filename",  r"^passwd$",                "Unix passwd file"),
    SnaffleRule("Hosts",              3, "filename",  r"^hosts$",                 "hosts file"),
    SnaffleRule("DatabaseConf",       2, "filename",  r"database\.(conf|yml|yaml|php)$|db\.conf$", "Database config"),
    SnaffleRule("Jenkins",            2, "filename",  r"credentials\.xml$|config\.xml$", "Jenkins credential store"),

    # Green – potentially interesting
    SnaffleRule("ScriptFiles",        3, "extension", r"\.(ps1|psm1|psd1|bat|cmd|vbs|sh|bash|zsh)$", "Script file"),
    SnaffleRule("BackupFiles",        2, "extension", r"\.(bak|backup|old|orig|save)$", "Backup file"),
    SnaffleRule("LogFiles",           3, "extension", r"\.(log|logs)$",           "Log file"),
    SnaffleRule("DatabaseFiles",      2, "extension", r"\.(sql|sqlite|sqlite3|db|mdb|accdb)$", "Database file"),
    SnaffleRule("CertFiles",          3, "extension", r"\.(crt|cer|der)$",        "Certificate (public)"),
    SnaffleRule("HistoryFiles",       2, "filename",  r"\.(bash_history|zsh_history|pshistory|ConsoleHost_history\.txt)$", "Shell history"),
]

# ── Content pattern rules (applied to file contents) ──────────────────────
CONTENT_RULES = [
    # Black
    SnaffleRule("Private-Key-PEM",    0, "content",
                r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
                "PEM private key block"),
    SnaffleRule("AWS-Access-Key",     0, "content",
                r"AKIA[0-9A-Z]{16}",
                "AWS access key ID"),
    SnaffleRule("AWS-Secret-Key",     0, "content",
                r"aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+]{40}",
                "AWS secret access key"),
    SnaffleRule("Azure-Storage-Key",  0, "content",
                r"AccountKey=[A-Za-z0-9+/]{88}==",
                "Azure storage account key"),
    SnaffleRule("Azure-ClientSecret", 0, "content",
                r"client[_-]?secret\s*[=:\"']\s*[A-Za-z0-9~._\-]{20,}",
                "Azure client secret"),
    SnaffleRule("GCP-ServiceAccount", 0, "content",
                r'"type"\s*:\s*"service_account"',
                "GCP service account JSON"),
    SnaffleRule("Slack-Token",        0, "content",
                r"xox[baprs]-[0-9A-Za-z\-]{10,}",
                "Slack API token"),
    SnaffleRule("GitHub-PAT",         0, "content",
                r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}",
                "GitHub personal access token"),
    SnaffleRule("JWT-Token",          0, "content",
                r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
                "JSON Web Token"),

    # Red
    SnaffleRule("Password-In-File",   1, "content",
                r"(?i)(password|passwd|pwd)\s*[=:\"']\s*\S{4,}",
                "Plaintext password assignment"),
    SnaffleRule("ConnectionString",   1, "content",
                r"(?i)(Data Source|Server)\s*=.*Password\s*=",
                "Database connection string with password"),
    SnaffleRule("NTLM-Hash",          1, "content",
                r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}",
                "NTLM hash (LM:NT)"),
    SnaffleRule("Net-NTLMv2",         1, "content",
                r"[A-Za-z0-9_\-]+::[A-Za-z0-9_\-]+:[A-Fa-f0-9]{16}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]+",
                "Net-NTLMv2 hash"),
    SnaffleRule("Kerberos-Hash",      1, "content",
                r"\$krb5(asrep|tgs)\$[0-9]+\$",
                "Kerberos hash (AS-REP/TGS)"),
    SnaffleRule("SSH-Password",       1, "content",
                r"(?i)StrictHostKeyChecking\s+no",
                "SSH weak config - StrictHostKeyChecking disabled"),
    SnaffleRule("API-Key-Generic",    1, "content",
                r"(?i)(api[_\-]?key|apikey)\s*[=:\"']\s*[A-Za-z0-9_\-]{16,}",
                "Generic API key"),
    SnaffleRule("Secret-Generic",     1, "content",
                r"(?i)(secret[_\-]?key|app[_\-]?secret)\s*[=:\"']\s*[A-Za-z0-9_\-]{8,}",
                "Generic secret key"),

    # Yellow
    SnaffleRule("Username-Field",     2, "content",
                r"(?i)(username|user|login)\s*[=:\"']\s*\S{2,}",
                "Username field"),
    SnaffleRule("DomainUser",         2, "content",
                r"[A-Za-z0-9_\-]{1,20}\\[A-Za-z0-9_\-]{1,20}",
                "Domain\\User format"),
    SnaffleRule("IP-Address",         3, "content",
                r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
                "Private IP address (RFC1918)"),
    SnaffleRule("Base64-Secret",      2, "content",
                r"(?i)(password|secret|token|key)\s*[=:\"']\s*[A-Za-z0-9+/]{20,}={0,2}",
                "Possible base64-encoded secret"),
    SnaffleRule("SQLServer-Cred",     1, "content",
                r"(?i)User ID\s*=.*Password\s*=",
                "SQL Server credential in connection string"),
    SnaffleRule("LDAP-Cred",          1, "content",
                r"(?i)ldap.*password\s*[=:\"']\s*\S+",
                "LDAP password"),
]

ALL_RULES = FILENAME_RULES + CONTENT_RULES
