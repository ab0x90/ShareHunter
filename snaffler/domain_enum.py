"""
Query a Domain Controller via LDAP to enumerate all computer objects
and return their DNS hostnames / IP addresses for use as scan targets.
"""

from ldap3 import Server, Connection, NTLM, ALL, SUBTREE, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPException


def _base_dn_from_domain(domain: str) -> str:
    return ','.join(f'DC={part}' for part in domain.split('.'))


def get_domain_computers(
    dc: str,
    username: str,
    password: str = '',
    domain: str = '',
    nthash: str = '',
    log_callback=None,
) -> list[str]:
    """
    Connect to *dc* via LDAP and return a list of dnsHostName values for
    all enabled computer objects.  Falls back to sAMAccountName (stripped
    of the trailing '$') when dnsHostName is absent.

    Supports password auth and pass-the-hash (nthash supplied as the NT
    portion; ldap3 expects 'LMHASH:NTHASH' format).
    """

    def log(msg, level='info'):
        if log_callback:
            log_callback(msg, level)

    if not domain:
        # Try to derive domain from the DC hostname
        parts = dc.split('.')
        if len(parts) >= 2:
            domain = '.'.join(parts[-2:])

    base_dn = _base_dn_from_domain(domain) if domain else ''

    # Build credential string
    if nthash:
        lm = 'aad3b435b51404eeaad3b435b51404ee'
        auth_password = f'{lm}:{nthash}'
    else:
        auth_password = password

    user_str = f'{domain}\\{username}' if domain else username

    log(f'[LDAP] Connecting to {dc} as {user_str}', 'info')

    try:
        server = Server(dc, get_info=ALL, connect_timeout=10)
        conn = Connection(
            server,
            user=user_str,
            password=auth_password,
            authentication=NTLM,
            auto_bind=True,
        )
    except LDAPException as e:
        log(f'[LDAP] Connection failed: {e}', 'error')
        return []

    if not base_dn:
        # Pull from server info
        base_dn = str(server.info.other.get('defaultNamingContext', [''])[0])
        if not base_dn:
            log('[LDAP] Could not determine base DN', 'error')
            conn.unbind()
            return []

    log(f'[LDAP] Base DN: {base_dn}', 'info')

    search_filter = '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    attributes = ['dnsHostName', 'sAMAccountName', 'operatingSystem']

    try:
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
        )
    except LDAPException as e:
        log(f'[LDAP] Search failed: {e}', 'error')
        conn.unbind()
        return []

    hosts = []
    for entry in conn.entries:
        dns = str(entry.dnsHostName) if entry.dnsHostName else ''
        sam = str(entry.sAMAccountName).rstrip('$') if entry.sAMAccountName else ''
        os_  = str(entry.operatingSystem) if entry.operatingSystem else ''

        host = dns if dns and dns != 'None' else sam
        if host and host != 'None':
            hosts.append(host)
            log(f'[LDAP]   Found: {host}  ({os_})', 'info')

    conn.unbind()
    log(f'[LDAP] Enumerated {len(hosts)} computer(s)', 'info')
    return hosts
