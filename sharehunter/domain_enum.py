"""
Query a Domain Controller via LDAP/LDAPS to enumerate all computer objects
and return their DNS hostnames / IP addresses for use as scan targets.

Kerberos mode (use_kerberos=True):
  Uses impacket's LDAPConnection.kerberosLogin() directly — no gssapi dependency.
  TGT and service ticket are handled entirely within impacket, avoiding the
  gssapi hostname-canonicalization issues that arise with ldap3 SASL/KERBEROS.

NTLM mode (use_kerberos=False):
  Uses ldap3 with NTLM auth.
  Tries plain LDAP (389) first; auto-falls back to LDAPS (636) if rejected.
"""

import os
import ssl
import socket
import ipaddress

from ldap3 import Server, Connection, NTLM, ALL, SUBTREE, Tls
from ldap3.core.exceptions import LDAPException


def _base_dn_from_domain(domain: str) -> str:
    return ','.join(f'DC={part}' for part in domain.split('.'))


def _make_tls(validate_cert: bool = False) -> Tls:
    ctx = ssl.create_default_context()
    if not validate_cert:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return Tls(validate=ssl.CERT_NONE if not validate_cert else ssl.CERT_REQUIRED)


def _resolve_dc_hostname(dc: str, domain: str, log) -> str:
    """
    Resolve dc to a machine FQDN suitable for Kerberos SPN lookup.
    SPNs are registered against machine hostnames, not IPs or zone apex names.

    Cases:
      - IP address  → rDNS to get machine FQDN
      - Zone apex   → forward DNS gives IP, then rDNS to get machine FQDN
      - Machine FQDN (more labels than domain) → use as-is
    """
    # If it's an IP, go straight to rDNS
    try:
        ipaddress.ip_address(dc)
        ip = dc
    except ValueError:
        # It's a hostname. Check if it's just the zone apex (same label count as domain).
        # If so, resolve forward to IP then rDNS to find the machine name.
        dc_labels     = len(dc.split('.'))
        domain_labels = len(domain.split('.'))
        if dc_labels <= domain_labels:
            # Likely the zone apex or just the domain — resolve to IP first
            try:
                ip = socket.gethostbyname(dc)
            except Exception:
                log(f'[Kerberos] Could not resolve {dc} — using as-is', 'warn')
                return dc
        else:
            # Already a machine FQDN (e.g. winterfell.north.sevenkingdoms.local)
            return dc

    try:
        names = socket.gethostbyaddr(ip)
        candidates = [names[0]] + names[1]
        in_domain = [n for n in candidates
                     if n.lower().endswith('.' + domain.lower())
                     or n.lower() == domain.lower()]
        in_domain.sort(key=lambda n: len(n.split('.')), reverse=True)
        resolved = in_domain[0] if in_domain else candidates[0]
        log(f'[Kerberos] Resolved {dc} → {resolved} for LDAP service ticket', 'info')
        return resolved
    except Exception:
        log(f'[Kerberos] rDNS failed for {ip} — Kerberos may fail (SPN requires FQDN)', 'warn')
        return dc


def _kerberos_enum(dc_fqdn: str, dc_ip: str, username: str, password: str,
                   domain: str, nthash: str, aes_key: str,
                   base_dn: str, log) -> list[str] | None:
    """
    Enumerate computers via impacket LDAPConnection with Kerberos auth.
    Returns list of hostnames, or None on auth/connection failure.
    """
    try:
        from impacket.ldap import ldap as impacket_ldap, ldapasn1 as ldapasn1_impacket
        from sharehunter.scanner import _parse_hash
    except ImportError as e:
        log(f'[Kerberos] impacket not available: {e}', 'error')
        return None

    lm, nt = ('', '')
    if nthash:
        lm, nt = _parse_hash(nthash)

    url = f'ldap://{dc_fqdn}'
    log(f'[LDAP] Connecting to {dc_fqdn} as {domain.split(".")[0].upper()}\\{username} (Kerberos)', 'info')
    try:
        conn = impacket_ldap.LDAPConnection(url, baseDN=base_dn, dstIp=dc_ip or None)
        conn.kerberosLogin(
            user=username,
            password=password,
            domain=domain,
            lmhash=lm,
            nthash=nt,
            aesKey=aes_key or '',
            kdcHost=dc_ip or dc_fqdn,
            useCache=False,
        )
    except Exception as e:
        log(f'[LDAP] Kerberos bind failed: {e}', 'error')
        return None

    log('[LDAP] Kerberos bind successful', 'info')

    search_filter = '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    try:
        resp = conn.search(searchFilter=search_filter,
                           attributes=['dNSHostName', 'sAMAccountName', 'operatingSystem'])
    except Exception as e:
        log(f'[LDAP] Search failed: {e}', 'error')
        return None

    hosts = []
    for entry in resp:
        if not isinstance(entry, ldapasn1_impacket.SearchResultEntry):
            continue
        dns = ''
        sam = ''
        os_ = ''
        for attr in entry['attributes']:
            atype = str(attr['type'])
            val   = str(attr['vals'][0]) if attr['vals'] else ''
            if atype == 'dNSHostName':      dns = val
            elif atype == 'sAMAccountName': sam = val
            elif atype == 'operatingSystem': os_ = val
        host = dns if dns else sam.rstrip('$')
        if host:
            hosts.append(host)
            log(f'[LDAP]   Found: {host}  ({os_})', 'info')

    log(f'[LDAP] Enumerated {len(hosts)} computer(s)', 'info')
    return hosts


def _ntlm_enum(dc: str, user_str: str, auth_password: str, use_ldaps: bool,
               base_dn: str, log) -> list[str] | None:
    """
    Enumerate computers via ldap3 with NTLM auth.
    Returns list of hostnames, or None on failure.
    """
    transport_attempts = [(True, 'LDAPS')] if use_ldaps else [(False, 'LDAP'), (True, 'LDAPS (fallback)')]

    server = None
    conn   = None
    last_error = None

    for ldaps, label in transport_attempts:
        port = 636 if ldaps else 389
        try:
            log(f'[LDAP] Trying {label} to {dc}:{port} as {user_str} (NTLM)', 'info')
            if ldaps:
                tls = _make_tls(validate_cert=False)
                srv = Server(dc, port=port, use_ssl=True, tls=tls, get_info=ALL, connect_timeout=10)
            else:
                srv = Server(dc, port=port, get_info=ALL, connect_timeout=10)

            c = Connection(srv, user=user_str, password=auth_password,
                           authentication=NTLM, auto_bind=False)
            c.open()
            c.bind()
            if c.bound:
                server = srv
                conn = c
                log(f'[LDAP] Bound via {label}', 'info')
                break
            last_error = f'Bind rejected: {c.result}'
            log(f'[LDAP] {label} bind rejected: {last_error}', 'info')
            c.unbind()
        except Exception as e:
            last_error = str(e)
            log(f'[LDAP] {label} failed: {e}', 'info')

    if conn is None or not conn.bound:
        log(f'[LDAP] All NTLM connection attempts failed. Last error: {last_error}', 'error')
        return None

    if not base_dn:
        try:
            base_dn = str(server.info.other.get('defaultNamingContext', [''])[0])
        except Exception:
            pass
        if not base_dn:
            log('[LDAP] Could not determine base DN', 'error')
            conn.unbind()
            return None

    log(f'[LDAP] Base DN: {base_dn}', 'info')

    search_filter = '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    try:
        conn.search(search_base=base_dn, search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=['dnsHostName', 'sAMAccountName', 'operatingSystem'])
    except Exception as e:
        log(f'[LDAP] Search failed: {e}', 'error')
        conn.unbind()
        return None

    hosts = []
    for entry in conn.entries:
        dns = str(entry.dnsHostName) if entry.dnsHostName else ''
        sam = str(entry.sAMAccountName).rstrip('$') if entry.sAMAccountName else ''
        os_ = str(entry.operatingSystem) if entry.operatingSystem else ''
        host = dns if dns and dns != 'None' else sam
        if host and host != 'None':
            hosts.append(host)
            log(f'[LDAP]   Found: {host}  ({os_})', 'info')

    conn.unbind()
    log(f'[LDAP] Enumerated {len(hosts)} computer(s)', 'info')
    return hosts


def get_domain_computers(
    dc: str,
    username: str,
    password: str = '',
    domain: str = '',
    nthash: str = '',
    use_ldaps: bool = False,
    use_kerberos: bool = False,
    aes_key: str = '',
    log_callback=None,
) -> list[str]:
    """
    Connect to *dc* via LDAP and return hostnames of all enabled computer objects.

    Auth:
      - Kerberos (use_kerberos=True): uses impacket's LDAPConnection.kerberosLogin()
        which handles TGT and service ticket acquisition without gssapi.
      - NTLM: ldap3 with auto-fallback from plain LDAP → LDAPS.
    """

    def log(msg, level='info'):
        if log_callback:
            log_callback(msg, level)

    if not domain:
        parts = dc.split('.')
        if len(parts) >= 2:
            domain = '.'.join(parts[-2:])

    base_dn = _base_dn_from_domain(domain) if domain else ''

    if use_kerberos:
        dc_fqdn = _resolve_dc_hostname(dc, domain, log)
        # Resolve dc_ip for the dstIp / kdcHost parameters
        try:
            ipaddress.ip_address(dc)
            dc_ip = dc
        except ValueError:
            try:
                dc_ip = socket.gethostbyname(dc_fqdn)
            except Exception:
                dc_ip = ''
        hosts = _kerberos_enum(dc_fqdn=dc_fqdn, dc_ip=dc_ip,
                               username=username, password=password,
                               domain=domain, nthash=nthash, aes_key=aes_key,
                               base_dn=base_dn, log=log)
        if hosts is None:
            return []
        return hosts

    # NTLM path
    ntlm_domain = domain.split('.')[0].upper() if '.' in domain else domain
    user_str    = f'{ntlm_domain}\\{username}' if ntlm_domain else username
    if nthash:
        from sharehunter.scanner import _parse_hash
        lm, nt = _parse_hash(nthash)
        auth_password = f'{lm}:{nt}'
    else:
        auth_password = password

    hosts = _ntlm_enum(dc=dc, user_str=user_str, auth_password=auth_password,
                       use_ldaps=use_ldaps, base_dn=base_dn, log=log)
    return hosts if hosts is not None else []
