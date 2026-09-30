"""Cloudflare inventory and bounded, evidence-checked baseline reconciliation.

No DNS record or routing rule is changed. Cloudflare edge settings apply only to
proxied traffic. A TLS handshake/root response never proves application readiness.
Full(strict) upgrades require direct, trusted origin certificates for every
proxied DNS origin; unsupported tunnels, Workers, or wildcard origins stay blocked.
API: run(apply=False) -> dict. Uses CF_API_TOKEN or CLOUDFLARE_API_TOKEN first,
then the dedicated SZL/Cloudflare/estate-api-token Windows credential. Optional
CF_ZONE_ID_A11OY_COM/CF_ZONE_ID_A11OY_NET must match the expected zone. Tokens
are never included in reports or exceptions. --setup-credential securely prompts
for an existing scoped token, validates both zones, then stores it in Windows.
"""
from __future__ import annotations

import concurrent.futures
import ctypes
from ctypes import wintypes
import getpass
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import warnings
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

ZONES = {'a-11-oy.com': 'CF_ZONE_ID_A11OY_COM', 'a11oy.net': 'CF_ZONE_ID_A11OY_NET'}
SETTINGS = ('always_use_https', 'min_tls_version', 'ssl')
MAX_PAGES = 100
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
WINDOWS_CREDENTIAL_TARGET = 'SZL/Cloudflare/estate-api-token'
MAX_CREDENTIAL_BYTES = 5 * 512


def timestamp():
    return datetime.now(timezone.utc).isoformat()


class CloudflareError(RuntimeError):
    """Safe, deliberately minimal failure text: no headers or response bodies."""


def _validated_token(token):
    if not isinstance(token, str) or not token or token.lower() in {'none', 'null'}:
        raise CloudflareError('CLOUDFLARE_TOKEN_UNAVAILABLE')
    if len(token.encode('utf-16-le')) > MAX_CREDENTIAL_BYTES or not re.fullmatch(
        r'[A-Za-z0-9._~+/-]+={0,2}', token
    ):
        raise CloudflareError('CLOUDFLARE_TOKEN_INVALID_FORMAT')
    return token


class _Credential(ctypes.Structure):
    _fields_ = [('Flags', wintypes.DWORD), ('Type', wintypes.DWORD),
                ('TargetName', wintypes.LPWSTR), ('Comment', wintypes.LPWSTR),
                ('LastWritten', wintypes.FILETIME), ('CredentialBlobSize', wintypes.DWORD),
                ('CredentialBlob', ctypes.POINTER(ctypes.c_ubyte)), ('Persist', wintypes.DWORD),
                ('AttributeCount', wintypes.DWORD), ('Attributes', ctypes.c_void_p),
                ('TargetAlias', wintypes.LPWSTR), ('UserName', wintypes.LPWSTR)]


def _wincred_api():
    """Only the documented Windows credential API; never enumerate other stores."""
    api = ctypes.WinDLL('advapi32', use_last_error=True)
    api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                             ctypes.POINTER(ctypes.POINTER(_Credential))]
    api.CredReadW.restype = wintypes.BOOL
    api.CredWriteW.argtypes = [ctypes.POINTER(_Credential), wintypes.DWORD]
    api.CredWriteW.restype = wintypes.BOOL
    api.CredFree.argtypes = [ctypes.c_void_p]
    api.CredFree.restype = None
    return api


def _is_windows():
    return os.name == 'nt'


def read_windows_credential():
    """Read only this runner's named generic credential in the current user vault."""
    if not _is_windows():
        return None
    try:
        api = _wincred_api()
        pointer = ctypes.POINTER(_Credential)()
        if not api.CredReadW(WINDOWS_CREDENTIAL_TARGET, 1, 0, ctypes.byref(pointer)):
            error = ctypes.get_last_error()
            if error == 1168:  # ERROR_NOT_FOUND
                return None
            raise CloudflareError('WINDOWS_CREDENTIAL_READ_FAILED_' + str(error))
        try:
            credential = pointer.contents
            size = credential.CredentialBlobSize
            if not credential.CredentialBlob or not 0 < size <= MAX_CREDENTIAL_BYTES or size % 2:
                raise CloudflareError('WINDOWS_CREDENTIAL_INVALID_BLOB')
            token = ctypes.string_at(credential.CredentialBlob, size).decode('utf-16-le').rstrip('\0')
            return _validated_token(token)
        finally:
            api.CredFree(pointer)
    except CloudflareError:
        raise
    except (OSError, ValueError, UnicodeError):
        raise CloudflareError('WINDOWS_CREDENTIAL_READ_UNAVAILABLE') from None


def store_windows_credential(token):
    """Store an explicitly supplied token under the dedicated current-user target."""
    if not _is_windows():
        raise CloudflareError('WINDOWS_CREDENTIAL_MANAGER_REQUIRED')
    token = _validated_token(token)
    encoded = token.encode('utf-16-le')
    blob = (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)
    try:
        api = _wincred_api()
        credential = _Credential()
        credential.Type = 1  # CRED_TYPE_GENERIC
        credential.TargetName = WINDOWS_CREDENTIAL_TARGET
        credential.Comment = 'SZL estate maintenance; scoped Cloudflare API token'
        credential.CredentialBlobSize = len(encoded)
        credential.CredentialBlob = ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte))
        credential.Persist = 2  # CRED_PERSIST_LOCAL_MACHINE: same user, same computer.
        credential.UserName = 'Cloudflare API token'
        if not api.CredWriteW(ctypes.byref(credential), 0):
            raise CloudflareError('WINDOWS_CREDENTIAL_WRITE_FAILED_' + str(ctypes.get_last_error()))
    except CloudflareError:
        raise
    except (OSError, ValueError):
        raise CloudflareError('WINDOWS_CREDENTIAL_WRITE_UNAVAILABLE') from None
    finally:
        ctypes.memset(blob, 0, len(encoded))
    try:
        readback = read_windows_credential()
    except CloudflareError:
        raise CloudflareError('WINDOWS_CREDENTIAL_READBACK_FAILED') from None
    if readback != token:
        raise CloudflareError('WINDOWS_CREDENTIAL_READBACK_FAILED')


def resolve_token(environ=None):
    """Never fall back from an explicitly configured invalid credential."""
    environ = os.environ if environ is None else environ
    for name in ('CF_API_TOKEN', 'CLOUDFLARE_API_TOKEN'):
        if environ.get(name):
            return _validated_token(environ[name]), {'source': 'environment', 'variable': name}
    token = read_windows_credential()
    if token:
        return token, {'source': 'windows_credential_manager', 'target': WINDOWS_CREDENTIAL_TARGET}
    raise CloudflareError('CLOUDFLARE_TOKEN_UNAVAILABLE')


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, token, timeout=20):
        self._token = _validated_token(token)
        self.timeout = timeout
        self._opener = build_opener(_NoRedirect())

    def request(self, method, path, query=None, body=None):
        if not re.fullmatch(r'/zones(?:/[A-Za-z0-9_/-]+)?', path):
            raise CloudflareError('INVALID_API_PATH')
        if method not in {'GET', 'PATCH'}:
            raise CloudflareError('UNSUPPORTED_METHOD')
        if method == 'PATCH' and not re.fullmatch(
            r'/zones/[0-9a-f]{32}/settings/(always_use_https|min_tls_version|ssl)', path
        ):
            raise CloudflareError('MUTATION_OUTSIDE_BASELINE_SCOPE')
        url = 'https://api.cloudflare.com/client/v4' + path
        if query:
            url += '?' + urlencode(query)
        request = Request(url, method=method,
                          data=None if body is None else json.dumps(body).encode(),
                          headers={'Authorization': 'Bearer ' + self._token,
                                   'Content-Type': 'application/json',
                                   'User-Agent': 'szl-estate-operations/2'})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise CloudflareError('RESPONSE_TOO_LARGE')
                data = json.loads(raw)
        except HTTPError as exc:
            raise CloudflareError('CLOUDFLARE_HTTP_' + str(exc.code)) from None
        except (URLError, TimeoutError, OSError, ValueError):
            raise CloudflareError('CLOUDFLARE_TRANSPORT_OR_JSON_ERROR') from None
        if not isinstance(data, dict) or data.get('success') is not True:
            raise CloudflareError('CLOUDFLARE_API_REJECTED')
        if 'result' not in data:
            raise CloudflareError('CLOUDFLARE_RESULT_MISSING')
        return data

    def list(self, path, query=None, per_page=100):
        result = []
        seen_pages = set()
        for page in range(1, MAX_PAGES + 1):
            data = self.request('GET', path, {**(query or {}), 'page': page, 'per_page': per_page})
            batch = data['result']
            if not isinstance(batch, list):
                raise CloudflareError('INVALID_PAGINATED_RESULT')
            marker = json.dumps(batch, sort_keys=True)
            if batch and marker in seen_pages:
                raise CloudflareError('PAGINATION_REPEATED_PAGE')
            seen_pages.add(marker)
            result.extend(batch)
            info = data.get('result_info') or {}
            if not isinstance(info, dict):
                raise CloudflareError('INVALID_PAGINATION_METADATA')
            total = info.get('total_pages')
            if total is not None:
                if not isinstance(total, int) or total < 0 or total > MAX_PAGES:
                    raise CloudflareError('PAGINATION_LIMIT_OR_INVALID_METADATA')
                if not batch and page < total:
                    raise CloudflareError('PAGINATION_PREMATURE_EMPTY_PAGE')
                if page >= total:
                    if isinstance(info.get('total_count'), int) and len(result) != info['total_count']:
                        raise CloudflareError('PAGINATION_COUNT_MISMATCH')
                    return result
            elif len(batch) < per_page:
                return result
        raise CloudflareError('PAGINATION_LIMIT')


def _zone(client, name, environ):
    configured = environ.get(ZONES[name])
    if configured:
        if not re.fullmatch(r'[0-9a-f]{32}', configured):
            raise CloudflareError('INVALID_CONFIGURED_ZONE_ID')
        zone = client.request('GET', '/zones/' + configured)['result']
    else:
        zones = client.list('/zones', {'name': name}, per_page=50)
        matches = [z for z in zones if z.get('name') == name]
        if len(matches) != 1:
            raise CloudflareError('ZONE_NOT_FOUND_OR_AMBIGUOUS')
        zone = matches[0]
    if not isinstance(zone, dict) or zone.get('name') != name:
        raise CloudflareError('ZONE_ID_NAME_MISMATCH')
    if not re.fullmatch(r'[0-9a-f]{32}', zone.get('id', '')):
        raise CloudflareError('INVALID_PROVIDER_ZONE_ID')
    return zone


def validate_setup_access(client):
    """GET-only validation of the two intended zones before any local secret write.

    Provider permission metadata reports edit authorization. We never mutate a
    setting as an authentication test and do not claim a witnessed write here.
    """
    verified = []
    for name in ZONES:
        zone = _zone(client, name, {})
        path = '/zones/' + zone['id']
        zone = client.request('GET', path)['result']
        if zone.get('name') != name:
            raise CloudflareError('ZONE_ID_NAME_MISMATCH')
        records = client.list(path + '/dns_records')
        settings = {}
        for setting in SETTINGS:
            observed = client.request('GET', path + '/settings/' + setting)['result']
            if not isinstance(observed, dict) or observed.get('id') != setting:
                raise CloudflareError('INVALID_SETTING_RESULT')
            desired_value(setting, observed.get('value'))
            settings[setting] = observed['value']
        permissions = zone.get('permissions') or []
        if not {'#zone_settings:edit', '#zone_settings:write'}.intersection(permissions):
            raise CloudflareError('ZONE_SETTINGS_EDIT_PERMISSION_NOT_CONFIRMED_' + name)
        verified.append({'name': name, 'id': zone['id'], 'dns_records': len(records),
                         'settings': settings, 'required_reads': 'VERIFIED',
                         'settings_edit': 'REPORTED_BY_PROVIDER_PERMISSIONS'})
    return verified


def setup_credential(*, prompt=None, client_factory=None, store=None):
    """Secure interactive setup. Prompts never accept a token in argv or a file."""
    report = {'provider': 'cloudflare', 'mode': 'credential_setup', 'observed_at': timestamp(),
              'status': 'BLOCKED', 'actions': [], 'blockers': [], 'stored': False,
              'credential_target': WINDOWS_CREDENTIAL_TARGET}
    token = None
    store_attempted = False
    try:
        if not _is_windows():
            raise CloudflareError('WINDOWS_CREDENTIAL_MANAGER_REQUIRED')
        if prompt is None:
            if not sys.stdin.isatty():
                raise CloudflareError('SETUP_REQUIRES_INTERACTIVE_TERMINAL')
            prompt = getpass.getpass
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            token = _validated_token(prompt('Cloudflare token (hidden; stored only after validation): '))
        client = (client_factory or Client)(token)
        report['validated_zones'] = validate_setup_access(client)
        store_attempted = True
        (store or store_windows_credential)(token)
        report.update(status='STORED_VERIFIED', stored=True,
                      write_authorization='REPORTED_BY_PROVIDER; no remote writes attempted')
    except CloudflareError as exc:
        report['blockers'].append({'reason': str(exc)})
        if str(exc) == 'WINDOWS_CREDENTIAL_READBACK_FAILED':
            report.update(status='UNKNOWN_AFTER_ATTEMPT', stored=None)
    except (getpass.GetPassWarning, EOFError, KeyboardInterrupt):
        if store_attempted:
            report.update(status='UNKNOWN_AFTER_ATTEMPT', stored=None)
            report['blockers'].append({'reason': 'CREDENTIAL_STORAGE_INTERRUPTED_OR_UNVERIFIED'})
        else:
            report['blockers'].append({'reason': 'SECURE_INPUT_UNAVAILABLE_OR_CANCELLED'})
    except Exception:
        # Do not serialize arbitrary library/mock/provider errors containing secrets.
        if store_attempted:
            report.update(status='UNKNOWN_AFTER_ATTEMPT', stored=None)
            report['blockers'].append({'reason': 'CREDENTIAL_STORAGE_UNVERIFIED'})
        else:
            report['blockers'].append({'reason': 'CREDENTIAL_SETUP_VALIDATION_FAILED'})
    finally:
        token = None
    return report


def tls_probe(host, target=None, family=socket.AF_UNSPEC, timeout=5):
    """Verify chain, hostname, validity, and a negotiated modern TLS connection.

    target is an explicit DNS origin; SNI always uses the requested public host.
    Never disables certificate verification, including for Cloudflare Origin CA.
    Origin-CA-only deployments therefore need a separately established trust path.
    """
    result = {'host': host, 'target': target or host, 'family': family, 'verified': False}
    try:
        context = ssl.create_default_context()
        addresses = socket.getaddrinfo(target or host, 443, family, socket.SOCK_STREAM)
        if not addresses:
            raise OSError('No addresses')
        # Limit address attempts; never silently admit a DNS origin on a private address.
        for af, socktype, proto, _, address in addresses[:4]:
            if not ipaddress.ip_address(address[0]).is_global:
                raise ValueError('Non-public address')
            try:
                with socket.socket(af, socktype, proto) as raw:
                    raw.settimeout(timeout)
                    raw.connect(address)
                    with context.wrap_socket(raw, server_hostname=host) as connection:
                        cert = connection.getpeercert()
                        result.update(verified=True, version=connection.version(),
                                      peer=address[0], expires=cert.get('notAfter'),
                                      subject_alt_names=cert.get('subjectAltName', []))
                        return result
            except (OSError, ssl.SSLError) as exc:
                result['error'] = type(exc).__name__
    except (OSError, ValueError, ssl.SSLError) as exc:
        result['error'] = type(exc).__name__
    return result


def public_probe(host, secure=True):
    result = {'url': ('https://' if secure else 'http://') + host + '/',
              'application_readiness': 'NOT_ASSESSED'}
    connection = None
    try:
        connection = (http.client.HTTPSConnection(host, timeout=8,
                       context=ssl.create_default_context()) if secure
                      else http.client.HTTPConnection(host, timeout=8))
        connection.request('GET', '/', headers={'User-Agent': 'szl-estate-operations/2'})
        response = connection.getresponse()
        result.update(status=response.status, location=response.getheader('location'),
                      server=response.getheader('server'), cf_ray=response.getheader('cf-ray'))
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        result['error'] = type(exc).__name__
    finally:
        if connection:
            connection.close()
    return result


def verify_origins(records, probe=tls_probe):
    origins = [r for r in records if r.get('proxied') and r.get('type') in {'A', 'AAAA', 'CNAME'}]
    results = []
    for record in origins:
        host, target = record['name'], record['content']
        if '*' in host or target.endswith('.cfargotunnel.com') or target == '100::':
            results.append({'host': host, 'target': target, 'verified': False,
                            'error': 'ORIGIN_ROUTE_REQUIRES_PROVIDER_SPECIFIC_VERIFICATION'})
        else:
            results.append(probe(host, target=target))
    return {'verified': bool(results) and all(x.get('verified') for x in results),
            'origins': results,
            'limit': 'DNS origins only; overrides must be absent before automatic SSL upgrade.'}


def desired_value(setting, current):
    if setting == 'min_tls_version':
        if current not in {'1.0', '1.1', '1.2', '1.3'}:
            raise CloudflareError('UNKNOWN_TLS_SETTING_VALUE')
        return current if current in {'1.2', '1.3'} else '1.2'
    if setting == 'ssl':
        if current not in {'off', 'flexible', 'full', 'strict', 'origin_pull'}:
            raise CloudflareError('UNKNOWN_SSL_SETTING_VALUE')
        return current if current in {'strict', 'origin_pull'} else 'strict'
    if setting == 'always_use_https':
        if current not in {'on', 'off'}:
            raise CloudflareError('UNKNOWN_HTTPS_SETTING_VALUE')
        return 'on'
    raise CloudflareError('UNKNOWN_SETTING')


def reconcile(client, zone, records, settings, apply=False, probe=tls_probe,
              routing_verified=False):
    actions, blockers = [], []
    for setting in SETTINGS:
        original = settings[setting]
        if not isinstance(original, dict):
            blockers.append({'zone': zone['name'], 'setting': setting,
                             'reason': 'INVALID_SETTING_RESULT'})
            continue
        current = original.get('value')
        action = {'zone': zone['name'], 'setting': setting, 'before': current,
                  'status': 'UNCHANGED'}
        actions.append(action)
        try:
            desired = desired_value(setting, current)
            action['desired'] = desired
            if current == desired:
                continue
            if zone.get('status') != 'active' or zone.get('paused'):
                raise CloudflareError('ZONE_NOT_ACTIVE')
            if original.get('editable') is not True:
                raise CloudflareError('SETTING_NOT_EDITABLE')
            if setting == 'ssl':
                if not routing_verified:
                    raise CloudflareError('SSL_ROUTING_OVERRIDES_NOT_VERIFIED')
                # Direct origin probes happen before the setting precheck; any
                # DNS/routing changes after inventory also invalidate admission.
                if apply:
                    fresh_records = client.list('/zones/' + zone['id'] + '/dns_records')
                    shape = lambda rows: sorted((r.get('id', ''), r.get('name', ''),
                        r.get('type', ''), r.get('content', ''), bool(r.get('proxied')))
                        for r in rows)
                    if shape(fresh_records) != shape(records):
                        raise CloudflareError('CONCURRENT_DNS_DRIFT')
                origin = verify_origins(records, probe)
                action['origin_evidence'] = origin
                if not origin['verified']:
                    raise CloudflareError('ORIGIN_TLS_NOT_VERIFIED')
            if setting == 'always_use_https':
                hosts = sorted({r['name'] for r in records if r.get('proxied')
                                and r.get('type') in {'A', 'AAAA', 'CNAME'}})
                if not hosts or any('*' in host for host in hosts):
                    raise CloudflareError('EDGE_HOSTS_NOT_VERIFIABLE')
                edge = [probe(host) for host in hosts]
                action['edge_evidence'] = edge
                if not all(item.get('verified') for item in edge):
                    raise CloudflareError('EDGE_HTTPS_NOT_VERIFIED')
            if not apply:
                action['status'] = 'PLANNED'
                continue
            path = '/zones/' + zone['id'] + '/settings/' + setting
            # Cloudflare has no conditional setting PATCH. Refuse observed drift,
            # then minimize the remaining unavoidable read/write race window.
            fresh_zone = client.request('GET', '/zones/' + zone['id'])['result']
            if (fresh_zone.get('name') != zone['name'] or fresh_zone.get('status') != 'active'
                    or fresh_zone.get('paused')):
                raise CloudflareError('ZONE_CHANGED_BEFORE_WRITE')
            fresh = client.request('GET', path)['result']
            if fresh.get('value') != current or fresh.get('modified_on') != original.get('modified_on'):
                raise CloudflareError('CONCURRENT_SETTING_DRIFT')
            if fresh.get('editable') is not True:
                raise CloudflareError('SETTING_NO_LONGER_EDITABLE')
            action['status'] = 'UNKNOWN_AFTER_ATTEMPT'
            write_error = None
            try:
                client.request('PATCH', path, body={'value': desired})
            except CloudflareError as exc:
                write_error = str(exc)
                action['write_error'] = write_error
            try:
                after = client.request('GET', path)['result']
                action['after'] = after
            except CloudflareError:
                raise CloudflareError('READBACK_UNAVAILABLE_AFTER_ATTEMPT') from None
            if write_error:
                action['status'] = 'DESIRED_OBSERVED_WRITE_UNCONFIRMED' if after.get('value') == desired else 'BLOCKED'
                raise CloudflareError(write_error)
            if after.get('value') != desired:
                raise CloudflareError('READBACK_MISMATCH')
            action['status'] = 'APPLIED_VERIFIED'
        except CloudflareError as exc:
            if action['status'] not in {'UNKNOWN_AFTER_ATTEMPT', 'DESIRED_OBSERVED_WRITE_UNCONFIRMED'}:
                action['status'] = 'BLOCKED'
            action['reason'] = str(exc)
            blockers.append({'zone': zone['name'], 'setting': setting, 'reason': str(exc)})
    return actions, blockers


def run(apply=False, *, client=None, environ=None, probe=tls_probe, public=True):
    environ = os.environ if environ is None else environ
    result = {'provider': 'cloudflare', 'observed_at': timestamp(),
              'mode': 'apply' if apply else 'audit', 'inventory': [],
              'actions': [], 'blockers': [], 'public': [],
              'application_readiness': 'NOT_ASSESSED'}
    if public:
        targets = [(name, secure) for name in ZONES for secure in (False, True)]
        targets += [('www.' + name, True) for name in ZONES]
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            result['public'] = list(pool.map(lambda target: public_probe(*target), targets))
        for observation in result['public']:
            if observation.get('error') or observation.get('status', 500) >= 400:
                result['blockers'].append({'url': observation['url'], 'reason': 'PUBLIC_ROUTING_OR_TLS_FAILED'})
    try:
        if client is None:
            token, authentication = resolve_token(environ)
            client = Client(token)
            result['authentication'] = {**authentication, 'status': 'CREDENTIAL_LOADED'}
            token = None
    except CloudflareError as exc:
        result['blockers'].append({'reason': str(exc)})
        result['status'] = 'BLOCKED'
        return result
    for name in ZONES:
        try:
            zone = _zone(client, name, environ)
            path = '/zones/' + zone['id']
            records = client.list(path + '/dns_records')
            settings = {key: client.request('GET', path + '/settings/' + key)['result'] for key in SETTINGS}
            # A zone with any custom rule, page rule, or Worker route requires
            # manual routing analysis before changing origin encryption mode.
            routing_verified = False
            routing = {}
            try:
                routing['rulesets'] = client.list(path + '/rulesets')
                routing['pagerules'] = client.list(path + '/pagerules')
                routing['worker_routes'] = client.list(path + '/workers/routes')
                routing['load_balancers'] = client.list(path + '/load_balancers')
                routing['custom_hostnames'] = client.list(path + '/custom_hostnames')
                routing_verified = not any(routing[key] for key in
                    ('pagerules', 'worker_routes', 'load_balancers', 'custom_hostnames')) and not any(
                    rule.get('kind') != 'managed' for rule in routing['rulesets'])
            except CloudflareError as exc:
                routing['verification_error'] = str(exc)
            clean_records = [{key: record.get(key) for key in
                             ('id', 'name', 'type', 'content', 'proxied', 'modified_on')}
                             for record in records]
            result['inventory'].append({'zone': {key: zone.get(key) for key in
                                        ('id', 'name', 'status', 'paused', 'permissions')},
                                        'dns': clean_records, 'settings': settings, 'routing': routing,
                                        'dns_only_hosts': sorted({r['name'] for r in records
                                        if not r.get('proxied') and r.get('type') in {'A', 'AAAA', 'CNAME'}})})
            actions, blockers = reconcile(client, zone, records, settings, apply, probe, routing_verified)
            result['actions'].extend(actions)
            result['blockers'].extend(blockers)
        except (CloudflareError, KeyError, TypeError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, CloudflareError) else 'INVALID_PROVIDER_RESPONSE'
            result['blockers'].append({'zone': name, 'reason': reason})
    result['status'] = ('BLOCKED' if result['blockers'] else
                        'PLANNED' if any(a['status'] == 'PLANNED' for a in result['actions']) else 'VERIFIED')
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--setup-credential', action='store_true',
                      help='Securely prompt, validate both zones, and save the dedicated Windows credential')
    parser.add_argument('--output')
    args = parser.parse_args()
    report = setup_credential() if args.setup_credential else run(args.apply)
    text = json.dumps(report, indent=2)
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(text + '\n', encoding='utf-8')
    print(text)
    raise SystemExit(2 if report['blockers'] else 0)
