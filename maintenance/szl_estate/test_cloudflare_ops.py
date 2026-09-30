"""Mocked regression checks for destructive downgrade and false-success cases."""
import copy
import ctypes
import json
import unittest
from unittest.mock import Mock, patch

try:
    from . import cloudflare_ops as cf
except ImportError:
    import cloudflare_ops as cf

ZONE = {'id': 'a' * 32, 'name': 'a-11-oy.com', 'status': 'active', 'paused': False}
RECORDS = [{'name': 'a-11-oy.com', 'content': '192.0.2.1', 'type': 'A', 'proxied': True}]


def settings(tls='1.0', mode='strict', https='on'):
    return {key: {'id': key, 'value': value, 'editable': True, 'modified_on': 'before'}
            for key, value in {'always_use_https': https, 'min_tls_version': tls, 'ssl': mode}.items()}


class Fake:
    def __init__(self, state=None):
        self.state = copy.deepcopy(state or settings())
        self.calls = []
        self.drift = None
        self.write_error = None
        self.readback_error = False
        self.wrong_readback = False
        self.did_write = False

    def request(self, method, path, query=None, body=None):
        self.calls.append((method, path, body))
        if path == '/zones/' + ZONE['id']:
            return {'success': True, 'result': dict(ZONE)}
        key = path.rsplit('/', 1)[-1]
        if method == 'GET':
            if self.did_write and self.readback_error:
                raise cf.CloudflareError('READBACK_NETWORK_ERROR')
            item = dict(self.state[key])
            if self.drift and not self.did_write:
                item['value'] = self.drift
            return {'success': True, 'result': item}
        self.did_write = True
        if self.write_error:
            raise cf.CloudflareError(self.write_error)
        if not self.wrong_readback:
            self.state[key]['value'] = body['value']
            self.state[key]['modified_on'] = 'after'
        return {'success': True, 'result': dict(self.state[key])}

    @property
    def writes(self):
        return [c for c in self.calls if c[0] == 'PATCH']

    def list(self, path, query=None, per_page=100):
        return copy.deepcopy(RECORDS)


class CloudflareTests(unittest.TestCase):
    def test_audit_performs_no_mutation(self):
        fake = Fake()
        actions, blockers = cf.reconcile(fake, ZONE, RECORDS, settings())
        self.assertEqual(fake.writes, [])
        self.assertEqual(actions[1]['status'], 'PLANNED')
        self.assertEqual(blockers, [])

    def test_tls13_and_origin_pull_are_preserved(self):
        state = settings(tls='1.3', mode='origin_pull')
        fake = Fake(state)
        actions, blockers = cf.reconcile(fake, ZONE, RECORDS, state, apply=True)
        self.assertEqual(fake.calls, [])
        self.assertEqual([a['status'] for a in actions], ['UNCHANGED'] * 3)
        self.assertEqual(blockers, [])

    def test_only_necessary_patch_and_idempotent_second_run(self):
        fake = Fake()
        actions, blockers = cf.reconcile(fake, ZONE, RECORDS, settings(), apply=True)
        self.assertEqual(actions[1]['status'], 'APPLIED_VERIFIED')
        self.assertEqual(blockers, [])
        self.assertEqual(len(fake.writes), 1)
        cf.reconcile(fake, ZONE, RECORDS, copy.deepcopy(fake.state), apply=True)
        self.assertEqual(len(fake.writes), 1)

    def test_prewrite_drift_stops_write(self):
        fake = Fake()
        fake.drift = '1.3'
        actions, blockers = cf.reconcile(fake, ZONE, RECORDS, settings(), apply=True)
        self.assertEqual(fake.writes, [])
        self.assertEqual(blockers[0]['reason'], 'CONCURRENT_SETTING_DRIFT')

    def test_failed_write_is_not_success_even_with_successful_readback(self):
        fake = Fake()
        fake.write_error = 'CLOUDFLARE_HTTP_403'
        actions, blockers = cf.reconcile(fake, ZONE, RECORDS, settings(), apply=True)
        self.assertEqual(actions[1]['status'], 'BLOCKED')
        self.assertEqual(actions[1]['after']['value'], '1.0')
        self.assertTrue(blockers)

    def test_uncertain_write_has_explicit_unknown_state(self):
        fake = Fake()
        fake.readback_error = True
        actions, blockers = cf.reconcile(fake, ZONE, RECORDS, settings(), apply=True)
        self.assertEqual(actions[1]['status'], 'UNKNOWN_AFTER_ATTEMPT')
        self.assertEqual(blockers[0]['reason'], 'READBACK_UNAVAILABLE_AFTER_ATTEMPT')

    def test_readback_mismatch_is_not_verified(self):
        fake = Fake()
        fake.wrong_readback = True
        actions, blockers = cf.reconcile(fake, ZONE, RECORDS, settings(), apply=True)
        self.assertEqual(actions[1]['status'], 'UNKNOWN_AFTER_ATTEMPT')
        self.assertEqual(blockers[0]['reason'], 'READBACK_MISMATCH')

    def test_flexible_origin_is_never_blindly_moved_to_strict(self):
        state = settings(tls='1.2', mode='flexible')
        fake = Fake(state)
        actions, blockers = cf.reconcile(fake, ZONE, RECORDS, state, apply=True,
                                         probe=lambda *a, **kw: {'verified': True})
        self.assertEqual(fake.writes, [])
        self.assertEqual(blockers[0]['reason'], 'SSL_ROUTING_OVERRIDES_NOT_VERIFIED')

    def test_invalid_origin_cert_stops_ssl_upgrade(self):
        state = settings(tls='1.2', mode='full')
        fake = Fake(state)
        actions, blockers = cf.reconcile(fake, ZONE, RECORDS, state, apply=True,
            probe=lambda *a, **kw: {'verified': False}, routing_verified=True)
        self.assertEqual(fake.writes, [])
        self.assertEqual(blockers[0]['reason'], 'ORIGIN_TLS_NOT_VERIFIED')

    def test_dns_target_and_requested_sni_are_both_checked(self):
        seen = []
        def probe(host, target=None):
            seen.append((host, target))
            return {'verified': True}
        state = settings(tls='1.2', mode='full')
        fake = Fake(state)
        actions, blockers = cf.reconcile(fake, ZONE, RECORDS, state, apply=True,
                                         probe=probe, routing_verified=True)
        self.assertEqual(seen, [('a-11-oy.com', '192.0.2.1')])
        self.assertEqual(actions[2]['status'], 'APPLIED_VERIFIED')

    def test_tunnel_is_not_mistaken_for_verified_origin(self):
        records = [{'name': 'gpu.a-11-oy.com', 'content': 'abc.cfargotunnel.com',
                    'type': 'CNAME', 'proxied': True}]
        result = cf.verify_origins(records, lambda *a, **kw: {'verified': True})
        self.assertFalse(result['verified'])

    def test_changed_dns_stops_ssl_upgrade(self):
        state = settings(tls='1.2', mode='full')
        fake = Fake(state)
        fake.list = lambda *a, **kw: [{**RECORDS[0], 'content': '192.0.2.99'}]
        actions, blockers = cf.reconcile(fake, ZONE, RECORDS, state, apply=True,
            probe=lambda *a, **kw: {'verified': True}, routing_verified=True)
        self.assertEqual(fake.writes, [])
        self.assertEqual(blockers[0]['reason'], 'CONCURRENT_DNS_DRIFT')

    def test_failed_edge_https_stops_redirect_enforcement(self):
        state = settings(tls='1.2', https='off')
        fake = Fake(state)
        _, blockers = cf.reconcile(fake, ZONE, RECORDS, state, apply=True,
                                    probe=lambda *a, **kw: {'verified': False})
        self.assertEqual(fake.writes, [])
        self.assertEqual(blockers[0]['reason'], 'EDGE_HTTPS_NOT_VERIFIED')

    def test_zone_env_id_must_match_expected_name(self):
        class WrongZone:
            def request(self, *a, **kw):
                return {'result': {**ZONE, 'name': 'other.example'}}
        with self.assertRaisesRegex(cf.CloudflareError, 'ZONE_ID_NAME_MISMATCH'):
            cf._zone(WrongZone(), 'a-11-oy.com', {'CF_ZONE_ID_A11OY_COM': 'a' * 32})

    def test_missing_token_fails_without_sending_bearer_none(self):
        with patch.object(cf.Client, 'request', side_effect=AssertionError('network called')), \
                patch.object(cf, 'read_windows_credential', return_value=None):
            report = cf.run(environ={}, public=False)
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertEqual(report['blockers'][0]['reason'], 'CLOUDFLARE_TOKEN_UNAVAILABLE')

    def test_pagination_rejects_error_objects(self):
        client = cf.Client('unit-test-placeholder')
        client.request = lambda *a, **kw: {'result': {'error': 'not a list'}}
        with self.assertRaisesRegex(cf.CloudflareError, 'INVALID_PAGINATED_RESULT'):
            client.list('/zones')

    def test_pagination_rejects_truncated_result(self):
        client = cf.Client('unit-test-placeholder')
        client.request = lambda *a, **kw: {'result': [{'id': 'a'}],
                                         'result_info': {'total_pages': 1, 'total_count': 2}}
        with self.assertRaisesRegex(cf.CloudflareError, 'PAGINATION_COUNT_MISMATCH'):
            client.list('/zones')

    def test_pagination_is_bounded_even_if_server_repeats(self):
        client = cf.Client('unit-test-placeholder')
        client.request = lambda *a, **kw: {'result': [{'id': 'a'}] * 100}
        with self.assertRaisesRegex(cf.CloudflareError, 'PAGINATION_REPEATED_PAGE'):
            client.list('/zones')

    def test_client_rejects_writes_outside_settings_and_cross_origin_paths(self):
        client = cf.Client('unit-test-placeholder')
        for method, path in [('PATCH', '/zones/' + 'a' * 32 + '/dns_records'),
                             ('GET', '//attacker.example/zones'),
                             ('DELETE', '/zones/' + 'a' * 32)]:
            with self.subTest(path=path), self.assertRaises(cf.CloudflareError):
                client.request(method, path)


class CredentialTests(unittest.TestCase):
    TOKEN = 'unit-test-placeholder-secret'

    def test_environment_wins_without_accessing_vault(self):
        with patch.object(cf, 'read_windows_credential', side_effect=AssertionError('vault accessed')):
            token, source = cf.resolve_token({'CF_API_TOKEN': self.TOKEN, 'CLOUDFLARE_API_TOKEN': 'other'})
        self.assertEqual(token, self.TOKEN)
        self.assertEqual(source['variable'], 'CF_API_TOKEN')
        self.assertNotIn(self.TOKEN, json.dumps(source))

    def test_invalid_explicit_environment_does_not_use_different_identity(self):
        with patch.object(cf, 'read_windows_credential') as reader:
            with self.assertRaisesRegex(cf.CloudflareError, 'TOKEN_INVALID_FORMAT'):
                cf.resolve_token({'CF_API_TOKEN': 'invalid token\n'})
        reader.assert_not_called()

    def test_dedicated_vault_fallback_without_environment(self):
        with patch.object(cf, 'read_windows_credential', return_value=self.TOKEN):
            token, source = cf.resolve_token({})
        self.assertEqual(token, self.TOKEN)
        self.assertEqual(source, {'source': 'windows_credential_manager',
                                  'target': 'SZL/Cloudflare/estate-api-token'})

    def test_vault_access_failure_is_explicit_and_no_network_request_occurs(self):
        with patch.object(cf, 'read_windows_credential',
                          side_effect=cf.CloudflareError('WINDOWS_CREDENTIAL_READ_FAILED_5')), \
                patch.object(cf.Client, 'request') as request:
            report = cf.run(environ={}, public=False)
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertEqual(report['blockers'][0]['reason'], 'WINDOWS_CREDENTIAL_READ_FAILED_5')
        request.assert_not_called()

    def test_wincred_missing_is_absent_and_only_our_target_is_queried(self):
        api = Mock()
        api.CredReadW.return_value = 0
        with patch.object(cf, '_is_windows', return_value=True), \
                patch.object(cf, '_wincred_api', return_value=api), \
                patch.object(ctypes, 'get_last_error', return_value=1168, create=True):
            self.assertIsNone(cf.read_windows_credential())
        self.assertEqual(api.CredReadW.call_args.args[:3], (cf.WINDOWS_CREDENTIAL_TARGET, 1, 0))
        api.CredFree.assert_not_called()

    def test_wincred_api_access_denial_is_not_silently_missing(self):
        api = Mock()
        api.CredReadW.return_value = 0
        with patch.object(cf, '_is_windows', return_value=True), \
                patch.object(cf, '_wincred_api', return_value=api), \
                patch.object(ctypes, 'get_last_error', return_value=5, create=True):
            with self.assertRaisesRegex(cf.CloudflareError, 'WINDOWS_CREDENTIAL_READ_FAILED_5'):
                cf.read_windows_credential()

    def _reader_api(self, blob):
        api = Mock()
        buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        credential = cf._Credential()
        credential.CredentialBlobSize = len(blob)
        credential.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
        def read(target, kind, flags, destination):
            ctypes.cast(destination, ctypes.POINTER(ctypes.POINTER(cf._Credential)))[0] = ctypes.pointer(credential)
            return 1
        api.CredReadW.side_effect = read
        api._keep_alive = (credential, buf)
        return api

    def test_wincred_blob_decodes_and_is_freed_without_serialization(self):
        api = self._reader_api(self.TOKEN.encode('utf-16-le'))
        with patch.object(cf, '_is_windows', return_value=True), patch.object(cf, '_wincred_api', return_value=api):
            self.assertEqual(cf.read_windows_credential(), self.TOKEN)
        api.CredFree.assert_called_once()

    def test_bad_wincred_blob_is_freed_and_fails_closed(self):
        api = self._reader_api(b'bad')
        with patch.object(cf, '_is_windows', return_value=True), patch.object(cf, '_wincred_api', return_value=api):
            with self.assertRaisesRegex(cf.CloudflareError, 'WINDOWS_CREDENTIAL_INVALID_BLOB'):
                cf.read_windows_credential()
        api.CredFree.assert_called_once()

    def test_native_store_uses_dedicated_user_record_and_verifies_readback(self):
        api = Mock()
        seen = {}
        def write(pointer, flags):
            credential = ctypes.cast(pointer, ctypes.POINTER(cf._Credential)).contents
            seen.update(target=credential.TargetName, kind=credential.Type, persist=credential.Persist,
                        token=ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize).decode('utf-16-le'))
            return 1
        api.CredWriteW.side_effect = write
        with patch.object(cf, '_is_windows', return_value=True), patch.object(cf, '_wincred_api', return_value=api), \
                patch.object(cf, 'read_windows_credential', return_value=self.TOKEN):
            cf.store_windows_credential(self.TOKEN)
        self.assertEqual(seen, {'target': cf.WINDOWS_CREDENTIAL_TARGET, 'kind': 1, 'persist': 2, 'token': self.TOKEN})

    def test_setup_rejects_insecure_prompt_without_storing(self):
        def insecure_prompt(_):
            import warnings
            warnings.warn('echo unavailable', cf.getpass.GetPassWarning)
            return self.TOKEN
        store = Mock()
        with patch.object(cf, '_is_windows', return_value=True):
            report = cf.setup_credential(prompt=insecure_prompt, store=store)
        self.assertEqual(report['blockers'][0]['reason'], 'SECURE_INPUT_UNAVAILABLE_OR_CANCELLED')
        store.assert_not_called()

    def test_setup_validation_failure_does_not_store_or_leak_token(self):
        store = Mock()
        with patch.object(cf, '_is_windows', return_value=True), \
                patch.object(cf, 'validate_setup_access', side_effect=RuntimeError(self.TOKEN)):
            report = cf.setup_credential(prompt=lambda _: self.TOKEN, client_factory=Mock(), store=store)
        self.assertFalse(report['stored'])
        self.assertNotIn(self.TOKEN, json.dumps(report))
        store.assert_not_called()

    def test_setup_stores_only_after_both_zones_validate(self):
        events = []
        def validate(_):
            events.append('validate')
            return [{'name': name} for name in cf.ZONES]
        with patch.object(cf, '_is_windows', return_value=True), patch.object(cf, 'validate_setup_access', side_effect=validate):
            report = cf.setup_credential(prompt=lambda _: self.TOKEN, client_factory=Mock(),
                                        store=lambda token: events.append('store'))
        self.assertEqual(events, ['validate', 'store'])
        self.assertTrue(report['stored'])
        self.assertEqual(report['status'], 'STORED_VERIFIED')
        self.assertNotIn(self.TOKEN, json.dumps(report))

    def test_setup_preserves_uncertain_local_write_state(self):
        with patch.object(cf, '_is_windows', return_value=True), patch.object(cf, 'validate_setup_access', return_value=[]):
            report = cf.setup_credential(prompt=lambda _: self.TOKEN, client_factory=Mock(),
                store=Mock(side_effect=cf.CloudflareError('WINDOWS_CREDENTIAL_READBACK_FAILED')))
        self.assertEqual(report['status'], 'UNKNOWN_AFTER_ATTEMPT')
        self.assertIsNone(report['stored'])

    def test_setup_interruption_or_unexpected_exception_during_store_is_unknown(self):
        for failure in (KeyboardInterrupt(), RuntimeError(self.TOKEN)):
            with self.subTest(failure=type(failure).__name__):
                simulated_writes = []
                def interrupted_store(token):
                    simulated_writes.append(True)
                    raise failure
                with patch.object(cf, '_is_windows', return_value=True), \
                        patch.object(cf, 'validate_setup_access', return_value=[]):
                    report = cf.setup_credential(prompt=lambda _: self.TOKEN,
                        client_factory=Mock(), store=interrupted_store)
                self.assertEqual(simulated_writes, [True])
                self.assertEqual(report['status'], 'UNKNOWN_AFTER_ATTEMPT')
                self.assertIsNone(report['stored'])
                self.assertNotIn(self.TOKEN, json.dumps(report))

    def test_setup_interruption_before_storage_remains_blocked_without_write(self):
        store = Mock()
        with patch.object(cf, '_is_windows', return_value=True), \
                patch.object(cf, 'validate_setup_access', side_effect=KeyboardInterrupt()):
            report = cf.setup_credential(prompt=lambda _: self.TOKEN,
                                        client_factory=Mock(), store=store)
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertFalse(report['stored'])
        store.assert_not_called()

    def _setup_client(self, settings_write=True, deny_second=False):
        class SetupClient:
            def list(self, path, query=None, per_page=100):
                if path == '/zones':
                    name = query['name']
                    return [{'name': name, 'id': ('a' if name == 'a-11-oy.com' else 'b') * 32}]
                return []
            def request(self, method, path, query=None, body=None):
                if method != 'GET':
                    raise AssertionError('remote writes forbidden during setup')
                is_second = '/zones/' + 'b' * 32 in path
                if deny_second and is_second:
                    raise cf.CloudflareError('CLOUDFLARE_HTTP_403')
                if '/settings/' in path:
                    key = path.rsplit('/', 1)[-1]
                    return {'result': settings(tls='1.2')[key]}
                return {'result': {'name': 'a11oy.net' if is_second else 'a-11-oy.com',
                                  'id': ('b' if is_second else 'a') * 32,
                                  'permissions': ['#zone_settings:edit' if settings_write else '#zone_settings:read']}}
        return SetupClient()

    def test_setup_access_checks_both_zones_without_remote_writes(self):
        report = cf.validate_setup_access(self._setup_client())
        self.assertEqual([z['name'] for z in report], list(cf.ZONES))
        self.assertTrue(all(z['settings_edit'] == 'REPORTED_BY_PROVIDER_PERMISSIONS' for z in report))

    def test_runner_audits_using_vault_without_token_environment(self):
        with patch.object(cf, 'read_windows_credential', return_value=self.TOKEN), \
                patch.object(cf, 'Client', return_value=self._setup_client()):
            report = cf.run(environ={}, public=False)
        self.assertEqual(report['status'], 'VERIFIED')
        self.assertEqual(report['authentication']['source'], 'windows_credential_manager')
        self.assertEqual(len(report['inventory']), 2)
        self.assertNotIn(self.TOKEN, json.dumps(report))

    def test_read_only_token_cannot_pass_setup_for_apply(self):
        with self.assertRaisesRegex(cf.CloudflareError, 'ZONE_SETTINGS_EDIT_PERMISSION_NOT_CONFIRMED'):
            cf.validate_setup_access(self._setup_client(settings_write=False))

    def test_missing_second_zone_prevents_credential_storage(self):
        store = Mock()
        with patch.object(cf, '_is_windows', return_value=True):
            report = cf.setup_credential(prompt=lambda _: self.TOKEN,
                client_factory=lambda _: self._setup_client(deny_second=True), store=store)
        self.assertFalse(report['stored'])
        store.assert_not_called()


if __name__ == '__main__':
    unittest.main()
