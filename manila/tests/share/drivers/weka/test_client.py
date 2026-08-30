# Copyright 2026 Weka.IO Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Unit tests for manila.share.drivers.weka.client."""

from unittest import mock

import requests

from manila.share.drivers.weka import client as weka_client
from manila.share.drivers.weka import exceptions as weka_exc
from manila import test
from manila.tests.share.drivers.weka import fakes


def _make_response(status_code=200, json_data=None):
    """Build a mock requests.Response."""
    resp = mock.Mock(spec=requests.Response)
    resp.status_code = status_code
    resp.content = b'{}' if json_data is None else b'content'
    json_data = json_data if json_data is not None else {}
    resp.json.return_value = json_data
    resp.text = str(json_data)
    return resp


def _login_response():
    return _make_response(200, {
        'data': {
            'access_token': 'fake-access-token',
            'refresh_token': 'fake-refresh-token',
        }
    })


class TestWekaApiClientAuth(test.TestCase):

    def _make_client(self):
        c = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        return c

    def test_login_stores_tokens(self):
        c = self._make_client()
        with mock.patch.object(c._session, 'post',
                               return_value=_login_response()):
            c.login()
        self.assertEqual('fake-access-token', c._access_token)
        self.assertEqual('fake-refresh-token', c._refresh_token)

    def test_raise_for_status_409_conflict(self):
        c = self._make_client()
        resp = _make_response(409, {'message': 'already exists'})
        self.assertRaises(
            weka_exc.WekaConflict, c._raise_for_status, resp)

    def test_raise_for_status_500_generic(self):
        c = self._make_client()
        resp = _make_response(500, {'message': 'internal error'})
        with self.assertRaises(weka_exc.WekaApiError) as ctx:
            c._raise_for_status(resp)
        self.assertEqual(500, ctx.exception.status_code)

    def test_raise_for_status_non_json_body(self):
        c = self._make_client()
        resp = mock.Mock()
        resp.status_code = 503
        resp.json.side_effect = ValueError('not json')
        resp.text = 'Service Unavailable'
        with self.assertRaises(weka_exc.WekaApiError) as ctx:
            c._raise_for_status(resp)
        self.assertIn('Unavailable', str(ctx.exception))

    def test_raise_for_status_400_capacity_raises_capacity_error(self):
        c = self._make_client()
        msg = (
            'Not enough available drive capacity for filesystem. '
            'requested "1.07 GB", but only "0 B" are free'
        )
        resp = _make_response(400, {'message': msg})
        self.assertRaises(
            weka_exc.WekaCapacityError, c._raise_for_status, resp)

    def test_raise_for_status_400_generic_raises_api_error(self):
        c = self._make_client()
        resp = _make_response(400, {'message': 'bad request'})
        with self.assertRaises(weka_exc.WekaApiError) as ctx:
            c._raise_for_status(resp)
        self.assertEqual(400, ctx.exception.status_code)

    def test_refresh_falls_back_to_login_when_refresh_token_missing(self):
        c = self._make_client()
        c._access_token = 'old-tok'
        c._refresh_token = None  # no refresh token
        with mock.patch.object(c, '_do_login') as do_login:
            c._refresh_or_login()
        do_login.assert_called_once()

    def test_refresh_falls_back_to_login_on_error(self):
        c = self._make_client()
        c._refresh_token = 'bad-refresh'
        refresh_resp = _make_response(401, {'message': 'invalid refresh'})
        with mock.patch.object(c._session, 'post',
                               return_value=refresh_resp):
            with mock.patch.object(c, '_do_login') as do_login:
                c._refresh_or_login()
        do_login.assert_called_once()

    def test_login_raises_auth_error_on_401(self):
        c = self._make_client()
        resp = _make_response(401, {'message': 'bad credentials'})
        with mock.patch.object(c._session, 'post', return_value=resp):
            self.assertRaises(weka_exc.WekaAuthError, c.login)

    def test_login_lockout_403_backs_off_and_raises(self):
        c = self._make_client()
        resp = _make_response(
            403, {'message': 'locked out for 2 minutes'})
        with mock.patch.object(c._session, 'post', return_value=resp):
            with mock.patch('time.sleep') as mock_sleep:
                with self.assertRaises(weka_exc.WekaApiError) as ctx:
                    c.login()
        # 2 minutes = 120 s, +5 guard, capped at 150 → expects 125
        mock_sleep.assert_called_once_with(125)
        self.assertEqual(403, ctx.exception.status_code)

    def test_login_lockout_seconds_backed_off_and_capped(self):
        """403 lockout with a large second count is capped at 150 s."""
        c = self._make_client()
        resp = _make_response(
            403, {'message': 'Locked Out for 200 seconds'})
        with mock.patch.object(c._session, 'post', return_value=resp):
            with mock.patch('time.sleep') as mock_sleep:
                self.assertRaises(weka_exc.WekaApiError, c.login)
        # 200+5=205, capped to 150
        mock_sleep.assert_called_once_with(150)

    def test_login_non_lockout_403_raises_without_sleep(self):
        c = self._make_client()
        resp = _make_response(403, {'message': 'forbidden'})
        with mock.patch.object(c._session, 'post', return_value=resp):
            with mock.patch('time.sleep') as mock_sleep:
                self.assertRaises(weka_exc.WekaApiError, c.login)
        mock_sleep.assert_not_called()

    def test_login_success_no_sleep(self):
        """A successful login must never call time.sleep."""
        c = self._make_client()
        with mock.patch.object(c._session, 'post',
                               return_value=_login_response()):
            with mock.patch('time.sleep') as mock_sleep:
                c.login()
        mock_sleep.assert_not_called()

    def test_login_lockout_non_json_403_raises_without_sleep(self):
        """A 403 whose body is not valid JSON is not treated as a lockout."""
        c = self._make_client()
        resp = mock.Mock()
        resp.status_code = 403
        resp.json.side_effect = ValueError('not json')
        resp.text = 'forbidden'
        with mock.patch.object(c._session, 'post', return_value=resp):
            with mock.patch('time.sleep') as mock_sleep:
                self.assertRaises(weka_exc.WekaApiError, c.login)
        mock_sleep.assert_not_called()

    def test_parse_lockout_seconds_no_match_returns_none(self):
        c = self._make_client()
        result = c._parse_lockout_seconds('some other error message')
        self.assertIsNone(result)

    def test_parse_lockout_compact_and_bare_forms(self):
        """_parse_lockout_seconds handles 1m55s / 2m / 90s forms."""
        c = self._make_client()
        self.assertEqual(
            115, c._parse_lockout_seconds('locked out for another 1m55s'))
        self.assertEqual(120, c._parse_lockout_seconds('locked out for 2m'))
        self.assertEqual(90, c._parse_lockout_seconds('locked out for 90s'))

    def test_login_lockout_real_data_key_backs_off(self):
        """Real Weka body carries the lockout under 'data' in 1m55s form."""
        c = self._make_client()
        resp = _make_response(403, {
            'data': 'Authentication Failed. User has been locked out for '
                    'another 1m55s due to too many login attempts'})
        with mock.patch.object(c._session, 'post', return_value=resp):
            with mock.patch('time.sleep') as mock_sleep:
                with self.assertRaises(weka_exc.WekaApiError) as ctx:
                    c.login()
        # 1m55s = 115 s, +5 guard = 120
        mock_sleep.assert_called_once_with(120)
        self.assertEqual(403, ctx.exception.status_code)

    def test_login_lockout_unparseable_duration_uses_default(self):
        c = self._make_client()
        resp = _make_response(403, {'data': 'user account is locked out'})
        with mock.patch.object(c._session, 'post', return_value=resp):
            with mock.patch('time.sleep') as mock_sleep:
                self.assertRaises(weka_exc.WekaApiError, c.login)
        # unparseable -> 125 default + 5 = 130
        mock_sleep.assert_called_once_with(130)

    def test_request_refreshes_token_on_401(self):
        c = self._make_client()
        c._access_token = 'old-token'
        c._refresh_token = 'old-refresh'

        ok_resp = _make_response(200, {'data': [fakes.fake_filesystem()]})

        # First call returns 401, second returns OK after refresh.
        auth_resp = _make_response(401, {'message': 'expired'})
        refresh_resp = _make_response(200, {
            'data': {'access_token': 'new-token', 'refresh_token': 'new-ref'}
        })

        with mock.patch.object(c._session, 'request',
                               side_effect=[auth_resp, ok_resp]) as req_mock:
            with mock.patch.object(c._session, 'post',
                                   return_value=refresh_resp):
                result = c._request('GET', '/fileSystems',
                                    _retry_auth=True)
        self.assertEqual(ok_resp, result)
        self.assertEqual(2, req_mock.call_count)

    def test_retry_on_429(self):
        c = self._make_client()
        c._access_token = 'tok'
        c._max_retries = 2
        rate_resp = _make_response(429, {'message': 'rate limited'})
        ok_resp = _make_response(200, {'data': []})

        with mock.patch.object(c._session, 'request',
                               side_effect=[rate_resp, rate_resp, ok_resp]):
            with mock.patch('time.sleep'):
                result = c._request('GET', '/fileSystems')
        self.assertEqual(ok_resp, result)

    def test_retry_exhausted_raises(self):
        c = self._make_client()
        c._access_token = 'tok'
        c._max_retries = 1
        rate_resp = _make_response(429, {'message': 'rate limited'})

        with mock.patch.object(c._session, 'request',
                               return_value=rate_resp):
            with mock.patch('time.sleep'):
                self.assertRaises(
                    weka_exc.WekaRateLimited,
                    c._request, 'GET', '/fileSystems')

    def test_retry_on_connection_error(self):
        c = self._make_client()
        c._access_token = 'tok'
        c._max_retries = 2
        ok_resp = _make_response(200, {'data': []})
        with mock.patch.object(
                c._session, 'request',
                side_effect=[requests.exceptions.ConnectionError('boom'),
                             ok_resp]):
            with mock.patch('time.sleep'):
                result = c._request('GET', '/fileSystems')
        self.assertEqual(ok_resp, result)

    def test_connection_error_exhausted_raises(self):
        c = self._make_client()
        c._access_token = 'tok'
        c._max_retries = 1
        with mock.patch.object(
                c._session, 'request',
                side_effect=requests.exceptions.ConnectionError('boom')):
            with mock.patch('time.sleep'):
                self.assertRaises(
                    requests.exceptions.ConnectionError,
                    c._request, 'GET', '/fileSystems')

    def test_404_not_retried(self):
        c = self._make_client()
        c._access_token = 'tok'
        c._max_retries = 3
        not_found = _make_response(404, {'message': 'not found'})

        with mock.patch.object(c._session, 'request',
                               return_value=not_found) as req_mock:
            self.assertRaises(
                weka_exc.WekaNotFound, c._request, 'GET', '/fileSystems/bad')
        # 404 is not retried and does not trigger auth refresh
        self.assertEqual(1, req_mock.call_count)


class TestWekaApiClientFilesystems(test.TestCase):

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def _mock_get(self, path, json_data):
        def side_effect(method, url, **kwargs):
            self.assertEqual('GET', method)
            self.assertIn(path, url)
            return _make_response(200, json_data)
        return mock.patch.object(
            self.client._session, 'request', side_effect=side_effect)

    def test_list_filesystems(self):
        fs_list = [fakes.fake_filesystem()]
        with self._mock_get('/fileSystems', {'data': fs_list}):
            result = self.client.list_filesystems()
        self.assertEqual(fs_list, result)

    def test_get_filesystem(self):
        fs = fakes.fake_filesystem()
        resp = _make_response(200, {'data': fs})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.get_filesystem(fakes.FAKE_FS_UID)
        self.assertEqual(fs, result)

    def test_create_filesystem(self):
        fs = fakes.fake_filesystem()
        resp = _make_response(200, {'data': fs})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.create_filesystem(
                name=fakes.FAKE_FS_NAME,
                group_name=fakes.FAKE_GROUP_NAME,
                total_capacity=10 * 1024 ** 3,
            )
        self.assertEqual(fs, result)

    def test_update_filesystem(self):
        fs = fakes.fake_filesystem(total_capacity=20 * 1024 ** 3)
        resp = _make_response(200, {'data': fs})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.update_filesystem(
                fakes.FAKE_FS_UID, total_capacity=20 * 1024 ** 3)
        self.assertEqual(fs['totalCapacity'], result['totalCapacity'])

    def test_delete_filesystem(self):
        resp = _make_response(200, {})
        resp.content = b''
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.delete_filesystem(fakes.FAKE_FS_UID)
        self.assertEqual({}, result)

    def test_delete_filesystem_purge_from_obs(self):
        resp = _make_response(200, {})
        resp.content = b''
        captured = {}

        def check(method, url, **kwargs):
            captured['params'] = kwargs.get('params')
            return resp

        with mock.patch.object(self.client._session, 'request',
                               side_effect=check):
            result = self.client.delete_filesystem(
                fakes.FAKE_FS_UID, purge_from_obs=True)
        self.assertEqual({}, result)
        self.assertTrue(captured['params'].get('purge_from_obs'))

    def test_get_filesystem_by_name_found(self):
        fs_list = [fakes.fake_filesystem()]
        with mock.patch.object(self.client, 'list_filesystems',
                               return_value=fs_list):
            result = self.client.get_filesystem_by_name(fakes.FAKE_FS_NAME)
        self.assertEqual(fakes.FAKE_FS_UID, result['uid'])

    def test_get_filesystem_by_name_not_found(self):
        with mock.patch.object(self.client, 'list_filesystems',
                               return_value=[]):
            result = self.client.get_filesystem_by_name('nonexistent')
        self.assertIsNone(result)


class TestWekaApiClientFilesystemGroups(test.TestCase):

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def test_list_filesystem_groups(self):
        groups = [fakes.fake_filesystem_group()]
        resp = _make_response(200, {'data': groups})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.list_filesystem_groups()
        self.assertEqual(groups, result)

    def test_create_filesystem_group(self):
        grp = fakes.fake_filesystem_group()
        resp = _make_response(200, {'data': grp})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.create_filesystem_group(
                fakes.FAKE_GROUP_NAME)
        self.assertEqual(grp, result)

    def test_get_filesystem_group_by_name_found(self):
        groups = [fakes.fake_filesystem_group()]
        with mock.patch.object(self.client, 'list_filesystem_groups',
                               return_value=groups):
            result = self.client.get_filesystem_group_by_name(
                fakes.FAKE_GROUP_NAME)
        self.assertEqual(fakes.FAKE_GROUP_UID, result['uid'])

    def test_get_filesystem_group_by_name_not_found(self):
        with mock.patch.object(self.client, 'list_filesystem_groups',
                               return_value=[]):
            result = self.client.get_filesystem_group_by_name('missing')
        self.assertIsNone(result)


class TestWekaApiClientSnapshots(test.TestCase):

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def test_create_snapshot(self):
        snap = fakes.fake_snapshot()
        resp = _make_response(200, {'data': snap})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp) as mock_req:
            result = self.client.create_snapshot(
                fakes.FAKE_FS_UID, fakes.FAKE_SNAP_NAME)
        self.assertEqual(snap, result)
        call_kwargs = mock_req.call_args[1]
        self.assertIn('fs_uid', call_kwargs.get('json', {}))
        self.assertNotIn('filesystem_id', call_kwargs.get('json', {}))
        self.assertNotIn('filesystemId', call_kwargs.get('json', {}))

    def test_delete_snapshot(self):
        resp = _make_response(200, {})
        resp.content = b''
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.delete_snapshot(fakes.FAKE_SNAP_UID)
        self.assertEqual({}, result)

    def test_restore_snapshot(self):
        resp = _make_response(200, {'data': {'status': 'ok'}})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp) as mock_req:
            result = self.client.restore_snapshot(
                fakes.FAKE_SNAP_UID, fakes.FAKE_FS_UID)
        self.assertIsNotNone(result)
        # Verify the v5 endpoint includes both fs_uid and snap_uid in path
        url = mock_req.call_args[1].get('url') or mock_req.call_args[0][1]
        self.assertIn(fakes.FAKE_FS_UID, url)
        self.assertIn(fakes.FAKE_SNAP_UID, url)

    def test_list_snapshots_returns_all(self):
        snaps = [fakes.fake_snapshot(), fakes.fake_snapshot(uid='snap-2')]
        resp = _make_response(200, {'data': snaps})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.list_snapshots()
        self.assertEqual(2, len(result))

    def test_list_snapshots_filtered_by_fs_uid(self):
        snap_match = fakes.fake_snapshot(uid='snap-match',
                                         fs_uid='target-fs-uid')
        snap_other = fakes.fake_snapshot(uid='snap-other',
                                         fs_uid='other-fs-uid')
        resp = _make_response(200, {'data': [snap_match, snap_other]})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.list_snapshots(fs_uid='target-fs-uid')
        self.assertEqual(1, len(result))
        self.assertEqual('snap-match', result[0]['uid'])

    def test_get_snapshot(self):
        snap = fakes.fake_snapshot()
        resp = _make_response(200, {'data': snap})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.get_snapshot(fakes.FAKE_SNAP_UID)
        self.assertEqual(snap, result)

    def test_get_snapshot_by_name_found(self):
        snap = fakes.fake_snapshot()
        with mock.patch.object(self.client, 'list_snapshots',
                               return_value=[snap]):
            result = self.client.get_snapshot_by_name(fakes.FAKE_SNAP_NAME)
        self.assertEqual(fakes.FAKE_SNAP_UID, result['uid'])

    def test_get_snapshot_by_name_not_found(self):
        with mock.patch.object(self.client, 'list_snapshots',
                               return_value=[]):
            result = self.client.get_snapshot_by_name('missing')
        self.assertIsNone(result)


class TestWekaApiClientNFS(test.TestCase):

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def test_create_nfs_permission(self):
        perm = fakes.fake_nfs_permission()
        resp = _make_response(200, {'data': perm})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.create_nfs_permission(
                client_group=fakes.FAKE_CG_UID,
                fs_uid=fakes.FAKE_FS_UID,
                path='/',
                access_type='RW',
            )
        self.assertEqual(perm, result)

    def test_delete_nfs_permission(self):
        resp = _make_response(200, {})
        resp.content = b''
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            self.client.delete_nfs_permission(fakes.FAKE_PERM_UID)

    def test_create_client_group(self):
        cg = fakes.fake_client_group()
        resp = _make_response(200, {'data': cg})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.create_client_group('test-group')
        self.assertEqual(cg, result)

    def test_add_client_group_rule_ip(self):
        resp = _make_response(200, {'data': {}})

        def check(method, url, **kwargs):
            self.assertEqual('POST', method)
            self.assertIn('/nfs/clientGroups/', url)
            self.assertIn('/rules', url)
            self.assertEqual({'ip': '10.0.0.0/255.255.255.0'},
                             kwargs.get('json'))
            return resp

        with mock.patch.object(self.client._session, 'request',
                               side_effect=check):
            self.client.add_client_group_rule(
                fakes.FAKE_CG_UID, 'IP', '10.0.0.0/255.255.255.0')

    def test_add_client_group_rule_dns(self):
        resp = _make_response(200, {'data': {}})

        def check(method, url, **kwargs):
            self.assertEqual('POST', method)
            self.assertIn('/nfs/clientGroups/', url)
            self.assertEqual({'dns': '*.example.com'}, kwargs.get('json'))
            return resp

        with mock.patch.object(self.client._session, 'request',
                               side_effect=check):
            self.client.add_client_group_rule(
                fakes.FAKE_CG_UID, 'DNS', '*.example.com')


class TestWekaApiClientSecurityPolicies(test.TestCase):

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def _capture(self, json_data=None):
        """Patch _session.request, capturing the call, returning a resp."""
        captured = {}

        def side_effect(method, url, **kwargs):
            captured['method'] = method
            captured['url'] = url
            captured['json'] = kwargs.get('json')
            resp = _make_response(200, json_data or {})
            if json_data is None:
                resp.content = b''
            return resp
        patch = mock.patch.object(
            self.client._session, 'request', side_effect=side_effect)
        return patch, captured

    def test_list_security_policies(self):
        pols = [fakes.fake_security_policy()]
        patch, cap = self._capture({'data': pols})
        with patch:
            result = self.client.list_security_policies()
        self.assertEqual(pols, result)
        self.assertEqual('GET', cap['method'])
        self.assertIn('/security/policies', cap['url'])

    def test_get_security_policy_by_name_found(self):
        pols = [fakes.fake_security_policy(name='manila-abc-rw')]
        with mock.patch.object(self.client, 'list_security_policies',
                               return_value=pols):
            result = self.client.get_security_policy_by_name('manila-abc-rw')
        self.assertEqual('manila-abc-rw', result['name'])

    def test_get_security_policy_by_name_not_found(self):
        with mock.patch.object(self.client, 'list_security_policies',
                               return_value=[]):
            result = self.client.get_security_policy_by_name('missing')
        self.assertIsNone(result)

    def test_create_security_policy(self):
        pol = fakes.fake_security_policy(ips=['10.0.0.0/24'])
        patch, cap = self._capture({'data': pol})
        with patch:
            result = self.client.create_security_policy(
                'manila-abc-rw', ips=['10.0.0.0/24'], read_only=False)
        self.assertEqual(pol, result)
        self.assertEqual('POST', cap['method'])
        self.assertEqual('Allow', cap['json']['action'])
        self.assertEqual(['10.0.0.0/24'], cap['json']['ip'])
        self.assertFalse(cap['json']['read_only'])

    def test_update_security_policy_add_and_remove(self):
        pol = fakes.fake_security_policy()
        patch, cap = self._capture({'data': pol})
        with patch:
            self.client.update_security_policy(
                fakes.FAKE_POLICY_UID,
                add_ips=['10.0.0.1'], remove_ips=['10.0.0.2'])
        self.assertEqual('PATCH', cap['method'])
        self.assertIn(fakes.FAKE_POLICY_UID, cap['url'])
        self.assertEqual(['10.0.0.1'], cap['json']['add_ip'])
        self.assertEqual(['10.0.0.2'], cap['json']['remove_ip'])
        # 'name' must never be sent: the API reads it as a rename and
        # rejects the policy's own name with "already in use".
        self.assertNotIn('name', cap['json'])

    def test_update_security_policy_sends_no_name(self):
        """A no-op update sends an empty body, never a name."""
        pol = fakes.fake_security_policy()
        patch, cap = self._capture({'data': pol})
        with patch:
            self.client.update_security_policy(fakes.FAKE_POLICY_UID)
        self.assertEqual({}, cap['json'])

    def test_delete_security_policy(self):
        patch, cap = self._capture()
        with patch:
            result = self.client.delete_security_policy(
                fakes.FAKE_POLICY_UID)
        self.assertEqual({}, result)
        self.assertEqual('DELETE', cap['method'])
        self.assertIn(fakes.FAKE_POLICY_UID, cap['url'])

    def test_get_fs_security_policies(self):
        pols = [fakes.fake_security_policy()]
        patch, cap = self._capture({'data': pols})
        with patch:
            result = self.client.get_fs_security_policies(fakes.FAKE_FS_UID)
        self.assertEqual(pols, result)
        self.assertIn(
            '/fileSystems/{}/securityPolicy'.format(fakes.FAKE_FS_UID),
            cap['url'])

    def test_attach_fs_security_policies(self):
        patch, cap = self._capture({'data': []})
        with patch:
            self.client.attach_fs_security_policies(
                fakes.FAKE_FS_UID, [fakes.FAKE_POLICY_UID])
        self.assertEqual('POST', cap['method'])
        self.assertIn('securityPolicy/attach', cap['url'])
        self.assertEqual(
            {'policies': [fakes.FAKE_POLICY_UID]}, cap['json'])

    def test_detach_fs_security_policies(self):
        patch, cap = self._capture({'data': []})
        with patch:
            self.client.detach_fs_security_policies(
                fakes.FAKE_FS_UID, [fakes.FAKE_POLICY_UID])
        self.assertEqual('POST', cap['method'])
        self.assertIn('securityPolicy/detach', cap['url'])
        self.assertEqual(
            {'policies': [fakes.FAKE_POLICY_UID]}, cap['json'])


class TestWekaApiClientCapacity(test.TestCase):

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def test_get_capacity(self):
        cap = fakes.fake_capacity()
        resp = _make_response(200, {'data': cap})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.get_capacity()
        self.assertEqual(cap, result)

    def test_get_cluster_status(self):
        status = fakes.fake_cluster_status()
        resp = _make_response(200, status)
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.get_cluster_status()
        self.assertEqual(status, result)


class TestWekaApiClientSDKStubs(test.TestCase):
    """Smoke tests for NFS client group methods."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def _patch_request(self, expected_method, expected_path,
                       response_data=None):
        resp = _make_response(200, {'data': response_data or {}})

        def check(method, url, **kwargs):
            assert method.upper() == expected_method.upper(), (
                'Expected %s got %s' % (expected_method, method))
            assert expected_path in url, (
                'Expected path %s in %s' % (expected_path, url))
            return resp

        return mock.patch.object(
            self.client._session, 'request', side_effect=check)

    def test_list_nfs_permissions(self):
        with self._patch_request('GET', '/nfs/permissions', []):
            self.client.list_nfs_permissions()

    def test_list_client_groups(self):
        with self._patch_request('GET', '/clientGroups', []):
            self.client.list_client_groups()

    def test_delete_client_group(self):
        resp = _make_response(200, {})
        resp.content = b''
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            self.client.delete_client_group('cg-1')


class TestWekaApiClientOrganizations(test.TestCase):

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def test_list_organizations(self):
        orgs = [fakes.fake_organization()]
        resp = _make_response(200, {'data': orgs})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.list_organizations()
        self.assertEqual(orgs, result)

    def test_get_organization_by_name_found(self):
        orgs = [fakes.fake_organization(name='manila-proj')]
        with mock.patch.object(self.client, 'list_organizations',
                               return_value=orgs):
            result = self.client.get_organization_by_name('manila-proj')
        self.assertEqual('manila-proj', result['name'])

    def test_get_organization_by_name_not_found(self):
        with mock.patch.object(self.client, 'list_organizations',
                               return_value=[]):
            result = self.client.get_organization_by_name('missing')
        self.assertIsNone(result)

    def test_create_organization_sends_name_user_password(self):
        org = fakes.fake_organization(name='manila-proj')
        captured = {}

        def check(method, url, **kwargs):
            captured['method'] = method
            captured['json'] = kwargs.get('json')
            return _make_response(200, {'data': org})

        with mock.patch.object(self.client._session, 'request',
                               side_effect=check):
            result = self.client.create_organization(
                'manila-proj', 'manila', 'FakePass1!')
        self.assertEqual(org, result)
        self.assertEqual('POST', captured['method'])
        # Netspace mount enforcement is disabled at creation: the tenant
        # has no network space and relies on per-FS auth tokens, so the
        # cluster default (enforced) would reject every mount.
        self.assertEqual(
            {'name': 'manila-proj', 'username': 'manila',
             'password': 'FakePass1!',
             'enforce_mount_netspace_access': False},
            captured['json'])

    def test_delete_organization(self):
        resp = _make_response(200, {})
        resp.content = b''
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            self.client.delete_organization(fakes.FAKE_ORG_UID)

    def test_create_user_sends_role(self):
        user = fakes.fake_user(role='Regular')
        captured = {}

        def check(method, url, **kwargs):
            captured['json'] = kwargs.get('json')
            return _make_response(200, {'data': user})

        with mock.patch.object(self.client._session, 'request',
                               side_effect=check):
            result = self.client.create_user(
                'mountuser', 'Regular', 'Pw1!aaaa')
        self.assertEqual(user, result)
        self.assertEqual('Regular', captured['json']['role'])

    def test_auth_token_payload(self):
        self.client._access_token = 'acc'
        self.client._refresh_token = 'ref'
        payload = self.client.auth_token_payload()
        self.assertEqual('acc', payload['access_token'])
        self.assertEqual('ref', payload['refresh_token'])
        self.assertEqual('Bearer', payload['token_type'])

    def test_for_org_builds_logged_in_client(self):
        with mock.patch.object(weka_client.WekaApiClient, 'login') as login:
            org_client = self.client.for_org(
                'manila-proj', 'manila', 'FakePass1!')
        self.assertIsInstance(org_client, weka_client.WekaApiClient)
        self.assertEqual('manila-proj', org_client._organization)
        self.assertEqual('manila', org_client._username)
        login.assert_called_once()


class TestWekaApiClientRetry(test.TestCase):
    """Test retry/backoff paths in _request."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=2)
        self.client._access_token = 'tok'

    def test_retry_5xx_logs_warning_and_succeeds(self):
        err_resp = _make_response(500, {'message': 'server error'})
        ok_resp = _make_response(200, {'data': []})
        with mock.patch.object(
                self.client._session, 'request',
                side_effect=[err_resp, ok_resp]):
            with mock.patch('time.sleep'):
                result = self.client._request('GET', '/fileSystems')
        self.assertEqual(ok_resp, result)

    def test_retry_5xx_exhausted_raises(self):
        err_resp = _make_response(503, {'message': 'unavailable'})
        with mock.patch.object(
                self.client._session, 'request',
                return_value=err_resp):
            with mock.patch('time.sleep'):
                self.assertRaises(
                    weka_exc.WekaApiError,
                    self.client._request, 'GET', '/fileSystems')


class TestWekaApiClientDelete(test.TestCase):
    """Test _delete helper branches."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def test_delete_with_content_returns_json(self):
        resp = _make_response(200, {'deleted': True})
        resp.content = b'{"deleted": true}'
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client._delete('/fileSystems/uid-1')
        self.assertEqual({'deleted': True}, result)

    def test_delete_with_content_malformed_json_returns_empty(self):
        resp = mock.Mock()
        resp.status_code = 200
        resp.content = b'not-json'
        resp.json.side_effect = ValueError('bad json')
        resp.text = 'not-json'
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client._delete('/fileSystems/uid-1')
        self.assertEqual({}, result)

    def test_delete_no_content_returns_empty(self):
        resp = _make_response(200, {})
        resp.content = b''
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client._delete('/fileSystems/uid-1')
        self.assertEqual({}, result)


class TestWekaApiClientPatch(test.TestCase):
    """Test _patch helper."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def test_patch_sends_patch_method(self):
        resp = _make_response(200, {'data': {'ok': True}})

        def check(method, url, **kwargs):
            self.assertEqual('PATCH', method)
            return resp

        with mock.patch.object(self.client._session, 'request',
                               side_effect=check):
            result = self.client._patch('/some/resource', json={'x': 1})
        self.assertEqual({'ok': True}, result.get('data'))


class TestWekaApiClientRefreshFallback(test.TestCase):
    """Test _refresh_or_login exception fallback branch."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'
        self.client._refresh_token = 'bad-refresh'

    def test_refresh_post_exception_falls_back_to_login(self):
        with mock.patch.object(
                self.client._session, 'post',
                side_effect=Exception('connection error')):
            with mock.patch.object(self.client, '_do_login') as do_login:
                self.client._refresh_or_login()
        do_login.assert_called_once()


class TestCreateOrganizationOptionalKwargs(test.TestCase):
    """Test optional quota params in create_organization."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def test_create_organization_with_ssd_quota(self):
        captured = {}

        def check(method, url, **kwargs):
            captured['json'] = kwargs.get('json')
            return _make_response(200, {'data': {'name': 'org1'}})

        with mock.patch.object(self.client._session, 'request',
                               side_effect=check):
            self.client.create_organization(
                'org1', 'u', 'p', ssd_quota=500)
        self.assertEqual(500, captured['json']['ssd_quota'])
        self.assertNotIn('total_quota', captured['json'])

    def test_create_organization_with_total_quota(self):
        captured = {}

        def check(method, url, **kwargs):
            captured['json'] = kwargs.get('json')
            return _make_response(200, {'data': {'name': 'org1'}})

        with mock.patch.object(self.client._session, 'request',
                               side_effect=check):
            self.client.create_organization(
                'org1', 'u', 'p', total_quota=1000)
        self.assertEqual(1000, captured['json']['total_quota'])
        self.assertNotIn('ssd_quota', captured['json'])


class TestCreateFilesystemOptionalKwargs(test.TestCase):
    """Test optional params in create_filesystem."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def _capture_post(self):
        captured = {}

        def check(method, url, **kwargs):
            captured['json'] = kwargs.get('json')
            return _make_response(200, {'data': {'name': 'fs1'}})

        return mock.patch.object(
            self.client._session, 'request', side_effect=check), captured

    def test_create_filesystem_with_ssd_capacity(self):
        patch, captured = self._capture_post()
        with patch:
            self.client.create_filesystem(
                'fs1', 'grp1', 10 * 1024 ** 3,
                ssd_capacity=5 * 1024 ** 3)
        self.assertEqual(5 * 1024 ** 3, captured['json']['ssd_capacity'])

    def test_create_filesystem_with_obs_buckets(self):
        patch, captured = self._capture_post()
        with patch:
            self.client.create_filesystem(
                'fs1', 'grp1', 10 * 1024 ** 3,
                obs_buckets=['bucket-uid-1'])
        self.assertEqual(['bucket-uid-1'], captured['json']['obs_buckets'])

    def test_create_filesystem_with_data_reduction(self):
        patch, captured = self._capture_post()
        with patch:
            self.client.create_filesystem(
                'fs1', 'grp1', 10 * 1024 ** 3,
                data_reduction=True)
        self.assertTrue(captured['json']['data_reduction'])


class TestUpdateFilesystemOptionalKwargs(test.TestCase):
    """Test optional params in update_filesystem."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def _capture_put(self):
        captured = {}

        def check(method, url, **kwargs):
            captured['json'] = kwargs.get('json')
            return _make_response(200, {'data': {'uid': 'fs-1'}})

        return mock.patch.object(
            self.client._session, 'request', side_effect=check), captured

    def test_update_filesystem_with_name(self):
        patch, captured = self._capture_put()
        with patch:
            self.client.update_filesystem('fs-1', name='new-name')
        self.assertEqual('new-name', captured['json']['name'])

    def test_update_filesystem_with_ssd_capacity(self):
        patch, captured = self._capture_put()
        with patch:
            self.client.update_filesystem('fs-1', ssd_capacity=1024)
        self.assertEqual(1024, captured['json']['ssd_capacity'])

    def test_update_filesystem_with_auth_required(self):
        patch, captured = self._capture_put()
        with patch:
            self.client.update_filesystem('fs-1', auth_required=True)
        self.assertTrue(captured['json']['auth_required'])

    def test_update_filesystem_with_data_reduction(self):
        patch, captured = self._capture_put()
        with patch:
            self.client.update_filesystem('fs-1', data_reduction=False)
        self.assertFalse(captured['json']['data_reduction'])


class TestGetFilesystemGroup(test.TestCase):
    """Test get_filesystem_group."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def test_get_filesystem_group(self):
        grp = {'uid': 'grp-1', 'name': 'default'}
        resp = _make_response(200, {'data': grp})
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp):
            result = self.client.get_filesystem_group('grp-1')
        self.assertEqual(grp, result)


class TestCreateFilesystemGroupOptionalKwargs(test.TestCase):
    """Test optional params in create_filesystem_group."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def _capture_post(self):
        captured = {}

        def check(method, url, **kwargs):
            captured['json'] = kwargs.get('json')
            return _make_response(200, {'data': {'name': 'grp1'}})

        return mock.patch.object(
            self.client._session, 'request', side_effect=check), captured

    def test_create_filesystem_group_with_target_ssd_retention(self):
        patch, captured = self._capture_post()
        with patch:
            self.client.create_filesystem_group(
                'grp1', target_ssd_retention=86400)
        self.assertEqual(86400, captured['json']['target_ssd_retention'])

    def test_create_filesystem_group_with_start_demote(self):
        patch, captured = self._capture_post()
        with patch:
            self.client.create_filesystem_group('grp1', start_demote=10)
        self.assertEqual(10, captured['json']['start_demote'])


class TestCreateNfsPermissionOptionalKwargs(test.TestCase):
    """Test optional params in create_nfs_permission."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def _capture_post(self):
        captured = {}

        def check(method, url, **kwargs):
            captured['json'] = kwargs.get('json')
            return _make_response(200, {'data': {'uid': 'perm-1'}})

        return mock.patch.object(
            self.client._session, 'request', side_effect=check), captured

    def test_create_nfs_permission_with_squash(self):
        patch, captured = self._capture_post()
        with patch:
            self.client.create_nfs_permission(
                'cg1', 'fs1', '/', squash='root')
        self.assertEqual('root', captured['json']['root_squashing'])

    def test_create_nfs_permission_with_anon_uid(self):
        patch, captured = self._capture_post()
        with patch:
            self.client.create_nfs_permission(
                'cg1', 'fs1', '/', anon_uid=65534)
        self.assertEqual(65534, captured['json']['anon_uid'])

    def test_create_nfs_permission_with_anon_gid(self):
        patch, captured = self._capture_post()
        with patch:
            self.client.create_nfs_permission(
                'cg1', 'fs1', '/', anon_gid=65534)
        self.assertEqual(65534, captured['json']['anon_gid'])


class TestDeleteClientGroup(test.TestCase):
    """Test delete_client_group error-handling paths."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def test_delete_client_group_rule(self):
        resp = _make_response(200, {})
        resp.content = b''
        with mock.patch.object(self.client._session, 'request',
                               return_value=resp) as req_mock:
            self.client.delete_client_group_rule('cg-1', 'rule-1')
        url = req_mock.call_args[0][1]
        self.assertIn('cg-1', url)
        self.assertIn('rule-1', url)

    def test_delete_client_group_with_rules(self):
        cg = {'uid': 'cg-1', 'name': 'grp',
              'rules': [{'uid': 'r-1'}, {'uid': 'r-2'}]}
        with mock.patch.object(self.client, 'get_client_group',
                               return_value=cg):
            with mock.patch.object(
                    self.client, 'delete_client_group_rule') as del_rule:
                with mock.patch.object(self.client._session, 'request',
                                       return_value=_make_response(
                                           200, {})) as req_mock:
                    req_mock.return_value.content = b''
                    self.client.delete_client_group('cg-1')
        self.assertEqual(2, del_rule.call_count)

    def test_delete_client_group_rule_error_suppressed(self):
        cg = {'uid': 'cg-1', 'name': 'grp', 'rules': [{'uid': 'r-1'}]}
        resp = _make_response(200, {})
        resp.content = b''
        with mock.patch.object(self.client, 'get_client_group',
                               return_value=cg):
            with mock.patch.object(
                    self.client, 'delete_client_group_rule',
                    side_effect=Exception('rule del failed')):
                with mock.patch.object(self.client._session, 'request',
                                       return_value=resp):
                    result = self.client.delete_client_group('cg-1')
        self.assertEqual({}, result)

    def test_delete_client_group_get_error_suppressed(self):
        resp = _make_response(200, {})
        resp.content = b''
        with mock.patch.object(self.client, 'get_client_group',
                               side_effect=Exception('not found')):
            with mock.patch.object(self.client._session, 'request',
                                   return_value=resp):
                result = self.client.delete_client_group('cg-1')
        self.assertEqual({}, result)


class TestGetCapacityFallback(test.TestCase):
    """Test get_capacity /drives fallback for Weka 5.x."""

    def setUp(self):
        super().setUp()
        self.client = weka_client.WekaApiClient(
            host='weka-test', username='admin', password='secret',
            ssl_verify=False, timeout=5, max_retries=0)
        self.client._access_token = 'tok'

    def test_get_capacity_falls_back_to_drives(self):
        drives = [
            {'size_bytes': 1000, 'percentage_used': 50},
            {'size_bytes': 2000, 'percentage_used': 25},
        ]
        drives_resp = _make_response(200, {'data': drives})

        def _get_side_effect(path, params=None):
            if path == '/capacity':
                raise weka_exc.WekaNotFound(reason='not found')
            if path == '/drives':
                return drives_resp.json()
            raise AssertionError('unexpected path: ' + path)

        with mock.patch.object(self.client, '_get',
                               side_effect=_get_side_effect):
            result = self.client.get_capacity()
        self.assertEqual(3000, result['totalBytes'])
        self.assertEqual(500 + 500, result['usedBytes'])

    def test_get_capacity_drives_not_list_returns_empty(self):
        def _get_side_effect(path, params=None):
            if path == '/capacity':
                raise weka_exc.WekaNotFound(reason='not found')
            if path == '/drives':
                return {'error': 'unexpected'}
            raise AssertionError('unexpected path: ' + path)

        with mock.patch.object(self.client, '_get',
                               side_effect=_get_side_effect):
            result = self.client.get_capacity()
        self.assertEqual({}, result)
