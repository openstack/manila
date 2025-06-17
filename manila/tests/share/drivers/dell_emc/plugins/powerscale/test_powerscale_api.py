# Copyright (c) 2015 EMC Corporation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from unittest import mock

import ddt
from oslo_serialization import jsonutils as json
import requests
import requests_mock

from manila import exception
from manila.share.drivers.dell_emc.plugins.powerscale import powerscale_api
from manila import test


@ddt.ddt
class PowerScaleApiTest(test.TestCase):

    @mock.patch('manila.share.drivers.dell_emc.plugins.powerscale.'
                'powerscale_api.PowerScaleApi.create_session')
    def setUp(self, mockup_create_session):
        super(PowerScaleApiTest, self).setUp()

        mockup_create_session.return_value = True
        self._mock_url = 'https://localhost:8080'
        self.username = 'admin'
        self.password = 'pwd'
        self.dir_permission = '0777'
        self.powerscale_api = powerscale_api.PowerScaleApi(
            self._mock_url, self.username, self.password,
            dir_permission=self.dir_permission
        )
        self.powerscale_api_threshold = powerscale_api.PowerScaleApi(
            self._mock_url, self.username, self.password,
            dir_permission=self.dir_permission,
            threshold_limit=80
        )

    @mock.patch('manila.share.drivers.dell_emc.plugins.powerscale.'
                'powerscale_api.PowerScaleApi.create_session')
    def test__init__login_failure(self, mockup_create_session):
        mockup_create_session.return_value = False
        self.assertRaises(
            exception.BadConfigurationException,
            self.powerscale_api.__init__,
            self._mock_url,
            self.username,
            self.password,
            False,
            None,
            self.dir_permission
        )

    def test__verify_cert(self):
        verify_cert = self.powerscale_api.verify_ssl_cert
        certificate_path = self.powerscale_api.certificate_path
        self.powerscale_api.verify_ssl_cert = True
        self.powerscale_api.certificate_path = "fake_certificate_path"
        self.assertEqual(self.powerscale_api._verify_cert,
                         self.powerscale_api.certificate_path)
        self.powerscale_api.verify_ssl_cert = verify_cert
        self.powerscale_api.certificate_path = certificate_path

    @mock.patch('requests.Session.request')
    def test_create_session_success(self, mock_request):
        mock_response = mock.Mock()
        mock_response.status_code = 201
        mock_response.cookies = {'isisessid': 'test_session_token',
                                 'isicsrf': 'test_csrf_token'}
        mock_request.return_value = mock_response
        result = self.powerscale_api.create_session(
            self.username, self.password)
        mock_request.assert_called_once_with(
            'POST', self._mock_url + '/session/1/session',
            headers={"Content-type": "application/json"},
            data=json.dumps({"username": self.username,
                             "password": self.password,
                             "services": ["platform", "namespace"]}),
            verify=False
        )
        self.assertTrue(result)
        self.assertEqual(self.powerscale_api.session_token,
                         'test_session_token')
        self.assertEqual(self.powerscale_api.csrf_token, 'test_csrf_token')

    @mock.patch('requests.Session.request')
    def test_create_session_failure(self, mock_request):
        mock_response = mock.Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {
            'message': 'Username or password is incorrect.'}
        mock_request.return_value = mock_response
        result = self.powerscale_api.create_session(
            self.username, self.password)
        self.assertFalse(result)
        self.assertIsNone(self.powerscale_api.session_token)
        self.assertIsNone(self.powerscale_api.csrf_token)

    @ddt.data(False, True)
    def test_create_directory(self, is_recursive):
        with requests_mock.Mocker() as m:
            path = '/ifs/test'
            self.assertEqual(0, len(m.request_history))
            self._add_create_directory_response(m, path, is_recursive)

            r = self.powerscale_api.create_directory(path,
                                                     recursive=is_recursive)

            self.assertTrue(r)
            self.assertEqual(1, len(m.request_history))
            request = m.request_history[0]
            self._verify_dir_creation_request(request, path, is_recursive)

    def test_create_directory_no_permission(self):
        with requests_mock.Mocker() as m:
            path = '/ifs/test'
            self.powerscale_api.dir_permission = None
            self.assertEqual(0, len(m.request_history))
            self._add_create_directory_response(m, path, True)

            r = self.powerscale_api.create_directory(path,
                                                     recursive=True)

            self.powerscale_api.dir_permission = '0777'
            self.assertTrue(r)
            self.assertEqual(1, len(m.request_history))
            request = m.request_history[0]
            self.assertNotIn("x-isi-ifs-access-control", request.headers)

    @requests_mock.mock()
    def test_clone_snapshot(self, m):
        snapshot_name = 'snapshot01'
        fq_target_dir = '/ifs/admin/target'

        self.assertEqual(0, len(m.request_history))
        self._add_create_directory_response(m, fq_target_dir, False)
        snapshots_json = (
            '{"snapshots": '
            '[{"name": "snapshot01", "path": "/ifs/admin/source"}]'
            '}'
        )
        self._add_get_snapshot_response(m, snapshot_name, snapshots_json)

        # In order to test cloning a snapshot, we build out a mock
        # source directory tree. After the method under test is called we
        # will verify the necessary calls are made to clone a snapshot.
        source_dir_listing_json = (
            '{"children": ['
            '{"name": "dir1", "type": "container"},'
            '{"name": "dir2", "type": "container"},'
            '{"name": "file1", "type": "object"},'
            '{"name": "file2", "type": "object"}'
            ']}'
        )
        self._add_get_directory_listing_response(
            m, '/ifs/.snapshot/{0}/admin/source'.format(snapshot_name),
            source_dir_listing_json)

        # Add request responses for creating directories and cloning files
        # to the destination tree
        self._add_file_clone_response(m, '/ifs/admin/target/file1',
                                      snapshot_name)
        self._add_file_clone_response(m, '/ifs/admin/target/file2',
                                      snapshot_name)
        self._add_create_directory_response(m, fq_target_dir + '/dir1', False)
        self._add_get_directory_listing_response(
            m, '/ifs/.snapshot/{0}/admin/source/dir1'.format(snapshot_name),
            '{"children": ['
            '{"name": "file11", "type": "object"}, '
            '{"name": "file12", "type": "object"}'
            ']}')
        self._add_file_clone_response(m, '/ifs/admin/target/dir1/file11',
                                      snapshot_name)
        self._add_file_clone_response(m, '/ifs/admin/target/dir1/file12',
                                      snapshot_name)
        self._add_create_directory_response(m, fq_target_dir + '/dir2', False)
        self._add_get_directory_listing_response(
            m, '/ifs/.snapshot/{0}/admin/source/dir2'.format(snapshot_name),
            '{"children": ['
            '{"name": "file21", "type": "object"}, '
            '{"name": "file22", "type": "object"}'
            ']}')
        self._add_file_clone_response(m, '/ifs/admin/target/dir2/file21',
                                      snapshot_name)
        self._add_file_clone_response(m, '/ifs/admin/target/dir2/file22',
                                      snapshot_name)

        # Call method under test
        self.powerscale_api.clone_snapshot(snapshot_name, fq_target_dir)

        # Verify calls needed to clone the source snapshot to the target dir
        expected_calls = []
        clone_path_list = [
            'file1', 'file2', 'dir1/file11', 'dir1/file12',
            'dir2/file21', 'dir2/file22']
        for path in clone_path_list:
            expected_call = PowerScaleApiTest.ExpectedCall(
                PowerScaleApiTest.ExpectedCall.FILE_CLONE,
                self._mock_url + '/namespace/ifs/admin/target/' + path,
                ['/ifs/admin/target/' + path, '/ifs/admin/source/' + path,
                 snapshot_name])
            expected_calls.append(expected_call)
        dir_path_list = [
            ('/dir1?recursive', '/dir1'),
            ('/dir2?recursive', '/dir2'),
            ('?recursive=', '')]
        for url, path in dir_path_list:
            expected_call = PowerScaleApiTest.ExpectedCall(
                PowerScaleApiTest.ExpectedCall.DIR_CREATION,
                self._mock_url + '/namespace/ifs/admin/target' + url,
                ['/ifs/admin/target' + path, False])
            expected_calls.append(expected_call)

        self._verify_clone_snapshot_calls(expected_calls, m.request_history)

    class ExpectedCall(object):
        DIR_CREATION = 'dir_creation'
        FILE_CLONE = 'file_clone'

        def __init__(self, request_type, match_url, verify_args):
            self.request_type = request_type
            self.match_url = match_url
            self.verify_args = verify_args

    def _verify_clone_snapshot_calls(self, expected_calls, response_calls):
        actual_calls = []
        for call in response_calls:
            actual_calls.append(call)
        for expected_call in expected_calls:
            # Match the expected call to the actual call, then verify
            match_found = False
            for call in actual_calls:
                if call.url.startswith(expected_call.match_url):
                    match_found = True
                    if expected_call.request_type == 'dir_creation':
                        self._verify_dir_creation_request(
                            call, *expected_call.verify_args)
                    elif expected_call.request_type == 'file_clone':
                        pass
                    else:
                        self.fail('Invalid request type')
                    actual_calls.remove(call)
            self.assertTrue(match_found)

    @requests_mock.mock()
    def test_get_directory_listing(self, m):
        self.assertEqual(0, len(m.request_history))
        fq_dir_path = 'ifs/admin/test'
        json_str = '{"my_json": "test123"}'
        self._add_get_directory_listing_response(m, fq_dir_path, json_str)

        actual_json = self.powerscale_api.get_directory_listing(fq_dir_path)

        self.assertEqual(1, len(m.request_history))
        self.assertEqual(json.loads(json_str), actual_json)

    @ddt.data((200, True), (404, False))
    def test_is_path_existent(self, data):
        status_code, expected_return_value = data
        with requests_mock.mock() as m:
            self.assertEqual(0, len(m.request_history))
            path = '/ifs/home/admin'
            m.head('{0}/namespace{1}'.format(self._mock_url, path),
                   status_code=status_code)

            r = self.powerscale_api.is_path_existent(path)

            self.assertEqual(expected_return_value, r)
            self.assertEqual(1, len(m.request_history))

    @requests_mock.mock()
    def test_is_path_existent_unexpected_error(self, m):
        path = '/ifs/home/admin'
        m.head('{0}/namespace{1}'.format(self._mock_url, path),
               status_code=400)

        self.assertRaises(
            requests.exceptions.HTTPError,
            self.powerscale_api.is_path_existent,
            '/ifs/home/admin')

    @ddt.data(
        (200, '{"snapshots": [{"path": "/ifs/home/test"}]}',
         {'path': '/ifs/home/test'}),
        (404, '{"errors": []}', None)
    )
    def test_get_snapshot(self, data):
        status_code, json_body, expected_return_value = data
        with requests_mock.mock() as m:
            self.assertEqual(0, len(m.request_history))
            snapshot_name = 'foo1'
            self._add_get_snapshot_response(m, snapshot_name, json_body,
                                            status=status_code)

            r = self.powerscale_api.get_snapshot(snapshot_name)

            self.assertEqual(1, len(m.request_history))
            self.assertEqual(expected_return_value, r)

    @requests_mock.mock()
    def test_get_snapshot_unexpected_error(self, m):
        snapshot_name = 'foo1'
        json_body = '{"snapshots": [{"path": "/ifs/home/test"}]}'
        self._add_get_snapshot_response(
            m, snapshot_name, json_body, status=400)

        self.assertRaises(
            requests.exceptions.HTTPError, self.powerscale_api.get_snapshot,
            snapshot_name)

    @requests_mock.mock()
    def test_get_snapshots(self, m):
        self.assertEqual(0, len(m.request_history))
        snapshot_json = '{"snapshots": [{"path": "/ifs/home/test"}]}'
        m.get('{0}/platform/1/snapshot/snapshots'.format(self._mock_url),
              status_code=200, json=json.loads(snapshot_json))

        r = self.powerscale_api.get_snapshots()

        self.assertEqual(1, len(m.request_history))
        self.assertEqual(json.loads(snapshot_json), r)

    @requests_mock.mock()
    def test_get_snapshots_error_occurred(self, m):
        self.assertEqual(0, len(m.request_history))
        m.get('{0}/platform/1/snapshot/snapshots'.format(self._mock_url),
              status_code=404)

        self.assertRaises(requests.exceptions.HTTPError,
                          self.powerscale_api.get_snapshots)

        self.assertEqual(1, len(m.request_history))

    @ddt.data(
        ('/ifs/home/admin',
         '{"exports": [{"id": 42, "paths": ["/ifs/home/admin"]}], "total": 1}',
         42),
        ('/ifs/home/test',
         '{"exports": [], "total": 0}', None)
    )
    def test_lookup_nfs_export(self, data):
        share_path, response_json, expected_return = data
        with requests_mock.mock() as m:
            self.assertEqual(0, len(m.request_history))
            m.get('{0}/platform/12/protocols/nfs/exports?path={1}'
                  .format(self._mock_url,
                          share_path.replace('/', '%2F')),
                  json=json.loads(response_json))

            r = self.powerscale_api.lookup_nfs_export(share_path)

            self.assertEqual(1, len(m.request_history))
            self.assertEqual(expected_return, r)

    @requests_mock.mock()
    def test_get_nfs_export(self, m):
        self.assertEqual(0, len(m.request_history))
        export_id = 42
        response_json = '{"exports": [{"id": 1}]}'
        status_code = 200
        m.get('{0}/platform/1/protocols/nfs/exports/{1}'
              .format(self._mock_url, export_id),
              json=json.loads(response_json), status_code=status_code)

        r = self.powerscale_api.get_nfs_export(export_id)

        self.assertEqual(1, len(m.request_history))
        self.assertEqual(json.loads('{"id": 1}'), r)

    @requests_mock.mock()
    def test_get_nfs_export_error(self, m):
        self.assertEqual(0, len(m.request_history))
        export_id = 3
        response_json = '{}'
        status_code = 404
        m.get('{0}/platform/1/protocols/nfs/exports/{1}'
              .format(self._mock_url, export_id),
              json=json.loads(response_json), status_code=status_code)

        r = self.powerscale_api.get_nfs_export(export_id)

        self.assertEqual(1, len(m.request_history))
        self.assertIsNone(r)

    @requests_mock.mock()
    def test_lookup_smb_share(self, m):
        self.assertEqual(0, len(m.request_history))
        share_name = 'my_smb_share'
        share_json = '{"id": "my_smb_share"}'
        response_json = '{{"shares": [{0}]}}'.format(share_json)
        m.get('{0}/platform/1/protocols/smb/shares/{1}'
              .format(self._mock_url, share_name), status_code=200,
              json=json.loads(response_json))

        r = self.powerscale_api.lookup_smb_share(share_name)

        self.assertEqual(1, len(m.request_history))
        self.assertEqual(json.loads(share_json), r)

    @requests_mock.mock()
    def test_lookup_smb_share_error(self, m):
        self.assertEqual(0, len(m.request_history))
        share_name = 'my_smb_share'
        m.get('{0}/platform/1/protocols/smb/shares/{1}'.format(
            self._mock_url, share_name), status_code=404)

        r = self.powerscale_api.lookup_smb_share(share_name)

        self.assertEqual(1, len(m.request_history))
        self.assertIsNone(r)

    @ddt.data((201, True), (404, False))
    def test_create_nfs_export(self, data):
        status_code, expected_return_value = data
        with requests_mock.mock() as m:
            self.assertEqual(0, len(m.request_history))
            export_path = '/ifs/home/test'
            m.post(self._mock_url + '/platform/1/protocols/nfs/exports',
                   status_code=status_code)

            r = self.powerscale_api.create_nfs_export(export_path)

            self.assertEqual(1, len(m.request_history))
            call = m.request_history[0]
            expected_request_body = '{"paths": ["/ifs/home/test"]}'
            self.assertEqual(json.loads(expected_request_body),
                             json.loads(call.body))
            self.assertEqual(expected_return_value, r)

    @ddt.data((201, True), (404, False))
    def test_create_smb_share(self, data):
        status_code, expected_return_value = data
        with requests_mock.mock() as m:
            self.assertEqual(0, len(m.request_history))
            share_name = 'my_smb_share'
            share_path = '/ifs/home/admin/smb_share'
            m.post(self._mock_url + '/platform/1/protocols/smb/shares',
                   status_code=status_code)

            r = self.powerscale_api.create_smb_share(share_name, share_path)

            self.assertEqual(expected_return_value, r)
            self.assertEqual(1, len(m.request_history))
            expected_request_data = {
                'name': share_name,
                'path': share_path,
                'permissions': []
            }
            self.assertEqual(expected_request_data,
                             json.loads(m.request_history[0].body))

    @requests_mock.mock()
    def test_create_snapshot(self, m):
        self.assertEqual(0, len(m.request_history))
        snapshot_name = 'my_snapshot_01'
        snapshot_path = '/ifs/home/admin'
        m.post(self._mock_url + '/platform/1/snapshot/snapshots',
               status_code=201)

        r = self.powerscale_api.create_snapshot(snapshot_name, snapshot_path)

        self.assertEqual(1, len(m.request_history))
        self.assertTrue(r)
        expected_request_body = json.loads(
            '{{"name": "{0}", "path": "{1}"}}'
            .format(snapshot_name, snapshot_path)
        )
        self.assertEqual(expected_request_body,
                         json.loads(m.request_history[0].body))

    @requests_mock.mock()
    def test_create_snapshot_error_case(self, m):
        self.assertEqual(0, len(m.request_history))
        snapshot_name = 'my_snapshot_01'
        snapshot_path = '/ifs/home/admin'
        m.post(self._mock_url + '/platform/1/snapshot/snapshots',
               status_code=404)

        self.assertEqual(
            self.powerscale_api.create_snapshot(snapshot_name, snapshot_path),
            False
        )

    @ddt.data(True, False)
    def test_delete_path(self, is_recursive_delete):
        with requests_mock.mock() as m:
            self.assertEqual(0, len(m.request_history))
            fq_path = '/ifs/home/admin/test'
            m.delete(self._mock_url + '/namespace' + fq_path + '?recursive='
                     + str(is_recursive_delete), status_code=204)

            self.powerscale_api.delete_path(
                fq_path, recursive=is_recursive_delete)

            self.assertEqual(1, len(m.request_history))

    @requests_mock.mock()
    def test_delete_path_error_case(self, m):
        fq_path = '/ifs/home/admin/test'
        m.delete(self._mock_url + '/namespace' + fq_path + '?recursive=False',
                 status_code=403)

        self.assertEqual(
            self.powerscale_api.delete_path(
                fq_path, recursive=False), False)

    @ddt.data((204, True), (404, False))
    def test_delete_nfs_share(self, data):
        status_code, expected_return_value = data
        with requests_mock.mock() as m:
            self.assertEqual(0, len(m.request_history))
            share_number = 42
            m.delete('{0}/platform/1/protocols/nfs/exports/{1}'
                     .format(self._mock_url, share_number),
                     status_code=status_code)

            r = self.powerscale_api.delete_nfs_share(share_number)

            self.assertEqual(1, len(m.request_history))
            self.assertEqual(expected_return_value, r)

    @ddt.data((204, True), (404, False))
    def test_delete_smb_shares(self, data):
        status_code, expected_return_value = data
        with requests_mock.mock() as m:
            self.assertEqual(0, len(m.request_history))

            share_name = 'smb_share_42'
            m.delete('{0}/platform/1/protocols/smb/shares/{1}'
                     .format(self._mock_url, share_name),
                     status_code=status_code)

            r = self.powerscale_api.delete_smb_share(share_name)

            self.assertEqual(1, len(m.request_history))
            self.assertEqual(expected_return_value, r)

    @requests_mock.mock()
    def test_delete_snapshot(self, m):
        self.assertEqual(0, len(m.request_history))
        m.delete(self._mock_url + '/platform/1/snapshot/snapshots/my_snapshot',
                 status_code=204)

        self.powerscale_api.delete_snapshot("my_snapshot")

        self.assertEqual(1, len(m.request_history))

    @requests_mock.mock()
    def test_delete_snapshot_error_case(self, m):
        m.delete(self._mock_url + '/platform/1/snapshot/snapshots/my_snapshot',
                 status_code=403)

        self.assertEqual(
            self.powerscale_api.delete_snapshot("my_snapshot"), False)

    @requests_mock.mock()
    def test_quota_create(self, m):
        quota_path = '/ifs/manila/test'
        quota_size = 256
        self.assertEqual(0, len(m.request_history))
        m.post(self._mock_url + '/platform/1/quota/quotas', status_code=201)

        self.powerscale_api.quota_create(quota_path, 'directory', quota_size)

        self.assertEqual(1, len(m.request_history))
        expected_request_json = {
            'path': quota_path,
            'type': 'directory',
            'include_snapshots': False,
            'thresholds_include_overhead': False,
            'enforced': True,
            'thresholds': {'hard': quota_size},
        }
        call_body = m.request_history[0].body
        self.assertEqual(expected_request_json, json.loads(call_body))

    @requests_mock.mock()
    def test_quota_create_with_threshold(self, m):
        quota_path = '/ifs/manila/test'
        quota_size = 100
        self.assertEqual(0, len(m.request_history))
        m.post(self._mock_url + '/platform/1/quota/quotas', status_code=201)
        self.powerscale_api_threshold.quota_create(
            quota_path,
            'directory',
            quota_size
        )

        advisory_size = round(
            (quota_size * self.powerscale_api_threshold.threshold_limit) / 100)
        self.assertEqual(1, len(m.request_history))
        expected_request_json = {
            'path': quota_path,
            'type': 'directory',
            'include_snapshots': False,
            'thresholds_include_overhead': False,
            'enforced': True,
            'thresholds': {'hard': quota_size,
                           'advisory': advisory_size},
        }
        call_body = m.request_history[0].body
        self.assertEqual(expected_request_json, json.loads(call_body))

    @requests_mock.mock()
    def test_quota_create__path_does_not_exist(self, m):
        quota_path = '/ifs/test2'
        self.assertEqual(0, len(m.request_history))
        m.post(self._mock_url + '/platform/1/quota/quotas', status_code=400)

        self.assertRaises(
            requests.exceptions.HTTPError,
            self.powerscale_api.quota_create,
            quota_path, 'directory', 2
        )

    @requests_mock.mock()
    def test_quota_get(self, m):
        self.assertEqual(0, len(m.request_history))
        response_json = {'quotas': [{}]}
        m.get(self._mock_url + '/platform/1/quota/quotas', json=response_json,
              status_code=200)
        quota_path = "/ifs/manila/test"
        quota_type = "directory"

        self.powerscale_api.quota_get(quota_path, quota_type)

        self.assertEqual(1, len(m.request_history))
        request_query_string = m.request_history[0].qs
        expected_query_string = {'path': [quota_path]}
        self.assertEqual(expected_query_string, request_query_string)

    @requests_mock.mock()
    def test_quota_get__path_does_not_exist(self, m):
        self.assertEqual(0, len(m.request_history))
        m.get(self._mock_url + '/platform/1/quota/quotas', status_code=404)

        response = self.powerscale_api.quota_get(
            '/ifs/does_not_exist', 'directory')

        self.assertIsNone(response)

    @requests_mock.mock()
    def test_quota_modify(self, m):
        self.assertEqual(0, len(m.request_history))
        quota_id = "ADEF1G"
        new_size = 1024
        m.put('{0}/platform/1/quota/quotas/{1}'.format(
            self._mock_url, quota_id), status_code=204)

        self.powerscale_api.quota_modify_size(quota_id, new_size)

        self.assertEqual(1, len(m.request_history))
        expected_request_body = {'thresholds': {'hard': new_size}}
        request_body = m.request_history[0].body
        self.assertEqual(expected_request_body, json.loads(request_body))

    @requests_mock.mock()
    def test_quota_modify_with_threshold(self, m):
        self.assertEqual(0, len(m.request_history))
        quota_id = "ADEF1G"
        new_size = 1024
        advisory_size = round(
            (new_size * self.powerscale_api_threshold.threshold_limit) / 100)
        m.put('{0}/platform/1/quota/quotas/{1}'.format(
            self._mock_url, quota_id), status_code=204)
        self.powerscale_api_threshold.quota_modify_size(quota_id, new_size)
        self.assertEqual(1, len(m.request_history))
        expected_request_body = {'thresholds': {'hard': new_size,
                                                'advisory': advisory_size}}
        request_body = m.request_history[0].body
        self.assertEqual(expected_request_body, json.loads(request_body))

    @requests_mock.mock()
    def test_quota_modify__given_id_does_not_exist(self, m):
        quota_id = 'ADE2F'
        m.put('{0}/platform/1/quota/quotas/{1}'.format(
            self._mock_url, quota_id), status_code=404)

        self.assertRaises(
            requests.exceptions.HTTPError,
            self.powerscale_api.quota_modify_size,
            quota_id, 1024
        )

    @requests_mock.mock()
    def test_quota_set__quota_already_exists(self, m):
        self.assertEqual(0, len(m.request_history))
        quota_path = '/ifs/manila/test'
        quota_type = 'directory'
        quota_size = 256
        quota_id = 'AFE2C'
        m.get('{0}/platform/1/quota/quotas'.format(
            self._mock_url), json={'quotas': [{'id': quota_id}]},
            status_code=200)
        m.put(
            '{0}/platform/1/quota/quotas/{1}'.format(self._mock_url, quota_id),
            status_code=204
        )

        self.powerscale_api.quota_set(quota_path, quota_type, quota_size)

        expected_quota_modify_json = {'thresholds': {'hard': quota_size}}
        quota_put_json = json.loads(m.request_history[1].body)
        self.assertEqual(expected_quota_modify_json, quota_put_json)

    @requests_mock.mock()
    def test_quota_set__quota_does_not_already_exist(self, m):
        self.assertEqual(0, len(m.request_history))
        m.get('{0}/platform/1/quota/quotas'.format(
            self._mock_url), status_code=404)
        m.post('{0}/platform/1/quota/quotas'.format(self._mock_url),
               status_code=201)
        quota_path = '/ifs/manila/test'
        quota_type = 'directory'
        quota_size = 256

        self.powerscale_api.quota_set(quota_path, quota_type, quota_size)

        # verify a call is made to create a quota
        expected_create_json = {
            str('path'): quota_path,
            str('type'): 'directory',
            str('include_snapshots'): False,
            str('thresholds_include_overhead'): False,
            str('enforced'): True,
            str('thresholds'): {str('hard'): quota_size},
        }
        create_request_json = json.loads(m.request_history[1].body)
        self.assertEqual(expected_create_json, create_request_json)

    @requests_mock.mock()
    def test_quota_set__path_does_not_already_exist(self, m):
        m.get(self._mock_url + '/platform/1/quota/quotas', status_code=400)

        e = self.assertRaises(
            requests.exceptions.HTTPError,
            self.powerscale_api.quota_set,
            '/ifs/does_not_exist', 'directory', 2048
        )
        self.assertEqual(400, e.response.status_code)

    def test_get_user_sid_success(self):
        sid = {"id": "SID:S-1-22-1-0",
               "name": "foo",
               "type": "user"}
        self.powerscale_api.auth_lookup_user = mock.MagicMock(
            return_value={
                "mapping": [{"user": {"sid": sid}}]
            }
        )
        expected_sid = self.powerscale_api.get_user_sid('foo')
        self.assertEqual(expected_sid, sid)

    def test_get_user_sid_wrong_mappings(self):
        self.powerscale_api.auth_lookup_user = mock.MagicMock(
            return_value={
                "mapping": [{"user": {"sid": 'fake_sid1'}},
                            {"user": {"sid": 'fake_sid2'}}]
            }
        )
        expected_sid = self.powerscale_api.get_user_sid('foo')
        self.assertIsNone(expected_sid)

    def test_get_user_sid_user_not_found(self):
        self.powerscale_api.auth_lookup_user = mock.MagicMock(
            return_value=None
        )
        expected_sid = self.powerscale_api.get_user_sid('foo')
        self.assertIsNone(expected_sid)

    @requests_mock.mock()
    def test_auth_lookup_user(self, m):
        user = 'foo'
        auth_url = '{0}/platform/1/auth/mapping/users/lookup?user={1}'.format(
            self._mock_url, user)
        example_sid = 'SID:S-1-5-21'
        sid_json = {
            'id': example_sid,
            'name': user,
            'type': 'user'
        }
        auth_json = {
            'mapping': [
                {'user': {'sid': sid_json}}
            ]
        }
        m.get(auth_url, status_code=200, json=auth_json)

        returned_auth_json = self.powerscale_api.auth_lookup_user(user)
        self.assertEqual(auth_json, returned_auth_json)

    @requests_mock.mock()
    def test_auth_lookup_user_with_nonexistent_user(self, m):
        user = 'nonexistent'
        auth_url = '{0}/platform/1/auth/mapping/users/lookup?user={1}'.format(
            self._mock_url, user)
        m.get(auth_url, status_code=404)
        self.assertIsNone(self.powerscale_api.auth_lookup_user(user))

    @requests_mock.mock()
    def test_auth_lookup_user_with_backend_error(self, m):
        user = 'foo'
        auth_url = '{0}/platform/1/auth/mapping/users/lookup?user={1}'.format(
            self._mock_url, user)
        m.get(auth_url, status_code=400)
        self.assertIsNone(self.powerscale_api.auth_lookup_user(user))

    def _add_create_directory_response(self, m, path, is_recursive):
        url = '{0}/namespace{1}?recursive={2}'.format(
            self._mock_url, path, str(is_recursive))
        m.put(url, status_code=200)

    def _add_file_clone_response(self, m, fq_dest_path, snapshot_name):
        url = '{0}/namespace{1}?clone=true&snapshot={2}'.format(
            self._mock_url, fq_dest_path, snapshot_name)
        m.put(url)

    def _add_get_directory_listing_response(self, m, fq_dir_path, json_str):
        url = '{0}/namespace{1}?detail=default'.format(
            self._mock_url, fq_dir_path)
        m.get(url, json=json.loads(json_str), status_code=200)

    def _add_get_snapshot_response(
            self, m, snapshot_name, json_str, status=200):
        url = '{0}/platform/1/snapshot/snapshots/{1}'.format(
            self._mock_url, snapshot_name
        )
        m.get(url, status_code=status, json=json.loads(json_str))

    def _verify_dir_creation_request(self, request, path, is_recursive):
        self.assertEqual('PUT', request.method)
        expected_url = '{0}/namespace{1}?recursive={2}'.format(
            self._mock_url, path, str(is_recursive))
        self.assertEqual(expected_url, request.url)
        self.assertIn("x-isi-ifs-target-type", request.headers)
        self.assertEqual("container",
                         request.headers['x-isi-ifs-target-type'])
        self.assertIn("x-isi-ifs-access-control", request.headers)
        self.assertEqual(self.dir_permission,
                         request.headers['x-isi-ifs-access-control'])

    def _verify_clone_file_from_snapshot(
            self, request, fq_file_path, fq_dest_path, snapshot_name):
        self.assertEqual('PUT', request.method)
        expected_url = '{0}/namespace{1}?clone=true&snapshot={2}'.format(
            self._mock_url, fq_dest_path, snapshot_name
        )
        self.assertEqual(expected_url, request.request.url)
        self.assertIn("x-isi-ifs-copy-source", request.headers)
        self.assertEqual('/namespace' + fq_file_path,
                         request.headers['x-isi-ifs-copy-source'])

    def test_modify_nfs_export_access_success(self):
        self.powerscale_api.send_put_request = mock.MagicMock()
        share_id = '123'
        ro_ips = ['10.0.0.1', '10.0.0.2']
        rw_ips = ['10.0.0.3', '10.0.0.4']
        self.powerscale_api.modify_nfs_export_access(share_id, ro_ips, rw_ips)
        expected_url = '{0}/platform/1/protocols/nfs/exports/{1}'.format(
            self.powerscale_api.host_url, share_id)
        expected_data = {'read_only_clients': ro_ips, 'clients': rw_ips}
        self.powerscale_api.send_put_request.assert_called_once_with(
            expected_url, data=expected_data)

    def test_modify_nfs_export_access_no_ro_ips(self):
        self.powerscale_api.send_put_request = mock.MagicMock()
        share_id = '123'
        rw_ips = ['10.0.0.3', '10.0.0.4']
        self.powerscale_api.modify_nfs_export_access(share_id, None, rw_ips)
        expected_url = '{0}/platform/1/protocols/nfs/exports/{1}'.format(
            self.powerscale_api.host_url, share_id)
        expected_data = {'clients': rw_ips}
        self.powerscale_api.send_put_request.assert_called_once_with(
            expected_url, data=expected_data)

    def test_modify_nfs_export_access_no_rw_ips(self):
        self.powerscale_api.send_put_request = mock.MagicMock()
        share_id = '123'
        ro_ips = ['10.0.0.1', '10.0.0.2']
        self.powerscale_api.modify_nfs_export_access(share_id, ro_ips, None)
        expected_url = '{0}/platform/1/protocols/nfs/exports/{1}'.format(
            self.powerscale_api.host_url, share_id)
        expected_data = {'read_only_clients': ro_ips}
        self.powerscale_api.send_put_request.assert_called_once_with(
            expected_url, data=expected_data)

    @mock.patch('requests.Session.request')
    def test_request_with_401_response(self, mock_request):
        """Test sending a request with a 401 Unauthorized response."""
        mock_request.return_value.status_code = 401
        self.powerscale_api.create_session = mock.MagicMock(return_value=True)
        self.powerscale_api.request('GET', 'http://example.com/api/data')
        self.assertEqual(mock_request.call_count, 2)

    def test_delete_quota_sends_delete_request(self):
        self.powerscale_api.send_delete_request = mock.MagicMock()
        quota_id = '123'
        self.powerscale_api.delete_quota(quota_id)
        self.powerscale_api.send_delete_request.assert_called_once_with(
            '{0}/platform/1/quota/quotas/{1}'.format(
                self.powerscale_api.host_url, quota_id)
        )

    def test_delete_quota_raises_exception_on_error(self):
        quota_id = '123'
        self.powerscale_api.send_delete_request = mock.MagicMock(
            side_effect=requests.exceptions.HTTPError)
        self.assertRaises(requests.exceptions.HTTPError,
                          self.powerscale_api.delete_quota,
                          quota_id)

    def test_get_space_stats_success(self):
        self.powerscale_api.send_get_request = mock.MagicMock()
        self.powerscale_api.send_get_request.return_value.status_code = 200
        self.powerscale_api.send_get_request.return_value.json.return_value = {
            'stats': [
                {'key': 'ifs.bytes.free', 'value': 1000},
                {'key': 'ifs.bytes.total', 'value': 2000},
                {'key': 'ifs.bytes.used', 'value': 500}
            ]
        }
        result = self.powerscale_api.get_space_stats()
        self.assertEqual(result, {'total': 2000, 'free': 1000, 'used': 500})

    def test_get_space_stats_failure(self):
        self.powerscale_api.send_get_request = mock.MagicMock()
        self.powerscale_api.send_get_request.return_value.status_code = 400
        self.assertRaises(exception.ShareBackendException,
                          self.powerscale_api.get_space_stats)

    def test_get_allocated_space_success(self):
        self.powerscale_api.send_get_request = mock.MagicMock()
        self.powerscale_api.send_get_request.return_value.status_code = 200
        self.powerscale_api.send_get_request.return_value.json.return_value = {
            'quotas': [
                {
                    'path': '/ifs/home',
                    'thresholds': {
                        'hard': None
                    }
                },
                {
                    'path': '/ifs/manila/CI-1d52ed66-a1ee-4b19-8f56-3706b',
                    'thresholds': {
                        'hard': 2147483648000
                    }
                },
                {
                    'path': '/ifs/manila/CI-0b622133-8b58-4a9f-ad1a-b8247',
                    'thresholds': {
                        'hard': 107374182400
                    }
                },
                {
                    'path': '/ifs/nilesh',
                    'thresholds': {
                        'hard': 10737418240
                    }
                }
            ]
        }
        result = self.powerscale_api.get_allocated_space()
        self.assertEqual(result, 2110.0)

    def test_get_allocated_space_failure(self):
        self.powerscale_api.send_get_request = mock.MagicMock()
        self.powerscale_api.send_get_request.return_value.status_code = 400
        self.assertRaises(exception.ShareBackendException,
                          self.powerscale_api.get_allocated_space)

    def test_get_cluster_version_success(self):
        self.powerscale_api.send_get_request = mock.MagicMock()
        self.powerscale_api.send_get_request.return_value.status_code = 200
        self.powerscale_api.send_get_request.return_value.json.return_value = {
            'nodes': [{'release': '1.0'}]}

        version = self.powerscale_api.get_cluster_version()
        self.assertEqual(version, '1.0')
        self.powerscale_api.send_get_request.assert_called_once_with(
            '{0}/platform/12/cluster/version'.format(
                self.powerscale_api.host_url)
        )

    def test_get_cluster_version_failure(self):
        self.powerscale_api.send_get_request = mock.MagicMock()
        self.powerscale_api.send_get_request.return_value.status_code = 404

        self.assertRaises(exception.ShareBackendException,
                          self.powerscale_api.get_cluster_version)

        self.powerscale_api.send_get_request.assert_called_once_with(
            '{0}/platform/12/cluster/version'.format(
                self.powerscale_api.host_url)
        )

    def test_modify_smb_share_access_with_host_acl_and_smb_permission(self):
        self.powerscale_api.send_put_request = mock.MagicMock()
        share_name = 'my_share'
        host_acl = 'host1,host2'
        smb_permission = 'read'
        self.powerscale_api.modify_smb_share_access(
            share_name, host_acl, smb_permission)
        expected_url = '{0}/platform/1/protocols/smb/shares/{1}'.format(
            self.powerscale_api.host_url, share_name)
        expected_data = {'host_acl': host_acl, 'permissions': smb_permission}
        self.powerscale_api.send_put_request.assert_called_with(
            expected_url, data=expected_data)

    def test_modify_smb_share_access_with_host_acl_only(self):
        self.powerscale_api.send_put_request = mock.MagicMock()
        share_name = 'my_share'
        host_acl = 'host1,host2'
        self.powerscale_api.modify_smb_share_access(share_name, host_acl)
        expected_url = '{0}/platform/1/protocols/smb/shares/{1}'.format(
            self.powerscale_api.host_url, share_name)
        expected_data = {'host_acl': host_acl}
        self.powerscale_api.send_put_request.assert_called_with(
            expected_url, data=expected_data)

    def test_modify_smb_share_access_with_smb_permission_only(self):
        self.powerscale_api.send_put_request = mock.MagicMock()
        share_name = 'my_share'
        smb_permission = 'read'
        self.powerscale_api.modify_smb_share_access(
            share_name, permissions=smb_permission)
        expected_url = '{0}/platform/1/protocols/smb/shares/{1}'.format(
            self.powerscale_api.host_url, share_name)
        expected_data = {'permissions': smb_permission}
        self.powerscale_api.send_put_request.assert_called_with(
            expected_url, data=expected_data)

    def test_modify_smb_share_access_with_no_arguments(self):
        self.powerscale_api.send_put_request = mock.MagicMock()
        share_name = 'my_share'
        self.powerscale_api.modify_smb_share_access(share_name)
        expected_url = '{0}/platform/1/protocols/smb/shares/{1}'.format(
            self.powerscale_api.host_url, share_name)
        expected_data = {}
        self.powerscale_api.send_put_request.assert_called_with(
            expected_url, data=expected_data)

    def test_modify_smb_share_access_with_http_error(self):
        self.powerscale_api.send_put_request = mock.MagicMock(
            side_effect=requests.exceptions.HTTPError
        )
        share_name = 'my_share'
        host_acl = 'host1,host2'
        smb_permission = 'read'

        self.assertRaises(requests.exceptions.HTTPError,
                          self.powerscale_api.modify_smb_share_access,
                          share_name, host_acl, smb_permission)
