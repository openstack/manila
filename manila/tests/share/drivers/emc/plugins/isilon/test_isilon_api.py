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

import ddt
from oslo_serialization import jsonutils as json
import requests
import requests_mock
import six

from manila.share.drivers.emc.plugins.isilon import isilon_api
from manila import test


@ddt.ddt
class IsilonApiTest(test.TestCase):

    def setUp(self):
        super(IsilonApiTest, self).setUp()

        self._mock_url = 'https://localhost:8080'
        _mock_auth = ('admin', 'admin')
        self.isilon_api = isilon_api.IsilonApi(
            self._mock_url, _mock_auth
        )

    @ddt.data(False, True)
    def test_create_directory(self, is_recursive):
        with requests_mock.Mocker() as m:
            path = '/ifs/test'
            self.assertEqual(0, len(m.request_history))
            self._add_create_directory_response(m, path, is_recursive)

            r = self.isilon_api.create_directory(path,
                                                 recursive=is_recursive)

            self.assertTrue(r)
            self.assertEqual(1, len(m.request_history))
            request = m.request_history[0]
            self._verify_dir_creation_request(request, path, is_recursive)

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
        # will verify the the necessary calls are made to clone a snapshot.
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
        self.isilon_api.clone_snapshot(snapshot_name, fq_target_dir)

        # Verify calls needed to clone the source snapshot to the target dir
        expected_calls = []
        clone_path_list = [
            'file1', 'file2', 'dir1/file11', 'dir1/file12',
            'dir2/file21', 'dir2/file22']
        for path in clone_path_list:
            expected_call = IsilonApiTest.ExpectedCall(
                IsilonApiTest.ExpectedCall.FILE_CLONE,
                self._mock_url + '/namespace/ifs/admin/target/' + path,
                ['/ifs/admin/target/' + path, '/ifs/admin/source/' + path,
                 snapshot_name])
            expected_calls.append(expected_call)
        dir_path_list = [
            ('/dir1?recursive', '/dir1'),
            ('/dir2?recursive', '/dir2'),
            ('?recursive=', '')]
        for url, path in dir_path_list:
            expected_call = IsilonApiTest.ExpectedCall(
                IsilonApiTest.ExpectedCall.DIR_CREATION,
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
                    if expected_call.request_type is 'dir_creation':
                        self._verify_dir_creation_request(
                            call, *expected_call.verify_args)
                    elif expected_call.request_type is 'file_clone':
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

        actual_json = self.isilon_api.get_directory_listing(fq_dir_path)

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

            r = self.isilon_api.is_path_existent(path)

            self.assertEqual(expected_return_value, r)
            self.assertEqual(1, len(m.request_history))

    @requests_mock.mock()
    def test_is_path_existent_unexpected_error(self, m):
        path = '/ifs/home/admin'
        m.head('{0}/namespace{1}'.format(self._mock_url, path),
               status_code=400)

        self.assertRaises(
            requests.exceptions.HTTPError, self.isilon_api.is_path_existent,
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

            r = self.isilon_api.get_snapshot(snapshot_name)

            self.assertEqual(1, len(m.request_history))
            self.assertEqual(expected_return_value, r)

    @requests_mock.mock()
    def test_get_snapshot_unexpected_error(self, m):
        snapshot_name = 'foo1'
        json_body = '{"snapshots": [{"path": "/ifs/home/test"}]}'
        self._add_get_snapshot_response(
            m, snapshot_name, json_body, status=400)

        self.assertRaises(
            requests.exceptions.HTTPError, self.isilon_api.get_snapshot,
            snapshot_name)

    @requests_mock.mock()
    def test_get_snapshots(self, m):
        self.assertEqual(0, len(m.request_history))
        snapshot_json = '{"snapshots": [{"path": "/ifs/home/test"}]}'
        m.get('{0}/platform/1/snapshot/snapshots'.format(self._mock_url),
              status_code=200, json=json.loads(snapshot_json))

        r = self.isilon_api.get_snapshots()

        self.assertEqual(1, len(m.request_history))
        self.assertEqual(json.loads(snapshot_json), r)

    @requests_mock.mock()
    def test_get_snapshots_error_occurred(self, m):
        self.assertEqual(0, len(m.request_history))
        m.get('{0}/platform/1/snapshot/snapshots'.format(self._mock_url),
              status_code=404)

        self.assertRaises(requests.exceptions.HTTPError,
                          self.isilon_api.get_snapshots)

        self.assertEqual(1, len(m.request_history))

    @ddt.data(
        ('/ifs/home/admin',
         '{"exports": [{"id": 42, "paths": ["/ifs/home/admin"]}]}', 42),
        ('/ifs/home/test',
         '{"exports": [{"id": 42, "paths": ["/ifs/home/admin"]}]}', None)
    )
    def test_lookup_nfs_export(self, data):
        share_path, response_json, expected_return = data
        with requests_mock.mock() as m:
            self.assertEqual(0, len(m.request_history))
            m.get('{0}/platform/1/protocols/nfs/exports'
                  .format(self._mock_url), json=json.loads(response_json))

            r = self.isilon_api.lookup_nfs_export(share_path)

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

        r = self.isilon_api.get_nfs_export(export_id)

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

        r = self.isilon_api.get_nfs_export(export_id)

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

        r = self.isilon_api.lookup_smb_share(share_name)

        self.assertEqual(1, len(m.request_history))
        self.assertEqual(json.loads(share_json), r)

    @requests_mock.mock()
    def test_lookup_smb_share_error(self, m):
        self.assertEqual(0, len(m.request_history))
        share_name = 'my_smb_share'
        m.get('{0}/platform/1/protocols/smb/shares/{1}'.format(
            self._mock_url, share_name), status_code=404)

        r = self.isilon_api.lookup_smb_share(share_name)

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

            r = self.isilon_api.create_nfs_export(export_path)

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

            r = self.isilon_api.create_smb_share(share_name, share_path)

            self.assertEqual(expected_return_value, r)
            self.assertEqual(1, len(m.request_history))
            expected_request_data = json.loads(
                '{{"name": "{0}", "path": "{1}"}}'.format(
                    share_name, share_path)
            )
            self.assertEqual(expected_request_data,
                             json.loads(m.request_history[0].body))

    @requests_mock.mock()
    def test_create_snapshot(self, m):
        self.assertEqual(0, len(m.request_history))
        snapshot_name = 'my_snapshot_01'
        snapshot_path = '/ifs/home/admin'
        m.post(self._mock_url + '/platform/1/snapshot/snapshots',
               status_code=201)

        r = self.isilon_api.create_snapshot(snapshot_name, snapshot_path)

        self.assertEqual(1, len(m.request_history))
        self.assertEqual(True, r)
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

        self.assertRaises(requests.exceptions.HTTPError,
                          self.isilon_api.create_snapshot,
                          snapshot_name, snapshot_path)
        self.assertEqual(1, len(m.request_history))

    @ddt.data(True, False)
    def test_delete(self, is_recursive_delete):
        with requests_mock.mock() as m:
            self.assertEqual(0, len(m.request_history))
            fq_path = '/ifs/home/admin/test'
            m.delete(self._mock_url + '/namespace' + fq_path + '?recursive='
                     + six.text_type(is_recursive_delete), status_code=204)

            self.isilon_api.delete(fq_path, recursive=is_recursive_delete)

            self.assertEqual(1, len(m.request_history))

    @requests_mock.mock()
    def test_delete_error_case(self, m):
        fq_path = '/ifs/home/admin/test'
        m.delete(self._mock_url + '/namespace' + fq_path + '?recursive=False',
                 status_code=403)

        self.assertRaises(requests.exceptions.HTTPError,
                          self.isilon_api.delete, fq_path, recursive=False)

    @ddt.data((204, True), (404, False))
    def test_delete_nfs_share(self, data):
        status_code, expected_return_value = data
        with requests_mock.mock() as m:
            self.assertEqual(0, len(m.request_history))
            share_number = 42
            m.delete('{0}/platform/1/protocols/nfs/exports/{1}'
                     .format(self._mock_url, share_number),
                     status_code=status_code)

            r = self.isilon_api.delete_nfs_share(share_number)

            self.assertEqual(1, len(m.request_history))
            self.assertEqual(r, expected_return_value)

    @ddt.data((204, True), (404, False))
    def test_delete_smb_shares(self, data):
        status_code, expected_return_value = data
        with requests_mock.mock() as m:
            self.assertEqual(0, len(m.request_history))

            share_name = 'smb_share_42'
            m.delete('{0}/platform/1/protocols/smb/shares/{1}'
                     .format(self._mock_url, share_name),
                     status_code=status_code)

            r = self.isilon_api.delete_smb_share(share_name)

            self.assertEqual(1, len(m.request_history))
            self.assertEqual(r, expected_return_value)

    @requests_mock.mock()
    def test_delete_snapshot(self, m):
        self.assertEqual(0, len(m.request_history))
        m.delete(self._mock_url + '/platform/1/snapshot/snapshots/my_snapshot',
                 status_code=204)

        self.isilon_api.delete_snapshot("my_snapshot")

        self.assertEqual(1, len(m.request_history))

    @requests_mock.mock()
    def test_delete_snapshot_error_case(self, m):
        m.delete(self._mock_url + '/platform/1/snapshot/snapshots/my_snapshot',
                 status_code=403)

        self.assertRaises(requests.exceptions.HTTPError,
                          self.isilon_api.delete_snapshot, "my_snapshot")

    def _add_create_directory_response(self, m, path, is_recursive):
        url = '{0}/namespace{1}?recursive={2}'.format(
            self._mock_url, path, six.text_type(is_recursive))
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
            self._mock_url, path, six.text_type(is_recursive))
        self.assertEqual(expected_url, request.url)
        self.assertTrue("x-isi-ifs-target-type" in request.headers)
        self.assertEqual("container",
                         request.headers['x-isi-ifs-target-type'])

    def _verify_clone_file_from_snapshot(
            self, request, fq_file_path, fq_dest_path, snapshot_name):
        self.assertEqual('PUT', request.method)
        expected_url = '{0}/namespace{1}?clone=true&snapshot={2}'.format(
            self._mock_url, fq_dest_path, snapshot_name
        )
        self.assertEqual(expected_url, request.request.url)
        self.assertTrue("x-isi-ifs-copy-source" in request.headers)
        self.assertEqual('/namespace' + fq_file_path,
                         request.headers['x-isi-ifs-copy-source'])
