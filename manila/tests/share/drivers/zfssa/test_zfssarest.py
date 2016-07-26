# Copyright (c) 2014, Oracle and/or its affiliates. All rights reserved.
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
"""
Unit tests for Oracle's ZFSSA REST API.
"""
import mock

from manila import exception
from manila.share.drivers.zfssa import restclient
from manila.share.drivers.zfssa import zfssarest
from manila import test
from manila.tests import fake_zfssa


class ZFSSAApiTestCase(test.TestCase):
    """Tests ZFSSAApi."""

    @mock.patch.object(zfssarest, 'factory_restclient')
    def setUp(self, _restclient):
        super(ZFSSAApiTestCase, self).setUp()
        self.host = 'fakehost'
        self.user = 'fakeuser'
        self.url = None
        self.pool = 'fakepool'
        self.project = 'fakeproject'
        self.share = 'fakeshare'
        self.snap = 'fakesnapshot'
        _restclient.return_value = fake_zfssa.FakeRestClient()
        self._zfssa = zfssarest.ZFSSAApi()
        self._zfssa.set_host('fakehost')

        self.schema = {
            'property': 'manila_managed',
            'description': 'Managed by Manila',
            'type': 'Boolean',
        }

    def _create_response(self, status):
        response = fake_zfssa.FakeResponse(status)
        return response

    def test_enable_service(self):
        self.mock_object(self._zfssa.rclient, 'put')
        self._zfssa.rclient.put.return_value = self._create_response(
            restclient.Status.ACCEPTED)

        self._zfssa.enable_service('nfs')
        self.assertEqual(1, self._zfssa.rclient.put.call_count)

        self._zfssa.rclient.put.return_value = self._create_response(
            restclient.Status.OK)
        self.assertRaises(exception.ShareBackendException,
                          self._zfssa.enable_service,
                          'nfs')

    def test_verify_avail_space(self):
        self.mock_object(self._zfssa, 'verify_project')
        self.mock_object(self._zfssa, 'get_project_stats')
        self._zfssa.get_project_stats.return_value = 2000

        self._zfssa.verify_avail_space(self.pool,
                                       self.project,
                                       self.share,
                                       1000)
        self.assertEqual(1, self._zfssa.verify_project.call_count)
        self.assertEqual(1, self._zfssa.get_project_stats.call_count)
        self._zfssa.verify_project.assert_called_with(self.pool, self.project)
        self._zfssa.get_project_stats.assert_called_with(self.pool,
                                                         self.project)

        self._zfssa.get_project_stats.return_value = 900
        self.assertRaises(exception.ShareBackendException,
                          self._zfssa.verify_avail_space,
                          self.pool,
                          self.project,
                          self.share,
                          1000)

    def test_create_project(self):
        self.mock_object(self._zfssa, 'verify_pool')
        self.mock_object(self._zfssa.rclient, 'get')
        self.mock_object(self._zfssa.rclient, 'post')
        arg = {
            'name': self.project,
            'sharesmb': 'off',
            'sharenfs': 'off',
            'mountpoint': 'fakemnpt',
        }
        self._zfssa.rclient.get.return_value = self._create_response(
            restclient.Status.NOT_FOUND)
        self._zfssa.rclient.post.return_value = self._create_response(
            restclient.Status.CREATED)

        self._zfssa.create_project(self.pool, self.project, arg)
        self.assertEqual(1, self._zfssa.rclient.get.call_count)
        self.assertEqual(1, self._zfssa.rclient.post.call_count)
        self.assertEqual(1, self._zfssa.verify_pool.call_count)
        self._zfssa.verify_pool.assert_called_with(self.pool)

        self._zfssa.rclient.post.return_value = self._create_response(
            restclient.Status.NOT_FOUND)
        self.assertRaises(exception.ShareBackendException,
                          self._zfssa.create_project,
                          self.pool,
                          self.project,
                          arg)

    def test_create_share(self):
        self.mock_object(self._zfssa, 'verify_avail_space')
        self.mock_object(self._zfssa.rclient, 'get')
        self.mock_object(self._zfssa.rclient, 'post')
        self._zfssa.rclient.get.return_value = self._create_response(
            restclient.Status.NOT_FOUND)
        self._zfssa.rclient.post.return_value = self._create_response(
            restclient.Status.CREATED)
        arg = {
            "name": self.share,
            "quota": 1,
        }

        self._zfssa.create_share(self.pool, self.project, arg)
        self.assertEqual(1, self._zfssa.rclient.get.call_count)
        self.assertEqual(1, self._zfssa.rclient.post.call_count)
        self.assertEqual(1, self._zfssa.verify_avail_space.call_count)
        self._zfssa.verify_avail_space.assert_called_with(self.pool,
                                                          self.project,
                                                          arg,
                                                          arg['quota'])

        self._zfssa.rclient.post.return_value = self._create_response(
            restclient.Status.NOT_FOUND)
        self.assertRaises(exception.ShareBackendException,
                          self._zfssa.create_share,
                          self.pool,
                          self.project,
                          arg)

        self._zfssa.rclient.get.return_value = self._create_response(
            restclient.Status.OK)
        self.assertRaises(exception.ShareBackendException,
                          self._zfssa.create_share,
                          self.pool,
                          self.project,
                          arg)

    def test_modify_share(self):
        self.mock_object(self._zfssa.rclient, 'put')
        self._zfssa.rclient.put.return_value = self._create_response(
            restclient.Status.ACCEPTED)
        arg = {"name": "dummyname"}
        svc = self._zfssa.share_path % (self.pool, self.project, self.share)

        self._zfssa.modify_share(self.pool, self.project, self.share, arg)
        self.assertEqual(1, self._zfssa.rclient.put.call_count)
        self._zfssa.rclient.put.assert_called_with(svc, arg)

        self._zfssa.rclient.put.return_value = self._create_response(
            restclient.Status.BAD_REQUEST)
        self.assertRaises(exception.ShareBackendException,
                          self._zfssa.modify_share,
                          self.pool,
                          self.project,
                          self.share,
                          arg)

    def test_delete_share(self):
        self.mock_object(self._zfssa.rclient, 'delete')
        self._zfssa.rclient.delete.return_value = self._create_response(
            restclient.Status.NO_CONTENT)
        svc = self._zfssa.share_path % (self.pool, self.project, self.share)

        self._zfssa.delete_share(self.pool, self.project, self.share)
        self.assertEqual(1, self._zfssa.rclient.delete.call_count)
        self._zfssa.rclient.delete.assert_called_with(svc)

    def test_create_snapshot(self):
        self.mock_object(self._zfssa.rclient, 'post')
        self._zfssa.rclient.post.return_value = self._create_response(
            restclient.Status.CREATED)
        arg = {"name": self.snap}
        svc = self._zfssa.snapshots_path % (self.pool,
                                            self.project,
                                            self.share)

        self._zfssa.create_snapshot(self.pool,
                                    self.project,
                                    self.share,
                                    self.snap)
        self.assertEqual(1, self._zfssa.rclient.post.call_count)
        self._zfssa.rclient.post.assert_called_with(svc, arg)

        self._zfssa.rclient.post.return_value = self._create_response(
            restclient.Status.BAD_REQUEST)
        self.assertRaises(exception.ShareBackendException,
                          self._zfssa.create_snapshot,
                          self.pool,
                          self.project,
                          self.share,
                          self.snap)

    def test_delete_snapshot(self):
        self.mock_object(self._zfssa.rclient, 'delete')
        self._zfssa.rclient.delete.return_value = self._create_response(
            restclient.Status.NO_CONTENT)
        svc = self._zfssa.snapshot_path % (self.pool,
                                           self.project,
                                           self.share,
                                           self.snap)

        self._zfssa.delete_snapshot(self.pool,
                                    self.project,
                                    self.share,
                                    self.snap)
        self.assertEqual(1, self._zfssa.rclient.delete.call_count)
        self._zfssa.rclient.delete.assert_called_with(svc)

        self._zfssa.rclient.delete.return_value = self._create_response(
            restclient.Status.BAD_REQUEST)
        self.assertRaises(exception.ShareBackendException,
                          self._zfssa.delete_snapshot,
                          self.pool,
                          self.project,
                          self.share,
                          self.snap)

    def test_clone_snapshot(self):
        self.mock_object(self._zfssa, 'verify_avail_space')
        self.mock_object(self._zfssa.rclient, 'put')
        self._zfssa.rclient.put.return_value = self._create_response(
            restclient.Status.CREATED)
        snapshot = {
            "id": self.snap,
            "share_id": self.share,
        }
        clone = {
            "id": "cloneid",
            "size": 1,
        }
        arg = {
            "name": "dummyname",
            "quota": 1,
        }

        self._zfssa.clone_snapshot(self.pool,
                                   self.project,
                                   snapshot,
                                   clone,
                                   arg)
        self.assertEqual(1, self._zfssa.rclient.put.call_count)
        self.assertEqual(1, self._zfssa.verify_avail_space.call_count)
        self._zfssa.verify_avail_space.assert_called_with(self.pool,
                                                          self.project,
                                                          clone['id'],
                                                          clone['size'])

        self._zfssa.rclient.put.return_value = self._create_response(
            restclient.Status.NOT_FOUND)
        self.assertRaises(exception.ShareBackendException,
                          self._zfssa.clone_snapshot,
                          self.pool,
                          self.project,
                          snapshot,
                          clone,
                          arg)

    def _create_entry(self, sharenfs, ip):
        if sharenfs == 'off':
            sharenfs = 'sec=sys'
        entry = (',rw=@%s' % ip)
        if '/' not in ip:
            entry = entry + '/32'
        arg = {'sharenfs': sharenfs + entry}
        return arg

    def test_allow_access_nfs(self):
        self.mock_object(self._zfssa, 'get_share')
        self.mock_object(self._zfssa, 'modify_share')
        details = {"sharenfs": "off"}
        access = {
            "access_type": "nonip",
            "access_to": "foo",
        }

        # invalid access type
        self.assertRaises(exception.InvalidShareAccess,
                          self._zfssa.allow_access_nfs,
                          self.pool,
                          self.project,
                          self.share,
                          access)

        # valid entry
        access.update({"access_type": "ip"})
        arg = self._create_entry("off", access['access_to'])
        self._zfssa.get_share.return_value = details
        self._zfssa.allow_access_nfs(self.pool,
                                     self.project,
                                     self.share,
                                     access)
        self.assertEqual(1, self._zfssa.get_share.call_count)
        self.assertEqual(1, self._zfssa.modify_share.call_count)
        self._zfssa.get_share.assert_called_with(self.pool,
                                                 self.project,
                                                 self.share)
        self._zfssa.modify_share.assert_called_with(self.pool,
                                                    self.project,
                                                    self.share,
                                                    arg)

        # add another entry
        access.update({"access_to": "10.0.0.1/24"})
        arg = self._create_entry("off", access['access_to'])
        self._zfssa.allow_access_nfs(self.pool,
                                     self.project,
                                     self.share,
                                     access)
        self.assertEqual(2, self._zfssa.modify_share.call_count)
        self._zfssa.modify_share.assert_called_with(self.pool,
                                                    self.project,
                                                    self.share,
                                                    arg)

        # verify modify_share is not called if sharenfs='on'
        details = {"sharenfs": "on"}
        self._zfssa.get_share.return_value = details
        self._zfssa.allow_access_nfs(self.pool,
                                     self.project,
                                     self.share,
                                     access)
        self.assertEqual(2, self._zfssa.modify_share.call_count)

        # verify modify_share is not called if ip is already in the list
        access.update({"access_to": "10.0.0.1/24"})
        details = self._create_entry("off", access['access_to'])
        self._zfssa.get_share.return_value = details
        self._zfssa.allow_access_nfs(self.pool,
                                     self.project,
                                     self.share,
                                     access)
        self.assertEqual(2, self._zfssa.modify_share.call_count)

    def test_deny_access_nfs(self):
        self.mock_object(self._zfssa, 'get_share')
        self.mock_object(self._zfssa, 'modify_share')
        data1 = self._create_entry("off", "10.0.0.1")
        access = {
            "access_type": "nonip",
            "access_to": "foo",
        }

        # invalid access_type
        self.assertRaises(exception.InvalidShareAccess,
                          self._zfssa.deny_access_nfs,
                          self.pool,
                          self.project,
                          self.share,
                          access)

        # valid entry
        access.update({"access_type": "ip"})
        self._zfssa.get_share.return_value = data1
        self._zfssa.deny_access_nfs(self.pool,
                                    self.project,
                                    self.share,
                                    access)
        self.assertEqual(1, self._zfssa.get_share.call_count)
        self.assertEqual(0, self._zfssa.modify_share.call_count)
        self._zfssa.get_share.assert_called_with(self.pool,
                                                 self.project,
                                                 self.share)
        # another valid entry
        data1 = self._create_entry(data1['sharenfs'], '10.0.0.2/24')
        data2 = self._create_entry(data1['sharenfs'], access['access_to'])
        self._zfssa.get_share.return_value = data2
        self._zfssa.deny_access_nfs(self.pool,
                                    self.project,
                                    self.share,
                                    access)
        self.assertEqual(2, self._zfssa.get_share.call_count)
        self.assertEqual(1, self._zfssa.modify_share.call_count)
        self._zfssa.get_share.assert_called_with(self.pool,
                                                 self.project,
                                                 self.share)
        self._zfssa.modify_share.assert_called_with(self.pool,
                                                    self.project,
                                                    self.share,
                                                    data1)

    def test_create_schema_negative(self):
        self.mock_object(self._zfssa.rclient, 'get')
        self.mock_object(self._zfssa.rclient, 'post')
        self._zfssa.rclient.post.return_value = self._create_response(
            restclient.Status.NOT_FOUND)

        self.assertRaises(exception.ShareBackendException,
                          self._zfssa.create_schema,
                          self.schema)

    def test_create_schema_property_exists(self):
        self.mock_object(self._zfssa.rclient, 'get')
        self.mock_object(self._zfssa.rclient, 'post')
        self._zfssa.rclient.get.return_value = self._create_response(
            restclient.Status.OK)

        self._zfssa.create_schema(self.schema)

        self.assertEqual(1, self._zfssa.rclient.get.call_count)
        self.assertEqual(0, self._zfssa.rclient.post.call_count)

    def test_create_schema(self):
        self.mock_object(self._zfssa.rclient, 'get')
        self.mock_object(self._zfssa.rclient, 'post')
        self._zfssa.rclient.get.return_value = self._create_response(
            restclient.Status.NOT_FOUND)
        self._zfssa.rclient.post.return_value = self._create_response(
            restclient.Status.CREATED)

        self._zfssa.create_schema(self.schema)

        self.assertEqual(1, self._zfssa.rclient.get.call_count)
        self.assertEqual(1, self._zfssa.rclient.post.call_count)
