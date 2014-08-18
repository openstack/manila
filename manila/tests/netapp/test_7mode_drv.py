# Copyright (c) 2014 NetApp, Inc.
# All Rights Reserved.
#
#     Licensed under the Apache License, Version 2.0 (the "License"); you may
#     not use this file except in compliance with the License. You may obtain
#     a copy of the License at
#
#          http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#     WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#     License for the specific language governing permissions and limitations
#     under the License.

import mock
from oslo.config import cfg

from manila import context
from manila import exception
from manila.share import configuration
from manila.share.drivers.netapp import api as naapi
from manila.share.drivers.netapp import driver
from manila import test

CONF = cfg.CONF


class NetApp7modeDrvTestCase(test.TestCase):
    """Tests for NetApp 7mode driver."""

    def setUp(self):
        super(NetApp7modeDrvTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._db = mock.Mock()
        self.driver = driver.NetAppShareDriver(
            self._db, configuration=configuration.Configuration(None))
        self.driver._client = mock.Mock()
        self.driver._client.send_request = mock.Mock()

        self.share = {'id': 'fake_uuid',
                      'tenant_id': 'fake_tenant_id',
                      'name': 'fake_name',
                      'size': 1,
                      'share_proto': 'fake'}
        self.snapshot = {'id': 'fake_snapshot_uuid',
                         'tenant_id': 'fake_tenant_id',
                         'share_id': 'fake_share_id'}
        self.helper = mock.Mock()
        self.driver._helpers = {'FAKE': self.helper}
        self.driver._licenses = ['fake']

    def test_update_share_stats(self):
        """Retrieve status info from share volume group."""
        aggrs = {'fake1': (3774873600, 943718400),
                 'fake2': (45506560, 3774873600)}
        self.driver.get_available_aggregates = mock.Mock(
            return_value=aggrs)
        self.driver._update_share_status()
        res = self.driver._stats

        expected = {}
        expected["share_backend_name"] = self.driver.backend_name
        expected["vendor_name"] = 'NetApp'
        expected["driver_version"] = '1.0'
        expected["storage_protocol"] = 'NFS_CIFS'
        expected['total_capacity_gb'] = 4
        expected['free_capacity_gb'] = 3
        expected['reserved_percentage'] = 0
        expected['QoS_support'] = False
        self.assertDictMatch(res, expected)

    def test_check_vfiler_exists(self):
        elem = naapi.NaElement('fake')
        elem['status'] = 'running'
        self.driver._client.send_request = mock.Mock(return_value=elem)
        self.driver._check_vfiler_exists()

    def test_check_vfiler_exists_error(self):
        elem = naapi.NaElement('fake')
        elem['status'] = 'error'
        self.driver._client.send_request = mock.Mock(return_value=elem)
        self.assertRaises(exception.NetAppException,
                          self.driver._check_vfiler_exists)

    def test_check_licenses(self):
        root = naapi.NaElement('fake')
        elem = naapi.NaElement('licenses')
        licenses = ['l1', 'l2']
        for license in licenses:
            el = naapi.NaElement('license')
            el['package'] = license
            elem.add_child_elem(el)
        root.add_child_elem(elem)
        self.driver._client.send_request = mock.Mock(return_value=root)
        self.driver._check_licenses()
        self.assertEqual(self.driver._licenses, licenses)

    def test_create_share(self):
        self.driver.configuration.netapp_nas_server_hostname\
            = 'fake-netapp-location'
        root = naapi.NaElement('root')
        aggregates = naapi.NaElement('aggregates')
        for i in range(1, 4):
            aggregates.add_node_with_children('aggr-attributes',
                                              **{'name': 'fake%s' % i,
                                              'size-available': '%s' % i,
                                              'size-total': '%s' % i})
        root.add_child_elem(aggregates)

        self.driver._client.send_request = mock.Mock(return_value=root)
        self.helper.create_share = mock.Mock(return_value="fake-location")
        export_location = self.driver.create_share(self._context, self.share)

        args = {'containing-aggr-name': 'fake3',
                'size': '1g',
                'volume': 'share_fake_uuid'}
        self.driver._client.send_request.assert_called_with('volume-create',
                                                            args)
        self.helper.create_share.assert_called_once_with(
            "share_%s" % self.share['id'], 'fake-netapp-location')
        self.assertEqual(export_location, "fake-location")

    def test_create_share_from_snapshot(self):
        self.helper.create_share = mock.Mock(return_value="fake-location")
        export_location = self.driver.create_share_from_snapshot(self._context,
                                                                 self.share,
                                                                 self.snapshot)
        args = {'volume': 'share_fake_uuid',
                'parent-volume': 'share_fake_share_id',
                'parent-snapshot': 'share_snapshot_fake_snapshot_uuid'}
        self.driver._client.send_request.assert_called_once_with(
            'volume-clone-create', args)
        self.assertEqual(export_location, "fake-location")

    def test_delete_share(self):
        self.driver.delete_share(self._context, self.share)
        self.driver._client.send_request.assert_has_calls([
            mock.call('volume-list-info', {'volume': 'share_fake_uuid'}),
            mock.call('volume-offline', {'name': 'share_fake_uuid'}),
            mock.call('volume-destroy', {'name': 'share_fake_uuid'})
        ])
        self.helper.get_target.assert_called_once_with(self.share)
        self.helper.delete_share.assert_called_once_with(self.share)

    def test_delete_share_not_exists(self):
        self.driver._client.send_request = mock.Mock(
            side_effect=naapi.NaApiError)
        self.driver.delete_share(self._context, self.share)
        self.driver._client.send_request.assert_has_calls([
            mock.call('volume-list-info', {'volume': 'share_fake_uuid'})
        ])

    def test_create_snapshot(self):
        self.driver.create_snapshot(self._context, self.snapshot)
        self.driver._client.send_request.assert_called_once_with(
            'snapshot-create',
            {'volume': 'share_fake_share_id',
             'snapshot': 'share_snapshot_fake_snapshot_uuid'})

    def test_delete_snapshot(self):
        res = mock.Mock()
        res.get_child_by_name.return_value = res
        snap = naapi.NaElement('snap')
        snap.add_new_child('busy', 'true')
        snap.add_new_child('name', 'share_snapshot_fake_snapshot_uuid')
        res.get_children = mock.Mock(return_value=[snap])
        self.driver._client.send_request = mock.Mock(return_value=res)
        self.assertRaises(exception.ShareSnapshotIsBusy,
                          self.driver.delete_snapshot, self._context,
                          self.snapshot)

    def test_delete_snapshot_busy(self):
        res = mock.Mock()
        res.get_child_by_name.return_value = res
        snap = naapi.NaElement('snap')
        snap.add_new_child('busy', 'false')
        snap.add_new_child('name', 'share_fake_uuid')
        res.get_children = mock.Mock(return_value=[snap])
        self.driver._client.send_request = mock.Mock(return_value=res)
        self.driver.delete_snapshot(self._context, self.snapshot)
        self.driver._client.send_request.assert_called_with(
            'snapshot-delete',
            {'volume': 'share_fake_share_id',
             'snapshot': 'share_snapshot_fake_snapshot_uuid'})

    def test_allow_access(self):
        access = "1.2.3.4"
        self.driver.allow_access(self._context, self.share, access)
        self.helper.allow_access.assert_called_ince_with(self._context,
                                                         self.share, access)

    def test_deny_access(self):
        access = "1.2.3.4"
        self.driver.deny_access(self._context, self.share, access)
        self.helper.deny_access.assert_called_ince_with(self._context,
                                                        self.share, access)


class NetAppNFSHelperTestCase(test.TestCase):
    """Tests for NetApp 7mode driver.
    """
    def setUp(self):
        super(NetAppNFSHelperTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._db = mock.Mock()
        self.client = mock.Mock()

        self.share = {'id': 'fake_uuid',
                      'tenant_id': 'fake_tenant_id',
                      'name': 'fake_name',
                      'size': 1,
                      'export_location': 'location:/path',
                      'share_proto': 'fake'}
        self.helper = driver.NetAppNFSHelper()
        self.helper._client = mock.Mock()
        self.helper._client.send_request = mock.Mock()

    def test_create_share(self):
        location = self.helper.create_share('share_name', 'location')
        self.helper._client.send_request.assert_called_once_with(
            'nfs-exportfs-append-rules-2', mock.ANY)
        self.assertEqual(location, 'location:/vol/share_name')

    def test_delete_share(self):
        self.helper.delete_share(self.share)
        self.helper._client.send_request.assert_called_once_with(
            'nfs-exportfs-delete-rules', mock.ANY)

    def test_allow_access(self):
        access = {'access_to': '1.2.3.4',
                  'access_type': 'ip'}
        root = naapi.NaElement('root')
        rules = naapi.NaElement('rules')
        root.add_child_elem(rules)
        self.helper._client.send_request = mock.Mock(return_value=root)
        self.helper.allow_access(self._context, self.share, access)
        self.helper._client.send_request.assert_has_calls([
            mock.call('nfs-exportfs-list-rules-2', mock.ANY),
            mock.call('nfs-exportfs-append-rules-2', mock.ANY)
        ])

    def test_deny_access(self):
        access = {'access_to': '1.2.3.4',
                  'access_type': 'ip'}
        root = naapi.NaElement('root')
        rules = naapi.NaElement('rules')
        root.add_child_elem(rules)
        self.helper._client.send_request = mock.Mock(return_value=root)
        self.helper.allow_access(self._context, self.share, access)
        self.helper._client.send_request.assert_has_calls([
            mock.call('nfs-exportfs-list-rules-2', mock.ANY),
            mock.call('nfs-exportfs-append-rules-2', mock.ANY)
        ])


class NetAppCIFSHelperTestCase(test.TestCase):
    """Tests for NetApp 7mode driver.
    """
    def setUp(self):
        super(NetAppCIFSHelperTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._db = mock.Mock()
        self.share = {'id': 'fake_uuid',
                      'tenant_id': 'fake_tenant_id',
                      'name': 'fake_name',
                      'size': 1,
                      'export_location': None,
                      'share_proto': 'fake'}
        self.share_name = 'fake_share_name'
        self.helper = driver.NetAppCIFSHelper()
        self.helper._client = mock.Mock()
        self.helper._client.send_request = mock.Mock()

    def test_create_share(self):
        self.helper.create_share(self.share_name, 'location')
        self.helper._client.send_request.assert_has_calls([
            mock.call('cifs-status'),
            mock.call().get_child_content('status'),
            mock.call('system-cli', mock.ANY),
            mock.call('cifs-share-add', mock.ANY),
            mock.call('cifs-share-ace-delete', mock.ANY),
        ])

    def test_delete_share(self):
        self.helper.delete_share(self.share)
        self.helper._client.send_request.assert_called_once_with(
            'cifs-share-delete', mock.ANY)

    def test_allow_access(self):
        access = {'access_to': 'user', 'access_type': 'user', }
        self.helper.allow_access(self._context, self.share, access)
        self.helper._client.send_request.assert_called_once_with(
            'cifs-share-ace-set', mock.ANY)
