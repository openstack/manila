# Copyright (c) 2015 Hitachi Data Systems, Inc.
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
import mock
from oslo_config import cfg

from manila import context
from manila import exception
import manila.share.configuration
import manila.share.driver
from manila.share.drivers.hitachi import hds_hnas
from manila.share.drivers.hitachi import ssh
from manila.share import share_types
from manila import test
from manila.tests.db import fakes as db_fakes

CONF = cfg.CONF


def fake_share(**kwargs):
    share = {
        'id': 'fake_id',
        'size': 1,
        'share_type_id': '7450f16e-4c7f-42ab-90f1-c1cfb2a6bc70',
        'share_proto': 'nfs',
        'share_network_id': 'fake_network_id',
        'share_server_id': 'fake_server_id',
        'host': ['None'],
        'export_locations': [{'path': '172.24.44.10:/nfs/volume-00002'}],
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)


@ddt.ddt
class HDSHNASTestCase(test.TestCase):

    def setUp(self):
        super(HDSHNASTestCase, self).setUp()

        self._context = context.get_admin_context()
        self._execute = mock.Mock(return_value=('', ''))
        CONF.set_default('driver_handles_share_servers', False)
        CONF.hds_hnas_evs_id = '2'
        CONF.hds_hnas_evs_ip = '172.24.44.10'
        CONF.hds_hnas_ip = '172.24.44.1'
        CONF.hds_hnas_ip_port = 'hds_hnas_ip_port'
        CONF.hds_hnas_user = 'hds_hnas_user'
        CONF.hds_hnas_password = 'hds_hnas_password'
        CONF.hds_hnas_file_system = 'file_system'
        CONF.hds_hnas_ssh_private_key = 'private_key'
        CONF.hds_hnas_cluster_admin_ip0 = None
        self.const_dhss = 'driver_handles_share_servers'
        self.fake_conf = manila.share.configuration.Configuration(None)
        self._db = mock.Mock()

        self.fake_private_storage = mock.Mock()
        self.mock_object(self.fake_private_storage, 'get',
                         mock.Mock(return_value=None))
        self.mock_object(self.fake_private_storage, 'delete',
                         mock.Mock(return_value=None))

        self.mock_log = self.mock_object(manila.share.drivers.hitachi.hds_hnas,
                                         'LOG')

        self._driver = hds_hnas.HDSHNASDriver(
            private_storage=self.fake_private_storage,
            configuration=self.fake_conf)

        self.server = {
            'instance_id': 'fake_instance_id',
            'ip': 'fake_ip',
            'username': 'fake_username',
            'password': 'fake_password',
            'pk_path': 'fake_pk_path',
            'backend_details': {
                'public_address': '1.2.3.4',
                'instance_id': 'fake',
            },
        }

        self.invalid_server = {
            'backend_details': {
                'ip': '1.1.1.1',
                'instance_id': 'fake',
            },
        }

        self.nfs_export_list = {'export_configuration': 'fake_export'}

        self.share = fake_share()

        self.invalid_share = {
            'id': 'fakeid',
            'name': 'fakename',
            'size': 1,
            'host': 'hnas',
            'share_proto': 'CIFS',
            'share_type_id': 1,
            'share_network_id': 'fake share network id',
            'share_server_id': 'fake share server id',
            'export_locations': [{'path': '172.24.44.110:'
                                          '/mnt/nfs/volume-00002'}],
        }

        self.access = {
            'id': 'fakeaccid',
            'access_type': 'ip',
            'access_to': '10.0.0.2',
            'access_level': 'fake_level',
            'state': 'active',
        }

        self.snapshot = {
            'id': 'snap_name',
            'share_id': 'fake_name',
        }

    @ddt.data('hds_hnas_evs_id', 'hds_hnas_evs_ip',
              'hds_hnas_ip', 'hds_hnas_user')
    def test_init_invalid_conf_parameters(self, attr_name):
        self.mock_object(manila.share.driver.ShareDriver,
                         '__init__')
        setattr(CONF, attr_name, None)

        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.__init__)

    def test_init_invalid_credentials(self):
        self.mock_object(manila.share.driver.ShareDriver,
                         '__init__')
        CONF.hds_hnas_password = None
        CONF.hds_hnas_ssh_private_key = None

        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.__init__)

    def test_allow_access(self):
        self.mock_object(ssh.HNASSSHBackend, 'allow_access')

        self._driver.allow_access(self._context, self.share,
                                  self.access, self.server)

        ssh.HNASSSHBackend.allow_access.assert_called_once_with('fake_id',
                                                                '10.0.0.2',
                                                                'nfs',
                                                                'fake_level')
        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.info.called)

    def test_allow_access_invalid_access_type(self):
        access = {'access_type': 'user', 'access_to': 'fake_dest'}

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.allow_access, self._context,
                          self.share, access, self.server)

    def test_allow_access_invalid_share_protocol(self):
        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.allow_access, self._context,
                          self.invalid_share, self.access, self.server)

    def test_deny_access(self):
        self.mock_object(ssh.HNASSSHBackend, 'deny_access')

        self._driver.deny_access(self._context, self.share,
                                 self.access, self.server)

        ssh.HNASSSHBackend.deny_access.assert_called_once_with('fake_id',
                                                               '10.0.0.2',
                                                               'nfs',
                                                               'fake_level')
        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.info.called)

    def test_deny_access_invalid_share_protocol(self):
        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.deny_access, self._context,
                          self.invalid_share, self.access, self.server)

    def test_create_share(self):
        # share server none
        path = '/' + self.share['id']

        self.mock_object(ssh.HNASSSHBackend, 'create_share',
                         mock.Mock(return_value=path))

        result = self._driver.create_share(self._context,
                                           self.share)

        ssh.HNASSSHBackend.create_share.assert_called_once_with('fake_id', 1,
                                                                'nfs')
        self.assertEqual('172.24.44.10:/fake_id', result)
        self.assertTrue(self.mock_log.debug.called)

    def test_create_share_invalid_share_protocol(self):
        self.assertRaises(exception.ShareBackendException,
                          self._driver.create_share,
                          self._context, self.invalid_share)
        self.assertTrue(self.mock_log.debug.called)

    def test_delete_share(self):
        self.mock_object(ssh.HNASSSHBackend, 'delete_share')

        self._driver.delete_share(self._context, self.share)

        ssh.HNASSSHBackend.delete_share.assert_called_once_with('fake_id',
                                                                'nfs')
        self.assertTrue(self.mock_log.debug.called)

    def test_ensure_share(self):
        export_list = ['172.24.44.10:/shares/fake_id']
        path = '/shares/fake_id'

        self.mock_object(ssh.HNASSSHBackend, 'ensure_share',
                         mock.Mock(return_value=path))

        out = self._driver.ensure_share(self._context, self.share)

        ssh.HNASSSHBackend.ensure_share.assert_called_once_with('fake_id',
                                                                'nfs')
        self.assertTrue(self.mock_log.debug.called)
        self.assertEqual(export_list, out)

    def test_ensure_share_invalid_share_protocol(self):
        # invalid share proto
        self.assertRaises(exception.ShareBackendException,
                          self._driver.ensure_share,
                          self._context, self.invalid_share)
        self.assertTrue(self.mock_log.debug.called)

    def test_extend_share(self):
        self.mock_object(ssh.HNASSSHBackend, 'extend_share')

        self._driver.extend_share(self.share, 5)

        ssh.HNASSSHBackend.extend_share.assert_called_once_with('fake_id', 5,
                                                                'nfs')
        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.info.called)

    def test_extend_share_invalid_share_protocol(self):
        # invalid share with proto != nfs
        m_extend = self.mock_object(ssh.HNASSSHBackend, 'extend_share')

        self.assertRaises(exception.ShareBackendException,
                          self._driver.extend_share,
                          self.invalid_share, 5)
        self.assertFalse(m_extend.called)
        self.assertTrue(self.mock_log.debug.called)

    # TODO(alyson): Implement network tests in DHSS = true mode
    def test_get_network_allocations_number(self):
        self.assertEqual(0, self._driver.get_network_allocations_number())

    def test_create_snapshot(self):
        # tests when hnas.create_snapshot returns successfully
        self.mock_object(ssh.HNASSSHBackend, 'create_snapshot')

        self._driver.create_snapshot(self._context, self.snapshot)

        ssh.HNASSSHBackend.create_snapshot.assert_called_once_with('fake_name',
                                                                   'snap_name')
        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.info.called)

    def test_delete_snapshot(self):
        # tests when hnas.delete_snapshot returns True
        self.mock_object(ssh.HNASSSHBackend, 'delete_snapshot')

        self._driver.delete_snapshot(self._context, self.snapshot)

        ssh.HNASSSHBackend.delete_snapshot.assert_called_once_with('fake_name',
                                                                   'snap_name')
        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.info.called)

    def test_create_share_from_snapshot(self):
        # share server none
        path = '/' + self.share['id']

        self.mock_object(ssh.HNASSSHBackend, 'create_share_from_snapshot',
                         mock.Mock(return_value=path))

        result = self._driver.create_share_from_snapshot(self._context,
                                                         self.share,
                                                         self.snapshot)

        (ssh.HNASSSHBackend.create_share_from_snapshot.
         assert_called_with(self.share, self.snapshot))
        self.assertEqual('172.24.44.10:/fake_id', result)
        self.assertTrue(self.mock_log.debug.called)

    def test_manage_existing(self):
        driver_op = 'fake'
        local_id = 'volume-00002'
        manage_return = {
            'size': 1,
            'export_locations': '172.24.44.10:/mnt/nfs/volume-00002',
        }

        CONF.set_default('share_backend_name', 'HDS1')
        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value='False'))
        self.mock_object(ssh.HNASSSHBackend, 'manage_existing',
                         mock.Mock(return_value=manage_return))

        output = self._driver.manage_existing(self.share, driver_op)

        self.assertEqual(manage_return, output)
        ssh.HNASSSHBackend.manage_existing.assert_called_once_with(self.share,
                                                                   local_id)
        self.assertTrue(self.mock_log.info.called)

        CONF._unset_defaults_and_overrides()

    def test_manage_invalid_host(self):
        driver_op = 'fake'
        self.share_invalid_host = {
            'id': 'fake_id',
            'size': 1,
            'share_type_id': '7450f16e-4c7f-42ab-90f1-c1cfb2a6bc70',
            'share_proto': 'nfs',
            'share_network_id': 'fake_network_id',
            'share_server_id': 'fake_server_id',
            'host': 'fake@INVALID#fake_pool',
            'export_locations': [{'path': '172.24.44.10:/nfs/volume-00002'}],
        }

        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value='False'))

        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing,
                          self.share_invalid_host, driver_op)

    def test_manage_invalid_path(self):
        driver_op = 'fake'
        self.share_invalid_path = {
            'id': 'fake_id',
            'size': 1,
            'share_type_id': '7450f16e-4c7f-42ab-90f1-c1cfb2a6bc70',
            'share_proto': 'nfs',
            'share_network_id': 'fake_network_id',
            'share_server_id': 'fake_server_id',
            'host': 'fake@INVALID#fake_pool',
            'export_locations': [{'path': '172.24.44.10:/volume-00002'}],
        }

        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value='False'))

        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing,
                          self.share_invalid_path, driver_op)

    def test_manage_invalid_evs_ip(self):
        driver_op = 'fake'
        self.share_invalid_ip = {
            'id': 'fake_id',
            'size': 1,
            'share_type_id': '7450f16e-4c7f-42ab-90f1-c1cfb2a6bc70',
            'share_proto': 'nfs',
            'share_network_id': 'fake_network_id',
            'share_server_id': 'fake_server_id',
            'host': 'fake@HDS1#fake_pool',
            'export_locations': [{'path': '9.9.9.9:/nfs/volume-00002'}],
        }

        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value='False'))

        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing,
                          self.share_invalid_ip, driver_op)

    def test_unmanage(self):
        self._driver.unmanage(self.share)

        self.assertTrue(self.mock_log.info.called)
        self.fake_private_storage.delete.assert_called_once_with(
            self.share['id'])

    def test_update_share_stats(self):
        self.mock_object(ssh.HNASSSHBackend, 'get_stats',
                         mock.Mock(return_value=[100, 30]))

        self._driver._update_share_stats()
        self.assertEqual(False,
                         self._driver._stats['driver_handles_share_servers'])
        self.assertEqual(100, self._driver._stats['total_capacity_gb'])
        self.assertEqual(30, self._driver._stats['free_capacity_gb'])
        self.assertEqual(0, self._driver._stats['reserved_percentage'])
        self.assertEqual(True, self._driver._stats['snapshot_support'])
        ssh.HNASSSHBackend.get_stats.assert_called_once_with()
        self.assertTrue(self.mock_log.info.called)
