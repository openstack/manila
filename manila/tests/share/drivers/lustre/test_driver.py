# Copyright 2026 Red Hat, Inc.
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

import os
from unittest import mock

import ddt
from oslo_utils import units

from manila.common import constants
from manila import context
from manila import exception
from manila.share.drivers.lustre import driver as lustre_driver
from manila import test
from manila.tests import fake_share

FAKE_SHARE_ID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
FAKE_NODEMAP_RW = 'm%srw' % lustre_driver.LustreShareDriver._share_hash(
    FAKE_SHARE_ID)
FAKE_NODEMAP_RO = 'm%sro' % lustre_driver.LustreShareDriver._share_hash(
    FAKE_SHARE_ID)


class FakeConfig(object):

    def __init__(self, **kwargs):
        self.driver_handles_share_servers = False
        self.share_backend_name = kwargs.get(
            'share_backend_name', 'FakeLustre')
        self.lustre_share_export_ip = kwargs.get(
            'lustre_share_export_ip', '10.0.0.1')
        self.lustre_mgs_ip = kwargs.get('lustre_mgs_ip', None)
        self.lustre_mds_ip = kwargs.get('lustre_mds_ip', None)
        self.lustre_mount_point = kwargs.get(
            'lustre_mount_point', '/mnt/lustre')
        self.lustre_fs_name = kwargs.get('lustre_fs_name', 'testfs')
        self.lustre_share_path_prefix = kwargs.get(
            'lustre_share_path_prefix', 'manila_shares')
        self.lustre_project_id_start = kwargs.get(
            'lustre_project_id_start', 10000)
        self.lustre_project_id_end = kwargs.get(
            'lustre_project_id_end', 60000)
        self.lustre_nid_type = kwargs.get('lustre_nid_type', 'tcp')
        self.lustre_ssh_username = kwargs.get(
            'lustre_ssh_username', 'root')
        self.lustre_ssh_private_key_path = kwargs.get(
            'lustre_ssh_private_key_path', None)
        self.lustre_reapply_access_on_startup = kwargs.get(
            'lustre_reapply_access_on_startup', False)
        self.network_config_group = kwargs.get(
            'network_config_group', None)
        self.admin_network_config_group = kwargs.get(
            'admin_network_config_group', None)
        self.config_group = kwargs.get('config_group', 'fake_group')
        self.reserved_share_percentage = kwargs.get(
            'reserved_share_percentage', 0)
        self.reserved_share_from_snapshot_percentage = kwargs.get(
            'reserved_share_from_snapshot_percentage', 0)
        self.reserved_share_extend_percentage = kwargs.get(
            'reserved_share_extend_percentage', 0)
        self.max_over_subscription_ratio = kwargs.get(
            'max_over_subscription_ratio', 20.0)
        self.filter_function = kwargs.get('filter_function', None)
        self.goodness_function = kwargs.get('goodness_function', None)
        self.ssh_conn_timeout = kwargs.get('ssh_conn_timeout', 60)

    def safe_get(self, key):
        return getattr(self, key, None)

    def append_config_values(self, *args, **kwargs):
        pass


class FakePrivateStorage(object):

    def __init__(self):
        self.storage = {}

    def update(self, entity_id, data):
        if entity_id not in self.storage:
            self.storage[entity_id] = {}
        self.storage[entity_id].update(data)

    def get(self, entity_id, key=None, default=None):
        if key is None:
            return self.storage.get(entity_id, default)
        return self.storage.get(entity_id, {}).get(key, default)

    def delete(self, entity_id, key=None):
        if key is None:
            self.storage.pop(entity_id, None)
        else:
            self.storage.get(entity_id, {}).pop(key, None)


@ddt.ddt
class LustreShareDriverTestCase(test.TestCase):

    def setUp(self):
        super(LustreShareDriverTestCase, self).setUp()
        self._context = context.get_admin_context()
        self.configuration = FakeConfig()
        self.private_storage = FakePrivateStorage()

        self.mock_object(lustre_driver.CONF, '_check_required_opts')

        self.driver = lustre_driver.LustreShareDriver(
            configuration=self.configuration,
            private_storage=self.private_storage)

        self._share = fake_share.fake_share(
            share_proto='LUSTRE', id=FAKE_SHARE_ID)

    def test_init(self):
        self.assertEqual(self.driver.backend_name, 'FakeLustre')
        self.assertFalse(self.driver.driver_handles_share_servers)
        self.assertIs(self.driver.private_storage, self.private_storage)
        self.assertIsNone(self.driver._mgs_ssh)
        self.assertIsNone(self.driver._mds_ssh)

    def test_do_setup(self):
        self.mock_object(os.path, 'ismount', mock.Mock(return_value=True))
        self.mock_object(os.path, 'isdir', mock.Mock(return_value=True))
        self.mock_object(self.driver, 'init_execute_mixin')
        self.mock_object(self.driver, '_check_lustre_version')
        self.mock_object(self.driver, '_setup_ssh_executors')

        self.driver.do_setup(self._context)

        self.driver._check_lustre_version.assert_called_once()
        self.driver._setup_ssh_executors.assert_called_once()

    def test_do_setup_not_mounted(self):
        self.mock_object(os.path, 'ismount', mock.Mock(return_value=False))
        self.mock_object(self.driver, 'init_execute_mixin')

        self.assertRaises(
            exception.ShareBackendException,
            self.driver.do_setup, self._context)

    def test_do_setup_creates_share_root(self):
        self.mock_object(os.path, 'ismount', mock.Mock(return_value=True))
        self.mock_object(os.path, 'isdir', mock.Mock(return_value=False))
        self.mock_object(self.driver, 'init_execute_mixin')
        self.mock_object(self.driver, '_check_lustre_version')
        self.mock_object(self.driver, '_setup_ssh_executors')
        mock_mkdir = self.mock_object(lustre_driver.privsep_os, 'mkdir')
        mock_chmod = self.mock_object(lustre_driver.privsep_os, 'chmod')

        self.driver.do_setup(self._context)

        mock_mkdir.assert_called_once_with('/mnt/lustre/manila_shares')
        mock_chmod.assert_called_once_with('0711', '/mnt/lustre/manila_shares')

    def test_check_lustre_version_ok(self):
        self.mock_object(
            self.driver, '_exec_mds',
            mock.Mock(return_value=('lustre: 2.16.0\n', '')))

        self.driver._check_lustre_version()

    def test_check_lustre_version_too_old(self):
        self.mock_object(
            self.driver, '_exec_mds',
            mock.Mock(return_value=('lustre: 2.15.4\n', '')))

        self.assertRaises(
            exception.ShareBackendException,
            self.driver._check_lustre_version)

    def test_check_lustre_version_exec_fails(self):
        self.mock_object(
            self.driver, '_exec_mds',
            mock.Mock(side_effect=exception.ProcessExecutionError(
                exit_code=1)))

        self.assertRaises(
            exception.ShareBackendException,
            self.driver._check_lustre_version)

    def test_check_lustre_version_unparseable(self):
        self.mock_object(
            self.driver, '_exec_mds',
            mock.Mock(return_value=('unknown\n', '')))

        self.assertRaises(
            exception.ShareBackendException,
            self.driver._check_lustre_version)

    @ddt.data('2.16.0', '2.17.1', '3.0.0')
    def test_check_lustre_version_acceptable(self, version):
        self.mock_object(
            self.driver, '_exec_mds',
            mock.Mock(return_value=('lustre: %s\n' % version, '')))

        self.driver._check_lustre_version()

    def test_setup_ssh_executors_local(self):
        self.driver._setup_ssh_executors()

        self.assertIsNone(self.driver._mgs_ssh)
        self.assertIsNone(self.driver._mds_ssh)

    def test_setup_ssh_executors_remote(self):
        self.driver.configuration.lustre_mgs_ip = '10.0.0.2'
        self.driver.configuration.lustre_mds_ip = '10.0.0.3'
        mock_pool = self.mock_object(
            lustre_driver.ssh_utils, 'SSHPool')

        self.driver._setup_ssh_executors()

        self.assertEqual(mock_pool.call_count, 2)
        self.assertIsNotNone(self.driver._mgs_ssh)
        self.assertIsNotNone(self.driver._mds_ssh)

    def test_exec_mgs_local(self):
        mock_privsep = self.mock_object(
            lustre_driver.privsep_lustre, 'lctl_nodemap_add')

        self.driver._exec_mgs('lctl_nodemap_add', 'test_nodemap')

        mock_privsep.assert_called_once_with('test_nodemap')

    def test_exec_mgs_remote(self):
        mock_pool = mock.Mock()
        mock_ssh = mock.Mock()
        mock_pool.get.return_value = mock_ssh
        self.driver._mgs_ssh = mock_pool
        self.mock_object(
            lustre_driver.processutils, 'ssh_execute',
            mock.Mock(return_value=('', '')))

        self.driver._exec_mgs('lctl_nodemap_add', 'test_nodemap')

        lustre_driver.processutils.ssh_execute.assert_called_once_with(
            mock_ssh, "sudo lctl nodemap_add test_nodemap")
        mock_pool.put.assert_called_once_with(mock_ssh)

    def test_exec_mds_local(self):
        mock_privsep = self.mock_object(
            lustre_driver.privsep_lustre, 'lfs_df',
            mock.Mock(return_value=('output', '')))

        result = self.driver._exec_mds('lfs_df', '/mnt/lustre')

        mock_privsep.assert_called_once_with('/mnt/lustre')
        self.assertEqual(result, ('output', ''))

    def test_exec_mds_remote(self):
        mock_pool = mock.Mock()
        mock_ssh = mock.Mock()
        mock_pool.get.return_value = mock_ssh
        self.driver._mds_ssh = mock_pool
        self.mock_object(
            lustre_driver.processutils, 'ssh_execute',
            mock.Mock(return_value=('output', '')))

        result = self.driver._exec_mds('lfs_df', '/mnt/lustre')

        lustre_driver.processutils.ssh_execute.assert_called_once_with(
            mock_ssh, "sudo lfs df /mnt/lustre")
        mock_pool.put.assert_called_once_with(mock_ssh)
        self.assertEqual(result, ('output', ''))

    def test_check_for_setup_error(self):
        self.mock_object(os.path, 'ismount', mock.Mock(return_value=True))
        self.driver.check_for_setup_error()

    def test_check_for_setup_error_not_mounted(self):
        self.mock_object(os.path, 'ismount', mock.Mock(return_value=False))
        self.assertRaises(
            exception.InvalidShare,
            self.driver.check_for_setup_error)

    def test_create_share(self):
        self.mock_object(
            self.driver, '_assign_project_id',
            mock.Mock(return_value=10000))
        mock_mkdir = self.mock_object(lustre_driver.privsep_os, 'mkdir')
        mock_chmod = self.mock_object(lustre_driver.privsep_os, 'chmod')
        mock_exec_mds = self.mock_object(
            self.driver, '_exec_mds')

        result = self.driver.create_share(self._context, self._share)

        share_path = '/mnt/lustre/manila_shares/' + FAKE_SHARE_ID
        mock_mkdir.assert_called_once_with(share_path)
        mock_chmod.assert_called_once_with('0777', share_path)
        self.driver._assign_project_id.assert_called_once_with(share_path)
        mock_exec_mds.assert_called_once_with(
            'lfs_setquota', 10000, '%dk' % (1 * units.Mi), '/mnt/lustre')

        self.assertEqual(
            self.private_storage.get(FAKE_SHARE_ID, 'project_id'),
            '10000')

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]['path'],
            '10.0.0.1@tcp:/testfs/manila_shares/' + FAKE_SHARE_ID)

    def test_create_share_wrong_protocol(self):
        share = fake_share.fake_share(share_proto='NFS')
        self.assertRaises(
            exception.InvalidShare,
            self.driver.create_share, self._context, share)

    def test_delete_share(self):
        self.private_storage.update(FAKE_SHARE_ID, {
            'project_id': '10001',
        })
        self.mock_object(os.path, 'isdir', mock.Mock(return_value=True))
        mock_exec_mds = self.mock_object(self.driver, '_exec_mds')
        mock_exec_mgs = self.mock_object(self.driver, '_exec_mgs')
        mock_rm = self.mock_object(
            lustre_driver.privsep_os, 'recursive_forced_rm')

        self.driver.delete_share(self._context, self._share)

        mock_exec_mds.assert_called_once_with(
            'lfs_clear_quota', '10001', '/mnt/lustre')
        mock_exec_mgs.assert_any_call(
            'lctl_nodemap_del', FAKE_NODEMAP_RW)
        mock_exec_mgs.assert_any_call(
            'lctl_nodemap_del', FAKE_NODEMAP_RO)
        mock_rm.assert_called_once_with(
            '/mnt/lustre/manila_shares/' + FAKE_SHARE_ID)
        self.assertIsNone(
            self.private_storage.get(FAKE_SHARE_ID, 'project_id'))

    def test_delete_share_not_found(self):
        self.mock_object(os.path, 'isdir', mock.Mock(return_value=False))
        mock_rm = self.mock_object(
            lustre_driver.privsep_os, 'recursive_forced_rm')

        self.driver.delete_share(self._context, self._share)

        mock_rm.assert_not_called()

    def test_delete_share_quota_clear_fails(self):
        self.private_storage.update(FAKE_SHARE_ID, {
            'project_id': '10001',
        })
        self.mock_object(os.path, 'isdir', mock.Mock(return_value=True))
        self.mock_object(
            self.driver, '_exec_mds',
            mock.Mock(side_effect=exception.ProcessExecutionError()))
        self.mock_object(self.driver, '_exec_mgs')
        self.mock_object(
            lustre_driver.privsep_os, 'recursive_forced_rm')

        self.driver.delete_share(self._context, self._share)
        self.assertIsNone(
            self.private_storage.get(FAKE_SHARE_ID, 'project_id'))

    def test_extend_share(self):
        self.private_storage.update(FAKE_SHARE_ID, {
            'project_id': '10001',
        })
        mock_exec_mds = self.mock_object(self.driver, '_exec_mds')
        new_size = 5

        self.driver.extend_share(self._share, new_size)

        mock_exec_mds.assert_called_once_with(
            'lfs_setquota', '10001', '%dk' % (5 * units.Mi), '/mnt/lustre')

    def test_extend_share_no_project_id(self):
        self.assertRaises(
            exception.ShareBackendException,
            self.driver.extend_share, self._share, 5)

    def test_shrink_share(self):
        self.private_storage.update(FAKE_SHARE_ID, {
            'project_id': '10001',
        })
        self.mock_object(
            self.driver, '_get_project_usage_kb',
            mock.Mock(return_value=512000))
        mock_exec_mds = self.mock_object(self.driver, '_exec_mds')

        self.driver.shrink_share(self._share, 1)

        mock_exec_mds.assert_called_once_with(
            'lfs_setquota', '10001', '%dk' % (1 * units.Mi), '/mnt/lustre')

    def test_shrink_share_data_loss(self):
        self.private_storage.update(FAKE_SHARE_ID, {
            'project_id': '10001',
        })
        usage_kb = 2 * units.Mi
        self.mock_object(
            self.driver, '_get_project_usage_kb',
            mock.Mock(return_value=usage_kb))

        self.assertRaises(
            exception.ShareShrinkingPossibleDataLoss,
            self.driver.shrink_share, self._share, 1)

    def test_shrink_share_no_project_id(self):
        self.assertRaises(
            exception.ShareBackendException,
            self.driver.shrink_share, self._share, 1)

    def test_get_project_usage_kb(self):
        quota_output = (
            "Disk quotas for prj 10001 (pid 10001):\n"
            "     Filesystem  kbytes   quota   limit   grace   files"
            "   quota   limit   grace\n"
            "     /mnt/lustre   204800       0  1048576       -      10"
            "       0       0       -\n"
        )
        self.mock_object(
            self.driver, '_exec_mds',
            mock.Mock(return_value=(quota_output, '')))

        result = self.driver._get_project_usage_kb('10001')

        self.assertEqual(result, 204800)

    def test_get_project_usage_kb_over_soft_limit(self):
        quota_output = (
            "Disk quotas for prj 10001 (pid 10001):\n"
            "     Filesystem  kbytes   quota   limit   grace   files"
            "   quota   limit   grace\n"
            "     /mnt/lustre   204800*      0  1048576       -      10"
            "       0       0       -\n"
        )
        self.mock_object(
            self.driver, '_exec_mds',
            mock.Mock(return_value=(quota_output, '')))

        result = self.driver._get_project_usage_kb('10001')

        self.assertEqual(result, 204800)

    def test_get_export_locations(self):
        result = self.driver._get_export_locations('fake-share-id')

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]['path'],
            '10.0.0.1@tcp:/testfs/manila_shares/fake-share-id')
        self.assertFalse(result[0]['is_admin_only'])

    def test_nodemap_name(self):
        rw = self.driver._nodemap_name('abc-def-ghi-1234', 'rw')
        ro = self.driver._nodemap_name('abc-def-ghi-1234', 'ro')
        self.assertTrue(rw.startswith('m'))
        self.assertTrue(rw.endswith('rw'))
        self.assertTrue(ro.endswith('ro'))
        self.assertNotEqual(rw, ro)
        self.assertLessEqual(len(rw), 15)
        self.assertLessEqual(len(ro), 15)

    def test_nodemap_name_long_id(self):
        long_id = 'a' * 36 + '-' + 'b' * 36
        name = self.driver._nodemap_name(long_id, 'rw')
        self.assertTrue(name.startswith('m'))
        self.assertTrue(name.endswith('rw'))
        self.assertLessEqual(len(name), 15)

    def test_nodemap_name_deterministic(self):
        name1 = self.driver._nodemap_name('share-123', 'rw')
        name2 = self.driver._nodemap_name('share-123', 'rw')
        self.assertEqual(name1, name2)

    def test_ip_to_nid_range_single_ip(self):
        result = lustre_driver.LustreShareDriver._ip_to_nid_range(
            '192.168.1.10', 'tcp')
        self.assertEqual(result, '192.168.1.10@tcp:192.168.1.10@tcp')

    def test_ip_to_nid_range_cidr(self):
        result = lustre_driver.LustreShareDriver._ip_to_nid_range(
            '10.0.0.0/24', 'tcp')
        self.assertEqual(result, '10.0.0.0@tcp:10.0.0.255@tcp')

    def test_ip_to_nid_range_all_ipv4(self):
        result = lustre_driver.LustreShareDriver._ip_to_nid_range(
            '0.0.0.0/0', 'tcp')
        self.assertEqual(result, '0.0.0.0@tcp:255.255.255.255@tcp')

    def test_ip_to_nid_range_o2ib(self):
        result = lustre_driver.LustreShareDriver._ip_to_nid_range(
            '192.168.1.10', 'o2ib')
        self.assertEqual(result, '192.168.1.10@o2ib:192.168.1.10@o2ib')

    def test_add_access_rule_ipv6_ignored(self):
        rule = {
            'id': 'mapping-v6',
            'access_id': 'rule-v6',
            'access_type': 'ip',
            'access_to': '2001:db8::1',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        mock_exec_mgs = self.mock_object(self.driver, '_exec_mgs')

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[rule],
            delete_rules=[], update_rules=[])

        mock_exec_mgs.assert_not_called()
        self.assertEqual(
            result['rule-v6']['state'], constants.ACCESS_STATE_ACTIVE)

    def test_update_access_add_rule(self):
        rule = {
            'id': 'mapping-1',
            'access_id': 'rule-1',
            'access_type': 'ip',
            'access_to': '192.168.1.10',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        mock_exec_mgs = self.mock_object(
            self.driver, '_exec_mgs')
        self.mock_object(lustre_driver.privsep_os, 'chmod')

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[rule],
            delete_rules=[], update_rules=[])

        mock_exec_mgs.assert_any_call(
            'lctl_nodemap_add', FAKE_NODEMAP_RW)
        mock_exec_mgs.assert_any_call(
            'lctl_nodemap_add_range', FAKE_NODEMAP_RW,
            '192.168.1.10@tcp:192.168.1.10@tcp')
        mock_exec_mgs.assert_any_call(
            'lctl_nodemap_modify', FAKE_NODEMAP_RW,
            'trusted', '1')
        mock_exec_mgs.assert_any_call(
            'lctl_nodemap_modify', FAKE_NODEMAP_RW,
            'admin', '1')

        self.assertEqual(
            result['rule-1']['state'], constants.ACCESS_STATE_ACTIVE)

    def test_update_access_add_ro_rule(self):
        rule = {
            'id': 'mapping-2',
            'access_id': 'rule-2',
            'access_type': 'ip',
            'access_to': '192.168.1.20',
            'access_level': constants.ACCESS_LEVEL_RO,
        }
        mock_exec_mgs = self.mock_object(
            self.driver, '_exec_mgs')
        self.mock_object(lustre_driver.privsep_os, 'chmod')

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[rule],
            delete_rules=[], update_rules=[])

        mock_exec_mgs.assert_any_call(
            'lctl_nodemap_modify', FAKE_NODEMAP_RO,
            'readonly_mount', '1')

        self.assertEqual(
            result['rule-2']['state'], constants.ACCESS_STATE_ACTIVE)

    def test_update_access_add_cidr_rule(self):
        rule = {
            'id': 'mapping-cidr',
            'access_id': 'rule-cidr',
            'access_type': 'ip',
            'access_to': '10.0.0.0/24',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        mock_exec_mgs = self.mock_object(
            self.driver, '_exec_mgs')
        self.mock_object(lustre_driver.privsep_os, 'chmod')

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[rule],
            delete_rules=[], update_rules=[])

        mock_exec_mgs.assert_any_call(
            'lctl_nodemap_add_range', FAKE_NODEMAP_RW,
            '10.0.0.0@tcp:10.0.0.255@tcp')

        self.assertEqual(
            result['rule-cidr']['state'], constants.ACCESS_STATE_ACTIVE)

    def test_update_access_invalid_type(self):
        rule = {
            'id': 'mapping-3',
            'access_id': 'rule-3',
            'access_type': 'user',
            'access_to': 'someuser',
            'access_level': constants.ACCESS_LEVEL_RW,
        }

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[rule],
            delete_rules=[], update_rules=[])

        self.assertEqual(
            result['rule-3']['state'], constants.ACCESS_STATE_ERROR)

    def test_update_access_delete_rule(self):
        rule = {
            'id': 'mapping-1',
            'access_id': 'rule-1',
            'access_type': 'ip',
            'access_to': '192.168.1.10',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        mock_exec_mgs = self.mock_object(
            self.driver, '_exec_mgs')

        self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[],
            delete_rules=[rule], update_rules=[])

        mock_exec_mgs.assert_called_once_with(
            'lctl_nodemap_del_range', FAKE_NODEMAP_RW,
            '192.168.1.10@tcp:192.168.1.10@tcp')

    def test_update_access_reconcile(self):
        rules = [
            {
                'id': 'mapping-a',
                'access_id': 'rule-a',
                'access_type': 'ip',
                'access_to': '10.0.0.1',
                'access_level': constants.ACCESS_LEVEL_RW,
            },
        ]
        mock_exec_mgs = self.mock_object(
            self.driver, '_exec_mgs')
        self.mock_object(lustre_driver.privsep_os, 'chmod')

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=rules, add_rules=[],
            delete_rules=[], update_rules=[])

        mock_exec_mgs.assert_any_call(
            'lctl_nodemap_del', FAKE_NODEMAP_RW)
        mock_exec_mgs.assert_any_call(
            'lctl_nodemap_del', FAKE_NODEMAP_RO)
        self.assertEqual(
            result['rule-a']['state'], constants.ACCESS_STATE_ACTIVE)

    def test_get_backend_info(self):
        result = self.driver.get_backend_info(self._context)
        self.assertEqual(result['lustre_fs_name'], 'testfs')
        self.assertEqual(result['lustre_mount_point'], '/mnt/lustre')
        self.assertEqual(result['lustre_share_export_ip'], '10.0.0.1')

    def test_ensure_shares(self):
        shares = [
            fake_share.fake_share(
                share_proto='LUSTRE', id='share-1'),
            fake_share.fake_share(
                share_proto='LUSTRE', id='share-2'),
        ]
        self.mock_object(os.path, 'isdir', mock.Mock(return_value=True))

        result = self.driver.ensure_shares(self._context, shares)

        self.assertIn('share-1', result)
        self.assertIn('share-2', result)
        self.assertFalse(result['share-1']['reapply_access_rules'])
        self.assertFalse(result['share-2']['reapply_access_rules'])
        self.assertEqual(len(result['share-1']['export_locations']), 1)

    def test_ensure_shares_reapply_access(self):
        shares = [
            fake_share.fake_share(
                share_proto='LUSTRE', id='share-1'),
        ]
        self.mock_object(os.path, 'isdir', mock.Mock(return_value=True))
        self.driver.configuration.lustre_reapply_access_on_startup = True

        result = self.driver.ensure_shares(self._context, shares)

        self.assertTrue(result['share-1']['reapply_access_rules'])

    def test_ensure_shares_missing_directory(self):
        shares = [
            fake_share.fake_share(
                share_proto='LUSTRE', id='share-ok'),
            fake_share.fake_share(
                share_proto='LUSTRE', id='share-gone'),
        ]

        def isdir_side_effect(path):
            return 'share-gone' not in path
        self.mock_object(os.path, 'isdir',
                         mock.Mock(side_effect=isdir_side_effect))

        result = self.driver.ensure_shares(self._context, shares)

        self.assertFalse(result['share-ok']['reapply_access_rules'])
        self.assertIn('export_locations', result['share-ok'])
        self.assertEqual(
            result['share-gone']['status'], constants.STATUS_ERROR)
        self.assertNotIn('export_locations', result['share-gone'])

    def test_parse_lfs_df(self):
        lfs_df_output = (
            "UUID                   1K-blocks        Used   Available "
            "Use% Mounted on\n"
            "testfs-MDT0000_UUID     1048576      204800      843776 "
            " 20% /mnt/lustre[MDT:0]\n"
            "testfs-OST0000_UUID    10485760     2097152     8388608 "
            " 20% /mnt/lustre[OST:0]\n"
            "testfs-OST0001_UUID    10485760     1048576     9437184 "
            " 10% /mnt/lustre[OST:1]\n"
            "\n"
            "filesystem_summary:    20971520     3145728    17825792 "
            " 15% /mnt/lustre\n"
        )
        self.mock_object(
            lustre_driver.privsep_lustre, 'lfs_df',
            mock.Mock(return_value=(lfs_df_output, '')))

        total_kb, free_kb = self.driver._parse_lfs_df()

        self.assertEqual(total_kb, 10485760 + 10485760)
        self.assertEqual(free_kb, 8388608 + 9437184)

    def test_update_share_stats(self):
        lfs_df_output = (
            "UUID                   1K-blocks        Used   Available "
            "Use% Mounted on\n"
            "testfs-OST0000_UUID    10485760     2097152     8388608 "
            " 20% /mnt/lustre[OST:0]\n"
        )
        self.mock_object(
            lustre_driver.privsep_lustre, 'lfs_df',
            mock.Mock(return_value=(lfs_df_output, '')))

        self.driver._update_share_stats()

        self.assertIn('pools', self.driver._stats)
        self.assertEqual(self.driver._stats['vendor_name'], 'Lustre')
        self.assertEqual(self.driver._stats['storage_protocol'], 'LUSTRE')
        self.assertFalse(self.driver._stats['snapshot_support'])
        pool = self.driver._stats['pools'][0]
        self.assertEqual(pool['pool_name'], 'testfs')
        expected_total = round(10485760 / units.Mi, 2)
        self.assertEqual(pool['total_capacity_gb'], expected_total)

    def test_update_share_stats_failure(self):
        self.mock_object(
            lustre_driver.privsep_lustre, 'lfs_df',
            mock.Mock(side_effect=exception.ProcessExecutionError()))

        self.driver._update_share_stats()

        self.assertEqual(
            self.driver._stats['total_capacity_gb'], 'unknown')
        self.assertEqual(
            self.driver._stats['free_capacity_gb'], 'unknown')

    def test_get_network_allocations_number(self):
        self.assertEqual(self.driver.get_network_allocations_number(), 0)

    def test_assign_project_id(self):
        self.mock_object(
            self.driver, '_allocate_project_id',
            mock.Mock(return_value=10000))
        mock_chattr = self.mock_object(
            lustre_driver.privsep_lustre, 'chattr_project')

        result = self.driver._assign_project_id('/mnt/lustre/shares/s1')

        self.assertEqual(result, 10000)
        mock_chattr.assert_called_once_with(10000, '/mnt/lustre/shares/s1')

    def test_allocate_project_id(self):
        self.mock_object(
            self.driver, '_get_used_project_ids',
            mock.Mock(return_value=set()))

        pid = self.driver._allocate_project_id()
        self.assertEqual(pid, 10000)

    def test_allocate_project_id_some_used(self):
        self.mock_object(
            self.driver, '_get_used_project_ids',
            mock.Mock(return_value={10000, 10001, 10002}))

        pid = self.driver._allocate_project_id()
        self.assertEqual(pid, 10003)

    def test_allocate_project_id_exhausted(self):
        self.driver.configuration.lustre_project_id_start = 100
        self.driver.configuration.lustre_project_id_end = 102
        self.mock_object(
            self.driver, '_get_used_project_ids',
            mock.Mock(return_value={100, 101, 102}))

        self.assertRaises(
            exception.ShareBackendException,
            self.driver._allocate_project_id)

    def test_get_used_project_ids(self):
        lfs_project_output = (
            "10000 P /mnt/lustre/manila_shares/share-1\n"
            "10001 P /mnt/lustre/manila_shares/share-2\n"
        )
        self.mock_object(
            lustre_driver.privsep_lustre, 'lfs_project',
            mock.Mock(return_value=(lfs_project_output, '')))

        result = self.driver._get_used_project_ids()

        self.assertEqual(result, {10000, 10001})

    def test_get_used_project_ids_error(self):
        self.mock_object(
            lustre_driver.privsep_lustre, 'lfs_project',
            mock.Mock(side_effect=exception.ProcessExecutionError()))

        result = self.driver._get_used_project_ids()
        self.assertEqual(result, set())

    def test_size_to_kb(self):
        self.assertEqual(self.driver._size_to_kb(1), units.Mi)
        self.assertEqual(self.driver._size_to_kb(5), 5 * units.Mi)

    def test_share_path(self):
        path = self.driver._share_path('clemson-tigers')
        self.assertEqual(
            path, '/mnt/lustre/manila_shares/clemson-tigers')

    def _managed_share(self, share_id, export_path):
        return fake_share.fake_share(
            share_proto='LUSTRE', id=share_id,
            export_locations=[{'path': export_path}])

    def test_manage_existing(self):
        share = self._managed_share(
            'managed-share-1',
            '10.0.0.1@tcp:/testfs/manila_shares/existing-dir')

        self.mock_object(os.path, 'isdir', mock.Mock(return_value=True))
        self.mock_object(
            self.driver, '_get_directory_project_id',
            mock.Mock(return_value=10050))
        self.mock_object(
            self.driver, '_get_project_limit_kb',
            mock.Mock(return_value=5 * units.Mi))

        result = self.driver.manage_existing(share, {})

        self.assertEqual(result['size'], 5)
        self.assertIn('export_locations', result)
        self.assertEqual(
            self.private_storage.get('managed-share-1', 'project_id'),
            '10050')

    def test_manage_existing_ignores_size_option(self):
        share = self._managed_share(
            'managed-share-2',
            '10.0.0.1@tcp:/testfs/manila_shares/existing-dir')

        self.mock_object(os.path, 'isdir', mock.Mock(return_value=True))
        self.mock_object(
            self.driver, '_get_directory_project_id',
            mock.Mock(return_value=10050))
        self.mock_object(
            self.driver, '_get_project_limit_kb',
            mock.Mock(return_value=5 * units.Mi))

        result = self.driver.manage_existing(share, {'size': 10})

        self.assertEqual(result['size'], 5)
        self.driver._get_project_limit_kb.assert_called_once_with(10050)

    def test_manage_existing_no_directory(self):
        share = self._managed_share(
            'managed-share-3',
            '10.0.0.1@tcp:/testfs/manila_shares/missing-dir')

        self.mock_object(os.path, 'isdir', mock.Mock(return_value=False))

        self.assertRaises(
            exception.ManageInvalidShare,
            self.driver.manage_existing, share, {})

    def test_manage_existing_no_quota(self):
        share = self._managed_share(
            'managed-share-4',
            '10.0.0.1@tcp:/testfs/manila_shares/no-quota')

        self.mock_object(os.path, 'isdir', mock.Mock(return_value=True))
        self.mock_object(
            self.driver, '_get_directory_project_id',
            mock.Mock(return_value=10050))
        self.mock_object(
            self.driver, '_get_project_limit_kb',
            mock.Mock(return_value=0))

        self.assertRaises(
            exception.ManageInvalidShare,
            self.driver.manage_existing, share, {})

    def test_unmanage(self):
        self.private_storage.update('share-to-unmanage', {
            'project_id': '10001',
        })
        share = fake_share.fake_share(
            share_proto='LUSTRE', id='share-to-unmanage')

        self.driver.unmanage(share)

        self.assertIsNone(
            self.private_storage.get('share-to-unmanage', 'project_id'))

    def test_export_to_local_path(self):
        path = self.driver._export_to_local_path(
            '10.0.0.1@tcp:/testfs/manila_shares/share-abc')
        self.assertEqual(path, '/mnt/lustre/manila_shares/share-abc')

    def test_export_to_local_path_invalid(self):
        self.assertRaises(
            exception.ManageInvalidShare,
            self.driver._export_to_local_path, '10.0.0.1@tcp:/testfs')

    def test_get_project_limit_kb(self):
        quota_output = (
            "Disk quotas for prj 10001 (pid 10001):\n"
            "     Filesystem  kbytes   quota   limit   grace   files"
            "   quota   limit   grace\n"
            "     /mnt/lustre   204800       0  5242880       -      10"
            "       0       0       -\n"
        )
        self.mock_object(
            self.driver, '_exec_mds',
            mock.Mock(return_value=(quota_output, '')))

        result = self.driver._get_project_limit_kb('10001')

        self.assertEqual(result, 5242880)

    def test_get_directory_project_id(self):
        lfs_output = "10050 P /mnt/lustre/manila_shares/share-1\n"
        self.mock_object(
            lustre_driver.privsep_lustre, 'lfs_project',
            mock.Mock(return_value=(lfs_output, '')))

        result = self.driver._get_directory_project_id(
            '/mnt/lustre/manila_shares/share-1')

        self.assertEqual(result, 10050)

    def test_get_directory_project_id_unparseable(self):
        self.mock_object(
            lustre_driver.privsep_lustre, 'lfs_project',
            mock.Mock(return_value=('garbage output\n', '')))

        self.assertRaises(
            exception.ShareBackendException,
            self.driver._get_directory_project_id, '/mnt/lustre/shares/s1')

    def test_mds_mount_point_default(self):
        self.assertEqual(self.driver._mds_mount_point, '/mnt/lustre')

    def test_mds_mount_point_override(self):
        self.driver.configuration.lustre_mds_mount_point = '/remote/mnt'
        self.assertEqual(self.driver._mds_mount_point, '/remote/mnt')

    def test_create_share_mkdir_fails(self):
        self.mock_object(
            lustre_driver.privsep_os, 'mkdir',
            mock.Mock(side_effect=exception.ProcessExecutionError()))

        self.assertRaises(
            exception.ProcessExecutionError,
            self.driver.create_share, self._context, self._share)

    def test_create_share_uses_mds_mount_for_quota(self):
        self.driver.configuration.lustre_mds_mount_point = '/remote/mnt'
        self.mock_object(
            self.driver, '_assign_project_id',
            mock.Mock(return_value=10000))
        self.mock_object(lustre_driver.privsep_os, 'mkdir')
        self.mock_object(lustre_driver.privsep_os, 'chmod')
        mock_exec_mds = self.mock_object(self.driver, '_exec_mds')

        self.driver.create_share(self._context, self._share)

        mock_exec_mds.assert_called_once_with(
            'lfs_setquota', 10000,
            '%dk' % (1 * units.Mi), '/remote/mnt')

    def test_extend_share_uses_mds_mount_for_quota(self):
        self.driver.configuration.lustre_mds_mount_point = '/remote/mnt'
        self.private_storage.update(FAKE_SHARE_ID, {
            'project_id': '10001',
        })
        mock_exec_mds = self.mock_object(self.driver, '_exec_mds')

        self.driver.extend_share(self._share, 5)

        mock_exec_mds.assert_called_once_with(
            'lfs_setquota', '10001',
            '%dk' % (5 * units.Mi), '/remote/mnt')

    def test_shrink_share_uses_mds_mount_for_quota(self):
        self.driver.configuration.lustre_mds_mount_point = '/remote/mnt'
        self.private_storage.update(FAKE_SHARE_ID, {
            'project_id': '10001',
        })
        self.mock_object(
            self.driver, '_get_project_usage_kb',
            mock.Mock(return_value=100))
        mock_exec_mds = self.mock_object(self.driver, '_exec_mds')

        self.driver.shrink_share(self._share, 1)

        mock_exec_mds.assert_called_once_with(
            'lfs_setquota', '10001',
            '%dk' % (1 * units.Mi), '/remote/mnt')

    def test_delete_share_no_private_storage_fallback(self):
        self.mock_object(os.path, 'isdir', mock.Mock(return_value=True))
        self.mock_object(
            self.driver, '_get_directory_project_id',
            mock.Mock(return_value=10001))
        mock_exec_mds = self.mock_object(self.driver, '_exec_mds')
        mock_exec_mgs = self.mock_object(self.driver, '_exec_mgs')
        mock_rm = self.mock_object(
            lustre_driver.privsep_os, 'recursive_forced_rm')

        self.driver.delete_share(self._context, self._share)

        mock_exec_mds.assert_called_once_with(
            'lfs_clear_quota', 10001, '/mnt/lustre')
        mock_exec_mgs.assert_any_call(
            'lctl_nodemap_del', FAKE_NODEMAP_RW)
        mock_rm.assert_called_once()

    def test_delete_share_no_private_storage_fallback_fails(self):
        self.mock_object(os.path, 'isdir', mock.Mock(return_value=True))
        self.mock_object(
            self.driver, '_get_directory_project_id',
            mock.Mock(side_effect=exception.ShareBackendException(
                msg='no project')))
        mock_rm = self.mock_object(
            lustre_driver.privsep_os, 'recursive_forced_rm')

        self.driver.delete_share(self._context, self._share)

        mock_rm.assert_called_once()

    def test_update_access_add_and_delete_same_call(self):
        add_rule = {
            'id': 'mapping-add',
            'access_id': 'rule-add',
            'access_type': 'ip',
            'access_to': '10.0.0.1',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        del_rule = {
            'id': 'mapping-del',
            'access_id': 'rule-del',
            'access_type': 'ip',
            'access_to': '10.0.0.2',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        self.mock_object(self.driver, '_exec_mgs')
        self.mock_object(lustre_driver.privsep_os, 'chmod')

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[add_rule],
            delete_rules=[del_rule], update_rules=[])

        self.assertEqual(
            result['rule-add']['state'], constants.ACCESS_STATE_ACTIVE)

    def test_update_access_delete_ipv6_noop(self):
        rule = {
            'id': 'mapping-v6',
            'access_id': 'rule-v6',
            'access_type': 'ip',
            'access_to': '2001:db8::1',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        mock_exec_mgs = self.mock_object(self.driver, '_exec_mgs')

        self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[],
            delete_rules=[rule], update_rules=[])

        mock_exec_mgs.assert_not_called()

    def test_update_access_delete_nonip_noop(self):
        rule = {
            'id': 'mapping-user',
            'access_id': 'rule-user',
            'access_type': 'user',
            'access_to': 'someone',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        mock_exec_mgs = self.mock_object(self.driver, '_exec_mgs')

        self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[],
            delete_rules=[rule], update_rules=[])

        mock_exec_mgs.assert_not_called()

    def test_update_access_reconcile_with_failure(self):
        rules = [
            {
                'id': 'mapping-ok',
                'access_id': 'rule-ok',
                'access_type': 'ip',
                'access_to': '10.0.0.1',
                'access_level': constants.ACCESS_LEVEL_RW,
            },
            {
                'id': 'mapping-bad',
                'access_id': 'rule-bad',
                'access_type': 'user',
                'access_to': 'baduser',
                'access_level': constants.ACCESS_LEVEL_RW,
            },
        ]
        self.mock_object(self.driver, '_exec_mgs')
        self.mock_object(lustre_driver.privsep_os, 'chmod')

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=rules, add_rules=[],
            delete_rules=[], update_rules=[])

        self.assertEqual(
            result['rule-ok']['state'], constants.ACCESS_STATE_ACTIVE)
        self.assertEqual(
            result['rule-bad']['state'], constants.ACCESS_STATE_ERROR)

    def test_update_share_stats_provisioned_capacity(self):
        lfs_df_output = (
            "UUID                   1K-blocks        Used   Available "
            "Use% Mounted on\n"
            "testfs-OST0000_UUID    10485760     2097152     8388608 "
            " 20% /mnt/lustre[OST:0]\n"
        )
        self.mock_object(
            lustre_driver.privsep_lustre, 'lfs_df',
            mock.Mock(return_value=(lfs_df_output, '')))

        self.driver._update_share_stats()

        pool = self.driver._stats['pools'][0]
        expected_provisioned = round(2097152 / units.Mi, 2)
        self.assertEqual(pool['provisioned_capacity_gb'],
                         expected_provisioned)

    def test_ssh_cmd_returns_connection_to_pool(self):
        mock_pool = mock.Mock()
        mock_ssh = mock.Mock()
        mock_pool.get.return_value = mock_ssh
        self.mock_object(
            lustre_driver.processutils, 'ssh_execute',
            mock.Mock(
                side_effect=exception.ProcessExecutionError()))

        self.assertRaises(
            exception.ProcessExecutionError,
            self.driver._ssh_cmd,
            mock_pool, 'lctl_nodemap_add', 'test')

        mock_pool.put.assert_called_once_with(mock_ssh)

    def test_setup_ssh_executors_mgs_only(self):
        self.driver.configuration.lustre_mgs_ip = '10.0.0.2'
        mock_pool = self.mock_object(
            lustre_driver.ssh_utils, 'SSHPool')

        self.driver._setup_ssh_executors()

        self.assertEqual(mock_pool.call_count, 1)
        self.assertIsNotNone(self.driver._mgs_ssh)
        self.assertIsNone(self.driver._mds_ssh)

    def test_parse_lfs_df_no_osts(self):
        lfs_df_output = (
            "UUID                   1K-blocks        Used   Available "
            "Use% Mounted on\n"
            "testfs-MDT0000_UUID     1048576      204800      843776 "
            " 20% /mnt/lustre[MDT:0]\n"
        )
        self.mock_object(
            lustre_driver.privsep_lustre, 'lfs_df',
            mock.Mock(return_value=(lfs_df_output, '')))

        total_kb, free_kb = self.driver._parse_lfs_df()

        self.assertEqual(total_kb, 0)
        self.assertEqual(free_kb, 0)

    def test_ip_to_nid_range_single_host_cidr(self):
        result = lustre_driver.LustreShareDriver._ip_to_nid_range(
            '10.0.0.5/32', 'tcp')
        self.assertEqual(result, '10.0.0.5@tcp:10.0.0.5@tcp')

    def test_get_used_project_ids_non_integer(self):
        lfs_output = (
            "10000 P /mnt/lustre/manila_shares/share-1\n"
            "badval P /mnt/lustre/manila_shares/share-2\n"
            "10002 P /mnt/lustre/manila_shares/share-3\n"
        )
        self.mock_object(
            lustre_driver.privsep_lustre, 'lfs_project',
            mock.Mock(return_value=(lfs_output, '')))

        result = self.driver._get_used_project_ids()

        self.assertEqual(result, {10000, 10002})

    def test_get_project_usage_kb_unparseable(self):
        self.mock_object(
            self.driver, '_exec_mds',
            mock.Mock(return_value=('no matching lines\n', '')))

        self.assertRaises(
            exception.ShareBackendException,
            self.driver._get_project_usage_kb, '10001')

    def test_get_project_limit_kb_unparseable(self):
        self.mock_object(
            self.driver, '_exec_mds',
            mock.Mock(return_value=('no matching lines\n', '')))

        self.assertRaises(
            exception.ShareBackendException,
            self.driver._get_project_limit_kb, '10001')

    def test_delete_share_nodemap_del_fails(self):
        self.private_storage.update(FAKE_SHARE_ID, {
            'project_id': '10001',
        })
        self.mock_object(os.path, 'isdir', mock.Mock(return_value=True))
        self.mock_object(self.driver, '_exec_mds')
        self.mock_object(
            self.driver, '_exec_mgs',
            mock.Mock(side_effect=exception.ProcessExecutionError()))
        self.mock_object(
            lustre_driver.privsep_os, 'recursive_forced_rm')

        self.driver.delete_share(self._context, self._share)

        self.assertIsNone(
            self.private_storage.get(FAKE_SHARE_ID, 'project_id'))

    def test_export_to_local_path_no_colon_slash(self):
        self.assertRaises(
            exception.ManageInvalidShare,
            self.driver._export_to_local_path, 'bare-path')

    def test_add_access_rule_nodemap_add_real_error(self):
        rule = {
            'id': 'mapping-1',
            'access_id': 'rule-1',
            'access_type': 'ip',
            'access_to': '10.0.0.1',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        self.mock_object(
            self.driver, '_exec_mgs',
            mock.Mock(side_effect=exception.ProcessExecutionError(
                stderr='some other error')))

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[rule],
            delete_rules=[], update_rules=[])

        self.assertEqual(
            result['rule-1']['state'], constants.ACCESS_STATE_ERROR)

    def test_add_access_rule_nodemap_range_real_error(self):
        rule = {
            'id': 'mapping-1',
            'access_id': 'rule-1',
            'access_type': 'ip',
            'access_to': '10.0.0.1',
            'access_level': constants.ACCESS_LEVEL_RW,
        }

        def side_effect(cmd, *args):
            if cmd == 'lctl_nodemap_add_range':
                raise exception.ProcessExecutionError(
                    stderr='permission denied')

        self.mock_object(
            self.driver, '_exec_mgs',
            mock.Mock(side_effect=side_effect))

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[rule],
            delete_rules=[], update_rules=[])

        self.assertEqual(
            result['rule-1']['state'], constants.ACCESS_STATE_ERROR)

    def test_add_access_rule_nodemap_range_exists(self):
        rule = {
            'id': 'mapping-1',
            'access_id': 'rule-1',
            'access_type': 'ip',
            'access_to': '10.0.0.1',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        call_count = [0]

        def side_effect(cmd, *args):
            call_count[0] += 1
            if cmd == 'lctl_nodemap_add_range':
                raise exception.ProcessExecutionError(
                    stderr='File exists')

        self.mock_object(
            self.driver, '_exec_mgs',
            mock.Mock(side_effect=side_effect))
        self.mock_object(lustre_driver.privsep_os, 'chmod')

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[rule],
            delete_rules=[], update_rules=[])

        self.assertEqual(
            result['rule-1']['state'], constants.ACCESS_STATE_ACTIVE)

    def test_remove_access_rule_del_range_fails(self):
        rule = {
            'id': 'mapping-1',
            'access_id': 'rule-1',
            'access_type': 'ip',
            'access_to': '10.0.0.1',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        self.mock_object(
            self.driver, '_exec_mgs',
            mock.Mock(side_effect=exception.ProcessExecutionError()))

        self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[],
            delete_rules=[rule], update_rules=[])

    def test_reconcile_access_nodemap_del_fails(self):
        rules = [
            {
                'id': 'mapping-a',
                'access_id': 'rule-a',
                'access_type': 'ip',
                'access_to': '10.0.0.1',
                'access_level': constants.ACCESS_LEVEL_RW,
            },
        ]

        call_count = [0]

        def side_effect(cmd, *args):
            call_count[0] += 1
            if cmd == 'lctl_nodemap_del' and call_count[0] == 1:
                raise exception.ProcessExecutionError()

        self.mock_object(
            self.driver, '_exec_mgs',
            mock.Mock(side_effect=side_effect))
        self.mock_object(lustre_driver.privsep_os, 'chmod')

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=rules, add_rules=[],
            delete_rules=[], update_rules=[])

        self.assertEqual(
            result['rule-a']['state'], constants.ACCESS_STATE_ACTIVE)

    def test_add_access_rule_single_ip_no_slash(self):
        rule = {
            'id': 'mapping-1',
            'access_id': 'rule-1',
            'access_type': 'ip',
            'access_to': '192.168.1.1',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        mock_exec_mgs = self.mock_object(self.driver, '_exec_mgs')
        self.mock_object(lustre_driver.privsep_os, 'chmod')

        result = self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[rule],
            delete_rules=[], update_rules=[])

        mock_exec_mgs.assert_any_call(
            'lctl_nodemap_add_range', FAKE_NODEMAP_RW,
            '192.168.1.1@tcp:192.168.1.1@tcp')
        self.assertEqual(
            result['rule-1']['state'], constants.ACCESS_STATE_ACTIVE)

    def test_remove_access_rule_single_ip_no_slash(self):
        rule = {
            'id': 'mapping-1',
            'access_id': 'rule-1',
            'access_type': 'ip',
            'access_to': '192.168.1.1',
            'access_level': constants.ACCESS_LEVEL_RW,
        }
        mock_exec_mgs = self.mock_object(self.driver, '_exec_mgs')

        self.driver.update_access(
            self._context, self._share,
            access_rules=[], add_rules=[],
            delete_rules=[rule], update_rules=[])

        mock_exec_mgs.assert_called_once_with(
            'lctl_nodemap_del_range', FAKE_NODEMAP_RW,
            '192.168.1.1@tcp:192.168.1.1@tcp')
