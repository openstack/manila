# Copyright (c) 2016 Red Hat, Inc.
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

import json
from unittest import mock

import ddt
from oslo_utils import units

from manila.common import constants
from manila import context
import manila.exception as exception
from manila.share import configuration
from manila.share.drivers.cephfs import driver
from manila.share import share_types
from manila import test
from manila.tests import fake_share


DEFAULT_VOLUME_MODE = '755'
ALT_VOLUME_MODE = '644'


class MockRadosModule(object):
    """Mocked up version of the rados module."""

    class Rados(mock.Mock):
        def __init__(self, *args, **kwargs):
            mock.Mock.__init__(self, spec=[
                "connect", "shutdown", "state"
            ])
            self.get_mon_addrs = mock.Mock(return_value=["1.2.3.4", "5.6.7.8"])
            self.get_cluster_stats = mock.Mock(return_value={
                "kb": 172953600,
                "kb_avail": 157123584,
                "kb_used": 15830016,
                "num_objects": 26,
            })

    class Error(mock.Mock):
        pass


class MockCephArgparseModule(object):
    """Mocked up version of the ceph_argparse module."""

    class json_command(mock.Mock):
        def __init__(self, *args, **kwargs):
            mock.Mock.__init__(self, spec=[
                "connect", "shutdown", "state"
            ])


@ddt.ddt
class CephFSDriverTestCase(test.TestCase):
    """Test the CephFS driver.

    This is a very simple driver that mainly
    calls through to the CephFSVolumeClient interface, so the tests validate
    that the Manila driver calls map to the appropriate CephFSVolumeClient
    calls.
    """

    def setUp(self):
        super(CephFSDriverTestCase, self).setUp()
        self._execute = mock.Mock()
        self.fake_conf = configuration.Configuration(None)
        self._context = context.get_admin_context()
        self._share = fake_share.fake_share(share_proto='CEPHFS')
        self._snapshot = fake_share.fake_snapshot_instance()

        self.fake_conf.set_default('driver_handles_share_servers', False)
        self.fake_conf.set_default('cephfs_auth_id', 'manila')

        self.mock_object(driver, "rados_command")
        self.mock_object(driver, "rados", MockRadosModule)
        self.mock_object(driver, "json_command", MockCephArgparseModule)
        self.mock_object(driver, 'NativeProtocolHelper')
        self.mock_object(driver, 'NFSProtocolHelper')
        self.mock_object(driver, 'NFSClusterProtocolHelper')

        driver.ceph_default_target = ('mon-mgr', )

        self._driver = (
            driver.CephFSDriver(execute=self._execute,
                                configuration=self.fake_conf))
        self._driver.protocol_helper = mock.Mock()

        type(self._driver).volname = mock.PropertyMock(return_value='cephfs')

        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value={}))

    @ddt.data(
        ('cephfs', None),
        ('nfs', None),
        ('nfs', 'fs-manila')
    )
    @ddt.unpack
    def test_do_setup(self, protocol_helper, cephfs_nfs_cluster_id):
        self._driver.configuration.cephfs_protocol_helper_type = (
            protocol_helper)
        self.fake_conf.set_default('cephfs_nfs_cluster_id',
                                   cephfs_nfs_cluster_id)

        self._driver.do_setup(self._context)

        if protocol_helper == 'cephfs':
            driver.NativeProtocolHelper.assert_called_once_with(
                self._execute, self._driver.configuration,
                rados_client=self._driver._rados_client,
                volname=self._driver.volname)
        else:
            if self.fake_conf.cephfs_nfs_cluster_id is None:
                driver.NFSProtocolHelper.assert_called_once_with(
                    self._execute, self._driver.configuration,
                    rados_client=self._driver._rados_client,
                    volname=self._driver.volname)
            else:
                driver.NFSClusterProtocolHelper.assert_called_once_with(
                    self._execute, self._driver.configuration,
                    rados_client=self._driver._rados_client,
                    volname=self._driver.volname)

        self._driver.protocol_helper.init_helper.assert_called_once_with()

        self.assertEqual(DEFAULT_VOLUME_MODE, self._driver._cephfs_volume_mode)

    @ddt.data(
        ('{"version": "ceph version 16.2.4"}', 'pacific'),
        ('{"version": "ceph version 15.1.2"}', 'octopus'),
        ('{"version": "ceph version 14.3.1"}', 'nautilus'),
    )
    @ddt.unpack
    def test_version_check(self, ceph_mon_version, codename):
        driver.ceph_default_target = None
        driver.rados_command.return_value = ceph_mon_version

        self._driver.do_setup(self._context)

        if codename == 'nautilus':
            self.assertEqual(('mgr', ), driver.ceph_default_target)
        else:
            self.assertEqual(('mon-mgr', ), driver.ceph_default_target)

        driver.rados_command.assert_called_once_with(
            self._driver.rados_client, "version", target=('mon', ))

        self.assertEqual(1, driver.rados_command.call_count)

    def test_version_check_not_supported(self):
        driver.ceph_default_target = None
        driver.rados_command.return_value = (
            '{"version": "ceph version 13.0.1"}')

        self.assertRaises(exception.ShareBackendException,
                          self._driver.do_setup,
                          self._context)

    @ddt.data('cephfs', 'nfs')
    def test_check_for_setup_error(self, protocol_helper):
        self._driver.configuration.cephfs_protocol_helper_type = (
            protocol_helper)

        self._driver.check_for_setup_error()

        (self._driver.protocol_helper.check_for_setup_error.
            assert_called_once_with())

    def test_create_share(self):
        create_share_prefix = "fs subvolume create"
        get_path_prefix = "fs subvolume getpath"

        create_share_dict = {
            "vol_name": self._driver.volname,
            "sub_name": self._share["id"],
            "size": self._share["size"] * units.Gi,
            "namespace_isolated": True,
            "mode": DEFAULT_VOLUME_MODE,
        }

        get_path_dict = {
            "vol_name": self._driver.volname,
            "sub_name": self._share["id"],
        }

        self._driver.create_share(self._context, self._share)

        driver.rados_command.assert_has_calls([
            mock.call(self._driver.rados_client,
                      create_share_prefix,
                      create_share_dict),
            mock.call(self._driver.rados_client,
                      get_path_prefix,
                      get_path_dict)])

        self.assertEqual(2, driver.rados_command.call_count)

    def test_create_share_error(self):
        share = fake_share.fake_share(share_proto='NFS')

        self.assertRaises(exception.ShareBackendException,
                          self._driver.create_share,
                          self._context,
                          share)

    def test_update_access(self):
        alice = {
            'id': 'instance_mapping_id1',
            'access_id': 'accessid1',
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'alice'
        }
        add_rules = access_rules = [alice, ]
        delete_rules = []

        self._driver.update_access(
            self._context, self._share, access_rules, add_rules, delete_rules,
            None)

        self._driver.protocol_helper.update_access.assert_called_once_with(
            self._context, self._share, access_rules, add_rules, delete_rules,
            share_server=None)

    def test_ensure_shares(self):
        self._driver.protocol_helper.reapply_rules_while_ensuring_shares = True
        shares = [
            fake_share.fake_share(share_id='123', share_proto='NFS'),
            fake_share.fake_share(share_id='456', share_proto='NFS'),
            fake_share.fake_share(share_id='789', share_proto='NFS')
        ]
        export_locations = [
            {
                'path': '1.2.3.4,5.6.7.8:/foo/bar',
                'is_admin_only': False,
                'metadata': {},
            },
            {
                'path': '1.2.3.4,5.6.7.8:/foo/quz',
                'is_admin_only': False,
                'metadata': {},
            },

        ]
        expected_updates = {
            shares[0]['id']: {
                'status': constants.STATUS_ERROR,
                'reapply_access_rules': True,
            },
            shares[1]['id']: {
                'export_locations': export_locations[0],
                'reapply_access_rules': True,
            },
            shares[2]['id']: {
                'export_locations': export_locations[1],
                'reapply_access_rules': True,
            }
        }
        err_message = (f"Error ENOENT: subvolume {self._share['id']} does "
                       f"not exist")
        expected_exception = exception.ShareBackendException(err_message)
        self.mock_object(
            self._driver, '_get_export_locations',
            mock.Mock(side_effect=[expected_exception] + export_locations))

        actual_updates = self._driver.ensure_shares(self._context, shares)

        self.assertEqual(3, self._driver._get_export_locations.call_count)
        self._driver._get_export_locations.assert_has_calls([
            mock.call(shares[0]), mock.call(shares[1]), mock.call(shares[2])])
        self.assertEqual(expected_updates, actual_updates)

    def test_delete_share(self):
        clone_status_prefix = "fs clone status"

        clone_status_dict = {
            "vol_name": self._driver.volname,
            "clone_name": self._share["id"],
        }

        delete_share_prefix = "fs subvolume rm"

        delete_share_dict = {
            "vol_name": self._driver.volname,
            "sub_name": self._share["id"],
            "force": True,
        }

        driver.rados_command.side_effect = [driver.rados.Error, mock.Mock()]

        self._driver.delete_share(self._context, self._share)

        driver.rados_command.assert_has_calls([
            mock.call(self._driver.rados_client,
                      clone_status_prefix,
                      clone_status_dict),
            mock.call(self._driver.rados_client,
                      delete_share_prefix,
                      delete_share_dict)])

        self.assertEqual(2, driver.rados_command.call_count)

    def test_extend_share(self):
        extend_share_prefix = "fs subvolume resize"

        new_size_gb = self._share['size'] * 2
        new_size = new_size_gb * units.Gi

        extend_share_dict = {
            "vol_name": self._driver.volname,
            "sub_name": self._share["id"],
            "new_size": new_size,
        }

        self._driver.extend_share(self._share, new_size_gb, None)

        driver.rados_command.assert_called_once_with(
            self._driver.rados_client, extend_share_prefix, extend_share_dict)

    def test_shrink_share(self):
        shrink_share_prefix = "fs subvolume resize"

        new_size_gb = self._share['size'] * 0.5
        new_size = new_size_gb * units.Gi

        shrink_share_dict = {
            "vol_name": self._driver.volname,
            "sub_name": self._share["id"],
            "new_size": new_size,
            "no_shrink": True,
        }

        self._driver.shrink_share(self._share, new_size_gb, None)

        driver.rados_command.assert_called_once_with(
            self._driver.rados_client, shrink_share_prefix, shrink_share_dict)

    def test_shrink_share_full(self):
        """That shrink fails when share is too full."""
        shrink_share_prefix = "fs subvolume resize"

        new_size_gb = self._share['size'] * 0.5
        new_size = new_size_gb * units.Gi

        msg = ("Can't resize the subvolume. "
               "The new size '{0}' would be lesser "
               "than the current used size '{1}'".format(
                   new_size, self._share['size']))
        driver.rados_command.side_effect = exception.ShareBackendException(msg)

        shrink_share_dict = {
            "vol_name": self._driver.volname,
            "sub_name": self._share["id"],
            "new_size": new_size,
            "no_shrink": True,
        }

        # Pretend to be full up
        self.assertRaises(exception.ShareShrinkingPossibleDataLoss,
                          self._driver.shrink_share,
                          self._share, new_size_gb, None)

        driver.rados_command.assert_called_once_with(
            self._driver.rados_client, shrink_share_prefix, shrink_share_dict)

    def test_create_snapshot(self):
        snapshot_create_prefix = "fs subvolume snapshot create"

        snapshot_create_dict = {
            "vol_name": self._driver.volname,
            "sub_name": self._snapshot["share_id"],
            "snap_name": "_".join([
                self._snapshot["snapshot_id"], self._snapshot["id"]]),
        }

        self._driver.create_snapshot(self._context, self._snapshot, None)

        driver.rados_command.assert_called_once_with(
            self._driver.rados_client,
            snapshot_create_prefix, snapshot_create_dict)

    def test_delete_snapshot(self):
        snapshot_remove_prefix = "fs subvolume snapshot rm"

        snapshot_remove_dict = {
            "vol_name": self._driver.volname,
            "sub_name": self._snapshot["share_id"],
            "snap_name": "_".join([
                self._snapshot["snapshot_id"], self._snapshot["id"]]),
            "force": True,
        }

        self._driver.delete_snapshot(self._context,
                                     self._snapshot,
                                     None)

        driver.rados_command.assert_called_once_with(
            self._driver.rados_client,
            snapshot_remove_prefix, snapshot_remove_dict)

    def test_create_share_group(self):
        group_create_prefix = "fs subvolumegroup create"

        group_create_dict = {
            "vol_name": self._driver.volname,
            "group_name": "grp1",
            "mode": DEFAULT_VOLUME_MODE,
        }

        self._driver.create_share_group(self._context, {"id": "grp1"}, None)

        driver.rados_command.assert_called_once_with(
            self._driver.rados_client,
            group_create_prefix, group_create_dict)

    def test_delete_share_group(self):
        group_delete_prefix = "fs subvolumegroup rm"

        group_delete_dict = {
            "vol_name": self._driver.volname,
            "group_name": "grp1",
            "force": True,
        }

        self._driver.delete_share_group(self._context, {"id": "grp1"}, None)

        driver.rados_command.assert_called_once_with(
            self._driver.rados_client,
            group_delete_prefix, group_delete_dict)

    def test_create_share_group_snapshot(self):
        msg = ("Share group snapshot feature is no longer supported in "
               "mainline CephFS (existing group snapshots can still be "
               "listed and deleted).")
        driver.rados_command.side_effect = exception.ShareBackendException(msg)

        self.assertRaises(exception.ShareBackendException,
                          self._driver.create_share_group_snapshot,
                          self._context, {'share_group_id': 'sgid',
                                          'id': 'snapid'})

    def test_delete_share_group_snapshot(self):
        group_snapshot_delete_prefix = "fs subvolumegroup snapshot rm"

        group_snapshot_delete_dict = {
            "vol_name": self._driver.volname,
            "group_name": "sgid",
            "snap_name": "snapid",
            "force": True,
        }

        self._driver.delete_share_group_snapshot(self._context, {
            'share_group_id': 'sgid',
            'id': 'snapid',
            "force": True,
        })

        driver.rados_command.assert_called_once_with(
            self._driver.rados_client,
            group_snapshot_delete_prefix, group_snapshot_delete_dict)

    def test_create_share_from_snapshot(self):
        parent_share = {
            'id': 'fakeparentshareid',
            'name': 'fakeparentshare',
        }

        create_share_from_snapshot_prefix = "fs subvolume snapshot clone"

        create_share_from_snapshot_dict = {
            "vol_name": self._driver.volname,
            "sub_name": parent_share["id"],
            "snap_name": "_".join([
                self._snapshot["snapshot_id"], self._snapshot["id"]]),
            "target_sub_name": self._share["id"]
        }

        get_clone_status_prefix = "fs clone status"
        get_clone_status_dict = {
            "vol_name": self._driver.volname,
            "clone_name": self._share["id"],
        }
        driver.rados_command.return_value = {
            'status': {
                'state': 'in-progress',
            },
        }

        self._driver.create_share_from_snapshot(
            self._context, self._share, self._snapshot, None,
            parent_share=parent_share
        )

        driver.rados_command.assert_has_calls([
            mock.call(self._driver.rados_client,
                      create_share_from_snapshot_prefix,
                      create_share_from_snapshot_dict),
            mock.call(self._driver.rados_client,
                      get_clone_status_prefix,
                      get_clone_status_dict,
                      True)])

        self.assertEqual(2, driver.rados_command.call_count)

    def test_delete_share_from_snapshot(self):
        clone_status_prefix = "fs clone status"

        clone_status_dict = {
            "vol_name": self._driver.volname,
            "clone_name": self._share["id"],
        }

        clone_cancel_prefix = "fs clone cancel"

        clone_cancel_dict = {
            "vol_name": self._driver.volname,
            "clone_name": self._share["id"],
            "force": True,
        }

        delete_share_prefix = "fs subvolume rm"

        delete_share_dict = {
            "vol_name": self._driver.volname,
            "sub_name": self._share["id"],
            "force": True,
        }

        driver.rados_command.side_effect = [
            'in-progress', mock.Mock(), mock.Mock()]

        self._driver.delete_share(self._context, self._share)

        driver.rados_command.assert_has_calls([
            mock.call(self._driver.rados_client,
                      clone_status_prefix,
                      clone_status_dict),
            mock.call(self._driver.rados_client,
                      clone_cancel_prefix,
                      clone_cancel_dict),
            mock.call(self._driver.rados_client,
                      delete_share_prefix,
                      delete_share_dict)])

        self.assertEqual(3, driver.rados_command.call_count)

    def test_delete_driver(self):
        # Create share to prompt volume_client construction
        self._driver.create_share(self._context,
                                  self._share)

        rc = self._driver._rados_client
        del self._driver

        rc.shutdown.assert_called_once_with()

    def test_delete_driver_no_client(self):
        self.assertIsNone(self._driver._rados_client)
        del self._driver

    def test_update_share_stats(self):
        self._driver.get_configured_ip_versions = mock.Mock(return_value=[4])
        self._driver.configuration.local_conf.set_override(
            'reserved_share_percentage', 5)
        self._driver.configuration.local_conf.set_override(
            'reserved_share_from_snapshot_percentage', 2)
        self._driver.configuration.local_conf.set_override(
            'reserved_share_extend_percentage', 2)

        self._driver._update_share_stats()
        result = self._driver._stats

        self.assertEqual(5, result['pools'][0]['reserved_percentage'])
        self.assertEqual(2, result['pools'][0]['reserved_snapshot_percentage'])
        self.assertEqual(
            2, result['pools'][0]['reserved_share_extend_percentage'])
        self.assertEqual(164.94, result['pools'][0]['total_capacity_gb'])
        self.assertEqual(149.84, result['pools'][0]['free_capacity_gb'])
        self.assertTrue(result['ipv4_support'])
        self.assertFalse(result['ipv6_support'])
        self.assertEqual("CEPHFS", result['storage_protocol'])

    @ddt.data('cephfs', 'nfs')
    def test_get_configured_ip_versions(self, protocol_helper):
        self._driver.configuration.cephfs_protocol_helper_type = (
            protocol_helper)

        self._driver.get_configured_ip_versions()

        (self._driver.protocol_helper.get_configured_ip_versions.
            assert_called_once_with())

    @ddt.data(
        ([{'id': 'instance_mapping_id1', 'access_id': 'accessid1',
           'access_level': 'rw', 'access_type': 'cephx', 'access_to': 'alice'
           }], 'fake_project_uuid_1'),
        ([{'id': 'instance_mapping_id1', 'access_id': 'accessid1',
           'access_level': 'rw', 'access_type': 'cephx', 'access_to': 'alice'
           }], 'fake_project_uuid_2'),
        ([], 'fake_project_uuid_1'),
        ([], 'fake_project_uuid_2'),
    )
    @ddt.unpack
    def test_transfer_accept(self, access_rules, new_project):
        fake_share_1 = {"project_id": "fake_project_uuid_1"}
        same_project = new_project == 'fake_project_uuid_1'
        if access_rules and not same_project:
            self.assertRaises(exception.DriverCannotTransferShareWithRules,
                              self._driver.transfer_accept,
                              self._context, fake_share_1,
                              'new_user', new_project, access_rules)


@ddt.ddt
class NativeProtocolHelperTestCase(test.TestCase):

    def setUp(self):
        super(NativeProtocolHelperTestCase, self).setUp()
        self.fake_conf = configuration.Configuration(None)
        self._context = context.get_admin_context()
        self._share = fake_share.fake_share_instance(share_proto='CEPHFS')

        self.fake_conf.set_default('driver_handles_share_servers', False)

        self.mock_object(driver, "rados_command")

        driver.ceph_default_target = ('mon-mgr', )

        self._native_protocol_helper = driver.NativeProtocolHelper(
            None,
            self.fake_conf,
            rados_client=MockRadosModule.Rados(),
            volname="cephfs"
        )

        self._rados_client = self._native_protocol_helper.rados_client

        self._native_protocol_helper.get_mon_addrs = mock.Mock(
            return_value=['1.2.3.4', '5.6.7.8'])

    def test_check_for_setup_error(self):
        expected = None

        result = self._native_protocol_helper.check_for_setup_error()

        self.assertEqual(expected, result)

    def test_get_export_locations(self):
        fake_cephfs_subvolume_path = '/foo/bar'
        expected_export_locations = {
            'path': '1.2.3.4,5.6.7.8:/foo/bar',
            'is_admin_only': False,
            'metadata': {},
        }

        export_locations = self._native_protocol_helper.get_export_locations(
            self._share, fake_cephfs_subvolume_path)

        self.assertEqual(expected_export_locations, export_locations)
        self._native_protocol_helper.get_mon_addrs.assert_called_once_with()

    @ddt.data(constants.ACCESS_LEVEL_RW, constants.ACCESS_LEVEL_RO)
    def test_allow_access_rw_ro(self, mode):
        access_allow_prefix = "fs subvolume authorize"
        access_allow_mode = "r" if mode == "ro" else "rw"

        access_allow_dict = {
            "vol_name": self._native_protocol_helper.volname,
            "sub_name": self._share["id"],
            "auth_id": "alice",
            "tenant_id": self._share["project_id"],
            "access_level": access_allow_mode,
        }

        rule = {
            'access_level': mode,
            'access_to': 'alice',
            'access_type': 'cephx',
        }

        driver.rados_command.return_value = 'native-zorilla'

        auth_key = self._native_protocol_helper._allow_access(
            self._context, self._share, rule)

        self.assertEqual("native-zorilla", auth_key)

        driver.rados_command.assert_called_once_with(
            self._rados_client,
            access_allow_prefix, access_allow_dict)

    def test_allow_access_wrong_type(self):
        self.assertRaises(exception.InvalidShareAccessType,
                          self._native_protocol_helper._allow_access,
                          self._context, self._share, {
                              'access_level': constants.ACCESS_LEVEL_RW,
                              'access_type': 'RHUBARB',
                              'access_to': 'alice'
                          })

    def test_allow_access_same_cephx_id_as_manila_service(self):
        self.assertRaises(exception.InvalidShareAccess,
                          self._native_protocol_helper._allow_access,
                          self._context, self._share, {
                              'access_level': constants.ACCESS_LEVEL_RW,
                              'access_type': 'cephx',
                              'access_to': 'manila',
                          })

    def test_allow_access_to_preexisting_ceph_user(self):
        msg = ("auth ID: admin exists and not created by "
               "ceph manager plugin. Not allowed to modify")
        driver.rados_command.side_effect = exception.ShareBackendException(msg)

        self.assertRaises(exception.InvalidShareAccess,
                          self._native_protocol_helper._allow_access,
                          self._context, self._share,
                          {
                              'access_level': constants.ACCESS_LEVEL_RW,
                              'access_type': 'cephx',
                              'access_to': 'admin'
                          })

    def test_deny_access(self):
        access_deny_prefix = "fs subvolume deauthorize"

        access_deny_dict = {
            "vol_name": self._native_protocol_helper.volname,
            "sub_name": self._share["id"],
            "auth_id": "alice",
        }

        evict_prefix = "fs subvolume evict"

        evict_dict = access_deny_dict

        self._native_protocol_helper._deny_access(self._context, self._share, {
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'alice'
        })

        driver.rados_command.assert_has_calls([
            mock.call(self._native_protocol_helper.rados_client,
                      access_deny_prefix,
                      access_deny_dict),
            mock.call(self._native_protocol_helper.rados_client,
                      evict_prefix,
                      evict_dict)])

        self.assertEqual(2, driver.rados_command.call_count)

    def test_deny_access_missing_access_rule(self):
        access_deny_prefix = "fs subvolume deauthorize"

        exception_msg = (
            f"json_command failed - prefix=fs subvolume deauthorize, "
            f"argdict='vol_name': {self._native_protocol_helper.volname}, "
            f"'sub_name': '{self._share['id']}', 'auth_id': 'alice', "
            f"'format': 'json' - exception message: [errno -2] "
            f"auth ID: alice doesn't exist.")

        driver.rados_command.side_effect = exception.ShareBackendException(
            msg=exception_msg)

        access_deny_dict = {
            "vol_name": self._native_protocol_helper.volname,
            "sub_name": self._share["id"],
            "auth_id": "alice",
        }

        self._native_protocol_helper._deny_access(self._context, self._share, {
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'alice'
        })

        driver.rados_command.assert_called_once_with(
            self._native_protocol_helper.rados_client,
            access_deny_prefix, access_deny_dict)

        self.assertEqual(1, driver.rados_command.call_count)

    def test_update_access_add_rm(self):
        alice = {
            'id': 'instance_mapping_id1',
            'access_id': 'accessid1',
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'alice'
        }
        bob = {
            'id': 'instance_mapping_id2',
            'access_id': 'accessid2',
            'access_level': 'ro',
            'access_type': 'cephx',
            'access_to': 'bob'
        }
        manila = {
            'id': 'instance_mapping_id3',
            'access_id': 'accessid3',
            'access_level': 'ro',
            'access_type': 'cephx',
            'access_to': 'manila'
        }
        admin = {
            'id': 'instance_mapping_id4',
            'access_id': 'accessid4',
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'admin'
        }
        dabo = {
            'id': 'instance_mapping_id5',
            'access_id': 'accessid5',
            'access_level': 'rwx',
            'access_type': 'cephx',
            'access_to': 'dabo'
        }

        allow_access_side_effects = [
            'abc123',
            exception.InvalidShareAccess(reason='not'),
            exception.InvalidShareAccess(reason='allowed'),
            exception.InvalidShareAccessLevel(level='rwx')
        ]
        self.mock_object(self._native_protocol_helper.message_api, 'create')
        self.mock_object(self._native_protocol_helper, '_deny_access')
        self.mock_object(self._native_protocol_helper,
                         '_allow_access',
                         mock.Mock(side_effect=allow_access_side_effects))

        access_updates = self._native_protocol_helper.update_access(
            self._context,
            self._share,
            access_rules=[alice, manila, admin, dabo],
            add_rules=[alice, manila, admin, dabo],
            delete_rules=[bob])

        expected_access_updates = {
            'accessid1': {'access_key': 'abc123'},
            'accessid3': {'state': 'error'},
            'accessid4': {'state': 'error'},
            'accessid5': {'state': 'error'}
        }
        self.assertEqual(expected_access_updates, access_updates)
        self._native_protocol_helper._allow_access.assert_has_calls(
            [mock.call(self._context, self._share, alice),
             mock.call(self._context, self._share, manila),
             mock.call(self._context, self._share, admin)])
        self._native_protocol_helper._deny_access.assert_called_once_with(
            self._context, self._share, bob)
        self.assertEqual(
            3, self._native_protocol_helper.message_api.create.call_count)

    def test_update_access_all(self):
        get_authorized_ids_prefix = "fs subvolume authorized_list"

        get_authorized_ids_dict = {
            "vol_name": self._native_protocol_helper.volname,
            "sub_name": self._share["id"]
        }

        access_allow_prefix = "fs subvolume authorize"

        access_allow_dict = {
            "vol_name": self._native_protocol_helper.volname,
            "sub_name": self._share["id"],
            "auth_id": "alice",
            "tenant_id": self._share["project_id"],
            "access_level": "rw",
        }

        access_deny_prefix = "fs subvolume deauthorize"

        access_deny_john_dict = {
            "vol_name": self._native_protocol_helper.volname,
            "sub_name": self._share["id"],
            "auth_id": "john",
        }

        access_deny_paul_dict = {
            "vol_name": self._native_protocol_helper.volname,
            "sub_name": self._share["id"],
            "auth_id": "paul",
        }

        evict_prefix = "fs subvolume evict"

        alice = {
            'id': 'instance_mapping_id1',
            'access_id': 'accessid1',
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'alice',
        }

        driver.rados_command.side_effect = [
            [{"john": "rw"}, {"paul": "r"}],
            'abc123',
            mock.Mock(), mock.Mock(),
            mock.Mock(), mock.Mock()]

        access_updates = self._native_protocol_helper.update_access(
            self._context, self._share, access_rules=[alice], add_rules=[],
            delete_rules=[])

        self.assertEqual(
            {'accessid1': {'access_key': 'abc123'}}, access_updates)

        driver.rados_command.assert_has_calls([
            mock.call(self._native_protocol_helper.rados_client,
                      get_authorized_ids_prefix,
                      get_authorized_ids_dict,
                      json_obj=True),
            mock.call(self._native_protocol_helper.rados_client,
                      access_allow_prefix,
                      access_allow_dict),
            mock.call(self._native_protocol_helper.rados_client,
                      access_deny_prefix,
                      access_deny_john_dict),
            mock.call(self._native_protocol_helper.rados_client,
                      evict_prefix,
                      access_deny_john_dict),
            mock.call(self._native_protocol_helper.rados_client,
                      access_deny_prefix,
                      access_deny_paul_dict),
            mock.call(self._native_protocol_helper.rados_client,
                      evict_prefix,
                      access_deny_paul_dict)], any_order=True)

        self.assertEqual(6, driver.rados_command.call_count)

    def test_get_configured_ip_versions(self):
        expected = [4]

        result = self._native_protocol_helper.get_configured_ip_versions()

        self.assertEqual(expected, result)


@ddt.ddt
class NFSProtocolHelperTestCase(test.TestCase):

    def setUp(self):
        super(NFSProtocolHelperTestCase, self).setUp()
        self._execute = mock.Mock()
        self._share = fake_share.fake_share(share_proto='NFS')
        self._rados_client = MockRadosModule.Rados()
        self._volname = "cephfs"
        self.fake_conf = configuration.Configuration(None)

        self.fake_conf.set_default('cephfs_ganesha_server_ip',
                                   'fakeip')
        self.mock_object(driver.ganesha_utils, 'SSHExecutor')
        self.mock_object(driver.ganesha_utils, 'RootExecutor')
        self.mock_object(driver.socket, 'gethostname')
        self.mock_object(driver, "rados_command")

        driver.ceph_default_target = ('mon-mgr', )

        self._nfs_helper = driver.NFSProtocolHelper(
            self._execute,
            self.fake_conf,
            rados_client=self._rados_client,
            volname=self._volname)

    @ddt.data(
        (['fakehost', 'some.host.name', 'some.host.name.', '1.1.1.0'], False),
        (['fakehost', 'some.host.name', 'some.host.name.', '1.1..1.0'], True),
        (['fakehost', 'some.host.name', 'some.host.name', '1.1.1.256'], True),
        (['fakehost..', 'some.host.name', 'some.host.name', '1.1.1.0'], True),
        (['fakehost', 'some.host.name..', 'some.host.name', '1.1.1.0'], True),
        (['fakehost', 'some.host.name', 'some.host.name.', '1.1..1.0'], True),
        (['fakehost', 'some.host.name', '1.1.1.0/24'], True),
        (['fakehost', 'some.host.name', '1.1.1.0', '1001::1001'], False),
        (['fakehost', 'some.host.name', '1.1.1.0', '1001:1001'], True),
        (['fakehost', 'some.host.name', '1.1.1.0', '1001::1001:'], True),
        (['fakehost', 'some.host.name', '1.1.1.0', '1001::1001.'], True),
        (['fakehost', 'some.host.name', '1.1.1.0', '1001::1001/129.'], True),
    )
    @ddt.unpack
    def test_check_for_setup_error(self, cephfs_ganesha_export_ips, raises):
        fake_conf = configuration.Configuration(None)
        fake_conf.set_default('cephfs_ganesha_export_ips',
                              cephfs_ganesha_export_ips)

        helper = driver.NFSProtocolHelper(
            self._execute,
            fake_conf,
            rados_client=MockRadosModule.Rados(),
            volname="cephfs"
        )

        if raises:
            self.assertRaises(exception.InvalidParameterValue,
                              helper.check_for_setup_error)
        else:
            self.assertIsNone(helper.check_for_setup_error())

    @ddt.data(False, True)
    def test_init_executor_type(self, ganesha_server_is_remote):
        fake_conf = configuration.Configuration(None)
        conf_args_list = [
            ('cephfs_ganesha_server_is_remote', ganesha_server_is_remote),
            ('cephfs_ganesha_server_ip', 'fakeip'),
            ('cephfs_ganesha_server_username', 'fake_username'),
            ('cephfs_ganesha_server_password', 'fakepwd'),
            ('cephfs_ganesha_path_to_private_key', 'fakepathtokey')]
        for args in conf_args_list:
            fake_conf.set_default(*args)

        driver.NFSProtocolHelper(
            self._execute,
            fake_conf,
            rados_client=MockRadosModule.Rados(),
            volname="cephfs"
        )

        if ganesha_server_is_remote:
            driver.ganesha_utils.SSHExecutor.assert_has_calls(
                [mock.call('fakeip', 22, None, 'fake_username',
                           password='fakepwd',
                           privatekey='fakepathtokey')])
        else:
            driver.ganesha_utils.RootExecutor.assert_has_calls(
                [mock.call(self._execute)])

    @ddt.data('fakeip', None)
    def test_init_identify_local_host(self, ganesha_server_ip):
        self.mock_object(driver.LOG, 'info')
        fake_conf = configuration.Configuration(None)
        conf_args_list = [
            ('cephfs_ganesha_server_ip', ganesha_server_ip),
            ('cephfs_ganesha_server_username', 'fake_username'),
            ('cephfs_ganesha_server_password', 'fakepwd'),
            ('cephfs_ganesha_path_to_private_key', 'fakepathtokey')]
        for args in conf_args_list:
            fake_conf.set_default(*args)

        driver.NFSProtocolHelper(
            self._execute,
            fake_conf,
            rados_client=MockRadosModule.Rados(),
            volname="cephfs"
        )

        driver.ganesha_utils.RootExecutor.assert_has_calls(
            [mock.call(self._execute)])
        if ganesha_server_ip:
            self.assertFalse(driver.socket.gethostname.called)
            self.assertFalse(driver.LOG.info.called)
        else:
            driver.socket.gethostname.assert_called_once_with()
            driver.LOG.info.assert_called_once()

    def test_get_export_locations_no_export_ips_configured(self):
        cephfs_subvolume_path = "/foo/bar"
        fake_conf = configuration.Configuration(None)
        fake_conf.set_default('cephfs_ganesha_server_ip', '1.2.3.4')

        helper = driver.NFSProtocolHelper(
            self._execute,
            fake_conf,
            rados_client=MockRadosModule.Rados(),
            volname="cephfs"
        )

        ret = helper.get_export_locations(self._share,
                                          cephfs_subvolume_path)
        self.assertEqual(
            [{
                'path': '1.2.3.4:/foo/bar',
                'is_admin_only': False,
                'metadata': {},
                'preferred': False
            }], ret)

    def test_get_export_locations_with_export_ips_configured(self):
        fake_conf = configuration.Configuration(None)
        conf_args_list = [
            ('cephfs_ganesha_server_ip', '1.2.3.4'),
            ('cephfs_ganesha_export_ips',
             ['127.0.0.1', 'fd3f:c057:1192:1::1', '::1'])]
        for args in conf_args_list:
            fake_conf.set_default(*args)

        helper = driver.NFSProtocolHelper(
            self._execute,
            fake_conf,
            rados_client=MockRadosModule.Rados(),
            volname="cephfs"
        )

        cephfs_subvolume_path = "/foo/bar"

        ret = helper.get_export_locations(self._share, cephfs_subvolume_path)

        self.assertEqual(
            [
                {
                    'path': '127.0.0.1:/foo/bar',
                    'is_admin_only': False,
                    'metadata': {},
                    'preferred': False
                },
                {
                    'path': '[fd3f:c057:1192:1::1]:/foo/bar',
                    'is_admin_only': False,
                    'metadata': {},
                    'preferred': False
                },
                {
                    'path': '[::1]:/foo/bar',
                    'is_admin_only': False,
                    'metadata': {},
                    'preferred': False
                },
            ], ret)

    @ddt.data(('some.host.name', None, [4, 6]), ('host.', None, [4, 6]),
              ('1001::1001', None, [6]), ('1.1.1.0', None, [4]),
              (None, ['1001::1001', '1.1.1.0'], [6, 4]),
              (None, ['1001::1001'], [6]), (None, ['1.1.1.0'], [4]),
              (None, ['1001::1001/129', '1.1.1.0'], [4, 6]))
    @ddt.unpack
    def test_get_configured_ip_versions(
            self, cephfs_ganesha_server_ip, cephfs_ganesha_export_ips,
            configured_ip_version):
        fake_conf = configuration.Configuration(None)
        conf_args_list = [
            ('cephfs_ganesha_server_ip', cephfs_ganesha_server_ip),
            ('cephfs_ganesha_export_ips', cephfs_ganesha_export_ips)]

        for args in conf_args_list:
            fake_conf.set_default(*args)

        helper = driver.NFSProtocolHelper(
            self._execute,
            fake_conf,
            rados_client=MockRadosModule.Rados(),
            volname="cephfs"
        )

        self.assertEqual(set(configured_ip_version),
                         set(helper.get_configured_ip_versions()))
        self.assertEqual(set(configured_ip_version),
                         helper.configured_ip_versions)

    def test_get_configured_ip_versions_already_set(self):
        fake_conf = configuration.Configuration(None)
        helper = driver.NFSProtocolHelper(
            self._execute,
            fake_conf,
            rados_client=MockRadosModule.Rados(),
            volname="cephfs"
        )

        ip_versions = ['foo', 'bar']

        helper.configured_ip_versions = ip_versions

        result = helper.get_configured_ip_versions()

        self.assertEqual(ip_versions, result)

    def test_default_config_hook(self):
        fake_conf_dict = {'key': 'value1'}
        self.mock_object(driver.ganesha.GaneshaNASHelper,
                         '_default_config_hook',
                         mock.Mock(return_value={}))
        self.mock_object(driver.ganesha_utils, 'path_from',
                         mock.Mock(return_value='/fakedir/cephfs/conf'))
        self.mock_object(self._nfs_helper, '_load_conf_dir',
                         mock.Mock(return_value=fake_conf_dict))

        ret = self._nfs_helper._default_config_hook()

        (driver.ganesha.GaneshaNASHelper._default_config_hook.
            assert_called_once_with())
        driver.ganesha_utils.path_from.assert_called_once_with(
            driver.__file__, 'conf')
        self._nfs_helper._load_conf_dir.assert_called_once_with(
            '/fakedir/cephfs/conf')
        self.assertEqual(fake_conf_dict, ret)

    def test_fsal_hook(self):
        access_allow_prefix = "fs subvolume authorize"

        access_allow_dict = {
            "vol_name": self._nfs_helper.volname,
            "sub_name": self._share["id"],
            "auth_id": "ganesha-fakeid",
            "tenant_id": self._share["project_id"],
            "access_level": "rw",
        }

        expected_ret = {
            "Name": "Ceph",
            "User_Id": "ganesha-fakeid",
            "Secret_Access_Key": "ganesha-zorilla",
            "Filesystem": self._nfs_helper.volname
        }

        driver.rados_command.return_value = 'ganesha-zorilla'

        ret = self._nfs_helper._fsal_hook(None, self._share, None)

        driver.rados_command.assert_called_once_with(
            self._nfs_helper.rados_client,
            access_allow_prefix, access_allow_dict)

        self.assertEqual(expected_ret, ret)

    def test_cleanup_fsal_hook(self):
        access_deny_prefix = "fs subvolume deauthorize"

        access_deny_dict = {
            "vol_name": self._nfs_helper.volname,
            "sub_name": self._share["id"],
            "auth_id": "ganesha-fakeid",
        }

        ret = self._nfs_helper._cleanup_fsal_hook(None, self._share, None)

        driver.rados_command.assert_called_once_with(
            self._nfs_helper.rados_client,
            access_deny_prefix, access_deny_dict)

        self.assertIsNone(ret)

    def test_get_export_path(self):
        get_path_prefix = "fs subvolume getpath"

        get_path_dict = {
            "vol_name": self._nfs_helper.volname,
            "sub_name": self._share["id"],
        }

        driver.rados_command.return_value = '/foo/bar'

        ret = self._nfs_helper._get_export_path(self._share)

        driver.rados_command.assert_called_once_with(
            self._nfs_helper.rados_client,
            get_path_prefix, get_path_dict)

        self.assertEqual('/foo/bar', ret)

    def test_get_export_pseudo_path(self):
        get_path_prefix = "fs subvolume getpath"

        get_path_dict = {
            "vol_name": self._nfs_helper.volname,
            "sub_name": self._share["id"],
        }

        driver.rados_command.return_value = '/foo/bar'

        ret = self._nfs_helper._get_export_pseudo_path(self._share)

        driver.rados_command.assert_called_once_with(
            self._nfs_helper.rados_client,
            get_path_prefix, get_path_dict)

        self.assertEqual('/foo/bar', ret)


@ddt.ddt
class NFSClusterProtocolHelperTestCase(test.TestCase):

    def setUp(self):
        super(NFSClusterProtocolHelperTestCase, self).setUp()
        self._execute = mock.Mock()
        self._context = context.get_admin_context()
        self._share = fake_share.fake_share(share_proto='NFS')
        self._rados_client = MockRadosModule.Rados()
        self._volname = "cephfs"
        self.fake_conf = configuration.Configuration(None)

        self.mock_object(driver.NFSClusterProtocolHelper,
                         '_get_export_path',
                         mock.Mock(return_value="ganesha:/foo/bar"))
        self.mock_object(driver.NFSClusterProtocolHelper,
                         '_get_export_pseudo_path',
                         mock.Mock(return_value="ganesha:/foo/bar"))
        self.mock_object(driver, "rados_command")

        driver.ceph_default_target = ('mon-mgr', )

        self._nfscluster_protocol_helper = driver.NFSClusterProtocolHelper(
            self._execute,
            self.fake_conf,
            rados_client=self._rados_client,
            volname=self._volname)

        type(self._nfscluster_protocol_helper).nfs_clusterid = (
            mock.PropertyMock(return_value='fs-manila'))

    def test_get_export_ips_no_backends(self):
        fake_conf = configuration.Configuration(None)
        cluster_info = {
            "fs-manila": {
                "virtual_ip": None,
                "backend": []
            }
        }

        driver.rados_command.return_value = json.dumps(cluster_info)

        helper = driver.NFSClusterProtocolHelper(
            self._execute,
            fake_conf,
            rados_client=self._rados_client,
            volname=self._volname
        )

        self.assertRaises(exception.ShareBackendException,
                          helper._get_export_ips)

    @ddt.data(constants.ACCESS_LEVEL_RW, constants.ACCESS_LEVEL_RO)
    def test_allow_access_rw_ro(self, mode):
        access_allow_prefix = "nfs export apply"
        nfs_clusterid = self._nfscluster_protocol_helper.nfs_clusterid
        volname = self._nfscluster_protocol_helper.volname

        clients = {
            'access_type': mode,
            'addresses': ['10.0.0.1'],
            'squash': 'none'
        }

        access_allow_dict = {
            "cluster_id": nfs_clusterid,
        }

        export = {
            "path": "ganesha:/foo/bar",
            "cluster_id": nfs_clusterid,
            "pseudo": "ganesha:/foo/bar",
            "squash": "none",
            "security_label": True,
            "protocols": [4],
            "fsal": {
                "name": "CEPH",
                "fs_name": volname,

            },
            "clients": clients
        }

        inbuf = json.dumps(export).encode('utf-8')

        self._nfscluster_protocol_helper._allow_access(self._share, clients)

        driver.rados_command.assert_called_once_with(
            self._rados_client,
            access_allow_prefix, access_allow_dict, inbuf=inbuf)

    def test_deny_access(self):
        access_deny_prefix = "nfs export rm"

        nfs_clusterid = self._nfscluster_protocol_helper.nfs_clusterid

        access_deny_dict = {
            "cluster_id": nfs_clusterid,
            "pseudo_path": "ganesha:/foo/bar"
        }

        self._nfscluster_protocol_helper._deny_access(self._share)

        driver.rados_command.assert_called_once_with(
            self._rados_client,
            access_deny_prefix, access_deny_dict)

    def test_get_export_locations(self):
        cluster_info_prefix = "nfs cluster info"
        nfs_clusterid = self._nfscluster_protocol_helper.nfs_clusterid

        cluster_info_dict = {
            "cluster_id": nfs_clusterid,
        }

        cluster_info = {"fs-manila": {
                        "virtual_ip": None,
                        "backend": [
                            {"hostname": "fake-ceph-node-1",
                             "ip": "10.0.0.10",
                             "port": "1010"},
                            {"hostname": "fake-ceph-node-2",
                             "ip": "10.0.0.11",
                             "port": "1011"}
                            ]
                        }}

        driver.rados_command.return_value = json.dumps(cluster_info)

        fake_cephfs_subvolume_path = "/foo/bar"
        expected_export_locations = [{
            'path': '10.0.0.10:/foo/bar',
            'is_admin_only': False,
            'metadata': {},
            'preferred': True
        }, {
            'path': '10.0.0.11:/foo/bar',
            'is_admin_only': False,
            'metadata': {},
            'preferred': True
        }]

        export_locations = (
            self._nfscluster_protocol_helper.get_export_locations(
                self._share, fake_cephfs_subvolume_path))

        driver.rados_command.assert_called_once_with(
            self._rados_client,
            cluster_info_prefix, cluster_info_dict)

        self.assertEqual(expected_export_locations, export_locations)

    @ddt.data(
        ('cephfs_ganesha_server_ip', '10.0.0.1'),
        ('cephfs_ganesha_export_ips', ['10.0.0.2, 10.0.0.3'])
    )
    @ddt.unpack
    def test_get_export_locations_ganesha_still_configured(self, opt, val):
        cluster_info_prefix = "nfs cluster info"
        nfs_clusterid = self._nfscluster_protocol_helper.nfs_clusterid
        self.fake_conf.set_default(opt, val)

        cluster_info_dict = {
            "cluster_id": nfs_clusterid,
        }

        cluster_info = {"fs-manila": {
            "virtual_ip": None,
            "backend": [
                {"hostname": "fake-ceph-node-1",
                 "ip": "10.0.0.10",
                 "port": "1010"},
                {"hostname": "fake-ceph-node-2",
                 "ip": "10.0.0.11",
                 "port": "1011"}
            ]
        }}

        driver.rados_command.return_value = json.dumps(cluster_info)

        fake_cephfs_subvolume_path = "/foo/bar"
        expected_export_locations = [{
            'path': '10.0.0.10:/foo/bar',
            'is_admin_only': False,
            'metadata': {},
            'preferred': True
        }, {
            'path': '10.0.0.11:/foo/bar',
            'is_admin_only': False,
            'metadata': {},
            'preferred': True
        }]
        if isinstance(val, list):
            for ip in val:
                expected_export_locations.append(
                    {
                        'path': f'{ip}:/foo/bar',
                        'is_admin_only': False,
                        'metadata': {},
                        'preferred': False
                    }
                )
        else:
            expected_export_locations.append(
                {
                    'path': f'{val}:/foo/bar',
                    'is_admin_only': False,
                    'metadata': {},
                    'preferred': False
                }
            )

        export_locations = (
            self._nfscluster_protocol_helper.get_export_locations(
                self._share, fake_cephfs_subvolume_path))

        driver.rados_command.assert_called_once_with(
            self._rados_client,
            cluster_info_prefix, cluster_info_dict)

        self.assertEqual(expected_export_locations, export_locations)


@ddt.ddt
class CephFSDriverAltConfigTestCase(test.TestCase):
    """Test the CephFS driver with non-default config values."""

    def setUp(self):
        super(CephFSDriverAltConfigTestCase, self).setUp()
        self._execute = mock.Mock()
        self.fake_conf = configuration.Configuration(None)
        self._rados_client = MockRadosModule.Rados()
        self._context = context.get_admin_context()
        self._share = fake_share.fake_share(share_proto='CEPHFS')

        self.fake_conf.set_default('driver_handles_share_servers', False)
        self.fake_conf.set_default('cephfs_auth_id', 'manila')

        self.mock_object(driver, "rados", MockRadosModule)
        self.mock_object(driver, "json_command",
                         MockCephArgparseModule.json_command)
        self.mock_object(driver, "rados_command")
        self.mock_object(driver, 'NativeProtocolHelper')
        self.mock_object(driver, 'NFSProtocolHelper')

        driver.ceph_default_target = ('mon-mgr', )

    @ddt.data('cephfs', 'nfs')
    def test_do_setup_alt_volume_mode(self, protocol_helper):
        self.fake_conf.set_default('cephfs_volume_mode', ALT_VOLUME_MODE)
        self._driver = driver.CephFSDriver(execute=self._execute,
                                           configuration=self.fake_conf,
                                           rados_client=self._rados_client)

        type(self._driver).volname = mock.PropertyMock(return_value='cephfs')

        self._driver.configuration.cephfs_protocol_helper_type = (
            protocol_helper)

        self._driver.do_setup(self._context)

        if protocol_helper == 'cephfs':
            driver.NativeProtocolHelper.assert_called_once_with(
                self._execute, self._driver.configuration,
                rados_client=self._driver.rados_client,
                volname=self._driver.volname)
        else:
            driver.NFSProtocolHelper.assert_called_once_with(
                self._execute, self._driver.configuration,
                rados_client=self._driver._rados_client,
                volname=self._driver.volname)

        self._driver.protocol_helper.init_helper.assert_called_once_with()

        self.assertEqual(ALT_VOLUME_MODE, self._driver._cephfs_volume_mode)

    @ddt.data('0o759', '0x755', '12a3')
    def test_volume_mode_exception(self, volume_mode):
        # cephfs_volume_mode must be a string representing an int as octal
        self.fake_conf.set_default('cephfs_volume_mode', volume_mode)

        self.assertRaises(exception.BadConfigurationException,
                          driver.CephFSDriver, execute=self._execute,
                          configuration=self.fake_conf)


@ddt.ddt
class MiscTests(test.TestCase):

    @ddt.data({'import_exc': None},
              {'import_exc': ImportError})
    @ddt.unpack
    def test_rados_module_missing(self, import_exc):
        driver.rados = None
        with mock.patch.object(
                driver.importutils,
                'import_module',
                side_effect=import_exc) as mock_import_module:
            if import_exc:
                self.assertRaises(
                    exception.ShareBackendException, driver.setup_rados)
            else:
                driver.setup_rados()
                self.assertEqual(mock_import_module.return_value,
                                 driver.rados)

            mock_import_module.assert_called_once_with('rados')

    @ddt.data({'import_exc': None},
              {'import_exc': ImportError})
    @ddt.unpack
    def test_setup_json_class_missing(self, import_exc):
        driver.json_command = None
        with mock.patch.object(
                driver.importutils,
                'import_class',
                side_effect=import_exc) as mock_import_class:
            if import_exc:
                self.assertRaises(
                    exception.ShareBackendException, driver.setup_json_command)
            else:
                driver.setup_json_command()
                self.assertEqual(mock_import_class.return_value,
                                 driver.json_command)
            mock_import_class.assert_called_once_with(
                'ceph_argparse.json_command')
