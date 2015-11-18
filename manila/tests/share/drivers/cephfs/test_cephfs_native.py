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


import mock
from oslo_utils import units


from manila.common import constants
from manila import context
import manila.exception as exception
from manila.share import configuration
from manila.share.drivers.cephfs import cephfs_native
from manila.share import share_types
from manila import test
from manila.tests import fake_share


class MockVolumeClientModule(object):
    """Mocked up version of ceph's VolumeClient interface."""

    class VolumePath(object):
        """Copy of VolumePath from CephFSVolumeClient."""

        def __init__(self, group_id, volume_id):
            self.group_id = group_id
            self.volume_id = volume_id

        def __eq__(self, other):
            return (self.group_id == other.group_id
                    and self.volume_id == other.volume_id)

        def __str__(self):
            return "{0}/{1}".format(self.group_id, self.volume_id)

    class CephFSVolumeClient(mock.Mock):
        mock_used_bytes = 0

        def __init__(self, *args, **kwargs):
            mock.Mock.__init__(self, spec=[
                "connect", "disconnect",
                "create_snapshot_volume", "destroy_snapshot_volume",
                "create_group", "destroy_group",
                "delete_volume", "purge_volume",
                "deauthorize", "evict", "set_max_bytes",
                "destroy_snapshot_group", "create_snapshot_group",
                "disconnect"
            ])
            self.create_volume = mock.Mock(return_value={
                "mount_path": "/foo/bar"
            })
            self.get_mon_addrs = mock.Mock(return_value=["1.2.3.4", "5.6.7.8"])
            self.authorize = mock.Mock(return_value={"auth_key": "abc123"})
            self.get_used_bytes = mock.Mock(return_value=self.mock_used_bytes)
            self.rados = mock.Mock()
            self.rados.get_cluster_stats = mock.Mock(return_value={
                "kb": 1000,
                "kb_avail": 500
            })


class CephFSNativeDriverTestCase(test.TestCase):
    """Test the CephFS native driver.

    This is a very simple driver that mainly
    calls through to the CephFSVolumeClient interface, so the tests validate
    that the Manila driver calls map to the appropriate CephFSVolumeClient
    calls.
    """

    def setUp(self):
        super(CephFSNativeDriverTestCase, self).setUp()
        self.fake_conf = configuration.Configuration(None)
        self._context = context.get_admin_context()
        self._share = fake_share.fake_share(share_proto='CEPHFS')

        self.fake_conf.set_default('driver_handles_share_servers', False)

        self.mock_object(cephfs_native, "ceph_volume_client",
                         MockVolumeClientModule)
        self.mock_object(cephfs_native, "ceph_module_found", True)

        self._driver = (
            cephfs_native.CephFSNativeDriver(configuration=self.fake_conf))

        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value={}))

    def test_create_share(self):
        expected_export_locations = {
            'path': '1.2.3.4,5.6.7.8:/foo/bar',
            'is_admin_only': False,
            'metadata': {},
        }

        export_locations = self._driver.create_share(self._context,
                                                     self._share)

        self.assertEqual(expected_export_locations, export_locations)
        self._driver._volume_client.create_volume.assert_called_once_with(
            self._driver._share_path(self._share),
            size=self._share['size'] * units.Gi,
            data_isolated=False)

    def test_ensure_share(self):
        self._driver.ensure_share(self._context,
                                  self._share)

        self._driver._volume_client.create_volume.assert_called_once_with(
            self._driver._share_path(self._share),
            size=self._share['size'] * units.Gi,
            data_isolated=False)

    def test_create_data_isolated(self):
        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value={"cephfs:data_isolated": True})
                         )

        self._driver.create_share(self._context, self._share)

        self._driver._volume_client.create_volume.assert_called_once_with(
            self._driver._share_path(self._share),
            size=self._share['size'] * units.Gi,
            data_isolated=True)

    def test_delete_share(self):
        self._driver.delete_share(self._context, self._share)

        self._driver._volume_client.delete_volume.assert_called_once_with(
            self._driver._share_path(self._share),
            data_isolated=False)
        self._driver._volume_client.purge_volume.assert_called_once_with(
            self._driver._share_path(self._share),
            data_isolated=False)

    def test_delete_data_isolated(self):
        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value={"cephfs:data_isolated": True})
                         )

        self._driver.delete_share(self._context, self._share)

        self._driver._volume_client.delete_volume.assert_called_once_with(
            self._driver._share_path(self._share),
            data_isolated=True)
        self._driver._volume_client.purge_volume.assert_called_once_with(
            self._driver._share_path(self._share),
            data_isolated=True)

    def test_allow_access(self):
        access_rule = {
            'access_level': constants.ACCESS_LEVEL_RW,
            'access_type': 'cephx',
            'access_to': 'alice'
        }

        self._driver._allow_access(self._context, self._share, access_rule)

        self._driver._volume_client.authorize.assert_called_once_with(
            self._driver._share_path(self._share),
            "alice")

    def test_allow_access_wrong_type(self):
        self.assertRaises(exception.InvalidShareAccess,
                          self._driver._allow_access,
                          self._context, self._share, {
                              'access_level': constants.ACCESS_LEVEL_RW,
                              'access_type': 'RHUBARB',
                              'access_to': 'alice'
                          })

    def test_allow_access_ro(self):
        self.assertRaises(exception.InvalidShareAccessLevel,
                          self._driver._allow_access,
                          self._context, self._share, {
                              'access_level': constants.ACCESS_LEVEL_RO,
                              'access_type': 'cephx',
                              'access_to': 'alice'
                          })

    def test_deny_access(self):
        self._driver._deny_access(self._context, self._share, {
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'alice'
        })

        self._driver._volume_client.deauthorize.assert_called_once_with(
            self._driver._share_path(self._share),
            "alice")

    def test_update_access_add_rm(self):
        alice = {
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'alice'
        }
        bob = {
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'bob'
        }
        self._driver.update_access(self._context, self._share,
                                   access_rules=[alice],
                                   add_rules=[alice],
                                   delete_rules=[bob])

        self._driver._volume_client.authorize.assert_called_once_with(
            self._driver._share_path(self._share),
            "alice")
        self._driver._volume_client.deauthorize.assert_called_once_with(
            self._driver._share_path(self._share),
            "bob")

    def test_update_access_all(self):
        alice = {
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'alice'
        }

        self._driver.update_access(self._context, self._share,
                                   access_rules=[alice], add_rules=[],
                                   delete_rules=[])

        self._driver._volume_client.authorize.assert_called_once_with(
            self._driver._share_path(self._share),
            "alice")

    def test_extend_share(self):
        new_size_gb = self._share['size'] * 2
        new_size = new_size_gb * units.Gi

        self._driver.extend_share(self._share, new_size_gb, None)

        self._driver._volume_client.set_max_bytes.assert_called_once_with(
            self._driver._share_path(self._share),
            new_size)

    def test_shrink_share(self):
        new_size_gb = self._share['size'] * 0.5
        new_size = new_size_gb * units.Gi

        self._driver.shrink_share(self._share, new_size_gb, None)

        self._driver._volume_client.get_used_bytes.assert_called_once_with(
            self._driver._share_path(self._share))
        self._driver._volume_client.set_max_bytes.assert_called_once_with(
            self._driver._share_path(self._share),
            new_size)

    def test_shrink_share_full(self):
        """That shrink fails when share is too full."""
        new_size_gb = self._share['size'] * 0.5

        # Pretend to be full up
        vc = MockVolumeClientModule.CephFSVolumeClient
        vc.mock_used_bytes = (units.Gi * self._share['size'])

        self.assertRaises(exception.ShareShrinkingPossibleDataLoss,
                          self._driver.shrink_share,
                          self._share, new_size_gb, None)
        self._driver._volume_client.set_max_bytes.assert_not_called()

    def test_create_snapshot(self):
        self._driver.create_snapshot(self._context,
                                     {
                                         "share": self._share,
                                         "name": "snappy1"
                                     },
                                     None)

        (self._driver._volume_client.create_snapshot_volume
            .assert_called_once_with(
                self._driver._share_path(self._share),
                "snappy1"))

    def test_delete_snapshot(self):
        self._driver.delete_snapshot(self._context,
                                     {
                                         "share": self._share,
                                         "name": "snappy1"
                                     },
                                     None)

        (self._driver._volume_client.destroy_snapshot_volume
            .assert_called_once_with(
                self._driver._share_path(self._share),
                "snappy1"))

    def test_create_consistency_group(self):
        self._driver.create_consistency_group(self._context, {"id": "grp1"},
                                              None)

        self._driver._volume_client.create_group.assert_called_once_with(
            "grp1")

    def test_delete_consistency_group(self):
        self._driver.delete_consistency_group(self._context, {"id": "grp1"},
                                              None)

        self._driver._volume_client.destroy_group.assert_called_once_with(
            "grp1")

    def test_create_cg_snapshot(self):
        self._driver.create_cgsnapshot(self._context, {
            'consistency_group_id': 'cgid',
            'id': 'snapid'
        })

        (self._driver._volume_client.create_snapshot_group.
         assert_called_once_with("cgid", "snapid"))

    def test_delete_cgsnapshot(self):
        self._driver.delete_cgsnapshot(self._context, {
            'consistency_group_id': 'cgid',
            'id': 'snapid'
        })

        (self._driver._volume_client.destroy_snapshot_group.
         assert_called_once_with("cgid", "snapid"))

    def test_delete_driver(self):
        # Create share to prompt volume_client construction
        self._driver.create_share(self._context,
                                  self._share)

        vc = self._driver._volume_client
        del self._driver

        vc.disconnect.assert_called_once_with()

    def test_delete_driver_no_client(self):
        self.assertEqual(None, self._driver._volume_client)
        del self._driver

    def test_connect_noevict(self):
        # When acting as "admin", driver should skip evicting
        self._driver.configuration.local_conf.set_override('cephfs_auth_id',
                                                           "admin")

        self._driver.create_share(self._context,
                                  self._share)

        vc = self._driver._volume_client
        vc.connect.assert_called_once_with(premount_evict=None)

    def test_update_share_stats(self):
        self._driver._volume_client
        self._driver._update_share_stats()
        result = self._driver._stats

        self.assertEqual("CEPHFS", result['storage_protocol'])

    def test_module_missing(self):
        cephfs_native.ceph_module_found = False
        cephfs_native.ceph_volume_client = None

        self.assertRaises(exception.ManilaException,
                          self._driver.create_share,
                          self._context,
                          self._share)
