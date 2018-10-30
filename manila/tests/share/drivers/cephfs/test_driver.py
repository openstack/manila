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


import ddt
import mock
from oslo_utils import units


from manila.common import constants
from manila import context
import manila.exception as exception
from manila.share import configuration
from manila.share.drivers.cephfs import driver
from manila.share import share_types
from manila import test
from manila.tests import fake_share


DEFAULT_VOLUME_MODE = 0o755
ALT_VOLUME_MODE_CFG = '775'
ALT_VOLUME_MODE = 0o775


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
        version = 1

        def __init__(self, *args, **kwargs):
            mock.Mock.__init__(self, spec=[
                "connect", "disconnect",
                "create_snapshot_volume", "destroy_snapshot_volume",
                "create_group", "destroy_group",
                "delete_volume", "purge_volume",
                "deauthorize", "evict", "set_max_bytes",
                "destroy_snapshot_group", "create_snapshot_group",
                "get_authorized_ids"
            ])
            self.create_volume = mock.Mock(return_value={
                "mount_path": "/foo/bar"
            })
            self._get_path = mock.Mock(return_value='/foo/bar')
            self.get_mon_addrs = mock.Mock(return_value=["1.2.3.4", "5.6.7.8"])
            self.get_authorized_ids = mock.Mock(
                return_value=[('eve', 'rw')])
            self.authorize = mock.Mock(return_value={"auth_key": "abc123"})
            self.get_used_bytes = mock.Mock(return_value=self.mock_used_bytes)
            self.rados = mock.Mock()
            self.rados.get_cluster_stats = mock.Mock(return_value={
                "kb": 1000,
                "kb_avail": 500
            })


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

        self.fake_conf.set_default('driver_handles_share_servers', False)
        self.fake_conf.set_default('cephfs_auth_id', 'manila')

        self.mock_object(driver, "ceph_volume_client",
                         MockVolumeClientModule)
        self.mock_object(driver, "ceph_module_found", True)
        self.mock_object(driver, "cephfs_share_path")
        self.mock_object(driver, 'NativeProtocolHelper')
        self.mock_object(driver, 'NFSProtocolHelper')

        self._driver = (
            driver.CephFSDriver(execute=self._execute,
                                configuration=self.fake_conf))
        self._driver.protocol_helper = mock.Mock()

        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value={}))

    @ddt.data('cephfs', 'nfs')
    def test_do_setup(self, protocol_helper):
        self._driver.configuration.cephfs_protocol_helper_type = (
            protocol_helper)

        self._driver.do_setup(self._context)

        if protocol_helper == 'cephfs':
            driver.NativeProtocolHelper.assert_called_once_with(
                self._execute, self._driver.configuration,
                ceph_vol_client=self._driver._volume_client)
        else:
            driver.NFSProtocolHelper.assert_called_once_with(
                self._execute, self._driver.configuration,
                ceph_vol_client=self._driver._volume_client)

        self._driver.protocol_helper.init_helper.assert_called_once_with()

        self.assertEqual(DEFAULT_VOLUME_MODE, self._driver._cephfs_volume_mode)

    def test_create_share(self):
        cephfs_volume = {"mount_path": "/foo/bar"}

        self._driver.create_share(self._context, self._share)

        self._driver._volume_client.create_volume.assert_called_once_with(
            driver.cephfs_share_path(self._share),
            size=self._share['size'] * units.Gi,
            data_isolated=False, mode=DEFAULT_VOLUME_MODE)
        (self._driver.protocol_helper.get_export_locations.
            assert_called_once_with(self._share, cephfs_volume))

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

    def test_ensure_share(self):
        self._driver.ensure_share(self._context,
                                  self._share)

        self._driver._volume_client.create_volume.assert_called_once_with(
            driver.cephfs_share_path(self._share),
            size=self._share['size'] * units.Gi,
            data_isolated=False,
            mode=DEFAULT_VOLUME_MODE)

    def test_create_data_isolated(self):
        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value={"cephfs:data_isolated": True})
                         )

        self._driver.create_share(self._context, self._share)

        self._driver._volume_client.create_volume.assert_called_once_with(
            driver.cephfs_share_path(self._share),
            size=self._share['size'] * units.Gi,
            data_isolated=True,
            mode=DEFAULT_VOLUME_MODE)

    def test_delete_share(self):
        self._driver.delete_share(self._context, self._share)

        self._driver._volume_client.delete_volume.assert_called_once_with(
            driver.cephfs_share_path(self._share),
            data_isolated=False)
        self._driver._volume_client.purge_volume.assert_called_once_with(
            driver.cephfs_share_path(self._share),
            data_isolated=False)

    def test_delete_data_isolated(self):
        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value={"cephfs:data_isolated": True})
                         )

        self._driver.delete_share(self._context, self._share)

        self._driver._volume_client.delete_volume.assert_called_once_with(
            driver.cephfs_share_path(self._share),
            data_isolated=True)
        self._driver._volume_client.purge_volume.assert_called_once_with(
            driver.cephfs_share_path(self._share),
            data_isolated=True)

    def test_extend_share(self):
        new_size_gb = self._share['size'] * 2
        new_size = new_size_gb * units.Gi

        self._driver.extend_share(self._share, new_size_gb, None)

        self._driver._volume_client.set_max_bytes.assert_called_once_with(
            driver.cephfs_share_path(self._share),
            new_size)

    def test_shrink_share(self):
        new_size_gb = self._share['size'] * 0.5
        new_size = new_size_gb * units.Gi

        self._driver.shrink_share(self._share, new_size_gb, None)

        self._driver._volume_client.get_used_bytes.assert_called_once_with(
            driver.cephfs_share_path(self._share))
        self._driver._volume_client.set_max_bytes.assert_called_once_with(
            driver.cephfs_share_path(self._share),
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
                                         "id": "instance1",
                                         "share": self._share,
                                         "snapshot_id": "snappy1"
                                     },
                                     None)

        (self._driver._volume_client.create_snapshot_volume
            .assert_called_once_with(
                driver.cephfs_share_path(self._share),
                "snappy1_instance1",
                mode=DEFAULT_VOLUME_MODE))

    def test_delete_snapshot(self):
        self._driver.delete_snapshot(self._context,
                                     {
                                         "id": "instance1",
                                         "share": self._share,
                                         "snapshot_id": "snappy1"
                                     },
                                     None)

        (self._driver._volume_client.destroy_snapshot_volume
            .assert_called_once_with(
                driver.cephfs_share_path(self._share),
                "snappy1_instance1"))

    def test_create_share_group(self):
        self._driver.create_share_group(self._context, {"id": "grp1"}, None)

        self._driver._volume_client.create_group.assert_called_once_with(
            "grp1", mode=DEFAULT_VOLUME_MODE)

    def test_delete_share_group(self):
        self._driver.delete_share_group(self._context, {"id": "grp1"}, None)

        self._driver._volume_client.destroy_group.assert_called_once_with(
            "grp1")

    def test_create_share_snapshot(self):
        self._driver.create_share_group_snapshot(self._context, {
            'share_group_id': 'sgid',
            'id': 'snapid',
        })

        (self._driver._volume_client.create_snapshot_group.
         assert_called_once_with("sgid", "snapid", mode=DEFAULT_VOLUME_MODE))

    def test_delete_share_group_snapshot(self):
        self._driver.delete_share_group_snapshot(self._context, {
            'share_group_id': 'sgid',
            'id': 'snapid',
        })

        (self._driver._volume_client.destroy_snapshot_group.
         assert_called_once_with("sgid", "snapid"))

    def test_delete_driver(self):
        # Create share to prompt volume_client construction
        self._driver.create_share(self._context,
                                  self._share)

        vc = self._driver._volume_client
        del self._driver

        vc.disconnect.assert_called_once_with()

    def test_delete_driver_no_client(self):
        self.assertIsNone(self._driver._volume_client)
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

        self.assertTrue(result['ipv4_support'])
        self.assertFalse(result['ipv6_support'])
        self.assertEqual("CEPHFS", result['storage_protocol'])

    def test_module_missing(self):
        driver.ceph_module_found = False
        driver.ceph_volume_client = None

        self.assertRaises(exception.ManilaException,
                          self._driver.create_share,
                          self._context,
                          self._share)


@ddt.ddt
class NativeProtocolHelperTestCase(test.TestCase):

    def setUp(self):
        super(NativeProtocolHelperTestCase, self).setUp()
        self.fake_conf = configuration.Configuration(None)
        self._context = context.get_admin_context()
        self._share = fake_share.fake_share(share_proto='CEPHFS')

        self.fake_conf.set_default('driver_handles_share_servers', False)

        self.mock_object(driver, "cephfs_share_path")

        self._native_protocol_helper = driver.NativeProtocolHelper(
            None,
            self.fake_conf,
            ceph_vol_client=MockVolumeClientModule.CephFSVolumeClient()
        )

    def test_get_export_locations(self):
        vc = self._native_protocol_helper.volume_client
        fake_cephfs_volume = {'mount_path': '/foo/bar'}
        expected_export_locations = {
            'path': '1.2.3.4,5.6.7.8:/foo/bar',
            'is_admin_only': False,
            'metadata': {},
        }

        export_locations = self._native_protocol_helper.get_export_locations(
            self._share, fake_cephfs_volume)

        self.assertEqual(expected_export_locations, export_locations)
        vc.get_mon_addrs.assert_called_once_with()

    @ddt.data(None, 1)
    def test_allow_access_rw(self, volume_client_version):
        vc = self._native_protocol_helper.volume_client
        rule = {
            'access_level': constants.ACCESS_LEVEL_RW,
            'access_to': 'alice',
            'access_type': 'cephx',
        }
        vc.version = volume_client_version

        auth_key = self._native_protocol_helper._allow_access(
            self._context, self._share, rule)

        self.assertEqual("abc123", auth_key)

        if not volume_client_version:
            vc.authorize.assert_called_once_with(
                driver.cephfs_share_path(self._share), "alice")
        else:
            vc.authorize.assert_called_once_with(
                driver.cephfs_share_path(self._share), "alice",
                readonly=False, tenant_id=self._share['project_id'])

    @ddt.data(None, 1)
    def test_allow_access_ro(self, volume_client_version):
        vc = self._native_protocol_helper.volume_client
        rule = {
            'access_level': constants.ACCESS_LEVEL_RO,
            'access_to': 'alice',
            'access_type': 'cephx',
        }
        vc.version = volume_client_version

        if not volume_client_version:
            self.assertRaises(exception.InvalidShareAccessLevel,
                              self._native_protocol_helper._allow_access,
                              self._context, self._share, rule)
        else:
            auth_key = (
                self._native_protocol_helper._allow_access(
                    self._context, self._share, rule)
            )

            self.assertEqual("abc123", auth_key)
            vc.authorize.assert_called_once_with(
                driver.cephfs_share_path(self._share), "alice", readonly=True,
                tenant_id=self._share['project_id'])

    def test_allow_access_wrong_type(self):
        self.assertRaises(exception.InvalidShareAccess,
                          self._native_protocol_helper._allow_access,
                          self._context, self._share, {
                              'access_level': constants.ACCESS_LEVEL_RW,
                              'access_type': 'RHUBARB',
                              'access_to': 'alice'
                          })

    def test_allow_access_same_cephx_id_as_manila_service(self):
        self.assertRaises(exception.InvalidInput,
                          self._native_protocol_helper._allow_access,
                          self._context, self._share, {
                              'access_level': constants.ACCESS_LEVEL_RW,
                              'access_type': 'cephx',
                              'access_to': 'manila',
                          })

    def test_deny_access(self):
        vc = self._native_protocol_helper.volume_client
        self._native_protocol_helper._deny_access(self._context, self._share, {
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'alice'
        })

        vc.deauthorize.assert_called_once_with(
            driver.cephfs_share_path(self._share), "alice")
        vc.evict.assert_called_once_with(
            "alice", volume_path=driver.cephfs_share_path(self._share))

    def test_update_access_add_rm(self):
        vc = self._native_protocol_helper.volume_client
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
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'bob'
        }

        access_updates = self._native_protocol_helper.update_access(
            self._context, self._share, access_rules=[alice],
            add_rules=[alice], delete_rules=[bob])

        self.assertEqual(
            {'accessid1': {'access_key': 'abc123'}}, access_updates)
        vc.authorize.assert_called_once_with(
            driver.cephfs_share_path(self._share), "alice", readonly=False,
            tenant_id=self._share['project_id'])
        vc.deauthorize.assert_called_once_with(
            driver.cephfs_share_path(self._share), "bob")

    @ddt.data(None, 1)
    def test_update_access_all(self, volume_client_version):
        vc = self._native_protocol_helper.volume_client
        alice = {
            'id': 'instance_mapping_id1',
            'access_id': 'accessid1',
            'access_level': 'rw',
            'access_type': 'cephx',
            'access_to': 'alice'
        }
        vc.version = volume_client_version

        access_updates = self._native_protocol_helper.update_access(
            self._context, self._share, access_rules=[alice], add_rules=[],
            delete_rules=[])

        self.assertEqual(
            {'accessid1': {'access_key': 'abc123'}}, access_updates)

        if volume_client_version:
            vc.get_authorized_ids.assert_called_once_with(
                driver.cephfs_share_path(self._share))
            vc.authorize.assert_called_once_with(
                driver.cephfs_share_path(self._share), "alice", readonly=False,
                tenant_id=self._share['project_id'])
            vc.deauthorize.assert_called_once_with(
                driver.cephfs_share_path(self._share), "eve")
        else:
            self.assertFalse(vc.get_authorized_ids.called)
            vc.authorize.assert_called_once_with(
                driver.cephfs_share_path(self._share), "alice")


@ddt.ddt
class NFSProtocolHelperTestCase(test.TestCase):

    def setUp(self):
        super(NFSProtocolHelperTestCase, self).setUp()
        self._execute = mock.Mock()
        self._share = fake_share.fake_share(share_proto='NFS')
        self._volume_client = MockVolumeClientModule.CephFSVolumeClient()
        self.fake_conf = configuration.Configuration(None)

        self.fake_conf.set_default('cephfs_ganesha_server_ip',
                                   'fakeip')
        self.mock_object(driver, "cephfs_share_path",
                         mock.Mock(return_value='fakevolumepath'))
        self.mock_object(driver.ganesha_utils, 'SSHExecutor')
        self.mock_object(driver.ganesha_utils, 'RootExecutor')
        self.mock_object(driver.socket, 'gethostname')

        self._nfs_helper = driver.NFSProtocolHelper(
            self._execute,
            self.fake_conf,
            ceph_vol_client=self._volume_client)

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
            ceph_vol_client=MockVolumeClientModule.CephFSVolumeClient()
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
            ceph_vol_client=MockVolumeClientModule.CephFSVolumeClient()
        )

        driver.ganesha_utils.RootExecutor.assert_has_calls(
            [mock.call(self._execute)])
        if ganesha_server_ip:
            self.assertFalse(driver.socket.gethostname.called)
            self.assertFalse(driver.LOG.info.called)
        else:
            driver.socket.gethostname.assert_called_once_with()
            driver.LOG.info.assert_called_once()

    def test_get_export_locations(self):
        cephfs_volume = {"mount_path": "/foo/bar"}

        ret = self._nfs_helper.get_export_locations(self._share,
                                                    cephfs_volume)
        self.assertEqual(
            {
                'path': 'fakeip:/foo/bar',
                'is_admin_only': False,
                'metadata': {}
            }, ret)

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
        expected_ret = {
            'Name': 'Ceph',
            'User_Id': 'ganesha-fakeid',
            'Secret_Access_Key': 'fakekey'
        }
        self.mock_object(self._volume_client, 'authorize',
                         mock.Mock(return_value={'auth_key': 'fakekey'}))

        ret = self._nfs_helper._fsal_hook(None, self._share, None)

        driver.cephfs_share_path.assert_called_once_with(self._share)
        self._volume_client.authorize.assert_called_once_with(
            'fakevolumepath', 'ganesha-fakeid', readonly=False,
            tenant_id='fake_project_uuid')
        self.assertEqual(expected_ret, ret)

    def test_cleanup_fsal_hook(self):
        self.mock_object(self._volume_client, 'deauthorize')

        ret = self._nfs_helper._cleanup_fsal_hook(None, self._share, None)

        driver.cephfs_share_path.assert_called_once_with(self._share)
        self._volume_client.deauthorize.assert_called_once_with(
            'fakevolumepath', 'ganesha-fakeid')
        self.assertIsNone(ret)

    def test_get_export_path(self):
        ret = self._nfs_helper._get_export_path(self._share)

        driver.cephfs_share_path.assert_called_once_with(self._share)
        self._volume_client._get_path.assert_called_once_with(
            'fakevolumepath')
        self.assertEqual('/foo/bar', ret)

    def test_get_export_pseudo_path(self):
        ret = self._nfs_helper._get_export_pseudo_path(self._share)

        driver.cephfs_share_path.assert_called_once_with(self._share)
        self._volume_client._get_path.assert_called_once_with(
            'fakevolumepath')
        self.assertEqual('/foo/bar', ret)


@ddt.ddt
class CephFSDriverAltConfigTestCase(test.TestCase):
    """Test the CephFS driver with non-default config values."""

    def setUp(self):
        super(CephFSDriverAltConfigTestCase, self).setUp()
        self._execute = mock.Mock()
        self.fake_conf = configuration.Configuration(None)
        self._context = context.get_admin_context()
        self._share = fake_share.fake_share(share_proto='CEPHFS')

        self.fake_conf.set_default('driver_handles_share_servers', False)
        self.fake_conf.set_default('cephfs_auth_id', 'manila')

        self.mock_object(driver, "ceph_volume_client",
                         MockVolumeClientModule)
        self.mock_object(driver, "ceph_module_found", True)
        self.mock_object(driver, "cephfs_share_path")
        self.mock_object(driver, 'NativeProtocolHelper')
        self.mock_object(driver, 'NFSProtocolHelper')

    @ddt.data('cephfs', 'nfs')
    def test_do_setup_alt_volume_mode(self, protocol_helper):

        self.fake_conf.set_default('cephfs_volume_mode', ALT_VOLUME_MODE_CFG)
        self._driver = driver.CephFSDriver(execute=self._execute,
                                           configuration=self.fake_conf)

        self._driver.configuration.cephfs_protocol_helper_type = (
            protocol_helper)

        self._driver.do_setup(self._context)

        if protocol_helper == 'cephfs':
            driver.NativeProtocolHelper.assert_called_once_with(
                self._execute, self._driver.configuration,
                ceph_vol_client=self._driver._volume_client)
        else:
            driver.NFSProtocolHelper.assert_called_once_with(
                self._execute, self._driver.configuration,
                ceph_vol_client=self._driver._volume_client)

        self._driver.protocol_helper.init_helper.assert_called_once_with()

        self.assertEqual(ALT_VOLUME_MODE, self._driver._cephfs_volume_mode)

    @ddt.data('0o759', '0x755', '12a3')
    def test_volume_mode_exception(self, volume_mode):
        # cephfs_volume_mode must be a string representing an int as octal
        self.fake_conf.set_default('cephfs_volume_mode', volume_mode)

        self.assertRaises(exception.BadConfigurationException,
                          driver.CephFSDriver, execute=self._execute,
                          configuration=self.fake_conf)
