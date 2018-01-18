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

import copy

import ddt
import mock
from oslo_log import log

from manila import exception
from manila.share.drivers.dell_emc.common.enas import connector
from manila.share.drivers.dell_emc.plugins.vnx import connection
from manila.share.drivers.dell_emc.plugins.vnx import object_manager
from manila import test
from manila.tests import fake_share
from manila.tests.share.drivers.dell_emc.common.enas import fakes
from manila.tests.share.drivers.dell_emc.common.enas import utils

LOG = log.getLogger(__name__)


@ddt.ddt
class StorageConnectionTestCase(test.TestCase):
    @mock.patch.object(connector.XMLAPIConnector, "_do_setup", mock.Mock())
    def setUp(self):
        super(StorageConnectionTestCase, self).setUp()
        self.emc_share_driver = fakes.FakeEMCShareDriver()

        self.connection = connection.VNXStorageConnection(LOG)

        self.pool = fakes.PoolTestData()
        self.vdm = fakes.VDMTestData()
        self.mover = fakes.MoverTestData()
        self.fs = fakes.FileSystemTestData()
        self.mount = fakes.MountPointTestData()
        self.snap = fakes.SnapshotTestData()
        self.cifs_share = fakes.CIFSShareTestData()
        self.nfs_share = fakes.NFSShareTestData()
        self.cifs_server = fakes.CIFSServerTestData()
        self.dns = fakes.DNSDomainTestData()

        with mock.patch.object(connector.XMLAPIConnector, 'request',
                               mock.Mock()):
            self.connection.connect(self.emc_share_driver, None)

    def test_check_for_setup_error(self):
        hook = utils.RequestSideEffect()
        hook.append(self.mover.resp_get_ref_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        with mock.patch.object(connection.VNXStorageConnection,
                               '_get_managed_storage_pools',
                               mock.Mock()):
            self.connection.check_for_setup_error()

        expected_calls = [mock.call(self.mover.req_get_ref())]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_check_for_setup_error_with_invalid_mover_name(self):
        hook = utils.RequestSideEffect()
        hook.append(self.mover.resp_get_error())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.assertRaises(exception.InvalidParameterValue,
                          self.connection.check_for_setup_error)

        expected_calls = [mock.call(self.mover.req_get_ref())]
        xml_req_mock.assert_has_calls(expected_calls)

    @ddt.data({'pool_conf': None,
               'real_pools': ['fake_pool', 'nas_pool'],
               'matched_pool': set()},
              {'pool_conf': [],
               'real_pools': ['fake_pool', 'nas_pool'],
               'matched_pool': set()},
              {'pool_conf': ['*'],
               'real_pools': ['fake_pool', 'nas_pool'],
               'matched_pool': {'fake_pool', 'nas_pool'}},
              {'pool_conf': ['fake_*'],
               'real_pools': ['fake_pool', 'nas_pool', 'Perf_Pool'],
               'matched_pool': {'fake_pool'}},
              {'pool_conf': ['*pool'],
               'real_pools': ['fake_pool', 'NAS_Pool', 'Perf_POOL'],
               'matched_pool': {'fake_pool'}},
              {'pool_conf': ['nas_pool'],
               'real_pools': ['fake_pool', 'nas_pool', 'perf_pool'],
               'matched_pool': {'nas_pool'}})
    @ddt.unpack
    def test__get_managed_storage_pools(self, pool_conf, real_pools,
                                        matched_pool):
        with mock.patch.object(object_manager.StoragePool,
                               'get_all',
                               mock.Mock(return_value=('ok', real_pools))):
            pool = self.connection._get_managed_storage_pools(pool_conf)
            self.assertEqual(matched_pool, pool)

    def test__get_managed_storage_pools_failed_to_get_pool_info(self):
        hook = utils.RequestSideEffect()
        hook.append(self.pool.resp_get_error())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        pool_conf = fakes.FakeData.pool_name
        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection._get_managed_storage_pools,
                          pool_conf)

        expected_calls = [mock.call(self.pool.req_get())]
        xml_req_mock.assert_has_calls(expected_calls)

    @ddt.data(
        {'pool_conf': ['fake_*'],
         'real_pools': ['nas_pool', 'Perf_Pool']},
        {'pool_conf': ['*pool'],
         'real_pools': ['NAS_Pool', 'Perf_POOL']},
        {'pool_conf': ['nas_pool'],
         'real_pools': ['fake_pool', 'perf_pool']},
    )
    @ddt.unpack
    def test__get_managed_storage_pools_without_matched_pool(self, pool_conf,
                                                             real_pools):
        with mock.patch.object(object_manager.StoragePool,
                               'get_all',
                               mock.Mock(return_value=('ok', real_pools))):
            self.assertRaises(exception.InvalidParameterValue,
                              self.connection._get_managed_storage_pools,
                              pool_conf)

    def test_create_cifs_share(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        hook.append(self.pool.resp_get_succeed())
        hook.append(self.fs.resp_task_succeed())
        hook.append(self.cifs_share.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append()
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        location = self.connection.create_share(None, share, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.pool.req_get()),
            mock.call(self.fs.req_create_on_vdm()),
            mock.call(self.cifs_share.req_create(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [mock.call(self.cifs_share.cmd_disable_access(), True)]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

        self.assertEqual(location, r'\\%s\%s' %
                         (fakes.FakeData.network_allocations_ip1,
                          share['name']),
                         'CIFS export path is incorrect')

    def test_create_cifs_share_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.CIFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed(
            interface1=fakes.FakeData.interface_name3,
            interface2=fakes.FakeData.interface_name4))
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True,
            ip_addr=fakes.FakeData.network_allocations_ip3))
        hook.append(self.pool.resp_get_succeed())
        hook.append(self.fs.resp_task_succeed())
        hook.append(self.cifs_share.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append()
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        location = self.connection.create_share(None, share, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.pool.req_get()),
            mock.call(self.fs.req_create_on_vdm()),
            mock.call(self.cifs_share.req_create(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [mock.call(self.cifs_share.cmd_disable_access(), True)]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

        self.assertEqual(location, r'\\%s.ipv6-literal.net\%s' %
                         (fakes.FakeData.network_allocations_ip3.replace(':',
                                                                         '-'),
                          share['name']),
                         'CIFS export path is incorrect')

    def test_create_nfs_share(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.NFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.pool.resp_get_succeed())
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.fs.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.nfs_share.output_create())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        location = self.connection.create_share(None, share, share_server)

        expected_calls = [
            mock.call(self.pool.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.fs.req_create_on_vdm()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [mock.call(self.nfs_share.cmd_create(), True)]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

        self.assertEqual(location, '192.168.1.2:/%s' % share['name'],
                         'NFS export path is incorrect')

    def test_create_nfs_share_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.NFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.pool.resp_get_succeed())
        hook.append(self.vdm.resp_get_succeed(
            interface1=fakes.FakeData.interface_name3,
            interface2=fakes.FakeData.interface_name4))
        hook.append(self.fs.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.nfs_share.output_create())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        location = self.connection.create_share(None, share, share_server)

        expected_calls = [
            mock.call(self.pool.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.fs.req_create_on_vdm()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [mock.call(self.nfs_share.cmd_create(), True)]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

        self.assertEqual(location, '[%s]:/%s' %
                         (fakes.FakeData.network_allocations_ip4,
                          share['name']),
                         'NFS export path is incorrect')

    def test_create_cifs_share_without_share_server(self):
        share = fakes.CIFS_SHARE

        self.assertRaises(exception.InvalidInput,
                          self.connection.create_share,
                          None, share, None)

    def test_create_cifs_share_without_share_server_name(self):
        share = fakes.CIFS_SHARE
        share_server = copy.deepcopy(fakes.SHARE_SERVER)
        share_server['backend_details']['share_server_name'] = None

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.create_share,
                          None, share, share_server)

    def test_create_cifs_share_with_invalide_cifs_server_name(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_error())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.create_share,
                          None, share, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_create_cifs_share_without_interface_in_cifs_server(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_without_interface(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        hook.append(self.pool.resp_get_succeed())
        hook.append(self.fs.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.create_share,
                          None, share, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.pool.req_get()),
            mock.call(self.fs.req_create_on_vdm()),

        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_create_cifs_share_without_pool_name(self):
        share_server = fakes.SHARE_SERVER
        share = fake_share.fake_share(host='HostA@BackendB',
                                      share_proto='CIFS')

        self.assertRaises(exception.InvalidHost,
                          self.connection.create_share,
                          None, share, share_server)

    def test_create_cifs_share_from_snapshot(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        snapshot = fake_share.fake_snapshot(
            name=fakes.FakeData.src_snap_name,
            share_name=fakes.FakeData.src_share_name,
            share_id=fakes.FakeData.src_share_name,
            id=fakes.FakeData.src_snap_name)

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        hook.append(self.cifs_share.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.mover.output_get_interconnect_id())
        ssh_hook.append()
        ssh_hook.append()
        ssh_hook.append(self.fs.output_copy_ckpt)
        ssh_hook.append(self.fs.output_info())
        ssh_hook.append()
        ssh_hook.append()
        ssh_hook.append()
        ssh_hook.append()
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        location = self.connection.create_share_from_snapshot(
            None, share, snapshot, share_server)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.cifs_share.req_create(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.mover.cmd_get_interconnect_id(), False),
            mock.call(self.fs.cmd_create_from_ckpt(), False),
            mock.call(self.mount.cmd_server_mount('ro'), False),
            mock.call(self.fs.cmd_copy_ckpt(), True),
            mock.call(self.fs.cmd_nas_fs_info(), False),
            mock.call(self.mount.cmd_server_umount(), False),
            mock.call(self.fs.cmd_delete(), False),
            mock.call(self.mount.cmd_server_mount('rw'), False),
            mock.call(self.cifs_share.cmd_disable_access(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

        self.assertEqual(location, r'\\192.168.1.1\%s' % share['name'],
                         'CIFS export path is incorrect')

    def test_create_cifs_share_from_snapshot_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.CIFS_SHARE
        snapshot = fake_share.fake_snapshot(
            name=fakes.FakeData.src_snap_name,
            share_name=fakes.FakeData.src_share_name,
            share_id=fakes.FakeData.src_share_name,
            id=fakes.FakeData.src_snap_name)

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.vdm.resp_get_succeed(
            interface1=fakes.FakeData.interface_name3,
            interface2=fakes.FakeData.interface_name4))
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True,
            ip_addr=fakes.FakeData.network_allocations_ip3))
        hook.append(self.cifs_share.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.mover.output_get_interconnect_id())
        ssh_hook.append()
        ssh_hook.append()
        ssh_hook.append(self.fs.output_copy_ckpt)
        ssh_hook.append(self.fs.output_info())
        ssh_hook.append()
        ssh_hook.append()
        ssh_hook.append()
        ssh_hook.append()
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        location = self.connection.create_share_from_snapshot(
            None, share, snapshot, share_server)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.cifs_share.req_create(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.mover.cmd_get_interconnect_id(), False),
            mock.call(self.fs.cmd_create_from_ckpt(), False),
            mock.call(self.mount.cmd_server_mount('ro'), False),
            mock.call(self.fs.cmd_copy_ckpt(), True),
            mock.call(self.fs.cmd_nas_fs_info(), False),
            mock.call(self.mount.cmd_server_umount(), False),
            mock.call(self.fs.cmd_delete(), False),
            mock.call(self.mount.cmd_server_mount('rw'), False),
            mock.call(self.cifs_share.cmd_disable_access(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

        self.assertEqual(location, r'\\%s.ipv6-literal.net\%s' %
                         (fakes.FakeData.network_allocations_ip3.replace(':',
                                                                         '-'),
                          share['name']),
                         'CIFS export path is incorrect')

    def test_create_nfs_share_from_snapshot(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.NFS_SHARE
        snapshot = fake_share.fake_snapshot(
            name=fakes.FakeData.src_snap_name,
            share_name=fakes.FakeData.src_share_name,
            share_id=fakes.FakeData.src_share_name,
            id=fakes.FakeData.src_snap_name)

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.mover.output_get_interconnect_id())
        ssh_hook.append()
        ssh_hook.append()
        ssh_hook.append(self.fs.output_copy_ckpt)
        ssh_hook.append(self.fs.output_info())
        ssh_hook.append()
        ssh_hook.append()
        ssh_hook.append()
        ssh_hook.append(self.nfs_share.output_create())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        location = self.connection.create_share_from_snapshot(
            None, share, snapshot, share_server)

        expected_calls = [mock.call(self.fs.req_get())]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.mover.cmd_get_interconnect_id(), False),
            mock.call(self.fs.cmd_create_from_ckpt(), False),
            mock.call(self.mount.cmd_server_mount('ro'), False),
            mock.call(self.fs.cmd_copy_ckpt(), True),
            mock.call(self.fs.cmd_nas_fs_info(), False),
            mock.call(self.mount.cmd_server_umount(), False),
            mock.call(self.fs.cmd_delete(), False),
            mock.call(self.mount.cmd_server_mount('rw'), False),
            mock.call(self.nfs_share.cmd_create(), True)
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

        self.assertEqual(location, '192.168.1.2:/%s' % share['name'],
                         'NFS export path is incorrect')

    def test_create_nfs_share_from_snapshot_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.NFS_SHARE
        snapshot = fake_share.fake_snapshot(
            name=fakes.FakeData.src_snap_name,
            share_name=fakes.FakeData.src_share_name,
            share_id=fakes.FakeData.src_share_name,
            id=fakes.FakeData.src_snap_name)

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.mover.output_get_interconnect_id())
        ssh_hook.append()
        ssh_hook.append()
        ssh_hook.append(self.fs.output_copy_ckpt)
        ssh_hook.append(self.fs.output_info())
        ssh_hook.append()
        ssh_hook.append()
        ssh_hook.append()
        ssh_hook.append(self.nfs_share.output_create())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        location = self.connection.create_share_from_snapshot(
            None, share, snapshot, share_server)

        expected_calls = [mock.call(self.fs.req_get())]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.mover.cmd_get_interconnect_id(), False),
            mock.call(self.fs.cmd_create_from_ckpt(), False),
            mock.call(self.mount.cmd_server_mount('ro'), False),
            mock.call(self.fs.cmd_copy_ckpt(), True),
            mock.call(self.fs.cmd_nas_fs_info(), False),
            mock.call(self.mount.cmd_server_umount(), False),
            mock.call(self.fs.cmd_delete(), False),
            mock.call(self.mount.cmd_server_mount('rw'), False),
            mock.call(self.nfs_share.cmd_create(), True)
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

        self.assertEqual(location, '[%s]:/%s' %
                         (fakes.FakeData.network_allocations_ip4,
                          share['name']),
                         'NFS export path is incorrect')

    def test_create_share_with_incorrect_proto(self):
        share_server = fakes.SHARE_SERVER
        share = fake_share.fake_share(share_proto='FAKE_PROTO')

        self.assertRaises(exception.InvalidShare,
                          self.connection.create_share,
                          context=None,
                          share=share,
                          share_server=share_server)

    def test_create_share_from_snapshot_with_incorrect_proto(self):
        share_server = fakes.SHARE_SERVER
        share = fake_share.fake_share(share_proto='FAKE_PROTO')
        snapshot = fake_share.fake_snapshot()

        self.assertRaises(exception.InvalidShare,
                          self.connection.create_share_from_snapshot,
                          None, share, snapshot, share_server)

    def test_create_share_from_snapshot_without_pool_name(self):
        share_server = fakes.SHARE_SERVER
        share = fake_share.fake_share(host='HostA@BackendB',
                                      share_proto='CIFS')
        snapshot = fake_share.fake_snapshot()

        self.assertRaises(exception.InvalidHost,
                          self.connection.create_share_from_snapshot,
                          None, share, snapshot, share_server)

    def test_delete_cifs_share(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.cifs_share.resp_get_succeed(self.vdm.vdm_id))
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_share.resp_task_succeed())
        hook.append(self.mount.resp_task_succeed())
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.fs.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.connection.delete_share(None, share, share_server)

        expected_calls = [
            mock.call(self.cifs_share.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_share.req_delete(self.vdm.vdm_id)),
            mock.call(self.mount.req_delete(self.vdm.vdm_id)),
            mock.call(self.fs.req_get()),
            mock.call(self.fs.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_delete_cifs_share_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.CIFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.cifs_share.resp_get_succeed(self.vdm.vdm_id))
        hook.append(self.vdm.resp_get_succeed(
            interface1=fakes.FakeData.interface_name3,
            interface2=fakes.FakeData.interface_name4))
        hook.append(self.cifs_share.resp_task_succeed())
        hook.append(self.mount.resp_task_succeed())
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.fs.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.connection.delete_share(None, share, share_server)

        expected_calls = [
            mock.call(self.cifs_share.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_share.req_delete(self.vdm.vdm_id)),
            mock.call(self.mount.req_delete(self.vdm.vdm_id)),
            mock.call(self.fs.req_get()),
            mock.call(self.fs.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_delete_nfs_share(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.NFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.mount.resp_task_succeed())
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.fs.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=self.nfs_share.rw_hosts,
            ro_hosts=self.nfs_share.ro_hosts))
        ssh_hook.append(self.nfs_share.output_delete_succeed())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.delete_share(None, share, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.mount.req_delete(self.vdm.vdm_id)),
            mock.call(self.fs.req_get()),
            mock.call(self.fs.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), False),
            mock.call(self.nfs_share.cmd_delete(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_delete_nfs_share_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.NFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed(
            interface1=fakes.FakeData.interface_name3,
            interface2=fakes.FakeData.interface_name4))
        hook.append(self.mount.resp_task_succeed())
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.fs.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=self.nfs_share.rw_hosts,
            ro_hosts=self.nfs_share.ro_hosts))
        ssh_hook.append(self.nfs_share.output_delete_succeed())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.delete_share(None, share, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.mount.req_delete(self.vdm.vdm_id)),
            mock.call(self.fs.req_get()),
            mock.call(self.fs.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), False),
            mock.call(self.nfs_share.cmd_delete(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_delete_share_without_share_server(self):
        share = fakes.CIFS_SHARE

        self.connection.delete_share(None, share)

    def test_delete_share_with_incorrect_proto(self):
        share_server = fakes.SHARE_SERVER
        share = fake_share.fake_share(share_proto='FAKE_PROTO')

        self.assertRaises(exception.InvalidShare,
                          self.connection.delete_share,
                          context=None,
                          share=share,
                          share_server=share_server)

    def test_delete_cifs_share_with_nonexistent_mount_and_filesystem(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.cifs_share.resp_get_succeed(self.vdm.vdm_id))
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_share.resp_task_succeed())
        hook.append(self.mount.resp_task_error())
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.fs.resp_task_error())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.connection.delete_share(None, share, share_server)

        expected_calls = [
            mock.call(self.cifs_share.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_share.req_delete(self.vdm.vdm_id)),
            mock.call(self.mount.req_delete(self.vdm.vdm_id)),
            mock.call(self.fs.req_get()),
            mock.call(self.fs.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_extend_share(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        new_size = fakes.FakeData.new_size

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.pool.resp_get_succeed())
        hook.append(self.fs.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.connection.extend_share(share, new_size, share_server)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.pool.req_get()),
            mock.call(self.fs.req_extend()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_extend_share_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.CIFS_SHARE
        new_size = fakes.FakeData.new_size

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.pool.resp_get_succeed())
        hook.append(self.fs.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.connection.extend_share(share, new_size, share_server)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.pool.req_get()),
            mock.call(self.fs.req_extend()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_extend_share_without_pool_name(self):
        share_server = fakes.SHARE_SERVER
        share = fake_share.fake_share(host='HostA@BackendB',
                                      share_proto='CIFS')
        new_size = fakes.FakeData.new_size

        self.assertRaises(exception.InvalidHost,
                          self.connection.extend_share,
                          share, new_size, share_server)

    def test_create_snapshot(self):
        share_server = fakes.SHARE_SERVER
        snapshot = fake_share.fake_snapshot(
            id=fakes.FakeData.snapshot_name,
            share_id=fakes.FakeData.filesystem_name,
            share_name=fakes.FakeData.share_name)

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.snap.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.connection.create_snapshot(None, snapshot, share_server)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.snap.req_create()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_create_snapshot_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        snapshot = fake_share.fake_snapshot(
            id=fakes.FakeData.snapshot_name,
            share_id=fakes.FakeData.filesystem_name,
            share_name=fakes.FakeData.share_name)

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.snap.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.connection.create_snapshot(None, snapshot, share_server)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.snap.req_create()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_create_snapshot_with_incorrect_share_info(self):
        share_server = fakes.SHARE_SERVER
        snapshot = fake_share.fake_snapshot(
            id=fakes.FakeData.snapshot_name,
            share_id=fakes.FakeData.filesystem_name,
            share_name=fakes.FakeData.share_name)

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_but_not_found())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.create_snapshot,
                          None, snapshot, share_server)

        expected_calls = [mock.call(self.fs.req_get())]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_delete_snapshot(self):
        share_server = fakes.SHARE_SERVER
        snapshot = fake_share.fake_snapshot(
            id=fakes.FakeData.snapshot_name,
            share_id=fakes.FakeData.filesystem_name,
            share_name=fakes.FakeData.share_name)

        hook = utils.RequestSideEffect()
        hook.append(self.snap.resp_get_succeed())
        hook.append(self.snap.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.connection.delete_snapshot(None, snapshot, share_server)

        expected_calls = [
            mock.call(self.snap.req_get()),
            mock.call(self.snap.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_delete_snapshot_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        snapshot = fake_share.fake_snapshot(
            id=fakes.FakeData.snapshot_name,
            share_id=fakes.FakeData.filesystem_name,
            share_name=fakes.FakeData.share_name)

        hook = utils.RequestSideEffect()
        hook.append(self.snap.resp_get_succeed())
        hook.append(self.snap.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.connection.delete_snapshot(None, snapshot, share_server)

        expected_calls = [
            mock.call(self.snap.req_get()),
            mock.call(self.snap.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    @utils.patch_get_managed_ports_vnx(return_value=['cge-1-0'])
    def test_setup_server(self):
        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_but_not_found())
        hook.append(self.mover.resp_get_ref_succeed())
        hook.append(self.vdm.resp_task_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.dns.resp_task_succeed())
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append()
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.setup_server(fakes.NETWORK_INFO, None)

        if_name_1 = fakes.FakeData.interface_name1
        if_name_2 = fakes.FakeData.interface_name2

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.vdm.req_create()),
            mock.call(self.mover.req_create_interface(
                if_name=if_name_1,
                ip=fakes.FakeData.network_allocations_ip1)),
            mock.call(self.mover.req_create_interface(
                if_name=if_name_2,
                ip=fakes.FakeData.network_allocations_ip2)),
            mock.call(self.dns.req_create()),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_create(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.vdm.cmd_attach_nfs_interface(), False),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    @utils.patch_get_managed_ports_vnx(return_value=['cge-1-0'])
    def test_setup_server_with_ipv6(self):
        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_but_not_found())
        hook.append(self.mover.resp_get_ref_succeed())
        hook.append(self.vdm.resp_task_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.dns.resp_task_succeed())
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append()
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.setup_server(fakes.NETWORK_INFO_IPV6, None)

        if_name_1 = fakes.FakeData.interface_name3
        if_name_2 = fakes.FakeData.interface_name4

        expect_ip_1 = fakes.FakeData.network_allocations_ip3
        expect_ip_2 = fakes.FakeData.network_allocations_ip4

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.vdm.req_create()),
            mock.call(self.mover.req_create_interface_with_ipv6(
                if_name=if_name_1,
                ip=expect_ip_1)),
            mock.call(self.mover.req_create_interface_with_ipv6(
                if_name=if_name_2,
                ip=expect_ip_2)),
            mock.call(self.dns.req_create(
                ip_addr=fakes.FakeData.dns_ipv6_address)),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_create(
                self.vdm.vdm_id,
                ip_addr=fakes.FakeData.network_allocations_ip3)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.vdm.cmd_attach_nfs_interface(
                interface=fakes.FakeData.interface_name4), False),
        ]

        ssh_cmd_mock.assert_has_calls(ssh_calls)

    @utils.patch_get_managed_ports_vnx(return_value=['cge-1-0'])
    def test_setup_server_with_existing_vdm(self):
        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.mover.resp_get_ref_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.dns.resp_task_succeed())
        hook.append(self.cifs_server.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append()
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock
        self.connection.setup_server(fakes.NETWORK_INFO, None)

        if_name_1 = fakes.FakeData.network_allocations_id1[-12:]
        if_name_2 = fakes.FakeData.network_allocations_id2[-12:]

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_create_interface(
                if_name=if_name_1,
                ip=fakes.FakeData.network_allocations_ip1)),
            mock.call(self.mover.req_create_interface(
                if_name=if_name_2,
                ip=fakes.FakeData.network_allocations_ip2)),
            mock.call(self.dns.req_create()),
            mock.call(self.cifs_server.req_create(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.vdm.cmd_attach_nfs_interface(), False),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_setup_server_with_invalid_security_service(self):
        network_info = copy.deepcopy(fakes.NETWORK_INFO)
        network_info['security_services'][0]['type'] = 'fake_type'

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.setup_server,
                          network_info, None)

    @utils.patch_get_managed_ports_vnx(
        side_effect=exception.EMCVnxXMLAPIError(
            err="Get managed ports fail."))
    def test_setup_server_without_valid_physical_device(self):
        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_but_not_found())
        hook.append(self.mover.resp_get_ref_succeed())
        hook.append(self.vdm.resp_task_succeed())
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_without_value())
        hook.append(self.vdm.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock
        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.vdm.output_get_interfaces_vdm(nfs_interface=''))
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.setup_server,
                          fakes.NETWORK_INFO, None)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.vdm.req_create()),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.vdm.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.vdm.cmd_get_interfaces(), False),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    @utils.patch_get_managed_ports_vnx(return_value=['cge-1-0'])
    def test_setup_server_with_exception(self):
        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_but_not_found())
        hook.append(self.mover.resp_get_ref_succeed())
        hook.append(self.vdm.resp_task_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.mover.resp_task_error())
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_without_value())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.vdm.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.vdm.output_get_interfaces_vdm(nfs_interface=''))
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.setup_server,
                          fakes.NETWORK_INFO, None)

        if_name_1 = fakes.FakeData.network_allocations_id1[-12:]
        if_name_2 = fakes.FakeData.network_allocations_id2[-12:]

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.vdm.req_create()),
            mock.call(self.mover.req_create_interface(
                if_name=if_name_1,
                ip=fakes.FakeData.network_allocations_ip1)),
            mock.call(self.mover.req_create_interface(
                if_name=if_name_2,
                ip=fakes.FakeData.network_allocations_ip2)),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.mover.req_delete_interface(
                fakes.FakeData.network_allocations_ip1)),
            mock.call(self.vdm.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.vdm.cmd_get_interfaces(), False),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_teardown_server(self):
        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        hook.append(self.cifs_server.resp_task_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=False))
        hook.append(self.mover.resp_get_ref_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.vdm.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.vdm.output_get_interfaces_vdm())
        ssh_hook.append()
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.teardown_server(fakes.SERVER_DETAIL,
                                        fakes.SECURITY_SERVICE)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.cifs_server.req_modify(
                mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=False)),
            mock.call(self.cifs_server.req_delete(self.vdm.vdm_id)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_delete_interface(
                fakes.FakeData.network_allocations_ip1)),
            mock.call(self.mover.req_delete_interface(
                fakes.FakeData.network_allocations_ip2)),
            mock.call(self.vdm.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.vdm.cmd_get_interfaces(), False),
            mock.call(self.vdm.cmd_detach_nfs_interface(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_teardown_server_with_ipv6(self):
        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        hook.append(self.cifs_server.resp_task_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=False))
        hook.append(self.mover.resp_get_ref_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.vdm.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.vdm.output_get_interfaces_vdm())
        ssh_hook.append()
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.teardown_server(fakes.SERVER_DETAIL_IPV6,
                                        fakes.SECURITY_SERVICE_IPV6)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.cifs_server.req_modify(
                mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=False)),
            mock.call(self.cifs_server.req_delete(self.vdm.vdm_id)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_delete_interface(
                fakes.FakeData.network_allocations_ip3)),
            mock.call(self.mover.req_delete_interface(
                fakes.FakeData.network_allocations_ip4)),
            mock.call(self.vdm.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.vdm.cmd_get_interfaces(), False),
            mock.call(self.vdm.cmd_detach_nfs_interface(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_teardown_server_without_server_detail(self):
        self.connection.teardown_server(None, fakes.SECURITY_SERVICE)

    def test_teardown_server_without_security_services(self):
        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.mover.resp_get_ref_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.vdm.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.vdm.output_get_interfaces_vdm())
        ssh_hook.append()
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.teardown_server(fakes.SERVER_DETAIL, [])

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_delete_interface(
                fakes.FakeData.network_allocations_ip1)),
            mock.call(self.mover.req_delete_interface(
                fakes.FakeData.network_allocations_ip2)),
            mock.call(self.vdm.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.vdm.cmd_get_interfaces(), False),
            mock.call(self.vdm.cmd_detach_nfs_interface(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_teardown_server_without_share_server_name_in_server_detail(self):
        server_detail = {
            'cifs_if': fakes.FakeData.network_allocations_ip1,
            'nfs_if': fakes.FakeData.network_allocations_ip2,
        }
        self.connection.teardown_server(server_detail, fakes.SECURITY_SERVICE)

    def test_teardown_server_with_invalid_server_name(self):
        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_error())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.connection.teardown_server(fakes.SERVER_DETAIL,
                                        fakes.SECURITY_SERVICE)

        expected_calls = [mock.call(self.vdm.req_get())]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_teardown_server_without_cifs_server(self):
        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_error())
        hook.append(self.mover.resp_get_ref_succeed())
        hook.append(self.cifs_server.resp_task_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=False))
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.vdm.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.vdm.output_get_interfaces_vdm())
        ssh_hook.append()
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.teardown_server(fakes.SERVER_DETAIL,
                                        fakes.SECURITY_SERVICE)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_delete_interface(
                fakes.FakeData.network_allocations_ip1)),
            mock.call(self.mover.req_delete_interface(
                fakes.FakeData.network_allocations_ip2)),
            mock.call(self.vdm.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.vdm.cmd_get_interfaces(), False),
            mock.call(self.vdm.cmd_detach_nfs_interface(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_teardown_server_with_invalid_cifs_server_modification(self):
        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        hook.append(self.cifs_server.resp_task_error())
        hook.append(self.cifs_server.resp_task_succeed())
        hook.append(self.mover.resp_get_ref_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.mover.resp_task_succeed())
        hook.append(self.vdm.resp_task_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.vdm.output_get_interfaces_vdm())
        ssh_hook.append()
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.teardown_server(fakes.SERVER_DETAIL,
                                        fakes.SECURITY_SERVICE)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.cifs_server.req_modify(self.vdm.vdm_id)),
            mock.call(self.cifs_server.req_delete(self.vdm.vdm_id)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_delete_interface(
                fakes.FakeData.network_allocations_ip1)),
            mock.call(self.mover.req_delete_interface(
                fakes.FakeData.network_allocations_ip2)),
            mock.call(self.vdm.req_delete()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.vdm.cmd_get_interfaces(), False),
            mock.call(self.vdm.cmd_detach_nfs_interface(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_update_access_add_cifs_rw(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RW_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.update_access(None, share, [], [access], [],
                                      share_server=share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_update_access_add_cifs_rw_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RW_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed(
            interface1=fakes.FakeData.interface_name3,
            interface2=fakes.FakeData.interface_name4))
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True,
            ip_addr=fakes.FakeData.network_allocations_ip3))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.update_access(None, share, [], [access], [],
                                      share_server=share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_update_access_deny_nfs(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.NFS_SHARE
        access = fakes.NFS_RW_ACCESS

        rw_hosts = copy.deepcopy(fakes.FakeData.rw_hosts)
        rw_hosts.append(access['access_to'])

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=rw_hosts,
            ro_hosts=fakes.FakeData.ro_hosts))
        ssh_hook.append(self.nfs_share.output_set_access_success())
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=fakes.FakeData.rw_hosts,
            ro_hosts=fakes.FakeData.ro_hosts))
        ssh_cmd_mock = utils.EMCNFSShareMock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.update_access(None, share, [], [], [access],
                                      share_server=share_server)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), True),
            mock.call(self.nfs_share.cmd_set_access(
                rw_hosts=self.nfs_share.rw_hosts,
                ro_hosts=self.nfs_share.ro_hosts), True),
            mock.call(self.nfs_share.cmd_get(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_update_access_deny_nfs_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.NFS_SHARE
        access = fakes.NFS_RW_ACCESS

        rw_hosts = copy.deepcopy(fakes.FakeData.rw_hosts_ipv6)
        rw_hosts.append(access['access_to'])

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=rw_hosts,
            ro_hosts=fakes.FakeData.ro_hosts_ipv6))
        ssh_hook.append(self.nfs_share.output_set_access_success())
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=fakes.FakeData.rw_hosts_ipv6,
            ro_hosts=fakes.FakeData.ro_hosts_ipv6))
        ssh_cmd_mock = utils.EMCNFSShareMock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.update_access(None, share, [], [], [access],
                                      share_server=share_server)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), True),
            mock.call(self.nfs_share.cmd_set_access(
                rw_hosts=self.nfs_share.rw_hosts_ipv6,
                ro_hosts=self.nfs_share.ro_hosts_ipv6), True),
            mock.call(self.nfs_share.cmd_get(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_update_access_recover_nfs_rule(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.NFS_SHARE
        access = fakes.NFS_RW_ACCESS
        hosts = ['192.168.1.5']

        rw_hosts = copy.deepcopy(fakes.FakeData.rw_hosts)
        rw_hosts.append(access['access_to'])

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=rw_hosts,
            ro_hosts=fakes.FakeData.ro_hosts))
        ssh_hook.append(self.nfs_share.output_set_access_success())
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=hosts,
            ro_hosts=[]))
        ssh_cmd_mock = utils.EMCNFSShareMock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.update_access(None, share, [access], [], [],
                                      share_server=share_server)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), True),
            mock.call(self.nfs_share.cmd_set_access(
                rw_hosts=hosts,
                ro_hosts=[]), True),
            mock.call(self.nfs_share.cmd_get(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_update_access_recover_nfs_rule_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.NFS_SHARE
        access = fakes.NFS_RW_ACCESS_IPV6
        hosts = ['fdf8:f53b:82e1::5']

        rw_hosts = copy.deepcopy(fakes.FakeData.rw_hosts_ipv6)
        rw_hosts.append(access['access_to'])

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=rw_hosts,
            ro_hosts=fakes.FakeData.ro_hosts_ipv6))
        ssh_hook.append(self.nfs_share.output_set_access_success())
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=hosts,
            ro_hosts=[]))
        ssh_cmd_mock = utils.EMCNFSShareMock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.update_access(None, share, [access], [], [],
                                      share_server=share_server)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), True),
            mock.call(self.nfs_share.cmd_set_access(
                rw_hosts=hosts,
                ro_hosts=[]), True),
            mock.call(self.nfs_share.cmd_get(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_update_access_recover_cifs_rule(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RW_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_hook.append(fakes.FakeData.cifs_access)
        ssh_hook.append('Command succeeded')

        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.update_access(None, share, [access], [], [],
                                      share_server=share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access(), True),
            mock.call(self.cifs_share.cmd_get_access(), True),
            mock.call(self.cifs_share.cmd_change_access(
                action='revoke', user='guest'), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_update_access_recover_cifs_rule_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RW_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed(
            interface1=fakes.FakeData.interface_name3,
            interface2=fakes.FakeData.interface_name4))
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True,
            ip_addr=fakes.FakeData.network_allocations_ip3))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_hook.append(fakes.FakeData.cifs_access)
        ssh_hook.append('Command succeeded')

        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.update_access(None, share, [access], [], [],
                                      share_server=share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access(), True),
            mock.call(self.cifs_share.cmd_get_access(), True),
            mock.call(self.cifs_share.cmd_change_access(
                action='revoke', user='guest'), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_cifs_clear_access_server_not_found(self):
        server = fakes.SHARE_SERVER

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True,
            cifs_server_name='cifs_server_name'))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection._cifs_clear_access,
                          'share_name', server, None)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_allow_cifs_rw_access(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RW_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.allow_access(None, share, access, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_allow_cifs_rw_access_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RW_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed(
            interface1=fakes.FakeData.interface_name3,
            interface2=fakes.FakeData.interface_name4))
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True,
            ip_addr=fakes.FakeData.network_allocations_ip3))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.allow_access(None, share, access, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_allow_cifs_ro_access(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RO_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.allow_access(None, share, access, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access('ro'), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_allow_cifs_ro_access_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RO_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed(
            interface1=fakes.FakeData.interface_name3,
            interface2=fakes.FakeData.interface_name4))
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True,
            ip_addr=fakes.FakeData.network_allocations_ip3))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.allow_access(None, share, access, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access('ro'), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_allow_ro_access_without_share_server_name(self):
        share = fakes.CIFS_SHARE
        share_server = copy.deepcopy(fakes.SHARE_SERVER)
        share_server['backend_details'].pop('share_server_name')
        access = fakes.CIFS_RO_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.allow_access(None, share, access, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access('ro'), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_allow_access_with_invalid_access_level(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        access = fake_share.fake_access(access_level='fake_level')

        self.assertRaises(exception.InvalidShareAccessLevel,
                          self.connection.allow_access,
                          None, share, access, share_server)

    def test_allow_access_with_invalid_share_server_name(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RW_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_error())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.allow_access,
                          None, share, access, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_allow_nfs_access(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.NFS_SHARE
        access = fakes.NFS_RW_ACCESS

        rw_hosts = copy.deepcopy(fakes.FakeData.rw_hosts)
        rw_hosts.append(access['access_to'])

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=fakes.FakeData.rw_hosts,
            ro_hosts=fakes.FakeData.ro_hosts))
        ssh_hook.append(self.nfs_share.output_set_access_success())
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=rw_hosts,
            ro_hosts=fakes.FakeData.ro_hosts))
        ssh_cmd_mock = utils.EMCNFSShareMock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.allow_access(None, share, access, share_server)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), True),
            mock.call(self.nfs_share.cmd_set_access(
                rw_hosts=rw_hosts, ro_hosts=self.nfs_share.ro_hosts), True),
            mock.call(self.nfs_share.cmd_get(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_allow_nfs_access_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.NFS_SHARE
        access = fakes.NFS_RW_ACCESS_IPV6

        rw_hosts = copy.deepcopy(fakes.FakeData.rw_hosts_ipv6)
        rw_hosts.append(access['access_to'])

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=fakes.FakeData.rw_hosts_ipv6,
            ro_hosts=fakes.FakeData.ro_hosts_ipv6))
        ssh_hook.append(self.nfs_share.output_set_access_success())
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=rw_hosts,
            ro_hosts=fakes.FakeData.ro_hosts_ipv6))
        ssh_cmd_mock = utils.EMCNFSShareMock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.allow_access(None, share, access, share_server)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), True),
            mock.call(self.nfs_share.cmd_set_access(
                rw_hosts=rw_hosts,
                ro_hosts=self.nfs_share.ro_hosts_ipv6),
                True),
            mock.call(self.nfs_share.cmd_get(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_allow_cifs_access_with_incorrect_access_type(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        access = fake_share.fake_access(access_type='fake_type')

        self.assertRaises(exception.InvalidShareAccess,
                          self.connection.allow_access,
                          None, share, access, share_server)

    def test_allow_nfs_access_with_incorrect_access_type(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.NFS_SHARE
        access = fake_share.fake_access(access_type='fake_type')

        self.assertRaises(exception.InvalidShareAccess,
                          self.connection.allow_access,
                          None, share, access, share_server)

    def test_allow_access_with_incorrect_proto(self):
        share_server = fakes.SHARE_SERVER
        share = fake_share.fake_share(share_proto='FAKE_PROTO')
        access = fake_share.fake_access()

        self.assertRaises(exception.InvalidShare,
                          self.connection.allow_access,
                          None, share, access, share_server)

    def test_deny_cifs_rw_access(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RW_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.deny_access(None, share, access, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access(action='revoke'),
                      True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_deny_cifs_rw_access_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RW_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed(
            interface1=fakes.FakeData.interface_name3,
            interface2=fakes.FakeData.interface_name4))
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True,
            ip_addr=fakes.FakeData.network_allocations_ip3))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.deny_access(None, share, access, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access(action='revoke'),
                      True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_deny_cifs_ro_access(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RO_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.deny_access(None, share, access, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access('ro', 'revoke'), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_deny_cifs_ro_access_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RO_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed(
            interface1=fakes.FakeData.interface_name3,
            interface2=fakes.FakeData.interface_name4))
        hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True,
            ip_addr=fakes.FakeData.network_allocations_ip3))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.cifs_share.output_allow_access())
        ssh_cmd_mock = mock.Mock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.deny_access(None, share, access, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access('ro', 'revoke'), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_deny_cifs_access_with_invliad_share_server_name(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        access = fakes.CIFS_RW_ACCESS

        hook = utils.RequestSideEffect()
        hook.append(self.vdm.resp_get_succeed())
        hook.append(self.cifs_server.resp_get_error())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.deny_access,
                          None, share, access, share_server)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_deny_nfs_access(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.NFS_SHARE
        access = fakes.NFS_RW_ACCESS

        rw_hosts = copy.deepcopy(fakes.FakeData.rw_hosts)
        rw_hosts.append(access['access_to'])

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=rw_hosts,
            ro_hosts=fakes.FakeData.ro_hosts))
        ssh_hook.append(self.nfs_share.output_set_access_success())
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=fakes.FakeData.rw_hosts,
            ro_hosts=fakes.FakeData.ro_hosts))
        ssh_cmd_mock = utils.EMCNFSShareMock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.deny_access(None, share, access, share_server)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), True),
            mock.call(self.nfs_share.cmd_set_access(
                rw_hosts=self.nfs_share.rw_hosts,
                ro_hosts=self.nfs_share.ro_hosts), True),
            mock.call(self.nfs_share.cmd_get(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_deny_nfs_access_with_ipv6(self):
        share_server = fakes.SHARE_SERVER_IPV6
        share = fakes.NFS_SHARE
        access = fakes.NFS_RW_ACCESS_IPV6

        rw_hosts = copy.deepcopy(fakes.FakeData.rw_hosts_ipv6)
        rw_hosts.append(access['access_to'])

        ssh_hook = utils.SSHSideEffect()
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=rw_hosts,
            ro_hosts=fakes.FakeData.ro_hosts_ipv6))
        ssh_hook.append(self.nfs_share.output_set_access_success())
        ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=fakes.FakeData.rw_hosts_ipv6,
            ro_hosts=fakes.FakeData.ro_hosts_ipv6))
        ssh_cmd_mock = utils.EMCNFSShareMock(side_effect=ssh_hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock

        self.connection.deny_access(None, share, access, share_server)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), True),
            mock.call(self.nfs_share.cmd_set_access(
                rw_hosts=self.nfs_share.rw_hosts_ipv6,
                ro_hosts=self.nfs_share.ro_hosts_ipv6), True),
            mock.call(self.nfs_share.cmd_get(), True),
        ]
        ssh_cmd_mock.assert_has_calls(ssh_calls)

    def test_deny_access_with_incorrect_proto(self):
        share_server = fakes.SHARE_SERVER
        share = fake_share.fake_share(share_proto='FAKE_PROTO')
        access = fakes.CIFS_RW_ACCESS

        self.assertRaises(exception.InvalidShare,
                          self.connection.deny_access,
                          None, share, access, share_server)

    def test_deny_cifs_access_with_incorrect_access_type(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.CIFS_SHARE
        access = fake_share.fake_access(access_type='fake_type')

        self.assertRaises(exception.InvalidShareAccess,
                          self.connection.deny_access,
                          None, share, access, share_server)

    def test_deny_nfs_access_with_incorrect_access_type(self):
        share_server = fakes.SHARE_SERVER
        share = fakes.NFS_SHARE
        access = fake_share.fake_access(access_type='fake_type')

        self.assertRaises(exception.InvalidShareAccess,
                          self.connection.deny_access,
                          None, share, access, share_server)

    def test_update_share_stats(self):
        hook = utils.RequestSideEffect()
        hook.append(self.mover.resp_get_ref_succeed())
        hook.append(self.pool.resp_get_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.connection.update_share_stats(fakes.STATS)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.pool.req_get()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        for pool in fakes.STATS['pools']:
            if pool['pool_name'] == fakes.FakeData.pool_name:
                self.assertEqual(fakes.FakeData.pool_total_size,
                                 pool['total_capacity_gb'])

                free_size = (fakes.FakeData.pool_total_size -
                             fakes.FakeData.pool_used_size)
                self.assertEqual(free_size, pool['free_capacity_gb'])

    def test_update_share_stats_without_matched_config_pools(self):
        self.connection.pools = set('fake_pool')

        hook = utils.RequestSideEffect()
        hook.append(self.mover.resp_get_ref_succeed())
        hook.append(self.pool.resp_get_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.update_share_stats,
                          fakes.STATS)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.pool.req_get()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_get_pool(self):
        share = fakes.CIFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.pool.resp_get_succeed())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        pool_name = self.connection.get_pool(share)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.pool.req_get()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

        self.assertEqual(fakes.FakeData.pool_name, pool_name)

    def test_get_pool_failed_to_get_filesystem_info(self):
        share = fakes.CIFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_error())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.get_pool,
                          share)

        expected_calls = [mock.call(self.fs.req_get())]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_get_pool_failed_to_get_pool_info(self):
        share = fakes.CIFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.pool.resp_get_error())
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.get_pool,
                          share)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.pool.req_get()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    def test_get_pool_failed_to_find_matched_pool_name(self):
        share = fakes.CIFS_SHARE

        hook = utils.RequestSideEffect()
        hook.append(self.fs.resp_get_succeed())
        hook.append(self.pool.resp_get_succeed(name='unmatch_pool_name',
                                               id='unmatch_pool_id'))
        xml_req_mock = utils.EMCMock(side_effect=hook)
        self.connection.manager.connectors['XML'].request = xml_req_mock

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.get_pool,
                          share)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.pool.req_get()),
        ]
        xml_req_mock.assert_has_calls(expected_calls)

    @ddt.data({'port_conf': None,
               'managed_ports': ['cge-1-0', 'cge-1-3']},
              {'port_conf': '*',
               'managed_ports': ['cge-1-0', 'cge-1-3']},
              {'port_conf': ['cge-1-*'],
               'managed_ports': ['cge-1-0', 'cge-1-3']},
              {'port_conf': ['cge-1-3'],
               'managed_ports': ['cge-1-3']})
    @ddt.unpack
    def test_get_managed_ports_one_port(self, port_conf, managed_ports):
        hook = utils.SSHSideEffect()
        hook.append(self.mover.output_get_physical_devices())

        ssh_cmd_mock = mock.Mock(side_effect=hook)
        expected_calls = [
            mock.call(self.mover.cmd_get_physical_devices(), False),
        ]
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock
        self.connection.port_conf = port_conf
        ports = self.connection.get_managed_ports()
        self.assertIsInstance(ports, list)
        self.assertEqual(sorted(managed_ports), sorted(ports))
        ssh_cmd_mock.assert_has_calls(expected_calls)

    def test_get_managed_ports_no_valid_port(self):
        hook = utils.SSHSideEffect()
        hook.append(self.mover.output_get_physical_devices())

        ssh_cmd_mock = mock.Mock(side_effect=hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock
        self.connection.port_conf = ['cge-2-0']

        self.assertRaises(exception.BadConfigurationException,
                          self.connection.get_managed_ports)

    def test_get_managed_ports_query_devices_failed(self):
        hook = utils.SSHSideEffect()
        hook.append(self.mover.fake_output)
        ssh_cmd_mock = mock.Mock(side_effect=hook)
        self.connection.manager.connectors['SSH'].run_ssh = ssh_cmd_mock
        self.connection.port_conf = ['cge-2-0']

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.connection.get_managed_ports)
