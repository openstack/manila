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
from oslo_concurrency import processutils

from manila.common import constants as const
from manila import exception
from manila.share.drivers.emc.plugins.vnx import connector
from manila.share.drivers.emc.plugins.vnx import constants
from manila.share.drivers.emc.plugins.vnx import object_manager as manager
from manila import test
from manila.tests.share.drivers.emc.plugins.vnx import fakes
from manila.tests.share.drivers.emc.plugins.vnx import utils


class StorageObjectManagerTestCase(test.TestCase):
    @mock.patch.object(connector, "XMLAPIConnector", mock.Mock())
    @mock.patch.object(connector, "SSHConnector", mock.Mock())
    def setUp(self):
        super(StorageObjectManagerTestCase, self).setUp()

        emd_share_driver = fakes.FakeEMCShareDriver()

        self.manager = manager.StorageObjectManager(
            emd_share_driver.configuration)

    def test_get_storage_context(self):
        type_map = {
            'FileSystem': manager.FileSystem,
            'StoragePool': manager.StoragePool,
            'MountPoint': manager.MountPoint,
            'Mover': manager.Mover,
            'VDM': manager.VDM,
            'Snapshot': manager.Snapshot,
            'MoverInterface': manager.MoverInterface,
            'DNSDomain': manager.DNSDomain,
            'CIFSServer': manager.CIFSServer,
            'CIFSShare': manager.CIFSShare,
            'NFSShare': manager.NFSShare,
        }

        for key, value in type_map.items():
            self.assertTrue(
                isinstance(self.manager.getStorageContext(key), value))

        for key in self.manager.context.keys():
            self.assertTrue(key in type_map)

    def test_get_storage_context_invalid_type(self):

        fake_type = 'fake_type'

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.manager.getStorageContext,
                          fake_type)


class StorageObjectTestCase(test.TestCase):
    @mock.patch.object(connector, "XMLAPIConnector", mock.Mock())
    @mock.patch.object(connector, "SSHConnector", mock.Mock())
    def setUp(self):
        super(StorageObjectTestCase, self).setUp()

        emd_share_driver = fakes.FakeEMCShareDriver()

        self.manager = manager.StorageObjectManager(
            emd_share_driver.configuration)

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


class FileSystemTestCase(StorageObjectTestCase):
    def setUp(self):
        super(self.__class__, self).setUp()
        self.hook = utils.RequestSideEffect()
        self.ssh_hook = utils.SSHSideEffect()

    def test_create_file_system_on_vdm(self):
        self.hook.append(self.pool.resp_get_succeed())
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.fs.resp_task_succeed())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(name=self.fs.filesystem_name,
                       size=self.fs.filesystem_size,
                       pool_name=self.pool.pool_name,
                       mover_name=self.vdm.vdm_name,
                       is_vdm=True)

        expected_calls = [
            mock.call(self.pool.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.fs.req_create_on_vdm()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_create_file_system_on_mover(self):
        self.hook.append(self.pool.resp_get_succeed())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.fs.resp_task_succeed())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(name=self.fs.filesystem_name,
                       size=self.fs.filesystem_size,
                       pool_name=self.pool.pool_name,
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        expected_calls = [
            mock.call(self.pool.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.fs.req_create_on_mover()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_create_file_system_but_already_exist(self):
        self.hook.append(self.pool.resp_get_succeed())
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.fs.resp_create_but_already_exist())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(name=self.fs.filesystem_name,
                       size=self.fs.filesystem_size,
                       pool_name=self.pool.pool_name,
                       mover_name=self.vdm.vdm_name,
                       is_vdm=True)

        expected_calls = [
            mock.call(self.pool.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.fs.req_create_on_vdm()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_create_file_system_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.pool.resp_get_succeed())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.fs.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.fs.resp_task_succeed())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(name=self.fs.filesystem_name,
                       size=self.fs.filesystem_size,
                       pool_name=self.pool.pool_name,
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        expected_calls = [
            mock.call(self.pool.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.fs.req_create_on_mover()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.fs.req_create_on_mover()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_create_file_system_with_error(self):
        self.hook.append(self.pool.resp_get_succeed())
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.fs.resp_task_error())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.create,
                          name=self.fs.filesystem_name,
                          size=self.fs.filesystem_size,
                          pool_name=self.pool.pool_name,
                          mover_name=self.vdm.vdm_name,
                          is_vdm=True)

        expected_calls = [
            mock.call(self.pool.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.fs.req_create_on_vdm()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_file_system(self):
        self.hook.append(self.fs.resp_get_succeed())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.fs.filesystem_name)
        self.assertEqual(constants.STATUS_OK, status)
        self.assertIn(self.fs.filesystem_name, context.filesystem_map)
        property_map = [
            'name',
            'pools_id',
            'volume_id',
            'size',
            'id',
            'type',
            'dataServicePolicies',
        ]
        for prop in property_map:
            self.assertIn(prop, out)

        id = context.get_id(self.fs.filesystem_name)
        self.assertEqual(self.fs.filesystem_id, id)

        expected_calls = [mock.call(self.fs.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_file_system_but_not_found(self):
        self.hook.append(self.fs.resp_get_but_not_found())
        self.hook.append(self.fs.resp_get_without_value())
        self.hook.append(self.fs.resp_get_error())
        self.hook.append(self.fs.resp_get_but_not_found())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.fs.filesystem_name)
        self.assertEqual(constants.STATUS_NOT_FOUND, status)

        status, out = context.get(self.fs.filesystem_name)
        self.assertEqual(constants.STATUS_NOT_FOUND, status)

        status, out = context.get(self.fs.filesystem_name)
        self.assertEqual(constants.STATUS_ERROR, status)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.get_id,
                          self.fs.filesystem_name)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.fs.req_get()),
            mock.call(self.fs.req_get()),
            mock.call(self.fs.req_get()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_file_system_but_miss_property(self):
        self.hook.append(self.fs.resp_get_but_miss_property())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.fs.filesystem_name)
        self.assertEqual(constants.STATUS_OK, status)
        self.assertIn(self.fs.filesystem_name, context.filesystem_map)
        property_map = [
            'name',
            'pools_id',
            'volume_id',
            'size',
            'id',
            'type',
            'dataServicePolicies',
        ]
        for prop in property_map:
            self.assertIn(prop, out)

        self.assertIsNone(out['dataServicePolicies'])

        id = context.get_id(self.fs.filesystem_name)
        self.assertEqual(self.fs.filesystem_id, id)

        expected_calls = [mock.call(self.fs.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_file_system(self):
        self.hook.append(self.fs.resp_get_succeed())
        self.hook.append(self.fs.resp_task_succeed())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(self.fs.filesystem_name)
        self.assertNotIn(self.fs.filesystem_name, context.filesystem_map)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.fs.req_delete()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertNotIn(self.fs.filesystem_name, context.filesystem_map)

    def test_delete_file_system_but_not_found(self):
        self.hook.append(self.fs.resp_get_but_not_found())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(self.fs.filesystem_name)

        expected_calls = [mock.call(self.fs.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_file_system_but_get_file_system_error(self):
        self.hook.append(self.fs.resp_get_error())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.delete,
                          self.fs.filesystem_name)

        expected_calls = [mock.call(self.fs.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_file_system_with_error(self):
        self.hook.append(self.fs.resp_get_succeed())
        self.hook.append(self.fs.resp_delete_but_failed())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.delete,
                          self.fs.filesystem_name)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.fs.req_delete()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertIn(self.fs.filesystem_name, context.filesystem_map)

    def test_extend_file_system(self):
        self.hook.append(self.fs.resp_get_succeed())
        self.hook.append(self.pool.resp_get_succeed())
        self.hook.append(self.fs.resp_task_succeed())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.extend(name=self.fs.filesystem_name,
                       pool_name=self.pool.pool_name,
                       new_size=self.fs.filesystem_new_size)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.pool.req_get()),
            mock.call(self.fs.req_extend()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_extend_file_system_but_not_found(self):
        self.hook.append(self.fs.resp_get_but_not_found())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.extend,
                          name=self.fs.filesystem_name,
                          pool_name=self.fs.pool_name,
                          new_size=self.fs.filesystem_new_size)

        expected_calls = [mock.call(self.fs.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_extend_file_system_with_small_size(self):
        self.hook.append(self.fs.resp_get_succeed())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.extend,
                          name=self.fs.filesystem_name,
                          pool_name=self.pool.pool_name,
                          new_size=1)

        expected_calls = [mock.call(self.fs.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_extend_file_system_with_same_size(self):
        self.hook.append(self.fs.resp_get_succeed())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.extend(name=self.fs.filesystem_name,
                       pool_name=self.pool.pool_name,
                       new_size=self.fs.filesystem_size)

        expected_calls = [mock.call(self.fs.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_extend_file_system_with_error(self):
        self.hook.append(self.fs.resp_get_succeed())
        self.hook.append(self.pool.resp_get_succeed())
        self.hook.append(self.fs.resp_extend_but_error())

        context = self.manager.getStorageContext('FileSystem')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.extend,
                          name=self.fs.filesystem_name,
                          pool_name=self.pool.pool_name,
                          new_size=self.fs.filesystem_new_size)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.pool.req_get()),
            mock.call(self.fs.req_extend()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_create_filesystem_from_snapshot(self):
        self.ssh_hook.append()
        self.ssh_hook.append()
        self.ssh_hook.append(self.fs.output_copy_ckpt)
        self.ssh_hook.append(self.fs.output_info())
        self.ssh_hook.append()
        self.ssh_hook.append()
        self.ssh_hook.append()

        context = self.manager.getStorageContext('FileSystem')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.create_from_snapshot(self.fs.filesystem_name,
                                     self.snap.src_snap_name,
                                     self.fs.src_fileystems_name,
                                     self.pool.pool_name,
                                     self.vdm.vdm_name,
                                     self.mover.interconnect_id,)

        ssh_calls = [
            mock.call(self.fs.cmd_create_from_ckpt(), False),
            mock.call(self.mount.cmd_server_mount('ro'), False),
            mock.call(self.fs.cmd_copy_ckpt(), True),
            mock.call(self.fs.cmd_nas_fs_info(), False),
            mock.call(self.mount.cmd_server_umount(), False),
            mock.call(self.fs.cmd_delete(), False),
            mock.call(self.mount.cmd_server_mount('rw'), False),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_create_filesystem_from_snapshot_with_error(self):
        self.ssh_hook.append()
        self.ssh_hook.append()
        self.ssh_hook.append(ex=processutils.ProcessExecutionError(
            stdout=self.fs.fake_output, stderr=None))
        self.ssh_hook.append(self.fs.output_info())
        self.ssh_hook.append()
        self.ssh_hook.append()
        self.ssh_hook.append()

        context = self.manager.getStorageContext('FileSystem')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.create_from_snapshot(
            self.fs.filesystem_name,
            self.snap.src_snap_name,
            self.fs.src_fileystems_name,
            self.pool.pool_name,
            self.vdm.vdm_name,
            self.mover.interconnect_id, )

        ssh_calls = [
            mock.call(self.fs.cmd_create_from_ckpt(), False),
            mock.call(self.mount.cmd_server_mount('ro'), False),
            mock.call(self.fs.cmd_copy_ckpt(), True),
            mock.call(self.fs.cmd_nas_fs_info(), False),
            mock.call(self.mount.cmd_server_umount(), False),
            mock.call(self.fs.cmd_delete(), False),
            mock.call(self.mount.cmd_server_mount('rw'), False),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)


class MountPointTestCase(StorageObjectTestCase):
    def setUp(self):
        super(self.__class__, self).setUp()
        self.hook = utils.RequestSideEffect()

    def test_create_mount_point_on_vdm(self):
        self.hook.append(self.fs.resp_get_succeed())
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.mount.resp_task_succeed())

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(mount_path=self.mount.path,
                       fs_name=self.fs.filesystem_name,
                       mover_name=self.vdm.vdm_name,
                       is_vdm=True)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.mount.req_create(self.vdm.vdm_id, True)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_create_mount_point_on_mover(self):
        self.hook.append(self.fs.resp_get_succeed())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mount.resp_task_succeed())

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(mount_path=self.mount.path,
                       fs_name=self.fs.filesystem_name,
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mount.req_create(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_create_mount_point_but_already_exist(self):
        self.hook.append(self.fs.resp_get_succeed())
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.mount.resp_create_but_already_exist())

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(mount_path=self.mount.path,
                       fs_name=self.fs.filesystem_name,
                       mover_name=self.vdm.vdm_name,
                       is_vdm=True)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.mount.req_create(self.vdm.vdm_id)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_create_mount_point_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.fs.resp_get_succeed())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mount.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mount.resp_task_succeed())

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(mount_path=self.mount.path,
                       fs_name=self.fs.filesystem_name,
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mount.req_create(self.mover.mover_id, False)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mount.req_create(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_create_mount_point_with_error(self):
        self.hook.append(self.fs.resp_get_succeed())
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.mount.resp_task_error())

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.create,
                          mount_path=self.mount.path,
                          fs_name=self.fs.filesystem_name,
                          mover_name=self.vdm.vdm_name,
                          is_vdm=True)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.mount.req_create(self.vdm.vdm_id)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_mount_point_on_vdm(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.mount.resp_task_succeed())

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(mount_path=self.mount.path,
                       mover_name=self.vdm.vdm_name,
                       is_vdm=True)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.mount.req_delete(self.vdm.vdm_id)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_mount_point_on_mover(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mount.resp_task_succeed())

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(mount_path=self.mount.path,
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mount.req_delete(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_mount_point_but_nonexistent(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.mount.resp_delete_but_nonexistent())

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(mount_path=self.mount.path,
                       mover_name=self.vdm.vdm_name,
                       is_vdm=True)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.mount.req_delete(self.vdm.vdm_id)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_delete_mount_point_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mount.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mount.resp_task_succeed())

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(mount_path=self.mount.path,
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mount.req_delete(self.mover.mover_id, False)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mount.req_delete(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_delete_mount_point_with_error(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.mount.resp_task_error())

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.delete,
                          mount_path=self.mount.path,
                          mover_name=self.vdm.vdm_name,
                          is_vdm=True)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.mount.req_delete(self.vdm.vdm_id)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_mount_points(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.mount.resp_get_succeed(self.vdm.vdm_id))
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mount.resp_get_succeed(self.mover.mover_id,
                                                     False))

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.vdm.vdm_name)
        self.assertEqual(constants.STATUS_OK, status)
        property_map = [
            'path',
            'mover',
            'moverIdIsVdm',
            'fileSystem',
        ]
        for item in out:
            for prop in property_map:
                self.assertIn(prop, item)

        status, out = context.get(self.mover.mover_name, False)
        self.assertEqual(constants.STATUS_OK, status)
        property_map = [
            'path',
            'mover',
            'moverIdIsVdm',
            'fileSystem',
        ]
        for item in out:
            for prop in property_map:
                self.assertIn(prop, item)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.mount.req_get(self.vdm.vdm_id)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mount.req_get(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_mount_points_but_not_found(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mount.resp_get_without_value())

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.mover.mover_name, False)
        self.assertEqual(constants.STATUS_NOT_FOUND, status)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mount.req_get(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_get_mount_points_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mount.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mount.resp_get_succeed(self.mover.mover_id,
                                                     False))

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.mover.mover_name, False)
        self.assertEqual(constants.STATUS_OK, status)

        property_map = [
            'path',
            'mover',
            'moverIdIsVdm',
            'fileSystem',
        ]
        for item in out:
            for prop in property_map:
                self.assertIn(prop, item)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mount.req_get(self.mover.mover_id, False)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mount.req_get(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_get_mount_points_with_error(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mount.resp_get_error())

        context = self.manager.getStorageContext('MountPoint')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.mover.mover_name, False)
        self.assertEqual(constants.STATUS_ERROR, status)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mount.req_get(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)


class VDMTestCase(StorageObjectTestCase):
    def setUp(self):
        super(self.__class__, self).setUp()
        self.hook = utils.RequestSideEffect()
        self.ssh_hook = utils.SSHSideEffect()

    def test_create_vdm(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.vdm.resp_task_succeed())

        context = self.manager.getStorageContext('VDM')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(self.vdm.vdm_name, self.mover.mover_name)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.vdm.req_create()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_create_vdm_but_already_exist(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.vdm.resp_create_but_already_exist())

        context = self.manager.getStorageContext('VDM')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        # Create VDM which already exists.
        context.create(self.vdm.vdm_name, self.mover.mover_name)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.vdm.req_create()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_create_vdm_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.vdm.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.vdm.resp_task_succeed())

        context = self.manager.getStorageContext('VDM')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        # Create VDM with invalid mover ID
        context.create(self.vdm.vdm_name, self.mover.mover_name)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.vdm.req_create()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.vdm.req_create()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_create_vdm_with_error(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.vdm.resp_task_error())

        context = self.manager.getStorageContext('VDM')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        # Create VDM with invalid mover ID
        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.create,
                          name=self.vdm.vdm_name,
                          mover_name=self.mover.mover_name)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.vdm.req_create()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_vdm(self):
        self.hook.append(self.vdm.resp_get_succeed())

        context = self.manager.getStorageContext('VDM')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.vdm.vdm_name)
        self.assertEqual(constants.STATUS_OK, status)
        self.assertIn(self.vdm.vdm_name, context.vdm_map)
        property_map = [
            'name',
            'id',
            'state',
            'host_mover_id',
            'interfaces',
        ]
        for prop in property_map:
            self.assertIn(prop, out)

        expected_calls = [mock.call(self.vdm.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_vdm_with_error(self):
        self.hook.append(self.vdm.resp_get_error())

        context = self.manager.getStorageContext('VDM')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        # Get VDM with error
        status, out = context.get(self.vdm.vdm_name)
        self.assertEqual(constants.STATUS_ERROR, status)

        expected_calls = [mock.call(self.vdm.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_vdm_but_not_found(self):
        self.hook.append(self.vdm.resp_get_without_value())
        self.hook.append(self.vdm.resp_get_succeed('fake'))

        context = self.manager.getStorageContext('VDM')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        # Get VDM which does not exist
        status, out = context.get(self.vdm.vdm_name)
        self.assertEqual(constants.STATUS_NOT_FOUND, status)

        status, out = context.get(self.vdm.vdm_name)
        self.assertEqual(constants.STATUS_NOT_FOUND, status)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.vdm.req_get()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_vdm_id_with_error(self):
        self.hook.append(self.vdm.resp_get_error())

        context = self.manager.getStorageContext('VDM')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.get_id,
                          self.vdm.vdm_name)

        expected_calls = [mock.call(self.vdm.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_vdm(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.vdm.resp_task_succeed())

        context = self.manager.getStorageContext('VDM')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(self.vdm.vdm_name)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.vdm.req_delete()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_vdm_but_not_found(self):
        self.hook.append(self.vdm.resp_get_but_not_found())

        context = self.manager.getStorageContext('VDM')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(self.vdm.vdm_name)

        expected_calls = [mock.call(self.vdm.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_vdm_but_failed_to_get_vdm(self):
        self.hook.append(self.vdm.resp_get_error())

        context = self.manager.getStorageContext('VDM')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.delete,
                          self.vdm.vdm_name)

        expected_calls = [mock.call(self.vdm.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_vdm_with_error(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.vdm.resp_task_error())

        context = self.manager.getStorageContext('VDM')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.delete,
                          self.vdm.vdm_name)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.vdm.req_delete()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_attach_detach_nfs_interface(self):
        self.ssh_hook.append()
        self.ssh_hook.append()

        context = self.manager.getStorageContext('VDM')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.attach_nfs_interface(self.vdm.vdm_name,
                                     self.mover.interface_name2)
        context.detach_nfs_interface(self.vdm.vdm_name,
                                     self.mover.interface_name2)

        ssh_calls = [
            mock.call(self.vdm.cmd_attach_nfs_interface(), False),
            mock.call(self.vdm.cmd_detach_nfs_interface(), True),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_detach_nfs_interface_with_error(self):
        self.ssh_hook.append(ex=processutils.ProcessExecutionError(
            stdout=self.vdm.fake_output))
        self.ssh_hook.append(self.vdm.output_get_interfaces(
            self.mover.interface_name2))
        self.ssh_hook.append(ex=processutils.ProcessExecutionError(
            stdout=self.vdm.fake_output))
        self.ssh_hook.append(self.vdm.output_get_interfaces(
            nfs_interface=fakes.FakeData.interface_name1))

        context = self.manager.getStorageContext('VDM')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.detach_nfs_interface,
                          self.vdm.vdm_name,
                          self.mover.interface_name2)

        context.detach_nfs_interface(self.vdm.vdm_name,
                                     self.mover.interface_name2)

        ssh_calls = [
            mock.call(self.vdm.cmd_detach_nfs_interface(), True),
            mock.call(self.vdm.cmd_get_interfaces(), False),
            mock.call(self.vdm.cmd_detach_nfs_interface(), True),
            mock.call(self.vdm.cmd_get_interfaces(), False),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_get_cifs_nfs_interface(self):
        self.ssh_hook.append(self.vdm.output_get_interfaces())

        context = self.manager.getStorageContext('VDM')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        interfaces = context.get_interfaces(self.vdm.vdm_name)
        self.assertIsNotNone(interfaces['cifs'])
        self.assertIsNotNone(interfaces['nfs'])

        ssh_calls = [mock.call(self.vdm.cmd_get_interfaces(), False)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)


class StoragePoolTestCase(StorageObjectTestCase):
    def setUp(self):
        super(self.__class__, self).setUp()
        self.hook = utils.RequestSideEffect()

    def test_get_pool(self):
        self.hook.append(self.pool.resp_get_succeed())

        context = self.manager.getStorageContext('StoragePool')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.pool.pool_name)
        self.assertEqual(constants.STATUS_OK, status)
        self.assertIn(self.pool.pool_name, context.pool_map)
        property_map = [
            'name',
            'movers_id',
            'total_size',
            'used_size',
            'diskType',
            'dataServicePolicies',
            'id',
        ]
        for prop in property_map:
            self.assertIn(prop, out)

        expected_calls = [mock.call(self.pool.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_pool_with_error(self):
        self.hook.append(self.pool.resp_get_error())
        self.hook.append(self.pool.resp_get_without_value())
        self.hook.append(self.pool.resp_get_succeed(name='other'))

        context = self.manager.getStorageContext('StoragePool')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.pool.pool_name)
        self.assertEqual(constants.STATUS_ERROR, status)

        status, out = context.get(self.pool.pool_name)
        self.assertEqual(constants.STATUS_NOT_FOUND, status)

        status, out = context.get(self.pool.pool_name)
        self.assertEqual(constants.STATUS_NOT_FOUND, status)

        expected_calls = [
            mock.call(self.pool.req_get()),
            mock.call(self.pool.req_get()),
            mock.call(self.pool.req_get()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_pool_id_with_error(self):
        self.hook.append(self.pool.resp_get_error())

        context = self.manager.getStorageContext('StoragePool')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.get_id,
                          self.pool.pool_name)

        expected_calls = [mock.call(self.pool.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)


class MoverTestCase(StorageObjectTestCase):
    def setUp(self):
        super(self.__class__, self).setUp()
        self.hook = utils.RequestSideEffect()
        self.ssh_hook = utils.SSHSideEffect()

    def test_get_mover(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_get_succeed())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_get_succeed())

        context = self.manager.getStorageContext('Mover')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.mover.mover_name)
        self.assertEqual(constants.STATUS_OK, status)
        self.assertIn(self.mover.mover_name, context.mover_map)
        property_map = [
            'name',
            'id',
            'Status',
            'version',
            'uptime',
            'role',
            'interfaces',
            'devices',
            'dns_domain',
        ]
        for prop in property_map:
            self.assertIn(prop, out)

        status, out = context.get(self.mover.mover_name)
        self.assertEqual(constants.STATUS_OK, status)

        status, out = context.get(self.mover.mover_name, True)
        self.assertEqual(constants.STATUS_OK, status)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_get()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_mover_ref_not_found(self):
        self.hook.append(self.mover.resp_get_ref_succeed(name='other'))

        context = self.manager.getStorageContext('Mover')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get_ref(self.mover.mover_name)
        self.assertEqual(constants.STATUS_NOT_FOUND, status)

        expected_calls = [mock.call(self.mover.req_get_ref())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_mover_ref_with_error(self):
        self.hook.append(self.mover.resp_get_error())

        context = self.manager.getStorageContext('Mover')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get_ref(self.mover.mover_name)
        self.assertEqual(constants.STATUS_ERROR, status)

        expected_calls = [mock.call(self.mover.req_get_ref())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_mover_ref_and_mover(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_get_succeed())

        context = self.manager.getStorageContext('Mover')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get_ref(self.mover.mover_name)
        self.assertEqual(constants.STATUS_OK, status)
        property_map = ['name', 'id']
        for prop in property_map:
            self.assertIn(prop, out)

        status, out = context.get(self.mover.mover_name)
        self.assertEqual(constants.STATUS_OK, status)
        self.assertIn(self.mover.mover_name, context.mover_map)
        property_map = [
            'name',
            'id',
            'Status',
            'version',
            'uptime',
            'role',
            'interfaces',
            'devices',
            'dns_domain',
        ]
        for prop in property_map:
            self.assertIn(prop, out)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_get()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_mover_failed_to_get_mover_ref(self):
        self.hook.append(self.mover.resp_get_error())

        context = self.manager.getStorageContext('Mover')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.get,
                          self.mover.mover_name)

        expected_calls = [mock.call(self.mover.req_get_ref())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_mover_but_not_found(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_get_without_value())

        context = self.manager.getStorageContext('Mover')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(name=self.mover.mover_name, force=True)
        self.assertEqual(constants.STATUS_NOT_FOUND, status)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_get()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_mover_with_error(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_get_error())

        context = self.manager.getStorageContext('Mover')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.mover.mover_name)
        self.assertEqual(constants.STATUS_ERROR, status)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_get()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_interconnect_id(self):
        self.ssh_hook.append(self.mover.output_get_interconnect_id())

        context = self.manager.getStorageContext('Mover')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        conn_id = context.get_interconnect_id(self.mover.mover_name,
                                              self.mover.mover_name)
        self.assertEqual(self.mover.interconnect_id, conn_id)

        ssh_calls = [mock.call(self.mover.cmd_get_interconnect_id(), False)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_get_physical_devices(self):
        self.ssh_hook.append(self.mover.output_get_physical_devices())

        context = self.manager.getStorageContext('Mover')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        devices = context.get_physical_devices(self.mover.mover_name)
        self.assertIn(self.mover.device_name, devices)

        ssh_calls = [mock.call(self.mover.cmd_get_physical_devices(), False)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)


class SnapshotTestCase(StorageObjectTestCase):
    def setUp(self):
        super(self.__class__, self).setUp()
        self.hook = utils.RequestSideEffect()

    def test_create_snapshot(self):
        self.hook.append(self.fs.resp_get_succeed())
        self.hook.append(self.snap.resp_task_succeed())

        context = self.manager.getStorageContext('Snapshot')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(name=self.snap.snapshot_name,
                       fs_name=self.fs.filesystem_name,
                       pool_id=self.pool.pool_id)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.snap.req_create()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_create_snapshot_but_already_exist(self):
        self.hook.append(self.fs.resp_get_succeed())
        self.hook.append(self.snap.resp_create_but_already_exist())

        context = self.manager.getStorageContext('Snapshot')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(name=self.snap.snapshot_name,
                       fs_name=self.fs.filesystem_name,
                       pool_id=self.pool.pool_id,
                       ckpt_size=self.snap.snapshot_size)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.snap.req_create_with_size()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_create_snapshot_with_error(self):
        self.hook.append(self.fs.resp_get_succeed())
        self.hook.append(self.snap.resp_task_error())

        context = self.manager.getStorageContext('Snapshot')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.create,
                          name=self.snap.snapshot_name,
                          fs_name=self.fs.filesystem_name,
                          pool_id=self.pool.pool_id,
                          ckpt_size=self.snap.snapshot_size)

        expected_calls = [
            mock.call(self.fs.req_get()),
            mock.call(self.snap.req_create_with_size()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_snapshot(self):
        self.hook.append(self.snap.resp_get_succeed())

        context = self.manager.getStorageContext('Snapshot')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.snap.snapshot_name)
        self.assertEqual(constants.STATUS_OK, status)
        self.assertIn(self.snap.snapshot_name, context.snap_map)
        property_map = [
            'name',
            'id',
            'checkpointOf',
            'state',
        ]
        for prop in property_map:
            self.assertIn(prop, out)

        expected_calls = [mock.call(self.snap.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_snapshot_but_not_found(self):
        self.hook.append(self.snap.resp_get_without_value())

        context = self.manager.getStorageContext('Snapshot')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.snap.snapshot_name)
        self.assertEqual(constants.STATUS_NOT_FOUND, status)

        expected_calls = [mock.call(self.snap.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_snapshot_with_error(self):
        self.hook.append(self.snap.resp_get_error())

        context = self.manager.getStorageContext('Snapshot')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(self.snap.snapshot_name)
        self.assertEqual(constants.STATUS_ERROR, status)

        expected_calls = [mock.call(self.snap.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_snapshot(self):
        self.hook.append(self.snap.resp_get_succeed())
        self.hook.append(self.snap.resp_task_succeed())

        context = self.manager.getStorageContext('Snapshot')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(self.snap.snapshot_name)
        self.assertNotIn(self.snap.snapshot_name, context.snap_map)

        expected_calls = [
            mock.call(self.snap.req_get()),
            mock.call(self.snap.req_delete()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_snapshot_failed_to_get_snapshot(self):
        self.hook.append(self.snap.resp_get_error())

        context = self.manager.getStorageContext('Snapshot')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.delete,
                          self.snap.snapshot_name)

        expected_calls = [mock.call(self.snap.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_snapshot_but_not_found(self):
        self.hook.append(self.snap.resp_get_without_value())

        context = self.manager.getStorageContext('Snapshot')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(self.snap.snapshot_name)
        self.assertNotIn(self.snap.snapshot_name, context.snap_map)

        expected_calls = [mock.call(self.snap.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_snapshot_with_error(self):
        self.hook.append(self.snap.resp_get_succeed())
        self.hook.append(self.snap.resp_task_error())

        context = self.manager.getStorageContext('Snapshot')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.delete,
                          self.snap.snapshot_name)

        expected_calls = [
            mock.call(self.snap.req_get()),
            mock.call(self.snap.req_delete()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_snapshot_id(self):
        self.hook.append(self.snap.resp_get_succeed())

        context = self.manager.getStorageContext('Snapshot')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        id = context.get_id(self.snap.snapshot_name)
        self.assertEqual(self.snap.snapshot_id, id)

        expected_calls = [mock.call(self.snap.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_snapshot_id_with_error(self):
        self.hook.append(self.snap.resp_get_error())

        context = self.manager.getStorageContext('Snapshot')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.get_id,
                          self.snap.snapshot_name)

        expected_calls = [mock.call(self.snap.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)


@ddt.ddt
class MoverInterfaceTestCase(StorageObjectTestCase):
    def setUp(self):
        super(self.__class__, self).setUp()
        self.hook = utils.RequestSideEffect()

    def test_create_mover_interface(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_task_succeed())
        self.hook.append(self.mover.resp_task_succeed())

        context = self.manager.getStorageContext('MoverInterface')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        interface = {
            'name': self.mover.interface_name1,
            'device_name': self.mover.device_name,
            'ip': self.mover.ip_address1,
            'mover_name': self.mover.mover_name,
            'net_mask': self.mover.net_mask,
            'vlan_id': self.mover.vlan_id,
        }
        context.create(interface)

        interface['name'] = self.mover.long_interface_name
        context.create(interface)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_create_interface()),
            mock.call(self.mover.req_create_interface(
                self.mover.long_interface_name[:31])),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_create_mover_interface_name_already_exist(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(
            self.mover.resp_create_interface_but_name_already_exist())

        context = self.manager.getStorageContext('MoverInterface')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        interface = {
            'name': self.mover.interface_name1,
            'device_name': self.mover.device_name,
            'ip': self.mover.ip_address1,
            'mover_name': self.mover.mover_name,
            'net_mask': self.mover.net_mask,
            'vlan_id': self.mover.vlan_id,
        }
        context.create(interface)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_create_interface()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_create_mover_interface_ip_already_exist(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(
            self.mover.resp_create_interface_but_ip_already_exist())

        context = self.manager.getStorageContext('MoverInterface')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        interface = {
            'name': self.mover.interface_name1,
            'device_name': self.mover.device_name,
            'ip': self.mover.ip_address1,
            'mover_name': self.mover.mover_name,
            'net_mask': self.mover.net_mask,
            'vlan_id': self.mover.vlan_id,
        }
        context.create(interface)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_create_interface()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @ddt.data(fakes.MoverTestData().resp_task_succeed(),
              fakes.MoverTestData().resp_task_error())
    def test_create_mover_interface_with_conflict_vlan_id(self, xml_resp):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(
            self.mover.resp_create_interface_with_conflicted_vlan_id())
        self.hook.append(xml_resp)

        context = self.manager.getStorageContext('MoverInterface')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        interface = {
            'name': self.mover.interface_name1,
            'device_name': self.mover.device_name,
            'ip': self.mover.ip_address1,
            'mover_name': self.mover.mover_name,
            'net_mask': self.mover.net_mask,
            'vlan_id': self.mover.vlan_id,
        }
        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.create,
                          interface)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_create_interface()),
            mock.call(self.mover.req_delete_interface()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_create_mover_interface_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_task_succeed())

        context = self.manager.getStorageContext('MoverInterface')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        interface = {
            'name': self.mover.interface_name1,
            'device_name': self.mover.device_name,
            'ip': self.mover.ip_address1,
            'mover_name': self.mover.mover_name,
            'net_mask': self.mover.net_mask,
            'vlan_id': self.mover.vlan_id,
        }
        context.create(interface)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_create_interface()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_create_interface()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_create_mover_interface_with_error(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_task_error())

        context = self.manager.getStorageContext('MoverInterface')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        interface = {
            'name': self.mover.interface_name1,
            'device_name': self.mover.device_name,
            'ip': self.mover.ip_address1,
            'mover_name': self.mover.mover_name,
            'net_mask': self.mover.net_mask,
            'vlan_id': self.mover.vlan_id,
        }
        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.create,
                          interface)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_create_interface()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_mover_interface(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_get_succeed())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_get_succeed())

        context = self.manager.getStorageContext('MoverInterface')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(name=self.mover.interface_name1,
                                  mover_name=self.mover.mover_name)
        self.assertEqual(constants.STATUS_OK, status)
        property_map = [
            'name',
            'device',
            'up',
            'ipVersion',
            'netMask',
            'ipAddress',
            'vlanid',
        ]
        for prop in property_map:
            self.assertIn(prop, out)

        context.get(name=self.mover.long_interface_name,
                    mover_name=self.mover.mover_name)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_get()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_mover_interface_not_found(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_get_without_value())

        context = self.manager.getStorageContext('MoverInterface')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(name=self.mover.interface_name1,
                                  mover_name=self.mover.mover_name)
        self.assertEqual(constants.STATUS_NOT_FOUND, status)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_get()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_mover_interface(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_task_succeed())

        context = self.manager.getStorageContext('MoverInterface')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(ip_addr=self.mover.ip_address1,
                       mover_name=self.mover.mover_name)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_delete_interface()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_mover_interface_but_nonexistent(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_delete_interface_but_nonexistent())

        context = self.manager.getStorageContext('MoverInterface')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(ip_addr=self.mover.ip_address1,
                       mover_name=self.mover.mover_name)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_delete_interface()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_delete_mover_interface_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_task_succeed())

        context = self.manager.getStorageContext('MoverInterface')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(ip_addr=self.mover.ip_address1,
                       mover_name=self.mover.mover_name)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_delete_interface()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_delete_interface()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_delete_mover_interface_with_error(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.mover.resp_task_error())

        context = self.manager.getStorageContext('MoverInterface')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.delete,
                          ip_addr=self.mover.ip_address1,
                          mover_name=self.mover.mover_name)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_delete_interface()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)


class DNSDomainTestCase(StorageObjectTestCase):
    def setUp(self):
        super(self.__class__, self).setUp()
        self.hook = utils.RequestSideEffect()

    def test_create_dns_domain(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.dns.resp_task_succeed())

        context = self.manager.getStorageContext('DNSDomain')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(mover_name=self.mover.mover_name,
                       name=self.dns.domain_name,
                       servers=self.dns.dns_ip_address)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.dns.req_create()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_create_dns_domain_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.dns.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.dns.resp_task_succeed())

        context = self.manager.getStorageContext('DNSDomain')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(mover_name=self.mover.mover_name,
                       name=self.dns.domain_name,
                       servers=self.dns.dns_ip_address)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.dns.req_create()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.dns.req_create()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_create_dns_domain_with_error(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.dns.resp_task_error())

        context = self.manager.getStorageContext('DNSDomain')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.create,
                          mover_name=self.mover.mover_name,
                          name=self.mover.domain_name,
                          servers=self.dns.dns_ip_address)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.dns.req_create()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_dns_domain(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.dns.resp_task_succeed())
        self.hook.append(self.dns.resp_task_error())

        context = self.manager.getStorageContext('DNSDomain')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(mover_name=self.mover.mover_name,
                       name=self.mover.domain_name)

        context.delete(mover_name=self.mover.mover_name,
                       name=self.mover.domain_name)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.dns.req_delete()),
            mock.call(self.dns.req_delete()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_delete_dns_domain_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.dns.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.dns.resp_task_succeed())

        context = self.manager.getStorageContext('DNSDomain')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(mover_name=self.mover.mover_name,
                       name=self.mover.domain_name)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.dns.req_delete()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.dns.req_delete()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)


class CIFSServerTestCase(StorageObjectTestCase):
    def setUp(self):
        super(self.__class__, self).setUp()
        self.hook = utils.RequestSideEffect()

    def test_create_cifs_server(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_server.resp_task_succeed())
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_server.resp_task_succeed())
        self.hook.append(self.cifs_server.resp_task_error())
        self.hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        # Create CIFS server on mover
        cifs_server_args = {
            'name': self.cifs_server.cifs_server_name,
            'interface_ip': self.cifs_server.ip_address1,
            'domain_name': self.cifs_server.domain_name,
            'user_name': self.cifs_server.domain_user,
            'password': self.cifs_server.domain_password,
            'mover_name': self.mover.mover_name,
            'is_vdm': False,
        }
        context.create(cifs_server_args)

        # Create CIFS server on VDM
        cifs_server_args = {
            'name': self.cifs_server.cifs_server_name,
            'interface_ip': self.cifs_server.ip_address1,
            'domain_name': self.cifs_server.domain_name,
            'user_name': self.cifs_server.domain_user,
            'password': self.cifs_server.domain_password,
            'mover_name': self.vdm.vdm_name,
            'is_vdm': True,
        }
        context.create(cifs_server_args)

        # Create CIFS server on VDM
        cifs_server_args = {
            'name': self.cifs_server.cifs_server_name,
            'interface_ip': self.cifs_server.ip_address1,
            'domain_name': self.cifs_server.domain_name,
            'user_name': self.cifs_server.domain_user,
            'password': self.cifs_server.domain_password,
            'mover_name': self.vdm.vdm_name,
            'is_vdm': True,
        }
        context.create(cifs_server_args)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_server.req_create(self.mover.mover_id, False)),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_create(self.vdm.vdm_id)),
            mock.call(self.cifs_server.req_create(self.vdm.vdm_id)),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_create_cifs_server_already_exist(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_server.resp_task_error())
        self.hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

    @mock.patch('time.sleep')
    def test_create_cifs_server_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_server.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_server.resp_task_succeed())

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        # Create CIFS server on mover
        cifs_server_args = {
            'name': self.cifs_server.cifs_server_name,
            'interface_ip': self.cifs_server.ip_address1,
            'domain_name': self.cifs_server.domain_name,
            'user_name': self.cifs_server.domain_user,
            'password': self.cifs_server.domain_password,
            'mover_name': self.mover.mover_name,
            'is_vdm': False,
        }
        context.create(cifs_server_args)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_server.req_create(self.mover.mover_id, False)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_server.req_create(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_create_cifs_server_with_error(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_server.resp_task_error())
        self.hook.append(self.cifs_server.resp_get_error())

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        # Create CIFS server on VDM
        cifs_server_args = {
            'name': self.cifs_server.cifs_server_name,
            'interface_ip': self.cifs_server.ip_address1,
            'domain_name': self.cifs_server.domain_name,
            'user_name': self.cifs_server.domain_user,
            'password': self.cifs_server.domain_password,
            'mover_name': self.vdm.vdm_name,
            'is_vdm': True,
        }
        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.create,
                          cifs_server_args)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_create(self.vdm.vdm_id)),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_all_cifs_server(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))
        self.hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get_all(self.vdm.vdm_name)
        self.assertEqual(constants.STATUS_OK, status)
        self.assertIn(self.vdm.vdm_name, context.cifs_server_map)

        # Get CIFS server from the cache
        status, out = context.get_all(self.vdm.vdm_name)
        self.assertEqual(constants.STATUS_OK, status)
        self.assertIn(self.vdm.vdm_name, context.cifs_server_map)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_get_all_cifs_server_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_server.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.mover.mover_id, is_vdm=False, join_domain=True))

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get_all(self.mover.mover_name, False)
        self.assertEqual(constants.STATUS_OK, status)
        self.assertIn(self.mover.mover_name, context.cifs_server_map)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_server.req_get(self.mover.mover_id, False)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_server.req_get(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_get_cifs_server(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True))

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        status, out = context.get(name=self.cifs_server.cifs_server_name,
                                  mover_name=self.vdm.vdm_name)
        self.assertEqual(constants.STATUS_OK, status)
        property_map = {
            'name',
            'compName',
            'Aliases',
            'type',
            'interfaces',
            'domain',
            'domainJoined',
            'mover',
            'moverIdIsVdm',
        }
        for prop in property_map:
            self.assertIn(prop, out)

        context.get(name=self.cifs_server.cifs_server_name,
                    mover_name=self.vdm.vdm_name)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_modify_cifs_server(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_server.resp_task_succeed())
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_server.resp_task_succeed())

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        cifs_server_args = {
            'name': self.cifs_server.cifs_server_name[-14:],
            'join_domain': True,
            'user_name': self.cifs_server.domain_user,
            'password': self.cifs_server.domain_password,
            'mover_name': self.mover.mover_name,
            'is_vdm': False,
        }
        context.modify(cifs_server_args)

        cifs_server_args = {
            'name': self.cifs_server.cifs_server_name[-14:],
            'join_domain': False,
            'user_name': self.cifs_server.domain_user,
            'password': self.cifs_server.domain_password,
            'mover_name': self.vdm.vdm_name,
        }
        context.modify(cifs_server_args)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_server.req_modify(
                mover_id=self.mover.mover_id, is_vdm=False, join_domain=True)),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_modify(
                mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_modify_cifs_server_but_unjoin_domain(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_server.resp_modify_but_unjoin_domain())

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        cifs_server_args = {
            'name': self.cifs_server.cifs_server_name[-14:],
            'join_domain': False,
            'user_name': self.cifs_server.domain_user,
            'password': self.cifs_server.domain_password,
            'mover_name': self.vdm.vdm_name,
        }

        context.modify(cifs_server_args)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_modify(
                mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_modify_cifs_server_but_already_join_domain(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(
            self.cifs_server.resp_modify_but_already_join_domain())

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        cifs_server_args = {
            'name': self.cifs_server.cifs_server_name[-14:],
            'join_domain': True,
            'user_name': self.cifs_server.domain_user,
            'password': self.cifs_server.domain_password,
            'mover_name': self.vdm.vdm_name,
        }

        context.modify(cifs_server_args)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_modify(
                mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=True)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_modify_cifs_server_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_server.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_server.resp_task_succeed())

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        cifs_server_args = {
            'name': self.cifs_server.cifs_server_name[-14:],
            'join_domain': True,
            'user_name': self.cifs_server.domain_user,
            'password': self.cifs_server.domain_password,
            'mover_name': self.mover.mover_name,
            'is_vdm': False,
        }
        context.modify(cifs_server_args)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_server.req_modify(
                mover_id=self.mover.mover_id, is_vdm=False, join_domain=True)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_server.req_modify(
                mover_id=self.mover.mover_id, is_vdm=False, join_domain=True)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_modify_cifs_server_with_error(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_server.resp_task_error())

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        cifs_server_args = {
            'name': self.cifs_server.cifs_server_name[-14:],
            'join_domain': False,
            'user_name': self.cifs_server.domain_user,
            'password': self.cifs_server.domain_password,
            'mover_name': self.vdm.vdm_name,
        }
        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.modify,
                          cifs_server_args)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_modify(
                mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_cifs_server(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.mover.mover_id, is_vdm=False, join_domain=True))
        self.hook.append(self.cifs_server.resp_task_succeed())
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.vdm.vdm_id, is_vdm=True, join_domain=False))
        self.hook.append(self.cifs_server.resp_task_succeed())

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(computer_name=self.cifs_server.cifs_server_name,
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        context.delete(computer_name=self.cifs_server.cifs_server_name,
                       mover_name=self.vdm.vdm_name)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_server.req_get(self.mover.mover_id, False)),
            mock.call(self.cifs_server.req_delete(self.mover.mover_id, False)),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_server.req_get(self.vdm.vdm_id)),
            mock.call(self.cifs_server.req_delete(self.vdm.vdm_id)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_cifs_server_but_not_found(self):
        self.hook.append(self.mover.resp_get_without_value())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_server.resp_get_without_value())

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(computer_name=self.cifs_server.cifs_server_name,
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        context.delete(computer_name=self.cifs_server.cifs_server_name,
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_server.req_get(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_cifs_server_with_error(self):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_server.resp_get_succeed(
            mover_id=self.mover.mover_id, is_vdm=False, join_domain=True))
        self.hook.append(self.cifs_server.resp_task_error())

        context = self.manager.getStorageContext('CIFSServer')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.delete,
                          computer_name=self.cifs_server.cifs_server_name,
                          mover_name=self.mover.mover_name,
                          is_vdm=False)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_server.req_get(self.mover.mover_id, False)),
            mock.call(self.cifs_server.req_delete(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)


class CIFSShareTestCase(StorageObjectTestCase):
    def setUp(self):
        super(self.__class__, self).setUp()
        self.hook = utils.RequestSideEffect()
        self.ssh_hook = utils.SSHSideEffect()

    def test_create_cifs_share(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_share.resp_task_succeed())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_share.resp_task_succeed())

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(name=self.cifs_share.share_name,
                       server_name=self.cifs_share.cifs_server_name[-14:],
                       mover_name=self.vdm.vdm_name,
                       is_vdm=True)

        context.create(name=self.cifs_share.share_name,
                       server_name=self.cifs_share.cifs_server_name[-14:],
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_share.req_create(self.vdm.vdm_id)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_share.req_create(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_create_cifs_share_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_share.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_share.resp_task_succeed())

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.create(name=self.cifs_share.share_name,
                       server_name=self.cifs_share.cifs_server_name[-14:],
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        expected_calls = [
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_share.req_create(self.mover.mover_id, False)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_share.req_create(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_create_cifs_share_with_error(self):
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_share.resp_task_error())

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.create,
                          name=self.cifs_share.share_name,
                          server_name=self.cifs_share.cifs_server_name[-14:],
                          mover_name=self.vdm.vdm_name,
                          is_vdm=True)

        expected_calls = [
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_share.req_create(self.vdm.vdm_id)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_cifs_share(self):
        self.hook.append(self.cifs_share.resp_get_succeed(self.vdm.vdm_id))
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_share.resp_task_succeed())
        self.hook.append(self.cifs_share.resp_get_succeed(self.mover.mover_id,
                                                          False))
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_share.resp_task_succeed())

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(name=self.cifs_share.share_name,
                       mover_name=self.vdm.vdm_name,
                       is_vdm=True)

        context.delete(name=self.cifs_share.share_name,
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        expected_calls = [
            mock.call(self.cifs_share.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_share.req_delete(self.vdm.vdm_id)),
            mock.call(self.cifs_share.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_share.req_delete(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_delete_cifs_share_not_found(self):
        self.hook.append(self.cifs_share.resp_get_error())
        self.hook.append(self.cifs_share.resp_get_without_value())

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.delete,
                          name=self.cifs_share.share_name,
                          mover_name=self.vdm.vdm_name,
                          is_vdm=True)

        context.delete(name=self.cifs_share.share_name,
                       mover_name=self.vdm.vdm_name,
                       is_vdm=True)

        expected_calls = [
            mock.call(self.cifs_share.req_get()),
            mock.call(self.cifs_share.req_get()),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    @mock.patch('time.sleep')
    def test_delete_cifs_share_invalid_mover_id(self, sleep_mock):
        self.hook.append(self.cifs_share.resp_get_succeed(self.mover.mover_id,
                                                          False))
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_share.resp_invalid_mover_id())
        self.hook.append(self.mover.resp_get_ref_succeed())
        self.hook.append(self.cifs_share.resp_task_succeed())

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.delete(name=self.cifs_share.share_name,
                       mover_name=self.mover.mover_name,
                       is_vdm=False)

        expected_calls = [
            mock.call(self.cifs_share.req_get()),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_share.req_delete(self.mover.mover_id, False)),
            mock.call(self.mover.req_get_ref()),
            mock.call(self.cifs_share.req_delete(self.mover.mover_id, False)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

        self.assertTrue(sleep_mock.called)

    def test_delete_cifs_share_with_error(self):
        self.hook.append(self.cifs_share.resp_get_succeed(self.vdm.vdm_id))
        self.hook.append(self.vdm.resp_get_succeed())
        self.hook.append(self.cifs_share.resp_task_error())

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.delete,
                          name=self.cifs_share.share_name,
                          mover_name=self.vdm.vdm_name,
                          is_vdm=True)

        expected_calls = [
            mock.call(self.cifs_share.req_get()),
            mock.call(self.vdm.req_get()),
            mock.call(self.cifs_share.req_delete(self.vdm.vdm_id)),
        ]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_get_cifs_share(self):
        self.hook.append(self.cifs_share.resp_get_succeed(self.vdm.vdm_id))

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['XML'].request = utils.EMCMock(side_effect=self.hook)

        context.get(self.cifs_share.share_name)

        expected_calls = [mock.call(self.cifs_share.req_get())]
        context.conn['XML'].request.assert_has_calls(expected_calls)

    def test_disable_share_access(self):
        self.ssh_hook.append('Command succeeded')

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.disable_share_access(share_name=self.cifs_share.share_name,
                                     mover_name=self.vdm.vdm_name)

        ssh_calls = [mock.call(self.cifs_share.cmd_disable_access(), True)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_disable_share_access_with_error(self):
        self.ssh_hook.append(ex=processutils.ProcessExecutionError(
            stdout=self.cifs_share.fake_output))

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.disable_share_access,
                          share_name=self.cifs_share.share_name,
                          mover_name=self.vdm.vdm_name)

        ssh_calls = [mock.call(self.cifs_share.cmd_disable_access(), True)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_allow_share_access(self):
        self.ssh_hook.append(self.cifs_share.output_allow_access())

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.allow_share_access(mover_name=self.vdm.vdm_name,
                                   share_name=self.cifs_share.share_name,
                                   user_name=self.cifs_server.domain_user,
                                   domain=self.cifs_server.domain_name,
                                   access=constants.CIFS_ACL_FULLCONTROL)

        ssh_calls = [mock.call(self.cifs_share.cmd_change_access(), True)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_allow_share_access_duplicate_ACE(self):
        expt_dup_ace = processutils.ProcessExecutionError(
            stdout=self.cifs_share.output_allow_access_but_duplicate_ace())
        self.ssh_hook.append(ex=expt_dup_ace)

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.allow_share_access(mover_name=self.vdm.vdm_name,
                                   share_name=self.cifs_share.share_name,
                                   user_name=self.cifs_server.domain_user,
                                   domain=self.cifs_server.domain_name,
                                   access=constants.CIFS_ACL_FULLCONTROL)

        ssh_calls = [mock.call(self.cifs_share.cmd_change_access(), True)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_allow_share_access_with_error(self):
        expt_err = processutils.ProcessExecutionError(
            self.cifs_share.fake_output)
        self.ssh_hook.append(ex=expt_err)

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.allow_share_access,
                          mover_name=self.vdm.vdm_name,
                          share_name=self.cifs_share.share_name,
                          user_name=self.cifs_server.domain_user,
                          domain=self.cifs_server.domain_name,
                          access=constants.CIFS_ACL_FULLCONTROL)

        ssh_calls = [mock.call(self.cifs_share.cmd_change_access(), True)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_deny_share_access(self):
        self.ssh_hook.append('Command succeeded')

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.deny_share_access(mover_name=self.vdm.vdm_name,
                                  share_name=self.cifs_share.share_name,
                                  user_name=self.cifs_server.domain_user,
                                  domain=self.cifs_server.domain_name,
                                  access=constants.CIFS_ACL_FULLCONTROL)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access(action='revoke'),
                      True),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_deny_share_access_no_ace(self):
        expt_no_ace = processutils.ProcessExecutionError(
            stdout=self.cifs_share.output_deny_access_but_no_ace())
        self.ssh_hook.append(ex=expt_no_ace)

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.deny_share_access(mover_name=self.vdm.vdm_name,
                                  share_name=self.cifs_share.share_name,
                                  user_name=self.cifs_server.domain_user,
                                  domain=self.cifs_server.domain_name,
                                  access=constants.CIFS_ACL_FULLCONTROL)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access(action='revoke'),
                      True),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_deny_share_access_but_no_user_found(self):
        expt_no_user = processutils.ProcessExecutionError(
            stdout=self.cifs_share.output_deny_access_but_no_user_found())
        self.ssh_hook.append(ex=expt_no_user)

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.deny_share_access(mover_name=self.vdm.vdm_name,
                                  share_name=self.cifs_share.share_name,
                                  user_name=self.cifs_server.domain_user,
                                  domain=self.cifs_server.domain_name,
                                  access=constants.CIFS_ACL_FULLCONTROL)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access(action='revoke'),
                      True),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_deny_share_access_with_error(self):
        expt_err = processutils.ProcessExecutionError(
            self.cifs_share.fake_output)
        self.ssh_hook.append(ex=expt_err)

        context = self.manager.getStorageContext('CIFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.deny_share_access,
                          mover_name=self.vdm.vdm_name,
                          share_name=self.cifs_share.share_name,
                          user_name=self.cifs_server.domain_user,
                          domain=self.cifs_server.domain_name,
                          access=constants.CIFS_ACL_FULLCONTROL)

        ssh_calls = [
            mock.call(self.cifs_share.cmd_change_access(action='revoke'),
                      True),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)


class NFSShareTestCase(StorageObjectTestCase):
    def setUp(self):
        super(self.__class__, self).setUp()
        self.ssh_hook = utils.SSHSideEffect()

    def test_create_nfs_share(self):
        self.ssh_hook.append(self.nfs_share.output_create())

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.create(name=self.nfs_share.share_name,
                       mover_name=self.vdm.vdm_name)

        ssh_calls = [mock.call(self.nfs_share.cmd_create(), True)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_create_nfs_share_with_error(self):
        expt_err = processutils.ProcessExecutionError(
            stdout=self.nfs_share.fake_output)
        self.ssh_hook.append(ex=expt_err)

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.create,
                          name=self.nfs_share.share_name,
                          mover_name=self.vdm.vdm_name)

        ssh_calls = [mock.call(self.nfs_share.cmd_create(), True)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_delete_nfs_share(self):
        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=self.nfs_share.rw_hosts,
            ro_hosts=self.nfs_share.ro_hosts))
        self.ssh_hook.append(self.nfs_share.output_delete_succeed())

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.delete(name=self.nfs_share.share_name,
                       mover_name=self.vdm.vdm_name)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), False),
            mock.call(self.nfs_share.cmd_delete(), True),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_delete_nfs_share_not_found(self):
        expt_not_found = processutils.ProcessExecutionError(
            stdout=self.nfs_share.output_get_but_not_found())
        self.ssh_hook.append(ex=expt_not_found)

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.delete(name=self.nfs_share.share_name,
                       mover_name=self.vdm.vdm_name)

        ssh_calls = [mock.call(self.nfs_share.cmd_get(), False)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    @mock.patch('time.sleep')
    def test_delete_nfs_share_locked(self, sleep_mock):
        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=self.nfs_share.rw_hosts,
            ro_hosts=self.nfs_share.ro_hosts))
        expt_locked = processutils.ProcessExecutionError(
            stdout=self.nfs_share.output_delete_but_locked())
        self.ssh_hook.append(ex=expt_locked)
        self.ssh_hook.append(self.nfs_share.output_delete_succeed())

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.delete(name=self.nfs_share.share_name,
                       mover_name=self.vdm.vdm_name)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), False),
            mock.call(self.nfs_share.cmd_delete(), True),
            mock.call(self.nfs_share.cmd_delete(), True),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

        self.assertTrue(sleep_mock.called)

    def test_delete_nfs_share_with_error(self):
        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=self.nfs_share.rw_hosts,
            ro_hosts=self.nfs_share.ro_hosts))
        expt_err = processutils.ProcessExecutionError(
            stdout=self.nfs_share.fake_output)
        self.ssh_hook.append(ex=expt_err)

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.delete,
                          name=self.nfs_share.share_name,
                          mover_name=self.vdm.vdm_name)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), False),
            mock.call(self.nfs_share.cmd_delete(), True),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_get_nfs_share(self):
        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=self.nfs_share.rw_hosts,
            ro_hosts=self.nfs_share.ro_hosts))

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.get(name=self.nfs_share.share_name,
                    mover_name=self.vdm.vdm_name)

        # Get NFS share from cache
        context.get(name=self.nfs_share.share_name,
                    mover_name=self.vdm.vdm_name)

        ssh_calls = [mock.call(self.nfs_share.cmd_get(), False)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_get_nfs_share_not_found(self):
        expt_not_found = processutils.ProcessExecutionError(
            stdout=self.nfs_share.output_get_but_not_found())
        self.ssh_hook.append(ex=expt_not_found)
        self.ssh_hook.append(self.nfs_share.output_get_but_not_found())

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        context.get(name=self.nfs_share.share_name,
                    mover_name=self.vdm.vdm_name)

        context.get(name=self.nfs_share.share_name,
                    mover_name=self.vdm.vdm_name)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get(), False),
            mock.call(self.nfs_share.cmd_get(), False),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_get_nfs_share_with_error(self):
        expt_err = processutils.ProcessExecutionError(
            stdout=self.nfs_share.fake_output)
        self.ssh_hook.append(ex=expt_err)

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = mock.Mock(side_effect=self.ssh_hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.get,
                          name=self.nfs_share.share_name,
                          mover_name=self.vdm.vdm_name)

        ssh_calls = [mock.call(self.nfs_share.cmd_get(), False)]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_allow_share_access(self):
        rw_hosts = copy.deepcopy(self.nfs_share.rw_hosts)
        rw_hosts.append(self.nfs_share.nfs_host_ip)

        ro_hosts = copy.deepcopy(self.nfs_share.ro_hosts)
        ro_hosts.append(self.nfs_share.nfs_host_ip)

        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=self.nfs_share.rw_hosts,
            ro_hosts=self.nfs_share.ro_hosts))
        self.ssh_hook.append(self.nfs_share.output_set_access_success())
        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=rw_hosts, ro_hosts=self.nfs_share.ro_hosts))
        self.ssh_hook.append(self.nfs_share.output_set_access_success())
        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=self.nfs_share.rw_hosts, ro_hosts=ro_hosts))
        self.ssh_hook.append(self.nfs_share.output_set_access_success())
        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=rw_hosts, ro_hosts=self.nfs_share.ro_hosts))

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = utils.EMCNFSShareMock(
            side_effect=self.ssh_hook)

        context.allow_share_access(share_name=self.nfs_share.share_name,
                                   host_ip=self.nfs_share.nfs_host_ip,
                                   mover_name=self.vdm.vdm_name,
                                   access_level=const.ACCESS_LEVEL_RW)

        context.allow_share_access(share_name=self.nfs_share.share_name,
                                   host_ip=self.nfs_share.nfs_host_ip,
                                   mover_name=self.vdm.vdm_name,
                                   access_level=const.ACCESS_LEVEL_RO)

        context.allow_share_access(share_name=self.nfs_share.share_name,
                                   host_ip=self.nfs_share.nfs_host_ip,
                                   mover_name=self.vdm.vdm_name,
                                   access_level=const.ACCESS_LEVEL_RW)

        context.allow_share_access(share_name=self.nfs_share.share_name,
                                   host_ip=self.nfs_share.nfs_host_ip,
                                   mover_name=self.vdm.vdm_name,
                                   access_level=const.ACCESS_LEVEL_RW)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get()),
            mock.call(self.nfs_share.cmd_set_access(
                rw_hosts=rw_hosts, ro_hosts=self.nfs_share.ro_hosts)),
            mock.call(self.nfs_share.cmd_get()),
            mock.call(self.nfs_share.cmd_set_access(
                rw_hosts=self.nfs_share.rw_hosts, ro_hosts=ro_hosts)),
            mock.call(self.nfs_share.cmd_get()),
            mock.call(self.nfs_share.cmd_set_access(
                rw_hosts=rw_hosts, ro_hosts=self.nfs_share.ro_hosts)),
            mock.call(self.nfs_share.cmd_get()),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_allow_share_access_not_found(self):
        expt_not_found = processutils.ProcessExecutionError(
            stdout=self.nfs_share.output_get_but_not_found())
        self.ssh_hook.append(ex=expt_not_found)

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = utils.EMCNFSShareMock(
            side_effect=self.ssh_hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.allow_share_access,
                          share_name=self.nfs_share.share_name,
                          host_ip=self.nfs_share.nfs_host_ip,
                          mover_name=self.vdm.vdm_name,
                          access_level=const.ACCESS_LEVEL_RW)

        ssh_calls = [mock.call(self.nfs_share.cmd_get())]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_deny_rw_share_access(self):
        rw_hosts = copy.deepcopy(self.nfs_share.rw_hosts)
        rw_hosts.append(self.nfs_share.nfs_host_ip)

        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=rw_hosts, ro_hosts=self.nfs_share.ro_hosts))
        self.ssh_hook.append(self.nfs_share.output_set_access_success())
        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=self.nfs_share.rw_hosts,
            ro_hosts=self.nfs_share.ro_hosts))

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = utils.EMCNFSShareMock(
            side_effect=self.ssh_hook)

        context.deny_share_access(share_name=self.nfs_share.share_name,
                                  host_ip=self.nfs_share.nfs_host_ip,
                                  mover_name=self.vdm.vdm_name)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get()),
            mock.call(self.nfs_share.cmd_set_access(self.nfs_share.rw_hosts,
                                                    self.nfs_share.ro_hosts)),
            mock.call(self.nfs_share.cmd_get()),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_deny_ro_share_access(self):
        ro_hosts = copy.deepcopy(self.nfs_share.ro_hosts)
        ro_hosts.append(self.nfs_share.nfs_host_ip)

        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=self.nfs_share.rw_hosts, ro_hosts=ro_hosts))
        self.ssh_hook.append(self.nfs_share.output_set_access_success())
        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=self.nfs_share.rw_hosts,
            ro_hosts=self.nfs_share.ro_hosts))

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = utils.EMCNFSShareMock(
            side_effect=self.ssh_hook)

        context.deny_share_access(share_name=self.nfs_share.share_name,
                                  host_ip=self.nfs_share.nfs_host_ip,
                                  mover_name=self.vdm.vdm_name)

        context.deny_share_access(share_name=self.nfs_share.share_name,
                                  host_ip=self.nfs_share.nfs_host_ip,
                                  mover_name=self.vdm.vdm_name)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get()),
            mock.call(self.nfs_share.cmd_set_access(self.nfs_share.rw_hosts,
                                                    self.nfs_share.ro_hosts)),
            mock.call(self.nfs_share.cmd_get()),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_deny_share_not_found(self):
        expt_not_found = processutils.ProcessExecutionError(
            stdout=self.nfs_share.output_get_but_not_found())
        self.ssh_hook.append(ex=expt_not_found)

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = utils.EMCNFSShareMock(
            side_effect=self.ssh_hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.deny_share_access,
                          share_name=self.nfs_share.share_name,
                          host_ip=self.nfs_share.nfs_host_ip,
                          mover_name=self.vdm.vdm_name)

        ssh_calls = [mock.call(self.nfs_share.cmd_get())]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)

    def test_deny_rw_share_with_error(self):
        rw_hosts = copy.deepcopy(self.nfs_share.rw_hosts)
        rw_hosts.append(self.nfs_share.nfs_host_ip)

        self.ssh_hook.append(self.nfs_share.output_get_succeed(
            rw_hosts=rw_hosts, ro_hosts=self.nfs_share.ro_hosts))
        expt_not_found = processutils.ProcessExecutionError(
            stdout=self.nfs_share.output_get_but_not_found())
        self.ssh_hook.append(ex=expt_not_found)

        context = self.manager.getStorageContext('NFSShare')
        context.conn['SSH'].run_ssh = utils.EMCNFSShareMock(
            side_effect=self.ssh_hook)

        self.assertRaises(exception.EMCVnxXMLAPIError,
                          context.deny_share_access,
                          share_name=self.nfs_share.share_name,
                          host_ip=self.nfs_share.nfs_host_ip,
                          mover_name=self.vdm.vdm_name)

        ssh_calls = [
            mock.call(self.nfs_share.cmd_get()),
            mock.call(self.nfs_share.cmd_set_access(self.nfs_share.rw_hosts,
                                                    self.nfs_share.ro_hosts)),
        ]
        context.conn['SSH'].run_ssh.assert_has_calls(ssh_calls)
