# Copyright (c) 2014 NetApp, Inc.
# Copyright (c) 2015 Mirantis, Inc.
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

"""Unit tests for the Generic driver module."""

import os

import ddt
import mock
from oslo_concurrency import processutils
from oslo_config import cfg

from manila.common import constants as const
from manila import compute
from manila import context
from manila import exception
import manila.share.configuration
from manila.share.drivers import generic
from manila import test
from manila.tests import fake_compute
from manila.tests import fake_service_instance
from manila.tests import fake_share
from manila.tests import fake_utils
from manila.tests import fake_volume
from manila import utils
from manila import volume

CONF = cfg.CONF


@ddt.ddt
class GenericShareDriverTestCase(test.TestCase):
    """Tests GenericShareDriver."""

    def setUp(self):
        super(GenericShareDriverTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._execute = mock.Mock(return_value=('', ''))

        self._helper_cifs = mock.Mock()
        self._helper_nfs = mock.Mock()
        CONF.set_default('driver_handles_share_servers', True)
        self.fake_conf = manila.share.configuration.Configuration(None)
        self._db = mock.Mock()
        with mock.patch.object(
                generic.service_instance,
                'ServiceInstanceManager',
                fake_service_instance.FakeServiceInstanceManager):
            self._driver = generic.GenericShareDriver(
                self._db, execute=self._execute, configuration=self.fake_conf)
        self._driver.service_tenant_id = 'service tenant id'
        self._driver.service_network_id = 'service network id'
        self._driver.compute_api = fake_compute.API()
        self._driver.volume_api = fake_volume.API()
        self._driver.share_networks_locks = {}
        self._driver.get_service_instance = mock.Mock()
        self._driver.share_networks_servers = {}
        self._driver.admin_context = self._context

        self.fake_sn = {"id": "fake_sn_id"}
        self.fake_net_info = {
            "id": "fake_srv_id",
            "share_network_id": "fake_sn_id"
        }
        fsim = fake_service_instance.FakeServiceInstanceManager()
        sim = mock.Mock(return_value=fsim)
        self._driver.instance_manager = sim
        self._driver.service_instance_manager = sim
        self.fake_server = sim._create_service_instance(
            context="fake", instance_name="fake",
            share_network_id=self.fake_sn["id"], old_server_ip="fake")

        self.stubs.Set(utils, 'synchronized',
                       mock.Mock(return_value=lambda f: f))
        self.stubs.Set(generic.os.path, 'exists', mock.Mock(return_value=True))
        self._driver._helpers = {
            'CIFS': self._helper_cifs,
            'NFS': self._helper_nfs,
        }
        self.share = fake_share.fake_share(share_proto='NFS')
        self.server = {
            'instance_id': 'fake_instance_id',
            'ip': 'fake_ip',
            'username': 'fake_username',
            'password': 'fake_password',
            'pk_path': 'fake_pk_path',
            'backend_details': {
                'ip': '1.2.3.4',
                'instance_id': 'fake'
            }
        }
        self.access = fake_share.fake_access()
        self.snapshot = fake_share.fake_snapshot()

    def test_do_setup(self):
        self.stubs.Set(volume, 'API', mock.Mock())
        self.stubs.Set(compute, 'API', mock.Mock())
        self.stubs.Set(self._driver, '_setup_helpers', mock.Mock())
        self._driver.do_setup(self._context)
        volume.API.assert_called_once_with()
        compute.API.assert_called_once_with()
        self._driver._setup_helpers.assert_called_once_with()

    def test_setup_helpers(self):
        self._driver._helpers = {}
        CONF.set_default('share_helpers', ['NFS=fakenfs'])
        self.stubs.Set(generic.importutils, 'import_class',
                       mock.Mock(return_value=self._helper_nfs))
        self._driver._setup_helpers()
        generic.importutils.import_class.assert_has_calls([
            mock.call('fakenfs')
        ])
        self._helper_nfs.assert_called_once_with(
            self._execute,
            self._driver._ssh_exec,
            self.fake_conf
        )
        self.assertEqual(len(self._driver._helpers), 1)

    def test_create_share(self):
        volume = 'fake_volume'
        volume2 = 'fake_volume2'
        self._helper_nfs.create_export.return_value = 'fakelocation'
        self.stubs.Set(self._driver, '_allocate_container',
                       mock.Mock(return_value=volume))
        self.stubs.Set(self._driver, '_attach_volume',
                       mock.Mock(return_value=volume2))
        self.stubs.Set(self._driver, '_format_device', mock.Mock())
        self.stubs.Set(self._driver, '_mount_device', mock.Mock())

        result = self._driver.create_share(
            self._context, self.share, share_server=self.server)

        self.assertEqual(result, 'fakelocation')
        self._driver._allocate_container.assert_called_once_with(
            self._driver.admin_context, self.share)
        self._driver._attach_volume.assert_called_once_with(
            self._driver.admin_context, self.share,
            self.server['backend_details']['instance_id'],
            volume)
        self._driver._format_device.assert_called_once_with(
            self.server['backend_details'], volume2)
        self._driver._mount_device.assert_called_once_with(
            self.share, self.server['backend_details'], volume2)

    def test_create_share_exception(self):
        share = fake_share.fake_share(share_network_id=None)
        self.assertRaises(exception.ManilaException, self._driver.create_share,
                          self._context, share)

    def test_format_device(self):
        volume = {'mountpoint': 'fake_mount_point'}
        self.stubs.Set(self._driver, '_ssh_exec',
                       mock.Mock(return_value=('', '')))
        self._driver._format_device(self.server, volume)
        self._driver._ssh_exec.assert_called_once_with(
            self.server,
            ['sudo', 'mkfs.%s' % self.fake_conf.share_volume_fstype,
             volume['mountpoint']])

    def test_mount_device_not_present(self):
        server = {'instance_id': 'fake_server_id'}
        mount_path = '/fake/mount/path'
        volume = {'mountpoint': 'fake_mount_point'}
        self.stubs.Set(self._driver, '_is_device_mounted',
                       mock.Mock(return_value=False))
        self.stubs.Set(self._driver, '_sync_mount_temp_and_perm_files',
                       mock.Mock())
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value=mount_path))
        self.stubs.Set(self._driver, '_ssh_exec',
                       mock.Mock(return_value=('', '')))

        self._driver._mount_device(self.share, server, volume)

        self._driver._get_mount_path.assert_called_once_with(self.share)
        self._driver._is_device_mounted.assert_called_once_with(
            self.share, server, volume)
        self._driver._sync_mount_temp_and_perm_files.assert_called_once_with(
            server)
        self._driver._ssh_exec.assert_called_once_with(
            server,
            ['sudo mkdir -p', mount_path,
             '&&', 'sudo mount', volume['mountpoint'], mount_path,
             '&& sudo chmod 777', mount_path],
        )

    def test_mount_device_present(self):
        mount_path = '/fake/mount/path'
        volume = {'mountpoint': 'fake_mount_point'}
        self.stubs.Set(self._driver, '_is_device_mounted',
                       mock.Mock(return_value=True))
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value=mount_path))
        self.stubs.Set(generic.LOG, 'warning', mock.Mock())

        self._driver._mount_device(self.share, self.server, volume)

        self._driver._get_mount_path.assert_called_once_with(self.share)
        self._driver._is_device_mounted.assert_called_once_with(
            self.share, self.server, volume)
        generic.LOG.warning.assert_called_once_with(mock.ANY, mock.ANY)

    def test_mount_device_exception_raised(self):
        volume = {'mountpoint': 'fake_mount_point'}
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value='fake'))
        self.stubs.Set(self._driver, '_is_device_mounted',
                       mock.Mock(side_effect=exception.ProcessExecutionError))

        self.assertRaises(
            exception.ShareBackendException,
            self._driver._mount_device,
            self.share,
            self.server,
            volume,
        )
        self._driver._get_mount_path.assert_called_once_with(self.share)
        self._driver._is_device_mounted.assert_called_once_with(
            self.share, self.server, volume)

    def test_unmount_device_present(self):
        mount_path = '/fake/mount/path'
        self.stubs.Set(self._driver, '_is_device_mounted',
                       mock.Mock(return_value=True))
        self.stubs.Set(self._driver, '_sync_mount_temp_and_perm_files',
                       mock.Mock())
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value=mount_path))
        self.stubs.Set(self._driver, '_ssh_exec',
                       mock.Mock(return_value=('', '')))

        self._driver._unmount_device(self.share, self.server)

        self._driver._get_mount_path.assert_called_once_with(self.share)
        self._driver._is_device_mounted.assert_called_once_with(
            self.share, self.server)
        self._driver._sync_mount_temp_and_perm_files.assert_called_once_with(
            self.server)
        self._driver._ssh_exec.assert_called_once_with(
            self.server,
            ['sudo umount', mount_path, '&& sudo rmdir', mount_path],
        )

    def test_unmount_device_not_present(self):
        mount_path = '/fake/mount/path'
        self.stubs.Set(self._driver, '_is_device_mounted',
                       mock.Mock(return_value=False))
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value=mount_path))
        self.stubs.Set(generic.LOG, 'warning', mock.Mock())

        self._driver._unmount_device(self.share, self.server)

        self._driver._get_mount_path.assert_called_once_with(self.share)
        self._driver._is_device_mounted.assert_called_once_with(
            self.share, self.server)
        generic.LOG.warning.assert_called_once_with(mock.ANY, mock.ANY)

    def test_is_device_mounted_true(self):
        volume = {'mountpoint': 'fake_mount_point', 'id': 'fake_id'}
        mount_path = '/fake/mount/path'
        mounts = "%(dev)s on %(path)s" % {'dev': volume['mountpoint'],
                                          'path': mount_path}
        self.stubs.Set(self._driver, '_ssh_exec',
                       mock.Mock(return_value=(mounts, '')))
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value=mount_path))

        result = self._driver._is_device_mounted(
            self.share, self.server, volume)

        self._driver._get_mount_path.assert_called_once_with(self.share)
        self._driver._ssh_exec.assert_called_once_with(
            self.server, ['sudo', 'mount'])
        self.assertEqual(result, True)

    def test_is_device_mounted_true_no_volume_provided(self):
        mount_path = '/fake/mount/path'
        mounts = "/fake/dev/path on %(path)s type fake" % {'path': mount_path}
        self.stubs.Set(self._driver, '_ssh_exec',
                       mock.Mock(return_value=(mounts, '')))
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value=mount_path))

        result = self._driver._is_device_mounted(self.share, self.server)

        self._driver._get_mount_path.assert_called_once_with(self.share)
        self._driver._ssh_exec.assert_called_once_with(
            self.server, ['sudo', 'mount'])
        self.assertEqual(result, True)

    def test_is_device_mounted_false(self):
        mount_path = '/fake/mount/path'
        volume = {'mountpoint': 'fake_mount_point', 'id': 'fake_id'}
        mounts = "%(dev)s on %(path)s" % {'dev': '/fake',
                                          'path': mount_path}
        self.stubs.Set(self._driver, '_ssh_exec',
                       mock.Mock(return_value=(mounts, '')))
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value=mount_path))

        result = self._driver._is_device_mounted(
            self.share, self.server, volume)

        self._driver._get_mount_path.assert_called_once_with(self.share)
        self._driver._ssh_exec.assert_called_once_with(
            self.server, ['sudo', 'mount'])
        self.assertEqual(result, False)

    def test_is_device_mounted_false_no_volume_provided(self):
        mount_path = '/fake/mount/path'
        mounts = "%(path)s" % {'path': 'fake'}
        self.stubs.Set(self._driver, '_ssh_exec',
                       mock.Mock(return_value=(mounts, '')))
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value=mount_path))

        result = self._driver._is_device_mounted(self.share, self.server)

        self._driver._get_mount_path.assert_called_once_with(self.share)
        self._driver._ssh_exec.assert_called_once_with(
            self.server, ['sudo', 'mount'])
        self.assertEqual(result, False)

    def test_sync_mount_temp_and_perm_files(self):
        self.stubs.Set(self._driver, '_ssh_exec', mock.Mock())
        self._driver._sync_mount_temp_and_perm_files(self.server)
        self._driver._ssh_exec.has_calls(
            mock.call(
                self.server,
                ['sudo', 'cp', const.MOUNT_FILE_TEMP, const.MOUNT_FILE]),
            mock.call(self.server, ['sudo', 'mount', '-a']))

    def test_sync_mount_temp_and_perm_files_raise_error_on_copy(self):
        self.stubs.Set(self._driver, '_ssh_exec',
                       mock.Mock(side_effect=exception.ProcessExecutionError))
        self.assertRaises(
            exception.ShareBackendException,
            self._driver._sync_mount_temp_and_perm_files,
            self.server
        )
        self._driver._ssh_exec.assert_called_once_with(
            self.server,
            ['sudo', 'cp', const.MOUNT_FILE_TEMP, const.MOUNT_FILE])

    def test_sync_mount_temp_and_perm_files_raise_error_on_mount(self):
        def raise_error_on_mount(*args, **kwargs):
            if args[1][1] == 'cp':
                raise exception.ProcessExecutionError()

        self.stubs.Set(self._driver, '_ssh_exec',
                       mock.Mock(side_effect=raise_error_on_mount))
        self.assertRaises(
            exception.ShareBackendException,
            self._driver._sync_mount_temp_and_perm_files,
            self.server
        )
        self._driver._ssh_exec.has_calls(
            mock.call(
                self.server,
                ['sudo', 'cp', const.MOUNT_FILE_TEMP, const.MOUNT_FILE]),
            mock.call(self.server, ['sudo', 'mount', '-a']))

    def test_get_mount_path(self):
        result = self._driver._get_mount_path(self.share)
        self.assertEqual(result, os.path.join(CONF.share_mount_path,
                                              self.share['name']))

    def test_attach_volume_not_attached(self):
        availiable_volume = fake_volume.FakeVolume()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.stubs.Set(self._driver.compute_api, 'instance_volume_attach',
                       mock.Mock())
        self.stubs.Set(self._driver.volume_api, 'get',
                       mock.Mock(return_value=attached_volume))

        result = self._driver._attach_volume(self._context, self.share,
                                             'fake_inst_id', availiable_volume)

        self._driver.compute_api.instance_volume_attach.\
            assert_called_once_with(self._context, 'fake_inst_id',
                                    availiable_volume['id'])
        self._driver.volume_api.get.assert_called_once_with(
            self._context, attached_volume['id'])
        self.assertEqual(result, attached_volume)

    def test_attach_volume_attached_correct(self):
        fake_server = fake_compute.FakeServer()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.stubs.Set(self._driver.compute_api, 'instance_volumes_list',
                       mock.Mock(return_value=[attached_volume]))

        result = self._driver._attach_volume(self._context, self.share,
                                             fake_server, attached_volume)

        self.assertEqual(result, attached_volume)

    def test_attach_volume_attached_incorrect(self):
        fake_server = fake_compute.FakeServer()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        anoter_volume = fake_volume.FakeVolume(id='fake_id2', status='in-use')
        self.stubs.Set(self._driver.compute_api, 'instance_volumes_list',
                       mock.Mock(return_value=[anoter_volume]))
        self.assertRaises(exception.ManilaException,
                          self._driver._attach_volume, self._context,
                          self.share, fake_server, attached_volume)

    def test_attach_volume_failed_attach(self):
        fake_server = fake_compute.FakeServer()
        availiable_volume = fake_volume.FakeVolume()
        self.stubs.Set(self._driver.compute_api, 'instance_volume_attach',
                       mock.Mock(side_effect=exception.ManilaException))
        self.assertRaises(exception.ManilaException,
                          self._driver._attach_volume,
                          self._context, self.share, fake_server,
                          availiable_volume)

    def test_attach_volume_error(self):
        fake_server = fake_compute.FakeServer()
        availiable_volume = fake_volume.FakeVolume()
        error_volume = fake_volume.FakeVolume(status='error')
        self.stubs.Set(self._driver.compute_api, 'instance_volume_attach',
                       mock.Mock())
        self.stubs.Set(self._driver.volume_api, 'get',
                       mock.Mock(return_value=error_volume))
        self.assertRaises(exception.ManilaException,
                          self._driver._attach_volume,
                          self._context, self.share,
                          fake_server, availiable_volume)

    def test_get_volume(self):
        volume = fake_volume.FakeVolume(
            display_name=CONF.volume_name_template % self.share['id'])
        self.stubs.Set(self._driver.volume_api, 'get_all',
                       mock.Mock(return_value=[volume]))
        result = self._driver._get_volume(self._context, self.share['id'])
        self.assertEqual(result, volume)

    def test_get_volume_none(self):
        self.stubs.Set(self._driver.volume_api, 'get_all',
                       mock.Mock(return_value=[]))
        result = self._driver._get_volume(self._context, self.share['id'])
        self.assertEqual(result, None)

    def test_get_volume_error(self):
        volume = fake_volume.FakeVolume(
            display_name=CONF.volume_name_template % self.share['id'])
        self.stubs.Set(self._driver.volume_api, 'get_all',
                       mock.Mock(return_value=[volume, volume]))
        self.assertRaises(exception.ManilaException,
                          self._driver._get_volume,
                          self._context, self.share['id'])

    def test_get_volume_snapshot(self):
        volume_snapshot = fake_volume.FakeVolumeSnapshot(
            display_name=CONF.volume_snapshot_name_template %
            self.snapshot['id'])
        self.stubs.Set(self._driver.volume_api, 'get_all_snapshots',
                       mock.Mock(return_value=[volume_snapshot]))
        result = self._driver._get_volume_snapshot(self._context,
                                                   self.snapshot['id'])
        self.assertEqual(result, volume_snapshot)

    def test_get_volume_snapshot_none(self):
        self.stubs.Set(self._driver.volume_api, 'get_all_snapshots',
                       mock.Mock(return_value=[]))
        result = self._driver._get_volume_snapshot(self._context,
                                                   self.share['id'])
        self.assertEqual(result, None)

    def test_get_volume_snapshot_error(self):
        volume_snapshot = fake_volume.FakeVolumeSnapshot(
            display_name=CONF.volume_snapshot_name_template %
            self.snapshot['id'])
        self.stubs.Set(self._driver.volume_api, 'get_all_snapshots',
                       mock.Mock(return_value=[volume_snapshot,
                                               volume_snapshot]))
        self.assertRaises(exception.ManilaException,
                          self._driver._get_volume_snapshot, self._context,
                          self.share['id'])

    def test_detach_volume(self):
        availiable_volume = fake_volume.FakeVolume()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.stubs.Set(self._driver, '_get_volume',
                       mock.Mock(return_value=attached_volume))
        self.stubs.Set(self._driver.compute_api, 'instance_volumes_list',
                       mock.Mock(return_value=[attached_volume]))
        self.stubs.Set(self._driver.compute_api, 'instance_volume_detach',
                       mock.Mock())
        self.stubs.Set(self._driver.volume_api, 'get',
                       mock.Mock(return_value=availiable_volume))

        self._driver._detach_volume(self._context, self.share,
                                    self.server['backend_details'])

        self._driver.compute_api.instance_volume_detach.\
            assert_called_once_with(
                self._context,
                self.server['backend_details']['instance_id'],
                availiable_volume['id'])
        self._driver.volume_api.get.assert_called_once_with(
            self._context, availiable_volume['id'])

    def test_detach_volume_detached(self):
        availiable_volume = fake_volume.FakeVolume()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.stubs.Set(self._driver, '_get_volume',
                       mock.Mock(return_value=attached_volume))
        self.stubs.Set(self._driver.compute_api, 'instance_volumes_list',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._driver.volume_api, 'get',
                       mock.Mock(return_value=availiable_volume))
        self.stubs.Set(self._driver.compute_api, 'instance_volume_detach',
                       mock.Mock())

        self._driver._detach_volume(self._context, self.share,
                                    self.server['backend_details'])

        self.assertFalse(self._driver.volume_api.get.called)
        self.assertFalse(
            self._driver.compute_api.instance_volume_detach.called)

    def test_allocate_container(self):
        fake_vol = fake_volume.FakeVolume()
        self.fake_conf.cinder_volume_type = 'fake_volume_type'
        self.stubs.Set(self._driver.volume_api, 'create',
                       mock.Mock(return_value=fake_vol))

        result = self._driver._allocate_container(self._context, self.share)
        self.assertEqual(result, fake_vol)
        self._driver.volume_api.create.assert_called_once_with(
            self._context,
            self.share['size'],
            CONF.volume_name_template % self.share['id'],
            '',
            snapshot=None,
            volume_type='fake_volume_type')

    def test_allocate_container_with_snaphot(self):
        fake_vol = fake_volume.FakeVolume()
        fake_vol_snap = fake_volume.FakeVolumeSnapshot()
        self.stubs.Set(self._driver, '_get_volume_snapshot',
                       mock.Mock(return_value=fake_vol_snap))
        self.stubs.Set(self._driver.volume_api, 'create',
                       mock.Mock(return_value=fake_vol))

        result = self._driver._allocate_container(self._context,
                                                  self.share,
                                                  self.snapshot)
        self.assertEqual(result, fake_vol)
        self._driver.volume_api.create.assert_called_once_with(
            self._context,
            self.share['size'],
            CONF.volume_name_template % self.share['id'],
            '',
            snapshot=fake_vol_snap,
            volume_type=None)

    def test_allocate_container_error(self):
        fake_vol = fake_volume.FakeVolume(status='error')
        self.stubs.Set(self._driver.volume_api, 'create',
                       mock.Mock(return_value=fake_vol))

        self.assertRaises(exception.ManilaException,
                          self._driver._allocate_container,
                          self._context,
                          self.share)

    def test_deallocate_container(self):
        fake_vol = fake_volume.FakeVolume()
        self.stubs.Set(self._driver, '_get_volume',
                       mock.Mock(return_value=fake_vol))
        self.stubs.Set(self._driver.volume_api, 'delete', mock.Mock())
        self.stubs.Set(self._driver.volume_api, 'get', mock.Mock(
            side_effect=exception.VolumeNotFound(volume_id=fake_vol['id'])))

        self._driver._deallocate_container(self._context, self.share)

        self._driver._get_volume.assert_called_once_with(
            self._context, self.share['id'])
        self._driver.volume_api.delete.assert_called_once_with(
            self._context, fake_vol['id'])
        self._driver.volume_api.get.assert_called_once_with(
            self._context, fake_vol['id'])

    def test_create_share_from_snapshot(self):
        vol1 = 'fake_vol1'
        vol2 = 'fake_vol2'
        self._helper_nfs.create_export.return_value = 'fakelocation'
        self.stubs.Set(self._driver, '_allocate_container',
                       mock.Mock(return_value=vol1))
        self.stubs.Set(self._driver, '_attach_volume',
                       mock.Mock(return_value=vol2))
        self.stubs.Set(self._driver, '_mount_device', mock.Mock())

        result = self._driver.create_share_from_snapshot(
            self._context,
            self.share,
            self.snapshot,
            share_server=self.server)

        self.assertEqual(result, 'fakelocation')
        self._driver._allocate_container.assert_called_once_with(
            self._driver.admin_context, self.share, self.snapshot)
        self._driver._attach_volume.assert_called_once_with(
            self._driver.admin_context, self.share,
            self.server['backend_details']['instance_id'], vol1)
        self._driver._mount_device.assert_called_once_with(
            self.share, self.server['backend_details'], vol2)
        self._helper_nfs.create_export.assert_called_once_with(
            self.server['backend_details'], self.share['name'])

    def test_delete_share_no_share_servers_handling(self):
        self.stubs.Set(self._driver, '_deallocate_container', mock.Mock())
        self.stubs.Set(
            self._driver.service_instance_manager,
            'get_common_server', mock.Mock(return_value=self.server))
        self.stubs.Set(
            self._driver.service_instance_manager,
            'ensure_service_instance', mock.Mock(return_value=False))

        CONF.set_default('driver_handles_share_servers', False)

        self._driver.delete_share(self._context, self.share)

        self._driver.service_instance_manager.get_common_server.\
            assert_called_once_with()
        self._driver._deallocate_container.assert_called_once_with(
            self._driver.admin_context, self.share)
        self._driver.service_instance_manager.ensure_service_instance.\
            assert_called_once_with(
                self._context, self.server['backend_details'])

    def test_delete_share(self):
        self.stubs.Set(self._driver, '_unmount_device', mock.Mock())
        self.stubs.Set(self._driver, '_detach_volume', mock.Mock())
        self.stubs.Set(self._driver, '_deallocate_container', mock.Mock())

        self._driver.delete_share(
            self._context, self.share, share_server=self.server)

        self._helper_nfs.remove_export.assert_called_once_with(
            self.server['backend_details'], self.share['name'])
        self._driver._unmount_device.assert_called_once_with(
            self.share, self.server['backend_details'])
        self._driver._detach_volume.assert_called_once_with(
            self._driver.admin_context, self.share,
            self.server['backend_details'])
        self._driver._deallocate_container.assert_called_once_with(
            self._driver.admin_context, self.share)
        self._driver.service_instance_manager.ensure_service_instance.\
            assert_called_once_with(
                self._context, self.server['backend_details'])

    def test_delete_share_without_share_server(self):
        self.stubs.Set(self._driver, '_unmount_device', mock.Mock())
        self.stubs.Set(self._driver, '_detach_volume', mock.Mock())
        self.stubs.Set(self._driver, '_deallocate_container', mock.Mock())

        self._driver.delete_share(
            self._context, self.share, share_server=None)

        self.assertFalse(self._helper_nfs.remove_export.called)
        self.assertFalse(self._driver._unmount_device.called)
        self.assertFalse(self._driver._detach_volume.called)
        self._driver._deallocate_container.assert_called_once_with(
            self._driver.admin_context, self.share)

    def test_delete_share_without_server_backend_details(self):
        self.stubs.Set(self._driver, '_unmount_device', mock.Mock())
        self.stubs.Set(self._driver, '_detach_volume', mock.Mock())
        self.stubs.Set(self._driver, '_deallocate_container', mock.Mock())

        fake_share_server = {
            'instance_id': 'fake_instance_id',
            'ip': 'fake_ip',
            'username': 'fake_username',
            'password': 'fake_password',
            'pk_path': 'fake_pk_path',
            'backend_details': {}
        }

        self._driver.delete_share(
            self._context, self.share, share_server=fake_share_server)

        self.assertFalse(self._helper_nfs.remove_export.called)
        self.assertFalse(self._driver._unmount_device.called)
        self.assertFalse(self._driver._detach_volume.called)
        self._driver._deallocate_container.assert_called_once_with(
            self._driver.admin_context, self.share)

    def test_delete_share_without_server_availability(self):
        self.stubs.Set(self._driver, '_unmount_device', mock.Mock())
        self.stubs.Set(self._driver, '_detach_volume', mock.Mock())
        self.stubs.Set(self._driver, '_deallocate_container', mock.Mock())

        self.stubs.Set(
            self._driver.service_instance_manager,
            'ensure_service_instance', mock.Mock(return_value=False))
        self._driver.delete_share(
            self._context, self.share, share_server=self.server)

        self.assertFalse(self._helper_nfs.remove_export.called)
        self.assertFalse(self._driver._unmount_device.called)
        self.assertFalse(self._driver._detach_volume.called)
        self._driver._deallocate_container.assert_called_once_with(
            self._driver.admin_context, self.share)
        self._driver.service_instance_manager.ensure_service_instance.\
            assert_called_once_with(
                self._context, self.server['backend_details'])

    def test_create_snapshot(self):
        fake_vol = fake_volume.FakeVolume()
        fake_vol_snap = fake_volume.FakeVolumeSnapshot(share_id=fake_vol['id'])
        self.stubs.Set(self._driver, '_get_volume',
                       mock.Mock(return_value=fake_vol))
        self.stubs.Set(self._driver.volume_api, 'create_snapshot_force',
                       mock.Mock(return_value=fake_vol_snap))

        self._driver.create_snapshot(self._context, fake_vol_snap,
                                     share_server=self.server)

        self._driver._get_volume.assert_called_once_with(
            self._driver.admin_context, fake_vol_snap['share_id'])
        self._driver.volume_api.create_snapshot_force.assert_called_once_with(
            self._context,
            fake_vol['id'],
            CONF.volume_snapshot_name_template % fake_vol_snap['id'],
            ''
        )

    def test_delete_snapshot(self):
        fake_vol_snap = fake_volume.FakeVolumeSnapshot()
        fake_vol_snap2 = {'id': 'fake_vol_snap2'}
        self.stubs.Set(self._driver, '_get_volume_snapshot',
                       mock.Mock(return_value=fake_vol_snap2))
        self.stubs.Set(self._driver.volume_api, 'delete_snapshot', mock.Mock())
        self.stubs.Set(self._driver.volume_api, 'get_snapshot',
                       mock.Mock(side_effect=exception.VolumeSnapshotNotFound(
                           snapshot_id=fake_vol_snap['id'])))

        self._driver.delete_snapshot(self._context, fake_vol_snap,
                                     share_server=self.server)

        self._driver._get_volume_snapshot.assert_called_once_with(
            self._driver.admin_context, fake_vol_snap['id'])
        self._driver.volume_api.delete_snapshot.assert_called_once_with(
            self._driver.admin_context, fake_vol_snap2['id'])
        self._driver.volume_api.get_snapshot.assert_called_once_with(
            self._driver.admin_context, fake_vol_snap2['id'])

    def test_ensure_share(self):
        vol1 = 'fake_vol1'
        vol2 = 'fake_vol2'
        self._helper_nfs.create_export.return_value = 'fakelocation'
        self.stubs.Set(self._driver, '_get_volume',
                       mock.Mock(return_value=vol1))
        self.stubs.Set(self._driver, '_attach_volume',
                       mock.Mock(return_value=vol2))
        self.stubs.Set(self._driver, '_mount_device', mock.Mock())

        self._driver.ensure_share(
            self._context, self.share, share_server=self.server)

        self._driver._get_volume.assert_called_once_with(
            self._context, self.share['id'])
        self._driver._attach_volume.assert_called_once_with(
            self._context, self.share,
            self.server['backend_details']['instance_id'], vol1)
        self._driver._mount_device.assert_called_once_with(
            self.share, self.server['backend_details'], vol2)
        self._helper_nfs.create_export.assert_called_once_with(
            self.server['backend_details'], self.share['name'], recreate=True)

    def test_allow_access(self):
        access = {'access_type': 'ip', 'access_to': 'fake_dest'}
        self._driver.allow_access(
            self._context, self.share, access, share_server=self.server)
        self._driver._helpers[self.share['share_proto']].\
            allow_access.assert_called_once_with(
                self.server['backend_details'],
                self.share['name'],
                access['access_type'],
                access['access_to'])

    def test_deny_access(self):
        access = {'access_type': 'ip', 'access_to': 'fake_dest'}
        self._driver.deny_access(self._context, self.share, access,
                                 share_server=self.server)
        self._driver._helpers[self.share['share_proto']]. \
            deny_access.assert_called_once_with(self.server['backend_details'],
                                                self.share['name'],
                                                access['access_type'],
                                                access['access_to'])

    @ddt.data(fake_share.fake_share(),
              fake_share.fake_share(share_proto='NFSBOGUS'),
              fake_share.fake_share(share_proto='CIFSBOGUS'))
    def test__get_helper_with_wrong_proto(self, share):
        self.assertRaises(exception.InvalidShare,
                          self._driver._get_helper, share)

    def test__setup_server(self):
        sim = self._driver.instance_manager
        net_info = {'server_id': 'fake',
                    'neutron_net_id': 'fake-net-id',
                    'neutron_subnet_id': 'fake-subnet-id'}
        self._driver.setup_server(net_info)
        sim.set_up_service_instance.assert_called_once_with(
            self._context,
            'fake',
            'fake-net-id',
            'fake-subnet-id')

    def test__setup_server_revert(self):

        def raise_exception(*args, **kwargs):
            raise exception.ServiceInstanceException

        net_info = {'server_id': 'fake',
                    'neutron_net_id': 'fake-net-id',
                    'neutron_subnet_id': 'fake-subnet-id'}
        self.stubs.Set(self._driver.service_instance_manager,
                       'set_up_service_instance',
                       mock.Mock(side_effect=raise_exception))
        self.assertRaises(exception.ServiceInstanceException,
                          self._driver.setup_server,
                          net_info)

    def test__teardown_server(self):
        server_details = {
            'instance_id': 'fake_instance_id',
            'subnet_id': 'fake_subnet_id',
            'router_id': 'fake_router_id',
        }
        self._driver.teardown_server(server_details)
        self._driver.service_instance_manager.delete_service_instance.\
            assert_called_once_with(
                self._driver.admin_context, server_details['instance_id'],
                server_details['subnet_id'], server_details['router_id'])

    def test_ssh_exec_connection_not_exist(self):
        ssh_output = 'fake_ssh_output'
        cmd = ['fake', 'command']
        ssh = mock.Mock()
        ssh.get_transport = mock.Mock()
        ssh.get_transport().is_active = mock.Mock(return_value=True)
        ssh_pool = mock.Mock()
        ssh_pool.create = mock.Mock(return_value=ssh)
        self.stubs.Set(utils, 'SSHPool', mock.Mock(return_value=ssh_pool))
        self.stubs.Set(processutils, 'ssh_execute',
                       mock.Mock(return_value=ssh_output))
        self._driver.ssh_connections = {}

        result = self._driver._ssh_exec(self.server, cmd)

        utils.SSHPool.assert_called_once_with(
            self.server['ip'], 22, None, self.server['username'],
            self.server['password'], self.server['pk_path'], max_size=1)
        ssh_pool.create.assert_called_once_with()
        processutils.ssh_execute.assert_called_once_with(ssh, 'fake command')
        ssh.get_transport().is_active.assert_called_once_with()
        self.assertEqual(
            self._driver.ssh_connections,
            {self.server['instance_id']: (ssh_pool, ssh)}
        )
        self.assertEqual(ssh_output, result)

    def test_ssh_exec_connection_exist(self):
        ssh_output = 'fake_ssh_output'
        cmd = ['fake', 'command']
        ssh = mock.Mock()
        ssh.get_transport = mock.Mock()
        ssh.get_transport().is_active = mock.Mock(side_effect=lambda: True)
        ssh_pool = mock.Mock()
        self.stubs.Set(processutils, 'ssh_execute',
                       mock.Mock(return_value=ssh_output))
        self._driver.ssh_connections = {
            self.server['instance_id']: (ssh_pool, ssh)
        }

        result = self._driver._ssh_exec(self.server, cmd)

        processutils.ssh_execute.assert_called_once_with(ssh, 'fake command')
        ssh.get_transport().is_active.assert_called_once_with()
        self.assertEqual(
            self._driver.ssh_connections,
            {self.server['instance_id']: (ssh_pool, ssh)}
        )
        self.assertEqual(ssh_output, result)

    def test_ssh_exec_connection_recreation(self):
        ssh_output = 'fake_ssh_output'
        cmd = ['fake', 'command']
        ssh = mock.Mock()
        ssh.get_transport = mock.Mock()
        ssh.get_transport().is_active = mock.Mock(side_effect=lambda: False)
        ssh_pool = mock.Mock()
        ssh_pool.create = mock.Mock(side_effect=lambda: ssh)
        ssh_pool.remove = mock.Mock()
        self.stubs.Set(processutils, 'ssh_execute',
                       mock.Mock(return_value=ssh_output))
        self._driver.ssh_connections = {
            self.server['instance_id']: (ssh_pool, ssh)
        }

        result = self._driver._ssh_exec(self.server, cmd)

        processutils.ssh_execute.assert_called_once_with(ssh, 'fake command')
        ssh.get_transport().is_active.assert_called_once_with()
        ssh_pool.create.assert_called_once_with()
        ssh_pool.remove.assert_called_once_with(ssh)
        self.assertEqual(
            self._driver.ssh_connections,
            {self.server['instance_id']: (ssh_pool, ssh)}
        )
        self.assertEqual(ssh_output, result)

    def test_get_share_stats_refresh_false(self):
        self._driver._stats = {'fake_key': 'fake_value'}

        result = self._driver.get_share_stats(False)

        self.assertEqual(self._driver._stats, result)

    def test_get_share_stats_refresh_true(self):
        fake_stats = {'fake_key': 'fake_value'}
        self._driver._stats = fake_stats
        expected_keys = [
            'QoS_support', 'driver_version', 'share_backend_name',
            'free_capacity_gb', 'total_capacity_gb',
            'driver_handles_share_servers',
            'reserved_percentage', 'vendor_name', 'storage_protocol',
        ]

        result = self._driver.get_share_stats(True)

        self.assertNotEqual(fake_stats, result)
        for key in expected_keys:
            self.assertIn(key, result)
        self.assertEqual(True, result['driver_handles_share_servers'])
        self.assertEqual('Open Source', result['vendor_name'])


@generic.ensure_server
def fake(driver_instance, context, share_server=None):
    return share_server


@ddt.ddt
class GenericDriverEnsureServerTestCase(test.TestCase):

    def setUp(self):
        super(GenericDriverEnsureServerTestCase, self).setUp()
        self._context = context.get_admin_context()
        self.server = {'id': 'fake_id', 'backend_details': {'foo': 'bar'}}
        self.dhss_false = type(
            'Fake', (object,), {'driver_handles_share_servers': False})
        self.dhss_true = type(
            'Fake', (object,), {'driver_handles_share_servers': True})

    def test_share_servers_are_not_handled_server_not_provided(self):
        self.dhss_false.service_instance_manager = mock.Mock()
        self.dhss_false.service_instance_manager.get_common_server = (
            mock.Mock(return_value=self.server))
        self.dhss_false.service_instance_manager.ensure_service_instance = (
            mock.Mock(return_value=True))

        actual = fake(self.dhss_false, self._context)

        self.assertEqual(self.server, actual)
        self.dhss_false.service_instance_manager.\
            get_common_server.assert_called_once_with()
        self.dhss_false.service_instance_manager.ensure_service_instance.\
            assert_called_once_with(
                self._context, self.server['backend_details'])

    @ddt.data({'id': 'without_details'},
              {'id': 'with_details', 'backend_details': {'foo': 'bar'}})
    def test_share_servers_are_not_handled_server_provided(self, server):
        self.assertRaises(
            exception.ManilaException,
            fake, self.dhss_false, self._context, share_server=server)

    def test_share_servers_are_handled_server_provided(self):
        self.dhss_true.service_instance_manager = mock.Mock()
        self.dhss_true.service_instance_manager.ensure_service_instance = (
            mock.Mock(return_value=True))

        actual = fake(self.dhss_true, self._context, share_server=self.server)

        self.assertEqual(self.server, actual)
        self.dhss_true.service_instance_manager.ensure_service_instance.\
            assert_called_once_with(
                self._context, self.server['backend_details'])

    def test_share_servers_are_handled_invalid_server_provided(self):
        server = {'id': 'without_details'}

        self.assertRaises(
            exception.ManilaException,
            fake, self.dhss_true, self._context, share_server=server)

    def test_share_servers_are_handled_server_not_provided(self):
        self.assertRaises(
            exception.ManilaException, fake, self.dhss_true, self._context)


class NFSHelperTestCase(test.TestCase):
    """Test case for NFS helper of generic driver."""

    def setUp(self):
        super(NFSHelperTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        self.fake_conf = manila.share.configuration.Configuration(None)
        self._ssh_exec = mock.Mock(return_value=('', ''))
        self._execute = mock.Mock(return_value=('', ''))
        self._helper = generic.NFSHelper(self._execute, self._ssh_exec,
                                         self.fake_conf)
        ip = '10.254.0.3'
        self.server = fake_compute.FakeServer(
            ip=ip, public_address=ip, instance_id='fake_instance_id')

    def test_create_export(self):
        ret = self._helper.create_export(self.server, 'fake_share')
        expected_location = ':'.join([self.server['public_address'],
                                      os.path.join(CONF.share_mount_path,
                                                   'fake_share')])
        self.assertEqual(ret, expected_location)

    def test_allow_access(self):
        self.stubs.Set(self._helper, '_sync_nfs_temp_and_perm_files',
                       mock.Mock())
        self._helper.allow_access(self.server, 'fake_share',
                                  'ip', '10.0.0.2')
        local_path = os.path.join(CONF.share_mount_path, 'fake_share')
        self._ssh_exec.assert_has_calls([
            mock.call(self.server, ['sudo', 'exportfs']),
            mock.call(self.server, ['sudo', 'exportfs', '-o',
                                    'rw,no_subtree_check',
                                    ':'.join(['10.0.0.2', local_path])])
        ])
        self._helper._sync_nfs_temp_and_perm_files.assert_called_once_with(
            self.server)

    def test_allow_access_no_ip(self):
        self.assertRaises(
            exception.InvalidShareAccess,
            self._helper.allow_access,
            self.server, 'fake_share', 'fake', 'fakerule',
        )

    def test_deny_access(self):
        self.stubs.Set(self._helper, '_sync_nfs_temp_and_perm_files',
                       mock.Mock())
        local_path = os.path.join(CONF.share_mount_path, 'fake_share')
        self._helper.deny_access(self.server, 'fake_share', 'ip', '10.0.0.2')
        export_string = ':'.join(['10.0.0.2', local_path])
        expected_exec = ['sudo', 'exportfs', '-u', export_string]
        self._ssh_exec.assert_called_once_with(self.server, expected_exec)
        self._helper._sync_nfs_temp_and_perm_files.assert_called_once_with(
            self.server)

    def test_sync_nfs_temp_and_perm_files(self):
        self._helper._sync_nfs_temp_and_perm_files(self.server)
        self._helper._ssh_exec.assert_called_once_with(self.server, mock.ANY)


class CIFSHelperTestCase(test.TestCase):
    """Test case for CIFS helper of generic driver."""

    def setUp(self):
        super(CIFSHelperTestCase, self).setUp()
        self.server_details = {'instance_id': 'fake',
                               'public_address': '1.2.3.4', }
        self.share_name = 'fake_share_name'
        self.fake_conf = manila.share.configuration.Configuration(None)
        self._ssh_exec = mock.Mock(return_value=('', ''))
        self._execute = mock.Mock(return_value=('', ''))
        self._helper = generic.CIFSHelper(self._execute, self._ssh_exec,
                                          self.fake_conf)

    def test_init_helper(self):
        self._helper.init_helper(self.server_details)
        self._helper._ssh_exec.assert_called_once_with(
            self.server_details,
            ['sudo', 'net', 'conf', 'list'],
        )

    def test_create_export_share_does_not_exist(self):
        def fake_ssh_exec(*args, **kwargs):
            if 'showshare' in args[1]:
                raise exception.ProcessExecutionError()
            else:
                return ('', '')

        self.stubs.Set(self._helper, '_ssh_exec',
                       mock.Mock(side_effect=fake_ssh_exec))

        ret = self._helper.create_export(self.server_details, self.share_name)
        expected_location = '//%s/%s' % (
            self.server_details['public_address'], self.share_name)
        self.assertEqual(ret, expected_location)
        share_path = os.path.join(
            self._helper.configuration.share_mount_path,
            self.share_name)
        self._helper._ssh_exec.assert_has_calls([
            mock.call(
                self.server_details,
                ['sudo', 'net', 'conf', 'showshare', self.share_name, ]
            ),
            mock.call(
                self.server_details,
                [
                    'sudo', 'net', 'conf', 'addshare', self.share_name,
                    share_path, 'writeable=y', 'guest_ok=y',
                ]
            ),
            mock.call(self.server_details, mock.ANY),
        ])

    def test_create_export_share_exist_recreate_true(self):
        ret = self._helper.create_export(self.server_details, self.share_name,
                                         recreate=True)
        expected_location = '//%s/%s' % (
            self.server_details['public_address'], self.share_name)
        self.assertEqual(ret, expected_location)
        share_path = os.path.join(
            self._helper.configuration.share_mount_path,
            self.share_name)
        self._helper._ssh_exec.assert_has_calls([
            mock.call(
                self.server_details,
                ['sudo', 'net', 'conf', 'showshare', self.share_name, ]
            ),
            mock.call(
                self.server_details,
                ['sudo', 'net', 'conf', 'delshare', self.share_name, ]
            ),
            mock.call(
                self.server_details,
                [
                    'sudo', 'net', 'conf', 'addshare', self.share_name,
                    share_path, 'writeable=y', 'guest_ok=y',
                ]
            ),
            mock.call(self.server_details, mock.ANY),
        ])

    def test_create_export_share_exist_recreate_false(self):
        self.assertRaises(
            exception.ShareBackendException,
            self._helper.create_export,
            self.server_details,
            self.share_name,
            recreate=False,
        )
        self._helper._ssh_exec.assert_has_calls([
            mock.call(
                self.server_details,
                ['sudo', 'net', 'conf', 'showshare', self.share_name, ]
            ),
        ])

    def test_remove_export(self):
        self._helper.remove_export(self.server_details, self.share_name)
        self._helper._ssh_exec.assert_called_once_with(
            self.server_details,
            ['sudo', 'net', 'conf', 'delshare', self.share_name],
        )

    def test_remove_export_forcibly(self):
        delshare_command = ['sudo', 'net', 'conf', 'delshare', self.share_name]

        def fake_ssh_exec(*args, **kwargs):
            if delshare_command == args[1]:
                raise exception.ProcessExecutionError()
            else:
                return ('', '')

        self.stubs.Set(self._helper, '_ssh_exec',
                       mock.Mock(side_effect=fake_ssh_exec))

        self._helper.remove_export(self.server_details, self.share_name)

        self._helper._ssh_exec.assert_has_calls([
            mock.call(
                self.server_details,
                ['sudo', 'net', 'conf', 'delshare', self.share_name],
            ),
            mock.call(
                self.server_details,
                ['sudo', 'smbcontrol', 'all', 'close-share', self.share_name],
            ),
        ])

    def test_allow_access_ip_exist(self):
        ip = '1.1.1.1'
        hosts = [ip, ]
        self.stubs.Set(self._helper, '_get_allow_hosts',
                       mock.Mock(return_value=hosts))
        self.stubs.Set(self._helper, '_set_allow_hosts', mock.Mock())

        self.assertRaises(
            exception.ShareAccessExists,
            self._helper.allow_access,
            self.server_details,
            self.share_name,
            'ip',
            ip,
        )

        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_has_calls([])

    def test_allow_access_ip_does_not_exist(self):
        ip = '1.1.1.1'
        hosts = []
        self.stubs.Set(self._helper, '_get_allow_hosts',
                       mock.Mock(return_value=hosts))
        self.stubs.Set(self._helper, '_set_allow_hosts', mock.Mock())

        self._helper.allow_access(
            self.server_details, self.share_name, 'ip', ip)

        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_called_once_with(
            self.server_details, hosts, self.share_name)

    def test_allow_access_wrong_type(self):
        self.assertRaises(
            exception.InvalidShareAccess,
            self._helper.allow_access,
            self.server_details,
            self.share_name,
            'fake',
            '1.1.1.1',
        )

    def test_deny_access_list_has_value(self):
        ip = '1.1.1.1'
        hosts = [ip, ]
        self.stubs.Set(self._helper, '_get_allow_hosts',
                       mock.Mock(return_value=hosts))
        self.stubs.Set(self._helper, '_set_allow_hosts', mock.Mock())

        self._helper.deny_access(
            self.server_details, self.share_name, 'ip', ip)

        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_called_once_with(
            self.server_details, [], self.share_name)

    def test_deny_access_list_does_not_have_value(self):
        ip = '1.1.1.1'
        hosts = []
        self.stubs.Set(self._helper, '_get_allow_hosts',
                       mock.Mock(return_value=hosts))
        self.stubs.Set(self._helper, '_set_allow_hosts', mock.Mock())

        self._helper.deny_access(
            self.server_details, self.share_name, 'ip', ip)

        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_has_calls([])

    def test_deny_access_force(self):
        self.stubs.Set(
            self._helper,
            '_get_allow_hosts',
            mock.Mock(side_effect=exception.ProcessExecutionError()),
        )
        self.stubs.Set(self._helper, '_set_allow_hosts', mock.Mock())

        self._helper.deny_access(
            self.server_details, self.share_name, 'ip', '1.1.1.1', force=True)

        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_has_calls([])

    def test_deny_access_not_force(self):
        def raise_process_execution_error(*args, **kwargs):
            raise exception.ProcessExecutionError()

        self.stubs.Set(self._helper, '_get_allow_hosts',
                       mock.Mock(side_effect=raise_process_execution_error))
        self.stubs.Set(self._helper, '_set_allow_hosts', mock.Mock())
        self.assertRaises(
            exception.ProcessExecutionError,
            self._helper.deny_access,
            self.server_details,
            self.share_name,
            'ip',
            '1.1.1.1',
        )
        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_has_calls([])
