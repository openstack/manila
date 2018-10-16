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
import time

import ddt
import mock
from oslo_concurrency import processutils
from oslo_config import cfg
from six import moves

from manila.common import constants as const
from manila import compute
from manila import context
from manila import exception
import manila.share.configuration
from manila.share.drivers import generic
from manila.share import share_types
from manila import test
from manila.tests import fake_compute
from manila.tests import fake_service_instance
from manila.tests import fake_share
from manila.tests import fake_volume
from manila import utils
from manila import volume


CONF = cfg.CONF


def get_fake_manage_share():
    return {
        'id': 'fake',
        'share_proto': 'NFS',
        'share_type_id': 'fake',
        'export_locations': [
            {'path': '10.0.0.1:/foo/fake/path'},
            {'path': '11.0.0.1:/bar/fake/path'},
        ],
    }


def get_fake_snap_dict():
    snap_dict = {
        'status': 'available',
        'project_id': '13c0be6290934bd98596cfa004650049',
        'user_id': 'a0314a441ca842019b0952224aa39192',
        'description': None,
        'deleted': '0',
        'created_at': '2015-08-10 00:05:58',
        'updated_at': '2015-08-10 00:05:58',
        'consistency_group_id': None,
        'deleted_at': None,
        'id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
        'name': None,
    }
    return snap_dict


def get_fake_access_rule(access_to, access_level, access_type='ip'):
    return {
        'access_type': access_type,
        'access_to': access_to,
        'access_level': access_level,
    }


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

        self.fake_private_storage = mock.Mock()
        self.mock_object(self.fake_private_storage, 'get',
                         mock.Mock(return_value=None))

        with mock.patch.object(
                generic.service_instance,
                'ServiceInstanceManager',
                fake_service_instance.FakeServiceInstanceManager):
            self._driver = generic.GenericShareDriver(
                private_storage=self.fake_private_storage,
                execute=self._execute, configuration=self.fake_conf)
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

        self.mock_object(utils, 'synchronized',
                         mock.Mock(return_value=lambda f: f))
        self.mock_object(generic.os.path, 'exists',
                         mock.Mock(return_value=True))
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
                'public_address': 'fake_public_address',
                'instance_id': 'fake',
                'service_ip': 'fake_ip',
            },
            'availability_zone': 'fake_az',
        }
        self.access = fake_share.fake_access()
        self.snapshot = fake_share.fake_snapshot()
        self.mock_object(time, 'sleep')
        self.mock_debug_log = self.mock_object(generic.LOG, 'debug')
        self.mock_warning_log = self.mock_object(generic.LOG, 'warning')
        self.mock_error_log = self.mock_object(generic.LOG, 'error')
        self.mock_exception_log = self.mock_object(generic.LOG, 'exception')

    @ddt.data(True, False)
    def test_do_setup_with_dhss(self, dhss):
        CONF.set_default('driver_handles_share_servers', dhss)
        fake_server = {'id': 'fake_server_id'}
        self.mock_object(volume, 'API')
        self.mock_object(compute, 'API')
        self.mock_object(self._driver, '_setup_helpers')
        self.mock_object(
            self._driver,
            '_is_share_server_active', mock.Mock(return_value=True))
        self.mock_object(
            self._driver.service_instance_manager,
            'get_common_server', mock.Mock(return_value=fake_server))

        self._driver.do_setup(self._context)

        volume.API.assert_called_once_with()
        compute.API.assert_called_once_with()
        self._driver._setup_helpers.assert_called_once_with()
        if not dhss:
            (self._driver.service_instance_manager.get_common_server.
                assert_called_once_with())
            self._driver._is_share_server_active.assert_called_once_with(
                self._context, fake_server)
        else:
            self.assertFalse(
                self._driver.service_instance_manager.get_common_server.called)
            self.assertFalse(self._driver._is_share_server_active.called)

    @mock.patch('time.sleep')
    def test_do_setup_dhss_false_server_avail_after_retry(self, mock_sleep):
        # This tests the scenario in which the common share server cannot be
        # retrieved during the first attempt, is not active during the second,
        # becoming active during the third attempt.
        CONF.set_default('driver_handles_share_servers', False)
        fake_server = {'id': 'fake_server_id'}
        self.mock_object(volume, 'API')
        self.mock_object(compute, 'API')
        self.mock_object(self._driver, '_setup_helpers')
        self.mock_object(
            self._driver,
            '_is_share_server_active', mock.Mock(side_effect=[False, True]))
        self.mock_object(
            self._driver.service_instance_manager,
            'get_common_server',
            mock.Mock(side_effect=[exception.ManilaException,
                                   fake_server,
                                   fake_server]))

        self._driver.do_setup(self._context)

        volume.API.assert_called_once_with()
        compute.API.assert_called_once_with()
        self._driver._setup_helpers.assert_called_once_with()
        (self._driver.service_instance_manager.get_common_server.
            assert_has_calls([mock.call()] * 3))
        self._driver._is_share_server_active.assert_has_calls(
            [mock.call(self._context, fake_server)] * 2)
        mock_sleep.assert_has_calls([mock.call(5)] * 2)

    def test_setup_helpers(self):
        self._driver._helpers = {}
        CONF.set_default('share_helpers', ['NFS=fakenfs'])
        self.mock_object(generic.importutils, 'import_class',
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
        self.assertEqual(1, len(self._driver._helpers))

    def test_setup_helpers_no_helpers(self):
        self._driver._helpers = {}
        CONF.set_default('share_helpers', [])
        self.assertRaises(exception.ManilaException,
                          self._driver._setup_helpers)

    def test_create_share(self):
        volume = 'fake_volume'
        volume2 = 'fake_volume2'
        self.mock_object(self._driver, '_allocate_container',
                         mock.Mock(return_value=volume))
        self.mock_object(self._driver, '_attach_volume',
                         mock.Mock(return_value=volume2))
        self.mock_object(self._driver, '_format_device')
        self.mock_object(self._driver, '_mount_device')

        result = self._driver.create_share(
            self._context, self.share, share_server=self.server)

        self.assertEqual(self._helper_nfs.create_exports.return_value, result)
        self._driver._allocate_container.assert_called_once_with(
            self._driver.admin_context, self.share, snapshot=None)
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

    def test_create_share_invalid_helper(self):
        self._driver._helpers = {'CIFS': self._helper_cifs}
        self.assertRaises(exception.InvalidShare, self._driver.create_share,
                          self._context, self.share, share_server=self.server)

    def test_is_device_file_available(self):
        volume = {'mountpoint': 'fake_mount_point'}
        self.mock_object(self._driver, '_ssh_exec',
                         mock.Mock(return_value=None))

        self._driver._is_device_file_available(self.server, volume)

        self._driver._ssh_exec.assert_called_once_with(
            self.server, ['sudo', 'test', '-b', volume['mountpoint']])

    def test_format_device(self):
        volume = {'mountpoint': 'fake_mount_point'}
        self.mock_object(self._driver, '_ssh_exec',
                         mock.Mock(return_value=('', '')))
        self.mock_object(self._driver, '_is_device_file_available')

        self._driver._format_device(self.server, volume)

        self._driver._is_device_file_available.assert_called_once_with(
            self.server, volume)
        self._driver._ssh_exec.assert_called_once_with(
            self.server,
            ['sudo', 'mkfs.%s' % self.fake_conf.share_volume_fstype,
             volume['mountpoint']])

    def test_mount_device_not_present(self):
        server = {'instance_id': 'fake_server_id'}
        mount_path = self._driver._get_mount_path(self.share)
        volume = {'mountpoint': 'fake_mount_point'}
        self.mock_object(self._driver, '_is_device_mounted',
                         mock.Mock(return_value=False))
        self.mock_object(self._driver, '_add_mount_permanently')
        self.mock_object(self._driver, '_ssh_exec',
                         mock.Mock(return_value=('', '')))

        self._driver._mount_device(self.share, server, volume)

        self._driver._is_device_mounted.assert_called_once_with(
            mount_path, server, volume)
        self._driver._add_mount_permanently.assert_called_once_with(
            self.share.id, server)
        self._driver._ssh_exec.assert_called_once_with(
            server, (
                'sudo', 'mkdir', '-p', mount_path,
                '&&', 'sudo', 'mount', volume['mountpoint'], mount_path,
                '&&', 'sudo', 'chmod', '777', mount_path,
                '&&', 'sudo', 'umount', mount_path,
                '&&', 'sudo', 'e2fsck', '-y', '-f', volume['mountpoint'],
                '&&', 'sudo', 'tune2fs', '-U', 'random', volume['mountpoint'],
                '&&', 'sudo', 'mount', volume['mountpoint'], mount_path,
            ),
        )

    def test_mount_device_present(self):
        mount_path = '/fake/mount/path'
        volume = {'mountpoint': 'fake_mount_point'}
        self.mock_object(self._driver, '_is_device_mounted',
                         mock.Mock(return_value=True))
        self.mock_object(self._driver, '_get_mount_path',
                         mock.Mock(return_value=mount_path))
        self.mock_object(generic.LOG, 'warning')

        self._driver._mount_device(self.share, self.server, volume)

        self._driver._get_mount_path.assert_called_once_with(self.share)
        self._driver._is_device_mounted.assert_called_once_with(
            mount_path, self.server, volume)
        generic.LOG.warning.assert_called_once_with(mock.ANY, mock.ANY)

    def test_mount_device_exception_raised(self):
        volume = {'mountpoint': 'fake_mount_point'}

        self.mock_object(
            self._driver, '_is_device_mounted',
            mock.Mock(side_effect=exception.ProcessExecutionError))

        self.assertRaises(
            exception.ShareBackendException,
            self._driver._mount_device,
            self.share,
            self.server,
            volume,
        )
        self._driver._is_device_mounted.assert_called_once_with(
            self._driver._get_mount_path(self.share), self.server, volume)

    def test_unmount_device_present(self):
        mount_path = '/fake/mount/path'
        self.mock_object(self._driver, '_is_device_mounted',
                         mock.Mock(return_value=True))
        self.mock_object(self._driver, '_remove_mount_permanently')
        self.mock_object(self._driver, '_get_mount_path',
                         mock.Mock(return_value=mount_path))
        self.mock_object(self._driver, '_ssh_exec',
                         mock.Mock(return_value=('', '')))

        self._driver._unmount_device(self.share, self.server)

        self._driver._get_mount_path.assert_called_once_with(self.share)
        self._driver._is_device_mounted.assert_called_once_with(
            mount_path, self.server)
        self._driver._remove_mount_permanently.assert_called_once_with(
            self.share.id, self.server)
        self._driver._ssh_exec.assert_called_once_with(
            self.server,
            ['sudo', 'umount', mount_path, '&&', 'sudo', 'rmdir', mount_path],
        )

    def test_unmount_device_retry_once(self):
        self.counter = 0

        def _side_effect(*args):
            self.counter += 1
            if self.counter < 2:
                raise exception.ProcessExecutionError

        mount_path = '/fake/mount/path'
        self.mock_object(self._driver, '_is_device_mounted',
                         mock.Mock(return_value=True))
        self.mock_object(self._driver, '_remove_mount_permanently')
        self.mock_object(self._driver, '_get_mount_path',
                         mock.Mock(return_value=mount_path))
        self.mock_object(self._driver, '_ssh_exec',
                         mock.Mock(side_effect=_side_effect))

        self._driver._unmount_device(self.share, self.server)

        self.assertEqual(1, time.sleep.call_count)
        self.assertEqual([mock.call(self.share) for i in moves.range(2)],
                         self._driver._get_mount_path.mock_calls)
        self.assertEqual([mock.call(mount_path,
                                    self.server) for i in moves.range(2)],
                         self._driver._is_device_mounted.mock_calls)
        self._driver._remove_mount_permanently.assert_called_once_with(
            self.share.id, self.server)
        self.assertEqual(
            [mock.call(self.server, ['sudo', 'umount', mount_path,
                                     '&&', 'sudo', 'rmdir', mount_path])
             for i in moves.range(2)],
            self._driver._ssh_exec.mock_calls,
        )

    def test_unmount_device_not_present(self):
        mount_path = '/fake/mount/path'
        self.mock_object(self._driver, '_is_device_mounted',
                         mock.Mock(return_value=False))
        self.mock_object(self._driver, '_get_mount_path',
                         mock.Mock(return_value=mount_path))
        self.mock_object(generic.LOG, 'warning')

        self._driver._unmount_device(self.share, self.server)

        self._driver._get_mount_path.assert_called_once_with(self.share)
        self._driver._is_device_mounted.assert_called_once_with(
            mount_path, self.server)
        generic.LOG.warning.assert_called_once_with(mock.ANY, mock.ANY)

    def test_is_device_mounted_true(self):
        volume = {'mountpoint': 'fake_mount_point', 'id': 'fake_id'}
        mount_path = '/fake/mount/path'
        mounts = "%(dev)s on %(path)s" % {'dev': volume['mountpoint'],
                                          'path': mount_path}
        self.mock_object(self._driver, '_ssh_exec',
                         mock.Mock(return_value=(mounts, '')))

        result = self._driver._is_device_mounted(
            mount_path, self.server, volume)

        self._driver._ssh_exec.assert_called_once_with(
            self.server, ['sudo', 'mount'])
        self.assertTrue(result)

    def test_is_device_mounted_true_no_volume_provided(self):
        mount_path = '/fake/mount/path'
        mounts = "/fake/dev/path on %(path)s type fake" % {'path': mount_path}
        self.mock_object(self._driver, '_ssh_exec',
                         mock.Mock(return_value=(mounts, '')))

        result = self._driver._is_device_mounted(mount_path, self.server)

        self._driver._ssh_exec.assert_called_once_with(
            self.server, ['sudo', 'mount'])
        self.assertTrue(result)

    def test_is_device_mounted_false(self):
        mount_path = '/fake/mount/path'
        volume = {'mountpoint': 'fake_mount_point', 'id': 'fake_id'}
        mounts = "%(dev)s on %(path)s" % {'dev': '/fake',
                                          'path': mount_path}
        self.mock_object(self._driver, '_ssh_exec',
                         mock.Mock(return_value=(mounts, '')))

        result = self._driver._is_device_mounted(
            mount_path, self.server, volume)

        self._driver._ssh_exec.assert_called_once_with(
            self.server, ['sudo', 'mount'])
        self.assertFalse(result)

    def test_is_device_mounted_false_no_volume_provided(self):
        mount_path = '/fake/mount/path'
        mounts = "%(path)s" % {'path': 'fake'}
        self.mock_object(self._driver, '_ssh_exec',
                         mock.Mock(return_value=(mounts, '')))
        self.mock_object(self._driver, '_get_mount_path',
                         mock.Mock(return_value=mount_path))

        result = self._driver._is_device_mounted(mount_path, self.server)

        self._driver._ssh_exec.assert_called_once_with(
            self.server, ['sudo', 'mount'])
        self.assertFalse(result)

    def test_add_mount_permanently(self):
        self.mock_object(self._driver, '_ssh_exec')
        self._driver._add_mount_permanently(self.share.id, self.server)
        self._driver._ssh_exec.has_calls(
            mock.call(
                self.server,
                ['grep', self.share.id, const.MOUNT_FILE_TEMP,
                 '|', 'sudo', 'tee', '-a', const.MOUNT_FILE]),
            mock.call(self.server, ['sudo', 'mount', '-a'])
        )

    def test_add_mount_permanently_raise_error_on_add(self):
        self.mock_object(
            self._driver, '_ssh_exec',
            mock.Mock(side_effect=exception.ProcessExecutionError))
        self.assertRaises(
            exception.ShareBackendException,
            self._driver._add_mount_permanently,
            self.share.id,
            self.server
        )
        self._driver._ssh_exec.assert_called_once_with(
            self.server,
            ['grep', self.share.id, const.MOUNT_FILE_TEMP,
             '|', 'sudo', 'tee', '-a', const.MOUNT_FILE],
        )

    def test_remove_mount_permanently(self):
        self.mock_object(self._driver, '_ssh_exec')
        self._driver._remove_mount_permanently(self.share.id, self.server)
        self._driver._ssh_exec.assert_called_once_with(
            self.server,
            ['sudo', 'sed', '-i', '\'/%s/d\'' % self.share.id,
             const.MOUNT_FILE],
        )

    def test_remove_mount_permanently_raise_error_on_remove(self):
        self.mock_object(
            self._driver, '_ssh_exec',
            mock.Mock(side_effect=exception.ProcessExecutionError))
        self.assertRaises(
            exception.ShareBackendException,
            self._driver._remove_mount_permanently,
            self.share.id,
            self.server
        )
        self._driver._ssh_exec.assert_called_once_with(
            self.server,
            ['sudo', 'sed', '-i', '\'/%s/d\'' % self.share.id,
             const.MOUNT_FILE],
        )

    def test_get_mount_path(self):
        result = self._driver._get_mount_path(self.share)
        self.assertEqual(os.path.join(CONF.share_mount_path,
                                      self.share['name']), result)

    def test_attach_volume_not_attached(self):
        available_volume = fake_volume.FakeVolume()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.mock_object(self._driver.compute_api, 'instance_volume_attach')
        self.mock_object(self._driver.volume_api, 'get',
                         mock.Mock(return_value=attached_volume))

        result = self._driver._attach_volume(self._context, self.share,
                                             'fake_inst_id', available_volume)

        (self._driver.compute_api.instance_volume_attach.
            assert_called_once_with(self._context, 'fake_inst_id',
                                    available_volume['id']))
        self._driver.volume_api.get.assert_called_once_with(
            self._context, attached_volume['id'])
        self.assertEqual(attached_volume, result)

    def test_attach_volume_attached_correct(self):
        fake_server = fake_compute.FakeServer()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.mock_object(self._driver.compute_api, 'instance_volumes_list',
                         mock.Mock(return_value=[attached_volume]))

        result = self._driver._attach_volume(self._context, self.share,
                                             fake_server, attached_volume)

        self.assertEqual(attached_volume, result)

    def test_attach_volume_attached_incorrect(self):
        fake_server = fake_compute.FakeServer()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        anoter_volume = fake_volume.FakeVolume(id='fake_id2', status='in-use')
        self.mock_object(self._driver.compute_api, 'instance_volumes_list',
                         mock.Mock(return_value=[anoter_volume]))
        self.assertRaises(exception.ManilaException,
                          self._driver._attach_volume, self._context,
                          self.share, fake_server, attached_volume)

    @ddt.data(exception.ManilaException, exception.Invalid)
    def test_attach_volume_failed_attach(self, side_effect):
        fake_server = fake_compute.FakeServer()
        available_volume = fake_volume.FakeVolume()
        self.mock_object(self._driver.compute_api, 'instance_volume_attach',
                         mock.Mock(side_effect=side_effect))
        self.assertRaises(exception.ManilaException,
                          self._driver._attach_volume,
                          self._context, self.share, fake_server,
                          available_volume)
        self.assertEqual(
            3, self._driver.compute_api.instance_volume_attach.call_count)

    def test_attach_volume_attached_retry_correct(self):
        fake_server = fake_compute.FakeServer()
        attached_volume = fake_volume.FakeVolume(status='available')
        in_use_volume = fake_volume.FakeVolume(status='in-use')

        side_effect = [exception.Invalid("Fake"), attached_volume]
        attach_mock = mock.Mock(side_effect=side_effect)
        self.mock_object(self._driver.compute_api, 'instance_volume_attach',
                         attach_mock)
        self.mock_object(self._driver.compute_api, 'instance_volumes_list',
                         mock.Mock(return_value=[attached_volume]))
        self.mock_object(self._driver.volume_api, 'get',
                         mock.Mock(return_value=in_use_volume))

        result = self._driver._attach_volume(self._context, self.share,
                                             fake_server, attached_volume)

        self.assertEqual(in_use_volume, result)
        self.assertEqual(
            2, self._driver.compute_api.instance_volume_attach.call_count)

    def test_attach_volume_error(self):
        fake_server = fake_compute.FakeServer()
        available_volume = fake_volume.FakeVolume()
        error_volume = fake_volume.FakeVolume(status='error')
        self.mock_object(self._driver.compute_api, 'instance_volume_attach')
        self.mock_object(self._driver.volume_api, 'get',
                         mock.Mock(return_value=error_volume))
        self.assertRaises(exception.ManilaException,
                          self._driver._attach_volume,
                          self._context, self.share,
                          fake_server, available_volume)

    def test_get_volume(self):
        volume = fake_volume.FakeVolume(
            name=CONF.volume_name_template % self.share['id'])
        self.mock_object(self._driver.volume_api, 'get_all',
                         mock.Mock(return_value=[volume]))
        result = self._driver._get_volume(self._context, self.share['id'])
        self.assertEqual(volume, result)
        self._driver.volume_api.get_all.assert_called_once_with(
            self._context, {'all_tenants': True, 'name': volume['name']})

    def test_get_volume_with_private_data(self):
        volume = fake_volume.FakeVolume()
        self.mock_object(self._driver.volume_api, 'get',
                         mock.Mock(return_value=volume))
        self.mock_object(self.fake_private_storage, 'get',
                         mock.Mock(return_value=volume['id']))

        result = self._driver._get_volume(self._context, self.share['id'])

        self.assertEqual(volume, result)
        self._driver.volume_api.get.assert_called_once_with(
            self._context, volume['id'])
        self.fake_private_storage.get.assert_called_once_with(
            self.share['id'], 'volume_id'
        )

    def test_get_volume_none(self):
        vol_name = (
            self._driver.configuration.volume_name_template % self.share['id'])
        self.mock_object(self._driver.volume_api, 'get_all',
                         mock.Mock(return_value=[]))

        result = self._driver._get_volume(self._context, self.share['id'])

        self.assertIsNone(result)
        self._driver.volume_api.get_all.assert_called_once_with(
            self._context, {'all_tenants': True, 'name': vol_name})

    def test_get_volume_error(self):
        volume = fake_volume.FakeVolume(
            name=CONF.volume_name_template % self.share['id'])
        self.mock_object(self._driver.volume_api, 'get_all',
                         mock.Mock(return_value=[volume, volume]))
        self.assertRaises(exception.ManilaException,
                          self._driver._get_volume,
                          self._context, self.share['id'])
        self._driver.volume_api.get_all.assert_called_once_with(
            self._context, {'all_tenants': True, 'name': volume['name']})

    def test_get_volume_snapshot(self):
        volume_snapshot = fake_volume.FakeVolumeSnapshot(
            name=self._driver.configuration.volume_snapshot_name_template %
            self.snapshot['id'])
        self.mock_object(self._driver.volume_api, 'get_all_snapshots',
                         mock.Mock(return_value=[volume_snapshot]))
        result = self._driver._get_volume_snapshot(self._context,
                                                   self.snapshot['id'])
        self.assertEqual(volume_snapshot, result)
        self._driver.volume_api.get_all_snapshots.assert_called_once_with(
            self._context, {'name': volume_snapshot['name']})

    def test_get_volume_snapshot_with_private_data(self):
        volume_snapshot = fake_volume.FakeVolumeSnapshot()
        self.mock_object(self._driver.volume_api, 'get_snapshot',
                         mock.Mock(return_value=volume_snapshot))
        self.mock_object(self.fake_private_storage, 'get',
                         mock.Mock(return_value=volume_snapshot['id']))
        result = self._driver._get_volume_snapshot(self._context,
                                                   self.snapshot['id'])
        self.assertEqual(volume_snapshot, result)
        self._driver.volume_api.get_snapshot.assert_called_once_with(
            self._context, volume_snapshot['id'])
        self.fake_private_storage.get.assert_called_once_with(
            self.snapshot['id'], 'volume_snapshot_id'
        )

    def test_get_volume_snapshot_none(self):
        snap_name = (
            self._driver.configuration.volume_snapshot_name_template %
            self.share['id'])
        self.mock_object(self._driver.volume_api, 'get_all_snapshots',
                         mock.Mock(return_value=[]))
        result = self._driver._get_volume_snapshot(self._context,
                                                   self.share['id'])
        self.assertIsNone(result)
        self._driver.volume_api.get_all_snapshots.assert_called_once_with(
            self._context, {'name': snap_name})

    def test_get_volume_snapshot_error(self):
        volume_snapshot = fake_volume.FakeVolumeSnapshot(
            name=self._driver.configuration.volume_snapshot_name_template %
            self.snapshot['id'])
        self.mock_object(
            self._driver.volume_api, 'get_all_snapshots',
            mock.Mock(return_value=[volume_snapshot, volume_snapshot]))
        self.assertRaises(
            exception.ManilaException, self._driver._get_volume_snapshot,
            self._context, self.snapshot['id'])
        self._driver.volume_api.get_all_snapshots.assert_called_once_with(
            self._context, {'name': volume_snapshot['name']})

    def test_detach_volume(self):
        available_volume = fake_volume.FakeVolume()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.mock_object(self._driver, '_get_volume',
                         mock.Mock(return_value=attached_volume))
        self.mock_object(self._driver.compute_api, 'instance_volumes_list',
                         mock.Mock(return_value=[attached_volume]))
        self.mock_object(self._driver.compute_api, 'instance_volume_detach')
        self.mock_object(self._driver.volume_api, 'get',
                         mock.Mock(return_value=available_volume))

        self._driver._detach_volume(self._context, self.share,
                                    self.server['backend_details'])

        (self._driver.compute_api.instance_volume_detach.
            assert_called_once_with(
                self._context,
                self.server['backend_details']['instance_id'],
                available_volume['id']))
        self._driver.volume_api.get.assert_called_once_with(
            self._context, available_volume['id'])

    def test_detach_volume_detached(self):
        available_volume = fake_volume.FakeVolume()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.mock_object(self._driver, '_get_volume',
                         mock.Mock(return_value=attached_volume))
        self.mock_object(self._driver.compute_api, 'instance_volumes_list',
                         mock.Mock(return_value=[]))
        self.mock_object(self._driver.volume_api, 'get',
                         mock.Mock(return_value=available_volume))
        self.mock_object(self._driver.compute_api, 'instance_volume_detach')

        self._driver._detach_volume(self._context, self.share,
                                    self.server['backend_details'])

        self.assertFalse(self._driver.volume_api.get.called)
        self.assertFalse(
            self._driver.compute_api.instance_volume_detach.called)

    def test_allocate_container(self):
        fake_vol = fake_volume.FakeVolume()
        self.fake_conf.cinder_volume_type = 'fake_volume_type'
        self.mock_object(self._driver.volume_api, 'create',
                         mock.Mock(return_value=fake_vol))

        result = self._driver._allocate_container(self._context, self.share)
        self.assertEqual(fake_vol, result)
        self._driver.volume_api.create.assert_called_once_with(
            self._context,
            self.share['size'],
            CONF.volume_name_template % self.share['id'],
            '',
            snapshot=None,
            volume_type='fake_volume_type',
            availability_zone=self.share['availability_zone'])

    def test_allocate_container_with_snaphot(self):
        fake_vol = fake_volume.FakeVolume()
        fake_vol_snap = fake_volume.FakeVolumeSnapshot()
        self.mock_object(self._driver, '_get_volume_snapshot',
                         mock.Mock(return_value=fake_vol_snap))
        self.mock_object(self._driver.volume_api, 'create',
                         mock.Mock(return_value=fake_vol))

        result = self._driver._allocate_container(self._context,
                                                  self.share,
                                                  self.snapshot)
        self.assertEqual(fake_vol, result)
        self._driver.volume_api.create.assert_called_once_with(
            self._context,
            self.share['size'],
            CONF.volume_name_template % self.share['id'],
            '',
            snapshot=fake_vol_snap,
            volume_type=None,
            availability_zone=self.share['availability_zone'])

    def test_allocate_container_error(self):
        fake_vol = fake_volume.FakeVolume(status='error')
        self.mock_object(self._driver.volume_api, 'create',
                         mock.Mock(return_value=fake_vol))

        self.assertRaises(exception.ManilaException,
                          self._driver._allocate_container,
                          self._context,
                          self.share)

    def test_wait_for_available_volume(self):
        fake_volume = {'status': 'creating', 'id': 'fake'}
        fake_available_volume = {'status': 'available', 'id': 'fake'}
        self.mock_object(self._driver.volume_api, 'get',
                         mock.Mock(return_value=fake_available_volume))

        actual_result = self._driver._wait_for_available_volume(
            fake_volume, 5, "error", "timeout")

        self.assertEqual(fake_available_volume, actual_result)
        self._driver.volume_api.get.assert_called_once_with(
            mock.ANY, fake_volume['id'])

    @mock.patch('time.sleep')
    def test_wait_for_available_volume_error_extending(self, mock_sleep):
        fake_volume = {'status': 'error_extending', 'id': 'fake'}
        self.assertRaises(exception.ManilaException,
                          self._driver._wait_for_available_volume,
                          fake_volume, 5, 'error', 'timeout')
        self.assertFalse(mock_sleep.called)

    @mock.patch('time.sleep')
    def test_wait_for_extending_volume(self, mock_sleep):
        initial_size = 1
        expected_size = 2
        mock_volume = fake_volume.FakeVolume(status='available',
                                             size=initial_size)
        mock_extending_vol = fake_volume.FakeVolume(status='extending',
                                                    size=initial_size)
        mock_extended_vol = fake_volume.FakeVolume(status='available',
                                                   size=expected_size)

        self.mock_object(self._driver.volume_api, 'get',
                         mock.Mock(side_effect=[mock_extending_vol,
                                                mock_extended_vol]))

        result = self._driver._wait_for_available_volume(
            mock_volume, 5, "error", "timeout",
            expected_size=expected_size)

        expected_get_count = 2

        self.assertEqual(mock_extended_vol, result)
        self._driver.volume_api.get.assert_has_calls(
            [mock.call(self._driver.admin_context, mock_volume['id'])] *
            expected_get_count)
        mock_sleep.assert_has_calls([mock.call(1)] * expected_get_count)

    @ddt.data(mock.Mock(return_value={'status': 'creating', 'id': 'fake'}),
              mock.Mock(return_value={'status': 'error', 'id': 'fake'}))
    def test_wait_for_available_volume_invalid(self, volume_get_mock):
        fake_volume = {'status': 'creating', 'id': 'fake'}
        self.mock_object(self._driver.volume_api, 'get', volume_get_mock)
        self.mock_object(time, 'time',
                         mock.Mock(side_effect=[1.0, 1.33, 1.67, 2.0]))

        self.assertRaises(
            exception.ManilaException,
            self._driver._wait_for_available_volume,
            fake_volume, 1, "error", "timeout"
        )

    def test_deallocate_container(self):
        fake_vol = fake_volume.FakeVolume()
        self.mock_object(self._driver, '_get_volume',
                         mock.Mock(return_value=fake_vol))
        self.mock_object(self._driver.volume_api, 'delete')
        self.mock_object(self._driver.volume_api, 'get', mock.Mock(
            side_effect=exception.VolumeNotFound(volume_id=fake_vol['id'])))

        self._driver._deallocate_container(self._context, self.share)

        self._driver._get_volume.assert_called_once_with(
            self._context, self.share['id'])
        self._driver.volume_api.delete.assert_called_once_with(
            self._context, fake_vol['id'])
        self._driver.volume_api.get.assert_called_once_with(
            self._context, fake_vol['id'])

    def test_deallocate_container_with_volume_not_found(self):
        fake_vol = fake_volume.FakeVolume()
        self.mock_object(self._driver, '_get_volume',
                         mock.Mock(side_effect=exception.VolumeNotFound(
                             volume_id=fake_vol['id'])))
        self.mock_object(self._driver.volume_api, 'delete')

        self._driver._deallocate_container(self._context, self.share)

        self._driver._get_volume.assert_called_once_with(
            self._context, self.share['id'])
        self.assertFalse(self._driver.volume_api.delete.called)

    def test_create_share_from_snapshot(self):
        vol1 = 'fake_vol1'
        vol2 = 'fake_vol2'
        self.mock_object(self._driver, '_allocate_container',
                         mock.Mock(return_value=vol1))
        self.mock_object(self._driver, '_attach_volume',
                         mock.Mock(return_value=vol2))
        self.mock_object(self._driver, '_mount_device')

        result = self._driver.create_share_from_snapshot(
            self._context,
            self.share,
            self.snapshot,
            share_server=self.server)

        self.assertEqual(self._helper_nfs.create_exports.return_value, result)
        self._driver._allocate_container.assert_called_once_with(
            self._driver.admin_context, self.share, snapshot=self.snapshot)
        self._driver._attach_volume.assert_called_once_with(
            self._driver.admin_context, self.share,
            self.server['backend_details']['instance_id'], vol1)
        self._driver._mount_device.assert_called_once_with(
            self.share, self.server['backend_details'], vol2)
        self._helper_nfs.create_exports.assert_called_once_with(
            self.server['backend_details'], self.share['name'])

    def test_create_share_from_snapshot_invalid_helper(self):
        self._driver._helpers = {'CIFS': self._helper_cifs}
        self.assertRaises(exception.InvalidShare,
                          self._driver.create_share_from_snapshot,
                          self._context, self.share, self.snapshot,
                          share_server=self.server)

    def test_delete_share_no_share_servers_handling(self):
        self.mock_object(self._driver, '_deallocate_container')
        self.mock_object(
            self._driver.service_instance_manager,
            'get_common_server', mock.Mock(return_value=self.server))
        self.mock_object(
            self._driver.service_instance_manager,
            'ensure_service_instance', mock.Mock(return_value=False))

        CONF.set_default('driver_handles_share_servers', False)

        self._driver.delete_share(self._context, self.share)

        (self._driver.service_instance_manager.get_common_server.
            assert_called_once_with())
        self._driver._deallocate_container.assert_called_once_with(
            self._driver.admin_context, self.share)
        (self._driver.service_instance_manager.ensure_service_instance.
            assert_called_once_with(
                self._context, self.server['backend_details']))

    def test_delete_share(self):
        self.mock_object(self._driver, '_unmount_device')
        self.mock_object(self._driver, '_detach_volume')
        self.mock_object(self._driver, '_deallocate_container')

        self._driver.delete_share(
            self._context, self.share, share_server=self.server)

        self._helper_nfs.remove_exports.assert_called_once_with(
            self.server['backend_details'], self.share['name'])
        self._driver._unmount_device.assert_called_once_with(
            self.share, self.server['backend_details'])
        self._driver._detach_volume.assert_called_once_with(
            self._driver.admin_context, self.share,
            self.server['backend_details'])
        self._driver._deallocate_container.assert_called_once_with(
            self._driver.admin_context, self.share)
        (self._driver.service_instance_manager.ensure_service_instance.
            assert_called_once_with(
                self._context, self.server['backend_details']))

    def test_detach_volume_with_volume_not_found(self):
        fake_vol = fake_volume.FakeVolume()
        fake_server_details = mock.MagicMock()
        self.mock_object(self._driver.compute_api, 'instance_volumes_list',
                         mock.Mock(return_value=[]))

        self.mock_object(self._driver, '_get_volume',
                         mock.Mock(side_effect=exception.VolumeNotFound(
                             volume_id=fake_vol['id'])))

        self._driver._detach_volume(self._context,
                                    self.share,
                                    fake_server_details)

        (self._driver.compute_api.instance_volumes_list.
            assert_called_once_with(self._driver.admin_context,
                                    fake_server_details['instance_id']))
        (self._driver._get_volume.
            assert_called_once_with(self._driver.admin_context,
                                    self.share['id']))
        self.assertEqual(1, self.mock_warning_log.call_count)

    def test_delete_share_without_share_server(self):
        self.mock_object(self._driver, '_unmount_device')
        self.mock_object(self._driver, '_detach_volume')
        self.mock_object(self._driver, '_deallocate_container')

        self._driver.delete_share(
            self._context, self.share, share_server=None)

        self.assertFalse(self._helper_nfs.remove_export.called)
        self.assertFalse(self._driver._unmount_device.called)
        self.assertFalse(self._driver._detach_volume.called)
        self._driver._deallocate_container.assert_called_once_with(
            self._driver.admin_context, self.share)

    def test_delete_share_without_server_backend_details(self):
        self.mock_object(self._driver, '_unmount_device')
        self.mock_object(self._driver, '_detach_volume')
        self.mock_object(self._driver, '_deallocate_container')

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
        self.mock_object(self._driver, '_unmount_device')
        self.mock_object(self._driver, '_detach_volume')
        self.mock_object(self._driver, '_deallocate_container')

        self.mock_object(
            self._driver.service_instance_manager,
            'ensure_service_instance', mock.Mock(return_value=False))
        self._driver.delete_share(
            self._context, self.share, share_server=self.server)

        self.assertFalse(self._helper_nfs.remove_export.called)
        self.assertFalse(self._driver._unmount_device.called)
        self.assertFalse(self._driver._detach_volume.called)
        self._driver._deallocate_container.assert_called_once_with(
            self._driver.admin_context, self.share)
        (self._driver.service_instance_manager.ensure_service_instance.
            assert_called_once_with(
                self._context, self.server['backend_details']))

    def test_delete_share_invalid_helper(self):
        self._driver._helpers = {'CIFS': self._helper_cifs}
        self.assertRaises(exception.InvalidShare,
                          self._driver.delete_share,
                          self._context, self.share, share_server=self.server)

    def test_create_snapshot(self):
        fake_vol = fake_volume.FakeVolume()
        fake_vol_snap = fake_volume.FakeVolumeSnapshot(
            share_instance_id=fake_vol['id'])
        self.mock_object(self._driver, '_get_volume',
                         mock.Mock(return_value=fake_vol))
        self.mock_object(self._driver.volume_api, 'create_snapshot_force',
                         mock.Mock(return_value=fake_vol_snap))

        self._driver.create_snapshot(self._context, fake_vol_snap,
                                     share_server=self.server)

        self._driver._get_volume.assert_called_once_with(
            self._driver.admin_context, fake_vol_snap['share_instance_id'])
        self._driver.volume_api.create_snapshot_force.assert_called_once_with(
            self._context,
            fake_vol['id'],
            CONF.volume_snapshot_name_template % fake_vol_snap['id'],
            ''
        )

    def test_delete_snapshot(self):
        fake_vol_snap = fake_volume.FakeVolumeSnapshot()
        fake_vol_snap2 = {'id': 'fake_vol_snap2'}
        self.mock_object(self._driver, '_get_volume_snapshot',
                         mock.Mock(return_value=fake_vol_snap2))
        self.mock_object(self._driver.volume_api, 'delete_snapshot')
        self.mock_object(
            self._driver.volume_api, 'get_snapshot',
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
        self.mock_object(self._driver, '_get_volume',
                         mock.Mock(return_value=vol1))
        self.mock_object(self._driver, '_attach_volume',
                         mock.Mock(return_value=vol2))
        self.mock_object(self._driver, '_mount_device')

        self._driver.ensure_share(
            self._context, self.share, share_server=self.server)

        self._driver._get_volume.assert_called_once_with(
            self._context, self.share['id'])
        self._driver._attach_volume.assert_called_once_with(
            self._context, self.share,
            self.server['backend_details']['instance_id'], vol1)
        self._driver._mount_device.assert_called_once_with(
            self.share, self.server['backend_details'], vol2)
        self._helper_nfs.create_exports.assert_called_once_with(
            self.server['backend_details'], self.share['name'], recreate=True)

    def test_ensure_share_volume_is_absent(self):
        self.mock_object(
            self._driver, '_get_volume', mock.Mock(return_value=None))
        self.mock_object(self._driver, '_attach_volume')

        self._driver.ensure_share(
            self._context, self.share, share_server=self.server)

        self._driver._get_volume.assert_called_once_with(
            self._context, self.share['id'])
        self.assertFalse(self._driver._attach_volume.called)

    def test_ensure_share_invalid_helper(self):
        self._driver._helpers = {'CIFS': self._helper_cifs}
        self.assertRaises(exception.InvalidShare, self._driver.ensure_share,
                          self._context, self.share, share_server=self.server)

    @ddt.data(const.ACCESS_LEVEL_RW, const.ACCESS_LEVEL_RO)
    def test_update_access(self, access_level):

        # fakes
        access_rules = [get_fake_access_rule('1.1.1.1', access_level),
                        get_fake_access_rule('2.2.2.2', access_level)]
        add_rules = [get_fake_access_rule('2.2.2.2', access_level), ]
        delete_rules = [get_fake_access_rule('3.3.3.3', access_level), ]

        # run
        self._driver.update_access(self._context, self.share, access_rules,
                                   add_rules=add_rules,
                                   delete_rules=delete_rules,
                                   share_server=self.server)

        # asserts
        (self._driver._helpers[self.share['share_proto']].
            update_access.assert_called_once_with(
                self.server['backend_details'], self.share['name'],
                access_rules, add_rules=add_rules, delete_rules=delete_rules))

    @ddt.data(fake_share.fake_share(),
              fake_share.fake_share(share_proto='NFSBOGUS'),
              fake_share.fake_share(share_proto='CIFSBOGUS'))
    def test__get_helper_with_wrong_proto(self, share):
        self.assertRaises(exception.InvalidShare,
                          self._driver._get_helper, share)

    def test__setup_server(self):
        sim = self._driver.instance_manager
        net_info = {
            'server_id': 'fake',
            'neutron_net_id': 'fake-net-id',
            'neutron_subnet_id': 'fake-subnet-id',
        }
        self._driver.setup_server(net_info)
        sim.set_up_service_instance.assert_called_once_with(
            self._context, net_info)

    def test__setup_server_revert(self):

        def raise_exception(*args, **kwargs):
            raise exception.ServiceInstanceException

        net_info = {'server_id': 'fake',
                    'neutron_net_id': 'fake-net-id',
                    'neutron_subnet_id': 'fake-subnet-id'}
        self.mock_object(self._driver.service_instance_manager,
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
        (self._driver.service_instance_manager.delete_service_instance.
            assert_called_once_with(
                self._driver.admin_context, server_details))

    def test_ssh_exec_connection_not_exist(self):
        ssh_conn_timeout = 30
        CONF.set_default('ssh_conn_timeout', ssh_conn_timeout)
        ssh_output = 'fake_ssh_output'
        cmd = ['fake', 'command']
        ssh = mock.Mock()
        ssh.get_transport = mock.Mock()
        ssh.get_transport().is_active = mock.Mock(return_value=True)
        ssh_pool = mock.Mock()
        ssh_pool.create = mock.Mock(return_value=ssh)
        self.mock_object(utils, 'SSHPool', mock.Mock(return_value=ssh_pool))
        self.mock_object(processutils, 'ssh_execute',
                         mock.Mock(return_value=ssh_output))
        self._driver.ssh_connections = {}

        result = self._driver._ssh_exec(self.server, cmd)

        utils.SSHPool.assert_called_once_with(
            self.server['ip'], 22, ssh_conn_timeout, self.server['username'],
            self.server['password'], self.server['pk_path'], max_size=1)
        ssh_pool.create.assert_called_once_with()
        processutils.ssh_execute.assert_called_once_with(
            ssh, 'fake command', check_exit_code=True)
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
        self.mock_object(processutils, 'ssh_execute',
                         mock.Mock(return_value=ssh_output))
        self._driver.ssh_connections = {
            self.server['instance_id']: (ssh_pool, ssh)
        }

        result = self._driver._ssh_exec(self.server, cmd)

        processutils.ssh_execute.assert_called_once_with(
            ssh, 'fake command', check_exit_code=True)
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
        self.mock_object(processutils, 'ssh_execute',
                         mock.Mock(return_value=ssh_output))
        self._driver.ssh_connections = {
            self.server['instance_id']: (ssh_pool, ssh)
        }

        result = self._driver._ssh_exec(self.server, cmd)

        processutils.ssh_execute.assert_called_once_with(
            ssh, 'fake command', check_exit_code=True)
        ssh.get_transport().is_active.assert_called_once_with()
        ssh_pool.create.assert_called_once_with()
        ssh_pool.remove.assert_called_once_with(ssh)
        self.assertEqual(
            self._driver.ssh_connections,
            {self.server['instance_id']: (ssh_pool, ssh)}
        )
        self.assertEqual(ssh_output, result)

    def test__ssh_exec_check_list_comprehensions_still_work(self):
        ssh_output = 'fake_ssh_output'
        cmd = ['fake', 'command spaced']
        ssh = mock.Mock()
        ssh_pool = mock.Mock()
        ssh_pool.create = mock.Mock(side_effect=lambda: ssh)
        ssh_pool.remove = mock.Mock()
        self.mock_object(processutils, 'ssh_execute',
                         mock.Mock(return_value=ssh_output))
        self._driver.ssh_connections = {
            self.server['instance_id']: (ssh_pool, ssh)
        }

        self._driver._ssh_exec(self.server, cmd)

        processutils.ssh_execute.assert_called_once_with(
            ssh, 'fake "command spaced"', check_exit_code=True)

    def test_get_share_stats_refresh_false(self):
        self._driver._stats = {'fake_key': 'fake_value'}

        result = self._driver.get_share_stats(False)

        self.assertEqual(self._driver._stats, result)

    def test_get_share_stats_refresh_true(self):
        fake_stats = {'fake_key': 'fake_value'}
        self._driver._stats = fake_stats
        expected_keys = [
            'qos', 'driver_version', 'share_backend_name',
            'free_capacity_gb', 'total_capacity_gb',
            'driver_handles_share_servers',
            'reserved_percentage', 'vendor_name', 'storage_protocol',
        ]

        result = self._driver.get_share_stats(True)

        self.assertNotEqual(fake_stats, result)
        for key in expected_keys:
            self.assertIn(key, result)
        self.assertTrue(result['driver_handles_share_servers'])
        self.assertEqual('Open Source', result['vendor_name'])

    def _setup_manage_mocks(self,
                            get_share_type_extra_specs='False',
                            is_device_mounted=True,
                            server_details=None):
        CONF.set_default('driver_handles_share_servers', False)

        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value=get_share_type_extra_specs))

        self.mock_object(self._driver, '_is_device_mounted',
                         mock.Mock(return_value=is_device_mounted))

        self.mock_object(self._driver, 'service_instance_manager')
        server = {'backend_details': server_details}
        self.mock_object(self._driver.service_instance_manager,
                         'get_common_server',
                         mock.Mock(return_value=server))

    def test_manage_invalid_protocol(self):
        share = {'share_proto': 'fake_proto'}
        self._setup_manage_mocks()

        self.assertRaises(exception.InvalidShare,
                          self._driver.manage_existing, share, {})

    def test_manage_not_mounted_share(self):
        share = get_fake_manage_share()
        fake_path = '/foo/bar'
        self._setup_manage_mocks(is_device_mounted=False)
        self.mock_object(
            self._driver._helpers[share['share_proto']],
            'get_share_path_by_export_location',
            mock.Mock(return_value=fake_path))

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver.manage_existing, share, {})

        self.assertEqual(
            1,
            self._driver.service_instance_manager.get_common_server.call_count)
        self._driver._is_device_mounted.assert_called_once_with(
            fake_path, None)
        (self._driver._helpers[share['share_proto']].
            get_share_path_by_export_location.assert_called_once_with(
                None, share['export_locations'][0]['path']))

    def test_manage_share_not_attached_to_cinder_volume_invalid_size(self):
        share = get_fake_manage_share()
        server_details = {}
        fake_path = '/foo/bar'
        self._setup_manage_mocks(server_details=server_details)
        self.mock_object(self._driver, '_get_volume',
                         mock.Mock(return_value=None))
        error = exception.ManageInvalidShare(reason="fake")
        self.mock_object(
            self._driver, '_get_mounted_share_size',
            mock.Mock(side_effect=error))
        self.mock_object(
            self._driver._helpers[share['share_proto']],
            'get_share_path_by_export_location',
            mock.Mock(return_value=fake_path))

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver.manage_existing, share, {})

        self._driver._get_mounted_share_size.assert_called_once_with(
            fake_path, server_details)
        (self._driver._helpers[share['share_proto']].
            get_share_path_by_export_location.assert_called_once_with(
                server_details, share['export_locations'][0]['path']))

    def test_manage_share_not_attached_to_cinder_volume(self):
        share = get_fake_manage_share()
        share_size = "fake"
        fake_path = '/foo/bar'
        fake_exports = ['foo', 'bar']
        server_details = {}
        self._setup_manage_mocks(server_details=server_details)
        self.mock_object(self._driver, '_get_volume')
        self.mock_object(self._driver, '_get_mounted_share_size',
                         mock.Mock(return_value=share_size))
        self.mock_object(
            self._driver._helpers[share['share_proto']],
            'get_share_path_by_export_location',
            mock.Mock(return_value=fake_path))
        self.mock_object(
            self._driver._helpers[share['share_proto']],
            'get_exports_for_share',
            mock.Mock(return_value=fake_exports))

        result = self._driver.manage_existing(share, {})

        self.assertEqual(
            {'size': share_size, 'export_locations': fake_exports}, result)
        (self._driver._helpers[share['share_proto']].get_exports_for_share.
            assert_called_once_with(
                server_details, share['export_locations'][0]['path']))
        (self._driver._helpers[share['share_proto']].
            get_share_path_by_export_location.assert_called_once_with(
                server_details, share['export_locations'][0]['path']))
        self._driver._get_mounted_share_size.assert_called_once_with(
            fake_path, server_details)
        self.assertFalse(self._driver._get_volume.called)

    def test_manage_share_attached_to_cinder_volume_not_found(self):
        share = get_fake_manage_share()
        server_details = {}
        driver_options = {'volume_id': 'fake'}
        self._setup_manage_mocks(server_details=server_details)
        self.mock_object(
            self._driver.volume_api, 'get',
            mock.Mock(side_effect=exception.VolumeNotFound(volume_id="fake"))
        )

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver.manage_existing, share, driver_options)

        self._driver.volume_api.get.assert_called_once_with(
            mock.ANY, driver_options['volume_id'])

    def test_manage_share_attached_to_cinder_volume_not_mounted_to_srv(self):
        share = get_fake_manage_share()
        server_details = {'instance_id': 'fake'}
        driver_options = {'volume_id': 'fake'}
        volume = {'id': 'fake'}
        self._setup_manage_mocks(server_details=server_details)
        self.mock_object(self._driver.volume_api, 'get',
                         mock.Mock(return_value=volume))
        self.mock_object(self._driver.compute_api, 'instance_volumes_list',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver.manage_existing, share, driver_options)

        self._driver.volume_api.get.assert_called_once_with(
            mock.ANY, driver_options['volume_id'])
        self._driver.compute_api.instance_volumes_list.assert_called_once_with(
            mock.ANY, server_details['instance_id'])

    def test_manage_share_attached_to_cinder_volume(self):
        share = get_fake_manage_share()
        fake_size = 'foobar'
        fake_exports = ['foo', 'bar']
        server_details = {'instance_id': 'fake'}
        driver_options = {'volume_id': 'fake'}
        volume = {'id': 'fake', 'name': 'fake_volume_1', 'size': fake_size}
        self._setup_manage_mocks(server_details=server_details)
        self.mock_object(self._driver.volume_api, 'get',
                         mock.Mock(return_value=volume))
        self._driver.volume_api.update = mock.Mock()
        fake_volume = mock.Mock()
        fake_volume.id = 'fake'
        self.mock_object(self._driver.compute_api, 'instance_volumes_list',
                         mock.Mock(return_value=[fake_volume]))
        self.mock_object(
            self._driver._helpers[share['share_proto']],
            'get_exports_for_share',
            mock.Mock(return_value=fake_exports))

        result = self._driver.manage_existing(share, driver_options)

        self.assertEqual(
            {'size': fake_size, 'export_locations': fake_exports}, result)
        (self._driver._helpers[share['share_proto']].get_exports_for_share.
            assert_called_once_with(
                server_details, share['export_locations'][0]['path']))
        expected_volume_update = {
            'name': self._driver._get_volume_name(share['id'])
        }
        self._driver.volume_api.update.assert_called_once_with(
            mock.ANY, volume['id'], expected_volume_update)
        self.fake_private_storage.update.assert_called_once_with(
            share['id'], {'volume_id': volume['id']}
        )

    def test_get_mounted_share_size(self):
        output = ("Filesystem   blocks  Used Available Capacity Mounted on\n"
                  "/dev/fake  1G  1G  1G  4% /shares/share-fake")
        self.mock_object(self._driver, '_ssh_exec',
                         mock.Mock(return_value=(output, '')))

        actual_result = self._driver._get_mounted_share_size('/fake/path', {})
        self.assertEqual(1, actual_result)

    @ddt.data("fake\nfake\n", "fake", "fake\n")
    def test_get_mounted_share_size_invalid_output(self, output):
        self.mock_object(self._driver, '_ssh_exec',
                         mock.Mock(return_value=(output, '')))
        self.assertRaises(exception.ManageInvalidShare,
                          self._driver._get_mounted_share_size,
                          '/fake/path', {})

    def test_get_consumed_space(self):
        mount_path = "fake_path"
        server_details = {}
        index = 2
        valid_result = 1
        self.mock_object(self._driver, '_get_mount_stats_by_index',
                         mock.Mock(return_value=valid_result * 1024))

        actual_result = self._driver._get_consumed_space(
            mount_path, server_details)

        self.assertEqual(valid_result, actual_result)
        self._driver._get_mount_stats_by_index.assert_called_once_with(
            mount_path, server_details, index, block_size='M'
        )

    def test_get_consumed_space_invalid(self):
        self.mock_object(
            self._driver,
            '_get_mount_stats_by_index',
            mock.Mock(side_effect=exception.ManilaException("fake"))
        )

        self.assertRaises(
            exception.InvalidShare,
            self._driver._get_consumed_space,
            "fake", "fake"
        )

    @ddt.data(100, 130, 123)
    def test_extend_share(self, volume_size):
        fake_volume = {
            "name": "fake",
            "size": volume_size,
        }
        fake_share = {
            'id': 'fake',
            'share_proto': 'NFS',
            'name': 'test_share',
        }
        new_size = 123
        srv_details = self.server['backend_details']
        self.mock_object(
            self._driver.service_instance_manager,
            'get_common_server',
            mock.Mock(return_value=self.server)
        )
        self.mock_object(self._driver, '_unmount_device')
        self.mock_object(self._driver, '_detach_volume')
        self.mock_object(self._driver, '_extend_volume')
        self.mock_object(self._driver, '_attach_volume')
        self.mock_object(self._driver, '_mount_device')
        self.mock_object(self._driver, '_resize_filesystem')
        self.mock_object(
            self._driver, '_get_volume',
            mock.Mock(return_value=fake_volume)
        )
        CONF.set_default('driver_handles_share_servers', False)

        self._driver.extend_share(fake_share, new_size)

        self.assertTrue(
            self._driver.service_instance_manager.get_common_server.called)
        self._driver._unmount_device.assert_called_once_with(
            fake_share, srv_details)
        self._driver._get_volume.assert_called_once_with(
            mock.ANY, fake_share['id'])

        if new_size > volume_size:
            self._driver._detach_volume.assert_called_once_with(
                mock.ANY, fake_share, srv_details)
            self._driver._extend_volume.assert_called_once_with(
                mock.ANY, fake_volume, new_size)
            self._driver._attach_volume.assert_called_once_with(
                mock.ANY, fake_share, srv_details['instance_id'], mock.ANY)
        else:
            self.assertFalse(self._driver._detach_volume.called)
            self.assertFalse(self._driver._extend_volume.called)
            self.assertFalse(self._driver._attach_volume.called)

        (self._helper_nfs.disable_access_for_maintenance.
            assert_called_once_with(srv_details, 'test_share'))
        (self._helper_nfs.restore_access_after_maintenance.
            assert_called_once_with(srv_details, 'test_share'))
        self.assertTrue(self._driver._resize_filesystem.called)

    def test_extend_volume(self):
        fake_volume = {'id': 'fake'}
        new_size = 123
        self.mock_object(self._driver.volume_api, 'extend')
        self.mock_object(self._driver, '_wait_for_available_volume')

        self._driver._extend_volume(self._context, fake_volume, new_size)

        self._driver.volume_api.extend.assert_called_once_with(
            self._context, fake_volume['id'], new_size
        )
        self._driver._wait_for_available_volume.assert_called_once_with(
            fake_volume, mock.ANY, msg_timeout=mock.ANY, msg_error=mock.ANY,
            expected_size=new_size
        )

    def test_resize_filesystem(self):
        fake_server_details = {'fake': 'fake'}
        fake_volume = {'mountpoint': '/dev/fake'}
        self.mock_object(self._driver, '_ssh_exec')

        self._driver._resize_filesystem(
            fake_server_details, fake_volume, new_size=123)

        self._driver._ssh_exec.assert_any_call(
            fake_server_details, ['sudo', 'fsck', '-pf', '/dev/fake'])
        self._driver._ssh_exec.assert_any_call(
            fake_server_details,
            ['sudo', 'resize2fs', '/dev/fake', "%sG" % 123]
        )
        self.assertEqual(2, self._driver._ssh_exec.call_count)

    @ddt.data(
        {
            'source': processutils.ProcessExecutionError(
                stderr="resize2fs: New size smaller than minimum (123456)"),
            'target': exception.Invalid
        },
        {
            'source': processutils.ProcessExecutionError(stderr="fake_error"),
            'target': exception.ManilaException
        }
    )
    @ddt.unpack
    def test_resize_filesystem_invalid_new_size(self, source, target):
        fake_server_details = {'fake': 'fake'}
        fake_volume = {'mountpoint': '/dev/fake'}
        ssh_mock = mock.Mock(side_effect=["fake", source])
        self.mock_object(self._driver, '_ssh_exec', ssh_mock)

        self.assertRaises(
            target,
            self._driver._resize_filesystem,
            fake_server_details, fake_volume, new_size=123
        )

    def test_shrink_share_invalid_size(self):
        fake_share = {'id': 'fake', 'export_locations': [{'path': 'test'}]}
        new_size = 123
        self.mock_object(
            self._driver.service_instance_manager,
            'get_common_server',
            mock.Mock(return_value=self.server)
        )
        self.mock_object(self._driver, '_get_helper')
        self.mock_object(self._driver, '_get_consumed_space',
                         mock.Mock(return_value=200))
        CONF.set_default('driver_handles_share_servers', False)

        self.assertRaises(
            exception.ShareShrinkingPossibleDataLoss,
            self._driver.shrink_share,
            fake_share,
            new_size
        )

        self._driver._get_helper.assert_called_once_with(fake_share)
        self._driver._get_consumed_space.assert_called_once_with(
            mock.ANY, self.server['backend_details'])

    def _setup_shrink_mocks(self):
        share = {'id': 'fake', 'export_locations': [{'path': 'test'}],
                 'name': 'fake'}
        volume = {'id': 'fake'}
        new_size = 123
        server_details = self.server['backend_details']
        self.mock_object(
            self._driver.service_instance_manager,
            'get_common_server',
            mock.Mock(return_value=self.server)
        )
        helper = mock.Mock()
        self.mock_object(self._driver, '_get_helper',
                         mock.Mock(return_value=helper))
        self.mock_object(self._driver, '_get_consumed_space',
                         mock.Mock(return_value=100))
        self.mock_object(self._driver, '_get_volume',
                         mock.Mock(return_value=volume))
        self.mock_object(self._driver, '_unmount_device')
        self.mock_object(self._driver, '_mount_device')
        CONF.set_default('driver_handles_share_servers', False)

        return share, volume, new_size, server_details, helper

    @ddt.data({'source': exception.Invalid("fake"),
               'target': exception.ShareShrinkingPossibleDataLoss},
              {'source': exception.ManilaException("fake"),
               'target': exception.Invalid})
    @ddt.unpack
    def test_shrink_share_error_on_resize_fs(self, source, target):
        share, vol, size, server_details, _ = self._setup_shrink_mocks()
        resize_mock = mock.Mock(side_effect=source)
        self.mock_object(self._driver, '_resize_filesystem', resize_mock)

        self.assertRaises(target, self._driver.shrink_share, share, size)

        resize_mock.assert_called_once_with(server_details, vol,
                                            new_size=size)

    def test_shrink_share(self):
        share, vol, size, server_details, helper = self._setup_shrink_mocks()
        self.mock_object(self._driver, '_resize_filesystem')

        self._driver.shrink_share(share, size)

        self._driver._get_helper.assert_called_once_with(share)
        self._driver._get_consumed_space.assert_called_once_with(
            mock.ANY, server_details)
        self._driver._get_volume.assert_called_once_with(mock.ANY, share['id'])
        self._driver._unmount_device.assert_called_once_with(share,
                                                             server_details)
        self._driver._resize_filesystem(
            server_details, vol, new_size=size)
        self._driver._mount_device(share, server_details, vol)
        self.assertTrue(helper.disable_access_for_maintenance.called)
        self.assertTrue(helper.restore_access_after_maintenance.called)

    @ddt.data({'share_servers': [], 'result': None},
              {'share_servers': None, 'result': None},
              {'share_servers': ['fake'], 'result': 'fake'},
              {'share_servers': ['fake', 'test'], 'result': 'fake'})
    @ddt.unpack
    def tests_choose_share_server_compatible_with_share(self, share_servers,
                                                        result):
        fake_share = "fake"

        actual_result = self._driver.choose_share_server_compatible_with_share(
            self._context, share_servers, fake_share
        )

        self.assertEqual(result, actual_result)

    def test_manage_snapshot_not_found(self):
        snapshot_instance = {'id': 'snap_instance_id',
                             'provider_location': 'vol_snap_id'}
        driver_options = {}
        self.mock_object(
            self._driver.volume_api, 'get_snapshot',
            mock.Mock(side_effect=exception.VolumeSnapshotNotFound(
                      snapshot_id='vol_snap_id')))

        self.assertRaises(exception.ManageInvalidShareSnapshot,
                          self._driver.manage_existing_snapshot,
                          snapshot_instance,
                          driver_options)
        self._driver.volume_api.get_snapshot.assert_called_once_with(
            self._context, 'vol_snap_id')

    def test_manage_snapshot_valid(self):
        snapshot_instance = {'id': 'snap_instance_id',
                             'provider_location': 'vol_snap_id'}
        volume_snapshot = {'id': 'vol_snap_id', 'size': 1}
        self.mock_object(self._driver.volume_api, 'get_snapshot',
                         mock.Mock(return_value=volume_snapshot))
        ret_manage = self._driver.manage_existing_snapshot(
            snapshot_instance, {})

        self.assertEqual({'provider_location': 'vol_snap_id',
                          'size': 1}, ret_manage)

        self._driver.volume_api.get_snapshot.assert_called_once_with(
            self._context, 'vol_snap_id')

    def test_unmanage_snapshot(self):
        snapshot_instance = {'id': 'snap_instance_id',
                             'provider_location': 'vol_snap_id'}
        self.mock_object(self._driver.private_storage, 'delete')
        self._driver.unmanage_snapshot(snapshot_instance)

        self._driver.private_storage.delete.assert_called_once_with(
            'snap_instance_id')


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
        (self.dhss_false.service_instance_manager.
            get_common_server.assert_called_once_with())
        (self.dhss_false.service_instance_manager.ensure_service_instance.
            assert_called_once_with(
                self._context, self.server['backend_details']))

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
        (self.dhss_true.service_instance_manager.ensure_service_instance.
            assert_called_once_with(
                self._context, self.server['backend_details']))

    def test_share_servers_are_handled_invalid_server_provided(self):
        server = {'id': 'without_details'}

        self.assertRaises(
            exception.ManilaException,
            fake, self.dhss_true, self._context, share_server=server)

    def test_share_servers_are_handled_server_not_provided(self):
        self.assertRaises(
            exception.ManilaException, fake, self.dhss_true, self._context)
