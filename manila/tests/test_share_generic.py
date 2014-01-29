# Copyright 2014 Mirantis Inc.
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

import copy
import mock
import os

from manila import context

from manila import compute
from manila import exception
from manila.network.neutron import api as neutron
from manila import volume

from manila.share.configuration import Configuration
from manila.share.drivers import generic
from manila import test
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_compute
from manila.tests import fake_network
from manila.tests import fake_utils
from manila.tests import fake_volume

from oslo.config import cfg

CONF = cfg.CONF


def fake_share(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'NFS',
        'share_network_id': 'fake share network id',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)


def fake_snapshot(**kwargs):
    snapshot = {
        'id': 'fakesnapshotid',
        'share_name': 'fakename',
        'share_id': 'fakeid',
        'name': 'fakesnapshotname',
        'share_size': 1,
        'share_proto': 'NFS',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }
    snapshot.update(kwargs)
    return db_fakes.FakeModel(snapshot)


def fake_access(**kwargs):
    access = {
        'id': 'fakeaccid',
        'access_type': 'ip',
        'access_to': '10.0.0.2',
        'state': 'active',
    }
    access.update(kwargs)
    return db_fakes.FakeModel(access)


class GenericShareDriverTestCase(test.TestCase):
    """Tests GenericShareDriver."""

    def setUp(self):
        super(GenericShareDriverTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._execute = mock.Mock(return_value=('', ''))

        self._helper_cifs = mock.Mock()
        self._helper_nfs = mock.Mock()
        self.fake_conf = Configuration(None)
        self._db = mock.Mock()
        self._driver = generic.GenericShareDriver(self._db,
                                                  execute=self._execute,
                                                  configuration=self.fake_conf)
        self._driver.service_tenant_id = 'service tenant id'
        self._driver.service_network_id = 'service network id'
        self._driver.neutron_api = fake_network.API()
        self._driver.compute_api = fake_compute.API()
        self._driver.volume_api = fake_volume.API()
        self._driver.share_networks_locks = {}
        self._driver.share_networks_servers = {}
        self._driver.admin_context = self._context
        self._driver.vif_driver = mock.Mock()
        self.stubs.Set(generic, '_ssh_exec', mock.Mock())
        self.stubs.Set(generic, 'synchronized', mock.Mock(side_effect=
                                                          lambda f: f))
        self.stubs.Set(generic.os.path, 'exists', mock.Mock(return_value=True))
        self._driver._helpers = {
            'CIFS': self._helper_cifs,
            'NFS': self._helper_nfs,
        }
        self.share = fake_share()
        self.access = fake_access()
        self.snapshot = fake_snapshot()

    def test_do_setup(self):
        self.stubs.Set(neutron, 'API', mock.Mock())
        self.stubs.Set(volume, 'API', mock.Mock())
        self.stubs.Set(compute, 'API', mock.Mock())
        self.stubs.Set(self._driver,
                       '_setup_connectivity_with_service_instances',
                       mock.Mock())
        self.stubs.Set(self._driver,
                       '_get_service_network',
                       mock.Mock(return_value='fake network id'))
        self.stubs.Set(self._driver, '_setup_helpers', mock.Mock())
        self._driver.do_setup(self._context)
        neutron.API.assert_called_once()
        volume.API.assert_called_once()
        compute.API.assert_called_once()
        self._driver._setup_helpers.assert_called_once()
        self._driver._setup_connectivity_with_service_instances.\
                                                        assert_called_once()
        self.assertEqual(self._driver.service_network_id, 'fake network id')

    def test_do_setup_exception(self):
        self.stubs.Set(neutron, 'API', mock.Mock())
        neutron.API.return_value = fake_network.API()
        self.stubs.Set(volume, 'API', mock.Mock())
        self.stubs.Set(compute, 'API', mock.Mock())
        self.stubs.Set(neutron.API, 'admin_tenant_id', mock.Mock())
        neutron.API.admin_tenant_id.side_effect = Exception
        self.assertRaises(exception.ManilaException,
                          self._driver.do_setup, self._context)

    def test_get_service_network_net_exists(self):
        net1 = copy.copy(fake_network.API.network)
        net2 = copy.copy(fake_network.API.network)
        net1['name'] = CONF.service_network_name
        net1['id'] = 'fake service network id'
        self.stubs.Set(self._driver.neutron_api, 'get_all_tenant_networks',
                mock.Mock(return_value=[net1, net2]))
        result = self._driver._get_service_network()
        self.assertEqual(result, net1['id'])

    def test_get_service_network_net_does_not_exists(self):
        net = fake_network.FakeNetwork()
        self.stubs.Set(self._driver.neutron_api, 'get_all_tenant_networks',
                mock.Mock(return_value=[]))
        self.stubs.Set(self._driver.neutron_api, 'network_create',
                mock.Mock(return_value=net))
        result = self._driver._get_service_network()
        self.assertEqual(result, net['id'])

    def test_get_service_network_ambiguos(self):
        net = fake_network.FakeNetwork(name=CONF.service_network_name)
        self.stubs.Set(self._driver.neutron_api, 'get_all_tenant_networks',
                mock.Mock(return_value=[net, net]))
        self.assertRaises(exception.ManilaException,
                          self._driver._get_service_network)

    def test_setup_helpers(self):
        CONF.set_default('share_helpers', ['NFS=fakenfs'])
        self.stubs.Set(generic.importutils, 'import_class',
                       mock.Mock(return_value=self._helper_nfs))
        self._driver._setup_helpers()
        generic.importutils.import_class.assert_has_calls([
            mock.call('fakenfs')
        ])
        self._helper_nfs.assert_called_once_with(self._execute,
                                             self.fake_conf,
                                             self._driver.share_networks_locks)
        self.assertEqual(len(self._driver._helpers), 1)

    def test_create_share(self):
        self._helper_nfs.create_export.return_value = 'fakelocation'
        methods = ('_get_service_instance', '_allocate_container',
                '_attach_volume', '_format_device', '_mount_device')
        for method in methods:
            self.stubs.Set(self._driver, method, mock.Mock())
        result = self._driver.create_share(self._context, self.share)
        for method in methods:
            getattr(self._driver, method).assert_called_once()
        self.assertEqual(result, 'fakelocation')

    def test_create_share_exception(self):
        share = fake_share(share_network_id=None)
        self.assertRaises(exception.ManilaException, self._driver.create_share,
                          self._context, share)

    def test_format_device(self):
        volume = {'mountpoint': 'fake_mount_point'}
        self._driver._format_device('fake_server', volume)
        generic._ssh_exec.assert_called_once_with('fake_server',
                ['sudo', 'mkfs.ext4', volume['mountpoint']])

    def _test_mount_device(self):
        volume = {'mountpoint': 'fake_mount_point'}
        self.stubs.Set(self._driver, '_get_mount_path',
                mock.Mock(return_value='fake_mount_path'))

        self._driver._mount_device(self._context, self.share, 'fake_server',
                                   volume)

        generic._ssh_exec.assert_has_calls([
            mock.call('fake_server', ['sudo', 'mkdir', '-p',
                                      'fake_mount_path',
                                      ';', 'sudo', 'mount',
                                      volume['mountpoint'],
                                      'fake_mount_path']),
            mock.call('fake_server', ['sudo', 'chmod', '777',
                      'fake_mount_path'])
            ])

    def test_mount_device_exception_01(self):
        volume = {'mountpoint': 'fake_mount_point'}
        generic._ssh_exec.side_effect = [
               exception.ProcessExecutionError(stderr='already mounted'), None]
        self.stubs.Set(self._driver, '_get_mount_path',
                mock.Mock(return_value='fake_mount_path'))

        self._driver._mount_device(self._context, self.share, 'fake_server',
                                   volume)

        generic._ssh_exec.assert_has_calls([
            mock.call('fake_server', ['sudo', 'mkdir', '-p',
                                      'fake_mount_path',
                                      ';', 'sudo', 'mount',
                                      volume['mountpoint'],
                                      'fake_mount_path']),
            mock.call('fake_server', ['sudo', 'chmod', '777',
                                      'fake_mount_path'])
            ])

    def test_mount_device_exception_02(self):
        volume = {'mountpoint': 'fake_mount_point'}
        generic._ssh_exec.side_effect = exception.ManilaException
        self.stubs.Set(self._driver, '_get_mount_path',
                mock.Mock(return_value='fake_mount_path'))
        self.assertRaises(exception.ManilaException,
                          self._driver._mount_device,
                          self._context, self.share, 'fake_server', volume)

    def test_umount_device(self):
        self.stubs.Set(self._driver, '_get_mount_path',
                mock.Mock(return_value='fake_mount_path'))
        self._driver._unmount_device(self._context, self.share, 'fake_server')
        generic._ssh_exec.assert_called_once_with('fake_server',
            ['sudo', 'umount', 'fake_mount_path', ';', 'sudo', 'rmdir',
             'fake_mount_path'])

    def test_get_mount_path(self):
        result = self._driver._get_mount_path(self.share)
        self.assertEqual(result, os.path.join(CONF.share_mount_path,
                                              self.share['name']))

    def test_attach_volume_not_attached(self):
        fake_server = fake_compute.FakeServer()
        availiable_volume = fake_volume.FakeVolume()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.stubs.Set(self._driver, '_get_device_path',
                       mock.Mock(return_value='fake_device_path'))
        self.stubs.Set(self._driver.compute_api, 'instance_volume_attach',
                       mock.Mock())
        self.stubs.Set(self._driver.volume_api, 'get',
                       mock.Mock(return_value=attached_volume))

        result = self._driver._attach_volume(self._context, self.share,
                                             fake_server, availiable_volume)

        self._driver._get_device_path.assert_called_once_with(self._context,
                                                              fake_server)
        self._driver.compute_api.instance_volume_attach.\
                assert_called_once_with(self._context, fake_server['id'],
                        availiable_volume['id'], 'fake_device_path')
        self._driver.volume_api.get.\
                assert_called_once_with(self._context, attached_volume['id'])
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
        self.stubs.Set(self._driver, '_get_device_path',
                       mock.Mock(return_value='fake_device_path'))
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
        self.stubs.Set(self._driver, '_get_device_path',
                       mock.Mock(return_value='fake_device_path'))
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
                self._driver._get_volume, self._context, self.share['id'])

    def test_get_volume_snapshot(self):
        volume_snapshot = fake_volume.FakeVolumeSnapshot(display_name=
                CONF.volume_snapshot_name_template % self.snapshot['id'])
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
        volume_snapshot = fake_volume.FakeVolumeSnapshot(display_name=
                CONF.volume_snapshot_name_template % self.snapshot['id'])
        self.stubs.Set(self._driver.volume_api, 'get_all_snapshots',
                mock.Mock(return_value=[volume_snapshot, volume_snapshot]))
        self.assertRaises(exception.ManilaException,
            self._driver._get_volume_snapshot, self._context, self.share['id'])

    def test_detach_volume(self):
        fake_server = fake_compute.FakeServer()
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

        self._driver._detach_volume(self._context, self.share, fake_server)

        self._driver.compute_api.instance_volume_detach.\
                assert_called_once_with(self._context, fake_server['id'],
                                        availiable_volume['id'])
        self._driver.volume_api.get.\
                assert_called_once_with(self._context, availiable_volume['id'])

    def test_detach_volume_detached(self):
        fake_server = fake_compute.FakeServer()
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

        self._driver._detach_volume(self._context, self.share, fake_server)

        self.assertFalse(self._driver.volume_api.get.called)
        self.assertFalse(self._driver.compute_api.
                                        instance_volume_detach.called)

    def test_get_device_path_01(self):
        fake_server = fake_compute.FakeServer()
        vol_list = [[], [fake_volume.FakeVolume(device='/dev/vdc')],
                [fake_volume.FakeVolume(device='/dev/vdd')]]
        self.stubs.Set(self._driver.compute_api, 'instance_volumes_list',
                mock.Mock(side_effect=lambda x, y: vol_list.pop()))

        result = self._driver._get_device_path(self._context, fake_server)

        self.assertEqual(result, '/dev/vdb')

    def test_get_device_path_02(self):
        fake_server = fake_compute.FakeServer()
        vol_list = [[fake_volume.FakeVolume(device='/dev/vdb')],
                [fake_volume.FakeVolume(device='/dev/vdb'),
                    fake_volume.FakeVolume(device='/dev/vdd')]]
        self.stubs.Set(self._driver.compute_api, 'instance_volumes_list',
                mock.Mock(side_effect=lambda x, y: vol_list.pop()))

        result = self._driver._get_device_path(self._context, fake_server)

        self.assertEqual(result, '/dev/vdc')

    def test_get_service_instance_name(self):
        result = self._driver._get_service_instance_name(self.share)
        self.assertEqual(result, CONF.service_instance_name_template %
                self.share['share_network_id'])

    def test_get_server_ip(self):
        fake_server = fake_compute.FakeServer(networks=
                {CONF.service_network_name: '10.254.0.1'})

        result = self._driver._get_server_ip(fake_server)

        self.assertEqual(result,
                fake_server['networks'][CONF.service_network_name][0])

    def test_get_server_ip_exception(self):
        fake_server = fake_compute.FakeServer(networks={})
        self.assertRaises(exception.ManilaException,
                          self._driver._get_server_ip, fake_server)

    def test_get_service_instance(self):
        fake_server = fake_compute.FakeServer()
        self.stubs.Set(self._driver, '_ensure_or_delete_server',
                       mock.Mock(return_value=True))
        self.stubs.Set(self._driver, '_get_server_ip',
                       mock.Mock(return_value='fake_ip'))
        self.stubs.Set(self._driver.compute_api, 'server_list',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._driver, '_create_service_instance',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._driver, '_get_ssh_pool',
                       mock.Mock(return_value=mock.Mock()))

        result = self._driver._get_service_instance(self._context, self.share)

        self.assertFalse(self._driver._ensure_or_delete_server.called)
        self._driver._get_ssh_pool.assert_called_once_with(fake_server)
        self._driver.compute_api.server_list.assert_called_once()
        self._driver._get_server_ip.assert_called_once()
        self._driver._create_service_instance.assert_called_once()
        self.assertEqual(result, fake_server)

    def test_get_service_instance_existed_in_memory(self):
        fake_server = fake_compute.FakeServer()
        self._driver.share_networks_servers = {self.share['share_network_id']:
                                               fake_server}
        self.stubs.Set(self._driver, '_ensure_or_delete_server',
                       mock.Mock(return_value=True))
        self.stubs.Set(self._driver.compute_api, 'server_list',
                       mock.Mock(return_value=[fake_server]))
        self.stubs.Set(self._driver, '_get_ssh_pool',
                       mock.Mock(return_value=mock.Mock()))
        self.stubs.Set(self._driver, '_create_service_instance',
                       mock.Mock(return_value=fake_server))

        result = self._driver._get_service_instance(self._context, self.share)

        self._driver._ensure_or_delete_server.assert_called_once()
        self.assertFalse(self._driver._get_ssh_pool.called)
        self.assertFalse(self._driver.compute_api.server_list.called)
        self.assertFalse(self._driver._create_service_instance.called)

        self.assertEqual(result, fake_server)

    def test_get_service_instance_existed_in_memory_non_active(self):
        old_fake_server = fake_compute.FakeServer(status='ERROR')
        new_fake_server = fake_compute.FakeServer()
        self._driver.share_networks_servers = {self.share['share_network_id']:
                                               old_fake_server}
        self.stubs.Set(self._driver, '_ensure_or_delete_server',
                mock.Mock(return_value=False))
        self.stubs.Set(self._driver, '_get_server_ip',
                       mock.Mock(return_value='fake_ip'))
        self.stubs.Set(self._driver.compute_api, 'server_list',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._driver, '_create_service_instance',
                       mock.Mock(return_value=new_fake_server))
        self.stubs.Set(self._driver, '_get_ssh_pool',
                       mock.Mock(return_value=mock.Mock()))

        result = self._driver._get_service_instance(self._context, self.share)

        self._driver._ensure_or_delete_server.assert_has_calls(
                [mock.call(self._context, old_fake_server, update=True)])
        self._driver._get_ssh_pool.assert_called_once_with(new_fake_server)
        self._driver.compute_api.server_list.assert_called_once()
        self._driver._get_server_ip.assert_called_once()
        self._driver._create_service_instance.assert_called_once()

        self.assertEqual(result, new_fake_server)

    def test_get_service_instance_existed(self):
        fake_server = fake_compute.FakeServer()
        self.stubs.Set(self._driver, '_ensure_or_delete_server',
                       mock.Mock(return_value=True))
        self.stubs.Set(self._driver, '_get_server_ip',
                       mock.Mock(return_value='fake_ip'))
        self.stubs.Set(self._driver.compute_api, 'server_list',
                       mock.Mock(return_value=[fake_server]))
        self.stubs.Set(self._driver, '_create_service_instance',
                       mock.Mock())
        self.stubs.Set(self._driver, '_get_ssh_pool',
                       mock.Mock(return_value=mock.Mock()))

        result = self._driver._get_service_instance(self._context, self.share)

        self._driver._ensure_or_delete_server.assert_called_once()
        self._driver._get_ssh_pool.assert_called_once_with(fake_server)
        self._driver.compute_api.server_list.assert_called_once()
        self._driver._get_server_ip.assert_called_once()
        self.assertFalse(self._driver._create_service_instance.called)
        self.assertEqual(result, fake_server)

    def test_ensure_or_delete_server(self):
        fake_server = fake_compute.FakeServer()
        self.stubs.Set(self._driver, '_check_server_availability',
                       mock.Mock(return_value=True))
        self.stubs.Set(self._driver.compute_api, 'server_get',
                       mock.Mock(return_value=fake_server))
        result = self._driver._ensure_or_delete_server(self._context,
                                                       fake_server,
                                                       update=True)
        self._driver.compute_api.server_get.\
                    assert_called_once_with(self._context, fake_server['id'])
        self._driver._check_server_availability.\
                                assert_called_once_with(fake_server)
        self.assertTrue(result)

    def test_ensure_or_delete_server_not_exists(self):
        fake_server = fake_compute.FakeServer()
        self.stubs.Set(self._driver, '_check_server_availability',
                       mock.Mock(return_value=True))
        self.stubs.Set(self._driver.compute_api, 'server_get',
                       mock.Mock(side_effect=exception.InstanceNotFound(
                                               instance_id=fake_server['id'])))
        result = self._driver._ensure_or_delete_server(self._context,
                                                       fake_server,
                                                       update=True)
        self._driver.compute_api.server_get.\
                    assert_called_once_with(self._context, fake_server['id'])
        self.assertFalse(self._driver._check_server_availability.called)
        self.assertFalse(result)

    def test_ensure_or_delete_server_exception(self):
        fake_server = fake_compute.FakeServer()
        self.stubs.Set(self._driver, '_check_server_availability',
                       mock.Mock(return_value=True))
        self.stubs.Set(self._driver.compute_api, 'server_get',
                       mock.Mock(side_effect=exception.ManilaException))
        self.assertRaises(exception.ManilaException,
                          self._driver._ensure_or_delete_server,
                          self._context,
                          fake_server,
                          update=True)
        self._driver.compute_api.server_get.\
                    assert_called_once_with(self._context, fake_server['id'])
        self.assertFalse(self._driver._check_server_availability.called)

    def test_ensure_or_delete_server_non_active(self):
        fake_server = fake_compute.FakeServer(status='ERROR')
        self.stubs.Set(self._driver, '_delete_server', mock.Mock())
        self.stubs.Set(self._driver, '_check_server_availability',
                       mock.Mock(return_value=True))
        result = self._driver._ensure_or_delete_server(self._context,
                                                       fake_server)
        self.assertFalse(self._driver._check_server_availability.called)
        self._driver._delete_server.assert_called_once_with(self._context,
                                                            fake_server)
        self.assertFalse(result)

    def test_get_key_create_new(self):
        fake_keypair = fake_compute.FakeKeypair(name=
                                            CONF.manila_service_keypair_name)
        self.stubs.Set(self._driver.compute_api, 'keypair_list',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._driver.compute_api, 'keypair_import',
                       mock.Mock(return_value=fake_keypair))

        result = self._driver._get_key(self._context)

        self.assertEqual(result, fake_keypair.name)
        self._driver.compute_api.keypair_list.assert_called_once()
        self._driver.compute_api.keypair_import.assert_called_once()

    def test_get_key_exists(self):
        fake_keypair = fake_compute.FakeKeypair(
                                name=CONF.manila_service_keypair_name,
                                public_key='fake_public_key')
        self.stubs.Set(self._driver.compute_api, 'keypair_list',
                       mock.Mock(return_value=[fake_keypair]))
        self.stubs.Set(self._driver.compute_api, 'keypair_import',
                       mock.Mock(return_value=fake_keypair))
        self.stubs.Set(self._driver, '_execute',
                       mock.Mock(return_value=('fake_public_key', '')))

        result = self._driver._get_key(self._context)

        self._driver.compute_api.keypair_list.assert_called_once()
        self.assertFalse(self._driver.compute_api.keypair_import.called)
        self.assertEqual(result, fake_keypair.name)

    def test_get_key_exists_recreate(self):
        fake_keypair = fake_compute.FakeKeypair(
                                name=CONF.manila_service_keypair_name,
                                public_key='fake_public_key1')
        self.stubs.Set(self._driver.compute_api, 'keypair_list',
                       mock.Mock(return_value=[fake_keypair]))
        self.stubs.Set(self._driver.compute_api, 'keypair_import',
                       mock.Mock(return_value=fake_keypair))
        self.stubs.Set(self._driver.compute_api, 'keypair_delete', mock.Mock())
        self.stubs.Set(self._driver, '_execute',
                       mock.Mock(return_value=('fake_public_key2', '')))

        result = self._driver._get_key(self._context)

        self._driver.compute_api.keypair_list.assert_called_once()
        self._driver.compute_api.keypair_delete.assert_called_once()
        self._driver.compute_api.keypair_import.\
                assert_called_once_with(self._context, fake_keypair.name,
                                        'fake_public_key2')
        self.assertEqual(result, fake_keypair.name)

    def test_get_service_image(self):
        fake_image1 = fake_compute.FakeImage(name=CONF.service_image_name)
        fake_image2 = fake_compute.FakeImage(name='another-image')
        self.stubs.Set(self._driver.compute_api, 'image_list',
                       mock.Mock(return_value=[fake_image1, fake_image2]))

        result = self._driver._get_service_image(self._context)

        self.assertEqual(result, fake_image1.id)

    def test_get_service_image_not_found(self):
        self.stubs.Set(self._driver.compute_api, 'image_list',
                       mock.Mock(return_value=[]))

        self.assertRaises(exception.ManilaException,
                          self._driver._get_service_image,
                          self._context)

    def test_get_service_image_ambiguous(self):
        fake_image = fake_compute.FakeImage(name=CONF.service_image_name)
        self.stubs.Set(self._driver.compute_api, 'image_list',
                       mock.Mock(return_value=[fake_image, fake_image]))

        self.assertRaises(exception.ManilaException,
                          self._driver._get_service_image,
                          self._context)

    def test_create_service_instance(self):
        fake_server = fake_compute.FakeServer()
        fake_port = fake_network.FakePort()
        self.stubs.Set(self._driver, '_get_service_image',
                       mock.Mock(return_value='fake_image_id'))
        self.stubs.Set(self._driver, '_get_key',
                       mock.Mock(return_value='fake_key_name'))
        self.stubs.Set(self._driver, '_setup_network_for_instance',
                       mock.Mock(return_value=fake_port))
        self.stubs.Set(self._driver,
                       '_setup_connectivity_with_service_instances',
                       mock.Mock())
        self.stubs.Set(self._driver.compute_api, 'server_create',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._driver, '_get_server_ip',
                       mock.Mock(return_value='fake_ip'))
        self.stubs.Set(generic.socket, 'socket', mock.Mock())

        result = self._driver._create_service_instance(self._context,
                                        'instance_name', self.share, None)

        self._driver._get_service_image.assert_called_once()
        self._driver._get_key.assert_called_once()
        self._driver._setup_network_for_instance.assert_called_once()
        self._driver._setup_connectivity_with_service_instances.\
                assert_called_once()
        self._driver.compute_api.server_create.assert_called_once_with(
                self._context, 'instance_name', 'fake_image_id',
                CONF.service_instance_flavor_id, 'fake_key_name', None, None,
                nics=[{'port-id': fake_port['id']}])
        generic.socket.socket.assert_called_once()
        self.assertEqual(result, fake_server)

    def test_create_service_instance_error(self):
        fake_server = fake_compute.FakeServer(status='ERROR')
        fake_port = fake_network.FakePort()
        self.stubs.Set(self._driver, '_get_service_image',
                       mock.Mock(return_value='fake_image_id'))
        self.stubs.Set(self._driver, '_get_key',
                       mock.Mock(return_value='fake_key_name'))
        self.stubs.Set(self._driver, '_setup_network_for_instance',
                       mock.Mock(return_value=fake_port))
        self.stubs.Set(self._driver,
                       '_setup_connectivity_with_service_instances',
                       mock.Mock())
        self.stubs.Set(self._driver.compute_api, 'server_create',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._driver.compute_api, 'server_get',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(generic.socket, 'socket', mock.Mock())

        self.assertRaises(exception.ManilaException,
                self._driver._create_service_instance, self._context,
                'instance_name', self.share, None)

        self._driver.compute_api.server_create.assert_called_once()
        self.assertFalse(self._driver.compute_api.server_get.called)
        self.assertFalse(generic.socket.socket.called)

    def test_create_service_instance_failed_setup_connectivity(self):
        fake_server = fake_compute.FakeServer(status='ERROR')
        fake_port = fake_network.FakePort()
        self.stubs.Set(self._driver, '_get_service_image',
                       mock.Mock(return_value='fake_image_id'))
        self.stubs.Set(self._driver, '_get_key',
                       mock.Mock(return_value='fake_key_name'))
        self.stubs.Set(self._driver, '_setup_network_for_instance',
                       mock.Mock(return_value=fake_port))
        self.stubs.Set(self._driver,
                       '_setup_connectivity_with_service_instances',
                       mock.Mock(side_effect=exception.ManilaException))
        self.stubs.Set(self._driver.neutron_api, 'delete_port', mock.Mock())
        self.stubs.Set(self._driver.compute_api, 'server_create',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._driver.compute_api, 'server_get',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(generic.socket, 'socket', mock.Mock())

        self.assertRaises(exception.ManilaException,
                self._driver._create_service_instance,
                self._context, 'instance_name', self.share, None)

        self._driver.neutron_api.delete_port.\
                assert_called_once_with(fake_port['id'])
        self.assertFalse(self._driver.compute_api.server_create.called)
        self.assertFalse(self._driver.compute_api.server_get.called)
        self.assertFalse(generic.socket.socket.called)

    def test_create_service_instance_no_key_and_password(self):
        self.stubs.Set(self._driver, '_get_service_image',
                       mock.Mock(return_value='fake_image_id'))
        self.stubs.Set(self._driver, '_get_key',
                       mock.Mock(return_value=None))
        self.assertRaises(exception.ManilaException,
                self._driver._create_service_instance, self._context,
                'instance_name', self.share, None)

    def test_setup_network_for_instance(self):
        fake_service_net = fake_network.FakeNetwork(subnets=[])
        fake_service_subnet = fake_network.\
                FakeSubnet(name=self.share['share_network_id'])
        fake_router = fake_network.FakeRouter()
        fake_port = fake_network.FakePort()
        self.stubs.Set(self._driver.neutron_api, 'get_network',
                mock.Mock(return_value=fake_service_net))
        self.stubs.Set(self._driver.neutron_api, 'subnet_create',
                mock.Mock(return_value=fake_service_subnet))
        self.stubs.Set(self._driver.db, 'share_network_get',
                mock.Mock(return_value='fake_share_network'))
        self.stubs.Set(self._driver, '_get_private_router',
                mock.Mock(return_value=fake_router))
        self.stubs.Set(self._driver.neutron_api, 'router_add_interface',
                mock.Mock())
        self.stubs.Set(self._driver.neutron_api, 'create_port',
                mock.Mock(return_value=fake_port))
        self.stubs.Set(self._driver, '_get_cidr_for_subnet',
                mock.Mock(return_value='fake_cidr'))

        result = self._driver._setup_network_for_instance(self._context,
                self.share, None)

        self._driver.neutron_api.get_network.\
                assert_called_once_with(self._driver.service_network_id)
        self._driver._get_private_router.\
                assert_called_once_with('fake_share_network')
        self._driver.neutron_api.router_add_interface.\
                assert_called_once_with('fake_router_id', 'fake_subnet_id')
        self._driver.neutron_api.subnet_create.assert_called_once_with(
                                         self._driver.service_tenant_id,
                                         self._driver.service_network_id,
                                         self.share['share_network_id'],
                                         'fake_cidr')
        self._driver.neutron_api.create_port.assert_called_once_with(
                                         self._driver.service_tenant_id,
                                         self._driver.service_network_id,
                                         subnet_id='fake_subnet_id',
                                         fixed_ip=None,
                                         device_owner='manila')
        self._driver._get_cidr_for_subnet.assert_called_once_with([])
        self.assertEqual(result, fake_port)

    def test_get_private_router(self):
        fake_net = fake_network.FakeNetwork()
        fake_subnet = fake_network.FakeSubnet(gateway_ip='fake_ip')
        fake_port = fake_network.FakePort(fixed_ips=[
                        {'subnet_id': fake_subnet['id'],
                         'ip_address': fake_subnet['gateway_ip']}],
                        device_id='fake_router_id')
        fake_router = fake_network.FakeRouter(id='fake_router_id')
        self.stubs.Set(self._driver.neutron_api, 'get_subnet',
                mock.Mock(return_value=fake_subnet))
        self.stubs.Set(self._driver.neutron_api, 'list_ports',
                mock.Mock(return_value=[fake_port]))
        self.stubs.Set(self._driver.neutron_api, 'show_router',
                mock.Mock(return_value=fake_router))

        result = self._driver._get_private_router(
                    {'neutron_subnet_id': fake_subnet['id'],
                     'neutron_net_id': fake_net['id']})

        self._driver.neutron_api.get_subnet.\
                assert_called_once_with(fake_subnet['id'])
        self._driver.neutron_api.list_ports.\
                assert_called_once_with(network_id=fake_net['id'])
        self._driver.neutron_api.show_router.\
                assert_called_once_with(fake_router['id'])
        self.assertEqual(result, fake_router)

    def test_get_private_router_exception(self):
        fake_net = fake_network.FakeNetwork()
        fake_subnet = fake_network.FakeSubnet(gateway_ip='fake_ip')
        self.stubs.Set(self._driver.neutron_api, 'get_subnet',
                mock.Mock(return_value=fake_subnet))
        self.stubs.Set(self._driver.neutron_api, 'list_ports',
                mock.Mock(return_value=[]))

        self.assertRaises(exception.ManilaException,
                self._driver._get_private_router,
                {'neutron_subnet_id': fake_subnet['id'],
                 'neutron_net_id': fake_net['id']})

    def test_setup_connectivity_with_service_instances(self):
        fake_subnet = fake_network.FakeSubnet(cidr='10.254.0.1/29')
        fake_port = fake_network.FakePort(fixed_ips=[
            {'subnet_id': fake_subnet['id'], 'ip_address': '10.254.0.2'}],
            mac_address='fake_mac_address')

        self.stubs.Set(self._driver, '_setup_service_port',
                mock.Mock(return_value=fake_port))
        self.stubs.Set(self._driver.vif_driver, 'get_device_name',
                mock.Mock(return_value='fake_interface_name'))
        self.stubs.Set(self._driver.neutron_api, 'get_subnet',
                mock.Mock(return_value=fake_subnet))
        self.stubs.Set(self._driver, '_clean_garbage', mock.Mock())
        self.stubs.Set(self._driver.vif_driver, 'plug', mock.Mock())
        device_mock = mock.Mock()
        self.stubs.Set(generic.ip_lib, 'IPDevice',
                mock.Mock(return_value=device_mock))

        self._driver._setup_connectivity_with_service_instances()

        self._driver._setup_service_port.assert_called_once()
        self._driver.vif_driver.get_device_name.\
                                            assert_called_once_with(fake_port)
        self._driver.vif_driver.plug.assert_called_once_with(fake_port['id'],
                'fake_interface_name', fake_port['mac_address'])
        self._driver.neutron_api.get_subnet.\
                        assert_called_once_with(fake_subnet['id'])
        self._driver.vif_driver.init_l3.assert_called_once()
        generic.ip_lib.IPDevice.assert_called_once()
        device_mock.route.pullup_route.assert_called_once()
        self._driver._clean_garbage.assert_called_once_with(device_mock)

    def test_setup_service_port(self):
        fake_service_port = fake_network.FakePort(device_id='manila-share')
        fake_service_net = fake_network.FakeNetwork(subnets=[])
        self.stubs.Set(self._driver.neutron_api, 'list_ports',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._driver.db, 'service_get_all_by_topic',
                mock.Mock(return_value=[{'host': 'fake_host'}]))
        self.stubs.Set(self._driver.neutron_api, 'create_port',
                       mock.Mock(return_value=fake_service_port))
        self.stubs.Set(self._driver.neutron_api, 'get_network',
                       mock.Mock(return_value=fake_service_net))
        self.stubs.Set(self._driver.neutron_api, 'update_port_fixed_ips',
                       mock.Mock(return_value=fake_service_port))

        result = self._driver._setup_service_port()

        self._driver.neutron_api.list_ports.\
                            assert_called_once_with(device_id='manila-share')
        self._driver.db.service_get_all_by_topic.assert_called_once()
        self._driver.neutron_api.create_port.assert_called_once_with(
                                    self._driver.service_tenant_id,
                                    self._driver.service_network_id,
                                    device_id='manila-share',
                                    device_owner='manila:generic_driver',
                                    host_id='fake_host'
                                    )
        self._driver.neutron_api.get_network.assert_called_once()
        self.assertFalse(self._driver.neutron_api.update_port_fixed_ips.called)
        self.assertEqual(result, fake_service_port)

    def test_setup_service_port_ambigious_ports(self):
        fake_service_port = fake_network.FakePort(device_id='manila-share')
        self.stubs.Set(self._driver.neutron_api, 'list_ports',
                mock.Mock(return_value=[fake_service_port, fake_service_port]))
        self.assertRaises(exception.ManilaException,
                          self._driver._setup_service_port)

    def test_setup_service_port_exists(self):
        fake_service_port = fake_network.FakePort(device_id='manila-share')
        fake_service_net = fake_network.FakeNetwork(subnets=[])
        self.stubs.Set(self._driver.neutron_api, 'list_ports',
                       mock.Mock(return_value=[fake_service_port]))
        self.stubs.Set(self._driver.db, 'service_get_all_by_topic',
                mock.Mock(return_value=[{'host': 'fake_host'}]))
        self.stubs.Set(self._driver.neutron_api, 'create_port',
                       mock.Mock(return_value=fake_service_port))
        self.stubs.Set(self._driver.neutron_api, 'get_network',
                       mock.Mock(return_value=fake_service_net))
        self.stubs.Set(self._driver.neutron_api, 'update_port_fixed_ips',
                       mock.Mock(return_value=fake_service_port))

        result = self._driver._setup_service_port()

        self._driver.neutron_api.list_ports.\
                            assert_called_once_with(device_id='manila-share')
        self.assertFalse(self._driver.db.service_get_all_by_topic.called)
        self.assertFalse(self._driver.neutron_api.create_port.called)
        self._driver.neutron_api.get_network.assert_called_once()
        self.assertFalse(self._driver.neutron_api.update_port_fixed_ips.called)
        self.assertEqual(result, fake_service_port)

    def test_get_cidr_for_subnet(self):
        serv_cidr = generic.netaddr.IPNetwork(CONF.service_network_cidr)
        cidrs = serv_cidr.subnet(29)
        cidr1 = str(cidrs.next())
        cidr2 = str(cidrs.next())

        result = self._driver._get_cidr_for_subnet([])
        self.assertEqual(result, cidr1)

        fake_subnet = fake_network.FakeSubnet(cidr=cidr1)
        result = self._driver._get_cidr_for_subnet([fake_subnet])
        self.assertEqual(result, cidr2)

    def test_allocate_container(self):
        fake_vol = fake_volume.FakeVolume()
        self.stubs.Set(self._driver.volume_api, 'create',
                       mock.Mock(return_value=fake_vol))

        result = self._driver._allocate_container(self._context, self.share)
        self.assertEqual(result, fake_vol)
        self._driver.volume_api.create.assert_called_once_with(self._context,
                                self.share['size'],
                                CONF.volume_name_template % self.share['id'],
                                '',
                                snapshot=None)

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
        self._driver.volume_api.create.assert_called_once_with(self._context,
                                self.share['size'],
                                CONF.volume_name_template % self.share['id'],
                                '',
                                snapshot=fake_vol_snap)

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

        self._driver._get_volume.assert_called_once()
        self._driver.volume_api.delete.assert_called_once()
        self._driver.volume_api.get.assert_called_once()

    def test_create_share_from_snapshot(self):
        self._helper_nfs.create_export.return_value = 'fakelocation'
        methods = ('_get_service_instance', '_allocate_container',
                '_attach_volume', '_mount_device')
        for method in methods:
            self.stubs.Set(self._driver, method, mock.Mock())
        result = self._driver.create_share_from_snapshot(self._context,
                                           self.share,
                                           self.snapshot)
        for method in methods:
            getattr(self._driver, method).assert_called_once()
        self.assertEqual(result, 'fakelocation')

    def test_delete_share(self):
        fake_server = fake_compute.FakeServer()
        self.stubs.Set(self._driver, '_get_service_instance',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._driver, '_unmount_device', mock.Mock())
        self.stubs.Set(self._driver, '_detach_volume', mock.Mock())
        self.stubs.Set(self._driver, '_deallocate_container', mock.Mock())

        self._driver.delete_share(self._context, self.share)

        self._driver._get_service_instance.assert_called_once()
        self._driver._unmount_device.assert_called_once()
        self._driver._detach_volume.assert_called_once()
        self._driver._deallocate_container.assert_called_once()

    def test_create_snapshot(self):
        fake_vol = fake_volume.FakeVolume()
        fake_vol_snap = fake_volume.FakeVolumeSnapshot()
        self.stubs.Set(self._driver, '_get_volume',
                       mock.Mock(return_value=fake_vol))
        self.stubs.Set(self._driver.volume_api, 'create_snapshot_force',
                       mock.Mock(return_value=fake_vol_snap))

        self._driver.create_snapshot(self._context, self.snapshot)

        self._driver._get_volume.assert_called_once()
        self._driver.volume_api.create_snapshot_force.assert_called_once_with(
                     self._context,
                     fake_vol['id'],
                     CONF.volume_snapshot_name_template % self.snapshot['id'],
                     ''
                )

    def test_delete_snapshot(self):
        fake_vol_snap = fake_volume.FakeVolumeSnapshot()
        self.stubs.Set(self._driver, '_get_volume_snapshot',
                       mock.Mock(return_value=fake_vol_snap))
        self.stubs.Set(self._driver.volume_api, 'delete_snapshot', mock.Mock())
        self.stubs.Set(self._driver.volume_api, 'get_snapshot',
                mock.Mock(side_effect=exception.VolumeSnapshotNotFound(
                    snapshot_id=fake_vol_snap['id'])))

        self._driver.delete_snapshot(self._context, fake_vol_snap)

        self._driver._get_volume_snapshot.assert_called_once()
        self._driver.volume_api.delete_snapshot.assert_called_once()
        self._driver.volume_api.get_snapshot.assert_called_once()

    def test_ensure_share(self):
        self._helper_nfs.create_export.return_value = 'fakelocation'
        methods = ('_get_service_instance', '_get_volume',
                '_attach_volume', '_mount_device')
        for method in methods:
            self.stubs.Set(self._driver, method, mock.Mock())
        self._driver.ensure_share(self._context, self.share)
        for method in methods:
            getattr(self._driver, method).assert_called_once()

    def test_allow_access(self):
        fake_server = fake_compute.FakeServer()
        access = {'access_type': 'ip', 'access_to': 'fake_dest'}
        self.stubs.Set(self._driver, '_get_service_instance',
                       mock.Mock(return_value=fake_server))
        self._driver.allow_access(self._context, self.share, access)

        self._driver._get_service_instance.assert_called_once()
        self._driver._helpers[self.share['share_proto']].\
                allow_access.assert_called_once_with(fake_server,
                                                     self.share['name'],
                                                     access['access_type'],
                                                     access['access_to'])

    def test_deny_access(self):
        fake_server = fake_compute.FakeServer()
        access = {'access_type': 'ip', 'access_to': 'fake_dest'}
        self.stubs.Set(self._driver, '_get_service_instance',
                       mock.Mock(return_value=fake_server))
        self._driver.deny_access(self._context, self.share, access)

        self._driver._get_service_instance.assert_called_once()
        self._driver._helpers[self.share['share_proto']].\
                deny_access.assert_called_once_with(fake_server,
                                                    self.share['name'],
                                                    access['access_type'],
                                                    access['access_to'])


class NFSHelperTestCase(test.TestCase):
    """Test case for NFS helper of generic driver."""

    def setUp(self):
        super(NFSHelperTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        self.fake_conf = Configuration(None)
        self.stubs.Set(generic, '_ssh_exec', mock.Mock(return_value=('', '')))
        self._execute = mock.Mock(return_value=('', ''))
        self._helper = generic.NFSHelper(self._execute, self.fake_conf, {})

    def test_create_export(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3')
        ret = self._helper.create_export(fake_server, 'volume-00001')
        expected_location = ':'.join([fake_server['ip'],
            os.path.join(CONF.share_mount_path, 'volume-00001')])
        self.assertEqual(ret, expected_location)

    def test_allow_access(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3')
        self._helper.allow_access(fake_server, 'volume-00001',
                                  'ip', '10.0.0.2')
        local_path = os.path.join(CONF.share_mount_path, 'volume-00001')
        generic._ssh_exec.assert_has_calls([
            mock.call(fake_server, ['sudo', 'exportfs']),
            mock.call(fake_server, ['sudo', 'exportfs', '-o',
                                    'rw,no_subtree_check',
                                    ':'.join(['10.0.0.2', local_path])])
            ])

    def test_allow_access_no_ip(self):
        self.assertRaises(exception.InvalidShareAccess,
                          self._helper.allow_access, 'fake_server', 'share0',
                          'fake', 'fakerule')

    def test_deny_access(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3')
        local_path = os.path.join(CONF.share_mount_path, 'volume-00001')
        self._helper.deny_access(fake_server, 'volume-00001', 'ip', '10.0.0.2')
        export_string = ':'.join(['10.0.0.2', local_path])
        expected_exec = ['sudo', 'exportfs', '-u', export_string]
        generic._ssh_exec.assert_called_once_with(fake_server, expected_exec)


class CIFSHelperTestCase(test.TestCase):
    """Test case for CIFS helper of generic driver."""

    def setUp(self):
        super(CIFSHelperTestCase, self).setUp()
        self.fake_conf = Configuration(None)
        self.stubs.Set(generic, '_ssh_exec', mock.Mock(return_value=('', '')))
        self._execute = mock.Mock(return_value=('', ''))
        self._helper = generic.CIFSHelper(self._execute, self.fake_conf, {})

    def test_create_export(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3',
                                    share_network_id='fake_share_network_id')
        self.stubs.Set(self._helper, '_update_config', mock.Mock())
        self.stubs.Set(self._helper, '_write_remote_config', mock.Mock())
        self.stubs.Set(self._helper, '_restart_service', mock.Mock())
        self.stubs.Set(self._helper, '_get_local_config', mock.Mock())
        self.stubs.Set(generic.ConfigParser, 'ConfigParser', mock.Mock())

        ret = self._helper.create_export(fake_server, 'volume-00001',
                                         recreate=True)
        self._helper._get_local_config.\
                assert_called_once_with(fake_server['share_network_id'])
        self._helper._update_config.assert_called_once()
        self._helper._write_remote_config.assert_called_once()
        self._helper._restart_service.assert_called_once()
        expected_location = '//%s/%s' % (fake_server['ip'], 'volume-00001')
        self.assertEqual(ret, expected_location)

    def test_remove_export(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3',
                                    share_network_id='fake_share_network_id')
        self.stubs.Set(generic.ConfigParser, 'ConfigParser', mock.Mock())
        self.stubs.Set(self._helper, '_get_local_config', mock.Mock())
        self.stubs.Set(self._helper, '_update_config', mock.Mock())
        self.stubs.Set(self._helper, '_write_remote_config', mock.Mock())
        self._helper.remove_export(fake_server, 'volume-00001')
        self._helper._get_local_config.assert_called_once()
        self._helper._update_config.assert_called_once()
        self._helper._write_remote_config.assert_called_once()
        generic._ssh_exec.assert_called_once_with(fake_server,
                ['sudo', 'smbcontrol', 'all', 'close-share', 'volume-00001'])

    def test_allow_access(self):
        class FakeParser(object):
            def read(self, *args, **kwargs):
                pass

            def get(self, *args, **kwargs):
                return ''

            def set(self, *args, **kwargs):
                pass

        fake_server = fake_compute.FakeServer(ip='10.254.0.3',
                                    share_network_id='fake_share_network_id')
        self.stubs.Set(generic.ConfigParser, 'ConfigParser', FakeParser)
        self.stubs.Set(self._helper, '_get_local_config', mock.Mock())
        self.stubs.Set(self._helper, '_update_config', mock.Mock())
        self.stubs.Set(self._helper, '_write_remote_config', mock.Mock())
        self.stubs.Set(self._helper, '_restart_service', mock.Mock())

        self._helper.allow_access(fake_server, 'volume-00001',
                                  'ip', '10.0.0.2')
        self._helper._get_local_config.assert_called_once()
        self._helper._update_config.assert_called_once()
        self._helper._write_remote_config.assert_called_once()
        self._helper._restart_service.assert_called_once()

    def test_deny_access(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3',
                                    share_network_id='fake_share_network_id')
        self.stubs.Set(generic.ConfigParser, 'ConfigParser', mock.Mock())
        self.stubs.Set(self._helper, '_get_local_config', mock.Mock())
        self.stubs.Set(self._helper, '_update_config', mock.Mock())
        self.stubs.Set(self._helper, '_write_remote_config', mock.Mock())
        self.stubs.Set(self._helper, '_restart_service', mock.Mock())

        self._helper.deny_access(fake_server, 'volume-00001',
                                  'ip', '10.0.0.2')
        self._helper._get_local_config.assert_called_once()
        self._helper._update_config.assert_called_once()
        self._helper._write_remote_config.assert_called_once()
        self._helper._restart_service.assert_called_once()
