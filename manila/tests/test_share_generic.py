# Copyright (c) 2014 NetApp, Inc.
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

import mock
from oslo.config import cfg

from manila import compute
from manila import context
from manila import exception
from manila.openstack.common import lockutils
from manila.share.configuration import Configuration
from manila.share.drivers import generic
from manila import test
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_compute
from manila.tests import fake_service_instance
from manila.tests import fake_utils
from manila.tests import fake_volume
from manila import volume


CONF = cfg.CONF


def fake_share(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'NFS',
        'share_network_id': 'fake share network id',
        'share_server_id': 'fake share server id',
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

        self._driver._ssh_exec = mock.Mock(return_value=('', ''))
        self.stubs.Set(lockutils, 'synchronized',
                       mock.Mock(return_value=lambda f: f))
        self.stubs.Set(generic.os.path, 'exists', mock.Mock(return_value=True))
        self._driver._helpers = {
            'CIFS': self._helper_cifs,
            'NFS': self._helper_nfs,
        }
        self.share = fake_share()
        self.server = {
            'backend_details': {
                'ip': '1.2.3.4',
                'instance_id': 'fake'
            }
        }
        self.access = fake_access()
        self.snapshot = fake_snapshot()

    def test_do_setup(self):
        self.stubs.Set(volume, 'API', mock.Mock())
        self.stubs.Set(compute, 'API', mock.Mock())
        self.stubs.Set(generic, 'service_instance', mock.Mock())
        self.stubs.Set(self._driver, '_setup_helpers', mock.Mock())
        self._driver.do_setup(self._context)
        volume.API.assert_called_once()
        compute.API.assert_called_once()
        self._driver._setup_helpers.assert_called_once()

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
        self._helper_nfs.create_export.return_value = 'fakelocation'
        methods = ('get_service_instance', '_allocate_container',
                   '_attach_volume', '_format_device', '_mount_device')
        for method in methods:
            self.stubs.Set(self._driver, method, mock.Mock())
        result = self._driver.create_share(self._context, self.share,
                                           share_server=self.server)
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
        self._driver._ssh_exec.assert_called_once_with(
            'fake_server',
            ['sudo', 'mkfs.%s' % self.fake_conf.share_volume_fstype,
             volume['mountpoint']])

    def _test_mount_device(self):
        volume = {'mountpoint': 'fake_mount_point'}
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value='fake_mount_path'))

        self._driver._mount_device(self._context, self.share, 'fake_server',
                                   volume)

        self._driver._ssh_exec.assert_has_calls([
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
        self._driver._ssh_exec.side_effect = [
            exception.ProcessExecutionError(stderr='already mounted'), None]
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value='fake_mount_path'))

        self._driver._mount_device(self._context, self.share, 'fake_server',
                                   volume)

        self._driver._ssh_exec.assert_has_calls([
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
        self._driver._ssh_exec.side_effect = exception.ManilaException
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value='fake_mount_path'))
        self.assertRaises(exception.ManilaException,
                          self._driver._mount_device,
                          self._context, self.share, 'fake_server', volume)

    def test_umount_device(self):
        self.stubs.Set(self._driver, '_get_mount_path',
                       mock.Mock(return_value='fake_mount_path'))
        self._driver._unmount_device(self.share, 'fake_server')
        self._driver._ssh_exec.assert_called_once_with(
            'fake_server',
            ['sudo', 'umount', 'fake_mount_path', ';', 'sudo', 'rmdir',
             'fake_mount_path'])

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
        self.stubs.Set(self._driver.volume_api, 'create',
                       mock.Mock(return_value=fake_vol))

        result = self._driver._allocate_container(self._context, self.share)
        self.assertEqual(result, fake_vol)
        self._driver.volume_api.create.assert_called_once_with(
            self._context,
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
        self._driver.volume_api.create.assert_called_once_with(
            self._context,
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
        methods = ('get_service_instance', '_allocate_container',
                   '_attach_volume', '_mount_device')
        for method in methods:
            self.stubs.Set(self._driver, method, mock.Mock())
        result = self._driver.create_share_from_snapshot(
            self._context,
            self.share,
            self.snapshot,
            share_server=self.server)
        for method in methods:
            getattr(self._driver, method).assert_called_once()
        self.assertEqual(result, 'fakelocation')

    def test_delete_share(self):
        fake_server = fake_compute.FakeServer()
        self.stubs.Set(self._driver, 'get_service_instance',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._driver, '_unmount_device', mock.Mock())
        self.stubs.Set(self._driver, '_detach_volume', mock.Mock())
        self.stubs.Set(self._driver, '_deallocate_container', mock.Mock())

        self._driver.delete_share(self._context, self.share,
                                  share_server=self.server)

        self._driver.get_service_instance.assert_called_once()
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

        self._driver.create_snapshot(self._context, self.snapshot,
                                     share_server=self.server)

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

        self._driver.delete_snapshot(self._context, fake_vol_snap,
                                     share_server=self.server)

        self._driver._get_volume_snapshot.assert_called_once()
        self._driver.volume_api.delete_snapshot.assert_called_once()
        self._driver.volume_api.get_snapshot.assert_called_once()

    def test_ensure_share(self):
        self._helper_nfs.create_export.return_value = 'fakelocation'
        methods = ('get_service_instance', '_get_volume',
                   '_attach_volume', '_mount_device')
        for method in methods:
            self.stubs.Set(self._driver, method, mock.Mock())
        self._driver.ensure_share(self._context, self.share,
                                  share_server=self.server)
        for method in methods:
            getattr(self._driver, method).assert_called_once()

    def test_allow_access(self):
        fake_server = fake_compute.FakeServer()
        access = {'access_type': 'ip', 'access_to': 'fake_dest'}
        self.stubs.Set(self._driver, 'get_service_instance',
                       mock.Mock(return_value=fake_server))
        self._driver.allow_access(self._context, self.share, access,
                                  share_server=self.server)
        self._driver.get_service_instance.assert_called_once()
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

    def test_setup_network(self):
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

    def test_setup_network_revert(self):

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

    def test_teardown_network(self):
        sim = self._driver.instance_manager
        self._driver.service_instance_manager = sim
        self._driver.teardown_server(self.fake_net_info)
        sim.delete_service_instance.assert_called_once()


class NFSHelperTestCase(test.TestCase):
    """Test case for NFS helper of generic driver."""

    def setUp(self):
        super(NFSHelperTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        self.fake_conf = Configuration(None)
        self._ssh_exec = mock.Mock(return_value=('', ''))
        self._execute = mock.Mock(return_value=('', ''))
        self._helper = generic.NFSHelper(self._execute, self._ssh_exec,
                                         self.fake_conf)

    def test_create_export(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3')
        ret = self._helper.create_export(fake_server, 'volume-00001')
        expected_location = ':'.join([fake_server['ip'],
                                      os.path.join(CONF.share_mount_path,
                                                   'volume-00001')])
        self.assertEqual(ret, expected_location)

    def test_allow_access(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3')
        self._helper.allow_access(fake_server, 'volume-00001',
                                  'ip', '10.0.0.2')
        local_path = os.path.join(CONF.share_mount_path, 'volume-00001')
        self._ssh_exec.assert_has_calls([
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
        self._ssh_exec.assert_called_once_with(fake_server, expected_exec)


class CIFSHelperTestCase(test.TestCase):
    """Test case for CIFS helper of generic driver."""

    def setUp(self):
        super(CIFSHelperTestCase, self).setUp()
        self.server_details = {'instance_id': 'fake', 'ip': '1.2.3.4', }
        self.share_name = 'fake_share_name'
        self.fake_conf = Configuration(None)
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
            self.server_details['ip'], self.share_name)
        self.assertEqual(ret, expected_location)
        self._helper._ssh_exec.assert_has_calls([
            mock.call(
                self.server_details,
                ['sudo', 'net', 'conf', 'showshare', self.share_name, ]
            ),
            mock.call(
                self.server_details,
                [
                    'sudo', 'net', 'conf', 'addshare', self.share_name,
                    self._helper.configuration.share_mount_path,
                    'writeable=y', 'guest_ok=y',
                ]
            ),
            mock.call(self.server_details, mock.ANY),
        ])

    def test_create_export_share_exist_recreate_true(self):
        ret = self._helper.create_export(self.server_details, self.share_name,
                                         recreate=True)
        expected_location = '//%s/%s' % (
            self.server_details['ip'], self.share_name)
        self.assertEqual(ret, expected_location)
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
                    self._helper.configuration.share_mount_path,
                    'writeable=y', 'guest_ok=y',
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
