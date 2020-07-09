# Copyright 2016 Mirantis, Inc.
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
"""Unit tests for the Container driver module."""

import functools
from unittest import mock

import ddt
from oslo_config import cfg

from manila.common import constants as const
from manila import context
from manila import exception
from manila.share import configuration
from manila.share.drivers.container import driver
from manila.share.drivers.container import protocol_helper
from manila import test
from manila.tests import fake_utils
from manila.tests.share.drivers.container import fakes as cont_fakes


CONF = cfg.CONF
CONF.import_opt('lvm_share_export_ips', 'manila.share.drivers.lvm')


@ddt.ddt
class ContainerShareDriverTestCase(test.TestCase):
    """Tests ContainerShareDriver"""

    def setUp(self):
        super(ContainerShareDriverTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self)
        self._context = context.get_admin_context()
        self._db = mock.Mock()
        self.fake_conf = configuration.Configuration(None)

        CONF.set_default('driver_handles_share_servers', True)

        self._driver = driver.ContainerShareDriver(
            configuration=self.fake_conf)

        self.share = cont_fakes.fake_share()
        self.access = cont_fakes.fake_access()
        self.server = {
            'public_address': self.fake_conf.lvm_share_export_ips,
            'instance_id': 'LVM',
        }

        # Used only to test compatibility with share manager
        self.share_server = "fake_share_server"

    def fake_exec_sync(self, *args, **kwargs):
        kwargs['execute_arguments'].append(args)
        try:
            ret_val = kwargs['ret_val']
        except KeyError:
            ret_val = None
        return ret_val

    def test__get_helper_ok(self):
        share = cont_fakes.fake_share(share_proto='CIFS')
        expected = protocol_helper.DockerCIFSHelper(None)

        actual = self._driver._get_helper(share)

        self.assertEqual(type(expected), type(actual))

    def test__get_helper_existing_ok(self):
        share = cont_fakes.fake_share(share_proto='CIFS')
        expected = protocol_helper.DockerCIFSHelper
        self._driver._helpers = {'CIFS': expected}

        actual = self._driver._get_helper(share)

        self.assertEqual(expected, type(actual))

    def test__get_helper_not_ok(self):
        share = cont_fakes.fake_share()

        self.assertRaises(exception.InvalidShare, self._driver._get_helper,
                          share)

    def test_update_share_stats(self):
        self.mock_object(self._driver.storage, 'get_share_server_pools',
                         mock.Mock(return_value='test-pool'))

        self._driver._update_share_stats()

        self.assertEqual('Docker', self._driver._stats['share_backend_name'])
        self.assertEqual('CIFS', self._driver._stats['storage_protocol'])
        self.assertEqual(0, self._driver._stats['reserved_percentage'])
        self.assertIsNone(self._driver._stats['consistency_group_support'])
        self.assertEqual(False, self._driver._stats['snapshot_support'])
        self.assertEqual('ContainerShareDriver',
                         self._driver._stats['driver_name'])
        self.assertEqual('test-pool', self._driver._stats['pools'])
        self.assertTrue(self._driver._stats['ipv4_support'])
        self.assertFalse(self._driver._stats['ipv6_support'])

    def test_create_share(self):

        share_server = {'id': 'fake'}
        fake_container_name = 'manila_fake_container'

        mock_provide_storage = self.mock_object(self._driver.storage,
                                                'provide_storage')
        mock_get_container_name = self.mock_object(
            self._driver, '_get_container_name',
            mock.Mock(return_value=fake_container_name))
        mock_create_and_mount = self.mock_object(
            self._driver, '_create_export_and_mount_storage',
            mock.Mock(return_value='export_location'))

        self.assertEqual('export_location',
                         self._driver.create_share(self._context, self.share,
                                                   share_server))
        mock_provide_storage.assert_called_once_with(
            self.share.share_id, self.share.size
        )
        mock_create_and_mount.assert_called_once_with(
            self.share, fake_container_name, self.share.share_id
        )
        mock_get_container_name.assert_called_once_with(
            share_server['id']
        )

    def test__create_export_and_mount_storage(self):
        helper = mock.Mock()
        server_id = 'fake_id'
        share_name = 'fake_name'

        mock_create_share = self.mock_object(
            helper, 'create_share', mock.Mock(return_value='export_location'))
        mock__get_helper = self.mock_object(
            self._driver, "_get_helper", mock.Mock(return_value=helper))
        self.mock_object(self._driver.storage, "_get_lv_device",
                         mock.Mock(return_value={}))
        mock_execute = self.mock_object(self._driver.container, 'execute')

        self.assertEqual('export_location',
                         self._driver._create_export_and_mount_storage(
                             self.share, server_id, share_name))
        mock_create_share.assert_called_once_with(server_id)
        mock__get_helper.assert_called_once_with(self.share)
        mock_execute.assert_has_calls([
            mock.call(server_id, ["mkdir", "-m", "750",
                                  "/shares/%s" % share_name]),
            mock.call(server_id, ["mount", {},
                                  "/shares/%s" % share_name])
        ])

    def test__delete_export_and_umount_storage(self):
        helper = mock.Mock()
        server_id = 'fake_id'
        share_name = 'fake_name'
        mock__get_helper = self.mock_object(
            self._driver, "_get_helper", mock.Mock(return_value=helper))
        mock_delete_share = self.mock_object(helper, 'delete_share')
        mock_execute = self.mock_object(self._driver.container, 'execute')
        self._driver._delete_export_and_umount_storage(
            self.share, server_id, share_name)

        mock__get_helper.assert_called_once_with(self.share)
        mock_delete_share.assert_called_once_with(
            server_id, share_name, ignore_errors=False)
        mock_execute.assert_has_calls([
            mock.call(server_id, ["umount", "/shares/%s" % share_name],
                      ignore_errors=False),
            mock.call(server_id, ["rm", "-fR", "/shares/%s" % share_name],
                      ignore_errors=True)]
        )

    def test_delete_share(self):
        fake_server_id = "manila_container_name"
        fake_share_name = "fake_share_name"
        fake_share_server = {'id': 'fake'}

        mock_get_container_name = self.mock_object(
            self._driver, '_get_container_name',
            mock.Mock(return_value=fake_server_id))
        mock_get_share_name = self.mock_object(
            self._driver, '_get_share_name',
            mock.Mock(return_value=fake_share_name))
        self.mock_object(self._driver.storage, 'remove_storage')
        mock_delete_and_umount = self.mock_object(
            self._driver, '_delete_export_and_umount_storage')

        self._driver.delete_share(self._context, self.share, fake_share_server)

        mock_get_container_name.assert_called_once_with(
            fake_share_server['id']
        )
        mock_get_share_name.assert_called_with(
            self.share
        )
        mock_delete_and_umount.assert_called_once_with(
            self.share, fake_server_id, fake_share_name,
            ignore_errors=True
        )

    @ddt.data(True, False)
    def test__get_share_name(self, has_export_location):

        if not has_export_location:
            fake_share = cont_fakes.fake_share_no_export_location()
            expected_result = fake_share.share_id
        else:
            fake_share = cont_fakes.fake_share()
            expected_result = fake_share['export_location'].split('/')[-1]

        result = self._driver._get_share_name(fake_share)
        self.assertEqual(expected_result, result)

    def test_extend_share(self):
        fake_new_size = 2
        fake_share_server = {'id': 'fake-server'}
        share = cont_fakes.fake_share()
        share_name = self._driver._get_share_name(share)
        actual_arguments = []
        expected_arguments = [
            ('manila_fake_server', ['umount', '/shares/%s' % share_name]),
            ('manila_fake_server',
             ['mount', '/dev/manila_docker_volumes/%s' % share_name,
              '/shares/%s' % share_name])
        ]
        mock_extend_share = self.mock_object(self._driver.storage,
                                             "extend_share")
        self._driver.container.execute = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='')

        self._driver.extend_share(share, fake_new_size, fake_share_server)

        self.assertEqual(expected_arguments, actual_arguments)
        mock_extend_share.assert_called_once_with(share_name, fake_new_size,
                                                  fake_share_server)

    def test_ensure_share(self):
        # Does effectively nothing by design.
        self.assertEqual(1, 1)

    def test_update_access_access_rules_ok(self):
        helper = mock.Mock()
        fake_share_name = self._driver._get_share_name(self.share)
        self.mock_object(self._driver, "_get_helper",
                         mock.Mock(return_value=helper))

        self._driver.update_access(self._context, self.share,
                                   [{'access_level': const.ACCESS_LEVEL_RW}],
                                   [], [], {"id": "fake"})

        helper.update_access.assert_called_with('manila_fake', fake_share_name,
                                                [{'access_level': 'rw'}],
                                                [], [])

    def test_get_network_allocation_numer(self):
        # Does effectively nothing by design.
        self.assertEqual(1, self._driver.get_network_allocations_number())

    def test__get_container_name(self):
        self.assertEqual("manila_fake_server",
                         self._driver._get_container_name("fake-server"))

    def test_do_setup(self):
        # Does effectively nothing by design.
        self.assertEqual(1, 1)

    def test_check_for_setup_error_host_not_ok_class_ok(self):
        setattr(self._driver.configuration.local_conf,
                'neutron_host_id', None)

        self.assertRaises(exception.ManilaException,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_host_not_ok_class_some_other(self):
        setattr(self._driver.configuration.local_conf,
                'neutron_host_id', None)
        setattr(self._driver.configuration.local_conf,
                'network_api_class',
                'manila.share.drivers.container.driver.ContainerShareDriver')
        self.mock_object(driver.LOG, "warning")

        self._driver.check_for_setup_error()

        setattr(self._driver.configuration.local_conf,
                'network_api_class',
                'manila.network.neutron.neutron_network_plugin.'
                'NeutronNetworkPlugin')

        self.assertTrue(driver.LOG.warning.called)

    def test__connect_to_network(self):
        network_info = cont_fakes.fake_network()
        helper = mock.Mock()
        self.mock_object(self._driver, "_execute",
                         mock.Mock(return_value=helper))
        self.mock_object(self._driver.container, "execute")

        self._driver._connect_to_network("fake-server", network_info,
                                         "fake-veth")

    @ddt.data({'veth': "fake_veth", 'exception': None},
              {'veth': "fake_veth", 'exception':
                  exception.ProcessExecutionError('fake')},
              {'veth': None, 'exception': None})
    @ddt.unpack
    def test__teardown_server(self, veth, exception):
        fake_server_details = {"id": "b5afb5c1-6011-43c4-8a37-29820e6951a7"}
        container_name = self._driver._get_container_name(
            fake_server_details['id'])
        mock_stop_container = self.mock_object(
            self._driver.container, "stop_container")
        mock_find_container = self.mock_object(
            self._driver.container, "find_container_veth",
            mock.Mock(return_value=veth))
        mock_execute = self.mock_object(self._driver, "_execute",
                                        mock.Mock(side_effect=exception))

        self._driver._teardown_server(
            server_details=fake_server_details)

        mock_stop_container.assert_called_once_with(
            container_name
        )
        mock_find_container.assert_called_once_with(
            container_name
        )
        if exception is None and veth is not None:
            mock_execute.assert_called_once_with(
                "ovs-vsctl", "--", "del-port",
                self._driver.configuration.container_ovs_bridge_name, veth,
                run_as_root=True)

    def test__get_veth_state(self):
        retval = ('veth0000000\n', '')
        self.mock_object(self._driver, "_execute",
                         mock.Mock(return_value=retval))

        result = self._driver._get_veth_state()

        self.assertEqual(['veth0000000'], result)

    def test__get_corresponding_veth_ok(self):
        before = ['veth0000000']
        after = ['veth0000000', 'veth0000001']

        result = self._driver._get_corresponding_veth(before, after)

        self.assertEqual('veth0000001', result)

    def test__get_corresponding_veth_raises(self):
        before = ['veth0000000']
        after = ['veth0000000', 'veth0000001', 'veth0000002']

        self.assertRaises(exception.ManilaException,
                          self._driver._get_corresponding_veth,
                          before, after)

    def test__setup_server_container_fails(self):
        network_info = cont_fakes.fake_network()
        self.mock_object(self._driver.container, 'start_container')
        self._driver.container.start_container.side_effect = KeyError()

        self.assertRaises(exception.ManilaException,
                          self._driver._setup_server, network_info)

    def test__setup_server_ok(self):
        network_info = cont_fakes.fake_network()
        server_id = self._driver._get_container_name(network_info["server_id"])
        self.mock_object(self._driver.container, 'start_container')
        self.mock_object(self._driver, '_get_veth_state')
        self.mock_object(self._driver, '_get_corresponding_veth',
                         mock.Mock(return_value='veth0'))
        self.mock_object(self._driver, '_connect_to_network')

        self.assertEqual(network_info['server_id'],
                         self._driver._setup_server(network_info)['id'])
        self._driver.container.start_container.assert_called_once_with(
            server_id)
        self._driver._connect_to_network.assert_called_once_with(server_id,
                                                                 network_info,
                                                                 'veth0')

    def test_manage_existing(self):

        fake_container_name = "manila_fake_container"
        fake_export_location = 'export_location'
        expected_result = {
            'size': 1,
            'export_locations': [fake_export_location]
        }
        fake_share_server = cont_fakes.fake_share()
        fake_share_name = self._driver._get_share_name(self.share)
        mock_get_container_name = self.mock_object(
            self._driver, '_get_container_name',
            mock.Mock(return_value=fake_container_name))
        mock_get_share_name = self.mock_object(
            self._driver, '_get_share_name',
            mock.Mock(return_value=fake_share_name))
        mock_rename_storage = self.mock_object(
            self._driver.storage, 'rename_storage')
        mock_get_size = self.mock_object(
            self._driver.storage, 'get_size', mock.Mock(return_value=1))
        mock_delete_and_umount = self.mock_object(
            self._driver, '_delete_export_and_umount_storage')
        mock_create_and_mount = self.mock_object(
            self._driver, '_create_export_and_mount_storage',
            mock.Mock(return_value=fake_export_location)
        )

        result = self._driver.manage_existing_with_server(
            self.share, {}, fake_share_server)

        mock_rename_storage.assert_called_once_with(
            fake_share_name, self.share.share_id
        )
        mock_get_size.assert_called_once_with(
            fake_share_name
        )
        mock_delete_and_umount.assert_called_once_with(
            self.share, fake_container_name, fake_share_name
        )
        mock_create_and_mount.assert_called_once_with(
            self.share, fake_container_name, self.share.share_id
        )
        mock_get_container_name.assert_called_once_with(
            fake_share_server['id']
        )
        mock_get_share_name.assert_called_with(
            self.share
        )
        self.assertEqual(expected_result, result)

    def test_manage_existing_no_share_server(self):

        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing_with_server,
                          self.share, {})

    def test_unmanage(self):
        self.assertIsNone(self._driver.unmanage_with_server(self.share))

    def test_get_share_server_network_info(self):

        fake_share_server = cont_fakes.fake_share_server()
        fake_id = cont_fakes.fake_identifier()
        expected_result = ['veth11b2c34']

        interfaces = [cont_fakes.FAKE_VSCTL_LIST_INTERFACE_1,
                      cont_fakes.FAKE_VSCTL_LIST_INTERFACE_2,
                      cont_fakes.FAKE_VSCTL_LIST_INTERFACE_4,
                      cont_fakes.FAKE_VSCTL_LIST_INTERFACE_3]

        self.mock_object(self._driver.container, 'execute',
                         mock.Mock(return_value=interfaces))

        result = self._driver.get_share_server_network_info(self._context,
                                                            fake_share_server,
                                                            fake_id, {})
        self.assertEqual(expected_result, result)

    def test_manage_server(self):

        fake_id = cont_fakes.fake_identifier()
        fake_share_server = cont_fakes.fake_share_server()
        fake_container_name = "manila_fake_container"
        fake_container_old_name = "fake_old_name"

        mock_get_container_name = self.mock_object(
            self._driver, '_get_container_name',
            mock.Mock(return_value=fake_container_name))
        mock_get_correct_container_old_name = self.mock_object(
            self._driver, '_get_correct_container_old_name',
            mock.Mock(return_value=fake_container_old_name)
        )
        mock_rename_container = self.mock_object(self._driver.container,
                                                 'rename_container')
        expected_result = {'id': fake_share_server['id']}

        new_identifier, new_backend_details = self._driver.manage_server(
            self._context, fake_share_server, fake_id, {})

        self.assertEqual(expected_result, new_backend_details)
        self.assertEqual(fake_container_name, new_identifier)
        mock_rename_container.assert_called_once_with(
            fake_container_old_name, fake_container_name)
        mock_get_container_name.assert_called_with(
            fake_share_server['id']
        )
        mock_get_correct_container_old_name.assert_called_once_with(
            fake_id
        )

    @ddt.data(True, False)
    def test__get_correct_container_old_name(self, container_exists):

        expected_name = 'fake-name'
        fake_name = 'fake-name'

        mock_container_exists = self.mock_object(
            self._driver.container, 'container_exists',
            mock.Mock(return_value=container_exists))

        if not container_exists:
            expected_name = 'manila_fake_name'

        result = self._driver._get_correct_container_old_name(fake_name)

        self.assertEqual(expected_name, result)
        mock_container_exists.assert_called_once_with(
            fake_name
        )

    def test_migration_complete(self):
        share_server = {'id': 'fakeid'}
        fake_container_name = 'manila_fake_container'
        new_export_location = 'new_export_location'

        mock_migraton_storage = self.mock_object(self._driver.storage,
                                                 'migration_complete')
        mock_get_container_name = self.mock_object(
            self._driver, '_get_container_name',
            mock.Mock(return_value=fake_container_name))

        mock_mount = self.mock_object(
            self._driver, '_mount_storage',
            mock.Mock(return_value=new_export_location))

        mock_umount = self.mock_object(self._driver, '_umount_storage')

        expected_location = {'export_locations': new_export_location}
        self.assertEqual(expected_location,
                         self._driver.migration_complete(
                             self._context, self.share, self.share, None,
                             None, share_server, share_server))

        mock_migraton_storage.assert_called_once_with(
            self._context, self.share, self.share, None, None,
            destination_share_server=share_server, share_server=share_server
        )
        mock_mount.assert_called_once_with(
            self.share, fake_container_name, self.share.share_id
        )
        mock_umount.assert_called_once_with(
            self.share, fake_container_name, self.share.share_id
        )
        mock_get_container_name.assert_called_with(
            share_server['id']
        )

    def test_share_server_migration_complete(self):
        source_server = {'id': 'source_fake_id', 'host': 'host@back1'}
        dest_server = {'id': 'dest_fake_id', 'host': 'host@back2'}
        fake_container_name = 'manila_fake_container'
        new_export_location = 'new_export_location'
        fake_pool_name = 'fake_vg'
        shares_list = [self.share, self.share]

        mock_get_container_name = self.mock_object(
            self._driver, '_get_container_name',
            mock.Mock(return_value=fake_container_name))
        mock_umount = self.mock_object(self._driver, '_umount_storage')
        mock_migraton_storage = self.mock_object(
            self._driver.storage, 'share_server_migration_complete')
        mock_mount = self.mock_object(
            self._driver, '_mount_storage',
            mock.Mock(return_value=new_export_location))
        mock_get_pool = self.mock_object(
            self._driver.storage, 'get_share_pool_name',
            mock.Mock(return_value=fake_pool_name))

        share_updates = {}
        for fake_share in shares_list:
            share_updates[fake_share['id']] = {
                'export_locations': new_export_location,
                'pool_name': fake_pool_name,
            }

        expected_result = {
            'share_updates': share_updates,
        }
        self.assertDictMatch(expected_result,
                             self._driver.share_server_migration_complete(
                                 self._context, source_server, dest_server,
                                 shares_list, None, None))
        mock_migraton_storage.assert_called_once_with(
            self._context, source_server, dest_server, shares_list, None, None)

        # assert shares
        for fake_share in shares_list:
            mock_get_pool.assert_any_call(fake_share['share_id'])
            mock_umount.assert_any_call(fake_share, fake_container_name,
                                        fake_share.share_id)
            mock_mount.assert_any_call(fake_share, fake_container_name,
                                       fake_share.share_id)

        mock_get_container_name.assert_any_call(source_server['id'])
        mock_get_container_name.assert_any_call(dest_server['id'])
