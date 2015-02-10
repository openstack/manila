# Copyright (c) 2014 Clinton Knight.  All rights reserved.
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
"""
Mock unit tests for the NetApp Data ONTAP cDOT storage driver library.
"""

import copy
import datetime
import socket

import mock
from oslo_utils import timeutils
from oslo_utils import units

from manila import context
from manila import exception
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_base
from manila.share.drivers.netapp.dataontap.protocols import cifs_cmode
from manila.share.drivers.netapp.dataontap.protocols import nfs_cmode
from manila.share.drivers.netapp import utils as na_utils
from manila import test
import manila.tests.share.drivers.netapp.dataontap.fakes as fake
import manila.tests.share.drivers.netapp.fakes as na_fakes


class EnsureVserverDecoratorTestCase(test.TestCase):

    def setUp(self):
        super(EnsureVserverDecoratorTestCase, self).setUp()
        self._client = mock.Mock()

    @lib_base.ensure_vserver
    def ensure_vserver_test_method(*args, **kwargs):
        return 'OK'

    def test_ensure_vserver(self):

        self._client.vserver_exists.return_value = True
        kwargs = {'share_server': fake.SHARE_SERVER}

        result = self.ensure_vserver_test_method(**kwargs)

        self.assertEqual('OK', result)

    def test_ensure_vserver_no_share_server(self):

        self._client.vserver_exists.return_value = True

        self.assertRaises(exception.NetAppException,
                          self.ensure_vserver_test_method)

    def test_ensure_vserver_no_backend_details(self):

        self._client.vserver_exists.return_value = True
        fake_share_server = copy.deepcopy(fake.SHARE_SERVER)
        fake_share_server['backend_details'] = None
        kwargs = {'share_server': fake_share_server}

        self.assertRaises(exception.NetAppException,
                          self.ensure_vserver_test_method,
                          **kwargs)

    def test_ensure_vserver_no_vserver_name(self):

        self._client.vserver_exists.return_value = True
        fake_share_server = copy.deepcopy(fake.SHARE_SERVER)
        fake_share_server['backend_details']['vserver_name'] = None
        kwargs = {'share_server': fake_share_server}

        self.assertRaises(exception.NetAppException,
                          self.ensure_vserver_test_method,
                          **kwargs)

    def test_ensure_vserver_not_found(self):

        self._client.vserver_exists.return_value = False
        kwargs = {'share_server': fake.SHARE_SERVER}

        self.assertRaises(exception.VserverUnavailable,
                          self.ensure_vserver_test_method,
                          **kwargs)


class NetAppFileStorageLibraryTestCase(test.TestCase):

    def setUp(self):
        super(NetAppFileStorageLibraryTestCase, self).setUp()

        self.mock_object(na_utils, 'validate_instantiation')
        self.mock_object(na_utils, 'setup_tracing')
        self.mock_object(lib_base, 'LOG')

        self.mock_db = mock.Mock()
        kwargs = {
            'configuration': self._get_config_cmode(),
            'app_version': fake.APP_VERSION
        }
        self.library = lib_base.NetAppCmodeFileStorageLibrary(self.mock_db,
                                                              fake.DRIVER_NAME,
                                                              **kwargs)
        self.library._client = mock.Mock()
        self.client = self.library._client
        self.context = mock.Mock()

    def _get_config_cmode(self):
        config = na_fakes.create_configuration_cmode()
        config.local_conf.set_override('share_backend_name',
                                       fake.BACKEND_NAME)
        config.netapp_login = fake.CLIENT_KWARGS['username']
        config.netapp_password = fake.CLIENT_KWARGS['password']
        config.netapp_server_hostname = fake.CLIENT_KWARGS['hostname']
        config.netapp_transport_type = fake.CLIENT_KWARGS['transport_type']
        config.netapp_server_port = fake.CLIENT_KWARGS['port']
        config.netapp_vserver = fake.VSERVER1
        config.netapp_volume_name_template = fake.VOLUME_NAME_TEMPLATE
        config.netapp_aggregate_name_search_pattern = \
            fake.AGGREGATE_NAME_SEARCH_PATTERN
        config.netapp_vserver_name_template = fake.VSERVER_NAME_TEMPLATE
        config.netapp_root_volume_aggregate = fake.ROOT_VOLUME_AGGREGATE
        config.netapp_root_volume = fake.ROOT_VOLUME
        config.netapp_lif_name_template = fake.LIF_NAME_TEMPLATE
        return config

    def test_init(self):
        self.assertEqual(fake.DRIVER_NAME, self.library.driver_name)
        self.assertEqual(self.mock_db, self.library.db)
        self.assertEqual(1, na_utils.validate_instantiation.call_count)
        self.assertEqual(1, na_utils.setup_tracing.call_count)
        self.assertIsNone(self.library._helpers)
        self.assertListEqual([], self.library._licenses)
        self.assertDictEqual({}, self.library._clients)
        self.assertIsNotNone(self.library._app_version)
        self.assertIsNotNone(self.library._last_ems)

    def test_do_setup(self):
        mock_setup_helpers = self.mock_object(self.library, '_setup_helpers')
        mock_get_api_client = self.mock_object(self.library,
                                               '_get_api_client')
        self.library.do_setup(self.context)

        mock_get_api_client.assert_called_once_with()
        mock_setup_helpers.assert_called_once_with()

    def test_check_for_setup_error(self):
        mock_get_licenses = self.mock_object(self.library, '_get_licenses')

        self.library.check_for_setup_error()

        mock_get_licenses.assert_called_once_with()

    def test_get_api_client(self):

        client_kwargs = fake.CLIENT_KWARGS.copy()

        # First call should proceed normally.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client1 = self.library._get_api_client()
        self.assertIsNotNone(client1)
        mock_client_constructor.assert_called_once_with(**client_kwargs)

        # Second call should yield the same object.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client2 = self.library._get_api_client()
        self.assertEqual(client1, client2)
        self.assertFalse(mock_client_constructor.called)

    def test_get_api_client_with_vserver(self):

        client_kwargs = fake.CLIENT_KWARGS.copy()
        client_kwargs['vserver'] = fake.VSERVER1

        # First call should proceed normally.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client1 = self.library._get_api_client(vserver=fake.VSERVER1)
        self.assertIsNotNone(client1)
        mock_client_constructor.assert_called_once_with(**client_kwargs)

        # Second call should yield the same object.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client2 = self.library._get_api_client(vserver=fake.VSERVER1)
        self.assertEqual(client1, client2)
        self.assertFalse(mock_client_constructor.called)

        # A different vserver should work normally without caching.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client3 = self.library._get_api_client(vserver=fake.VSERVER2)
        self.assertNotEqual(client1, client3)
        client_kwargs['vserver'] = fake.VSERVER2
        mock_client_constructor.assert_called_once_with(**client_kwargs)

    def test_get_licenses_both_protocols(self):
        self.mock_object(self.client,
                         'get_licenses',
                         mock.Mock(return_value=fake.LICENSES))

        result = self.library._get_licenses()

        self.assertListEqual(fake.LICENSES, result)
        self.assertEqual(0, lib_base.LOG.error.call_count)
        self.assertEqual(1, lib_base.LOG.info.call_count)

    def test_get_licenses_one_protocol(self):
        licenses = list(fake.LICENSES)
        licenses.remove('nfs')
        self.mock_object(self.client,
                         'get_licenses',
                         mock.Mock(return_value=licenses))

        result = self.library._get_licenses()

        self.assertListEqual(licenses, result)
        self.assertEqual(0, lib_base.LOG.error.call_count)
        self.assertEqual(1, lib_base.LOG.info.call_count)

    def test_get_licenses_no_protocols(self):
        licenses = list(fake.LICENSES)
        licenses.remove('nfs')
        licenses.remove('cifs')
        self.mock_object(self.client,
                         'get_licenses',
                         mock.Mock(return_value=licenses))

        result = self.library._get_licenses()

        self.assertListEqual(licenses, result)
        self.assertEqual(1, lib_base.LOG.error.call_count)
        self.assertEqual(1, lib_base.LOG.info.call_count)

    def test_get_valid_share_name(self):

        result = self.library._get_valid_share_name(fake.SHARE_ID)
        expected = (fake.VOLUME_NAME_TEMPLATE %
                    {'share_id': fake.SHARE_ID.replace('-', '_')})

        self.assertEqual(expected, result)

    def test_get_valid_snapshot_name(self):

        result = self.library._get_valid_snapshot_name(fake.SNAPSHOT_ID)
        expected = 'share_snapshot_' + fake.SNAPSHOT_ID.replace('-', '_')

        self.assertEqual(expected, result)

    def test_get_share_stats(self):

        self.mock_object(self.library, '_find_matching_aggregates')
        self.mock_object(self.client,
                         'calculate_aggregate_capacity',
                         mock.Mock(return_value=(fake.TOTAL_CAPACITY,
                                                 fake.FREE_CAPACITY)))
        mock_handle_ems_logging = self.mock_object(self.library,
                                                   '_handle_ems_logging')

        result = self.library.get_share_stats()

        expected = {
            'share_backend_name': fake.BACKEND_NAME,
            'driver_name': fake.DRIVER_NAME,
            'vendor_name': 'NetApp',
            'driver_version': '1.0',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': fake.TOTAL_CAPACITY / units.Gi,
            'free_capacity_gb': fake.FREE_CAPACITY / units.Gi
        }

        self.assertDictEqual(expected, result)
        self.assertTrue(mock_handle_ems_logging.called)

    def test_handle_ems_logging(self):

        self.mock_object(self.library,
                         '_build_ems_log_message',
                         mock.Mock(return_value=fake.EMS_MESSAGE))
        test_now = timeutils.utcnow() - datetime.timedelta(
            seconds=(self.library.AUTOSUPPORT_INTERVAL_SECONDS + 1))
        self.library._last_ems = test_now

        self.library._handle_ems_logging()

        self.assertTrue(self.library._last_ems > test_now)
        self.library._client.send_ems_log_message.assert_called_with(
            fake.EMS_MESSAGE)

    def test_handle_ems_logging_not_yet(self):

        self.mock_object(self.library,
                         '_build_ems_log_message',
                         mock.Mock(return_value=fake.EMS_MESSAGE))
        test_now = timeutils.utcnow() - datetime.timedelta(
            seconds=(self.library.AUTOSUPPORT_INTERVAL_SECONDS - 1))
        self.library._last_ems = test_now

        self.library._handle_ems_logging()

        self.assertEqual(test_now, self.library._last_ems)
        self.assertFalse(self.library._client.send_ems_log_message.called)

    def test_build_ems_log_message(self):

        self.mock_object(socket,
                         'getfqdn',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = self.library._build_ems_log_message()

        fake_ems_log = {
            'computer-name': fake.HOST_NAME,
            'event-id': '0',
            'event-source': 'Manila driver %s' % fake.DRIVER_NAME,
            'app-version': fake.APP_VERSION,
            'category': 'provisioning',
            'event-description': 'OpenStack Manila connected to cluster node',
            'log-level': '6',
            'auto-support': 'false'
        }
        self.assertDictEqual(fake_ems_log, result)

    def test_find_matching_aggregates(self):

        self.mock_object(self.client,
                         'list_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))

        self.library.configuration.netapp_aggregate_name_search_pattern =\
            fake.AGGREGATE_NAME_SEARCH_PATTERN
        result = self.library._find_matching_aggregates()
        self.assertListEqual(result, fake.AGGREGATES)

        self.library.configuration.netapp_aggregate_name_search_pattern =\
            'aggr.*'
        result = self.library._find_matching_aggregates()
        self.assertListEqual(result, ['aggr0'])

    def test_setup_helpers(self):

        self.mock_object(cifs_cmode,
                         'NetAppCmodeCIFSHelper',
                         mock.Mock(return_value='fake_cifs_helper'))
        self.mock_object(nfs_cmode,
                         'NetAppCmodeNFSHelper',
                         mock.Mock(return_value='fake_nfs_helper'))
        self.library._helpers = None

        self.library._setup_helpers()

        self.assertDictEqual({'CIFS': 'fake_cifs_helper',
                              'NFS': 'fake_nfs_helper'},
                             self.library._helpers)

    def test_get_helper(self):

        self.library._helpers = {'CIFS': 'fake_cifs_helper',
                                 'NFS': 'fake_nfs_helper'}
        self.library._licenses = fake.LICENSES
        fake_share = fake.SHARE.copy()
        fake_share['share_proto'] = 'NFS'

        result = self.library._get_helper(fake_share)

        self.assertEqual('fake_nfs_helper', result)

    def test_get_helper_newly_licensed_protocol(self):

        self.mock_object(self.library,
                         '_get_licenses',
                         mock.Mock(return_value=['base', 'nfs']))
        self.library._helpers = {'CIFS': 'fake_cifs_helper',
                                 'NFS': 'fake_nfs_helper'}
        self.library._licenses = ['base']
        fake_share = fake.SHARE.copy()
        fake_share['share_proto'] = 'NFS'

        result = self.library._get_helper(fake_share)

        self.assertEqual('fake_nfs_helper', result)
        self.assertTrue(self.library._get_licenses.called)

    def test_get_helper_unlicensed_protocol(self):

        self.mock_object(self.library,
                         '_get_licenses',
                         mock.Mock(return_value=['base']))
        self.library._helpers = {'CIFS': 'fake_cifs_helper',
                                 'NFS': 'fake_nfs_helper'}
        self.library._licenses = ['base']
        fake_share = fake.SHARE.copy()
        fake_share['share_proto'] = 'NFS'

        self.assertRaises(exception.NetAppException,
                          self.library._get_helper,
                          fake_share)

    def test_get_helper_invalid_protocol(self):

        self.mock_object(self.library,
                         '_get_licenses',
                         mock.Mock(return_value=['base', 'iscsi']))
        self.library._helpers = {'CIFS': 'fake_cifs_helper',
                                 'NFS': 'fake_nfs_helper'}
        self.library._licenses = ['base', 'iscsi']
        fake_share = fake.SHARE.copy()
        fake_share['share_proto'] = 'iSCSI'

        self.assertRaises(exception.NetAppException,
                          self.library._get_helper,
                          fake_share)

    def test_setup_server(self):

        mock_create_vserver = self.mock_object(
            self.library, '_create_vserver_if_nonexistent',
            mock.Mock(return_value=fake.VSERVER1))

        result = self.library.setup_server(fake.NETWORK_INFO)

        self.assertTrue(mock_create_vserver.called)
        self.assertDictEqual({'vserver_name': fake.VSERVER1}, result)

    def test_create_vserver_if_nonexistent(self):

        vserver_id = fake.NETWORK_INFO['server_id']
        vserver_name = fake.VSERVER_NAME_TEMPLATE % vserver_id
        vserver_client = mock.Mock()

        self.mock_object(context,
                         'get_admin_context',
                         mock.Mock(return_value='fake_admin_context'))
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))
        self.mock_object(self.library._client,
                         'vserver_exists',
                         mock.Mock(return_value=False))
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library, '_create_vserver_lifs')

        result = self.library._create_vserver_if_nonexistent(
            fake.NETWORK_INFO)

        self.assertEqual(vserver_name, result)
        self.library.db.share_server_backend_details_set.assert_called_with(
            'fake_admin_context',
            vserver_id,
            {'vserver_name': vserver_name})
        self.library._get_api_client.assert_called_with(vserver=vserver_name)
        self.library._client.create_vserver.assert_called_with(
            vserver_name,
            fake.ROOT_VOLUME_AGGREGATE,
            fake.ROOT_VOLUME,
            fake.AGGREGATES)
        self.library._create_vserver_lifs.assert_called_with(
            vserver_name,
            vserver_client,
            fake.NETWORK_INFO)
        self.assertTrue(vserver_client.enable_nfs.called)
        self.library._client.setup_security_services.assert_called_with(
            fake.NETWORK_INFO['security_services'],
            vserver_client,
            vserver_name)

    def test_create_vserver_if_nonexistent_already_present(self):

        vserver_id = fake.NETWORK_INFO['server_id']
        vserver_name = fake.VSERVER_NAME_TEMPLATE % vserver_id

        self.mock_object(context,
                         'get_admin_context',
                         mock.Mock(return_value='fake_admin_context'))
        self.mock_object(self.library._client,
                         'vserver_exists',
                         mock.Mock(return_value=True))

        self.assertRaises(exception.NetAppException,
                          self.library._create_vserver_if_nonexistent,
                          fake.NETWORK_INFO)

        self.library.db.share_server_backend_details_set.assert_called_with(
            'fake_admin_context',
            vserver_id,
            {'vserver_name': vserver_name})

    def test_create_vserver_if_nonexistent_lif_creation_failure(self):

        vserver_id = fake.NETWORK_INFO['server_id']
        vserver_name = fake.VSERVER_NAME_TEMPLATE % vserver_id
        vserver_client = mock.Mock()

        self.mock_object(context,
                         'get_admin_context',
                         mock.Mock(return_value='fake_admin_context'))
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))
        self.mock_object(self.library._client,
                         'vserver_exists',
                         mock.Mock(return_value=False))
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library,
                         '_create_vserver_lifs',
                         mock.Mock(side_effect=netapp_api.NaApiError))

        self.assertRaises(netapp_api.NaApiError,
                          self.library._create_vserver_if_nonexistent,
                          fake.NETWORK_INFO)

        self.library.db.share_server_backend_details_set.assert_called_with(
            'fake_admin_context',
            vserver_id,
            {'vserver_name': vserver_name})
        self.library._get_api_client.assert_called_with(vserver=vserver_name)
        self.assertTrue(self.library._client.create_vserver.called)
        self.library._create_vserver_lifs.assert_called_with(
            vserver_name,
            vserver_client,
            fake.NETWORK_INFO)
        self.library._client.delete_vserver.assert_called_once_with(
            vserver_name,
            vserver_client)
        self.assertFalse(vserver_client.enable_nfs.called)
        self.assertEqual(1, lib_base.LOG.error.call_count)

    def test_create_vserver_lifs(self):

        self.mock_object(self.library._client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.CLUSTER_NODES))
        self.mock_object(self.library._client,
                         'get_node_data_port',
                         mock.Mock(return_value=fake.NODE_DATA_PORT))
        self.mock_object(self.library, '_create_lif_if_nonexistent')

        self.library._create_vserver_lifs(fake.VSERVER1,
                                          'fake_vserver_client',
                                          fake.NETWORK_INFO)

        self.library._create_lif_if_nonexistent.assert_has_calls([
            mock.call(
                fake.VSERVER1,
                fake.NETWORK_INFO['network_allocations'][0]['id'],
                fake.NETWORK_INFO['segmentation_id'],
                fake.CLUSTER_NODES[0],
                fake.NODE_DATA_PORT,
                fake.NETWORK_INFO['network_allocations'][0]['ip_address'],
                fake.NETWORK_INFO_NETMASK,
                'fake_vserver_client'),
            mock.call(
                fake.VSERVER1,
                fake.NETWORK_INFO['network_allocations'][1]['id'],
                fake.NETWORK_INFO['segmentation_id'],
                fake.CLUSTER_NODES[1],
                fake.NODE_DATA_PORT,
                fake.NETWORK_INFO['network_allocations'][1]['ip_address'],
                fake.NETWORK_INFO_NETMASK,
                'fake_vserver_client')])

    def test_create_lif_if_nonexistent(self):

        vserver_client = mock.Mock()
        vserver_client.network_interface_exists = mock.Mock(
            return_value=False)

        self.library._create_lif_if_nonexistent('fake_vserver',
                                                'fake_allocation_id',
                                                'fake_vlan',
                                                'fake_node',
                                                'fake_port',
                                                'fake_ip',
                                                'fake_netmask',
                                                vserver_client)

        self.library._client.create_network_interface.assert_has_calls([
            mock.call(
                'fake_ip',
                'fake_netmask',
                'fake_vlan',
                'fake_node',
                'fake_port',
                'fake_vserver',
                'fake_allocation_id',
                fake.LIF_NAME_TEMPLATE)])

    def test_create_lif_if_nonexistent_already_present(self):

        vserver_client = mock.Mock()
        vserver_client.network_interface_exists = mock.Mock(
            return_value=True)

        self.library._create_lif_if_nonexistent('fake_vserver',
                                                'fake_allocation_id',
                                                'fake_vlan',
                                                'fake_node',
                                                'fake_port',
                                                'fake_ip',
                                                'fake_netmask',
                                                vserver_client)

        self.assertFalse(self.library._client.create_network_interface.called)

    def test_create_share(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))
        mock_allocate_container = self.mock_object(self.library,
                                                   '_allocate_container')
        mock_create_export = self.mock_object(
            self.library,
            '_create_export',
            mock.Mock(return_value='fake_export_location'))

        result = self.library.create_share(self.context,
                                           fake.SHARE,
                                           share_server=fake.SHARE_SERVER)

        mock_allocate_container.assert_called_once_with(fake.SHARE,
                                                        fake.VSERVER1,
                                                        vserver_client)
        mock_create_export.assert_called_once_with(fake.SHARE,
                                                   fake.VSERVER1,
                                                   vserver_client)
        self.assertEqual('fake_export_location', result)

    def test_create_share_from_snapshot(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))
        mock_allocate_container_from_snapshot = self.mock_object(
            self.library,
            '_allocate_container_from_snapshot')
        mock_create_export = self.mock_object(
            self.library,
            '_create_export',
            mock.Mock(return_value='fake_export_location'))

        result = self.library.create_share_from_snapshot(
            self.context,
            fake.SHARE,
            fake.SNAPSHOT,
            share_server=fake.SHARE_SERVER)

        mock_allocate_container_from_snapshot.assert_called_once_with(
            fake.SHARE,
            fake.SNAPSHOT,
            vserver_client)
        mock_create_export.assert_called_once_with(fake.SHARE,
                                                   fake.VSERVER1,
                                                   vserver_client)
        self.assertEqual('fake_export_location', result)

    def test_allocate_container(self):

        aggregates = {'aggr0': 10000000000, 'aggr1': 20000000000}
        vserver_client = mock.Mock()
        vserver_client.get_aggregates_for_vserver.return_value = aggregates

        self.library._allocate_container(fake.SHARE,
                                         fake.VSERVER1,
                                         vserver_client)

        share_name = self.library._get_valid_share_name(fake.SHARE['id'])
        vserver_client.create_volume.assert_called_with('aggr1',
                                                        share_name,
                                                        fake.SHARE['size'])

    def test_allocate_container_from_snapshot(self):

        vserver_client = mock.Mock()

        self.library._allocate_container_from_snapshot(fake.SHARE,
                                                       fake.SNAPSHOT,
                                                       vserver_client)

        share_name = self.library._get_valid_share_name(fake.SHARE['id'])
        parent_share_name = self.library._get_valid_share_name(
            fake.SNAPSHOT['share_id'])
        parent_snapshot_name = self.library._get_valid_snapshot_name(
            fake.SNAPSHOT['id'])
        vserver_client.create_volume_clone.assert_called_with(
            share_name,
            parent_share_name,
            parent_snapshot_name)

    def test_share_exists(self):

        vserver_client = mock.Mock()

        vserver_client.volume_exists.return_value = True
        result = self.library._share_exists(fake.SHARE_NAME, vserver_client)
        self.assertTrue(result)

        vserver_client.volume_exists.return_value = False
        result = self.library._share_exists(fake.SHARE_NAME, vserver_client)
        self.assertFalse(result)

    def test_delete_share(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=True))
        mock_remove_export = self.mock_object(self.library, '_remove_export')
        mock_deallocate_container = self.mock_object(self.library,
                                                     '_deallocate_container')

        self.library.delete_share(self.context,
                                  fake.SHARE,
                                  share_server=fake.SHARE_SERVER)

        share_name = self.library._get_valid_share_name(fake.SHARE['id'])
        mock_share_exists.assert_called_once_with(share_name, vserver_client)
        mock_remove_export.assert_called_once_with(fake.SHARE, vserver_client)
        mock_deallocate_container.assert_called_once_with(share_name,
                                                          vserver_client)
        self.assertEqual(0, lib_base.LOG.info.call_count)

    def test_delete_share_not_found(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=False))
        mock_remove_export = self.mock_object(self.library, '_remove_export')
        mock_deallocate_container = self.mock_object(self.library,
                                                     '_deallocate_container')

        self.library.delete_share(self.context,
                                  fake.SHARE,
                                  share_server=fake.SHARE_SERVER)

        share_name = self.library._get_valid_share_name(fake.SHARE['id'])
        mock_share_exists.assert_called_once_with(share_name, vserver_client)
        self.assertFalse(mock_remove_export.called)
        self.assertFalse(mock_deallocate_container.called)
        self.assertEqual(1, lib_base.LOG.info.call_count)

    def test_deallocate_container(self):

        vserver_client = mock.Mock()

        self.library._deallocate_container(fake.SHARE_NAME, vserver_client)

        vserver_client.unmount_volume.assert_called_with(fake.SHARE_NAME,
                                                         force=True)
        vserver_client.offline_volume.assert_called_with(fake.SHARE_NAME)
        vserver_client.delete_volume.assert_called_with(fake.SHARE_NAME)

    def test_create_export(self):

        protocol_helper = mock.Mock()
        protocol_helper.create_share.return_value = 'fake_export_location'
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()
        vserver_client.get_network_interfaces.return_value = fake.LIFS

        result = self.library._create_export(fake.SHARE,
                                             fake.VSERVER1,
                                             vserver_client)

        share_name = self.library._get_valid_share_name(fake.SHARE['id'])
        self.assertEqual('fake_export_location', result)
        protocol_helper.create_share.assert_called_once_with(
            share_name,
            fake.LIFS[0]['address'])

    def test_create_export_lifs_not_found(self):

        self.mock_object(self.library, '_get_helper')
        vserver_client = mock.Mock()
        vserver_client.get_network_interfaces.return_value = []

        self.assertRaises(exception.NetAppException,
                          self.library._create_export,
                          fake.SHARE,
                          fake.VSERVER1,
                          vserver_client)

    def test_remove_export(self):

        protocol_helper = mock.Mock()
        protocol_helper.get_target.return_value = 'fake_target'
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()

        self.library._remove_export(fake.SHARE, vserver_client)

        protocol_helper.set_client.assert_called_once_with(vserver_client)
        protocol_helper.get_target.assert_called_once_with(fake.SHARE)
        protocol_helper.delete_share.assert_called_once_with(fake.SHARE)

    def test_remove_export_target_not_found(self):

        protocol_helper = mock.Mock()
        protocol_helper.get_target.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()

        self.library._remove_export(fake.SHARE, vserver_client)

        protocol_helper.set_client.assert_called_once_with(vserver_client)
        protocol_helper.get_target.assert_called_once_with(fake.SHARE)
        self.assertFalse(protocol_helper.delete_share.called)

    def test_create_snapshot(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))

        self.library.create_snapshot(self.context,
                                     fake.SNAPSHOT,
                                     share_server=fake.SHARE_SERVER)

        share_name = self.library._get_valid_share_name(
            fake.SNAPSHOT['share_id'])
        snapshot_name = self.library._get_valid_snapshot_name(
            fake.SNAPSHOT['id'])
        vserver_client.create_snapshot.assert_called_once_with(
            share_name,
            snapshot_name)

    def test_delete_snapshot(self):

        vserver_client = mock.Mock()
        vserver_client.is_snapshot_busy.return_value = False
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))

        self.library.delete_snapshot(self.context,
                                     fake.SNAPSHOT,
                                     share_server=fake.SHARE_SERVER)

        share_name = self.library._get_valid_share_name(
            fake.SNAPSHOT['share_id'])
        snapshot_name = self.library._get_valid_snapshot_name(
            fake.SNAPSHOT['id'])
        vserver_client.delete_snapshot.assert_called_once_with(
            share_name,
            snapshot_name)

    def test_delete_snapshot_busy(self):

        vserver_client = mock.Mock()
        vserver_client.is_snapshot_busy.return_value = True
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))

        self.assertRaises(exception.ShareSnapshotIsBusy,
                          self.library.delete_snapshot,
                          self.context,
                          fake.SNAPSHOT,
                          share_server=fake.SHARE_SERVER)

    def test_allow_access(self):

        protocol_helper = mock.Mock()
        protocol_helper.allow_access.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))

        self.library.allow_access(self.context,
                                  fake.SHARE,
                                  fake.SHARE_ACCESS,
                                  share_server=fake.SHARE_SERVER)

        protocol_helper.set_client.assert_called_once_with(vserver_client)
        protocol_helper.allow_access.assert_called_once_with(
            self.context,
            fake.SHARE,
            fake.SHARE_ACCESS)

    def test_deny_access(self):

        protocol_helper = mock.Mock()
        protocol_helper.deny_access.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))

        self.library.deny_access(self.context,
                                 fake.SHARE,
                                 fake.SHARE_ACCESS,
                                 share_server=fake.SHARE_SERVER)

        protocol_helper.set_client.assert_called_once_with(vserver_client)
        protocol_helper.deny_access.assert_called_once_with(
            self.context,
            fake.SHARE,
            fake.SHARE_ACCESS)

    def test_get_network_allocations_number(self):

        self.library._client.list_cluster_nodes.return_value = \
            fake.CLUSTER_NODES

        result = self.library.get_network_allocations_number()

        self.assertEqual(len(fake.CLUSTER_NODES), result)

    def test_teardown_server(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))

        self.library.teardown_server(
            fake.SHARE_SERVER['backend_details'],
            security_services=fake.NETWORK_INFO['security_services'])

        self.library._client.delete_vserver.assert_called_once_with(
            fake.VSERVER1,
            vserver_client,
            security_services=fake.NETWORK_INFO['security_services'])
