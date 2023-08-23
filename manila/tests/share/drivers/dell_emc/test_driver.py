# Copyright (c) 2014 EMC Corporation.
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

from unittest import mock

from stevedore import extension

from manila.share import configuration as conf
from manila.share.drivers.dell_emc import driver as emcdriver
from manila.share.drivers.dell_emc.plugins import base
from manila import test


class FakeConnection(base.StorageConnection):
    def __init__(self, *args, **kwargs):
        self.ipv6_implemented = True
        self.dhss_mandatory_security_service_association = {}
        pass

    @property
    def driver_handles_share_servers(self):
        return True

    def create_share(self, context, share, share_server):
        """Is called to create share."""

    def create_snapshot(self, context, snapshot, share_server):
        """Is called to create snapshot."""

    def delete_share(self, context, share, share_server):
        """Is called to remove share."""

    def extend_share(self, share, new_size, share_server):
        """Is called to extend share."""

    def shrink_share(self, share, new_size, share_server):
        """Is called to shrink share."""

    def delete_snapshot(self, context, snapshot, share_server):
        """Is called to remove snapshot."""

    def ensure_share(self, context, share, share_server):
        """Invoked to sure that share is exported."""

    def allow_access(self, context, share, access, share_server):
        """Allow access to the share."""

    def deny_access(self, context, share, access, share_server):
        """Deny access to the share."""

    def raise_connect_error(self):
        """Check for setup error."""

    def connect(self, emc_share_driver, context):
        """Any initialization the share driver does while starting."""

    def update_share_stats(self, stats_dict):
        """Add key/values to stats_dict."""

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""

    def setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""

    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""


class FakeConnection_vmax(FakeConnection):
    def __init__(self, *args, **kwargs):
        self.dhss_mandatory_security_service_association = {}
        self.revert_to_snap_support = False
        self.shrink_share_support = False
        self.manage_existing_support = False
        self.manage_existing_with_server_support = False
        self.manage_existing_snapshot_support = False
        self.manage_snapshot_with_server_support = False
        self.manage_server_support = False
        self.get_share_server_network_info_support = False
        pass


FAKE_BACKEND = 'fake_backend'
FAKE_BACKEND_VMAX = 'vmax'
FAKE_BACKEND_POWERMAX = 'powermax'


class FakeEMCExtensionManager(object):
    def __init__(self):
        self.extensions = []
        self.extensions.append(
            extension.Extension(name=FAKE_BACKEND,
                                plugin=FakeConnection,
                                entry_point=None,
                                obj=None))
        self.extensions.append(
            extension.Extension(name=FAKE_BACKEND_POWERMAX,
                                plugin=FakeConnection_vmax,
                                entry_point=None,
                                obj=None))


class EMCShareFrameworkTestCase(test.TestCase):

    @mock.patch('stevedore.extension.ExtensionManager',
                mock.Mock(return_value=FakeEMCExtensionManager()))
    def setUp(self):
        super(EMCShareFrameworkTestCase, self).setUp()
        self.configuration = conf.Configuration(None)
        self.configuration.append_config_values = mock.Mock(return_value=0)
        self.configuration.share_backend_name = FAKE_BACKEND
        self.mock_object(self.configuration, 'safe_get', self._fake_safe_get)
        self.driver = emcdriver.EMCShareDriver(
            configuration=self.configuration)

        self.configuration_vmax = conf.Configuration(None)
        self.configuration_vmax.append_config_values = \
            mock.Mock(return_value=0)
        self.configuration_vmax.share_backend_name = FAKE_BACKEND_VMAX
        self.mock_object(self.configuration_vmax, 'safe_get',
                         self._fake_safe_get_vmax)
        self.driver_vmax = emcdriver.EMCShareDriver(
            configuration=self.configuration_vmax)

    def test_driver_setup(self):
        FakeConnection.connect = mock.Mock()
        self.driver.do_setup(None)
        self.assertIsInstance(self.driver.plugin, FakeConnection,
                              "Not an instance of FakeConnection")
        FakeConnection.connect.assert_called_with(self.driver, None)

    def test_update_share_stats(self):
        data = {}
        self.driver.plugin = mock.Mock()
        self.driver.plugin.get_default_filter_function.return_value = None
        self.driver._update_share_stats()
        data["share_backend_name"] = FAKE_BACKEND
        data["driver_handles_share_servers"] = True
        data["vendor_name"] = 'Dell EMC'
        data["driver_version"] = '1.0'
        data["storage_protocol"] = 'NFS_CIFS'
        data['total_capacity_gb'] = 'unknown'
        data['free_capacity_gb'] = 'unknown'
        data['reserved_percentage'] = 0
        data['reserved_snapshot_percentage'] = 0
        data['reserved_share_extend_percentage'] = 0
        data['qos'] = False
        data['pools'] = None
        data['snapshot_support'] = True
        data['create_share_from_snapshot_support'] = True
        data['revert_to_snapshot_support'] = False
        data['share_group_stats'] = {'consistent_snapshot_support': None}
        data['mount_snapshot_support'] = False
        data['replication_domain'] = None
        data['filter_function'] = None
        data['goodness_function'] = None
        data['snapshot_support'] = True
        data['create_share_from_snapshot_support'] = True
        data['ipv4_support'] = True
        data['ipv6_support'] = False
        data['max_shares_per_share_server'] = -1
        data['max_share_server_size'] = -1
        data['security_service_update_support'] = False
        data['share_server_multiple_subnet_support'] = False
        data['network_allocation_update_support'] = False
        self.assertEqual(data, self.driver._stats)

    def _fake_safe_get(self, value):
        if value in ['emc_share_backend', 'share_backend_name']:
            return FAKE_BACKEND
        elif value == 'driver_handles_share_servers':
            return True
        return None

    def _fake_safe_get_vmax(self, value):
        if value in ['emc_share_backend', 'share_backend_name']:
            return FAKE_BACKEND_VMAX
        elif value == 'driver_handles_share_servers':
            return True
        return None

    def test_support_manage(self):
        share = mock.Mock()
        driver_options = mock.Mock()
        share_server = mock.Mock()
        snapshot = mock.Mock()
        context = mock.Mock()
        identifier = mock.Mock()
        self.driver.plugin = mock.Mock()
        self.driver.manage_existing_support = True
        self.driver.manage_existing_with_server_support = True
        self.driver.manage_existing_snapshot_support = True
        self.driver.manage_snapshot_with_server_support = True
        self.driver.manage_server_support = True
        self.driver.manage_existing(share, driver_options)
        self.driver.manage_existing_with_server(share, driver_options,
                                                share_server)
        self.driver.manage_existing_snapshot(snapshot, driver_options)
        self.driver.manage_existing_snapshot_with_server(snapshot,
                                                         driver_options,
                                                         share_server)
        self.driver.manage_server(context, share_server, identifier,
                                  driver_options)
        self.driver.get_share_server_network_info_support = True
        self.driver.get_share_server_network_info(context, share_server,
                                                  identifier, driver_options)
        self.driver.create_share(context, share, share_server)
        self.driver.create_share_from_snapshot(context, share, snapshot,
                                               share_server)
        self.driver.extend_share(share, 20, share_server)
        self.driver.shrink_share_support = True
        self.driver.shrink_share(share, 20, share_server)
        self.driver.create_snapshot(context, snapshot, share_server)
        self.driver.delete_share(context, share, share_server)
        self.driver.delete_snapshot(context, snapshot, share_server)
        self.driver.ensure_share(context, share, share_server)
        access = mock.Mock()
        self.driver.allow_access(context, share, access, share_server)
        self.driver.deny_access(context, share, access, share_server)
        self.driver.update_access(context, share, None, None, share_server)
        self.driver.check_for_setup_error()
        self.driver.get_network_allocations_number()
        self.driver._teardown_server(None)
        self.driver.revert_to_snap_support = True
        share_access_rules = mock.Mock()
        snapshot_access_rules = mock.Mock()
        self.driver.revert_to_snapshot(context, snapshot, share_access_rules,
                                       snapshot_access_rules, share_server)
        self.driver.ipv6_implemented = False
        self.driver.get_configured_ip_versions()

    def test_not_support_manage(self):
        share = mock.Mock()
        driver_options = {}
        share_server = mock.Mock()
        snapshot = mock.Mock()
        identifier = mock.Mock()
        self.driver.plugin = mock.Mock()
        result = self.driver.manage_existing(share, driver_options)
        self.assertIsInstance(result, NotImplementedError)
        result = self.driver.manage_existing_with_server(
            share, driver_options, share_server)
        self.assertIsInstance(result, NotImplementedError)
        result = self.driver.manage_existing_snapshot(snapshot, driver_options)
        self.assertIsInstance(result, NotImplementedError)
        result = self.driver.manage_existing_snapshot_with_server(
            snapshot, driver_options, share_server)
        self.assertIsInstance(result, NotImplementedError)
        result = self.driver.manage_server(None, share_server, identifier,
                                           driver_options)
        self.assertIsInstance(result, NotImplementedError)
        result = self.driver.get_share_server_network_info(None,
                                                           share_server,
                                                           identifier,
                                                           driver_options)
        self.assertIsInstance(result, NotImplementedError)

        self.assertRaises(NotImplementedError, self.driver.shrink_share, share,
                          20, share_server)

        share_access_rules = mock.Mock()
        snapshot_access_rules = mock.Mock()
        self.assertRaises(NotImplementedError, self.driver.revert_to_snapshot,
                          None, snapshot, share_access_rules,
                          snapshot_access_rules, share_server)

    def test_unmanage_manage(self):
        share = mock.Mock()
        server_details = {}
        share_server = mock.Mock()
        snapshot = mock.Mock()
        self.driver.plugin = mock.Mock(share)
        self.driver.unmanage(share)
        self.driver.unmanage_with_server(share, share_server)
        self.driver.unmanage_snapshot(snapshot)
        self.driver.unmanage_snapshot_with_server(snapshot, share_server)
        self.driver.unmanage_server(server_details)

    def test_get_default_filter_function(self):
        expected = None
        actual = self.driver.get_default_filter_function()
        self.assertEqual(expected, actual)

    def test_setup_server(self):
        network_info = [{}]
        expected = None
        result = self.driver._setup_server(network_info)
        self.assertEqual(expected, result)
