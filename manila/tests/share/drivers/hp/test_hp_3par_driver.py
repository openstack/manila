# Copyright 2015 Hewlett Packard Development Company, L.P.
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

import sys

import mock
if 'hp3parclient' not in sys.modules:
    sys.modules['hp3parclient'] = mock.Mock()

from manila import exception
from manila.share.drivers.hp import hp_3par_driver as hp3pardriver
from manila.share.drivers.hp import hp_3par_mediator as hp3parmediator
from manila import test
from manila.tests.share.drivers.hp import test_hp_3par_constants as constants


class HP3ParDriverTestCase(test.TestCase):

    def setUp(self):
        super(HP3ParDriverTestCase, self).setUp()

        # Create a mock configuration with attributes and a safe_get()
        self.conf = mock.Mock()
        self.conf.driver_handles_share_servers = False
        self.conf.hp3par_debug = constants.EXPECTED_HP_DEBUG
        self.conf.hp3par_username = constants.USERNAME
        self.conf.hp3par_password = constants.PASSWORD
        self.conf.hp3par_api_url = constants.API_URL
        self.conf.hp3par_san_login = constants.SAN_LOGIN
        self.conf.hp3par_san_password = constants.SAN_PASSWORD
        self.conf.hp3par_san_ip = constants.EXPECTED_IP_1234
        self.conf.hp3par_fpg = constants.EXPECTED_FPG
        self.conf.hp3par_san_ssh_port = constants.PORT
        self.conf.ssh_conn_timeout = constants.TIMEOUT
        self.conf.hp3par_share_ip_address = constants.EXPECTED_IP_10203040
        self.conf.hp3par_fstore_per_share = False
        self.conf.network_config_group = 'test_network_config_group'

        def safe_get(attr):
            try:
                return self.conf.__getattribute__(attr)
            except AttributeError:
                return None
        self.conf.safe_get = safe_get

        self.real_hp_3par_mediator = hp3parmediator.HP3ParMediator
        self.mock_object(hp3parmediator, 'HP3ParMediator')
        self.mock_mediator_constructor = hp3parmediator.HP3ParMediator
        self.mock_mediator = self.mock_mediator_constructor()

        self.driver = hp3pardriver.HP3ParShareDriver(
            configuration=self.conf)

    def test_driver_setup_success(self):
        """Driver do_setup without any errors."""

        self.mock_mediator.get_vfs_name.return_value = constants.EXPECTED_VFS

        self.driver.do_setup(None)
        conf = self.conf
        self.mock_mediator_constructor.assert_has_calls([
            mock.call(hp3par_san_ssh_port=conf.hp3par_san_ssh_port,
                      hp3par_san_password=conf.hp3par_san_password,
                      hp3par_username=conf.hp3par_username,
                      hp3par_san_login=conf.hp3par_san_login,
                      hp3par_debug=conf.hp3par_debug,
                      hp3par_api_url=conf.hp3par_api_url,
                      hp3par_password=conf.hp3par_password,
                      hp3par_san_ip=conf.hp3par_san_ip,
                      hp3par_fstore_per_share=conf.hp3par_fstore_per_share,
                      ssh_conn_timeout=conf.ssh_conn_timeout)])

        self.mock_mediator.assert_has_calls([
            mock.call.do_setup(),
            mock.call.get_vfs_name(conf.hp3par_fpg)])

        self.assertEqual(constants.EXPECTED_VFS, self.driver.vfs)

    def test_driver_with_setup_error(self):
        """Driver do_setup when the mediator setup fails."""

        self.mock_mediator.do_setup.side_effect = (
            exception.ShareBackendException('fail'))

        self.assertRaises(exception.ShareBackendException,
                          self.driver.do_setup, None)

        conf = self.conf
        self.mock_mediator_constructor.assert_has_calls([
            mock.call(hp3par_san_ssh_port=conf.hp3par_san_ssh_port,
                      hp3par_san_password=conf.hp3par_san_password,
                      hp3par_username=conf.hp3par_username,
                      hp3par_san_login=conf.hp3par_san_login,
                      hp3par_debug=conf.hp3par_debug,
                      hp3par_api_url=conf.hp3par_api_url,
                      hp3par_password=conf.hp3par_password,
                      hp3par_san_ip=conf.hp3par_san_ip,
                      hp3par_fstore_per_share=conf.hp3par_fstore_per_share,
                      ssh_conn_timeout=conf.ssh_conn_timeout)])

        self.mock_mediator.assert_has_calls([mock.call.do_setup()])

    def test_driver_with_vfs_error(self):
        """Driver do_setup when the get_vfs_name fails."""

        self.mock_mediator.get_vfs_name.side_effect = (
            exception.ShareBackendException('fail'))

        self.assertRaises(exception.ShareBackendException,
                          self.driver.do_setup, None)

        conf = self.conf
        self.mock_mediator_constructor.assert_has_calls([
            mock.call(hp3par_san_ssh_port=conf.hp3par_san_ssh_port,
                      hp3par_san_password=conf.hp3par_san_password,
                      hp3par_username=conf.hp3par_username,
                      hp3par_san_login=conf.hp3par_san_login,
                      hp3par_debug=conf.hp3par_debug,
                      hp3par_api_url=conf.hp3par_api_url,
                      hp3par_password=conf.hp3par_password,
                      hp3par_san_ip=conf.hp3par_san_ip,
                      hp3par_fstore_per_share=conf.hp3par_fstore_per_share,
                      ssh_conn_timeout=conf.ssh_conn_timeout)])

        self.mock_mediator.assert_has_calls([
            mock.call.do_setup(),
            mock.call.get_vfs_name(conf.hp3par_fpg)])

    def init_driver(self):
        """Simple driver setup for re-use with tests that need one."""

        self.driver._hp3par = self.mock_mediator
        self.driver.vfs = constants.EXPECTED_VFS
        self.driver.fpg = constants.EXPECTED_FPG
        self.driver.share_ip_address = self.conf.hp3par_share_ip_address
        self.mock_object(hp3pardriver, 'share_types')
        get_extra_specs = hp3pardriver.share_types.get_extra_specs_from_share
        get_extra_specs.return_value = constants.EXPECTED_EXTRA_SPECS

    def do_create_share(self, protocol, share_type_id, expected_project_id,
                        expected_share_id, expected_size):
        """Re-usable code for create share."""
        context = None
        share_server = None
        share = {
            'project_id': expected_project_id,
            'id': expected_share_id,
            'share_proto': protocol,
            'share_type_id': share_type_id,
            'size': expected_size,
        }
        location = self.driver.create_share(context, share, share_server)
        return location

    def do_create_share_from_snapshot(self,
                                      protocol,
                                      share_type_id,
                                      snapshot_id,
                                      expected_share_id,
                                      expected_size):
        """Re-usable code for create share from snapshot."""
        context = None
        share_server = None
        share = {
            'id': expected_share_id,
            'share_proto': protocol,
            'share_type_id': share_type_id,
            'size': expected_size,
        }
        location = self.driver.create_share_from_snapshot(context,
                                                          share,
                                                          snapshot_id,
                                                          share_server)
        return location

    def test_driver_check_for_setup_error_success(self):
        """check_for_setup_error when things go well."""

        # Generally this is always mocked, but here we reference the class.
        hp3parmediator.HP3ParMediator = self.real_hp_3par_mediator

        self.mock_object(hp3pardriver, 'LOG')
        self.init_driver()
        self.driver.check_for_setup_error()
        expected_calls = [
            mock.call.debug('HP3ParShareDriver SHA1: %s', mock.ANY),
            mock.call.debug('HP3ParMediator SHA1: %s', mock.ANY)
        ]
        hp3pardriver.LOG.assert_has_calls(expected_calls)

    def test_driver_check_for_setup_error_exception(self):
        """check_for_setup_error catch and log any exceptions."""

        # Since HP3ParMediator is mocked, we'll hit the except/log.
        self.mock_object(hp3pardriver, 'LOG')
        self.init_driver()
        self.driver.check_for_setup_error()
        expected_calls = [
            mock.call.debug('HP3ParShareDriver SHA1: %s', mock.ANY),
            mock.call.debug('Source code SHA1 not logged due to: %s', mock.ANY)
        ]
        hp3pardriver.LOG.assert_has_calls(expected_calls)

    def test_driver_create_cifs_share(self):
        self.init_driver()

        expected_location = '\\\\%s\%s' % (constants.EXPECTED_IP_10203040,
                                           constants.EXPECTED_SHARE_NAME)

        self.mock_mediator.create_share.return_value = (
            constants.EXPECTED_SHARE_NAME)

        location = self.do_create_share(constants.CIFS,
                                        constants.SHARE_TYPE_ID,
                                        constants.EXPECTED_PROJECT_ID,
                                        constants.EXPECTED_SHARE_ID,
                                        constants.EXPECTED_SIZE_2)

        self.assertEqual(expected_location, location)
        expected_calls = [mock.call.create_share(
            constants.EXPECTED_PROJECT_ID,
            constants.EXPECTED_SHARE_ID,
            constants.CIFS,
            constants.EXPECTED_EXTRA_SPECS,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS,
            size=constants.EXPECTED_SIZE_2)]
        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_create_nfs_share(self):
        self.init_driver()

        expected_location = ':'.join((constants.EXPECTED_IP_10203040,
                                      constants.EXPECTED_SHARE_PATH))

        self.mock_mediator.create_share.return_value = (
            constants.EXPECTED_SHARE_PATH)

        location = self.do_create_share(constants.NFS,
                                        constants.SHARE_TYPE_ID,
                                        constants.EXPECTED_PROJECT_ID,
                                        constants.EXPECTED_SHARE_ID,
                                        constants.EXPECTED_SIZE_1)

        self.assertEqual(expected_location, location)
        expected_calls = [
            mock.call.create_share(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.NFS,
                                   constants.EXPECTED_EXTRA_SPECS,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS,
                                   size=constants.EXPECTED_SIZE_1)]

        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_create_cifs_share_from_snapshot(self):
        self.init_driver()

        expected_location = '\\\\%s\%s' % (constants.EXPECTED_IP_10203040,
                                           constants.EXPECTED_SHARE_NAME)

        self.mock_mediator.create_share_from_snapshot.return_value = (
            constants.EXPECTED_SHARE_NAME)

        location = self.do_create_share_from_snapshot(
            constants.CIFS,
            constants.SHARE_TYPE_ID,
            constants.SNAPSHOT_INFO,
            constants.EXPECTED_SHARE_ID,
            constants.EXPECTED_SIZE_2)

        self.assertEqual(expected_location, location)
        expected_calls = [
            mock.call.create_share_from_snapshot(
                constants.EXPECTED_SHARE_ID,
                constants.CIFS,
                constants.EXPECTED_EXTRA_SPECS,
                constants.EXPECTED_FSTORE,
                constants.EXPECTED_SHARE_ID,
                constants.NFS,
                constants.EXPECTED_SNAP_ID,
                constants.EXPECTED_FPG,
                constants.EXPECTED_VFS),
        ]
        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_create_nfs_share_from_snapshot(self):
        self.init_driver()

        expected_location = ':'.join((constants.EXPECTED_IP_10203040,
                                      constants.EXPECTED_SHARE_PATH))

        self.mock_mediator.create_share_from_snapshot.return_value = (
            constants.EXPECTED_SHARE_PATH)

        location = self.do_create_share_from_snapshot(
            constants.NFS,
            constants.SHARE_TYPE_ID,
            constants.SNAPSHOT_INFO,
            constants.EXPECTED_SHARE_ID,
            constants.EXPECTED_SIZE_1)

        self.assertEqual(expected_location, location)
        expected_calls = [
            mock.call.create_share_from_snapshot(
                constants.EXPECTED_SHARE_ID,
                constants.NFS,
                constants.EXPECTED_EXTRA_SPECS,
                constants.EXPECTED_PROJECT_ID,
                constants.EXPECTED_SHARE_ID,
                constants.NFS,
                constants.EXPECTED_SNAP_ID,
                constants.EXPECTED_FPG,
                constants.EXPECTED_VFS)
        ]

        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_delete_share(self):
        self.init_driver()

        context = None
        share_server = None
        share = {
            'project_id': constants.EXPECTED_PROJECT_ID,
            'id': constants.EXPECTED_SHARE_ID,
            'share_proto': constants.CIFS,
            'size': constants.EXPECTED_SIZE_1,
        }

        self.driver.delete_share(context, share, share_server)

        expected_calls = [
            mock.call.delete_share(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.CIFS,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS)]

        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_create_snapshot(self):
        self.init_driver()

        context = None
        share_server = None
        self.driver.create_snapshot(context,
                                    constants.SNAPSHOT_INFO,
                                    share_server)

        expected_calls = [
            mock.call.create_snapshot(constants.EXPECTED_PROJECT_ID,
                                      constants.EXPECTED_SHARE_ID,
                                      constants.NFS,
                                      constants.EXPECTED_SNAP_ID,
                                      constants.EXPECTED_FPG,
                                      constants.EXPECTED_VFS)]
        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_delete_snapshot(self):
        self.init_driver()

        context = None
        share_server = None
        self.driver.delete_snapshot(context,
                                    constants.SNAPSHOT_INFO,
                                    share_server)

        expected_calls = [
            mock.call.delete_snapshot(constants.EXPECTED_PROJECT_ID,
                                      constants.EXPECTED_SHARE_ID,
                                      constants.NFS,
                                      constants.EXPECTED_SNAP_ID,
                                      constants.EXPECTED_FPG,
                                      constants.EXPECTED_VFS)
        ]
        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_allow_access(self):
        self.init_driver()

        context = None
        self.driver.allow_access(context,
                                 constants.NFS_SHARE_INFO,
                                 constants.ACCESS_INFO)

        expected_calls = [
            mock.call.allow_access(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.NFS,
                                   constants.IP,
                                   constants.EXPECTED_IP_1234,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS)
        ]
        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_deny_access(self):
        self.init_driver()

        context = None
        self.driver.deny_access(context,
                                constants.NFS_SHARE_INFO,
                                constants.ACCESS_INFO)

        expected_calls = [
            mock.call.deny_access(constants.EXPECTED_PROJECT_ID,
                                  constants.EXPECTED_SHARE_ID,
                                  constants.NFS,
                                  constants.IP,
                                  constants.EXPECTED_IP_1234,
                                  constants.EXPECTED_FPG,
                                  constants.EXPECTED_VFS)
        ]
        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_get_share_stats_no_refresh(self):
        """Driver does not call mediator when refresh=False."""

        self.init_driver()
        self.driver._stats = constants.EXPECTED_STATS

        result = self.driver.get_share_stats(refresh=False)

        self.assertEqual(constants.EXPECTED_STATS, result)
        self.assertEqual([], self.mock_mediator.mock_calls)

    def test_driver_get_share_stats_with_refresh(self):
        """Driver adds stats from mediator to expected structure."""

        self.init_driver()
        expected_free = constants.EXPECTED_SIZE_1
        expected_capacity = constants.EXPECTED_SIZE_2
        expected_version = self.driver.VERSION

        self.mock_mediator.get_fpg_status.return_value = {
            'free_capacity_gb': expected_free,
            'total_capacity_gb': expected_capacity,
            'thin_provisioning': True,
            'dedupe': False,
            'hpe3par_flash_cache': False,
        }

        expected_result = {
            'QoS_support': False,
            'driver_handles_share_servers': False,
            'driver_version': expected_version,
            'free_capacity_gb': expected_free,
            'max_over_subscription_ratio': None,
            'pools': None,
            'provisioned_capacity_gb': 0,
            'reserved_percentage': 0,
            'share_backend_name': 'HP_3PAR',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': expected_capacity,
            'vendor_name': 'HP',
            'thin_provisioning': True,
            'dedupe': False,
            'hpe3par_flash_cache': False,
            'snapshot_support': True,
        }

        result = self.driver.get_share_stats(refresh=True)
        self.assertEqual(expected_result, result)

        expected_calls = [
            mock.call.get_fpg_status(constants.EXPECTED_FPG)
        ]
        self.mock_mediator.assert_has_calls(expected_calls)
        self.assertTrue(self.mock_mediator.get_fpg_status.called)

    def test_driver_get_share_stats_premature(self):
        """Driver init stats before init_driver completed."""

        expected_version = self.driver.VERSION

        self.mock_mediator.get_fpg_status.return_value = {'not_called': 1}

        expected_result = {
            'QoS_support': False,
            'driver_handles_share_servers': False,
            'driver_version': expected_version,
            'free_capacity_gb': 0,
            'max_over_subscription_ratio': None,
            'pools': None,
            'provisioned_capacity_gb': 0,
            'reserved_percentage': 0,
            'share_backend_name': 'HP_3PAR',
            'storage_protocol': 'NFS_CIFS',
            'thin_provisioning': True,
            'total_capacity_gb': 0,
            'vendor_name': 'HP',
            'snapshot_support': True,
        }

        result = self.driver.get_share_stats(refresh=True)
        self.assertEqual(expected_result, result)
        self.assertFalse(self.mock_mediator.get_fpg_status.called)
