# Copyright 2015 Hewlett Packard Enterprise Development LP
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

import ddt
import mock
if 'hpe3parclient' not in sys.modules:
    sys.modules['hpe3parclient'] = mock.Mock()

from manila import exception
from manila.share.drivers.hpe import hpe_3par_driver as hpe3pardriver
from manila.share.drivers.hpe import hpe_3par_mediator as hpe3parmediator
from manila import test
from manila.tests.share.drivers.hpe import test_hpe_3par_constants as constants


@ddt.ddt
class HPE3ParDriverTestCase(test.TestCase):

    def setUp(self):
        super(HPE3ParDriverTestCase, self).setUp()

        # Create a mock configuration with attributes and a safe_get()
        self.conf = mock.Mock()
        self.conf.driver_handles_share_servers = True
        self.conf.hpe3par_debug = constants.EXPECTED_HPE_DEBUG
        self.conf.hpe3par_username = constants.USERNAME
        self.conf.hpe3par_password = constants.PASSWORD
        self.conf.hpe3par_api_url = constants.API_URL
        self.conf.hpe3par_san_login = constants.SAN_LOGIN
        self.conf.hpe3par_san_password = constants.SAN_PASSWORD
        self.conf.hpe3par_san_ip = constants.EXPECTED_IP_1234
        self.conf.hpe3par_fpg = constants.EXPECTED_FPG
        self.conf.hpe3par_san_ssh_port = constants.PORT
        self.conf.ssh_conn_timeout = constants.TIMEOUT
        self.conf.hpe3par_share_ip_address = None
        self.conf.hpe3par_fstore_per_share = False
        self.conf.hpe3par_require_cifs_ip = False
        self.conf.hpe3par_share_ip_address = constants.EXPECTED_IP_10203040
        self.conf.hpe3par_cifs_admin_access_username = constants.USERNAME,
        self.conf.hpe3par_cifs_admin_access_password = constants.PASSWORD,
        self.conf.hpe3par_cifs_admin_access_domain = (
            constants.EXPECTED_CIFS_DOMAIN),
        self.conf.hpe3par_share_mount_path = constants.EXPECTED_MOUNT_PATH,
        self.conf.my_ip = constants.EXPECTED_IP_1234
        self.conf.network_config_group = 'test_network_config_group'
        self.conf.admin_network_config_group = (
            'test_admin_network_config_group')

        def safe_get(attr):
            try:
                return self.conf.__getattribute__(attr)
            except AttributeError:
                return None
        self.conf.safe_get = safe_get

        self.real_hpe_3par_mediator = hpe3parmediator.HPE3ParMediator
        self.mock_object(hpe3parmediator, 'HPE3ParMediator')
        self.mock_mediator_constructor = hpe3parmediator.HPE3ParMediator
        self.mock_mediator = self.mock_mediator_constructor()

        self.driver = hpe3pardriver.HPE3ParShareDriver(
            configuration=self.conf)

    def test_driver_setup_success(self):
        """Driver do_setup without any errors."""

        self.mock_mediator.get_vfs_name.return_value = constants.EXPECTED_VFS

        self.driver.do_setup(None)
        conf = self.conf
        self.mock_mediator_constructor.assert_has_calls([
            mock.call(hpe3par_san_ssh_port=conf.hpe3par_san_ssh_port,
                      hpe3par_san_password=conf.hpe3par_san_password,
                      hpe3par_username=conf.hpe3par_username,
                      hpe3par_san_login=conf.hpe3par_san_login,
                      hpe3par_debug=conf.hpe3par_debug,
                      hpe3par_api_url=conf.hpe3par_api_url,
                      hpe3par_password=conf.hpe3par_password,
                      hpe3par_san_ip=conf.hpe3par_san_ip,
                      hpe3par_fstore_per_share=conf.hpe3par_fstore_per_share,
                      hpe3par_require_cifs_ip=conf.hpe3par_require_cifs_ip,
                      hpe3par_share_ip_address=(
                          self.conf.hpe3par_share_ip_address),
                      hpe3par_cifs_admin_access_username=(
                          conf.hpe3par_cifs_admin_access_username),
                      hpe3par_cifs_admin_access_password=(
                          conf.hpe3par_cifs_admin_access_password),
                      hpe3par_cifs_admin_access_domain=(
                          conf.hpe3par_cifs_admin_access_domain),
                      hpe3par_share_mount_path=conf.hpe3par_share_mount_path,
                      my_ip=self.conf.my_ip,
                      ssh_conn_timeout=conf.ssh_conn_timeout)])

        self.mock_mediator.assert_has_calls([
            mock.call.do_setup(),
            mock.call.get_vfs_name(conf.hpe3par_fpg)])

        self.assertEqual(constants.EXPECTED_VFS, self.driver.vfs)

    def test_driver_setup_no_dhss_success(self):
        """Driver do_setup without any errors with dhss=False."""

        self.conf.driver_handles_share_servers = False
        self.conf.hpe3par_share_ip_address = constants.EXPECTED_IP_10203040

        self.test_driver_setup_success()

    def test_driver_setup_no_ss_no_ip(self):
        """Configured IP address is required for dhss=False."""

        self.conf.driver_handles_share_servers = False
        self.conf.hpe3par_share_ip_address = None
        self.assertRaises(exception.HPE3ParInvalid,
                          self.driver.do_setup, None)

    def test_driver_with_setup_error(self):
        """Driver do_setup when the mediator setup fails."""

        self.mock_mediator.do_setup.side_effect = (
            exception.ShareBackendException('fail'))

        self.assertRaises(exception.ShareBackendException,
                          self.driver.do_setup, None)

        conf = self.conf
        self.mock_mediator_constructor.assert_has_calls([
            mock.call(hpe3par_san_ssh_port=conf.hpe3par_san_ssh_port,
                      hpe3par_san_password=conf.hpe3par_san_password,
                      hpe3par_username=conf.hpe3par_username,
                      hpe3par_san_login=conf.hpe3par_san_login,
                      hpe3par_debug=conf.hpe3par_debug,
                      hpe3par_api_url=conf.hpe3par_api_url,
                      hpe3par_password=conf.hpe3par_password,
                      hpe3par_san_ip=conf.hpe3par_san_ip,
                      hpe3par_fstore_per_share=conf.hpe3par_fstore_per_share,
                      hpe3par_require_cifs_ip=conf.hpe3par_require_cifs_ip,
                      hpe3par_share_ip_address=(
                          self.conf.hpe3par_share_ip_address),
                      hpe3par_cifs_admin_access_username=(
                          conf.hpe3par_cifs_admin_access_username),
                      hpe3par_cifs_admin_access_password=(
                          conf.hpe3par_cifs_admin_access_password),
                      hpe3par_cifs_admin_access_domain=(
                          conf.hpe3par_cifs_admin_access_domain),
                      hpe3par_share_mount_path=conf.hpe3par_share_mount_path,
                      my_ip=self.conf.my_ip,
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
            mock.call(hpe3par_san_ssh_port=conf.hpe3par_san_ssh_port,
                      hpe3par_san_password=conf.hpe3par_san_password,
                      hpe3par_username=conf.hpe3par_username,
                      hpe3par_san_login=conf.hpe3par_san_login,
                      hpe3par_debug=conf.hpe3par_debug,
                      hpe3par_api_url=conf.hpe3par_api_url,
                      hpe3par_password=conf.hpe3par_password,
                      hpe3par_san_ip=conf.hpe3par_san_ip,
                      hpe3par_fstore_per_share=conf.hpe3par_fstore_per_share,
                      hpe3par_require_cifs_ip=conf.hpe3par_require_cifs_ip,
                      hpe3par_share_ip_address=(
                          self.conf.hpe3par_share_ip_address),
                      hpe3par_cifs_admin_access_username=(
                          conf.hpe3par_cifs_admin_access_username),
                      hpe3par_cifs_admin_access_password=(
                          conf.hpe3par_cifs_admin_access_password),
                      hpe3par_cifs_admin_access_domain=(
                          conf.hpe3par_cifs_admin_access_domain),
                      hpe3par_share_mount_path=conf.hpe3par_share_mount_path,
                      my_ip=self.conf.my_ip,
                      ssh_conn_timeout=conf.ssh_conn_timeout)])

        self.mock_mediator.assert_has_calls([
            mock.call.do_setup(),
            mock.call.get_vfs_name(conf.hpe3par_fpg)])

    def init_driver(self):
        """Simple driver setup for re-use with tests that need one."""

        self.driver._hpe3par = self.mock_mediator
        self.driver.vfs = constants.EXPECTED_VFS
        self.driver.fpg = constants.EXPECTED_FPG
        self.mock_object(hpe3pardriver, 'share_types')
        get_extra_specs = hpe3pardriver.share_types.get_extra_specs_from_share
        get_extra_specs.return_value = constants.EXPECTED_EXTRA_SPECS

    def do_create_share(self, protocol, share_type_id, expected_project_id,
                        expected_share_id, expected_size):
        """Re-usable code for create share."""
        context = None
        share_server = {
            'backend_details': {'ip': constants.EXPECTED_IP_10203040}}
        share = {
            'display_name': constants.EXPECTED_SHARE_NAME,
            'host': constants.EXPECTED_HOST,
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
                                      snapshot_instance,
                                      expected_share_id,
                                      expected_size):
        """Re-usable code for create share from snapshot."""
        context = None
        share_server = {
            'backend_details': {
                'ip': constants.EXPECTED_IP_10203040,
            },
        }
        share = {
            'project_id': constants.EXPECTED_PROJECT_ID,
            'display_name': constants.EXPECTED_SHARE_NAME,
            'host': constants.EXPECTED_HOST,
            'id': expected_share_id,
            'share_proto': protocol,
            'share_type_id': share_type_id,
            'size': expected_size,
        }
        location = self.driver.create_share_from_snapshot(context,
                                                          share,
                                                          snapshot_instance,
                                                          share_server)
        return location

    def test_driver_check_for_setup_error_success(self):
        """check_for_setup_error when things go well."""

        # Generally this is always mocked, but here we reference the class.
        hpe3parmediator.HPE3ParMediator = self.real_hpe_3par_mediator

        self.mock_object(hpe3pardriver, 'LOG')
        self.init_driver()
        self.driver.check_for_setup_error()
        expected_calls = [
            mock.call.debug('HPE3ParShareDriver SHA1: %s', mock.ANY),
            mock.call.debug('HPE3ParMediator SHA1: %s', mock.ANY)
        ]
        hpe3pardriver.LOG.assert_has_calls(expected_calls)

    def test_driver_check_for_setup_error_exception(self):
        """check_for_setup_error catch and log any exceptions."""

        # Since HPE3ParMediator is mocked, we'll hit the except/log.
        self.mock_object(hpe3pardriver, 'LOG')
        self.init_driver()
        self.driver.check_for_setup_error()
        expected_calls = [
            mock.call.debug('HPE3ParShareDriver SHA1: %s', mock.ANY),
            mock.call.debug('Source code SHA1 not logged due to: %s', mock.ANY)
        ]
        hpe3pardriver.LOG.assert_has_calls(expected_calls)

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
            comment=mock.ANY,
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
                                   comment=mock.ANY,
                                   size=constants.EXPECTED_SIZE_1)]

        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_create_cifs_share_from_snapshot(self):
        self.init_driver()

        expected_location = '\\\\%s\%s' % (constants.EXPECTED_IP_10203040,
                                           constants.EXPECTED_SHARE_NAME)

        self.mock_mediator.create_share_from_snapshot.return_value = (
            constants.EXPECTED_SHARE_NAME)

        snapshot_instance = constants.SNAPSHOT_INSTANCE.copy()
        snapshot_instance['protocol'] = constants.CIFS

        location = self.do_create_share_from_snapshot(
            constants.CIFS,
            constants.SHARE_TYPE_ID,
            snapshot_instance,
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
                constants.EXPECTED_SNAP_ID,
                constants.EXPECTED_FPG,
                constants.EXPECTED_VFS,
                comment=mock.ANY),
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
            constants.SNAPSHOT_INSTANCE,
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
                constants.EXPECTED_SNAP_ID,
                constants.EXPECTED_FPG,
                constants.EXPECTED_VFS,
                comment=mock.ANY),
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
                                   constants.EXPECTED_EXTRA_SPECS,
                                   constants.IP,
                                   constants.EXPECTED_IP_1234,
                                   constants.ACCESS_INFO['access_level'],
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
                                  constants.READ_WRITE,
                                  constants.EXPECTED_FPG,
                                  constants.EXPECTED_VFS)
        ]
        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_extend_share(self):
        self.init_driver()

        old_size = constants.NFS_SHARE_INFO['size']
        new_size = old_size * 2

        self.driver.extend_share(constants.NFS_SHARE_INFO, new_size)

        self.mock_mediator.resize_share.assert_called_once_with(
            constants.EXPECTED_PROJECT_ID,
            constants.EXPECTED_SHARE_ID,
            constants.NFS,
            new_size,
            old_size,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS)

    def test_driver_shrink_share(self):
        self.init_driver()

        old_size = constants.NFS_SHARE_INFO['size']
        new_size = old_size / 2

        self.driver.shrink_share(constants.NFS_SHARE_INFO, new_size)

        self.mock_mediator.resize_share.assert_called_once_with(
            constants.EXPECTED_PROJECT_ID,
            constants.EXPECTED_SHARE_ID,
            constants.NFS,
            new_size,
            old_size,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS)

    def test_driver_get_share_stats_not_ready(self):
        """Protect against stats update before driver is ready."""

        self.mock_object(hpe3pardriver, 'LOG')

        expected_result = {
            'driver_handles_share_servers': True,
            'qos': False,
            'driver_version': self.driver.VERSION,
            'free_capacity_gb': 0,
            'max_over_subscription_ratio': None,
            'reserved_percentage': 0,
            'provisioned_capacity_gb': 0,
            'share_backend_name': 'HPE_3PAR',
            'snapshot_support': True,
            'storage_protocol': 'NFS_CIFS',
            'thin_provisioning': True,
            'total_capacity_gb': 0,
            'vendor_name': 'HPE',
            'pools': None,
            'replication_domain': None,
        }

        result = self.driver.get_share_stats(refresh=True)
        self.assertEqual(expected_result, result)

        expected_calls = [
            mock.call.info('Skipping capacity and capabilities update. '
                           'Setup has not completed.')
        ]
        hpe3pardriver.LOG.assert_has_calls(expected_calls)

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
            'hp3par_flash_cache': False,
        }

        expected_result = {
            'driver_handles_share_servers': True,
            'qos': False,
            'driver_version': expected_version,
            'free_capacity_gb': expected_free,
            'max_over_subscription_ratio': None,
            'pools': None,
            'provisioned_capacity_gb': 0,
            'reserved_percentage': 0,
            'share_backend_name': 'HPE_3PAR',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': expected_capacity,
            'vendor_name': 'HPE',
            'thin_provisioning': True,
            'dedupe': False,
            'hpe3par_flash_cache': False,
            'hp3par_flash_cache': False,
            'snapshot_support': True,
            'replication_domain': None,
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
            'qos': False,
            'driver_handles_share_servers': True,
            'driver_version': expected_version,
            'free_capacity_gb': 0,
            'max_over_subscription_ratio': None,
            'pools': None,
            'provisioned_capacity_gb': 0,
            'reserved_percentage': 0,
            'share_backend_name': 'HPE_3PAR',
            'storage_protocol': 'NFS_CIFS',
            'thin_provisioning': True,
            'total_capacity_gb': 0,
            'vendor_name': 'HPE',
            'snapshot_support': True,
            'replication_domain': None,
        }

        result = self.driver.get_share_stats(refresh=True)
        self.assertEqual(expected_result, result)
        self.assertFalse(self.mock_mediator.get_fpg_status.called)

    @ddt.data(('test"dquote', 'test_dquote'),
              ("test'squote", "test_squote"),
              ('test-:;,.punc', 'test-:_punc'),
              ('test with spaces ', 'test with spaces '),
              ('x' * 300, 'x' * 300))
    @ddt.unpack
    def test_build_comment(self, display_name, clean_name):

        host = 'test-stack1@backend#pool'
        share = {
            'host': host,
            'display_name': display_name
        }
        comment = self.driver.build_share_comment(share)

        cleaned = {
            'host': host,
            'clean_name': clean_name
        }

        expected = ("OpenStack Manila - host=%(host)s  "
                    "orig_name=%(clean_name)s created=" % cleaned)[:254]

        self.assertLess(len(comment), 255)
        self.assertTrue(comment.startswith(expected))

        # Test for some chars that are not allowed.
        # Don't test with same regex as the code uses.
        for c in "'\".,;":
            self.assertNotIn(c, comment)

    def test_get_network_allocations_number(self):
        self.assertEqual(1, self.driver.get_network_allocations_number())

    def test_build_export_location_bad_protocol(self):
        self.assertRaises(exception.InvalidInput,
                          self.driver._build_export_location,
                          "BOGUS",
                          constants.EXPECTED_IP_1234,
                          constants.EXPECTED_SHARE_PATH)

    def test_build_export_location_bad_ip(self):
        self.assertRaises(exception.InvalidInput,
                          self.driver._build_export_location,
                          constants.NFS,
                          None,
                          None)

    def test_build_export_location_bad_path(self):
        self.assertRaises(exception.InvalidInput,
                          self.driver._build_export_location,
                          constants.NFS,
                          constants.EXPECTED_IP_1234,
                          None)

    def test_setup_server(self):
        """Setup server by creating a new FSIP."""

        self.init_driver()

        network_info = {
            'network_allocations': [
                {'ip_address': constants.EXPECTED_IP_1234}],
            'cidr': '/'.join((constants.EXPECTED_IP_1234,
                              constants.CIDR_PREFIX)),
            'network_type': constants.EXPECTED_VLAN_TYPE,
            'segmentation_id': constants.EXPECTED_VLAN_TAG,
            'server_id': constants.EXPECTED_SERVER_ID,
        }

        expected_result = {
            'share_server_name': constants.EXPECTED_SERVER_ID,
            'share_server_id': constants.EXPECTED_SERVER_ID,
            'ip': constants.EXPECTED_IP_1234,
            'subnet': constants.EXPECTED_SUBNET,
            'vlantag': constants.EXPECTED_VLAN_TAG,
            'fpg': constants.EXPECTED_FPG,
            'vfs': constants.EXPECTED_VFS,
        }

        result = self.driver._setup_server(network_info)

        expected_calls = [
            mock.call.create_fsip(constants.EXPECTED_IP_1234,
                                  constants.EXPECTED_SUBNET,
                                  constants.EXPECTED_VLAN_TAG,
                                  constants.EXPECTED_FPG,
                                  constants.EXPECTED_VFS)
        ]
        self.mock_mediator.assert_has_calls(expected_calls)

        self.assertEqual(expected_result, result)

    def test_teardown_server(self):

        self.init_driver()

        server_details = {
            'ip': constants.EXPECTED_IP_1234,
            'fpg': constants.EXPECTED_FPG,
            'vfs': constants.EXPECTED_VFS,
        }

        self.driver._teardown_server(server_details)

        expected_calls = [
            mock.call.remove_fsip(constants.EXPECTED_IP_1234,
                                  constants.EXPECTED_FPG,
                                  constants.EXPECTED_VFS)
        ]
        self.mock_mediator.assert_has_calls(expected_calls)
