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

from copy import deepcopy
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
class HPE3ParDriverFPGTestCase(test.TestCase):

    @ddt.data((-1, 4),
              (0, 5),
              (0, -1))
    @ddt.unpack
    def test_FPG_init_args_failure(self, min_ip, max_ip):
        self.assertRaises(exception.HPE3ParInvalid,
                          hpe3pardriver.FPG, min_ip, max_ip)

    @ddt.data(('invalid_ip_fpg, 10.256.0.1', 0, 4),
              (None, 0, 4),
              (' ', 0, 4),
              ('', 0, 4),
              ('max_ip_fpg, 10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5',
              0, 4),
              ('min_1_ip_fpg', 1, 4))
    @ddt.unpack
    def test_FPG_type_failures(self, value, min_ip, max_ip):
        fpg_type_obj = hpe3pardriver.FPG(min_ip=min_ip, max_ip=max_ip)
        self.assertRaises(exception.HPE3ParInvalid, fpg_type_obj, value)

    @ddt.data(('samplefpg, 10.0.0.1', {'samplefpg': ['10.0.0.1']}),
              ('samplefpg', {'samplefpg': []}),
              ('samplefpg, 10.0.0.1, 10.0.0.2',
               {'samplefpg': ['10.0.0.1', '10.0.0.2']}))
    @ddt.unpack
    def test_FPG_type_success(self, value, expected_fpg):
        fpg_type_obj = hpe3pardriver.FPG()
        fpg = fpg_type_obj(value)
        self.assertEqual(expected_fpg, fpg)


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
        self.conf.hpe3par_fpg = constants.EXPECTED_FPG_CONF
        self.conf.hpe3par_san_ssh_port = constants.PORT
        self.conf.ssh_conn_timeout = constants.TIMEOUT
        self.conf.hpe3par_fstore_per_share = False
        self.conf.hpe3par_require_cifs_ip = False
        self.conf.hpe3par_cifs_admin_access_username = constants.USERNAME,
        self.conf.hpe3par_cifs_admin_access_password = constants.PASSWORD,
        self.conf.hpe3par_cifs_admin_access_domain = (
            constants.EXPECTED_CIFS_DOMAIN),
        self.conf.hpe3par_share_mount_path = constants.EXPECTED_MOUNT_PATH,
        self.conf.my_ip = constants.EXPECTED_IP_1234
        self.conf.network_config_group = 'test_network_config_group'
        self.conf.admin_network_config_group = (
            'test_admin_network_config_group')
        self.conf.filter_function = None
        self.conf.goodness_function = None

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
        # restore needed static methods
        self.mock_mediator.ensure_supported_protocol = (
            self.real_hpe_3par_mediator.ensure_supported_protocol)
        self.mock_mediator.build_export_locations = (
            self.real_hpe_3par_mediator.build_export_locations)

        self.driver = hpe3pardriver.HPE3ParShareDriver(
            configuration=self.conf)

    def test_driver_setup_success(self,
                                  get_vfs_ret_val=constants.EXPECTED_GET_VFS):
        """Driver do_setup without any errors."""

        self.mock_mediator.get_vfs.return_value = get_vfs_ret_val

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
            mock.call.get_vfs(constants.EXPECTED_FPG)])

    def test_driver_setup_dhss_success(self):
        """Driver do_setup without any errors with dhss=True."""

        self.test_driver_setup_success()
        self.assertEqual(constants.EXPECTED_FPG_MAP, self.driver.fpgs)

    def test_driver_setup_no_dhss_success(self):
        """Driver do_setup without any errors with dhss=False."""

        self.conf.driver_handles_share_servers = False
        self.test_driver_setup_success()
        self.assertEqual(constants.EXPECTED_FPG_MAP, self.driver.fpgs)

    def test_driver_setup_no_dhss_multi_getvfs_success(self):
        """Driver do_setup when dhss=False, getvfs returns multiple IPs."""

        self.conf.driver_handles_share_servers = False
        self.test_driver_setup_success(
            get_vfs_ret_val=constants.EXPECTED_GET_VFS_MULTIPLES)
        self.assertEqual(constants.EXPECTED_FPG_MAP,
                         self.driver.fpgs)

    def test_driver_setup_success_no_dhss_no_conf_ss_ip(self):
        """test driver's do_setup()

        Driver do_setup with dhss=False, share server ip not set in config file
        but discoverable at 3par array
        """

        self.conf.driver_handles_share_servers = False
        # ss ip not provided in conf
        original_fpg = deepcopy(self.conf.hpe3par_fpg)
        self.conf.hpe3par_fpg[0][constants.EXPECTED_FPG] = []

        self.test_driver_setup_success()

        self.assertEqual(constants.EXPECTED_FPG_MAP, self.driver.fpgs)
        constants.EXPECTED_FPG_CONF = original_fpg

    def test_driver_setup_failure_no_dhss_no_conf_ss_ip(self):
        """Configured IP address is required for dhss=False."""

        self.conf.driver_handles_share_servers = False
        # ss ip not provided in conf
        fpg_without_ss_ip = deepcopy(self.conf.hpe3par_fpg)
        self.conf.hpe3par_fpg[0][constants.EXPECTED_FPG] = []
        # ss ip not configured on array
        vfs_without_ss_ip = deepcopy(constants.EXPECTED_GET_VFS)
        vfs_without_ss_ip['vfsip']['address'] = []
        self.mock_mediator.get_vfs.return_value = vfs_without_ss_ip

        self.assertRaises(exception.HPE3ParInvalid,
                          self.driver.do_setup, None)
        constants.EXPECTED_FPG_CONF = fpg_without_ss_ip

    def test_driver_setup_mediator_error(self):
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

    def test_driver_setup_with_vfs_error(self):
        """Driver do_setup when the get_vfs fails."""

        self.mock_mediator.get_vfs.side_effect = (
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
            mock.call.get_vfs(constants.EXPECTED_FPG)])

    def test_driver_setup_conf_ips_validation_fails(self):
        """Driver do_setup when the _validate_pool_ips fails."""

        self.conf.driver_handles_share_servers = False
        vfs_with_ss_ip = deepcopy(constants.EXPECTED_GET_VFS)
        vfs_with_ss_ip['vfsip']['address'] = ['10.100.100.100']
        self.mock_mediator.get_vfs.return_value = vfs_with_ss_ip
        self.assertRaises(exception.HPE3ParInvalid,
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
            mock.call.get_vfs(constants.EXPECTED_FPG)])

    def init_driver(self):
        """Simple driver setup for re-use with tests that need one."""

        self.driver._hpe3par = self.mock_mediator
        self.driver.fpgs = constants.EXPECTED_FPG_MAP
        self.mock_object(hpe3pardriver, 'share_types')
        get_extra_specs = hpe3pardriver.share_types.get_extra_specs_from_share
        get_extra_specs.return_value = constants.EXPECTED_EXTRA_SPECS

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

    @ddt.data(([constants.SHARE_SERVER], constants.SHARE_SERVER),
              ([], None),)
    @ddt.unpack
    def test_choose_share_server_compatible_with_share(self, share_servers,
                                                       expected_share_sever):
        context = None
        share_server = self.driver.choose_share_server_compatible_with_share(
            context,
            share_servers,
            constants.NFS_SHARE_INFO,
            None,
            None)

        self.assertEqual(expected_share_sever, share_server)

    def test_choose_share_server_compatible_with_share_with_cg(self):
        context = None
        cg_ref = {'id': 'dummy'}
        self.assertRaises(
            exception.InvalidRequest,
            self.driver.choose_share_server_compatible_with_share,
            context,
            [constants.SHARE_SERVER],
            constants.NFS_SHARE_INFO,
            None,
            cg_ref)

    def do_create_share(self, protocol, share_type_id, expected_project_id,
                        expected_share_id, expected_size):
        """Re-usable code for create share."""
        context = None

        share = {
            'display_name': constants.EXPECTED_SHARE_NAME,
            'host': constants.EXPECTED_HOST,
            'project_id': expected_project_id,
            'id': expected_share_id,
            'share_proto': protocol,
            'share_type_id': share_type_id,
            'size': expected_size,
        }
        location = self.driver.create_share(context, share,
                                            constants.SHARE_SERVER)
        return location

    def do_create_share_from_snapshot(self,
                                      protocol,
                                      share_type_id,
                                      snapshot_instance,
                                      expected_share_id,
                                      expected_size):
        """Re-usable code for create share from snapshot."""
        context = None
        share = {
            'project_id': constants.EXPECTED_PROJECT_ID,
            'display_name': constants.EXPECTED_SHARE_NAME,
            'host': constants.EXPECTED_HOST,
            'id': expected_share_id,
            'share_proto': protocol,
            'share_type_id': share_type_id,
            'size': expected_size,
        }
        location = self.driver.create_share_from_snapshot(
            context,
            share,
            snapshot_instance,
            constants.SHARE_SERVER)
        return location

    @ddt.data((constants.UNEXPECTED_HOST, exception.InvalidHost),
              (constants.HOST_WITHOUT_POOL_1, exception.InvalidHost),
              (constants.HOST_WITHOUT_POOL_2, exception.InvalidHost))
    @ddt.unpack
    def test_driver_create_share_fails_get_pool_location(self, host,
                                                         expected_exception):
        """get_pool_location fails to extract pool name from host"""
        self.init_driver()
        context = None
        share_server = None
        share = {
            'display_name': constants.EXPECTED_SHARE_NAME,
            'host': host,
            'project_id': constants.EXPECTED_PROJECT_ID,
            'id': constants.EXPECTED_SHARE_ID,
            'share_proto': constants.CIFS,
            'share_type_id': constants.SHARE_TYPE_ID,
            'size': constants.EXPECTED_SIZE_2,
        }
        self.assertRaises(expected_exception,
                          self.driver.create_share,
                          context, share, share_server)

    def test_driver_create_cifs_share(self):
        self.init_driver()

        expected_location = '\\\\%s\%s' % (constants.EXPECTED_IP_10203040,
                                           constants.EXPECTED_SHARE_NAME)

        self.mock_mediator.create_share.return_value = (
            constants.EXPECTED_SHARE_NAME)

        hpe3parmediator.HPE3ParMediator = self.real_hpe_3par_mediator

        location = self.do_create_share(constants.CIFS,
                                        constants.SHARE_TYPE_ID,
                                        constants.EXPECTED_PROJECT_ID,
                                        constants.EXPECTED_SHARE_ID,
                                        constants.EXPECTED_SIZE_2)

        self.assertIn(expected_location, location)
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
        hpe3parmediator.HPE3ParMediator = self.real_hpe_3par_mediator

        location = self.do_create_share(constants.NFS,
                                        constants.SHARE_TYPE_ID,
                                        constants.EXPECTED_PROJECT_ID,
                                        constants.EXPECTED_SHARE_ID,
                                        constants.EXPECTED_SIZE_1)

        self.assertIn(expected_location, location)
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
        hpe3parmediator.HPE3ParMediator = self.real_hpe_3par_mediator

        snapshot_instance = constants.SNAPSHOT_INSTANCE.copy()
        snapshot_instance['protocol'] = constants.CIFS

        location = self.do_create_share_from_snapshot(
            constants.CIFS,
            constants.SHARE_TYPE_ID,
            snapshot_instance,
            constants.EXPECTED_SHARE_ID,
            constants.EXPECTED_SIZE_2)

        self.assertIn(expected_location, location)
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
                [constants.EXPECTED_IP_10203040],
                comment=mock.ANY,
                size=constants.EXPECTED_SIZE_2),
        ]
        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_create_nfs_share_from_snapshot(self):
        self.init_driver()

        expected_location = ':'.join((constants.EXPECTED_IP_10203040,
                                      constants.EXPECTED_SHARE_PATH))

        self.mock_mediator.create_share_from_snapshot.return_value = (
            constants.EXPECTED_SHARE_PATH)
        hpe3parmediator.HPE3ParMediator = self.real_hpe_3par_mediator

        location = self.do_create_share_from_snapshot(
            constants.NFS,
            constants.SHARE_TYPE_ID,
            constants.SNAPSHOT_INSTANCE,
            constants.EXPECTED_SHARE_ID,
            constants.EXPECTED_SIZE_1)

        self.assertIn(expected_location, location)
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
                [constants.EXPECTED_IP_10203040],
                comment=mock.ANY,
                size=constants.EXPECTED_SIZE_1),
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
            'host': constants.EXPECTED_HOST
        }

        self.driver.delete_share(context, share, share_server)

        expected_calls = [
            mock.call.delete_share(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.EXPECTED_SIZE_1,
                                   constants.CIFS,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_IP_10203040)]

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

    def test_driver_update_access_add_rule(self):
        self.init_driver()

        context = None

        self.driver.update_access(context,
                                  constants.NFS_SHARE_INFO,
                                  [constants.ACCESS_RULE_NFS],
                                  [constants.ADD_RULE_IP],
                                  [],
                                  constants.SHARE_SERVER)

        expected_calls = [
            mock.call.update_access(constants.EXPECTED_PROJECT_ID,
                                    constants.EXPECTED_SHARE_ID,
                                    constants.NFS,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_NFS],
                                    [constants.ADD_RULE_IP],
                                    [],
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)
        ]
        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_update_access_delete_rule(self):
        self.init_driver()

        context = None

        self.driver.update_access(context,
                                  constants.NFS_SHARE_INFO,
                                  [constants.ACCESS_RULE_NFS],
                                  [],
                                  [constants.DELETE_RULE_IP],
                                  constants.SHARE_SERVER)

        expected_calls = [
            mock.call.update_access(constants.EXPECTED_PROJECT_ID,
                                    constants.EXPECTED_SHARE_ID,
                                    constants.NFS,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_NFS],
                                    [],
                                    [constants.DELETE_RULE_IP],
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)
        ]
        self.mock_mediator.assert_has_calls(expected_calls)

    def test_driver_extend_share(self):
        self.init_driver()

        old_size = constants.NFS_SHARE_INFO['size']
        new_size = old_size * 2

        share_server = None
        self.driver.extend_share(constants.NFS_SHARE_INFO,
                                 new_size, share_server)

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
        share_server = None
        self.driver.shrink_share(constants.NFS_SHARE_INFO,
                                 new_size, share_server)

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
            'create_share_from_snapshot_support': True,
            'revert_to_snapshot_support': False,
            'mount_snapshot_support': False,
            'share_group_stats': {
                'consistent_snapshot_support': None,
            },
            'storage_protocol': 'NFS_CIFS',
            'thin_provisioning': True,
            'total_capacity_gb': 0,
            'vendor_name': 'HPE',
            'pools': None,
            'replication_domain': None,
            'filter_function': None,
            'goodness_function': None,
            'ipv4_support': True,
            'ipv6_support': False,
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
            'pool_name': constants.EXPECTED_FPG,
            'total_capacity_gb': expected_capacity,
            'free_capacity_gb': expected_free,
            'thin_provisioning': True,
            'dedupe': False,
            'hpe3par_flash_cache': False,
            'hp3par_flash_cache': False,
            'reserved_percentage': 0,
            'provisioned_capacity_gb': expected_capacity
        }

        expected_result = {
            'share_backend_name': 'HPE_3PAR',
            'vendor_name': 'HPE',
            'driver_version': expected_version,
            'storage_protocol': 'NFS_CIFS',
            'driver_handles_share_servers': True,
            'total_capacity_gb': 0,
            'free_capacity_gb': 0,
            'provisioned_capacity_gb': 0,
            'reserved_percentage': 0,
            'max_over_subscription_ratio': None,
            'qos': False,
            'thin_provisioning': True,
            'pools': [{
                'pool_name': constants.EXPECTED_FPG,
                'total_capacity_gb': expected_capacity,
                'free_capacity_gb': expected_free,
                'thin_provisioning': True,
                'dedupe': False,
                'hpe3par_flash_cache': False,
                'hp3par_flash_cache': False,
                'reserved_percentage': 0,
                'provisioned_capacity_gb': expected_capacity}],
            'snapshot_support': True,
            'create_share_from_snapshot_support': True,
            'revert_to_snapshot_support': False,
            'mount_snapshot_support': False,
            'share_group_stats': {
                'consistent_snapshot_support': None,
            },
            'replication_domain': None,
            'filter_function': None,
            'goodness_function': None,
            'ipv4_support': True,
            'ipv6_support': False,
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
            'create_share_from_snapshot_support': True,
            'revert_to_snapshot_support': False,
            'mount_snapshot_support': False,
            'share_group_stats': {
                'consistent_snapshot_support': None,
            },
            'replication_domain': None,
            'filter_function': None,
            'goodness_function': None,
            'ipv4_support': True,
            'ipv6_support': False,
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
        metadata = {'request_host': constants.EXPECTED_HOST}
        result = self.driver._setup_server(network_info, metadata)

        expected_calls = [
            mock.call.create_fsip(constants.EXPECTED_IP_1234,
                                  constants.EXPECTED_SUBNET,
                                  constants.EXPECTED_VLAN_TAG,
                                  constants.EXPECTED_FPG,
                                  constants.EXPECTED_VFS)
        ]
        self.mock_mediator.assert_has_calls(expected_calls)

        self.assertEqual(expected_result, result)

    def test_setup_server_fails_for_unsupported_network_type(self):
        """Setup server fails for unsupported network type"""

        self.init_driver()

        network_info = {
            'network_allocations': [
                {'ip_address': constants.EXPECTED_IP_1234}],
            'cidr': '/'.join((constants.EXPECTED_IP_1234,
                              constants.CIDR_PREFIX)),
            'network_type': constants.EXPECTED_VXLAN_TYPE,
            'segmentation_id': constants.EXPECTED_VLAN_TAG,
            'server_id': constants.EXPECTED_SERVER_ID,
        }
        metadata = {'request_host': constants.EXPECTED_HOST}

        self.assertRaises(exception.NetworkBadConfigurationException,
                          self.driver._setup_server,
                          network_info, metadata)

    def test_setup_server_fails_for_exceed_pool_max_supported_ips(self):
        """Setup server fails when the VFS has reached max supported IPs"""

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
        metadata = {'request_host': constants.EXPECTED_HOST}

        expected_vfs = self.driver.fpgs[
            constants.EXPECTED_FPG][constants.EXPECTED_VFS]
        self.driver.fpgs[constants.EXPECTED_FPG][constants.EXPECTED_VFS] = [
            '10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']

        self.assertRaises(exception.Invalid,
                          self.driver._setup_server,
                          network_info, metadata)
        self.driver.fpgs[constants.EXPECTED_FPG][constants.EXPECTED_VFS
                                                 ] = expected_vfs

    def test_teardown_server(self):
        """Test tear down server"""

        self.init_driver()

        server_details = {
            'ip': constants.EXPECTED_IP_10203040,
            'fpg': constants.EXPECTED_FPG,
            'vfs': constants.EXPECTED_VFS,
        }

        self.driver._teardown_server(server_details)

        expected_calls = [
            mock.call.remove_fsip(constants.EXPECTED_IP_10203040,
                                  constants.EXPECTED_FPG,
                                  constants.EXPECTED_VFS)
        ]
        self.mock_mediator.assert_has_calls(expected_calls)
