# Copyright (c) 2015 Cloudbase Solutions SRL
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

import os

import ddt
import mock
from oslo_concurrency import processutils
from oslo_config import cfg

from manila import exception
from manila.share import configuration
from manila.share.drivers import service_instance as generic_service_instance
from manila.share.drivers.windows import service_instance
from manila.share.drivers.windows import windows_utils
from manila import test

CONF = cfg.CONF
CONF.import_opt('driver_handles_share_servers',
                'manila.share.driver')
CONF.register_opts(generic_service_instance.common_opts)

serv_mgr_cls = service_instance.WindowsServiceInstanceManager
generic_serv_mgr_cls = generic_service_instance.ServiceInstanceManager


@ddt.ddt
class WindowsServiceInstanceManagerTestCase(test.TestCase):
    _FAKE_SERVER = {'ip': mock.sentinel.ip,
                    'instance_id': mock.sentinel.instance_id}

    @mock.patch.object(windows_utils, 'WindowsUtils')
    @mock.patch.object(serv_mgr_cls, '_check_auth_mode')
    def setUp(self, mock_check_auth, mock_utils_cls):
        self.flags(service_instance_user=mock.sentinel.username)
        self._remote_execute = mock.Mock()

        fake_conf = configuration.Configuration(None)
        self._mgr = serv_mgr_cls(remote_execute=self._remote_execute,
                                 driver_config=fake_conf)
        self._windows_utils = mock_utils_cls.return_value
        super(WindowsServiceInstanceManagerTestCase, self).setUp()

    @ddt.data({},
              {'use_cert_auth': False},
              {'use_cert_auth': False, 'valid_pass_complexity': False},
              {'certs_exist': False})
    @mock.patch('os.path.exists')
    @mock.patch.object(serv_mgr_cls, '_check_password_complexity')
    @ddt.unpack
    def test_check_auth_mode(self, mock_check_complexity, mock_path_exists,
                             use_cert_auth=True, certs_exist=True,
                             valid_pass_complexity=True):
        self.flags(service_instance_password=mock.sentinel.password)
        self._mgr._cert_pem_path = mock.sentinel.cert_path
        self._mgr._cert_key_pem_path = mock.sentinel.key_path
        mock_path_exists.return_value = certs_exist
        mock_check_complexity.return_value = valid_pass_complexity

        self._mgr._use_cert_auth = use_cert_auth

        invalid_auth = ((use_cert_auth and not certs_exist)
                        or not valid_pass_complexity)

        if invalid_auth:
            self.assertRaises(exception.ServiceInstanceException,
                              self._mgr._check_auth_mode)
        else:
            self._mgr._check_auth_mode()

        if not use_cert_auth:
            mock_check_complexity.assert_called_once_with(
                mock.sentinel.password)

    @ddt.data(False, True)
    def test_get_auth_info(self, use_cert_auth):
        self._mgr._use_cert_auth = use_cert_auth
        self._mgr._cert_pem_path = mock.sentinel.cert_path
        self._mgr._cert_key_pem_path = mock.sentinel.key_path

        auth_info = self._mgr._get_auth_info()

        expected_auth_info = {'use_cert_auth': use_cert_auth}
        if use_cert_auth:
            expected_auth_info.update(cert_pem_path=mock.sentinel.cert_path,
                                      cert_key_pem_path=mock.sentinel.key_path)

        self.assertEqual(expected_auth_info, auth_info)

    @mock.patch.object(serv_mgr_cls, '_get_auth_info')
    @mock.patch.object(generic_serv_mgr_cls, 'get_common_server')
    def test_common_server(self, mock_generic_get_server, mock_get_auth):
        mock_server_details = {'backend_details': {}}
        mock_auth_info = {'fake_auth_info': mock.sentinel.auth_info}

        mock_generic_get_server.return_value = mock_server_details
        mock_get_auth.return_value = mock_auth_info
        expected_server_details = dict(backend_details=mock_auth_info)

        server_details = self._mgr.get_common_server()

        mock_generic_get_server.assert_called_once_with()
        self.assertEqual(expected_server_details, server_details)

    @mock.patch.object(serv_mgr_cls, '_get_auth_info')
    @mock.patch.object(generic_serv_mgr_cls, '_get_new_instance_details')
    def test_get_new_instance_details(self, mock_generic_get_details,
                                      mock_get_auth):
        mock_server_details = {'fake_server_details':
                               mock.sentinel.server_details}
        mock_generic_get_details.return_value = mock_server_details
        mock_auth_info = {'fake_auth_info': mock.sentinel.auth_info}
        mock_get_auth.return_value = mock_auth_info

        expected_server_details = dict(mock_server_details, **mock_auth_info)
        instance_details = self._mgr._get_new_instance_details(
            server=mock.sentinel.server)

        mock_generic_get_details.assert_called_once_with(mock.sentinel.server)
        self.assertEqual(expected_server_details, instance_details)

    @ddt.data(('abAB01', True),
              ('abcdef', False),
              ('aA0', False))
    @ddt.unpack
    def test_check_password_complexity(self, password, expected_result):
        valid_complexity = self._mgr._check_password_complexity(
            password)
        self.assertEqual(expected_result, valid_complexity)

    @ddt.data(None, Exception)
    def test_server_connection(self, side_effect):
        self._remote_execute.side_effect = side_effect

        expected_result = side_effect is None
        is_available = self._mgr._test_server_connection(self._FAKE_SERVER)

        self.assertEqual(expected_result, is_available)
        self._remote_execute.assert_called_once_with(self._FAKE_SERVER,
                                                     "whoami",
                                                     retry=False)

    @ddt.data(False, True)
    def test_get_service_instance_create_kwargs(self, use_cert_auth):
        self._mgr._use_cert_auth = use_cert_auth
        self.flags(service_instance_password=mock.sentinel.admin_pass)

        if use_cert_auth:
            mock_cert_data = 'mock_cert_data'
            self.mock_object(service_instance, 'open',
                             mock.mock_open(
                                 read_data=mock_cert_data))
            expected_kwargs = dict(user_data=mock_cert_data)
        else:
            expected_kwargs = dict(
                meta=dict(admin_pass=mock.sentinel.admin_pass))

        create_kwargs = self._mgr._get_service_instance_create_kwargs()

        self.assertEqual(expected_kwargs, create_kwargs)

    @mock.patch.object(generic_serv_mgr_cls, 'set_up_service_instance')
    @mock.patch.object(serv_mgr_cls, 'get_valid_security_service')
    @mock.patch.object(serv_mgr_cls, '_setup_security_service')
    def test_set_up_service_instance(self, mock_setup_security_service,
                                     mock_get_valid_security_service,
                                     mock_generic_setup_serv_inst):
        mock_service_instance = {'instance_details': None}
        mock_network_info = {'security_services':
                             mock.sentinel.security_services}

        mock_generic_setup_serv_inst.return_value = mock_service_instance
        mock_get_valid_security_service.return_value = (
            mock.sentinel.security_service)

        instance_details = self._mgr.set_up_service_instance(
            mock.sentinel.context, mock_network_info)

        mock_generic_setup_serv_inst.assert_called_once_with(
            mock.sentinel.context, mock_network_info)
        mock_get_valid_security_service.assert_called_once_with(
            mock.sentinel.security_services)

        mock_setup_security_service.assert_called_once_with(
            mock_service_instance, mock.sentinel.security_service)

        expected_instance_details = dict(mock_service_instance,
                                         joined_domain=True)
        self.assertEqual(expected_instance_details,
                         instance_details)

    @mock.patch.object(serv_mgr_cls, '_run_cloudbase_init_plugin_after_reboot')
    @mock.patch.object(serv_mgr_cls, '_join_domain')
    def test_setup_security_service(self, mock_join_domain,
                                    mock_run_cbsinit_plugin):
        utils = self._windows_utils
        mock_security_service = {'domain': mock.sentinel.domain,
                                 'user': mock.sentinel.admin_username,
                                 'password': mock.sentinel.admin_password,
                                 'dns_ip': mock.sentinel.dns_ip}
        utils.get_interface_index_by_ip.return_value = (
            mock.sentinel.interface_index)

        self._mgr._setup_security_service(self._FAKE_SERVER,
                                          mock_security_service)

        utils.set_dns_client_search_list.assert_called_once_with(
            self._FAKE_SERVER,
            [mock_security_service['domain']])
        utils.get_interface_index_by_ip.assert_called_once_with(
            self._FAKE_SERVER,
            self._FAKE_SERVER['ip'])
        utils.set_dns_client_server_addresses.assert_called_once_with(
            self._FAKE_SERVER,
            mock.sentinel.interface_index,
            [mock_security_service['dns_ip']])
        mock_run_cbsinit_plugin.assert_called_once_with(
            self._FAKE_SERVER,
            plugin_name=self._mgr._CBS_INIT_WINRM_PLUGIN)
        mock_join_domain.assert_called_once_with(
            self._FAKE_SERVER,
            mock.sentinel.domain,
            mock.sentinel.admin_username,
            mock.sentinel.admin_password)

    @ddt.data({'join_domain_side_eff': Exception},
              {'server_available': False,
               'expected_exception': exception.ServiceInstanceException},
              {'join_domain_side_eff': processutils.ProcessExecutionError,
               'expected_exception': processutils.ProcessExecutionError},
              {'domain_mismatch': True,
               'expected_exception': exception.ServiceInstanceException})
    @mock.patch.object(generic_serv_mgr_cls, 'reboot_server')
    @mock.patch.object(generic_serv_mgr_cls, 'wait_for_instance_to_be_active')
    @mock.patch.object(generic_serv_mgr_cls, '_check_server_availability')
    @ddt.unpack
    def test_join_domain(self, mock_check_avail,
                         mock_wait_instance_active,
                         mock_reboot_server,
                         expected_exception=None,
                         server_available=True,
                         domain_mismatch=False,
                         join_domain_side_eff=None):
        self._windows_utils.join_domain.side_effect = join_domain_side_eff
        mock_check_avail.return_value = server_available
        self._windows_utils.get_current_domain.return_value = (
            None if domain_mismatch else mock.sentinel.domain)
        domain_params = (mock.sentinel.domain,
                         mock.sentinel.admin_username,
                         mock.sentinel.admin_password)

        if expected_exception:
            self.assertRaises(expected_exception,
                              self._mgr._join_domain,
                              self._FAKE_SERVER,
                              *domain_params)
        else:
            self._mgr._join_domain(self._FAKE_SERVER,
                                   *domain_params)

        if join_domain_side_eff != processutils.ProcessExecutionError:
            mock_reboot_server.assert_called_once_with(
                self._FAKE_SERVER, soft_reboot=True)
            mock_wait_instance_active.assert_called_once_with(
                self._FAKE_SERVER['instance_id'],
                timeout=self._mgr.max_time_to_build_instance)
            mock_check_avail.assert_called_once_with(self._FAKE_SERVER)
            if server_available:
                self._windows_utils.get_current_domain.assert_called_once_with(
                    self._FAKE_SERVER)

        self._windows_utils.join_domain.assert_called_once_with(
            self._FAKE_SERVER,
            *domain_params)

    @ddt.data([],
              [{'type': 'active_directory'}],
              [{'type': 'active_directory'}] * 2,
              [{'type': mock.sentinel.invalid_type}])
    def test_get_valid_security_service(self, security_services):
        valid_security_service = self._mgr.get_valid_security_service(
            security_services)

        if (security_services and len(security_services) == 1 and
                security_services[0]['type'] == 'active_directory'):
            expected_valid_sec_service = security_services[0]
        else:
            expected_valid_sec_service = None

        self.assertEqual(expected_valid_sec_service,
                         valid_security_service)

    @mock.patch.object(serv_mgr_cls, '_get_cbs_init_reg_section')
    def test_run_cloudbase_init_plugin_after_reboot(self,
                                                    mock_get_cbs_init_reg):
        self._FAKE_SERVER = {'instance_id': mock.sentinel.instance_id}
        mock_get_cbs_init_reg.return_value = mock.sentinel.cbs_init_reg_sect
        expected_plugin_key_path = "%(cbs_init)s\\%(instance_id)s\\Plugins" % {
            'cbs_init': mock.sentinel.cbs_init_reg_sect,
            'instance_id': self._FAKE_SERVER['instance_id']}

        self._mgr._run_cloudbase_init_plugin_after_reboot(
            server=self._FAKE_SERVER,
            plugin_name=mock.sentinel.plugin_name)

        mock_get_cbs_init_reg.assert_called_once_with(self._FAKE_SERVER)
        self._windows_utils.set_win_reg_value.assert_called_once_with(
            self._FAKE_SERVER,
            path=expected_plugin_key_path,
            key=mock.sentinel.plugin_name,
            value=self._mgr._CBS_INIT_RUN_PLUGIN_AFTER_REBOOT)

    @ddt.data(
        {},
        {'exec_errors': [
            processutils.ProcessExecutionError(stderr='Cannot find path'),
            processutils.ProcessExecutionError(stderr='Cannot find path')],
         'expected_exception': exception.ServiceInstanceException},
        {'exec_errors': [processutils.ProcessExecutionError(stderr='')],
         'expected_exception': processutils.ProcessExecutionError},
        {'exec_errors': [
            processutils.ProcessExecutionError(stderr='Cannot find path'),
            None]}
    )
    @ddt.unpack
    def test_get_cbs_init_reg_section(self, exec_errors=None,
                                      expected_exception=None):
        self._windows_utils.normalize_path.return_value = (
            mock.sentinel.normalized_section_path)
        self._windows_utils.get_win_reg_value.side_effect = exec_errors

        if expected_exception:
            self.assertRaises(expected_exception,
                              self._mgr._get_cbs_init_reg_section,
                              mock.sentinel.server)
        else:
            cbs_init_section = self._mgr._get_cbs_init_reg_section(
                mock.sentinel.server)
            self.assertEqual(mock.sentinel.normalized_section_path,
                             cbs_init_section)

        base_path = 'hklm:\\SOFTWARE'
        cbs_section = 'Cloudbase Solutions\\Cloudbase-Init'
        tested_upper_sections = ['']

        if exec_errors and 'Cannot find path' in exec_errors[0].stderr:
            tested_upper_sections.append('Wow6432Node')

        tested_sections = [os.path.join(base_path,
                                        upper_section,
                                        cbs_section)
                           for upper_section in tested_upper_sections]
        self._windows_utils.normalize_path.assert_has_calls(
            [mock.call(tested_section)
             for tested_section in tested_sections])
