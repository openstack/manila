# Copyright (c) 2021 NetApp, Inc.
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
"""Unit tests for the Security Service helper module."""

from unittest import mock

import ddt

from manila import exception
from manila.share import configuration
from manila.share.drivers.container import security_service_helper
from manila import test
from manila.tests import db_utils


INVALID_CREDENTIALS_EXIT_CODE = 49


@ddt.ddt
class SecurityServiceHelperTestCase(test.TestCase):
    """Tests DockerExecHelper"""

    def setUp(self):
        super(SecurityServiceHelperTestCase, self).setUp()
        self.fake_conf = configuration.Configuration(None)
        self.fake_conf.container_image_name = "fake_image"
        self.fake_conf.container_volume_mount_path = "/tmp/shares"
        self.security_service_helper = (
            security_service_helper.SecurityServiceHelper(
                configuration=self.fake_conf))

    def test_setup_security_service(self):
        share_server = db_utils.create_share_server()
        security_service = db_utils.create_security_service()

        mock_ldap_bind = self.mock_object(
            self.security_service_helper, 'ldap_bind')

        self.security_service_helper.setup_security_service(
            share_server['id'], security_service)

        mock_ldap_bind.assert_called_once_with(
            share_server['id'], security_service)

    def test_update_security_service(self):
        share_server = db_utils.create_share_server()
        current_security_service = db_utils.create_security_service()
        new_security_service = db_utils.create_security_service()

        mock_ldap_bind = self.mock_object(
            self.security_service_helper, 'ldap_bind')

        self.security_service_helper.update_security_service(
            share_server['id'], current_security_service, new_security_service)

        mock_ldap_bind.assert_called_once_with(
            share_server['id'], new_security_service)

    def _setup_test_ldap_bind_tests(self):
        share_server = db_utils.create_security_service()
        security_service = db_utils.create_security_service()
        ldap_get_info = {
            'ss_password': security_service['password'],
            'ss_user': security_service['user']
        }
        expected_cmd = [
            "docker", "exec", "%s" % share_server['id'], "ldapwhoami", "-x",
            "-H", "ldap://localhost:389", "-D",
                              "cn=%s,dc=example,dc=com" % ldap_get_info[
                                  "ss_user"],
            "-w", "%s" % ldap_get_info["ss_password"]]

        return share_server, security_service, ldap_get_info, expected_cmd

    def test_ldap_bind(self):
        share_server, security_service, ldap_get_info, expected_cmd = (
            self._setup_test_ldap_bind_tests())

        mock_ldap_get_info = self.mock_object(
            self.security_service_helper, 'ldap_get_info',
            mock.Mock(return_value=ldap_get_info))
        mock_ldap_retry_operation = self.mock_object(
            self.security_service_helper, 'ldap_retry_operation')

        self.security_service_helper.ldap_bind(
            share_server['id'], security_service)

        mock_ldap_get_info.assert_called_once_with(security_service)
        mock_ldap_retry_operation.assert_called_once_with(expected_cmd,
                                                          run_as_root=True)

    def test_ldap_get_info(self):
        security_service = db_utils.create_security_service()
        expected_ldap_get_info = {
            'ss_password': security_service['password'],
            'ss_user': security_service['user']
        }

        ldap_get_info = self.security_service_helper.ldap_get_info(
            security_service)

        self.assertEqual(expected_ldap_get_info, ldap_get_info)

    @ddt.data(
        {'type': 'ldap'},
        {'user': 'fake_user'},
        {'password': 'fake_password'},
    )
    def test_ldap_get_info_exception(self, sec_service_data):
        self.assertRaises(
            exception.ShareBackendException,
            self.security_service_helper.ldap_get_info,
            sec_service_data
        )

    def test_ldap_retry_operation(self):
        mock_cmd = ["command", "to", "be", "executed"]

        mock_execute = self.mock_object(self.security_service_helper,
                                        '_execute')

        self.security_service_helper.ldap_retry_operation(mock_cmd,
                                                          run_as_root=True)

        mock_execute.assert_called_once_with(*mock_cmd, run_as_root=True)

    def test_ldap_retry_operation_timeout(self):
        mock_cmd = ["command", "to", "be", "executed"]

        mock_execute = self.mock_object(
            self.security_service_helper, '_execute',
            mock.Mock(
                side_effect=exception.ProcessExecutionError(exit_code=1)))

        self.assertRaises(
            exception.ShareBackendException,
            self.security_service_helper.ldap_retry_operation,
            mock_cmd,
            run_as_root=False,
            timeout=10)

        mock_execute.assert_has_calls([
            mock.call(*mock_cmd, run_as_root=False),
            mock.call(*mock_cmd, run_as_root=False)])

    def test_ldap_retry_operation_invalid_credential(self):
        mock_cmd = ["command", "to", "be", "executed"]

        mock_execute = self.mock_object(
            self.security_service_helper, '_execute',
            mock.Mock(
                side_effect=exception.ProcessExecutionError(
                    exit_code=49)))

        self.assertRaises(
            exception.ShareBackendException,
            self.security_service_helper.ldap_retry_operation,
            mock_cmd,
            run_as_root=False)

        mock_execute.assert_called_once_with(*mock_cmd, run_as_root=False)
