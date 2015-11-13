# Copyright (c) 2015 EMC Corporation.
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

from eventlet import greenthread
import mock
from oslo_concurrency import processutils
from six.moves.urllib import error as url_error  # pylint: disable=E0611
from six.moves.urllib import request as url_request  # pylint: disable=E0611

from manila import exception
from manila.share import configuration as conf
from manila.share.drivers.emc.plugins.vnx import connector
from manila import test
from manila.tests.share.drivers.emc.plugins.vnx import fakes
from manila.tests.share.drivers.emc.plugins.vnx import utils as emc_utils
from manila import utils


class XMLAPIConnectorTestData(object):
    FAKE_BODY = '<fakebody></fakebody>'
    FAKE_RESP = '<Response></Response>'
    FAKE_METHOD = 'fake_method'

    FAKE_KEY = 'key'
    FAKE_VALUE = 'value'

    @staticmethod
    def req_auth_url():
        return 'https://' + fakes.FakeData.emc_nas_server + '/Login'

    @staticmethod
    def req_credential():
        return (
            'user=' + fakes.FakeData.emc_nas_login
            + '&password=' + fakes.FakeData.emc_nas_password
            + '&Login=Login'
        )

    @staticmethod
    def req_url_encode():
        return {'Content-Type': 'application/x-www-form-urlencoded'}

    @staticmethod
    def req_url():
        return (
            'https://'
            + fakes.FakeData.emc_nas_server
            + '/servlets/CelerraManagementServices'
        )


XML_CONN_TD = XMLAPIConnectorTestData


class XMLAPIConnectorTest(test.TestCase):
    @mock.patch.object(url_request, 'Request', mock.Mock())
    def setUp(self):
        super(XMLAPIConnectorTest, self).setUp()

        emc_share_driver = fakes.FakeEMCShareDriver()

        self.configuration = emc_share_driver.configuration

        xml_socket = mock.Mock()
        xml_socket.read = mock.Mock(return_value=XML_CONN_TD.FAKE_RESP)
        opener = mock.Mock()
        opener.open = mock.Mock(return_value=xml_socket)

        with mock.patch.object(url_request, 'build_opener',
                               mock.Mock(return_value=opener)):
            self.XmlConnector = connector.XMLAPIConnector(
                configuration=self.configuration, debug=False)

            expected_calls = [
                mock.call(XML_CONN_TD.req_auth_url(),
                          XML_CONN_TD.req_credential(),
                          XML_CONN_TD.req_url_encode()),
            ]

            url_request.Request.assert_has_calls(expected_calls)

    def test_request_with_debug(self):
        self.XmlConnector.debug = True

        request = mock.Mock()
        request.headers = {XML_CONN_TD.FAKE_KEY: XML_CONN_TD.FAKE_VALUE}
        request.get_full_url = mock.Mock(
            return_value=XML_CONN_TD.FAKE_VALUE)

        with mock.patch.object(url_request, 'Request',
                               mock.Mock(return_value=request)):
            rsp = self.XmlConnector.request(XML_CONN_TD.FAKE_BODY,
                                            XML_CONN_TD.FAKE_METHOD)

            self.assertEqual(XML_CONN_TD.FAKE_RESP, rsp)

    def test_request_with_no_authorized_exception(self):
        xml_socket = mock.Mock()
        xml_socket.read = mock.Mock(return_value=XML_CONN_TD.FAKE_RESP)

        hook = emc_utils.RequestSideEffect()
        hook.append(ex=url_error.HTTPError(XML_CONN_TD.req_url(),
                                           '403', 'fake_message', None, None))
        hook.append(xml_socket)
        hook.append(xml_socket)

        self.XmlConnector.url_opener.open = mock.Mock(side_effect=hook)

        self.XmlConnector.request(XML_CONN_TD.FAKE_BODY)

    def test_request_with_general_exception(self):
        hook = emc_utils.RequestSideEffect()
        hook.append(ex=url_error.HTTPError(XML_CONN_TD.req_url(),
                                           'error_code', 'fake_message',
                                           None, None))
        self.XmlConnector.url_opener.open = mock.Mock(side_effect=hook)

        self.assertRaises(exception.ManilaException,
                          self.XmlConnector.request,
                          XML_CONN_TD.FAKE_BODY)


class MockSSH(object):
        def __enter__(self):
            return self

        def __exit__(self, type, value, traceback):
            pass


class MockSSHPool(object):
    def __init__(self):
        self.ssh = MockSSH()

    def item(self):
        try:
            return self.ssh
        finally:
            pass


class CmdConnectorTest(test.TestCase):
    def setUp(self):
        super(CmdConnectorTest, self).setUp()

        self.configuration = conf.Configuration(None)
        self.configuration.append_config_values = mock.Mock(return_value=0)
        self.configuration.emc_nas_login = fakes.FakeData.emc_nas_login
        self.configuration.emc_nas_password = fakes.FakeData.emc_nas_password
        self.configuration.emc_nas_server = fakes.FakeData.emc_nas_server

        self.sshpool = MockSSHPool()
        with mock.patch.object(utils, "SSHPool",
                               mock.Mock(return_value=self.sshpool)):
            self.CmdHelper = connector.SSHConnector(
                configuration=self.configuration, debug=False)

            utils.SSHPool.assert_called_once_with(
                ip=fakes.FakeData.emc_nas_server,
                port=22,
                conn_timeout=None,
                login=fakes.FakeData.emc_nas_login,
                password=fakes.FakeData.emc_nas_password)

    def test_run_ssh(self):
        with mock.patch.object(processutils, "ssh_execute",
                               mock.Mock(return_value=('fake_output', ''))):
            cmd_list = ['fake', 'cmd']
            self.CmdHelper.run_ssh(cmd_list)

            processutils.ssh_execute.assert_called_once_with(
                self.sshpool.item(), 'fake cmd', check_exit_code=False)

    def test_run_ssh_with_debug(self):
        self.CmdHelper.debug = True

        with mock.patch.object(processutils, "ssh_execute",
                               mock.Mock(return_value=('fake_output', ''))):
            cmd_list = ['fake', 'cmd']
            self.CmdHelper.run_ssh(cmd_list)

            processutils.ssh_execute.assert_called_once_with(
                self.sshpool.item(), 'fake cmd', check_exit_code=False)

    @mock.patch.object(
        processutils, "ssh_execute",
        mock.Mock(side_effect=processutils.ProcessExecutionError))
    def test_run_ssh_exception(self):
        cmd_list = ['fake', 'cmd']

        self.mock_object(greenthread, 'sleep', mock.Mock())

        sshpool = MockSSHPool()

        with mock.patch.object(utils, "SSHPool",
                               mock.Mock(return_value=sshpool)):
            self.CmdHelper = connector.SSHConnector(self.configuration)

            self.assertRaises(processutils.ProcessExecutionError,
                              self.CmdHelper.run_ssh,
                              cmd_list,
                              True)

            utils.SSHPool.assert_called_once_with(
                ip=fakes.FakeData.emc_nas_server,
                port=22,
                conn_timeout=None,
                login=fakes.FakeData.emc_nas_login,
                password=fakes.FakeData.emc_nas_password)

            processutils.ssh_execute.assert_called_once_with(
                sshpool.item(), 'fake cmd', check_exit_code=True)
