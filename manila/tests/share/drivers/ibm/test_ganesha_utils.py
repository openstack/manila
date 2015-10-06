# Copyright (c) 2014 IBM Corp.
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

"""Unit tests for the Ganesha Utils module."""

import socket
import time

import mock
from oslo_config import cfg

from manila import exception
import manila.share.drivers.ibm.ganesha_utils as ganesha_utils
from manila import test
from manila import utils


CONF = cfg.CONF


def fake_pre_lines(**kwargs):
    pre_lines = [
        '###################################################',
        '#     Export entries',
        '###################################################',
        '',
        '',
        '# First export entry',
    ]
    return pre_lines


def fake_exports(**kwargs):
    exports = {
        '100': {
            'anonymous_root_uid': '-2',
            'export_id': '100',
            'filesystem_id': '192.168',
            'fsal': '"GPFS"',
            'maxread': '65536',
            'maxwrite': '65536',
            'nfs_protocols': '"3,4"',
            'path': '"/fs0/share-1234"',
            'prefread': '65536',
            'prefwrite': '65536',
            'pseudo': '"/fs0/share-1234"',
            'root_access': '"*"',
            'rw_access': '""',
            'sectype': '"sys"',
            'tag': '"fs100"',
            'transport_protocols': '"UDP,TCP"',
        },
        '101': {
            'anonymous_root_uid': '-2',
            'export_id': '101',
            'filesystem_id': '192.168',
            'fsal': '"GPFS"',
            'maxread': '65536',
            'maxwrite': '65536',
            'nfs_protocols': '"3,4"',
            'path': '"/fs0/share-5678"',
            'prefread': '65536',
            'prefwrite': '65536',
            'pseudo': '"/fs0/share-5678"',
            'root_access': '"*"',
            'rw_access': '"172.24.4.4"',
            'sectype': '"sys"',
            'tag': '"fs101"',
            'transport_protocols': '"UDP,TCP"',
        },
    }
    return exports


class GaneshaUtilsTestCase(test.TestCase):
    """Tests Ganesha Utils."""

    def setUp(self):
        super(GaneshaUtilsTestCase, self).setUp()
        self.fake_path = "/fs0/share-1234"
        self.fake_pre_lines = fake_pre_lines()
        self.fake_exports = fake_exports()
        self.fake_configpath = "/etc/ganesha/ganesha.exports.conf"
        self.local_ip = ["192.11.22.1"]
        self.remote_ips = ["192.11.22.2", "192.11.22.3"]
        self.servers = self.local_ip + self.remote_ips
        self.sshlogin = "fake_login"
        self.sshkey = "fake_sshkey"
        self.STARTING_EXPORT_ID = 100
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value="testserver"))
        self.mock_object(socket, 'gethostbyname_ex', mock.Mock(
            return_value=('localhost',
                          ['localhost.localdomain', 'testserver'],
                          ['127.0.0.1'] + self.local_ip)
        ))

    def test_get_export_by_path(self):
        fake_export = {'export_id': '100'}
        self.mock_object(ganesha_utils, '_get_export_by_path',
                         mock.Mock(return_value=fake_export))
        export = ganesha_utils.get_export_by_path(self.fake_exports,
                                                  self.fake_path)
        self.assertEqual(export, fake_export)
        ganesha_utils._get_export_by_path.assert_called_once_with(
            self.fake_exports, self.fake_path
        )

    def test_export_exists(self):
        fake_export = {'export_id': '100'}
        self.mock_object(ganesha_utils, '_get_export_by_path',
                         mock.Mock(return_value=fake_export))
        result = ganesha_utils.export_exists(self.fake_exports, self.fake_path)
        self.assertTrue(result)
        ganesha_utils._get_export_by_path.assert_called_once_with(
            self.fake_exports, self.fake_path
        )

    def test__get_export_by_path_export_exists(self):
        expected_export = {
            'anonymous_root_uid': '-2',
            'export_id': '100',
            'filesystem_id': '192.168',
            'fsal': '"GPFS"',
            'maxread': '65536',
            'maxwrite': '65536',
            'nfs_protocols': '"3,4"',
            'path': '"/fs0/share-1234"',
            'prefread': '65536',
            'prefwrite': '65536',
            'pseudo': '"/fs0/share-1234"',
            'root_access': '"*"',
            'rw_access': '""',
            'sectype': '"sys"',
            'tag': '"fs100"',
            'transport_protocols': '"UDP,TCP"',
        }
        export = ganesha_utils._get_export_by_path(self.fake_exports,
                                                   self.fake_path)
        self.assertEqual(export, expected_export)

    def test__get_export_by_path_export_does_not_exists(self):
        share_path = '/fs0/share-1111'
        export = ganesha_utils._get_export_by_path(self.fake_exports,
                                                   share_path)
        self.assertIsNone(export)

    def test_get_next_id(self):
        expected_id = 102
        result = ganesha_utils.get_next_id(self.fake_exports)
        self.assertEqual(result, expected_id)

    def test_convert_ipstring_to_ipn_exception(self):
        ipstring = 'fake ip string'
        self.assertRaises(exception.GPFSGaneshaException,
                          ganesha_utils._convert_ipstring_to_ipn,
                          ipstring)

    @mock.patch('six.moves.builtins.map')
    def test_get_next_id_first_export(self, mock_map):
        expected_id = self.STARTING_EXPORT_ID
        mock_map.side_effect = ValueError
        result = ganesha_utils.get_next_id(self.fake_exports)
        self.assertEqual(result, expected_id)

    def test_format_access_list(self):
        access_string = "9.123.12.1,9.123.12.2,9.122"
        result = ganesha_utils.format_access_list(access_string, None)
        self.assertEqual(result, "9.122.0.0,9.123.12.1,9.123.12.2")

    def test_format_access_list_deny_access(self):
        access_string = "9.123.12.1,9.123,12.2"
        deny_access = "9.123,12.2"
        result = ganesha_utils.format_access_list(access_string,
                                                  deny_access=deny_access)
        self.assertEqual(result, "9.123.12.1")

    def test_publish_ganesha_config(self):
        configpath = self.fake_configpath
        methods = ('_publish_local_config', '_publish_remote_config')
        for method in methods:
            self.mock_object(ganesha_utils, method)
        ganesha_utils.publish_ganesha_config(self.servers, self.sshlogin,
                                             self.sshkey, configpath,
                                             self.fake_pre_lines,
                                             self.fake_exports)
        ganesha_utils._publish_local_config.assert_called_once_with(
            configpath, self.fake_pre_lines, self.fake_exports
        )
        for remote_ip in self.remote_ips:
            ganesha_utils._publish_remote_config.assert_any_call(
                remote_ip, self.sshlogin, self.sshkey, configpath
            )

    def test_reload_ganesha_config(self):
        self.mock_object(utils, 'execute', mock.Mock(return_value=True))
        service = 'ganesha.nfsd'
        ganesha_utils.reload_ganesha_config(self.servers, self.sshlogin)
        reload_cmd = ['service', service, 'restart']
        utils.execute.assert_any_call(*reload_cmd, run_as_root=True)
        for remote_ip in self.remote_ips:
            reload_cmd = ['service', service, 'restart']
            remote_login = self.sshlogin + '@' + remote_ip
            reload_cmd = ['ssh', remote_login] + reload_cmd
            utils.execute.assert_any_call(
                *reload_cmd, run_as_root=False
            )

    def test_reload_ganesha_config_exception(self):
        self.mock_object(
            utils, 'execute',
            mock.Mock(side_effect=exception.ProcessExecutionError))
        self.assertRaises(exception.GPFSGaneshaException,
                          ganesha_utils.reload_ganesha_config,
                          self.servers, self.sshlogin)

    @mock.patch('six.moves.builtins.open')
    def test__publish_local_config(self, mock_open):
        self.mock_object(utils, 'execute', mock.Mock(return_value=True))
        fake_timestamp = 1415506949.75
        self.mock_object(time, 'time', mock.Mock(return_value=fake_timestamp))
        configpath = self.fake_configpath
        tmp_path = '%s.tmp.%s' % (configpath, fake_timestamp)
        ganesha_utils._publish_local_config(configpath,
                                            self.fake_pre_lines,
                                            self.fake_exports)
        cpcmd = ['install', '-m', '666', configpath, tmp_path]
        utils.execute.assert_any_call(*cpcmd, run_as_root=True)
        mvcmd = ['mv', tmp_path, configpath]
        utils.execute.assert_any_call(*mvcmd, run_as_root=True)
        self.assertTrue(time.time.called)

    @mock.patch('six.moves.builtins.open')
    def test__publish_local_config_exception(self, mock_open):
        self.mock_object(
            utils, 'execute',
            mock.Mock(side_effect=exception.ProcessExecutionError))
        fake_timestamp = 1415506949.75
        self.mock_object(time, 'time', mock.Mock(return_value=fake_timestamp))
        configpath = self.fake_configpath
        tmp_path = '%s.tmp.%s' % (configpath, fake_timestamp)
        self.assertRaises(exception.GPFSGaneshaException,
                          ganesha_utils._publish_local_config, configpath,
                          self.fake_pre_lines, self.fake_exports)
        cpcmd = ['install', '-m', '666', configpath, tmp_path]
        utils.execute.assert_called_once_with(*cpcmd, run_as_root=True)
        self.assertTrue(time.time.called)

    def test__publish_remote_config(self):
        utils.execute = mock.Mock(return_value=True)
        server = self.remote_ips[1]
        dest = '%s@%s:%s' % (self.sshlogin, server, self.fake_configpath)
        scpcmd = ['scp', '-i', self.sshkey, self.fake_configpath, dest]

        ganesha_utils._publish_remote_config(server, self.sshlogin,
                                             self.sshkey, self.fake_configpath)
        utils.execute.assert_called_once_with(*scpcmd, run_as_root=False)

    def test__publish_remote_config_exception(self):
        self.mock_object(
            utils, 'execute',
            mock.Mock(side_effect=exception.ProcessExecutionError))
        server = self.remote_ips[1]
        dest = '%s@%s:%s' % (self.sshlogin, server, self.fake_configpath)
        scpcmd = ['scp', '-i', self.sshkey, self.fake_configpath, dest]

        self.assertRaises(exception.GPFSGaneshaException,
                          ganesha_utils._publish_remote_config, server,
                          self.sshlogin, self.sshkey, self.fake_configpath)
        utils.execute.assert_called_once_with(*scpcmd, run_as_root=False)
