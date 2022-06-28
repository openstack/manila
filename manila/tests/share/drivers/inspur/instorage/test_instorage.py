# Copyright 2019 Inspur Corp.
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

"""
Share driver test for Inspur InStorage
"""

from unittest import mock

import ddt
from eventlet import greenthread
from oslo_concurrency import processutils
from oslo_config import cfg
import paramiko

from manila import context
from manila import exception
from manila.share import driver
from manila.share.drivers.inspur.instorage import cli_helper
from manila.share.drivers.inspur.instorage import instorage
from manila import test
from manila.tests import fake_share
from manila import utils as manila_utils

CONF = cfg.CONF


class FakeConfig(object):
    def __init__(self, *args, **kwargs):
        self.driver_handles_share_servers = False
        self.share_driver = 'fake_share_driver_name'
        self.share_backend_name = 'fake_instorage'
        self.instorage_nas_ip = kwargs.get(
            'instorage_nas_ip', 'some_ip')
        self.instorage_nas_port = kwargs.get(
            'instorage_nas_port', 'some_port')
        self.instorage_nas_login = kwargs.get(
            'instorage_nas_login', 'username')
        self.instorage_nas_password = kwargs.get(
            'instorage_nas_password', 'password')
        self.instorage_nas_pools = kwargs.get(
            'instorage_nas_pools', ['fakepool'])
        self.network_config_group = kwargs.get(
            "network_config_group", "fake_network_config_group")
        self.admin_network_config_group = kwargs.get(
            "admin_network_config_group", "fake_admin_network_config_group")
        self.config_group = kwargs.get("config_group", "fake_config_group")
        self.reserved_share_percentage = kwargs.get(
            "reserved_share_percentage", 0)
        self.reserved_share_from_snapshot_percentage = kwargs.get(
            "reserved_share_from_snapshot_percentage", 0)
        self.reserved_share_extend_percentage = kwargs.get(
            "reserved_share_extend_percentage", 0)
        self.max_over_subscription_ratio = kwargs.get(
            "max_over_subscription_ratio", 0)
        self.filter_function = kwargs.get("filter_function", None)
        self.goodness_function = kwargs.get("goodness_function", None)

    def safe_get(self, key):
        return getattr(self, key)

    def append_config_values(self, *args, **kwargs):
        pass


@ddt.ddt
class InStorageShareDriverTestCase(test.TestCase):
    def __init__(self, *args, **kwargs):
        super(InStorageShareDriverTestCase, self).__init__(*args, **kwargs)
        self._ctxt = context.get_admin_context()
        self.configuration = FakeConfig()
        self.share = fake_share.fake_share()
        self.share_instance = fake_share.fake_share_instance(
            self.share, host='H@B#P'
        )

    def setUp(self):
        self.mock_object(instorage.CONF, '_check_required_opts')
        self.driver = instorage.InStorageShareDriver(
            configuration=self.configuration
        )
        super(InStorageShareDriverTestCase, self).setUp()

    def test_check_for_setup_error_failed_no_nodes(self):
        mock_gni = mock.Mock(return_value={})
        self.mock_object(
            instorage.InStorageAssistant, 'get_nodes_info', mock_gni
        )

        self.assertRaises(
            exception.ShareBackendException,
            self.driver.check_for_setup_error
        )

    def test_check_for_setup_error_failed_pool_invalid(self):
        mock_gni = mock.Mock(return_value={'node1': {}})
        self.mock_object(
            instorage.InStorageAssistant, 'get_nodes_info', mock_gni
        )
        mock_gap = mock.Mock(return_value=['pool0'])
        self.mock_object(
            instorage.InStorageAssistant, 'get_available_pools', mock_gap
        )

        self.assertRaises(
            exception.InvalidParameterValue,
            self.driver.check_for_setup_error
        )

    def test_check_for_setup_error_success(self):
        mock_gni = mock.Mock(return_value={'node1': {}})
        self.mock_object(
            instorage.InStorageAssistant, 'get_nodes_info', mock_gni
        )
        mock_gap = mock.Mock(return_value=['fakepool', 'pool0'])
        self.mock_object(
            instorage.InStorageAssistant, 'get_available_pools', mock_gap
        )

        self.driver.check_for_setup_error()
        mock_gni.assert_called_once()
        mock_gap.assert_called_once()

    def test__update_share_stats(self):
        pool_attr = {
            'pool0': {
                'pool_name': 'pool0',
                'total_capacity_gb': 110,
                'free_capacity_gb': 100,
                'allocated_capacity_gb': 10,
                'reserved_percentage': 0,
                'reserved_snapshot_percentage': 0,
                'reserved_share_extend_percentage': 0,
                'qos': False,
                'dedupe': False,
                'compression': False,
                'thin_provisioning': False,
                'max_over_subscription_ratio': 0
            }
        }
        mock_gpa = mock.Mock(return_value=pool_attr)
        self.mock_object(
            instorage.InStorageAssistant, 'get_pools_attr', mock_gpa
        )
        mock_uss = mock.Mock()
        self.mock_object(driver.ShareDriver, '_update_share_stats', mock_uss)

        self.driver._update_share_stats()

        mock_gpa.assert_called_once_with(['fakepool'])
        stats = {
            'share_backend_name': 'fake_instorage',
            'vendor_name': 'INSPUR',
            'driver_version': '1.0.0',
            'storage_protocol': 'NFS_CIFS',
            'reserved_percentage': 0,
            'reserved_snapshot_percentage': 0,
            'reserved_share_extend_percentage': 0,
            'max_over_subscription_ratio': 0,
            'snapshot_support': False,
            'create_share_from_snapshot_support': False,
            'revert_to_snapshot_support': False,
            'qos': False,
            'total_capacity_gb': 110,
            'free_capacity_gb': 100,
            'pools': [pool_attr['pool0']]
        }
        mock_uss.assert_called_once_with(stats)

    @ddt.data(
        {'id': 'abc-123', 'real': 'abc123'},
        {'id': '123-abc', 'real': 'B23abc'})
    @ddt.unpack
    def test_generate_share_name(self, id, real):
        ret = self.driver.generate_share_name({'id': id})
        self.assertEqual(real, ret)

    def test_get_network_allocations_number(self):
        ret = self.driver.get_network_allocations_number()
        self.assertEqual(0, ret)

    def test_create_share(self):
        mock_cs = self.mock_object(
            instorage.InStorageAssistant, 'create_share'
        )
        mock_gel = self.mock_object(
            instorage.InStorageAssistant,
            'get_export_locations',
            mock.Mock(return_value=['fake_export_location'])
        )

        ret = self.driver.create_share(self._ctxt, self.share_instance)

        self.assertEqual(['fake_export_location'], ret)
        mock_cs.assert_called_once_with('fakeinstanceid', 'P', 1, 'fake_proto')
        mock_gel.assert_called_once_with('fakeinstanceid', 'fake_proto')

    def test_delete_share(self):
        mock_ds = self.mock_object(
            instorage.InStorageAssistant, 'delete_share'
        )

        self.driver.delete_share(self._ctxt, self.share_instance)

        mock_ds.assert_called_once_with('fakeinstanceid', 'fake_proto')

    def test_extend_share(self):
        mock_es = self.mock_object(
            instorage.InStorageAssistant, 'extend_share'
        )

        self.driver.extend_share(self.share_instance, 3)

        mock_es.assert_called_once_with('fakeinstanceid', 3)

    def test_ensure_share(self):
        mock_gel = self.mock_object(
            instorage.InStorageAssistant,
            'get_export_locations',
            mock.Mock(return_value=['fake_export_location'])
        )

        ret = self.driver.ensure_share(self._ctxt, self.share_instance)

        self.assertEqual(['fake_export_location'], ret)
        mock_gel.assert_called_once_with('fakeinstanceid', 'fake_proto')

    def test_update_access(self):
        mock_ua = self.mock_object(
            instorage.InStorageAssistant, 'update_access'
        )

        self.driver.update_access(self._ctxt, self.share_instance, [], [], [])

        mock_ua.assert_called_once_with(
            'fakeinstanceid', 'fake_proto', [], [], []
        )


class FakeSSH(object):
    def __enter__(self):
        return self

    def __exit__(self, exec_type, exec_val, exec_tb):
        if exec_val:
            raise


class FakeSSHPool(object):
    def __init__(self, ssh):
        self.fakessh = ssh

    def item(self):
        return self.fakessh


class SSHRunnerTestCase(test.TestCase):
    def setUp(self):
        self.fakessh = FakeSSH()
        self.fakePool = FakeSSHPool(self.fakessh)
        super(SSHRunnerTestCase, self).setUp()

    def test___call___success(self):
        mock_csi = self.mock_object(manila_utils, 'check_ssh_injection')
        mock_sshpool = mock.Mock(return_value=self.fakePool)
        self.mock_object(manila_utils, 'SSHPool', mock_sshpool)
        mock_se = mock.Mock(return_value='fake_value')
        self.mock_object(cli_helper.SSHRunner, '_ssh_execute', mock_se)

        runner = cli_helper.SSHRunner(
            '127.0.0.1', '22', 'fakeuser', 'fakepassword'
        )
        ret = runner(['mcsinq', 'lsvdisk'])

        mock_csi.assert_called_once_with(['mcsinq', 'lsvdisk'])
        mock_sshpool.assert_called_once_with(
            '127.0.0.1', '22', 60, 'fakeuser',
            password='fakepassword',
            privatekey=None,
            min_size=1,
            max_size=10
        )
        mock_se.assert_called_once_with(
            self.fakePool,
            'mcsinq lsvdisk',
            True,
            1
        )
        self.assertEqual('fake_value', ret)

    def test___call___ssh_pool_failed(self):
        mock_csi = self.mock_object(manila_utils, 'check_ssh_injection')
        mock_sshpool = mock.Mock(side_effect=paramiko.SSHException())
        self.mock_object(manila_utils, 'SSHPool', mock_sshpool)

        runner = cli_helper.SSHRunner(
            '127.0.0.1', '22', 'fakeuser', 'fakepassword'
        )

        self.assertRaises(paramiko.SSHException, runner, ['mcsinq', 'lsvdisk'])
        mock_csi.assert_called_once_with(['mcsinq', 'lsvdisk'])

    def test___call___ssh_exec_failed(self):
        mock_csi = self.mock_object(manila_utils, 'check_ssh_injection')
        mock_sshpool = mock.Mock(return_value=self.fakePool)
        self.mock_object(manila_utils, 'SSHPool', mock_sshpool)
        exception = processutils.ProcessExecutionError()
        mock_se = mock.Mock(side_effect=exception)
        self.mock_object(cli_helper.SSHRunner, '_ssh_execute', mock_se)

        runner = cli_helper.SSHRunner(
            '127.0.0.1', '22', 'fakeuser', 'fakepassword'
        )

        self.assertRaises(
            processutils.ProcessExecutionError,
            runner,
            ['mcsinq', 'lsvdisk']
        )
        mock_csi.assert_called_once_with(['mcsinq', 'lsvdisk'])
        mock_sshpool.assert_called_once_with(
            '127.0.0.1', '22', 60, 'fakeuser',
            password='fakepassword',
            privatekey=None,
            min_size=1,
            max_size=10
        )

    def test__ssh_execute_success(self):
        mock_se = mock.Mock(return_value='fake_value')
        self.mock_object(processutils, 'ssh_execute', mock_se)

        runner = cli_helper.SSHRunner(
            '127.0.0.1', '22', 'fakeuser', 'fakepassword'
        )
        ret = runner._ssh_execute(self.fakePool, 'mcsinq lsvdisk')

        mock_se.assert_called_once_with(
            self.fakessh,
            'mcsinq lsvdisk',
            check_exit_code=True
        )
        self.assertEqual('fake_value', ret)

    def test__ssh_execute_success_run_again(self):
        mock_se = mock.Mock(side_effect=[Exception(), 'fake_value'])
        self.mock_object(processutils, 'ssh_execute', mock_se)
        mock_sleep = self.mock_object(greenthread, 'sleep')

        runner = cli_helper.SSHRunner(
            '127.0.0.1', '22', 'fakeuser', 'fakepassword'
        )
        ret = runner._ssh_execute(
            self.fakePool,
            'mcsinq lsvdisk',
            check_exit_code=True,
            attempts=2
        )

        call = mock.call(self.fakessh, 'mcsinq lsvdisk', check_exit_code=True)
        mock_se.assert_has_calls([call, call])
        mock_sleep.assert_called_once()
        self.assertEqual('fake_value', ret)

    def test__ssh_execute_failed_exec_failed(self):
        exception = Exception()
        exception.exit_code = '1'
        exception.stdout = 'fake_stdout'
        exception.stderr = 'fake_stderr'
        exception.cmd = 'fake_cmd_list'
        mock_se = mock.Mock(side_effect=exception)
        self.mock_object(processutils, 'ssh_execute', mock_se)
        mock_sleep = self.mock_object(greenthread, 'sleep')

        runner = cli_helper.SSHRunner(
            '127.0.0.1', '22', 'fakeuser', 'fakepassword'
        )

        self.assertRaises(
            processutils.ProcessExecutionError,
            runner._ssh_execute,
            self.fakePool,
            'mcsinq lsvdisk',
            check_exit_code=True,
            attempts=1
        )
        mock_se.assert_called_once_with(
            self.fakessh,
            'mcsinq lsvdisk',
            check_exit_code=True
        )
        mock_sleep.assert_called_once()

    def test__ssh_execute_failed_exec_failed_exception_error(self):
        mock_se = mock.Mock(side_effect=Exception())
        self.mock_object(processutils, 'ssh_execute', mock_se)
        mock_sleep = self.mock_object(greenthread, 'sleep')

        runner = cli_helper.SSHRunner(
            '127.0.0.1', '22', 'fakeuser', 'fakepassword'
        )

        self.assertRaises(
            processutils.ProcessExecutionError,
            runner._ssh_execute,
            self.fakePool,
            'mcsinq lsvdisk',
            check_exit_code=True,
            attempts=1
        )
        mock_se.assert_called_once_with(
            self.fakessh,
            'mcsinq lsvdisk',
            check_exit_code=True
        )
        mock_sleep.assert_called_once()


class CLIParserTestCase(test.TestCase):
    def test_cliparser_with_header(self):
        cmdlist = ['mcsinq', 'lsnasportip', '-delim', '!']
        response = [
            'head1!head2',
            'r1c1!r1c2',
            'r2c1!r2c2'
        ]
        response = '\n'.join(response)

        ret = cli_helper.CLIParser(
            response, cmdlist, delim='!', with_header=True
        )

        self.assertEqual(2, len(ret))
        self.assertEqual('r1c1', ret[0]['head1'])
        self.assertEqual('r1c2', ret[0]['head2'])
        self.assertEqual('r2c1', ret[1]['head1'])
        self.assertEqual('r2c2', ret[1]['head2'])

        value = [(v['head1'], v['head2']) for v in ret]
        self.assertEqual([('r1c1', 'r1c2'), ('r2c1', 'r2c2')], value)

    def test_cliparser_without_header(self):
        cmdlist = ['mcsinq', 'lsnasportip', '-delim', '!']
        response = [
            'head1!p1v1',
            'head2!p1v2',
            '',
            'head1!p2v1',
            'head2!p2v2'
        ]
        response = '\n'.join(response)

        ret = cli_helper.CLIParser(
            response, cmdlist, delim='!', with_header=False
        )

        self.assertEqual(2, len(ret))
        self.assertEqual('p1v1', ret[0]['head1'])
        self.assertEqual('p1v2', ret[0]['head2'])
        self.assertEqual('p2v1', ret[1]['head1'])
        self.assertEqual('p2v2', ret[1]['head2'])


@ddt.ddt
class InStorageSSHTestCase(test.TestCase):
    def setUp(self):
        self.sshMock = mock.Mock()
        self.ssh = cli_helper.InStorageSSH(self.sshMock)
        super(InStorageSSHTestCase, self).setUp()

    def tearDown(self):
        super(InStorageSSHTestCase, self).tearDown()

    @ddt.data(None, 'node1')
    def test_lsnode(self, node_id):
        if node_id:
            cmd = ['mcsinq', 'lsnode', '-delim', '!', node_id]
            response = [
                'id!1',
                'name!node1'
            ]
        else:
            cmd = ['mcsinq', 'lsnode', '-delim', '!']
            response = [
                'id!name',
                '1!node1',
                '2!node2'
            ]

        response = '\n'.join(response)
        self.sshMock.return_value = (response, '')

        ret = self.ssh.lsnode(node_id)

        if node_id:
            self.sshMock.assert_called_once_with(cmd)
            self.assertEqual('node1', ret[0]['name'])
        else:
            self.sshMock.assert_called_once_with(cmd)
            self.assertEqual('node1', ret[0]['name'])
            self.assertEqual('node2', ret[1]['name'])

    @ddt.data(None, 'Pool0')
    def test_lsnaspool(self, pool_id):
        response = [
            'pool_name!available_capacity',
            'Pool0!2GB'
        ]
        if pool_id is None:
            response.append('Pool1!3GB')

        response = '\n'.join(response)
        self.sshMock.return_value = (response, '')

        ret = self.ssh.lsnaspool(pool_id)

        if pool_id is None:
            cmd = ['mcsinq', 'lsnaspool', '-delim', '!']
            self.sshMock.assert_called_once_with(cmd)
            self.assertEqual('Pool0', ret[0]['pool_name'])
            self.assertEqual('2GB', ret[0]['available_capacity'])
            self.assertEqual('Pool1', ret[1]['pool_name'])
            self.assertEqual('3GB', ret[1]['available_capacity'])
        else:
            cmd = ['mcsinq', 'lsnaspool', '-delim', '!', pool_id]
            self.sshMock.assert_called_once_with(cmd)
            self.assertEqual('Pool0', ret[0]['pool_name'])
            self.assertEqual('2GB', ret[0]['available_capacity'])

    @ddt.data({'node_name': 'node1', 'fsname': 'fs1'},
              {'node_name': 'node1', 'fsname': None},
              {'node_name': None, 'fsname': 'fs1'},
              {'node_name': None, 'fsname': None})
    @ddt.unpack
    def test_lsfs(self, node_name, fsname):
        response = [
            'pool_name!fs_name!total_capacity!used_capacity',
            'pool0!fs0!10GB!1GB',
            'pool1!fs1!8GB!3GB'
        ]
        response = '\n'.join(response)
        self.sshMock.return_value = (response, '')

        if fsname and not node_name:
            self.assertRaises(exception.InvalidParameterValue,
                              self.ssh.lsfs,
                              node_name=node_name,
                              fsname=fsname)
        else:
            ret = self.ssh.lsfs(node_name, fsname)

            cmdlist = []
            if node_name and not fsname:
                cmdlist = ['mcsinq', 'lsfs', '-delim', '!', '-node', '"node1"']
            elif node_name and fsname:
                cmdlist = ['mcsinq', 'lsfs', '-delim', '!',
                           '-node', '"node1"', '-name', '"fs1"']
            else:
                cmdlist = ['mcsinq', 'lsfs', '-delim', '!', '-all']

            self.sshMock.assert_called_once_with(cmdlist)
            self.assertEqual('pool0', ret[0]['pool_name'])
            self.assertEqual('fs0', ret[0]['fs_name'])
            self.assertEqual('10GB', ret[0]['total_capacity'])
            self.assertEqual('1GB', ret[0]['used_capacity'])
            self.assertEqual('pool1', ret[1]['pool_name'])
            self.assertEqual('fs1', ret[1]['fs_name'])
            self.assertEqual('8GB', ret[1]['total_capacity'])
            self.assertEqual('3GB', ret[1]['used_capacity'])

    def test_addfs(self):
        self.sshMock.return_value = ('', '')

        self.ssh.addfs('fsname', 'fake_pool', 1, 'node1')

        cmdlist = ['mcsop', 'addfs', '-name', '"fsname"',
                   '-pool', '"fake_pool"', '-size', '1g', '-node', '"node1"']
        self.sshMock.assert_called_once_with(cmdlist)

    def test_rmfs(self):
        self.sshMock.return_value = ('', '')

        self.ssh.rmfs('fsname')

        cmdlist = ['mcsop', 'rmfs', '-name', '"fsname"']
        self.sshMock.assert_called_once_with(cmdlist)

    def test_expandfs(self):
        self.sshMock.return_value = ('', '')

        self.ssh.expandfs('fsname', 2)

        cmdlist = ['mcsop', 'expandfs', '-name', '"fsname"', '-size', '2g']
        self.sshMock.assert_called_once_with(cmdlist)

    def test_lsnasdir(self):
        response = [
            'parent_dir!name',
            '/fs/test_01!share_01'
        ]

        response = '\n'.join(response)
        self.sshMock.return_value = (response, '')

        ret = self.ssh.lsnasdir('/fs/test_01')

        cmdlist = ['mcsinq', 'lsnasdir', '-delim', '!', '"/fs/test_01"']
        self.sshMock.assert_called_once_with(cmdlist)
        self.assertEqual('/fs/test_01', ret[0]['parent_dir'])
        self.assertEqual('share_01', ret[0]['name'])

    def test_addnasdir(self):
        self.sshMock.return_value = ('', '')

        self.ssh.addnasdir('/fs/test_01/share_01')

        cmdlist = ['mcsop', 'addnasdir', '"/fs/test_01/share_01"']
        self.sshMock.assert_called_once_with(cmdlist)

    def test_chnasdir(self):
        self.sshMock.return_value = ('', '')

        self.ssh.chnasdir('/fs/test_01/share_01', '/fs/test_01/share_02')

        cmdlist = ['mcsop', 'chnasdir', '-oldpath', '"/fs/test_01/share_01"',
                   '-newpath', '"/fs/test_01/share_02"']
        self.sshMock.assert_called_once_with(cmdlist)

    def test_rmnasdir(self):
        self.sshMock.return_value = ('', '')

        self.ssh.rmnasdir('/fs/test_01/share_01')

        cmdlist = ['mcsop', 'rmnasdir', '"/fs/test_01/share_01"']
        self.sshMock.assert_called_once_with(cmdlist)

    def test_rmnfs(self):
        self.sshMock.return_value = ('', '')

        self.ssh.rmnfs('/fs/test_01/share_01')

        cmdlist = ['mcsop', 'rmnfs', '"/fs/test_01/share_01"']
        self.sshMock.assert_called_once_with(cmdlist)

    @ddt.data(None, '/fs/test_01')
    def test_lsnfslist(self, prefix):
        cmdlist = ['mcsinq', 'lsnfslist', '-delim', '!']
        if prefix:
            cmdlist.append('"/fs/test_01"')
        response = '\n'.join([
            'path',
            '/fs/test_01/share_01',
            '/fs/test_01/share_02'
        ])
        self.sshMock.return_value = (response, '')

        ret = self.ssh.lsnfslist(prefix)
        self.sshMock.assert_called_once_with(cmdlist)
        self.assertEqual('/fs/test_01/share_01', ret[0]['path'])
        self.assertEqual('/fs/test_01/share_02', ret[1]['path'])

    def test_lsnfsinfo(self):
        cmdlist = [
            'mcsinq', 'lsnfsinfo', '-delim', '!', '"/fs/test_01/share_01"'
        ]
        response = '\n'.join([
            'ip!mask!rights!root_squash!all_squash',
            '192.168.1.0!255.255.255.0!rw!root_squash!all_squash'
        ])
        self.sshMock.return_value = (response, '')

        ret = self.ssh.lsnfsinfo('/fs/test_01/share_01')

        self.sshMock.assert_called_once_with(cmdlist)
        self.assertEqual('192.168.1.0', ret[0]['ip'])
        self.assertEqual('255.255.255.0', ret[0]['mask'])
        self.assertEqual('rw', ret[0]['rights'])

    def test_addnfsclient(self):
        self.sshMock.return_value = ('', '')

        cmdlist = [
            'mcsop', 'addnfsclient', '-path', '"/fs/test_01/share_01"',
            '-client', '192.168.1.0/255.255.255.0:rw:ALL_SQUASH:ROOT_SQUASH'
        ]

        self.ssh.addnfsclient(
            '/fs/test_01/share_01',
            '192.168.1.0/255.255.255.0:rw:ALL_SQUASH:ROOT_SQUASH'
        )

        self.sshMock.assert_called_once_with(cmdlist)

    def test_chnfsclient(self):
        self.sshMock.return_value = ('', '')

        cmdlist = [
            'mcsop', 'chnfsclient', '-path', '"/fs/test_01/share_01"',
            '-client', '192.168.1.0/255.255.255.0:rw:ALL_SQUASH:ROOT_SQUASH'
        ]

        self.ssh.chnfsclient(
            '/fs/test_01/share_01',
            '192.168.1.0/255.255.255.0:rw:ALL_SQUASH:ROOT_SQUASH'
        )

        self.sshMock.assert_called_once_with(cmdlist)

    def test_rmnfsclient(self):
        self.sshMock.return_value = ('', '')

        cmdlist = [
            'mcsop', 'rmnfsclient', '-path', '"/fs/test_01/share_01"',
            '-client', '192.168.1.0/255.255.255.0'
        ]

        self.ssh.rmnfsclient(
            '/fs/test_01/share_01',
            '192.168.1.0/255.255.255.0:rw:ALL_SQUASH:ROOT_SQUASH'
        )

        self.sshMock.assert_called_once_with(cmdlist)

    @ddt.data(None, 'cifs')
    def test_lscifslist(self, filter):
        cmdlist = ['mcsinq', 'lscifslist', '-delim', '!']
        if filter:
            cmdlist.append('"%s"' % filter)
        response = '\n'.join([
            'name!path',
            'cifs!/fs/test_01/share_01'
        ])
        self.sshMock.return_value = (response, '')

        ret = self.ssh.lscifslist(filter)

        self.sshMock.assert_called_once_with(cmdlist)
        self.assertEqual('cifs', ret[0]['name'])
        self.assertEqual('/fs/test_01/share_01', ret[0]['path'])

    def test_lscifsinfo(self):
        cmdlist = ['mcsinq', 'lscifsinfo', '-delim', '!', '"cifs"']
        response = '\n'.join([
            'path!oplocks!type!name!rights',
            '/fs/test_01/share_01!on!LU!user1!rw'
        ])
        self.sshMock.return_value = (response, '')

        ret = self.ssh.lscifsinfo('cifs')

        self.sshMock.assert_called_once_with(cmdlist)
        self.assertEqual('/fs/test_01/share_01', ret[0]['path'])
        self.assertEqual('on', ret[0]['oplocks'])
        self.assertEqual('LU', ret[0]['type'])
        self.assertEqual('user1', ret[0]['name'])
        self.assertEqual('rw', ret[0]['rights'])

    def test_addcifs(self):
        self.sshMock.return_value = ('', '')

        cmdlist = [
            'mcsop', 'addcifs', '-name', 'cifs',
            '-path', '/fs/test_01/share_01', '-oplocks', 'off'
        ]

        self.ssh.addcifs('cifs', '/fs/test_01/share_01', 'off')
        self.sshMock.assert_called_once_with(cmdlist)

    def test_rmcifs(self):
        self.sshMock.return_value = ('', '')

        cmdlist = ['mcsop', 'rmcifs', 'cifs']

        self.ssh.rmcifs('cifs')
        self.sshMock.assert_called_once_with(cmdlist)

    def test_chcifs(self):
        self.sshMock.return_value = ('', '')

        cmdlist = ['mcsop', 'chcifs', '-name', 'cifs', '-oplocks', 'off']

        self.ssh.chcifs('cifs', 'off')
        self.sshMock.assert_called_once_with(cmdlist)

    def test_addcifsuser(self):
        self.sshMock.return_value = ('', '')

        cmdlist = [
            'mcsop', 'addcifsuser', '-name', 'cifs', '-rights', 'LU:user1:rw'
        ]

        self.ssh.addcifsuser('cifs', 'LU:user1:rw')
        self.sshMock.assert_called_once_with(cmdlist)

    def test_chcifsuser(self):
        self.sshMock.return_value = ('', '')

        cmdlist = [
            'mcsop', 'chcifsuser', '-name', 'cifs', '-rights', 'LU:user1:rw'
        ]

        self.ssh.chcifsuser('cifs', 'LU:user1:rw')
        self.sshMock.assert_called_once_with(cmdlist)

    def test_rmcifsuser(self):
        self.sshMock.return_value = ('', '')

        cmdlist = [
            'mcsop', 'rmcifsuser', '-name', 'cifs', '-rights', 'LU:user1'
        ]

        self.ssh.rmcifsuser('cifs', 'LU:user1:rw')
        self.sshMock.assert_called_once_with(cmdlist)

    def test_lsnasportip(self):
        cmdlist = ['mcsinq', 'lsnasportip', '-delim', '!']
        response = '\n'.join([
            'node_name!id!ip!mask!gw!link_state',
            'node1!1!192.168.10.1!255.255.255.0!192.168.10.254!active',
            'node2!1!192.168.10.2!255.255.255.0!192.168.10.254!inactive'
        ])

        self.sshMock.return_value = (response, '')

        ret = self.ssh.lsnasportip()

        self.sshMock.assert_called_once_with(cmdlist)
        self.assertEqual('node1', ret[0]['node_name'])
        self.assertEqual('1', ret[0]['id'])
        self.assertEqual('192.168.10.1', ret[0]['ip'])
        self.assertEqual('255.255.255.0', ret[0]['mask'])
        self.assertEqual('192.168.10.254', ret[0]['gw'])
        self.assertEqual('active', ret[0]['link_state'])
        self.assertEqual('node2', ret[1]['node_name'])
        self.assertEqual('1', ret[1]['id'])
        self.assertEqual('192.168.10.2', ret[1]['ip'])
        self.assertEqual('255.255.255.0', ret[1]['mask'])
        self.assertEqual('192.168.10.254', ret[1]['gw'])
        self.assertEqual('inactive', ret[1]['link_state'])


@ddt.ddt
class InStorageAssistantTestCase(test.TestCase):
    def setUp(self):
        self.sshMock = mock.Mock()
        self.assistant = instorage.InStorageAssistant(self.sshMock)
        super(InStorageAssistantTestCase, self).setUp()

    def tearDown(self):
        super(InStorageAssistantTestCase, self).tearDown()

    @ddt.data(
        {'size': '1000MB', 'gb_size': 1},
        {'size': '3GB', 'gb_size': 3},
        {'size': '4TB', 'gb_size': 4096},
        {'size': '5PB', 'gb_size': 5242880})
    @ddt.unpack
    def test_size_to_gb(self, size, gb_size):
        ret = self.assistant.size_to_gb(size)
        self.assertEqual(gb_size, ret)

    def test_get_available_pools(self):
        response_for_lsnaspool = ('\n'.join([
            'pool_name!available_capacity',
            'pool0!100GB',
            'pool1!150GB'
        ]), '')
        cmdlist = ['mcsinq', 'lsnaspool', '-delim', '!']
        self.sshMock.return_value = response_for_lsnaspool

        ret = self.assistant.get_available_pools()

        pools = ['pool0', 'pool1']
        self.assertEqual(pools, ret)
        self.sshMock.assert_called_once_with(cmdlist)

    def test_get_pools_attr(self):
        response_for_lsfs = ('\n'.join([
            'pool_name!fs_name!total_capacity!used_capacity',
            'pool0!fs0!10GB!1GB',
            'pool1!fs1!8GB!3GB'
        ]), '')
        call_for_lsfs = mock.call(['mcsinq', 'lsfs', '-delim', '!', '-all'])
        response_for_lsnaspool = ('\n'.join([
            'pool_name!available_capacity',
            'pool0!100GB',
            'pool1!150GB'
        ]), '')
        call_for_lsnaspool = mock.call(['mcsinq', 'lsnaspool', '-delim', '!'])
        self.sshMock.side_effect = [
            response_for_lsfs,
            response_for_lsnaspool
        ]

        ret = self.assistant.get_pools_attr(['pool0'])
        pools = {
            'pool0': {
                'pool_name': 'pool0',
                'total_capacity_gb': 110,
                'free_capacity_gb': 100,
                'allocated_capacity_gb': 10,
                'qos': False,
                'reserved_percentage': 0,
                'reserved_snapshot_percentage': 0,
                'reserved_share_extend_percentage': 0,
                'dedupe': False,
                'compression': False,
                'thin_provisioning': False,
                'max_over_subscription_ratio': 0
            }
        }
        self.assertEqual(pools, ret)
        self.sshMock.assert_has_calls([call_for_lsfs, call_for_lsnaspool])

    def test_get_nodes_info(self):
        response_for_lsnasportip = ('\n'.join([
            'node_name!id!ip!mask!gw!link_state',
            'node1!1!192.168.10.1!255.255.255.0!192.168.10.254!active',
            'node2!1!192.168.10.2!255.255.255.0!192.168.10.254!inactive',
            'node1!2!!!!inactive',
            'node2!2!!!!inactive'
        ]), '')
        call_for_lsnasportip = mock.call([
            'mcsinq', 'lsnasportip', '-delim', '!'
        ])
        self.sshMock.side_effect = [response_for_lsnasportip]

        ret = self.assistant.get_nodes_info()
        nodes = {
            'node1': {
                '1': {
                    'node_name': 'node1',
                    'id': '1',
                    'ip': '192.168.10.1',
                    'mask': '255.255.255.0',
                    'gw': '192.168.10.254',
                    'link_state': 'active'
                }
            },
            'node2': {
                '1': {
                    'node_name': 'node2',
                    'id': '1',
                    'ip': '192.168.10.2',
                    'mask': '255.255.255.0',
                    'gw': '192.168.10.254',
                    'link_state': 'inactive'
                }
            }
        }
        self.assertEqual(nodes, ret)
        self.sshMock.assert_has_calls([call_for_lsnasportip])

    @ddt.data(
        {'name': '1' * 30, 'fsname': '1' * 30},
        {'name': '1' * 40, 'fsname': '1' * 32})
    @ddt.unpack
    def test_get_fsname_by_name(self, name, fsname):
        ret = self.assistant.get_fsname_by_name(name)

        self.assertEqual(fsname, ret)

    @ddt.data(
        {'name': '1' * 30, 'dirname': '1' * 30},
        {'name': '1' * 40, 'dirname': '1' * 32})
    @ddt.unpack
    def test_get_dirsname_by_name(self, name, dirname):
        ret = self.assistant.get_dirname_by_name(name)

        self.assertEqual(dirname, ret)

    @ddt.data(
        {'name': '1' * 30, 'dirpath': '/fs/' + '1' * 30 + '/' + '1' * 30},
        {'name': '1' * 40, 'dirpath': '/fs/' + '1' * 32 + '/' + '1' * 32})
    @ddt.unpack
    def test_get_dirpath_by_name(self, name, dirpath):
        ret = self.assistant.get_dirpath_by_name(name)

        self.assertEqual(dirpath, ret)

    @ddt.data('CIFS', 'NFS')
    def test_create_share(self, proto):
        response_for_lsnasportip = ('\n'.join([
            'node_name!id!ip!mask!gw!link_state',
            'node1!1!192.168.10.1!255.255.255.0!192.168.10.254!active'
        ]), '')
        call_for_lsnasportip = mock.call([
            'mcsinq', 'lsnasportip', '-delim', '!'
        ])
        response_for_addfs = ('', '')
        call_for_addfs = mock.call([
            'mcsop', 'addfs', '-name', '"fakename"', '-pool', '"fakepool"',
            '-size', '10g', '-node', '"node1"'
        ])
        response_for_addnasdir = ('', '')
        call_for_addnasdir = mock.call([
            'mcsop', 'addnasdir', '"/fs/fakename/fakename"'
        ])
        response_for_addcifs = ('', '')
        call_for_addcifs = mock.call([
            'mcsop', 'addcifs', '-name', 'fakename',
            '-path', '/fs/fakename/fakename', '-oplocks', 'off'
        ])

        side_effect = [
            response_for_lsnasportip,
            response_for_addfs,
            response_for_addnasdir
        ]
        calls = [call_for_lsnasportip, call_for_addfs, call_for_addnasdir]
        if proto == 'CIFS':
            side_effect.append(response_for_addcifs)
            calls.append(call_for_addcifs)
        self.sshMock.side_effect = side_effect

        self.assistant.create_share('fakename', 'fakepool', 10, proto)

        self.sshMock.assert_has_calls(calls)

    @ddt.data(True, False)
    def test_check_share_exist(self, exist):
        response_for_lsfs = ('\n'.join([
            'pool_name!fs_name!total_capacity!used_capacity',
            'pool0!fs0!10GB!1GB',
            'pool1!fs1!8GB!3GB'
        ]), '')
        call_for_lsfs = mock.call([
            'mcsinq', 'lsfs', '-delim', '!', '-all'
        ])
        self.sshMock.side_effect = [
            response_for_lsfs
        ]

        share_name = 'fs0' if exist else 'fs2'

        ret = self.assistant.check_share_exist(share_name)

        self.assertEqual(exist, ret)
        self.sshMock.assert_has_calls([call_for_lsfs])

    @ddt.data({'proto': 'CIFS', 'share_exist': False},
              {'proto': 'CIFS', 'share_exist': True},
              {'proto': 'NFS', 'share_exist': False},
              {'proto': 'NFS', 'share_exist': True})
    @ddt.unpack
    def test_delete_share(self, proto, share_exist):
        mock_cse = self.mock_object(
            instorage.InStorageAssistant,
            'check_share_exist',
            mock.Mock(return_value=share_exist)
        )
        response_for_rmcifs = ('', '')
        call_for_rmcifs = mock.call([
            'mcsop', 'rmcifs', 'fakename'
        ])
        response_for_rmnasdir = ('', '')
        call_for_rmnasdir = mock.call([
            'mcsop', 'rmnasdir', '"/fs/fakename/fakename"'
        ])
        response_for_rmfs = ('', '')
        call_for_rmfs = mock.call([
            'mcsop', 'rmfs', '-name', '"fakename"'
        ])

        side_effect = [response_for_rmnasdir, response_for_rmfs]
        calls = [call_for_rmnasdir, call_for_rmfs]
        if proto == 'CIFS':
            side_effect.insert(0, response_for_rmcifs)
            calls.insert(0, call_for_rmcifs)
        self.sshMock.side_effect = side_effect

        self.assistant.delete_share('fakename', proto)

        mock_cse.assert_called_once_with('fakename')
        if share_exist:
            self.sshMock.assert_has_calls(calls)
        else:
            self.sshMock.assert_not_called()

    def test_extend_share(self):
        response_for_lsfs = ('\n'.join([
            'pool_name!fs_name!total_capacity!used_capacity',
            'pool0!fs0!10GB!1GB',
            'pool1!fs1!8GB!3GB'
        ]), '')
        call_for_lsfs = mock.call([
            'mcsinq', 'lsfs', '-delim', '!', '-all'
        ])
        response_for_expandfs = ('', '')
        call_for_expandfs = mock.call([
            'mcsop', 'expandfs', '-name', '"fs0"', '-size', '2g'
        ])
        self.sshMock.side_effect = [response_for_lsfs, response_for_expandfs]

        self.assistant.extend_share('fs0', 12)

        self.sshMock.assert_has_calls([call_for_lsfs, call_for_expandfs])

    @ddt.data('CIFS', 'NFS')
    def test_get_export_locations(self, proto):
        response_for_lsnode = ('\n'.join([
            'id!name',
            '1!node1',
            '2!node2'
        ]), '')
        call_for_lsnode = mock.call([
            'mcsinq', 'lsnode', '-delim', '!'
        ])
        response_for_lsfs_node1 = ('\n'.join([
            'pool_name!fs_name!total_capacity!used_capacity',
            'pool0!fs0!10GB!1GB'
        ]), '')
        call_for_lsfs_node1 = mock.call([
            'mcsinq', 'lsfs', '-delim', '!', '-node', '"node1"'
        ])
        response_for_lsfs_node2 = ('\n'.join([
            'pool_name!fs_name!total_capacity!used_capacity',
            'pool1!fs1!10GB!1GB'
        ]), '')
        call_for_lsfs_node2 = mock.call([
            'mcsinq', 'lsfs', '-delim', '!', '-node', '"node2"'
        ])
        response_for_lsnasportip = ('\n'.join([
            'node_name!id!ip!mask!gw!link_state',
            'node1!1!192.168.10.1!255.255.255.0!192.168.10.254!active',
            'node1!2!192.168.10.2!255.255.255.0!192.168.10.254!active',
            'node1!3!!!!inactive',
            'node2!1!192.168.10.3!255.255.255.0!192.168.10.254!active',
            'node2!2!192.168.10.4!255.255.255.0!192.168.10.254!active',
            'node2!3!!!!inactive'
        ]), '')
        call_for_lsnasportip = mock.call([
            'mcsinq', 'lsnasportip', '-delim', '!'
        ])
        self.sshMock.side_effect = [
            response_for_lsnode,
            response_for_lsfs_node1,
            response_for_lsfs_node2,
            response_for_lsnasportip
        ]
        calls = [
            call_for_lsnode,
            call_for_lsfs_node1,
            call_for_lsfs_node2,
            call_for_lsnasportip
        ]

        ret = self.assistant.get_export_locations('fs1', proto)
        if proto == 'CIFS':
            locations = [
                {
                    'path': '\\\\192.168.10.3\\fs1',
                    'is_admin_only': False,
                    'metadata': {}
                },
                {
                    'path': '\\\\192.168.10.4\\fs1',
                    'is_admin_only': False,
                    'metadata': {}
                }
            ]
        else:
            locations = [
                {
                    'path': '192.168.10.3:/fs/fs1/fs1',
                    'is_admin_only': False,
                    'metadata': {}
                },
                {
                    'path': '192.168.10.4:/fs/fs1/fs1',
                    'is_admin_only': False,
                    'metadata': {}
                }
            ]
        self.assertEqual(locations, ret)
        self.sshMock.assert_has_calls(calls)

    def test_classify_nfs_client_spec_has_nfsinfo(self):
        response_for_lsnfslist = ('\n'.join([
            'path',
            '/fs/fs01/fs01'
        ]), '')
        call_for_lsnfslist = mock.call([
            'mcsinq', 'lsnfslist', '-delim', '!', '"/fs/fs01/fs01"'
        ])
        response_for_lsnfsinfo = ('\n'.join([
            'ip!mask!rights!all_squash!root_squash',
            '192.168.1.0!255.255.255.0!rw!all_squash!root_squash',
            '192.168.2.0!255.255.255.0!rw!all_squash!root_squash'
        ]), '')
        call_for_lsnfsinfo = mock.call([
            'mcsinq', 'lsnfsinfo', '-delim', '!', '"/fs/fs01/fs01"'
        ])
        self.sshMock.side_effect = [
            response_for_lsnfslist, response_for_lsnfsinfo
        ]
        calls = [call_for_lsnfslist, call_for_lsnfsinfo]

        client_spec = [
            '192.168.2.0/255.255.255.0:rw:all_squash:root_squash',
            '192.168.3.0/255.255.255.0:rw:all_squash:root_squash'
        ]
        add_spec, del_spec = self.assistant.classify_nfs_client_spec(
            client_spec, '/fs/fs01/fs01'
        )

        self.assertEqual(
            add_spec, ['192.168.3.0/255.255.255.0:rw:all_squash:root_squash']
        )
        self.assertEqual(
            del_spec, ['192.168.1.0/255.255.255.0:rw:all_squash:root_squash']
        )
        self.sshMock.assert_has_calls(calls)

    def test_classify_nfs_client_spec_has_no_nfsinfo(self):
        cmdlist = [
            'mcsinq', 'lsnfslist', '-delim', '!', '"/fs/fs01/fs01"'
        ]
        self.sshMock.return_value = ('', '')

        client_spec = [
            '192.168.2.0/255.255.255.0:rw:all_squash:root_squash',
        ]
        add_spec, del_spec = self.assistant.classify_nfs_client_spec(
            client_spec, '/fs/fs01/fs01'
        )

        self.assertEqual(client_spec, add_spec)
        self.assertEqual([], del_spec)
        self.sshMock.assert_called_once_with(cmdlist)

    def test_access_rule_to_client_spec(self):
        rule = {
            'access_type': 'ip',
            'access_to': '192.168.10.0/24',
            'access_level': 'rw'
        }

        ret = self.assistant.access_rule_to_client_spec(rule)

        spec = '192.168.10.0/255.255.255.0:rw:all_squash:root_squash'
        self.assertEqual(spec, ret)

    def test_access_rule_to_client_spec_type_failed(self):
        rule = {
            'access_type': 'user',
            'access_to': 'test01',
            'access_level': 'rw'
        }

        self.assertRaises(
            exception.ShareBackendException,
            self.assistant.access_rule_to_client_spec,
            rule
        )

    def test_access_rule_to_client_spec_ipversion_failed(self):
        rule = {
            'access_type': 'ip',
            'access_to': '2001:db8::/64',
            'access_level': 'rw'
        }

        self.assertRaises(
            exception.ShareBackendException,
            self.assistant.access_rule_to_client_spec,
            rule
        )

    @ddt.data(True, False)
    def test_update_nfs_access(self, check_del_add):
        response_for_rmnfsclient = ('', '')
        call_for_rmnfsclient = mock.call(
            ['mcsop', 'rmnfsclient', '-path', '"/fs/fs01/fs01"', '-client',
             '192.168.1.0/255.255.255.0']
        )
        response_for_addnfsclient = ('', '')
        call_for_addnfsclient = mock.call(
            ['mcsop', 'addnfsclient', '-path', '"/fs/fs01/fs01"', '-client',
             '192.168.3.0/255.255.255.0:rw:all_squash:root_squash']
        )
        access_rules = [
            {
                'access_type': 'ip',
                'access_to': '192.168.2.0/24',
                'access_level': 'rw'
            },
            {
                'access_type': 'ip',
                'access_to': '192.168.3.0/24',
                'access_level': 'rw'
            }
        ]
        add_rules = [
            {
                'access_type': 'ip',
                'access_to': '192.168.3.0/24',
                'access_level': 'rw'
            }
        ]
        del_rules = [
            {
                'access_type': 'ip',
                'access_to': '192.168.1.0/24',
                'access_level': 'rw'
            },
            {
                'access_type': 'ip',
                'access_to': '192.168.4.0/24',
                'access_level': 'rw'
            }
        ]

        cncs_mock = mock.Mock(return_value=(
            ['192.168.3.0/255.255.255.0:rw:all_squash:root_squash'],
            ['192.168.1.0/255.255.255.0:rw:all_squash:root_squash']
        ))
        self.mock_object(self.assistant, 'classify_nfs_client_spec', cncs_mock)
        self.sshMock.side_effect = [
            response_for_rmnfsclient, response_for_addnfsclient
        ]

        if check_del_add:
            self.assistant.update_nfs_access('fs01', [], add_rules, del_rules)
        else:
            self.assistant.update_nfs_access('fs01', access_rules, [], [])

        if check_del_add:
            cncs_mock.assert_called_once_with(
                [], '/fs/fs01/fs01'
            )
        else:
            cncs_mock.assert_called_once_with(
                [
                    '192.168.2.0/255.255.255.0:rw:all_squash:root_squash',
                    '192.168.3.0/255.255.255.0:rw:all_squash:root_squash'
                ],
                '/fs/fs01/fs01'
            )

        self.sshMock.assert_has_calls(
            [call_for_rmnfsclient, call_for_addnfsclient]
        )

    def test_classify_cifs_rights(self):
        cmdlist = ['mcsinq', 'lscifsinfo', '-delim', '!', '"fs01"']
        response_for_lscifsinfo = '\n'.join([
            'path!oplocks!type!name!rights',
            '/fs/fs01/fs01!on!LU!user1!rw',
            '/fs/fs01/fs01!on!LU!user2!rw'
        ])
        self.sshMock.return_value = (response_for_lscifsinfo, '')

        access_rights = [
            'LU:user2:rw',
            'LU:user3:rw'
        ]
        add_rights, del_rights = self.assistant.classify_cifs_rights(
            access_rights, 'fs01'
        )

        self.sshMock.assert_called_once_with(cmdlist)
        self.assertEqual(['LU:user3:rw'], add_rights)
        self.assertEqual(['LU:user1:rw'], del_rights)

    def test_access_rule_to_rights(self):
        rule = {
            'access_type': 'user',
            'access_to': 'test01',
            'access_level': 'rw'
        }

        ret = self.assistant.access_rule_to_rights(rule)
        self.assertEqual('LU:test01:rw', ret)

    def test_access_rule_to_rights_fail_type(self):
        rule = {
            'access_type': 'ip',
            'access_to': '192.168.1.0/24',
            'access_level': 'rw'
        }

        self.assertRaises(
            exception.ShareBackendException,
            self.assistant.access_rule_to_rights,
            rule
        )

    @ddt.data(True, False)
    def test_update_cifs_access(self, check_del_add):
        response_for_rmcifsuser = ('', None)
        call_for_rmcifsuser = mock.call(
            ['mcsop', 'rmcifsuser', '-name', 'fs01', '-rights', 'LU:user1']
        )
        response_for_addcifsuser = ('', None)
        call_for_addcifsuser = mock.call(
            ['mcsop', 'addcifsuser', '-name', 'fs01', '-rights', 'LU:user3:rw']
        )
        access_rules = [
            {
                'access_type': 'user',
                'access_to': 'user2',
                'access_level': 'rw'
            },
            {
                'access_type': 'user',
                'access_to': 'user3',
                'access_level': 'rw'
            }
        ]
        add_rules = [
            {
                'access_type': 'user',
                'access_to': 'user3',
                'access_level': 'rw'
            }
        ]
        del_rules = [
            {
                'access_type': 'user',
                'access_to': 'user1',
                'access_level': 'rw'
            }
        ]

        ccr_mock = mock.Mock(return_value=(['LU:user3:rw'], ['LU:user1:rw']))
        self.mock_object(self.assistant, 'classify_cifs_rights', ccr_mock)
        self.sshMock.side_effect = [
            response_for_rmcifsuser, response_for_addcifsuser
        ]

        if check_del_add:
            self.assistant.update_cifs_access('fs01', [], add_rules, del_rules)
        else:
            self.assistant.update_cifs_access('fs01', access_rules, [], [])

        if not check_del_add:
            ccr_mock.assert_called_once_with(
                ['LU:user2:rw', 'LU:user3:rw'], 'fs01'
            )

        self.sshMock.assert_has_calls(
            [call_for_rmcifsuser, call_for_addcifsuser]
        )

    def test_check_access_type(self):
        rules1 = {
            'access_type': 'ip',
            'access_to': '192.168.1.0/24',
            'access_level': 'rw'
        }
        rules2 = {
            'access_type': 'ip',
            'access_to': '192.168.2.0/24',
            'access_level': 'rw'
        }
        rules3 = {
            'access_type': 'user',
            'access_to': 'user1',
            'access_level': 'rw'
        }
        rules4 = {
            'access_type': 'user',
            'access_to': 'user2',
            'access_level': 'rw'
        }

        ret = self.assistant.check_access_type('ip', [rules1], [rules2])
        self.assertTrue(ret)
        ret = self.assistant.check_access_type('user', [rules3], [rules4])
        self.assertTrue(ret)
        ret = self.assistant.check_access_type('ip', [rules1], [rules3])
        self.assertFalse(ret)
        ret = self.assistant.check_access_type('user', [rules3], [rules1])
        self.assertFalse(ret)

    @ddt.data(
        {'proto': 'CIFS', 'ret': True},
        {'proto': 'CIFS', 'ret': False},
        {'proto': 'NFS', 'ret': True},
        {'proto': 'NFS', 'ret': False},
        {'proto': 'unknown', 'ret': True})
    @ddt.unpack
    def test_update_access(self, proto, ret):
        uca_mock = self.mock_object(
            self.assistant, 'update_cifs_access', mock.Mock()
        )
        una_mock = self.mock_object(
            self.assistant, 'update_nfs_access', mock.Mock()
        )
        cat_mock = self.mock_object(
            self.assistant, 'check_access_type', mock.Mock(return_value=ret)
        )

        if proto == 'unknown':
            self.assertRaises(
                exception.ShareBackendException,
                self.assistant.update_access,
                'fs01',
                proto,
                [],
                [],
                []
            )
            cat_mock.assert_not_called()
        elif ret is False:
            self.assertRaises(
                exception.InvalidShareAccess,
                self.assistant.update_access,
                'fs01',
                proto,
                [],
                [],
                []
            )
            cat_mock.assert_called_once()
        else:
            self.assistant.update_access(
                'fs01',
                proto,
                [],
                [],
                []
            )
            if proto == 'CIFS':
                uca_mock.assert_called_once_with('fs01', [], [], [])
                una_mock.assert_not_called()
            else:
                una_mock.assert_called_once_with('fs01', [], [], [])
                uca_mock.assert_not_called()
            cat_mock.assert_called_once()
