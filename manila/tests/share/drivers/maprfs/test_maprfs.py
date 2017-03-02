# Copyright (c) 2016, MapR Technologies
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

"""Unit tests for MapRFS native protocol driver module."""

import mock
from oslo_concurrency import processutils
from oslo_config import cfg
import six

from manila import context
from manila import exception
import manila.share.configuration as config
from manila.share.drivers.maprfs import driver_util as mapru
import manila.share.drivers.maprfs.maprfs_native as maprfs
from manila import test
from manila.tests import fake_share
from manila import utils

CONF = cfg.CONF


class MapRFSNativeShareDriverTestCase(test.TestCase):
    """Tests MapRFSNativeShareDriver."""

    def setUp(self):
        super(MapRFSNativeShareDriverTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._hdfs_execute = mock.Mock(return_value=('', ''))
        self.local_ip = '192.168.1.1'
        CONF.set_default('driver_handles_share_servers', False)
        CONF.set_default('maprfs_clinode_ip', [self.local_ip])
        CONF.set_default('maprfs_ssh_name', 'fake_sshname')
        CONF.set_default('maprfs_ssh_pw', 'fake_sshpw')
        CONF.set_default('maprfs_ssh_private_key', 'fake_sshkey')
        CONF.set_default('maprfs_rename_managed_volume', True)

        self.fake_conf = config.Configuration(None)
        self.cluster_name = 'fake'
        export_locations = {0: {'path': '/share-0'}}
        export_locations[0]['el_metadata'] = {
            'volume-name': 'share-0'}
        self.share = fake_share.fake_share(share_proto='MAPRFS',
                                           name='share-0', size=2, share_id=1,
                                           export_locations=export_locations,
                                           export_location='/share-0')
        self.snapshot = fake_share.fake_snapshot(share_proto='MAPRFS',
                                                 name='fake',
                                                 share_name=self.share['name'],
                                                 share_id=self.share['id'],
                                                 share=self.share,
                                                 share_instance=self.share,
                                                 provider_location='fake')
        self.access = fake_share.fake_access(access_type='user',
                                             access_to='fake',
                                             access_level='rw')

        self.snapshot = self.snapshot.values
        self.snapshot.update(share_instance=self.share)
        self.export_path = 'maprfs:///share-0 -C  -Z  -N fake'
        self.fakesnapshot_path = '/share-0/.snapshot/snapshot-0'
        self.hadoop_bin = '/usr/bin/hadoop'
        self.maprcli_bin = '/usr/bin/maprcli'

        self.mock_object(utils, 'execute')
        self.mock_object(
            mapru.socket, 'gethostname', mock.Mock(return_value='testserver'))
        self.mock_object(
            mapru.socket, 'gethostbyname_ex', mock.Mock(return_value=(
                'localhost',
                ['localhost.localdomain',
                 mapru.socket.gethostname.return_value],
                ['127.0.0.1', self.local_ip])))
        self._driver = maprfs.MapRFSNativeShareDriver(
            configuration=self.fake_conf)
        self._driver.do_setup(self._context)
        self._driver.api.get_share_metadata = mock.Mock(return_value={})
        self._driver.api.update_share_metadata = mock.Mock()

    def test_do_setup(self):
        self._driver.do_setup(self._context)

        self.assertIsNotNone(self._driver._maprfs_util)
        self.assertEqual([self.local_ip], self._driver._maprfs_util.hosts)

    def test_check_for_setup_error(self):
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))
        self._driver._maprfs_util.check_state = mock.Mock(return_value=True)
        self._driver._maprfs_util.maprfs_ls = mock.Mock()

        self._driver.check_for_setup_error()

    def test_check_for_setup_error_exception_config(self):
        self._driver.configuration.maprfs_clinode_ip = None

        self.assertRaises(exception.MapRFSException,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_exception_no_dir(self):
        self._driver._maprfs_util.check_state = mock.Mock(return_value=True)
        self._driver._maprfs_util.maprfs_ls = mock.Mock(
            side_effect=exception.ProcessExecutionError)

        self.assertRaises(exception.MapRFSException,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_exception_cldb_state(self):
        self._driver._check_maprfs_state = mock.Mock(return_value=False)

        self.assertRaises(exception.MapRFSException,
                          self._driver.check_for_setup_error)

    def test__check_maprfs_state_healthy(self):
        fake_out = """Found 8 items
        drwxr-xr-x   - mapr mapr          0 2016-07-29 05:38 /apps"""
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=(fake_out, ''))

        result = self._driver._check_maprfs_state()

        self._driver._maprfs_util._execute.assert_called_once_with(
            self.hadoop_bin, 'fs', '-ls', '/', check_exit_code=False)
        self.assertTrue(result)

    def test__check_maprfs_state_down(self):
        fake_out = "No CLDB"
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=(fake_out, ''))

        result = self._driver._check_maprfs_state()

        self._driver._maprfs_util._execute.assert_called_once_with(
            self.hadoop_bin, 'fs', '-ls', '/', check_exit_code=False)
        self.assertFalse(result)

    def test__check_maprfs_state_exception(self):
        self._driver._maprfs_util._execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)

        self.assertRaises(exception.MapRFSException,
                          self._driver._check_maprfs_state)
        self._driver._maprfs_util._execute.assert_called_once_with(
            self.hadoop_bin, 'fs', '-ls', '/', check_exit_code=False)

    def test_create_share_unsupported_proto(self):
        self._driver.api.get_share_metadata = mock.Mock(return_value={})
        self._driver._get_share_path = mock.Mock()

        self.assertRaises(exception.MapRFSException,
                          self._driver.create_share,
                          self._context,
                          fake_share.fake_share(share_id=1),
                          share_server=None)
        self.assertFalse(self._driver._get_share_path.called)

    def test_manage_existing(self):
        self._driver._maprfs_util.get_volume_info_by_path = mock.Mock(
            return_value={'quota': 1024, 'totalused': 966,
                          'volumename': 'fake'})
        self._driver._maprfs_util._execute = mock.Mock()
        self._driver._maprfs_util.get_cluster_name = mock.Mock(
            return_value="fake")

    def test_manage_existing_no_rename(self):
        self._driver._maprfs_util.get_volume_info_by_path = mock.Mock(
            return_value={'quota': 1024, 'totalused': 966,
                          'volumename': 'fake'})
        self._driver._maprfs_util._execute = mock.Mock()
        self._driver._maprfs_util.get_cluster_name = mock.Mock(
            return_value="fake")

        result = self._driver.manage_existing(self.share, {'rename': 'no'})

        self.assertEqual(1, result['size'])

    def test_manage_existing_exception(self):
        self._driver._maprfs_util.get_volume_info_by_path = mock.Mock(
            side_effect=exception.ProcessExecutionError)

        self.assertRaises(exception.MapRFSException,
                          self._driver.manage_existing, self.share, {})

    def test_manage_existing_invalid_share(self):
        def fake_execute(self, *cmd, **kwargs):
            check_exit_code = kwargs.get('check_exit_code', True)
            if check_exit_code:
                raise exception.ProcessExecutionError
            else:
                return 'No such volume', 0

        self._driver._maprfs_util._execute = fake_execute

        mock_execute = self._driver.manage_existing

        self.assertRaises(exception.ManageInvalidShare, mock_execute,
                          self.share, {})

    def test_manage_existing_snapshot(self):
        self._driver._maprfs_util.get_snapshot_list = mock.Mock(
            return_value=[self.snapshot['provider_location']])
        self._driver._maprfs_util.maprfs_du = mock.Mock(return_value=11)

        update = self._driver.manage_existing_snapshot(self.snapshot, {})

        self.assertEqual(1, update['size'])

    def test_manage_existing_snapshot_invalid(self):
        self._driver._maprfs_util.get_snapshot_list = mock.Mock(
            return_value=[])

        mock_execute = self._driver.manage_existing_snapshot

        self.assertRaises(exception.ManageInvalidShareSnapshot, mock_execute,
                          self.snapshot, {})

    def test_manage_existing_snapshot_exception(self):
        self._driver._maprfs_util.get_snapshot_list = mock.Mock(
            side_effect=exception.ProcessExecutionError)

        mock_execute = self._driver.manage_existing_snapshot

        self.assertRaises(exception.MapRFSException, mock_execute,
                          self.snapshot, {})

    def test_manage_existing_with_no_quota(self):
        self._driver._maprfs_util.get_volume_info_by_path = mock.Mock(
            return_value={'quota': 0, 'totalused': 1999,
                          'volumename': 'fake'})
        self._driver._maprfs_util.rename_volume = mock.Mock()
        self._driver._maprfs_util.get_cluster_name = mock.Mock(
            return_value="fake")

        result = self._driver.manage_existing(self.share, {})

        self.assertEqual(2, result['size'])

    def test__set_volume_size(self):
        volume = self._driver._volume_name(self.share['name'])
        sizestr = six.text_type(self.share['size']) + 'G'
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))

        self._driver._maprfs_util.set_volume_size(volume,
                                                  self.share['size'])

        self._driver._maprfs_util._execute.assert_called_once_with(
            self.maprcli_bin, 'volume', 'modify', '-name', volume, '-quota',
            sizestr)

    def test_extend_share(self):
        volume = self._driver._volume_name(self.share['name'])
        self._driver._maprfs_util.set_volume_size = mock.Mock()

        self._driver.extend_share(self.share, self.share['size'])

        self._driver._maprfs_util.set_volume_size.assert_called_once_with(
            volume, self.share['size'])

    def test_extend_exception(self):
        self._driver._maprfs_util.set_volume_size = mock.Mock(
            side_effect=exception.ProcessExecutionError)

        self.assertRaises(exception.MapRFSException, self._driver.extend_share,
                          self.share, self.share['size'])

    def test_shrink_share(self):
        volume = self._driver._volume_name(self.share['name'])
        self._driver._maprfs_util.set_volume_size = mock.Mock()
        self._driver._maprfs_util.get_volume_info = mock.Mock(
            return_value={'total_user': 0})

        self._driver.shrink_share(self.share, self.share['size'])

        self._driver._maprfs_util.set_volume_size.assert_called_once_with(
            volume, self.share['size'])

    def test_update_access_add(self):
        aces = {
            'volumeAces': {
                'readAce': 'u:fake|fake:fake',
                'writeAce': 'u:fake',
            }
        }
        volume = self._driver._volume_name(self.share['name'])
        self._driver._maprfs_util.get_volume_info = mock.Mock(
            return_value=aces)
        self._driver._maprfs_util.group_exists = mock.Mock(return_value=True)
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))

        self._driver.update_access(self._context, self.share, [self.access],
                                   [self.access], [])

        self._driver._maprfs_util._execute.assert_any_call(
            self.maprcli_bin, 'volume', 'modify', '-name', volume, '-readAce',
            'g:' + self.access['access_to'], '-writeAce',
            'g:' + self.access['access_to'])

    def test_update_access_add_no_user_no_group_exists(self):
        aces = {
            'volumeAces': {
                'readAce': 'u:fake|fake:fake',
                'writeAce': 'u:fake',
            }
        }
        volume = self._driver._volume_name(self.share['name'])
        self._driver._maprfs_util.get_volume_info = mock.Mock(
            return_value=aces)
        self._driver._maprfs_util.group_exists = mock.Mock(return_value=False)
        self._driver._maprfs_util.user_exists = mock.Mock(return_value=False)
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))

        self._driver.update_access(self._context, self.share, [self.access],
                                   [self.access], [])

        self._driver._maprfs_util._execute.assert_any_call(
            self.maprcli_bin, 'volume', 'modify', '-name', volume, '-readAce',
            'g:' + self.access['access_to'], '-writeAce',
            'g:' + self.access['access_to'])

    def test_update_access_delete(self):
        aces = {
            'volumeAces': {
                'readAce': 'p',
                'writeAce': 'p',
            }
        }
        volume = self._driver._volume_name(self.share['name'])
        self._driver._maprfs_util.get_volume_info = mock.Mock(
            return_value=aces)
        self._driver._maprfs_util.group_exists = mock.Mock(return_value=True)
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))

        self._driver.update_access(self._context, self.share, [], [],
                                   [self.access])

        self._driver._maprfs_util._execute.assert_any_call(
            self.maprcli_bin, 'volume', 'modify', '-name', volume, '-readAce',
            '',
            '-writeAce', '')

    def test_update_access_recover(self):
        aces = {
            'volumeAces': {
                'readAce': 'u:fake',
                'writeAce': 'u:fake',
            }
        }
        volume = self._driver._volume_name(self.share['name'])
        self._driver._maprfs_util.get_volume_info = mock.Mock(
            return_value=aces)
        self._driver._maprfs_util.group_exists = mock.Mock(return_value=False)
        self._driver._maprfs_util.user_exists = mock.Mock(return_value=True)
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))

        self._driver.update_access(self._context, self.share, [self.access],
                                   [], [])

        self._driver._maprfs_util._execute.assert_any_call(
            self.maprcli_bin, 'volume', 'modify', '-name', volume, '-readAce',
            'u:' + self.access['access_to'], '-writeAce',
            'u:' + self.access['access_to'])

    def test_update_access_share_not_exists(self):
        self._driver._maprfs_util.volume_exists = mock.Mock(
            return_value=False)
        self._driver._maprfs_util.group_exists = mock.Mock(return_value=True)
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))

        self._driver.update_access(self._context, self.share, [self.access],
                                   [], [])

        self._driver._maprfs_util._execute.assert_not_called()

    def test_update_access_exception(self):
        aces = {
            'volumeAces': {
                'readAce': 'p',
                'writeAce': 'p',
            }
        }
        self._driver._maprfs_util.get_volume_info = mock.Mock(
            return_value=aces)
        self._driver._maprfs_util.group_exists = mock.Mock(return_value=True)
        utils.execute = mock.Mock(
            side_effect=exception.ProcessExecutionError(stdout='ERROR'))

        self.assertRaises(exception.MapRFSException,
                          self._driver.update_access, self._context,
                          self.share, [self.access], [], [])

    def test_update_access_invalid_access(self):
        access = fake_share.fake_access(access_type='ip', access_to='fake',
                                        access_level='rw')

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.update_access, self._context,
                          self.share, [access], [], [])

    def test_ensure_share(self):
        self._driver._maprfs_util.volume_exists = mock.Mock(
            return_value=True)
        self._driver._maprfs_util.get_volume_info = mock.Mock(
            return_value={'mountdir': self.share['export_location']})
        self._driver._maprfs_util.get_cluster_name = mock.Mock(
            return_value=self.cluster_name)

        result = self._driver.ensure_share(self._context, self.share)

        self.assertEqual(self.export_path, result[0]['path'])

    def test_create_share(self):
        size_str = six.text_type(self.share['size']) + 'G'
        path = self._driver._share_dir(self.share['name'])
        self._driver.api.get_share_metadata = mock.Mock(
            return_value={'_fake': 'fake'})
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))
        self._driver._maprfs_util.set_volume_size = mock.Mock()
        self._driver._maprfs_util.maprfs_chmod = mock.Mock()
        self._driver._maprfs_util.get_cluster_name = mock.Mock(
            return_value=self.cluster_name)

        self._driver.create_share(self._context, self.share)

        self._driver._maprfs_util._execute.assert_called_once_with(
            self.maprcli_bin, 'volume', 'create', '-name', self.share['name'],
            '-path', path, '-quota', size_str, '-readAce', '', '-writeAce', '',
            '-fake', 'fake')
        self._driver._maprfs_util.maprfs_chmod.assert_called_once_with(path,
                                                                       '777')

    def test_create_share_with_custom_name(self):
        size_str = six.text_type(self.share['size']) + 'G'
        self._driver.api.get_share_metadata = mock.Mock(
            return_value={'_name': 'fake', '_path': 'fake'})
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))
        self._driver._maprfs_util.set_volume_size = mock.Mock()
        self._driver._maprfs_util.maprfs_chmod = mock.Mock()
        self._driver._maprfs_util.get_cluster_name = mock.Mock(
            return_value=self.cluster_name)

        self._driver.create_share(self._context, self.share)

        self._driver._maprfs_util._execute.assert_called_once_with(
            self.maprcli_bin, 'volume', 'create', '-name', 'fake',
            '-path', 'fake', '-quota', size_str, '-readAce', '', '-writeAce',
            '')
        self._driver._maprfs_util.maprfs_chmod.assert_called_once_with('fake',
                                                                       '777')

    def test_create_share_exception(self):
        self._driver.api.get_share_metadata = mock.Mock(return_value={})
        self._driver._maprfs_util._execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self._driver._maprfs_util.set_volume_size = mock.Mock()
        self._driver._maprfs_util.maprfs_chmod = mock.Mock()
        self._driver._maprfs_util.get_cluster_name = mock.Mock(
            return_value=self.cluster_name)

        self.assertRaises(exception.MapRFSException, self._driver.create_share,
                          self._context, self.share)

    def test_create_share_from_snapshot(self):
        fake_snapshot = dict(self.snapshot)
        fake_snapshot.update(share_instance={'share_id': 1})
        size_str = six.text_type(self.share['size']) + 'G'
        path = self._driver._share_dir(self.share['name'])
        snapthot_path = self._driver._get_snapshot_path(self.snapshot) + '/*'
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=('Found', 0))
        self._driver._maprfs_util.set_volume_size = mock.Mock()
        self._driver._maprfs_util.get_cluster_name = mock.Mock(
            return_value=self.cluster_name)
        self._driver.api.get_share_metadata = mock.Mock(
            return_value={'_fake': 'fake', 'fake2': 'fake2'})
        mock_execute = self._driver._maprfs_util._execute

        self._driver.create_share_from_snapshot(self._context, self.share,
                                                self.snapshot)

        mock_execute.assert_any_call(self.hadoop_bin, 'fs', '-cp', '-p',
                                     snapthot_path, path)
        mock_execute.assert_any_call(self.maprcli_bin, 'volume', 'create',
                                     '-name',
                                     self.share['name'], '-path', path,
                                     '-quota', size_str, '-readAce', '',
                                     '-writeAce', '', '-fake', 'fake')

    def test_create_share_from_snapshot_wrong_tenant(self):
        fake_snapshot = dict(self.snapshot)
        fake_snapshot.update(share_instance={'share_id': 10})
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))
        self._driver._maprfs_util.set_volume_size = mock.Mock()
        self._driver._maprfs_util.get_cluster_name = mock.Mock(
            return_value=self.cluster_name)

        def fake_meta(context, share):
            return {'_tenantuser': 'fake'} if share['id'] == 10 else {}

        self._driver.api.get_share_metadata = fake_meta

        self.assertRaises(exception.MapRFSException,
                          self._driver.create_share_from_snapshot,
                          self._context, self.share, fake_snapshot)

    def test_create_share_from_snapshot_exception(self):
        fake_snapshot = dict(self.snapshot)
        fake_snapshot.update(share_instance={'share_id': 10})
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=('Found 0', 0))
        self._driver._maprfs_util.maprfs_cp = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self._driver.api.get_share_metadata = mock.Mock(
            return_value={'_tenantuser': 'fake'})

        self.assertRaises(exception.MapRFSException,
                          self._driver.create_share_from_snapshot,
                          self._context, self.share, self.snapshot)

    def test_delete_share(self):
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))

        self._driver.delete_share(self._context, self.share)

        self._driver._maprfs_util._execute.assert_called_once_with(
            self.maprcli_bin, 'volume', 'remove', '-name', self.share['name'],
            '-force', 'true', check_exit_code=False)

    def test_delete_share_skip(self):
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))
        self._driver.api.get_share_metadata = mock.Mock(
            return_value={'_name': 'error'})

        self._driver.delete_share(self._context, self.share)

        self._driver._maprfs_util._execute.assert_not_called()

    def test_delete_share_exception(self):
        self._driver._maprfs_util._execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)

        self.assertRaises(exception.MapRFSException, self._driver.delete_share,
                          self._context, self.share)

    def test_delete_share_not_exist(self):
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=('No such volume', 0))

        self._driver.delete_share(self._context, self.share)

    def test_create_snapshot(self):
        volume = self._driver._volume_name(self.share['name'])
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))

        self._driver.create_snapshot(self._context, self.snapshot)

        self._driver._maprfs_util._execute.assert_called_once_with(
            self.maprcli_bin, 'volume', 'snapshot', 'create', '-snapshotname',
            self.snapshot['name'], '-volume', volume)

    def test_create_snapshot_exception(self):
        self._driver._maprfs_util._execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)

        self.assertRaises(exception.MapRFSException,
                          self._driver.create_snapshot, self._context,
                          self.snapshot)

    def test_delete_snapshot(self):
        volume = self._driver._volume_name(self.share['name'])
        self._driver._maprfs_util._execute = mock.Mock(return_value=('', 0))

        self._driver.delete_snapshot(self._context, self.snapshot)

        self._driver._maprfs_util._execute.assert_called_once_with(
            self.maprcli_bin, 'volume', 'snapshot', 'remove', '-snapshotname',
            self.snapshot['name'], '-volume', volume, check_exit_code=False)

    def test_delete_snapshot_exception(self):
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=('ERROR (fake)', None))

        self.assertRaises(exception.MapRFSException,
                          self._driver.delete_snapshot,
                          self._context, self.snapshot)

    def test__execute(self):
        first_host_skip = 'first'
        available_host = 'available'
        hosts = [first_host_skip, self.local_ip, available_host, 'extra']
        test_config = mock.Mock()
        test_config.maprfs_clinode_ip = hosts
        test_config.maprfs_ssh_name = 'fake_maprfs_ssh_name'
        test_maprfs_util = mapru.get_version_handler(test_config)
        # mutable container
        done = [False]
        skips = []

        def fake_ssh_run(host, cmd, check_exit_code):
            if host == available_host:
                done[0] = True
                return '', 0
            else:
                skips.append(host)
                raise Exception()

        test_maprfs_util._run_ssh = fake_ssh_run

        test_maprfs_util._execute('fake', 'cmd')

        self.assertTrue(done[0])
        self.assertEqual(available_host, test_maprfs_util.hosts[0])
        self.assertEqual(first_host_skip, test_maprfs_util.hosts[2])
        self.assertEqual([first_host_skip], skips)
        utils.execute.assert_called_once_with(
            'sudo', 'su', '-', 'fake_maprfs_ssh_name', '-c', 'fake cmd',
            check_exit_code=True)

    def test__execute_exeption(self):
        utils.execute = mock.Mock(side_effect=Exception)

        self.assertRaises(exception.ProcessExecutionError,
                          self._driver._maprfs_util._execute, "fake", "cmd")

    def test__execute_native_exeption(self):
        utils.execute = mock.Mock(
            side_effect=exception.ProcessExecutionError(stdout='fake'))

        self.assertRaises(exception.ProcessExecutionError,
                          self._driver._maprfs_util._execute, "fake", "cmd")

    def test__execute_local(self):
        self.mock_object(utils, 'execute', mock.Mock(return_value=("fake", 0)))

        self._driver._maprfs_util._execute("fake", "cmd")

        utils.execute.assert_called_once_with('sudo', 'su', '-',
                                              'fake_sshname', '-c', 'fake cmd',
                                              check_exit_code=True)

    def test_share_shrink_error(self):
        fake_info = {
            'totalused': 1024,
            'quota': 2024
        }
        self._driver._maprfs_util._execute = mock.Mock()
        self._driver._maprfs_util.get_volume_info = mock.Mock(
            return_value=fake_info)

        self.assertRaises(exception.ShareShrinkingPossibleDataLoss,
                          self._driver.shrink_share, self.share, 1)

    def test__get_volume_info(self):
        fake_out = """
        {"data": [{"mounted":1,"quota":"1024","used":"0","totalused":"0"}]}
        """
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=(fake_out, 0))

        result = self._driver._maprfs_util.get_volume_info('fake_name')

        self.assertEqual('0', result['used'])

    def test__get_volume_info_by_path(self):
        fake_out = """
        {"data": [{"mounted":1,"quota":"1024","used":"0","totalused":"0"}]}
        """
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=(fake_out, 0))

        result = self._driver._maprfs_util.get_volume_info_by_path('fake_path')

        self.assertEqual('0', result['used'])

    def test__get_volume_info_by_path_not_exist(self):
        fake_out = "No such volume"
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=(fake_out, 0))

        result = self._driver._maprfs_util.get_volume_info_by_path(
            'fake_path', check_if_exists=True)

        self.assertIsNone(result)

    def test_get_share_stats_refresh_false(self):
        self._driver._stats = {'fake_key': 'fake_value'}

        result = self._driver.get_share_stats(False)

        self.assertEqual(self._driver._stats, result)

    def test_get_share_stats_refresh_true(self):
        self._driver._maprfs_util.fs_capacity = mock.Mock(
            return_value=(1143554.0, 124111.0))

        result = self._driver.get_share_stats(True)

        expected_keys = [
            'qos', 'driver_version', 'share_backend_name',
            'free_capacity_gb', 'total_capacity_gb',
            'driver_handles_share_servers',
            'reserved_percentage', 'vendor_name', 'storage_protocol',
        ]
        for key in expected_keys:
            self.assertIn(key, result)
        self.assertEqual('MAPRFS', result['storage_protocol'])
        self._driver._maprfs_util.fs_capacity.assert_called_once_with()

    def test_get_share_stats_refresh_exception(self):
        self._driver._maprfs_util.fs_capacity = mock.Mock(
            side_effect=exception.ProcessExecutionError)

        self.assertRaises(exception.MapRFSException,
                          self._driver.get_share_stats, True)

    def test__get_available_capacity(self):
        fake_out = """Filesystem         Size        Used    Available  Use%
        maprfs:///  26367492096  1231028224  25136463872    5%
        """
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=(fake_out, ''))

        total, free = self._driver._maprfs_util.fs_capacity()

        self._driver._maprfs_util._execute.assert_called_once_with(
            self.hadoop_bin, 'fs', '-df')
        self.assertEqual(26367492096, total)
        self.assertEqual(25136463872, free)

    def test__get_available_capacity_exception(self):
        fake_out = 'fake'
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=(fake_out, ''))

        self.assertRaises(exception.ProcessExecutionError,
                          self._driver._maprfs_util.fs_capacity)

    def test__get_snapshot_list(self):
        fake_out = """{"data":[{"snapshotname":"fake-snapshot"}]}"""
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=(fake_out, None))

        snapshot_list = self._driver._maprfs_util.get_snapshot_list(
            volume_name='fake', volume_path='fake')

        self.assertEqual(['fake-snapshot'], snapshot_list)

    def test__cluster_name(self):
        fake_info = """{
        "data":[
            {
                "version":"fake",
                "cluster":{
                    "name":"fake",
                    "secure":false,
                    "ip":"10.10.10.10",
                    "id":"7133813101868836065",
                    "nodesUsed":1,
                    "totalNodesAllowed":-1
                }
            }
            ]
        }
        """
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=(fake_info, 0))

        name = self._driver._maprfs_util.get_cluster_name()

        self.assertEqual('fake', name)

    def test__cluster_name_exception(self):
        fake_info = 'fake'

        self._driver._maprfs_util._execute = mock.Mock(
            return_value=(fake_info, 0))

        self.assertRaises(exception.ProcessExecutionError,
                          self._driver._maprfs_util.get_cluster_name)

    def test__run_ssh(self):
        ssh_output = 'fake_ssh_output'
        cmd_list = ['fake', 'cmd']
        ssh = mock.Mock()
        ssh.get_transport = mock.Mock()
        ssh.get_transport().is_active = mock.Mock(return_value=False)
        ssh_pool = mock.Mock()
        ssh_pool.create = mock.Mock(return_value=ssh)
        self.mock_object(utils, 'SSHPool', mock.Mock(return_value=ssh_pool))
        self.mock_object(processutils, 'ssh_execute',
                         mock.Mock(return_value=ssh_output))
        result = self._driver._maprfs_util._run_ssh(self.local_ip, cmd_list)
        utils.SSHPool.assert_called_once_with(
            self._driver.configuration.maprfs_clinode_ip[0],
            self._driver.configuration.maprfs_ssh_port,
            self._driver.configuration.ssh_conn_timeout,
            self._driver.configuration.maprfs_ssh_name,
            password=self._driver.configuration.maprfs_ssh_pw,
            privatekey=self._driver.configuration.maprfs_ssh_private_key,
            min_size=self._driver.configuration.ssh_min_pool_conn,
            max_size=self._driver.configuration.ssh_max_pool_conn)
        ssh_pool.create.assert_called()
        ssh.get_transport().is_active.assert_called_once_with()
        processutils.ssh_execute.assert_called_once_with(
            ssh, 'fake cmd', check_exit_code=False)
        self.assertEqual(ssh_output, result)

    def test__run_ssh_exception(self):
        cmd_list = ['fake', 'cmd']
        ssh = mock.Mock()
        ssh.get_transport = mock.Mock()
        ssh.get_transport().is_active = mock.Mock(return_value=True)
        ssh_pool = mock.Mock()
        ssh_pool.create = mock.Mock(return_value=ssh)
        self.mock_object(utils, 'SSHPool', mock.Mock(return_value=ssh_pool))
        self.mock_object(processutils, 'ssh_execute', mock.Mock(
            side_effect=exception.ProcessExecutionError))
        self.assertRaises(exception.ProcessExecutionError,
                          self._driver._maprfs_util._run_ssh,
                          self.local_ip,
                          cmd_list)
        utils.SSHPool.assert_called_once_with(
            self._driver.configuration.maprfs_clinode_ip[0],
            self._driver.configuration.maprfs_ssh_port,
            self._driver.configuration.ssh_conn_timeout,
            self._driver.configuration.maprfs_ssh_name,
            password=self._driver.configuration.maprfs_ssh_pw,
            privatekey=self._driver.configuration.maprfs_ssh_private_key,
            min_size=self._driver.configuration.ssh_min_pool_conn,
            max_size=self._driver.configuration.ssh_max_pool_conn)
        ssh_pool.create.assert_called_once_with()
        ssh.get_transport().is_active.assert_called_once_with()
        processutils.ssh_execute.assert_called_once_with(
            ssh, 'fake cmd', check_exit_code=False)

    def test__share_dir(self):
        self._driver._base_volume_dir = '/volumes'
        share_dir = '/volumes/' + self.share['name']
        actual_dir = self._driver._share_dir(self.share['name'])

        self.assertEqual(share_dir, actual_dir)

    def test__get_volume_name(self):
        volume_name = self._driver._get_volume_name("fake", self.share)

        self.assertEqual('share-0', volume_name)

    def test__maprfs_du(self):
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=('1024 /', 0))

        size = self._driver._maprfs_util.maprfs_du('/')

        self._driver._maprfs_util._execute.assert_called()
        self.assertEqual(1024, size)

    def test__maprfs_ls(self):
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=('fake', 0))

        self._driver._maprfs_util.maprfs_ls('/')

        self._driver._maprfs_util._execute.assert_called_with(self.hadoop_bin,
                                                              'fs', '-ls', '/')

    def test_rename_volume(self):
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=('fake', 0))

        self._driver._maprfs_util.rename_volume('fake', 'newfake')

        self._driver._maprfs_util._execute.assert_called_with(self.maprcli_bin,
                                                              'volume',
                                                              'rename',
                                                              '-name', 'fake',
                                                              '-newname',
                                                              'newfake')

    def test__run_as_user(self):
        cmd = ['fake', 'cmd']
        u_cmd = self._driver._maprfs_util._as_user(cmd, 'user')

        self.assertEqual(['sudo', 'su', '-', 'user', '-c', 'fake cmd'], u_cmd)

    def test__add_params(self):
        params = {'p1': 1, 'p2': 2, 'p3': '3'}
        cmd = ['fake', 'cmd']
        cmd_with_params = self._driver._maprfs_util._add_params(cmd, **params)

        self.assertEqual(cmd[:2], cmd_with_params[:2])

    def test_get_network_allocations_number(self):
        number = self._driver.get_admin_network_allocations_number()

        self.assertEqual(0, number)

    def test__user_exists(self):
        fake_out = 'user:x:1000:1000::/opt/user:/bin/bash'
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=(fake_out, 0))

        result = self._driver._maprfs_util.user_exists('user')

        self.assertTrue(result)

    def test__group_exists(self):
        fake_out = 'user:x:1000:'
        self._driver._maprfs_util._execute = mock.Mock(
            return_value=(fake_out, 0))

        result = self._driver._maprfs_util.group_exists('user')

        self.assertTrue(result)
