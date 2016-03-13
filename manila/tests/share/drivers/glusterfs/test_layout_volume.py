# Copyright (c) 2014 Red Hat, Inc.
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

""" GlusterFS volume mapped share layout testcases.
"""

import re
import shutil
import tempfile

import ddt
import mock
from oslo_config import cfg

from manila.common import constants
from manila import context
from manila import exception
from manila.share import configuration as config
from manila.share.drivers.glusterfs import common
from manila.share.drivers.glusterfs import layout_volume
from manila import test
from manila.tests import fake_utils


CONF = cfg.CONF


def new_share(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'glusterfs',
    }
    share.update(kwargs)
    return share


def glusterXMLOut(**kwargs):

    template = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cliOutput>
  <opRet>%(ret)d</opRet>
  <opErrno>%(errno)d</opErrno>
  <opErrstr>fake error</opErrstr>
</cliOutput>"""

    return template % kwargs, ''


FAKE_UUID1 = '11111111-1111-1111-1111-111111111111'
FAKE_UUID2 = '22222222-2222-2222-2222-222222222222'


@ddt.ddt
class GlusterfsVolumeMappedLayoutTestCase(test.TestCase):
    """Tests GlusterfsVolumeMappedLayout."""

    def setUp(self):
        super(GlusterfsVolumeMappedLayoutTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self)
        self._execute = fake_utils.fake_execute
        self._context = context.get_admin_context()

        self.glusterfs_target1 = 'root@host1:/gv1'
        self.glusterfs_target2 = 'root@host2:/gv2'
        self.glusterfs_server1 = 'root@host1'
        self.glusterfs_server2 = 'root@host2'
        self.glusterfs_server1_volumes = 'manila-share-1-1G\nshare1'
        self.glusterfs_server2_volumes = 'manila-share-2-2G\nshare2'
        self.share1 = new_share(
            export_location=self.glusterfs_target1,
            status=constants.STATUS_AVAILABLE)
        self.share2 = new_share(
            export_location=self.glusterfs_target2,
            status=constants.STATUS_AVAILABLE)
        gmgr = common.GlusterManager
        self.gmgr1 = gmgr(self.glusterfs_server1, self._execute, None, None,
                          requires={'volume': False})
        self.gmgr2 = gmgr(self.glusterfs_server2, self._execute, None, None,
                          requires={'volume': False})
        self.glusterfs_volumes_dict = (
            {'root@host1:/manila-share-1-1G': {'size': 1},
             'root@host2:/manila-share-2-2G': {'size': 2}})
        self.glusterfs_used_vols = set([
            'root@host1:/manila-share-1-1G',
            'root@host2:/manila-share-2-2G'])

        CONF.set_default('glusterfs_servers',
                         [self.glusterfs_server1, self.glusterfs_server2])
        CONF.set_default('glusterfs_server_password',
                         'fake_password')
        CONF.set_default('glusterfs_path_to_private_key',
                         '/fakepath/to/privatekey')
        CONF.set_default('glusterfs_volume_pattern',
                         'manila-share-\d+-#{size}G$')
        CONF.set_default('driver_handles_share_servers', False)

        self.fake_driver = mock.Mock()
        self.mock_object(self.fake_driver, '_execute',
                         self._execute)
        self.fake_driver.GLUSTERFS_VERSION_MIN = (3, 6)

        self.fake_conf = config.Configuration(None)
        self.mock_object(tempfile, 'mkdtemp',
                         mock.Mock(return_value='/tmp/tmpKGHKJ'))
        self.mock_object(common.GlusterManager, 'make_gluster_call')

        self.fake_private_storage = mock.Mock()

        with mock.patch.object(layout_volume.GlusterfsVolumeMappedLayout,
                               '_glustermanager',
                               side_effect=[self.gmgr1, self.gmgr2]):
            self._layout = layout_volume.GlusterfsVolumeMappedLayout(
                self.fake_driver, configuration=self.fake_conf,
                private_storage=self.fake_private_storage)
        self._layout.glusterfs_versions = {self.glusterfs_server1: ('3', '6'),
                                           self.glusterfs_server2: ('3', '7')}
        self.addCleanup(fake_utils.fake_execute_set_repliers, [])
        self.addCleanup(fake_utils.fake_execute_clear_log)

    @ddt.data({"test_kwargs": {}, "requires": {"volume": True}},
              {"test_kwargs": {'req_volume': False},
               "requires": {"volume": False}})
    @ddt.unpack
    def test_glustermanager(self, test_kwargs, requires):
        fake_obj = mock.Mock()
        self.mock_object(common, 'GlusterManager',
                         mock.Mock(return_value=fake_obj))

        ret = self._layout._glustermanager(self.glusterfs_target1,
                                           **test_kwargs)

        common.GlusterManager.assert_called_once_with(
            self.glusterfs_target1, self._execute,
            self._layout.configuration.glusterfs_path_to_private_key,
            self._layout.configuration.glusterfs_server_password,
            requires=requires)
        self.assertEqual(fake_obj, ret)

    def test_compile_volume_pattern(self):
        volume_pattern = 'manila-share-\d+-(?P<size>\d+)G$'

        ret = self._layout._compile_volume_pattern()

        self.assertEqual(re.compile(volume_pattern), ret)

    @ddt.data({'root@host1:/manila-share-1-1G': 'NONE',
               'root@host2:/manila-share-2-2G': None},
              {'root@host1:/manila-share-1-1G': FAKE_UUID1,
               'root@host2:/manila-share-2-2G': None},
              {'root@host1:/manila-share-1-1G': 'foobarbaz',
               'root@host2:/manila-share-2-2G': FAKE_UUID2},
              {'root@host1:/manila-share-1-1G': FAKE_UUID1,
               'root@host2:/manila-share-2-2G': FAKE_UUID2})
    def test_fetch_gluster_volumes(self, sharemark):
        vol1_qualified = 'root@host1:/manila-share-1-1G'
        gmgr_vol1 = common.GlusterManager(vol1_qualified)
        gmgr_vol1.get_vol_option = mock.Mock(
            return_value=sharemark[vol1_qualified])
        vol2_qualified = 'root@host2:/manila-share-2-2G'
        gmgr_vol2 = common.GlusterManager(vol2_qualified)
        gmgr_vol2.get_vol_option = mock.Mock(
            return_value=sharemark[vol2_qualified])
        self.mock_object(
            self.gmgr1, 'gluster_call',
            mock.Mock(return_value=(self.glusterfs_server1_volumes, '')))
        self.mock_object(
            self.gmgr2, 'gluster_call',
            mock.Mock(return_value=(self.glusterfs_server2_volumes, '')))
        _glustermanager_calls = (self.gmgr1, gmgr_vol1, self.gmgr2, gmgr_vol2)
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(side_effect=_glustermanager_calls))
        expected_output = {}
        for q, d in self.glusterfs_volumes_dict.items():
            if sharemark[q] not in (FAKE_UUID1, FAKE_UUID2):
                expected_output[q] = d

        ret = self._layout._fetch_gluster_volumes()

        test_args = ('volume', 'list')
        self.gmgr1.gluster_call.assert_called_once_with(*test_args,
                                                        log=mock.ANY)
        self.gmgr2.gluster_call.assert_called_once_with(*test_args,
                                                        log=mock.ANY)
        gmgr_vol1.get_vol_option.assert_called_once_with(
            'user.manila-share')
        gmgr_vol2.get_vol_option.assert_called_once_with(
            'user.manila-share')
        self.assertEqual(expected_output, ret)

    def test_fetch_gluster_volumes_no_filter_used(self):
        vol1_qualified = 'root@host1:/manila-share-1-1G'
        gmgr_vol1 = common.GlusterManager(vol1_qualified)
        gmgr_vol1.get_vol_option = mock.Mock()
        vol2_qualified = 'root@host2:/manila-share-2-2G'
        gmgr_vol2 = common.GlusterManager(vol2_qualified)
        gmgr_vol2.get_vol_option = mock.Mock()
        self.mock_object(
            self.gmgr1, 'gluster_call',
            mock.Mock(return_value=(self.glusterfs_server1_volumes, '')))
        self.mock_object(
            self.gmgr2, 'gluster_call',
            mock.Mock(return_value=(self.glusterfs_server2_volumes, '')))
        _glustermanager_calls = (self.gmgr1, gmgr_vol1, self.gmgr2, gmgr_vol2)
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(side_effect=_glustermanager_calls))
        expected_output = self.glusterfs_volumes_dict

        ret = self._layout._fetch_gluster_volumes(filter_used=False)

        test_args = ('volume', 'list')
        self.gmgr1.gluster_call.assert_called_once_with(*test_args,
                                                        log=mock.ANY)
        self.gmgr2.gluster_call.assert_called_once_with(*test_args,
                                                        log=mock.ANY)
        self.assertFalse(gmgr_vol1.get_vol_option.called)
        self.assertFalse(gmgr_vol2.get_vol_option.called)
        self.assertEqual(expected_output, ret)

    def test_fetch_gluster_volumes_no_keymatch(self):
        vol1_qualified = 'root@host1:/manila-share-1'
        gmgr_vol1 = common.GlusterManager(vol1_qualified)
        gmgr_vol1.get_vol_option = mock.Mock(return_value=None)
        self._layout.configuration.glusterfs_servers = [self.glusterfs_server1]
        self.mock_object(
            self.gmgr1, 'gluster_call',
            mock.Mock(return_value=('manila-share-1', '')))
        _glustermanager_calls = (self.gmgr1, gmgr_vol1)
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(side_effect=_glustermanager_calls))
        self.mock_object(self._layout, 'volume_pattern',
                         re.compile('manila-share-\d+(-(?P<size>\d+)G)?$'))
        expected_output = {'root@host1:/manila-share-1': {'size': None}}

        ret = self._layout._fetch_gluster_volumes()

        test_args = ('volume', 'list')
        self.gmgr1.gluster_call.assert_called_once_with(*test_args,
                                                        log=mock.ANY)
        self.assertEqual(expected_output, ret)

    def test_fetch_gluster_volumes_error(self):
        test_args = ('volume', 'list')

        def raise_exception(*args, **kwargs):
            if(args == test_args):
                raise exception.GlusterfsException()

        self._layout.configuration.glusterfs_servers = [self.glusterfs_server1]
        self.mock_object(self.gmgr1, 'gluster_call',
                         mock.Mock(side_effect=raise_exception))
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=self.gmgr1))
        self.mock_object(layout_volume.LOG, 'error')

        self.assertRaises(exception.GlusterfsException,
                          self._layout._fetch_gluster_volumes)

        self.gmgr1.gluster_call.assert_called_once_with(*test_args,
                                                        log=mock.ANY)

    def test_do_setup(self):
        self._layout.configuration.glusterfs_servers = [self.glusterfs_server1]
        self.mock_object(self.gmgr1, 'get_gluster_version',
                         mock.Mock(return_value=('3', '6')))
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=self.gmgr1))
        self.mock_object(self._layout, '_fetch_gluster_volumes',
                         mock.Mock(return_value=self.glusterfs_volumes_dict))
        self.mock_object(self._layout, '_check_mount_glusterfs')
        self._layout.gluster_used_vols = self.glusterfs_used_vols
        self.mock_object(layout_volume.LOG, 'warning')

        self._layout.do_setup(self._context)

        self._layout._fetch_gluster_volumes.assert_called_once_with(
            filter_used=False)
        self._layout._check_mount_glusterfs.assert_called_once_with()
        self.gmgr1.get_gluster_version.assert_called_once_with()

    def test_do_setup_unsupported_glusterfs_version(self):
        self._layout.configuration.glusterfs_servers = [self.glusterfs_server1]
        self.mock_object(self.gmgr1, 'get_gluster_version',
                         mock.Mock(return_value=('3', '5')))
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=self.gmgr1))

        self.assertRaises(exception.GlusterfsException,
                          self._layout.do_setup, self._context)

        self.gmgr1.get_gluster_version.assert_called_once_with()

    @ddt.data(exception.GlusterfsException, RuntimeError)
    def test_do_setup_get_gluster_version_fails(self, exc):
        def raise_exception(*args, **kwargs):
            raise exc

        self._layout.configuration.glusterfs_servers = [self.glusterfs_server1]
        self.mock_object(self.gmgr1, 'get_gluster_version',
                         mock.Mock(side_effect=raise_exception))
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=self.gmgr1))

        self.assertRaises(exc, self._layout.do_setup, self._context)

        self.gmgr1.get_gluster_version.assert_called_once_with()

    def test_do_setup_glusterfs_no_volumes_provided_by_backend(self):
        self._layout.configuration.glusterfs_servers = [self.glusterfs_server1]
        self.mock_object(self.gmgr1, 'get_gluster_version',
                         mock.Mock(return_value=('3', '6')))
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=self.gmgr1))
        self.mock_object(self._layout, '_fetch_gluster_volumes',
                         mock.Mock(return_value={}))

        self.assertRaises(exception.GlusterfsException,
                          self._layout.do_setup, self._context)

        self._layout._fetch_gluster_volumes.assert_called_once_with(
            filter_used=False)

    def test_share_manager(self):
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=self.gmgr1))
        self.mock_object(self._layout.private_storage,
                         'get', mock.Mock(return_value='host1:/gv1'))

        ret = self._layout._share_manager(self.share1)

        self._layout.private_storage.get.assert_called_once_with(
            self.share1['id'], 'volume')
        self._layout._glustermanager.assert_called_once_with('host1:/gv1')
        self.assertEqual(self.gmgr1, ret)

    def test_share_manager_no_privdata(self):
        self.mock_object(self._layout.private_storage,
                         'get', mock.Mock(return_value=None))

        ret = self._layout._share_manager(self.share1)

        self._layout.private_storage.get.assert_called_once_with(
            self.share1['id'], 'volume')
        self.assertEqual(None, ret)

    def test_ensure_share(self):
        share = self.share1
        gmgr1 = common.GlusterManager(self.glusterfs_target1, self._execute,
                                      None, None)
        gmgr1.set_vol_option = mock.Mock()
        self.mock_object(self._layout, '_share_manager',
                         mock.Mock(return_value=gmgr1))

        self._layout.ensure_share(self._context, share)

        self._layout._share_manager.assert_called_once_with(share)
        self.assertIn(self.glusterfs_target1, self._layout.gluster_used_vols)
        gmgr1.set_vol_option.assert_called_once_with(
            'user.manila-share', share['id'])

    @ddt.data({"voldict": {"host:/share2G": {"size": 2}}, "used_vols": set(),
               "size": 1, "expected": "host:/share2G"},
              {"voldict": {"host:/share2G": {"size": 2}}, "used_vols": set(),
               "size": 2, "expected": "host:/share2G"},
              {"voldict": {"host:/share2G": {"size": 2}}, "used_vols": set(),
               "size": None, "expected": "host:/share2G"},
              {"voldict": {"host:/share2G": {"size": 2},
                           "host:/share": {"size": None}},
               "used_vols": set(["host:/share2G"]), "size": 1,
               "expected": "host:/share"},
              {"voldict": {"host:/share2G": {"size": 2},
                           "host:/share": {"size": None}},
               "used_vols": set(["host:/share2G"]), "size": 2,
               "expected": "host:/share"},
              {"voldict": {"host:/share2G": {"size": 2},
               "host:/share": {"size": None}},
               "used_vols": set(["host:/share2G"]), "size": 3,
               "expected": "host:/share"},
              {"voldict": {"host:/share2G": {"size": 2},
                           "host:/share": {"size": None}},
               "used_vols": set(["host:/share2G"]), "size": None,
               "expected": "host:/share"},
              {"voldict": {"host:/share": {}}, "used_vols": set(), "size": 1,
               "expected": "host:/share"},
              {"voldict": {"host:/share": {}}, "used_vols": set(),
               "size": None, "expected": "host:/share"})
    @ddt.unpack
    def test_pop_gluster_vol(self, voldict, used_vols, size, expected):
        gmgr = common.GlusterManager
        gmgr1 = gmgr(expected, self._execute, None, None)
        self._layout._fetch_gluster_volumes = mock.Mock(return_value=voldict)
        self._layout.gluster_used_vols = used_vols
        self._layout._glustermanager = mock.Mock(return_value=gmgr1)
        self._layout.volume_pattern_keys = list(voldict.values())[0].keys()

        result = self._layout._pop_gluster_vol(size=size)

        self.assertEqual(expected, result)
        self.assertIn(result, used_vols)
        self._layout._fetch_gluster_volumes.assert_called_once_with()
        self._layout._glustermanager.assert_called_once_with(result)

    @ddt.data({"voldict": {"share2G": {"size": 2}},
               "used_vols": set(), "size": 3},
              {"voldict": {"share2G": {"size": 2}},
               "used_vols": set(["share2G"]), "size": None})
    @ddt.unpack
    def test_pop_gluster_vol_excp(self, voldict, used_vols, size):
        self._layout._fetch_gluster_volumes = mock.Mock(return_value=voldict)
        self._layout.gluster_used_vols = used_vols
        self._layout.volume_pattern_keys = list(voldict.values())[0].keys()

        self.assertRaises(exception.GlusterfsException,
                          self._layout._pop_gluster_vol, size=size)

        self._layout._fetch_gluster_volumes.assert_called_once_with()
        self.assertFalse(
            self.fake_driver._setup_via_manager.called)

    def test_push_gluster_vol(self):
        self._layout.gluster_used_vols = set([
            self.glusterfs_target1, self.glusterfs_target2])

        self._layout._push_gluster_vol(self.glusterfs_target2)

        self.assertEqual(1, len(self._layout.gluster_used_vols))
        self.assertFalse(
            self.glusterfs_target2 in self._layout.gluster_used_vols)

    def test_push_gluster_vol_excp(self):
        self._layout.gluster_used_vols = set([self.glusterfs_target1])
        self._layout.gluster_unused_vols_dict = {}

        self.assertRaises(exception.GlusterfsException,
                          self._layout._push_gluster_vol,
                          self.glusterfs_target2)

    @ddt.data({'vers_minor': '6',
               'cmd': ['find', '/tmp/tmpKGHKJ', '-mindepth', '1',
                       '-delete']},
              {'vers_minor': '7',
               'cmd': ['find', '/tmp/tmpKGHKJ', '-mindepth', '1', '!',
                       '-path', '/tmp/tmpKGHKJ/.trashcan', '!', '-path',
                       '/tmp/tmpKGHKJ/.trashcan/internal_op', '-delete']})
    @ddt.unpack
    def test_wipe_gluster_vol(self, vers_minor, cmd):
        tmpdir = '/tmp/tmpKGHKJ'
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.glusterfs_target1, self._execute, None, None)
        self._layout.glusterfs_versions = {
            self.glusterfs_server1: ('3', vers_minor)}

        self.mock_object(tempfile, 'mkdtemp',
                         mock.Mock(return_value=tmpdir))
        self.mock_object(self.fake_driver, '_execute', mock.Mock())
        self.mock_object(common, '_mount_gluster_vol', mock.Mock())
        self.mock_object(common, '_umount_gluster_vol', mock.Mock())
        self.mock_object(shutil, 'rmtree', mock.Mock())

        self._layout._wipe_gluster_vol(gmgr1)

        tempfile.mkdtemp.assert_called_once_with()
        common._mount_gluster_vol.assert_called_once_with(
            self.fake_driver._execute, gmgr1.export,
            tmpdir)
        kwargs = {'run_as_root': True}
        self.fake_driver._execute.assert_called_once_with(
            *cmd, **kwargs)
        common._umount_gluster_vol.assert_called_once_with(
            self.fake_driver._execute, tmpdir)
        kwargs = {'ignore_errors': True}
        shutil.rmtree.assert_called_once_with(tmpdir,
                                              **kwargs)

    def test_wipe_gluster_vol_mount_fail(self):
        tmpdir = '/tmp/tmpKGHKJ'
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.glusterfs_target1, self._execute, None, None)
        self._layout.glusterfs_versions = {
            self.glusterfs_server1: ('3', '6')}
        self.mock_object(tempfile, 'mkdtemp',
                         mock.Mock(return_value=tmpdir))
        self.mock_object(self.fake_driver, '_execute', mock.Mock())
        self.mock_object(common, '_mount_gluster_vol',
                         mock.Mock(side_effect=exception.GlusterfsException))
        self.mock_object(common, '_umount_gluster_vol', mock.Mock())
        self.mock_object(shutil, 'rmtree', mock.Mock())

        self.assertRaises(exception.GlusterfsException,
                          self._layout._wipe_gluster_vol,
                          gmgr1)

        tempfile.mkdtemp.assert_called_once_with()
        common._mount_gluster_vol.assert_called_once_with(
            self.fake_driver._execute, gmgr1.export,
            tmpdir)
        self.assertFalse(self.fake_driver._execute.called)
        self.assertFalse(common._umount_gluster_vol.called)
        kwargs = {'ignore_errors': True}
        shutil.rmtree.assert_called_once_with(tmpdir,
                                              **kwargs)

    def test_wipe_gluster_vol_error_wiping_gluster_vol(self):
        tmpdir = '/tmp/tmpKGHKJ'
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.glusterfs_target1, self._execute, None, None)
        self._layout.glusterfs_versions = {
            self.glusterfs_server1: ('3', '6')}
        cmd = ['find', '/tmp/tmpKGHKJ', '-mindepth', '1', '-delete']
        self.mock_object(tempfile, 'mkdtemp',
                         mock.Mock(return_value=tmpdir))
        self.mock_object(
            self.fake_driver, '_execute',
            mock.Mock(side_effect=exception.ProcessExecutionError))
        self.mock_object(common, '_mount_gluster_vol', mock.Mock())
        self.mock_object(common, '_umount_gluster_vol', mock.Mock())
        self.mock_object(shutil, 'rmtree', mock.Mock())

        self.assertRaises(exception.GlusterfsException,
                          self._layout._wipe_gluster_vol,
                          gmgr1)

        tempfile.mkdtemp.assert_called_once_with()
        common._mount_gluster_vol.assert_called_once_with(
            self.fake_driver._execute, gmgr1.export,
            tmpdir)
        kwargs = {'run_as_root': True}
        self.fake_driver._execute.assert_called_once_with(
            *cmd, **kwargs)
        common._umount_gluster_vol.assert_called_once_with(
            self.fake_driver._execute, tmpdir)
        kwargs = {'ignore_errors': True}
        shutil.rmtree.assert_called_once_with(tmpdir,
                                              **kwargs)

    def test_create_share(self):
        self._layout._pop_gluster_vol = mock.Mock(
            return_value=self.glusterfs_target1)
        gmgr1 = common.GlusterManager(self.glusterfs_target1)
        gmgr1.set_vol_option = mock.Mock()
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=gmgr1))
        self.mock_object(self.fake_driver, '_setup_via_manager',
                         mock.Mock(return_value='host1:/gv1'))

        share = new_share()
        exp_locn = self._layout.create_share(self._context, share)

        self._layout._pop_gluster_vol.assert_called_once_with(share['size'])
        self.fake_driver._setup_via_manager.assert_called_once_with(
            {'manager': gmgr1, 'share': share})
        self._layout.private_storage.update.assert_called_once_with(
            share['id'], {'volume': self.glusterfs_target1})
        gmgr1.set_vol_option.assert_called_once_with(
            'user.manila-share', share['id'])
        self.assertEqual('host1:/gv1', exp_locn)

    def test_create_share_error(self):
        self._layout._pop_gluster_vol = mock.Mock(
            side_effect=exception.GlusterfsException)

        share = new_share()
        self.assertRaises(exception.GlusterfsException,
                          self._layout.create_share, self._context, share)

        self._layout._pop_gluster_vol.assert_called_once_with(
            share['size'])

    @ddt.data(None, '', 'Eeyore')
    def test_delete_share(self, clone_of):
        self._layout._push_gluster_vol = mock.Mock()
        self._layout._wipe_gluster_vol = mock.Mock()
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.glusterfs_target1, self._execute, None, None)
        gmgr1.set_vol_option = mock.Mock()
        gmgr1.get_vol_option = mock.Mock(return_value=clone_of)
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=gmgr1))
        self._layout.gluster_used_vols = set([self.glusterfs_target1])

        self._layout.delete_share(self._context, self.share1)

        gmgr1.get_vol_option.assert_called_once_with(
            'user.manila-cloned-from')
        self._layout._wipe_gluster_vol.assert_called_once_with(gmgr1)
        self._layout._push_gluster_vol.assert_called_once_with(
            self.glusterfs_target1)
        self._layout.private_storage.delete.assert_called_once_with(
            self.share1['id'])
        gmgr1.set_vol_option.assert_called_once_with(
            'user.manila-share', 'NONE')

    def test_delete_share_clone(self):
        self._layout._push_gluster_vol = mock.Mock()
        self._layout._wipe_gluster_vol = mock.Mock()
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.glusterfs_target1, self._execute, None, None)
        gmgr1.gluster_call = mock.Mock()
        gmgr1.get_vol_option = mock.Mock(return_value=FAKE_UUID1)
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=gmgr1))
        self._layout.gluster_used_vols = set([self.glusterfs_target1])

        self._layout.delete_share(self._context, self.share1)

        gmgr1.get_vol_option.assert_called_once_with(
            'user.manila-cloned-from')
        self.assertFalse(self._layout._wipe_gluster_vol.called)
        self._layout._push_gluster_vol.assert_called_once_with(
            self.glusterfs_target1)
        self._layout.private_storage.delete.assert_called_once_with(
            self.share1['id'])
        gmgr1.gluster_call.assert_called_once_with(
            'volume', 'delete', 'gv1')

    def test_delete_share_error(self):
        self._layout._wipe_gluster_vol = mock.Mock()
        self._layout._wipe_gluster_vol.side_effect = (
            exception.GlusterfsException)
        self._layout._push_gluster_vol = mock.Mock()
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.glusterfs_target1, self._execute, None, None)
        gmgr1.get_vol_option = mock.Mock(return_value=None)
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=gmgr1))
        self._layout.gluster_used_vols = set([self.glusterfs_target1])

        self.assertRaises(exception.GlusterfsException,
                          self._layout.delete_share, self._context,
                          self.share1)

        self._layout._wipe_gluster_vol.assert_called_once_with(gmgr1)
        self.assertFalse(self._layout._push_gluster_vol.called)

    def test_delete_share_missing_record(self):
        self.mock_object(self._layout, '_share_manager',
                         mock.Mock(return_value=None))

        self._layout.delete_share(self._context, self.share1)

        self._layout._share_manager.assert_called_once_with(self.share1)

    def test_create_snapshot(self):
        self._layout.gluster_nosnap_vols_dict = {}
        self._layout.glusterfs_versions = {self.glusterfs_server1: ('3', '6')}
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.glusterfs_target1, self._execute, None, None)
        self._layout.gluster_used_vols = set([self.glusterfs_target1])
        self.mock_object(gmgr1, 'gluster_call',
                         mock.Mock(
                             side_effect=(glusterXMLOut(ret=0, errno=0),)))
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=gmgr1))

        snapshot = {
            'id': 'fake_snap_id',
            'share_id': self.share1['id'],
            'share': self.share1
        }
        ret = self._layout.create_snapshot(self._context, snapshot)

        self.assertIsNone(ret)
        args = ('--xml', 'snapshot', 'create', 'manila-fake_snap_id',
                gmgr1.volume)
        gmgr1.gluster_call.assert_called_once_with(*args, log=mock.ANY)

    @ddt.data({'side_effect': (glusterXMLOut(ret=-1, errno=2),),
               '_exception': exception.GlusterfsException},
              {'side_effect': (('', ''),),
               '_exception': exception.GlusterfsException})
    @ddt.unpack
    def test_create_snapshot_error(self, side_effect, _exception):
        self._layout.gluster_nosnap_vols_dict = {}
        self._layout.glusterfs_versions = {self.glusterfs_server1: ('3', '6')}
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.glusterfs_target1, self._execute, None, None)
        self._layout.gluster_used_vols = set([self.glusterfs_target1])
        self.mock_object(gmgr1, 'gluster_call',
                         mock.Mock(side_effect=side_effect))
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=gmgr1))

        snapshot = {
            'id': 'fake_snap_id',
            'share_id': self.share1['id'],
            'share': self.share1
        }
        self.assertRaises(_exception, self._layout.create_snapshot,
                          self._context, snapshot)

        args = ('--xml', 'snapshot', 'create', 'manila-fake_snap_id',
                gmgr1.volume)
        gmgr1.gluster_call.assert_called_once_with(*args, log=mock.ANY)

    @ddt.data({"vers_minor": '6', "exctype": exception.GlusterfsException},
              {"vers_minor": '7',
               "exctype": exception.ShareSnapshotNotSupported})
    @ddt.unpack
    def test_create_snapshot_no_snap(self, vers_minor, exctype):
        self._layout.gluster_nosnap_vols_dict = {}
        self._layout.glusterfs_versions = {
            self.glusterfs_server1: ('3', vers_minor)}
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.glusterfs_target1, self._execute, None, None)
        self._layout.gluster_used_vols = set([self.glusterfs_target1])
        self.mock_object(gmgr1, 'gluster_call',
                         mock.Mock(
                             side_effect=(glusterXMLOut(ret=-1, errno=0),)))
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=gmgr1))

        snapshot = {
            'id': 'fake_snap_id',
            'share_id': self.share1['id'],
            'share': self.share1
        }
        self.assertRaises(exctype, self._layout.create_snapshot, self._context,
                          snapshot)

        args = ('--xml', 'snapshot', 'create', 'manila-fake_snap_id',
                gmgr1.volume)
        gmgr1.gluster_call.assert_called_once_with(*args, log=mock.ANY)

    @ddt.data({"vers_minor": '6', "exctype": exception.GlusterfsException},
              {"vers_minor": '7',
               "exctype": exception.ShareSnapshotNotSupported})
    @ddt.unpack
    def test_create_snapshot_no_snap_cached(self, vers_minor, exctype):
        self._layout.gluster_nosnap_vols_dict = {
            self.glusterfs_target1: 'fake error'}
        self._layout.glusterfs_versions = {
            self.glusterfs_server1: ('3', vers_minor)}
        self._layout.gluster_used_vols = set([self.glusterfs_target1])
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.glusterfs_target1, self._execute, None, None)
        self.mock_object(self._layout, '_share_manager',
                         mock.Mock(return_value=gmgr1))

        snapshot = {
            'id': 'fake_snap_id',
            'share_id': self.share1['id'],
            'share': self.share1
        }
        self.assertRaises(exctype, self._layout.create_snapshot, self._context,
                          snapshot)

    def test_find_actual_backend_snapshot_name(self):
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.share1['export_location'], self._execute, None, None)
        self.mock_object(gmgr1, 'gluster_call',
                         mock.Mock(return_value=('fake_snap_id_xyz', '')))

        snapshot = {
            'id': 'fake_snap_id',
            'share_id': self.share1['id'],
            'share': self.share1
        }
        ret = self._layout._find_actual_backend_snapshot_name(gmgr1, snapshot)

        args = ('snapshot', 'list', gmgr1.volume, '--mode=script')
        gmgr1.gluster_call.assert_called_once_with(*args, log=mock.ANY)
        self.assertEqual('fake_snap_id_xyz', ret)

    @ddt.data('this is too bad', 'fake_snap_id_xyx\nfake_snap_id_pqr')
    def test_find_actual_backend_snapshot_name_bad_snap_list(self, snaplist):
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.share1['export_location'], self._execute, None, None)
        self.mock_object(gmgr1, 'gluster_call',
                         mock.Mock(return_value=(snaplist, '')))

        snapshot = {
            'id': 'fake_snap_id',
            'share_id': self.share1['id'],
            'share': self.share1
        }
        self.assertRaises(exception.GlusterfsException,
                          self._layout._find_actual_backend_snapshot_name,
                          gmgr1, snapshot)

        args = ('snapshot', 'list', gmgr1.volume, '--mode=script')
        gmgr1.gluster_call.assert_called_once_with(*args, log=mock.ANY)

    @ddt.data({'glusterfs_target': 'root@host1:/gv1',
               'glusterfs_server': 'root@host1'},
              {'glusterfs_target': 'host1:/gv1',
               'glusterfs_server': 'host1'})
    @ddt.unpack
    def test_create_share_from_snapshot(self, glusterfs_target,
                                        glusterfs_server):
        share = new_share()
        snapshot = {
            'id': 'fake_snap_id',
            'share_instance': new_share(export_location=glusterfs_target),
            'share_id': 'fake_share_id',
        }
        volume = ''.join(['manila-', share['id']])
        new_vol_addr = ':/'.join([glusterfs_server, volume])
        gmgr = common.GlusterManager
        old_gmgr = gmgr(glusterfs_target, self._execute, None, None)
        new_gmgr = gmgr(new_vol_addr, self._execute, None, None)
        self._layout.gluster_used_vols = set([glusterfs_target])
        self._layout.glusterfs_versions = {glusterfs_server: ('3', '7')}
        self.mock_object(old_gmgr, 'gluster_call',
                         mock.Mock(side_effect=[('', ''), ('', '')]))
        self.mock_object(new_gmgr, 'gluster_call',
                         mock.Mock(side_effect=[('', ''), ('', ''), ('', '')]))
        self.mock_object(new_gmgr, 'get_vol_option',
                         mock.Mock())
        new_gmgr.get_vol_option.return_value = (
            'glusterfs-server-1,client')
        self.mock_object(self._layout, '_find_actual_backend_snapshot_name',
                         mock.Mock(return_value='fake_snap_id_xyz'))
        self.mock_object(self._layout, '_share_manager',
                         mock.Mock(return_value=old_gmgr))
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=new_gmgr))
        self.mock_object(self.fake_driver, '_setup_via_manager',
                         mock.Mock(return_value='host1:/gv1'))

        ret = self._layout.create_share_from_snapshot(
            self._context, share, snapshot, None)

        (self._layout._find_actual_backend_snapshot_name.
            assert_called_once_with(old_gmgr, snapshot))
        args = (('snapshot', 'activate', 'fake_snap_id_xyz',
                 'force', '--mode=script'),
                ('snapshot', 'clone', volume, 'fake_snap_id_xyz'))
        old_gmgr.gluster_call.assert_has_calls(
            [mock.call(*a, log=mock.ANY) for a in args])
        args = (('volume', 'start', volume),
                ('volume', 'set', volume, 'user.manila-share', share['id']),
                ('volume', 'set', volume, 'user.manila-cloned-from',
                 snapshot['share_id']))
        new_gmgr.gluster_call.assert_has_calls(
            [mock.call(*a, log=mock.ANY) for a in args], any_order=True)
        self._layout._share_manager.assert_called_once_with(
            snapshot['share_instance'])
        self._layout._glustermanager.assert_called_once_with(
            gmgr.parse(new_vol_addr))
        self._layout.driver._setup_via_manager.assert_called_once_with(
            {'manager': new_gmgr, 'share': share},
            {'manager': old_gmgr, 'share': snapshot['share_instance']})
        self._layout.private_storage.update.assert_called_once_with(
            share['id'], {'volume': new_vol_addr})
        self.assertIn(
            new_vol_addr,
            self._layout.gluster_used_vols)
        self.assertEqual('host1:/gv1', ret)

    def test_create_share_from_snapshot_error_unsupported_gluster_version(
            self):
        glusterfs_target = 'root@host1:/gv1'
        glusterfs_server = 'root@host1'
        share = new_share()
        volume = ''.join(['manila-', share['id']])
        new_vol_addr = ':/'.join([glusterfs_server, volume])
        gmgr = common.GlusterManager
        old_gmgr = gmgr(glusterfs_target, self._execute, None, None)
        new_gmgr = gmgr(new_vol_addr, self._execute, None, None)
        self._layout.gluster_used_vols_dict = {glusterfs_target: old_gmgr}
        self._layout.glusterfs_versions = {glusterfs_server: ('3', '6')}
        self.mock_object(
            old_gmgr, 'gluster_call',
            mock.Mock(side_effect=[('', ''), ('', '')]))
        self.mock_object(new_gmgr, 'get_vol_option',
                         mock.Mock())
        new_gmgr.get_vol_option.return_value = (
            'glusterfs-server-1,client')
        self.mock_object(self._layout, '_find_actual_backend_snapshot_name',
                         mock.Mock(return_value='fake_snap_id_xyz'))
        self.mock_object(self._layout, '_share_manager',
                         mock.Mock(return_value=old_gmgr))
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=new_gmgr))

        snapshot = {
            'id': 'fake_snap_id',
            'share_instance': new_share(export_location=glusterfs_target)
        }
        self.assertRaises(exception.GlusterfsException,
                          self._layout.create_share_from_snapshot,
                          self._context, share, snapshot)

        self.assertFalse(
            self._layout._find_actual_backend_snapshot_name.called)
        self.assertFalse(old_gmgr.gluster_call.called)
        self._layout._share_manager.assert_called_once_with(
            snapshot['share_instance'])
        self.assertFalse(self._layout._glustermanager.called)
        self.assertFalse(new_gmgr.get_vol_option.called)
        self.assertFalse(new_gmgr.gluster_call.called)
        self.assertNotIn(new_vol_addr,
                         self._layout.glusterfs_versions.keys())

    def test_delete_snapshot(self):
        self._layout.gluster_nosnap_vols_dict = {}
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.share1['export_location'], self._execute, None, None)
        self._layout.gluster_used_vols = set([self.glusterfs_target1])
        self.mock_object(self._layout, '_find_actual_backend_snapshot_name',
                         mock.Mock(return_value='fake_snap_id_xyz'))
        self.mock_object(
            gmgr1, 'gluster_call',
            mock.Mock(return_value=glusterXMLOut(ret=0, errno=0)))
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=gmgr1))
        snapshot = {
            'id': 'fake_snap_id',
            'share_id': self.share1['id'],
            'share': self.share1
        }
        ret = self._layout.delete_snapshot(self._context, snapshot)

        self.assertIsNone(ret)
        args = ('--xml', 'snapshot', 'delete', 'fake_snap_id_xyz',
                '--mode=script')
        gmgr1.gluster_call.assert_called_once_with(*args, log=mock.ANY)
        (self._layout._find_actual_backend_snapshot_name.
            assert_called_once_with(gmgr1, snapshot))

    @ddt.data({'side_effect': (glusterXMLOut(ret=-1, errno=0),),
               '_exception': exception.GlusterfsException},
              {'side_effect': (('', ''),),
               '_exception': exception.GlusterfsException})
    @ddt.unpack
    def test_delete_snapshot_error(self, side_effect, _exception):
        self._layout.gluster_nosnap_vols_dict = {}
        gmgr = common.GlusterManager
        gmgr1 = gmgr(self.share1['export_location'], self._execute, None, None)
        self._layout.gluster_used_vols = set([self.glusterfs_target1])
        self.mock_object(self._layout, '_find_actual_backend_snapshot_name',
                         mock.Mock(return_value='fake_snap_id_xyz'))
        args = ('--xml', 'snapshot', 'delete', 'fake_snap_id_xyz',
                '--mode=script')
        self.mock_object(
            gmgr1, 'gluster_call',
            mock.Mock(side_effect=side_effect))
        self.mock_object(self._layout, '_glustermanager',
                         mock.Mock(return_value=gmgr1))

        snapshot = {
            'id': 'fake_snap_id',
            'share_id': self.share1['id'],
            'share': self.share1
        }
        self.assertRaises(_exception, self._layout.delete_snapshot,
                          self._context, snapshot)

        gmgr1.gluster_call.assert_called_once_with(*args, log=mock.ANY)
        (self._layout._find_actual_backend_snapshot_name.
            assert_called_once_with(gmgr1, snapshot))

    @ddt.data(
        ('manage_existing', ('share', 'driver_options'), {}),
        ('unmanage', ('share',), {}),
        ('extend_share', ('share', 'new_size'), {'share_server': None}),
        ('shrink_share', ('share', 'new_size'), {'share_server': None}))
    def test_nonimplemented_methods(self, method_invocation):
        method, args, kwargs = method_invocation
        self.assertRaises(NotImplementedError, getattr(self._layout, method),
                          *args, **kwargs)
