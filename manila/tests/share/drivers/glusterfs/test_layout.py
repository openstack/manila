# Copyright (c) 2015 Red Hat, Inc.
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

import errno
import os

import ddt
import mock
from oslo_config import cfg
from oslo_utils import importutils

from manila import exception
from manila.share import configuration as config
from manila.share import driver
from manila.share.drivers.glusterfs import layout
from manila import test
from manila.tests import fake_utils


CONF = cfg.CONF


fake_local_share_path = '/mnt/nfs/testvol/fakename'

fake_path_to_private_key = '/fakepath/to/privatekey'
fake_remote_server_password = 'fakepassword'


class GlusterfsFakeShareDriver(layout.GlusterfsShareDriverBase):

    supported_layouts = ('layout_fake.FakeLayout',
                         'layout_something.SomeLayout')
    supported_protocols = ('NFS,')


@ddt.ddt
class GlusterfsShareDriverBaseTestCase(test.TestCase):
    """Tests GlusterfsShareDriverBase."""

    def setUp(self):
        super(GlusterfsShareDriverBaseTestCase, self).setUp()
        CONF.set_default('driver_handles_share_servers', False)
        fake_conf, __ = self._setup()
        self._driver = GlusterfsFakeShareDriver(False, configuration=fake_conf)
        self.fake_share = mock.Mock()
        self.fake_context = mock.Mock()
        self.fake_access = mock.Mock()

    def _setup(self):
        fake_conf = config.Configuration(None)
        fake_layout = mock.Mock()
        self.mock_object(importutils, "import_object",
                         mock.Mock(return_value=fake_layout))
        return fake_conf, fake_layout

    def test_init(self):
        self.assertRaises(IndexError, layout.GlusterfsShareDriverBase, False,
                          configuration=config.Configuration(None))

    @ddt.data({'has_snap': None, 'layout_name': None},
              {'has_snap': False, 'layout_name': 'layout_fake.FakeLayout'},
              {'has_snap': True, 'layout_name': 'layout_something.SomeLayout'})
    @ddt.unpack
    def test_init_subclass(self, has_snap, layout_name):
        conf, _layout = self._setup()
        if layout_name is not None:
            conf.glusterfs_share_layout = layout_name
        if has_snap is None:
            del(_layout._snapshots_are_supported)
        else:
            _layout._snapshots_are_supported = has_snap

        _driver = GlusterfsFakeShareDriver(False, configuration=conf)

        snap_result = {None: False}.get(has_snap, has_snap)
        layout_result = {None: 'layout_fake.FakeLayout'}.get(layout_name,
                                                             layout_name)

        importutils.import_object.assert_called_once_with(
            'manila.share.drivers.glusterfs.%s' % layout_result,
            _driver, configuration=conf)
        self.assertEqual(_layout, _driver.layout)
        self.assertEqual(snap_result, _driver.snapshots_are_supported)

    def test_init_nosupp_layout(self):
        conf = config.Configuration(None)
        conf.glusterfs_share_layout = 'nonsense_layout'

        self.assertRaises(exception.GlusterfsException,
                          GlusterfsFakeShareDriver, False, configuration=conf)

    def test_setup_via_manager(self):
        self.assertIsNone(self._driver._setup_via_manager(mock.Mock()))

    @ddt.data('allow', 'deny')
    def test_allow_deny_access(self, op):
        conf, _layout = self._setup()
        gmgr = mock.Mock()
        self.mock_object(_layout, '_share_manager',
                         mock.Mock(return_value=gmgr))

        _driver = GlusterfsFakeShareDriver(False, configuration=conf)
        self.mock_object(_driver, "_%s_access_via_manager" % op, mock.Mock())

        getattr(_driver, "%s_access" % op)(self.fake_context, self.fake_share,
                                           self.fake_access)

        _layout._share_manager.assert_called_once_with(self.fake_share)
        getattr(_driver,
                "_%s_access_via_manager" % op).assert_called_once_with(
            gmgr, self.fake_context, self.fake_share, self.fake_access, None)

    @ddt.data('allow', 'deny')
    def test_allow_deny_access_via_manager(self, op):
        self.assertRaises(NotImplementedError,
                          getattr(self._driver,
                                  "_%s_access_via_manager" % op),
                          mock.Mock(), self.fake_context, self.fake_share,
                          self.fake_access, None)

    @ddt.data('NFS', 'PROTATO')
    def test_check_proto_baseclass(self, proto):
        self.assertRaises(exception.ShareBackendException,
                          layout.GlusterfsShareDriverBase._check_proto,
                          {'share_proto': proto})

    def test_check_proto(self):
        GlusterfsFakeShareDriver._check_proto({'share_proto': 'NFS'})

    def test_check_proto_notsupported(self):
        self.assertRaises(exception.ShareBackendException,
                          GlusterfsFakeShareDriver._check_proto,
                          {'share_proto': 'PROTATO'})

    @ddt.data('', '_from_snapshot')
    def test_create_share(self, variant):
        conf, _layout = self._setup()
        _driver = GlusterfsFakeShareDriver(False, configuration=conf)
        self.mock_object(_driver, '_check_proto', mock.Mock())

        getattr(_driver, 'create_share%s' % variant)(self.fake_context,
                                                     self.fake_share)

        _driver._check_proto.assert_called_once_with(self.fake_share)
        getattr(_layout,
                'create_share%s' % variant).assert_called_once_with(
            self.fake_context, self.fake_share)

    @ddt.data(True, False)
    def test_update_share_stats(self, internal_exception):
        data = mock.Mock()
        conf, _layout = self._setup()

        def raise_exception(*args, **kwargs):
            raise NotImplementedError
        layoutstats = mock.Mock()

        mock_kw = ({'side_effect': raise_exception} if internal_exception
                   else {'return_value': layoutstats})

        self.mock_object(_layout, '_update_share_stats', mock.Mock(**mock_kw))
        self.mock_object(driver.ShareDriver, '_update_share_stats',
                         mock.Mock())
        _driver = GlusterfsFakeShareDriver(False, configuration=conf)
        _driver._update_share_stats(data)

        if internal_exception:
            self.assertFalse(data.update.called)
        else:
            data.update.assert_called_once_with(layoutstats)
        driver.ShareDriver._update_share_stats.assert_called_once_with(
            data)

    @ddt.data('do_setup', 'create_snapshot', 'delete_share', 'delete_snapshot',
              'ensure_share', 'manage_existing', 'unmanage', 'extend_share',
              'shrink_share')
    def test_delegated_methods(self, method):
        conf, _layout = self._setup()
        _driver = GlusterfsFakeShareDriver(False, configuration=conf)
        fake_args = (mock.Mock(), mock.Mock(), mock.Mock())

        getattr(_driver, method)(*fake_args)

        getattr(_layout, method).assert_called_once_with(*fake_args)


@ddt.ddt
class GlusterfsShareLayoutBaseTestCase(test.TestCase):
    """Tests GlusterfsShareLayoutBaseTestCase."""

    def setUp(self):
        super(GlusterfsShareLayoutBaseTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self)
        self._execute = fake_utils.fake_execute
        self.addCleanup(fake_utils.fake_execute_set_repliers, [])
        self.addCleanup(fake_utils.fake_execute_clear_log)
        self.fake_driver = mock.Mock()
        self.mock_object(self.fake_driver, '_execute',
                         self._execute)

    class FakeLayout(layout.GlusterfsShareLayoutBase):

        def _share_manager(self, share):
            """Return GlusterManager object representing share's backend."""

        def do_setup(self, context):
            """Any initialization the share driver does while starting."""

        def create_share(self, context, share, share_server=None):
            """Is called to create share."""

        def create_share_from_snapshot(self, context, share, snapshot,
                                       share_server=None):
            """Is called to create share from snapshot."""

        def create_snapshot(self, context, snapshot, share_server=None):
            """Is called to create snapshot."""

        def delete_share(self, context, share, share_server=None):
            """Is called to remove share."""

        def delete_snapshot(self, context, snapshot, share_server=None):
            """Is called to remove snapshot."""

        def ensure_share(self, context, share, share_server=None):
            """Invoked to ensure that share is exported."""

        def manage_existing(self, share, driver_options):
            """Brings an existing share under Manila management."""

        def unmanage(self, share):
            """Removes the specified share from Manila management."""

        def extend_share(self, share, new_size, share_server=None):
            """Extends size of existing share."""

        def shrink_share(self, share, new_size, share_server=None):
            """Shrinks size of existing share."""

    def test_init_invalid(self):
        self.assertRaises(TypeError, layout.GlusterfsShareLayoutBase,
                          mock.Mock())

    def test_subclass(self):
        fake_conf = mock.Mock()
        _layout = self.FakeLayout(self.fake_driver, configuration=fake_conf)

        self.assertEqual(fake_conf, _layout.configuration)
        self.assertRaises(NotImplementedError, _layout._update_share_stats)

    def test_check_mount_glusterfs(self):
        fake_conf = mock.Mock()
        _driver = mock.Mock()
        _driver._execute = mock.Mock()
        _layout = self.FakeLayout(_driver, configuration=fake_conf)

        _layout._check_mount_glusterfs()

        _driver._execute.assert_called_once_with(
            'mount.glusterfs',
            check_exit_code=False)

    @ddt.data({'_errno': errno.ENOENT,
               '_exception': exception.GlusterfsException},
              {'_errno': errno.EACCES, '_exception': OSError})
    @ddt.unpack
    def test_check_mount_glusterfs_not_installed(self, _errno, _exception):
        fake_conf = mock.Mock()
        _layout = self.FakeLayout(self.fake_driver, configuration=fake_conf)

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise OSError(_errno, os.strerror(_errno))

        expected_exec = ['mount.glusterfs']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(_exception, _layout._check_mount_glusterfs)
