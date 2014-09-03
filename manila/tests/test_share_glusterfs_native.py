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

""" GlusterFS native protocol (glusterfs) driver for shares.

Test cases for GlusterFS native protocol driver.
"""


import mock
from oslo.config import cfg

from manila import context
from manila import exception
from manila.share import configuration as config
from manila.share.drivers import glusterfs_native
from manila import test
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_utils


CONF = cfg.CONF


gluster_address_attrs = {
    'export': '127.0.0.1:/testvol',
    'host': '127.0.0.1',
    'qualified': 'testuser@127.0.0.1:/testvol',
    'remote_user': 'testuser',
    'volume': 'testvol',
}


def fake_share(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'glusterfs',
        'export_location': '127.0.0.1:/mnt/glusterfs/testvol',
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)


class GlusterfsNativeShareDriverTestCase(test.TestCase):
    """Tests GlusterfsNativeShareDriver."""

    def setUp(self):
        super(GlusterfsNativeShareDriverTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        self._execute = fake_utils.fake_execute
        self._context = context.get_admin_context()

        CONF.set_default('glusterfs_mount_point_base', '/mnt/glusterfs')
        CONF.set_default('reserved_share_percentage', 50)

        self.fake_conf = config.Configuration(None)
        self._db = mock.Mock()
        self._driver = glusterfs_native.GlusterfsNativeShareDriver(
            self._db, execute=self._execute,
            configuration=self.fake_conf)
        self._driver.gluster_address = mock.Mock(**gluster_address_attrs)
        self.share = fake_share()

        self.addCleanup(fake_utils.fake_execute_set_repliers, [])
        self.addCleanup(fake_utils.fake_execute_clear_log)

    def test_create_share(self):
        self._driver._setup_gluster_vol = mock.Mock()

        expected = gluster_address_attrs['export']
        actual = self._driver.create_share(self._context, self.share)

        self.assertTrue(self._driver._setup_gluster_vol.called)
        self.assertEqual(actual, expected)

    def test_create_share_error(self):
        self._driver._setup_gluster_vol = mock.Mock()
        self._driver._setup_gluster_vol.side_effect = (
            exception.ProcessExecutionError)

        self.assertRaises(exception.ProcessExecutionError,
                          self._driver.create_share, self._context, self.share)

    def test_delete_share(self):
        self._driver.gluster_address = mock.Mock(
            make_gluster_args=mock.Mock(return_value=(('true',), {})))

        self._driver.delete_share(self._context, self.share)

        self.assertTrue(self._driver.gluster_address.make_gluster_args.called)
        self.assertEqual(
            self._driver.gluster_address.make_gluster_args.call_args[0][1],
            'reset')

    def test_delete_share_error(self):
        self._driver.gluster_address = mock.Mock(
            make_gluster_args=mock.Mock(return_value=(('true',), {})))

        def exec_runner(*ignore_args, **ignore_kw):
            raise exception.ProcessExecutionError

        expected_exec = ['true']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.ProcessExecutionError,
                          self._driver.delete_share, self._context, self.share)

    def test_allow_access(self):
        self._driver.gluster_address = mock.Mock(
            make_gluster_args=mock.Mock(return_value=(('true',), {})))
        access = {'access_type': 'cert', 'access_to': 'client.example.com'}

        self._driver.allow_access(self._context, self.share, access)

        self.assertTrue(self._driver.gluster_address.make_gluster_args.called)
        self.assertEqual(
            self._driver.gluster_address.make_gluster_args.call_args[0][1],
            'set')
        self.assertEqual(
            self._driver.gluster_address.make_gluster_args.call_args[0][-2],
            'auth.ssl-allow')
        self.assertEqual(
            self._driver.gluster_address.make_gluster_args.call_args[0][-1],
            access['access_to'])

    def test_allow_access_error(self):
        # Invalid access type
        access = {'access_type': 'invalid', 'access_to': 'client.example.com'}

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.allow_access, self._context, self.share,
                          access)

        # ProcessExecutionError
        self._driver.gluster_address = mock.Mock(
            make_gluster_args=mock.Mock(return_value=(('true',), {})))
        access = {'access_type': 'cert', 'access_to': 'client.example.com'}

        def exec_runner(*ignore_args, **ignore_kw):
            raise exception.ProcessExecutionError

        expected_exec = ['true']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.ProcessExecutionError,
                          self._driver.allow_access, self._context, self.share,
                          access)

    def test_deny_access(self):
        self._driver.gluster_address = mock.Mock(
            make_gluster_args=mock.Mock(return_value=(('true',), {})))
        access = {'access_type': 'cert', 'access_to': 'client.example.com'}

        self._driver.deny_access(self._context, self.share, access)

        self.assertTrue(self._driver.gluster_address.make_gluster_args.called)
        self.assertEqual(
            self._driver.gluster_address.make_gluster_args.call_args[0][1],
            'reset')
        self.assertEqual(
            self._driver.gluster_address.make_gluster_args.call_args[0][-1],
            'auth.ssl-allow')

    def test_deny_access_error(self):
        # Invalid access type
        access = {'access_type': 'invalid', 'access_to': 'client.example.com'}

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.deny_access, self._context, self.share,
                          access)

        # ProcessExecutionError
        self._driver.gluster_address = mock.Mock(
            make_gluster_args=mock.Mock(return_value=(('true',), {})))
        access = {'access_type': 'cert', 'access_to': 'client.example.com'}

        def exec_runner(*ignore_args, **ignore_kw):
            raise exception.ProcessExecutionError

        expected_exec = ['true']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.ProcessExecutionError,
                          self._driver.deny_access, self._context, self.share,
                          access)
