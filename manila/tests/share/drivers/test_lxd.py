# Copyright (c) 2016 Mirantis, Inc.
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
"""Unit tests for the LXD driver module."""

import functools
import mock
from oslo_config import cfg
import testtools

from manila.common import constants as const
from manila import context
from manila import exception
from manila.share import configuration
from manila.share.drivers import lxd
from manila import test
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_utils
from manila import utils

CONF = cfg.CONF


def fake_share(**kwargs):
    share = {
        'id': 'fakeid',
        'share_id': 'fakeshareid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'NFS',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)


def fake_access(**kwargs):
    access = {
        'id': 'fakeaccid',
        'access_type': 'ip',
        'access_to': '10.0.0.2',
        'access_level': 'rw',
        'state': 'active',
    }
    access.update(kwargs)
    return db_fakes.FakeModel(access)


def fake_network(**kwargs):
    allocations = db_fakes.FakeModel({'id': 'fake_allocation_id',
                                      'ip_address': '127.0.0.0.1',
                                      'mac_address': 'fe:16:3e:61:e0:58'})
    network = {
        'id': 'fake_network_id',
        'server_id': 'fake_server_id',
        'network_allocations': [allocations],
        'neutron_subnet_id': 'fake_subnet',
    }
    network.update(kwargs)
    return db_fakes.FakeModel(network)


@testtools.skipIf(lxd.NO_LXD, "pylxd is unavailable")
class LXDHelperTestCase(test.TestCase):
    """Tests LXDUnfs3Helper"""

    def setUp(self):
        super(LXDHelperTestCase, self).setUp()
        lxd_api = mock.Mock()
        config = None
        self.LXDHelper = lxd.LXDHelper(lxd_api, config)

    def tearDown(self):
        super(LXDHelperTestCase, self).tearDown()

    def test_create_container_initialized_ok(self):
        self.LXDHelper.conf = mock.Mock()
        self.LXDHelper.conf.lxd_image_name = "fake-image"
        fake_data = {"operation": "2"}

        def fake_inner_wait():
            return True

        def fake__wait(wait, whatever):
            try:
                fake_inner_wait()
            except Exception:
                raise exception.ManilaException()
        self.mock_object(self.LXDHelper, "_wait", fake__wait)
        self.mock_object(self.LXDHelper.api, "container_init",
                         mock.Mock(return_value=(0, fake_data)))
        self.mock_object(self.LXDHelper, "_wait", fake__wait)
        self.LXDHelper.create_container("fake_container")

    def test_create_container_initialized_not_ok(self):
        self.LXDHelper.conf = mock.Mock()
        self.LXDHelper.conf.lxd_image_name = "fake-image"
        fake_data = {"operation": "2"}
        fake_operation = {"operation": "2", "status": "failure"}

        def fake_inner_wait():
            return True

        def fake__wait(wait, whatever):
            fake_inner_wait()
        self.mock_object(self.LXDHelper, "_wait", fake__wait)
        self.mock_object(self.LXDHelper.api, "container_init",
                         mock.Mock(return_value=(0, fake_data)))
        self.mock_object(self.LXDHelper.api, "operation_info",
                         mock.Mock(return_value=(0, fake_operation)))
        self.mock_object(self.LXDHelper, "_wait", fake__wait)
        self.LXDHelper.create_container("fake_container")

    def test_start_container_running_ok_status_fails(self):
        fake_data = {"operation": "2"}

        def fake_inner_wait():
            return False

        def fake__wait(wait, whatever):
            try:
                fake_inner_wait()
            except Exception:
                raise exception.ManilaException()
        self.mock_object(self.LXDHelper, "_wait", fake__wait)
        self.mock_object(self.LXDHelper.api, "container_start",
                         mock.Mock(return_value=(0, fake_data)))
        self.mock_object(self.LXDHelper, "_wait", fake__wait)
        self.LXDHelper.start_container("fake_container")

    def test_start_container_running_ok_status_ok(self):
        fake_data = {"operation": "1"}

        def fake_inner_wait():
            return True

        def fake__wait(wait, whatever):
            try:
                fake_inner_wait()
            except Exception:
                raise exception.ManilaException()
        self.mock_object(self.LXDHelper, "_wait", fake__wait)
        self.mock_object(self.LXDHelper.api, "container_start",
                         mock.Mock(return_value=(0, fake_data)))
        self.mock_object(self.LXDHelper, "_wait", fake__wait)
        self.LXDHelper.start_container("fake_container")

    def test_stop_container(self):
        self.mock_object(self.LXDHelper.api, "container_stop",
                         mock.Mock(return_value=(0, 0)))
        self.mock_object(self.LXDHelper.api, "container_destroy")
        self.mock_object(self.LXDHelper, "_wait")
        self.LXDHelper.stop_container("fake")
        self.LXDHelper.api.container_stop.assert_called_once_with("fake", 60)

    def test__wait(self):
        self.mock_object(utils, "wait_until_true")
        self.LXDHelper.conf = mock.Mock()
        self.LXDHelper.conf.lxd_build_timeout = 0
        self.LXDHelper.conf.lxd_check_timeout = 0
        self.LXDHelper._wait("spam", KeyError)
        utils.wait_until_true.assert_called_with('spam', exception=KeyError,
                                                 sleep=0, timeout=0)

    def test__wait_operation_ok(self):
        def fake_inner_wait():
            return True

        def fake__wait(wait, whatever):
            try:
                fake_inner_wait()
            except Exception:
                raise exception.ManilaException()
        self.mock_object(self.LXDHelper, "_wait", fake__wait)
        self.LXDHelper._wait_operation("whatever")

    def test__wait_operation_unkown_error(self):
        def fake_inner_wait():
            raise exception.ManilaException("Cannot get operation info")

        def fake__wait(wait, whatever):
            try:
                wait()
            except Exception:
                raise exception.ManilaException()
        self.mock_object(self.LXDHelper, "_wait", fake__wait)
        self.assertRaises(exception.ManilaException,
                          self.LXDHelper._wait_operation,
                          fake_inner_wait)

    def test_execute_sync_soket_error(self):
        self.mock_object(self.LXDHelper.api, 'container_run_command',
                         mock.Mock(return_value=(0, {})))
        self.assertRaises(exception.ManilaException,
                          self.LXDHelper.execute_sync, 'fake', "fakes")

    def test_execute_sync(self):
        ret_val = {"metadata": {"metadata": {"fds": {"0": ""}}},
                   "operation": "None"}
        fake_stream = mock.Mock()
        self.mock_object(fake_stream, "receive", mock.Mock(return_value=None))
        self.mock_object(self.LXDHelper.api, 'container_run_command',
                         mock.Mock(return_value=(0, ret_val)))
        self.mock_object(self.LXDHelper.api, 'operation_stream',
                         mock.Mock(return_value=fake_stream))
        self.mock_object(self.LXDHelper.api, 'operation_info',
                         mock.Mock(return_value=("", "")))
        self.LXDHelper.execute_sync("fake", "fake")
        fake_stream.close.assert_called_once_with()


@testtools.skipIf(lxd.NO_LXD, "pylxd is unavailable")
class LXDUnfs3HelperTestCase(test.TestCase):
    """Tests LXDUnfs3Helper"""

    def setUp(self):
        super(LXDUnfs3HelperTestCase, self).setUp()
        self.lxd_helper = mock.Mock()
        self.UNFS3Helper = lxd.LXDUnfs3Helper(self.lxd_helper,
                                              share=fake_share())

    def tearDown(self):
        super(LXDUnfs3HelperTestCase, self).tearDown()

    def fake_exec_sync(self, *args, **kwargs):
        kwargs['execute_arguments'].append(args)
        try:
            ret_val = kwargs['ret_val']
        except KeyError:
            ret_val = None
        return ret_val

    def test__restart_unfsd(self):
        actual_arguments = []
        expected_arguments = [
            ('fakeserver', ['pkill', 'unfsd']),
            ('fakeserver', ['service', 'unfs3', 'start'])]
        self.lxd_helper.execute_sync = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='')
        self.UNFS3Helper._restart_unfsd('fakeserver')
        self.assertEqual(expected_arguments, actual_arguments)

    def test_create_share(self):
        self.mock_object(self.lxd_helper, 'execute_sync',
                         mock.Mock(return_value="0/0 " * 20))
        self.UNFS3Helper.create_share('fakeserver')
        self.UNFS3Helper.lxd.execute_sync.assert_called_with(
            'fakeserver', ['ip', 'addr', 'show', 'eth0'])

    def test_delete_share(self):
        self.mock_object(self.UNFS3Helper, '_restart_unfsd')
        self.mock_object(self.lxd_helper, 'execute_sync')
        self.UNFS3Helper.delete_share('fakeserver')
        self.UNFS3Helper.lxd.execute_sync.assert_called_once_with(
            'fakeserver',
            ['sed', '-i', '\\$/shares/fakeshareid.*$d', '/etc/exports'])
        self.UNFS3Helper._restart_unfsd.assert_called_once_with('fakeserver')

    def test__deny_access(self):
        self.mock_object(self.UNFS3Helper, '_restart_unfsd')
        self.mock_object(self.lxd_helper, 'execute_sync')
        self.UNFS3Helper._deny_access('fakeserver', '127.0.0.1')
        self.UNFS3Helper.lxd.execute_sync.assert_called_once_with(
            'fakeserver',
            ['sed', '-i', '\\$/shares/fakeshareid.*127\\.0\\.0'
             '\\.1.*$d', '/etc/exports'])
        self.UNFS3Helper._restart_unfsd.assert_called_once_with('fakeserver')

    def test__allow_access_wrong_level(self):
        self.assertRaises(exception.InvalidShareAccessLevel,
                          self.UNFS3Helper._allow_access, 'fakeshare',
                          'fakeserver', '127.0.0.1', 'rwx')

    def test__allow_access_host_present_ro(self):
        actual_arguments = []
        expected_arguments = [
            ('fakeserver',
             ['grep', '/shares/fakeshareid.*127\\.0\\.0\\.1.*',
              '/etc/exports'])]
        self.lxd_helper.execute_sync = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='127.0.0.1')
        self.UNFS3Helper._allow_access('fakeshare', 'fakeserver', '127.0.0.1',
                                       'rw')
        self.assertEqual(expected_arguments, actual_arguments)

    def test__allow_access_host_present_rw(self):
        actual_arguments = []
        expected_arguments = [
            ('fakeserver',
             ['grep', '/shares/fakeshareid.*127\\.0\\.0\\.1.*',
              '/etc/exports'])]
        self.lxd_helper.execute_sync = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='127.0.0.1')
        self.UNFS3Helper._allow_access('fakeshare', 'fakeserver', '127.0.0.1',
                                       'rw')
        self.assertEqual(expected_arguments, actual_arguments)

    def test__allow_access_host_present_other(self):
        actual_arguments = []
        expected_arguments = [
            ('fakeserver',
             ['grep', '/shares/fakeshareid.*127\\.0\\.0\\.1.*',
              '/etc/exports'])]
        self.lxd_helper.execute_sync = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='127.0.0.1')
        self.UNFS3Helper._allow_access('fakeshare', 'fakeserver', '127.0.0.1',
                                       'rw')
        self.assertEqual(expected_arguments, actual_arguments)

    def test__allow_access_no_host_ro(self):
        actual_arguments = []
        expected_arguments = [
            ('fakeserver',
             ['grep', '/shares/fakeshareid.*127\\.0\\.0\\.1.*',
              '/etc/exports']),
            ('fakeserver',
             ['sed', '-i',
              '$ a\\/shares/fakeshareid 127.0.0.1(rw,no_root_squash,async,'
              'no_subtree_check)', '/etc/exports'])]
        self.lxd_helper.execute_sync = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='')
        self.mock_object(self.UNFS3Helper, '_restart_unfsd')
        self.UNFS3Helper._allow_access('fakeshare', 'fakeserver', '127.0.0.1',
                                       'rw')
        self.UNFS3Helper._restart_unfsd.assert_called_once_with('fakeserver')
        self.assertEqual(expected_arguments, actual_arguments)

    def test__allow_access_no_host_rw(self):
        actual_arguments = []
        expected_arguments = [
            ('fakeserver',
             ['grep', '/shares/fakeshareid.*127\\.0\\.0\\.1.*',
              '/etc/exports']),
            ('fakeserver',
             ['sed', '-i',
              '$ a\\/shares/fakeshareid 127.0.0.1(rw,no_root_squash,async,'
              'no_subtree_check)', '/etc/exports'])]
        self.lxd_helper.execute_sync = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='')
        self.mock_object(self.UNFS3Helper, '_restart_unfsd')
        self.UNFS3Helper._allow_access('fakeshare', 'fakeserver', '127.0.0.1',
                                       'rw')
        self.UNFS3Helper._restart_unfsd.assert_called_once_with('fakeserver')
        self.assertEqual(expected_arguments, actual_arguments)

    def test_update_access_access_rules_ok(self):
        allow_rules = [{
            'access_to': '127.0.0.1',
            'access_level': 'ro',
            'access_type': 'ip'
        }]
        self.mock_object(self.UNFS3Helper, "_allow_access")
        self.UNFS3Helper.update_access("fakeshareid", "fakeserver",
                                       allow_rules, [], [])
        self.UNFS3Helper._allow_access.assert_called_once_with("fakeshareid",
                                                               "fakeserver",
                                                               "127.0.0.1",
                                                               "ro")

    def test_update_access_access_rules_wrong_type(self):
        access_rules = [{
            'access_to': '127.0.0.1',
            'access_level': 'ro',
            'access_type': 'user'
        }]
        self.mock_object(self.UNFS3Helper, "_allow_access")
        self.assertRaises(exception.InvalidShareAccess,
                          self.UNFS3Helper.update_access, "fakeshareid",
                          "fakeserver", access_rules, [], [])

    def test_update_access_add_rules_ok(self):
        add_rules = [{
            'access_to': '127.0.0.1',
            'access_level': 'ro',
            'access_type': 'ip'
        }]
        self.mock_object(self.UNFS3Helper, "_allow_access")
        self.UNFS3Helper.update_access("fakeshareid", "fakeserver", [],
                                       add_rules, [])
        self.UNFS3Helper._allow_access.assert_called_once_with("fakeshareid",
                                                               "fakeserver",
                                                               "127.0.0.1",
                                                               "ro")

    def test_update_access_add_rules_wrong_type(self):
        add_rules = [{
            'access_to': '127.0.0.1',
            'access_level': 'ro',
            'access_type': 'user'
        }]
        self.mock_object(self.UNFS3Helper, "_allow_access")
        self.assertRaises(exception.InvalidShareAccess,
                          self.UNFS3Helper.update_access, "fakeshareid",
                          "fakeserver", [], add_rules, [])

    def test_update_access_delete_rules_ok(self):
        delete_rules = [{
            'access_to': '127.0.0.1',
            'access_level': 'ro',
            'access_type': 'ip'
        }]
        self.mock_object(self.UNFS3Helper, "_deny_access")
        self.UNFS3Helper.update_access("fakeshareid", "fakeserver", [], [],
                                       delete_rules)
        self.UNFS3Helper._deny_access.assert_called_once_with("fakeserver",
                                                              "127.0.0.1")

    def test_update_access_delete_rules_not_ok(self):
        delete_rules = [{
            'access_to': '127.0.0.1',
            'access_level': 'ro',
            'access_type': 'user'
        }]
        self.mock_object(self.UNFS3Helper, "_deny_access")
        self.UNFS3Helper.update_access("fakeshareid", "fakeserver", [], [],
                                       delete_rules)
        self.assertFalse(self.UNFS3Helper._deny_access.called)


@testtools.skipIf(lxd.NO_LXD, "pylxd is unavailable")
class LXDCIFSHelperTestCase(test.TestCase):
    """Tests LXDCIFSHelper"""

    def setUp(self):
        super(LXDCIFSHelperTestCase, self).setUp()
        self.lxd_helper = mock.Mock()
        self.fake_conf = mock.Mock()
        self.fake_conf.lxd_cifs_guest_ok = "yes"
        self.CIFSHelper = lxd.LXDCIFSHelper(self.lxd_helper,
                                            share=fake_share(),
                                            config=self.fake_conf)

    def tearDown(self):
        super(LXDCIFSHelperTestCase, self).tearDown()

    def fake_exec_sync(self, *args, **kwargs):
        kwargs['execute_arguments'].append(args)
        try:
            ret_val = kwargs['ret_val']
        except KeyError:
            ret_val = None
        return ret_val

    def test_create_share_guest_ok(self):
        expected_arguments = [
            ('fakeserver', ['net', 'conf', 'addshare', 'fakeshareid',
             '/shares/fakeshareid', 'writeable=y', 'guest_ok=y']),
            ('fakeserver', ['net', 'conf', 'setparm', 'fakeshareid',
             'browseable', 'yes']),
            ('fakeserver', ['net', 'conf', 'setparm', 'fakeshareid',
             'hosts allow', '127.0.0.1']),
            ('fakeserver', ['net', 'conf', 'setparm', 'fakeshareid',
             'read only', 'no']),
            ('fakeserver', ['net', 'conf', 'setparm', 'fakeshareid',
             'hosts deny', '0.0.0.0/0']),
            ('fakeserver', ['net', 'conf', 'setparm', 'fakeshareid',
             'create mask', '0755'])]
        actual_arguments = []
        self.lxd_helper.execute_sync = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val="0/0 " * 20)
        self.CIFSHelper.share = fake_share()
        self.CIFSHelper.create_share("fakeserver")
        self.assertEqual(expected_arguments.sort(), actual_arguments.sort())

    def test_create_share_guest_not_ok(self):
        self.CIFSHelper.conf = mock.Mock()
        self.CIFSHelper.conf.lxd_cifs_guest_ok = "no"
        expected_arguments = [
            ('fakeserver', ['net', 'conf', 'addshare', 'fakeshareid',
             '/shares/fakeshareid', 'writeable=y', 'guest_ok=n']),
            ('fakeserver', ['net', 'conf', 'setparm', 'fakeshareid',
             'browseable', 'yes']),
            ('fakeserver', ['net', 'conf', 'setparm', 'fakeshareid',
             'hosts allow', '127.0.0.1']),
            ('fakeserver', ['net', 'conf', 'setparm', 'fakeshareid',
             'read only', 'no']),
            ('fakeserver', ['net', 'conf', 'setparm', 'fakeshareid',
             'hosts deny', '0.0.0.0/0']),
            ('fakeserver', ['net', 'conf', 'setparm', 'fakeshareid',
             'create mask', '0755'])]
        actual_arguments = []
        self.lxd_helper.execute_sync = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val="0/0 " * 20)
        self.CIFSHelper.share = fake_share()
        self.CIFSHelper.create_share("fakeserver")
        self.assertEqual(expected_arguments.sort(), actual_arguments.sort())

    def test_delete_share(self):
        self.CIFSHelper.share = fake_share()
        self.CIFSHelper.delete_share("fakeserver")
        self.CIFSHelper.lxd.execute_sync.assert_called_with(
            'fakeserver',
            ['net', 'conf', 'delshare', 'fakeshareid'])

    def test__deny_access_host_present(self):
        self.lxd_helper.execute_sync.side_effect = ['127.0.0.1', ""]
        self.CIFSHelper.share = fake_share()
        self.CIFSHelper._deny_access("fakeserver", "127.0.0.1")
        self.CIFSHelper.lxd.execute_sync.assert_called_with(
            'fakeserver',
            ['net', 'conf', 'setparm', 'fakeshareid', 'hosts allow', ''])

    def test__deny_access_no_host(self):
        self.lxd_helper.execute_sync.side_effect = ['', ""]
        self.CIFSHelper.share = fake_share()
        self.CIFSHelper._deny_access("fakeserver", "127.0.0.1")
        self.CIFSHelper.lxd.execute_sync.assert_called_with(
            'fakeserver',
            ['net', 'conf', 'getparm', 'fakeshareid', 'hosts allow'])

    def test__allow_access_host_present(self):
        self.lxd_helper.execute_sync.side_effect = ['127.0.0.1', ""]
        self.CIFSHelper._allow_access("fakeshareid", "fakeserver", "127.0.0.1",
                                      "rw")
        self.CIFSHelper.lxd.execute_sync.assert_called_with(
            'fakeserver',
            ['net', 'conf', 'getparm', 'fakeshareid', 'hosts allow'])

    def test__allow_access_no_host(self):
        self.lxd_helper.execute_sync.side_effect = ['', ""]
        self.CIFSHelper._allow_access("fakeshareid", "fakeserver", "127.0.0.1",
                                      "rw")
        self.CIFSHelper.lxd.execute_sync.assert_called_with(
            'fakeserver',
            ['net', 'conf', 'setparm', 'fakeshareid', 'hosts allow',
             '127.0.0.1, '])

    def test_allow_access_ro_guest_ok(self):
        self.CIFSHelper.conf = mock.Mock()
        self.CIFSHelper.conf.lxd_cifs_guest_ok = "yes"
        self.CIFSHelper._allow_access("fakeshareid", "fakeserver", "127.0.0.1",
                                      "ro")
        self.assertFalse(self.lxd_helper.execute_sync.called)

    def test_allow_access_ro_guest_not_ok(self):
        self.CIFSHelper.conf = mock.Mock()
        self.CIFSHelper.conf.lxd_cifs_guest_ok = "no"
        self.assertRaises(exception.ManilaException,
                          self.CIFSHelper._allow_access, "fakeshareid",
                          "fakeserver", "127.0.0.1", "ro")

    def test_allow_user_access_ok(self):
        self.CIFSHelper._allow_user_access("fakeshareid", "fakeserver",
                                           "fakeuser", "ro")
        self.CIFSHelper.lxd.execute_sync.assert_called_with(
            'fakeserver',
            ['net', 'conf', 'setparm', 'fakeshareid', 'read list', 'fakeuser'])

    def test_allow_user_access_not_ok(self):
        self.assertRaises(exception.InvalidShareAccessLevel,
                          self.CIFSHelper._allow_user_access,
                          "fakeshareid", "fakeserver", "fakeuser", "rx")

    def test_update_access_access_rules_ok(self):
        allow_rules = [{
            'access_to': '127.0.0.1',
            'access_level': 'ro',
            'access_type': 'ip'
        }]
        self.mock_object(self.CIFSHelper, "_allow_access")
        self.CIFSHelper.update_access("fakeshareid", "fakeserver", allow_rules,
                                      [], [])
        self.CIFSHelper._allow_access.assert_called_once_with("fakeshareid",
                                                              "fakeserver",
                                                              "127.0.0.1",
                                                              "ro")

    def test_update_access_access_rules_ok_user(self):
        allow_rules = [{
            'access_to': 'fakeuser',
            'access_level': 'ro',
            'access_type': 'user'
        }]
        self.mock_object(self.CIFSHelper, "_allow_user_access")
        self.CIFSHelper.update_access("fakeshareid", "fakeserver", allow_rules,
                                      [], [])
        self.CIFSHelper._allow_user_access.assert_called_once_with(
            "fakeshareid",
            "fakeserver",
            "fakeuser",
            "ro")

    def test_update_access_access_rules_wrong_type(self):
        allow_rules = [{
            'access_to': '127.0.0.1',
            'access_level': 'ro',
            'access_type': 'fake'
        }]
        self.mock_object(self.CIFSHelper, "_allow_access")
        self.assertRaises(exception.InvalidShareAccess,
                          self.CIFSHelper.update_access, "fakeshareid",
                          "fakeserver", allow_rules, [], [])

    def test_update_access_add_rules_ok(self):
        add_rules = [{
            'access_to': '127.0.0.1',
            'access_level': 'ro',
            'access_type': 'ip'
        }]
        self.mock_object(self.CIFSHelper, "_allow_access")
        self.CIFSHelper.update_access("fakeshareid", "fakeserver", [],
                                      add_rules, [])
        self. CIFSHelper._allow_access.assert_called_once_with("fakeshareid",
                                                               "fakeserver",
                                                               "127.0.0.1",
                                                               "ro")

    def test_update_access_add_rules_ok_user(self):
        add_rules = [{
            'access_to': 'fakeuser',
            'access_level': 'ro',
            'access_type': 'user'
        }]
        self.mock_object(self.CIFSHelper, "_allow_user_access")
        self.CIFSHelper.update_access("fakeshareid", "fakeserver", [],
                                      add_rules, [])
        self. CIFSHelper._allow_user_access.assert_called_once_with(
            "fakeshareid",
            "fakeserver",
            "fakeuser",
            "ro")

    def test_update_access_add_rules_wrong_type(self):
        add_rules = [{
            'access_to': '127.0.0.1',
            'access_level': 'ro',
            'access_type': 'fake'
        }]
        self.mock_object(self.CIFSHelper, "_allow_access")
        self.assertRaises(exception.InvalidShareAccess,
                          self.CIFSHelper.update_access, "fakeshareid",
                          "fakeserver", [], add_rules, [])

    def test_update_access_delete_rules_ok(self):
        delete_rules = [{
            'access_to': '127.0.0.1',
            'access_level': 'ro',
            'access_type': 'ip'
        }]
        self.mock_object(self.CIFSHelper, "_deny_access")
        self.CIFSHelper.update_access("fakeshareid", "fakeserver", [], [],
                                      delete_rules)
        self.CIFSHelper._deny_access.assert_called_once_with("fakeserver",
                                                             "127.0.0.1")

    def test_update_access_delete_rules_not_ok(self):
        delete_rules = [{
            'access_to': '127.0.0.1',
            'access_level': 'ro',
            'access_type': 'user'
        }]
        self.mock_object(self.CIFSHelper, "_deny_access")
        self.CIFSHelper.update_access("fakeshareid", "fakeserver", [], [],
                                      delete_rules)
        self.assertFalse(self.CIFSHelper._deny_access.called)


@testtools.skipIf(lxd.NO_LXD, "pylxd is unavailable")
class LXDDriverTestCase(test.TestCase):
    """Tests LXDDriver."""

    def setUp(self):
        super(LXDDriverTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self)
        self._context = context.get_admin_context()
        self._db = mock.Mock()
        self.fake_conf = configuration.Configuration(None)

        CONF.set_default('driver_handles_share_servers', True)

        self._driver = lxd.LXDDriver(self._db, configuration=self.fake_conf)

        self.share = fake_share()
        self.access = fake_access()
        self.server = {
            'public_address': self.fake_conf.lvm_share_export_ip,
            'instance_id': 'LVM',
        }

        # Used only to test compatibility with share manager
        self.share_server = "fake_share_server"

    def tearDown(self):
        super(LXDDriverTestCase, self).tearDown()

    def test_create_share(self):
        helper = mock.Mock()
        self.mock_object(helper, 'create_share',
                         mock.Mock(return_value='export_location'))
        self.mock_object(self._driver, "_get_helper",
                         mock.Mock(return_value=helper))
        self.mock_object(self._driver, '_execute')
        self.mock_object(self._driver.lxd, 'execute_sync')
        self.assertEqual('export_location',
                         self._driver.create_share(self._context, self.share,
                                                   {'id': 'fake'}))

    def test_update_share_stats(self):
        self.mock_object(self._driver, 'get_share_server_pools',
                         mock.Mock(return_value='test-pool'))

        self._driver._update_share_stats()
        self.assertEqual('LXD', self._driver._stats['share_backend_name'])
        self.assertEqual('NFS_CIFS', self._driver._stats['storage_protocol'])
        self.assertEqual(0, self._driver._stats['reserved_percentage'])
        self.assertEqual(None,
                         self._driver._stats['consistency_group_support'])
        self.assertEqual(False, self._driver._stats['snapshot_support'])
        self.assertEqual('LXDDriver', self._driver._stats['driver_name'])
        self.assertEqual('test-pool', self._driver._stats['pools'])

    def test_get_share_server_pools(self):
        ret_vgs = "VSize 100g size\nVFree 100g whatever"
        expected_result = [{'reserved_percentage': 0,
                            'pool_name': 'manila_lxd_volumes',
                            'total_capacity_gb': 100.0,
                            'free_capacity_gb': 100.0}]
        self.mock_object(self._driver, "_execute",
                         mock.Mock(return_value=(ret_vgs, 0)))
        result = self._driver.get_share_server_pools()
        self.assertEqual(expected_result, result)

    def test__get_nfs_helper_ganesha(self):
        self._driver.configuration.lxd_nfs_server = "ganesha"
        self.assertRaises(exception.ManilaException,
                          self._driver._get_nfs_helper)

    def test__get_nfs_helper_unfs3(self):
        self.assertEqual(lxd.LXDUnfs3Helper, self._driver._get_nfs_helper())

    def test__get_nfs_helper_other(self):
        self._driver.configuration.lxd_nfs_server = "MightyNFS"
        self.assertRaises(exception.ManilaException,
                          self._driver._get_nfs_helper)

    def test__get_helper_nfs_new(self):
        share = {'share_proto': 'NFS'}
        self.mock_object(self._driver, "nfshelper")
        self._driver._get_helper(share)
        self._driver.nfshelper.assert_called_once_with(self._driver.lxd,
                                                       share=share)

    def test__get_helper_nfs_existing(self):
        share = {'share_proto': 'NFS'}
        self._driver._helpers['NFS'] = mock.Mock()
        result = self._driver._get_helper(share)
        self.assertEqual(share, result.share)

    def test__get_helper_cifs_new(self):
        share = {'share_proto': 'CIFS'}
        result = self._driver._get_helper(share)
        self.assertEqual(lxd.LXDCIFSHelper, type(result))

    def test__get_helper_cifs_existing(self):
        share = {'share_proto': 'CIFS'}
        self._driver._helpers['CIFS'] = mock.Mock()
        result = self._driver._get_helper(share)
        self.assertEqual(share, result.share)

    def test__get_helper_other(self):
        share = {'share_proto': 'SuperProtocol'}
        self.assertRaises(exception.InvalidShare, self._driver._get_helper,
                          share)

    def test__get_lv_device(self):
        self.assertEqual("/dev/manila_lxd_volumes/fakeshareid",
                         self._driver._get_lv_device(self.share))

    def test__get_lv_folder(self):
        self.assertEqual("/tmp/fakeshareid",
                         self._driver._get_lv_folder(self.share))

    def test_extend_share(self):
        self.mock_object(self._driver, '_execute')
        self.mock_object(self._driver, '_get_lv_device',
                         mock.Mock(return_value="path"))
        self._driver.extend_share(self.share, 'share', 3)
        local_path = 'path'
        self._driver._execute.assert_called_with('resize2fs', local_path,
                                                 run_as_root=True)

    def test__connect_to_network(self):
        network_info = fake_network()
        helper = mock.Mock()
        self.mock_object(self._driver, "_execute",
                         mock.Mock(return_value=helper))
        self.mock_object(self._driver.lxd, "execute_sync")
        self.mock_object(self._driver, "_get_host_veth",
                         mock.Mock(return_value="vethBEEF42"))
        self._driver._connect_to_network("fake-server", network_info)

    def test_delete_share(self):
        helper = mock.Mock()
        self.mock_object(self._driver, "_get_helper",
                         mock.Mock(return_value=helper))
        self.mock_object(self._driver, '_execute')
        self.mock_object(self._driver.lxd, 'execute_sync')
        self._driver.delete_share(self._context, self.share, {'id': 'fake'})
        self._driver._execute.assert_called_with(
            'lvremove', '-f', '--autobackup', 'n',
            '/dev/manila_lxd_volumes/fakeshareid',
            run_as_root=True)

    def test__get_host_veth(self):
        fake_data = {
            "network": {"eth0": {"host_name": "vethBEEF42"}}
        }
        self.mock_object(self._driver.lxd.api, "container_info",
                         mock.Mock(return_value=fake_data))
        self.assertEqual("vethBEEF42",
                         self._driver._get_host_veth("fakeserver"))

    def test__teardown_server(self):
        self.mock_object(self._driver, '_get_host_veth',
                         mock.Mock(return_value='veth42BEEF'))
        self.mock_object(self._driver.lxd, 'stop_container')
        self.mock_object(self._driver, '_execute')
        self._driver._teardown_server(server_details={'id': 'fake'})
        self._driver.lxd.stop_container.assert_called_with('manila-fake')
        self._driver._execute.assert_called_with("ovs-vsctl", "--", "del-port",
                                                 'br-int', 'veth42BEEF',
                                                 run_as_root=True)

    def test_update_access_access_rules_ok(self):
        helper = mock.Mock()
        self.mock_object(self._driver, "_get_helper",
                         mock.Mock(return_value=helper))
        self._driver.update_access(self._context, self.share,
                                   [{'access_level': const.ACCESS_LEVEL_RW}],
                                   [], [], {"id": "fake"})
        helper.update_access.assert_called_with('fakeshareid', 'manila-fake',
                                                [{'access_level': 'rw'}],
                                                [], [])

    def test__get_container_name(self):
        self.assertEqual("manila-fake-server",
                         self._driver._get_container_name("fake-server"))

    def test__setup_server_container_fails(self):
        network_info = fake_network()
        self.mock_object(self._driver.lxd, 'create_container')
        self._driver.lxd.create_container.side_effect = KeyError()
        self.assertRaises(exception.ManilaException,
                          self._driver._setup_server, network_info)

    def test__setup_server_ok(self):
        network_info = fake_network()
        server_id = self._driver._get_container_name(network_info["server_id"])
        self.mock_object(self._driver.lxd, 'create_container')
        self.mock_object(self._driver.lxd, 'start_container')
        self.mock_object(self._driver.lxd.api, 'container_run_command')
        self.mock_object(self._driver, '_connect_to_network')
        self.assertEqual(network_info['server_id'],
                         self._driver._setup_server(network_info)['id'])
        self._driver.lxd.create_container.assert_called_once_with(server_id)
        self._driver.lxd.start_container.assert_called_once_with(server_id)
        self._driver._connect_to_network.assert_called_once_with(server_id,
                                                                 network_info)
