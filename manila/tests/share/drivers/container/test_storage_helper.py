# Copyright 2016 Mirantis, Inc.
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
"""Unit tests for the Storage helper module."""

import functools
import mock

from manila import exception
from manila.share import configuration
from manila.share.drivers.container import storage_helper
from manila import test
from manila.tests.share.drivers.container.fakes import fake_share


class LVMHelperTestCase(test.TestCase):
    """Tests ContainerShareDriver"""

    def setUp(self):
        super(LVMHelperTestCase, self).setUp()
        self.share = fake_share()
        self.fake_conf = configuration.Configuration(None)
        self.LVMHelper = storage_helper.LVMHelper(configuration=self.fake_conf)

    def fake_exec_sync(self, *args, **kwargs):
        kwargs['execute_arguments'].append(args)
        try:
            ret_val = kwargs['ret_val']
        except KeyError:
            ret_val = None
        return ret_val

    def test_lvmhelper_setup_explodes_in_gore_on_no_config_supplied(self):
        self.assertRaises(exception.ManilaException,
                          storage_helper.LVMHelper,
                          None)

    def test_get_share_server_pools(self):
        ret_vgs = "VSize 100g size\nVFree 100g whatever"
        expected_result = [{'reserved_percentage': 0,
                            'pool_name': 'manila_docker_volumes',
                            'total_capacity_gb': 100.0,
                            'free_capacity_gb': 100.0}]
        self.mock_object(self.LVMHelper, "_execute",
                         mock.Mock(return_value=(ret_vgs, 0)))

        result = self.LVMHelper.get_share_server_pools()

        self.assertEqual(expected_result, result)

    def test__get_lv_device(self):
        self.assertEqual("/dev/manila_docker_volumes/fakeshareid",
                         self.LVMHelper._get_lv_device(self.share))

    def test__get_lv_folder(self):
        self.assertEqual("/tmp/shares/fakeshareid",
                         self.LVMHelper._get_lv_folder(self.share))

    def test_provide_storage(self):
        actual_arguments = []
        expected_arguments = [
            ('lvcreate', '-p', 'rw', '-L', '1G', '-n', 'fakeshareid',
             'manila_docker_volumes'),
            ('mkfs.ext4', '/dev/manila_docker_volumes/fakeshareid'),
        ]
        self.LVMHelper._execute = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='')

        self.LVMHelper.provide_storage(self.share)

        self.assertEqual(expected_arguments, actual_arguments)

    def test_remove_storage(self):
        actual_arguments = []
        expected_arguments = [
            ('umount', '/dev/manila_docker_volumes/fakeshareid'),
            ('lvremove', '-f', '--autobackup', 'n',
             '/dev/manila_docker_volumes/fakeshareid')
        ]
        self.LVMHelper._execute = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='')

        self.LVMHelper.remove_storage(self.share)

        self.assertEqual(expected_arguments, actual_arguments)

    def test_remove_storage_umount_failed(self):
        def fake_execute(*args, **kwargs):
            if 'umount' in args:
                raise exception.ProcessExecutionError()

        self.mock_object(storage_helper.LOG, "warning")
        self.mock_object(self.LVMHelper, "_execute", fake_execute)

        self.LVMHelper.remove_storage(self.share)

        self.assertTrue(storage_helper.LOG.warning.called)

    def test_remove_storage_lvremove_failed(self):
        def fake_execute(*args, **kwargs):
            if 'lvremove' in args:
                raise exception.ProcessExecutionError()

        self.mock_object(storage_helper.LOG, "warning")
        self.mock_object(self.LVMHelper, "_execute", fake_execute)

        self.LVMHelper.remove_storage(self.share)

        self.assertTrue(storage_helper.LOG.warning.called)

    def test_extend_share(self):
        actual_arguments = []
        expected_arguments = [
            ('lvextend', '-L', 'shareG', '-n',
             '/dev/manila_docker_volumes/fakeshareid'),
            ('e2fsck', '-f', '-y', '/dev/manila_docker_volumes/fakeshareid'),
            ('resize2fs', '/dev/manila_docker_volumes/fakeshareid'),
        ]
        self.LVMHelper._execute = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='')

        self.LVMHelper.extend_share(self.share, 'share', 3)

        self.assertEqual(expected_arguments, actual_arguments)
