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
import ddt
import functools
import mock

from manila import exception
from manila.share import configuration
from manila.share.drivers.container import storage_helper
from manila import test
from manila.tests.share.drivers.container.fakes import fake_share


@ddt.ddt
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

    @ddt.data("62.50g 72.50g", "    72.50g 62.50g\n", "  <62.50g <72.50g\n")
    def test_get_share_server_pools(self, ret_vgs):
        expected_result = [{'reserved_percentage': 0,
                            'pool_name': 'manila_docker_volumes',
                            'total_capacity_gb': 72.5,
                            'free_capacity_gb': 62.5}]
        self.mock_object(self.LVMHelper, "_execute",
                         mock.Mock(return_value=(ret_vgs, 0)))

        result = self.LVMHelper.get_share_server_pools()

        self.assertEqual(expected_result, result)

    def test__get_lv_device(self):
        fake_share_name = 'fakeshareid'
        self.assertEqual("/dev/manila_docker_volumes/%s" % fake_share_name,
                         self.LVMHelper._get_lv_device(fake_share_name))

    def test__get_lv_folder(self):
        fake_share_name = 'fakeshareid'
        self.assertEqual("/tmp/shares/%s" % fake_share_name,
                         self.LVMHelper._get_lv_folder(fake_share_name))

    def test_provide_storage(self):
        actual_arguments = []
        fake_share_name = 'fakeshareid'
        expected_arguments = [
            ('lvcreate', '-p', 'rw', '-L', '1G', '-n', 'fakeshareid',
             'manila_docker_volumes'),
            ('mkfs.ext4', '/dev/manila_docker_volumes/fakeshareid'),
        ]
        self.LVMHelper._execute = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='')

        self.LVMHelper.provide_storage(fake_share_name, 1)

        self.assertEqual(expected_arguments, actual_arguments)

    @ddt.data(None, exception.ProcessExecutionError)
    def test__try_to_unmount_device(self, side_effect):
        device = {}
        mock_warning = self.mock_object(storage_helper.LOG, 'warning')
        mock_execute = self.mock_object(self.LVMHelper, '_execute',
                                        mock.Mock(side_effect=side_effect))
        self.LVMHelper._try_to_unmount_device(device)

        mock_execute.assert_called_once_with(
            "umount", device, run_as_root=True
        )
        if side_effect is not None:
            mock_warning.assert_called_once()

    def test_remove_storage(self):
        fake_share_name = 'fakeshareid'
        fake_device = {}

        mock_get_lv_device = self.mock_object(
            self.LVMHelper, '_get_lv_device',
            mock.Mock(return_value=fake_device))
        mock_try_to_umount = self.mock_object(self.LVMHelper,
                                              '_try_to_unmount_device')
        mock_execute = self.mock_object(self.LVMHelper, '_execute')

        self.LVMHelper.remove_storage(fake_share_name)

        mock_get_lv_device.assert_called_once_with(
            fake_share_name
        )
        mock_try_to_umount.assert_called_once_with(fake_device)
        mock_execute.assert_called_once_with(
            'lvremove', '-f', '--autobackup', 'n', fake_device,
            run_as_root=True
        )

    def test_remove_storage_lvremove_failed(self):
        fake_share_name = 'fakeshareid'

        def fake_execute(*args, **kwargs):
            if 'lvremove' in args:
                raise exception.ProcessExecutionError()

        self.mock_object(storage_helper.LOG, "warning")
        self.mock_object(self.LVMHelper, "_execute", fake_execute)

        self.LVMHelper.remove_storage(fake_share_name)

        self.assertTrue(storage_helper.LOG.warning.called)

    @ddt.data(None, exception.ProcessExecutionError)
    def test_rename_storage(self, side_effect):
        fake_old_share_name = 'fake_old_name'
        fake_new_share_name = 'fake_new_name'
        fake_new_device = "/dev/new_device"
        fake_old_device = "/dev/old_device"

        mock_get_lv_device = self.mock_object(
            self.LVMHelper, '_get_lv_device',
            mock.Mock(side_effect=[fake_old_device, fake_new_device]))
        mock_try_to_umount = self.mock_object(self.LVMHelper,
                                              '_try_to_unmount_device')

        mock_execute = self.mock_object(self.LVMHelper, '_execute',
                                        mock.Mock(side_effect=side_effect))

        if side_effect is None:
            self.LVMHelper.rename_storage(fake_old_share_name,
                                          fake_new_share_name)
        else:
            self.assertRaises(exception.ProcessExecutionError,
                              self.LVMHelper.rename_storage,
                              fake_old_share_name, fake_new_share_name)
        mock_try_to_umount.assert_called_once_with(fake_old_device)
        mock_execute.mock_assert_called_once_with(
            "lvrename", "--autobackup", "n", fake_old_device, fake_new_device,
            run_as_root=True
        )
        mock_get_lv_device.assert_has_calls([
            mock.call(fake_old_share_name),
            mock.call(fake_new_share_name)
        ])

    def test_extend_share(self):
        actual_arguments = []
        expected_arguments = [
            ('lvextend', '-L', 'shareG', '-n',
             '/dev/manila_docker_volumes/fakeshareid'),
            ('e2fsck', '-f', '-y', '/dev/manila_docker_volumes/fakeshareid'),
            ('resize2fs', '/dev/manila_docker_volumes/fakeshareid'),
        ]
        fake_share_name = 'fakeshareid'
        self.LVMHelper._execute = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='')

        self.LVMHelper.extend_share(fake_share_name, 'share', 3)

        self.assertEqual(expected_arguments, actual_arguments)

    def test_get_size(self):
        share_name = 'fakeshareid'
        fake_old_device = {}

        mock_get_lv_device = self.mock_object(
            self.LVMHelper, '_get_lv_device',
            mock.Mock(return_value=fake_old_device))
        mock_execute = self.mock_object(self.LVMHelper, '_execute',
                                        mock.Mock(return_value=[1, "args"]))

        result = self.LVMHelper.get_size(share_name)

        mock_execute.assert_called_once_with(
            "lvs", "-o", "lv_size", "--noheadings", "--nosuffix", "--units",
            "g", fake_old_device, run_as_root=True
        )
        mock_get_lv_device.assert_called_once_with(share_name)
        self.assertEqual(result, 1)
