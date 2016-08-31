# Copyright 2015 Hitachi Data Systems inc.
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

import os
import six

import ddt
import mock

from manila.common import constants
from manila import context
from manila.data import helper as data_copy_helper
from manila import db
from manila import exception
from manila.share import rpcapi as share_rpc
from manila import test
from manila.tests import db_utils
from manila import utils


@ddt.ddt
class DataServiceHelperTestCase(test.TestCase):
    """Tests DataServiceHelper."""

    def setUp(self):
        super(DataServiceHelperTestCase, self).setUp()
        self.share = db_utils.create_share()
        self.share_instance = db_utils.create_share_instance(
            share_id=self.share['id'],
            status=constants.STATUS_AVAILABLE)
        self.context = context.get_admin_context()
        self.share_instance = db.share_instance_get(
            self.context, self.share_instance['id'], with_share_data=True)
        self.access = db_utils.create_access(share_id=self.share['id'])
        self.helper = data_copy_helper.DataServiceHelper(
            self.context, db, self.share)

    @ddt.data(True, False)
    def test_allow_access_to_data_service(self, allow_dest_instance):

        access = db_utils.create_access(share_id=self.share['id'])
        info_src = {
            'access_mapping': {
                'ip': ['nfs'],
                'user': ['cifs', 'nfs'],
            }
        }
        info_dest = {
            'access_mapping': {
                'ip': ['nfs', 'cifs'],
                'user': ['cifs'],
            }
        }
        if allow_dest_instance:
            mapping = {'ip': ['nfs'], 'user': ['cifs']}
        else:
            mapping = info_src['access_mapping']

        fake_access = {
            'access_to': 'fake_ip',
            'access_level': constants.ACCESS_LEVEL_RW,
            'access_type': 'ip',
        }
        access_values = fake_access
        access_values['share_id'] = self.share['id']

        self.mock_object(
            self.helper, '_get_access_entries_according_to_mapping',
            mock.Mock(return_value=[fake_access]))
        self.mock_object(
            self.helper.db, 'share_access_get_all_by_type_and_access',
            mock.Mock(return_value=[access]))
        self.mock_object(self.helper, '_change_data_access_to_instance')
        self.mock_object(self.helper.db, 'share_instance_access_create',
                         mock.Mock(return_value=access))

        if allow_dest_instance:
            result = self.helper.allow_access_to_data_service(
                self.share_instance, info_src, self.share_instance, info_dest)
        else:
            result = self.helper.allow_access_to_data_service(
                self.share_instance, info_src)

        self.assertEqual([access], result)

        (self.helper._get_access_entries_according_to_mapping.
         assert_called_once_with(mapping))
        (self.helper.db.share_access_get_all_by_type_and_access.
            assert_called_once_with(
                self.context, self.share['id'], fake_access['access_type'],
                fake_access['access_to']))
        access_create_calls = [
            mock.call(self.context, access_values, self.share_instance['id'])
        ]
        if allow_dest_instance:
            access_create_calls.append(mock.call(
                self.context, access_values, self.share_instance['id']))
        self.helper.db.share_instance_access_create.assert_has_calls(
            access_create_calls)
        change_access_calls = [
            mock.call(self.share_instance, access, allow=False),
            mock.call(self.share_instance, access, allow=True),
        ]
        if allow_dest_instance:
            change_access_calls.append(
                mock.call(self.share_instance, access, allow=True))
        self.helper._change_data_access_to_instance.assert_has_calls(
            change_access_calls)

    @ddt.data({'ip': []}, {'cert': []}, {'user': []}, {'cephx': []}, {'x': []})
    def test__get_access_entries_according_to_mapping(self, mapping):

        data_copy_helper.CONF.data_node_access_cert = None
        data_copy_helper.CONF.data_node_access_ip = 'fake'
        data_copy_helper.CONF.data_node_access_admin_user = 'fake'
        expected = [{
            'access_type': six.next(six.iteritems(mapping))[0],
            'access_level': constants.ACCESS_LEVEL_RW,
            'access_to': 'fake',
        }]

        exists = [x for x in mapping if x in ('ip', 'user')]

        if exists:
            result = self.helper._get_access_entries_according_to_mapping(
                mapping)
        else:
            self.assertRaises(
                exception.ShareDataCopyFailed,
                self.helper._get_access_entries_according_to_mapping, mapping)

        if exists:
            self.assertEqual(expected, result)

    def test_deny_access_to_data_service(self):

        # mocks
        self.mock_object(self.helper, '_change_data_access_to_instance')

        # run
        self.helper.deny_access_to_data_service(
            [self.access], self.share_instance['id'])

        # asserts
        self.helper._change_data_access_to_instance.\
            assert_called_once_with(
                self.share_instance['id'], self.access, allow=False)

    @ddt.data(None, Exception('fake'))
    def test_cleanup_data_access(self, exc):

        # mocks
        self.mock_object(self.helper, 'deny_access_to_data_service',
                         mock.Mock(side_effect=exc))

        self.mock_object(data_copy_helper.LOG, 'warning')

        # run
        self.helper.cleanup_data_access([self.access],
                                        self.share_instance['id'])

        # asserts
        self.helper.deny_access_to_data_service.assert_called_once_with(
            [self.access], self.share_instance['id'])

        if exc:
            self.assertTrue(data_copy_helper.LOG.warning.called)

    @ddt.data(False, True)
    def test_cleanup_temp_folder(self, exc):

        fake_path = ''.join(('/fake_path/', self.share_instance['id']))

        # mocks
        self.mock_object(os.path, 'exists',
                         mock.Mock(side_effect=[True, True, exc]))
        self.mock_object(os, 'rmdir')

        self.mock_object(data_copy_helper.LOG, 'warning')

        # run
        self.helper.cleanup_temp_folder(
            self.share_instance['id'], '/fake_path/')

        # asserts
        os.rmdir.assert_called_once_with(fake_path)
        os.path.exists.assert_has_calls([
            mock.call(fake_path),
            mock.call(fake_path),
            mock.call(fake_path)
        ])

        if exc:
            self.assertTrue(data_copy_helper.LOG.warning.called)

    @ddt.data(None, Exception('fake'))
    def test_cleanup_unmount_temp_folder(self, exc):

        # mocks
        self.mock_object(self.helper, 'unmount_share_instance',
                         mock.Mock(side_effect=exc))
        self.mock_object(data_copy_helper.LOG, 'warning')

        # run
        self.helper.cleanup_unmount_temp_folder(
            'unmount_template', 'fake_path', self.share_instance['id'])

        # asserts
        self.helper.unmount_share_instance.assert_called_once_with(
            'unmount_template', 'fake_path', self.share_instance['id'])

        if exc:
            self.assertTrue(data_copy_helper.LOG.warning.called)

    @ddt.data(True, False)
    def test__change_data_access_to_instance(self, allow):

        # mocks
        self.mock_object(self.helper.db, 'share_instance_update_access_status')

        if allow:
            self.mock_object(share_rpc.ShareAPI, 'allow_access')
        else:
            self.mock_object(share_rpc.ShareAPI, 'deny_access')

        self.mock_object(utils, 'wait_for_access_update')

        # run
        self.helper._change_data_access_to_instance(
            self.share_instance, self.access, allow=allow)

        # asserts
        self.helper.db.share_instance_update_access_status.\
            assert_called_once_with(self.context, self.share_instance['id'],
                                    constants.STATUS_OUT_OF_SYNC)

        if allow:
            share_rpc.ShareAPI.allow_access.assert_called_once_with(
                self.context, self.share_instance, self.access)
        else:
            share_rpc.ShareAPI.deny_access.assert_called_once_with(
                self.context, self.share_instance, self.access)

        utils.wait_for_access_update.assert_called_once_with(
            self.context, self.helper.db, self.share_instance,
            data_copy_helper.CONF.data_access_wait_access_rules_timeout)

    def test_mount_share_instance(self):

        fake_path = ''.join(('/fake_path/', self.share_instance['id']))

        # mocks
        self.mock_object(utils, 'execute')
        self.mock_object(os.path, 'exists', mock.Mock(
            side_effect=[False, False, True]))
        self.mock_object(os, 'makedirs')

        # run
        self.helper.mount_share_instance(
            'mount %(path)s', '/fake_path', self.share_instance)

        # asserts
        utils.execute.assert_called_once_with('mount', fake_path,
                                              run_as_root=True)

        os.makedirs.assert_called_once_with(fake_path)
        os.path.exists.assert_has_calls([
            mock.call(fake_path),
            mock.call(fake_path),
            mock.call(fake_path)
        ])

    @ddt.data([True, True, False], [True, True, Exception('fake')])
    def test_unmount_share_instance(self, side_effect):

        fake_path = ''.join(('/fake_path/', self.share_instance['id']))

        # mocks
        self.mock_object(utils, 'execute')
        self.mock_object(os.path, 'exists', mock.Mock(
            side_effect=side_effect))
        self.mock_object(os, 'rmdir')
        self.mock_object(data_copy_helper.LOG, 'warning')

        # run
        self.helper.unmount_share_instance(
            'unmount %(path)s', '/fake_path', self.share_instance['id'])

        # asserts
        utils.execute.assert_called_once_with('unmount', fake_path,
                                              run_as_root=True)
        os.rmdir.assert_called_once_with(fake_path)
        os.path.exists.assert_has_calls([
            mock.call(fake_path),
            mock.call(fake_path),
            mock.call(fake_path)
        ])

        if any(isinstance(x, Exception) for x in side_effect):
            self.assertTrue(data_copy_helper.LOG.warning.called)
