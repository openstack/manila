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
        change_data_access_call = self.mock_object(
            self.helper, '_change_data_access_to_instance')
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
            mock.call(self.share_instance, [access], deny=True),
            mock.call(self.share_instance),
        ]
        if allow_dest_instance:
            change_access_calls.append(
                mock.call(self.share_instance))
        self.assertEqual(len(change_access_calls),
                         change_data_access_call.call_count)
        change_data_access_call.assert_has_calls(change_access_calls)

    @ddt.data({'ip': []}, {'cert': []}, {'user': []}, {'cephx': []}, {'x': []})
    def test__get_access_entries_according_to_mapping(self, mapping):

        data_copy_helper.CONF.data_node_access_cert = 'fake'
        data_copy_helper.CONF.data_node_access_ip = 'fake'
        data_copy_helper.CONF.data_node_access_admin_user = 'fake'
        expected = [{
            'access_type': list(mapping.keys())[0],
            'access_level': constants.ACCESS_LEVEL_RW,
            'access_to': 'fake',
        }]

        exists = [x for x in mapping if x in ('ip', 'user', 'cert')]

        if exists:
            result = self.helper._get_access_entries_according_to_mapping(
                mapping)
            self.assertEqual(expected, result)
        else:
            self.assertRaises(
                exception.ShareDataCopyFailed,
                self.helper._get_access_entries_according_to_mapping, mapping)

    def test__get_access_entries_according_to_mapping_exception_not_set(self):

        data_copy_helper.CONF.data_node_access_ip = None

        self.assertRaises(
            exception.ShareDataCopyFailed,
            self.helper._get_access_entries_according_to_mapping, {'ip': []})

    def test__get_access_entries_according_to_mapping_ip_list(self):

        ips = ['fake1', 'fake2']
        data_copy_helper.CONF.data_node_access_ips = ips
        data_copy_helper.CONF.data_node_access_ip = None

        expected = [{
            'access_type': 'ip',
            'access_level': constants.ACCESS_LEVEL_RW,
            'access_to': x,
        } for x in ips]

        result = self.helper._get_access_entries_according_to_mapping(
            {'ip': []})
        self.assertEqual(expected, result)

    def test_deny_access_to_data_service(self):

        # mocks
        self.mock_object(self.helper, '_change_data_access_to_instance')

        # run
        self.helper.deny_access_to_data_service(
            [self.access], self.share_instance['id'])

        # asserts
        self.helper._change_data_access_to_instance.assert_called_once_with(
            self.share_instance['id'], [self.access], deny=True)

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
    def test__change_data_access_to_instance(self, deny):
        access_rule = db_utils.create_access(share_id=self.share['id'])
        access_rule = db.share_instance_access_get(
            self.context, access_rule['id'], self.share_instance['id'])

        # mocks
        self.mock_object(share_rpc.ShareAPI, 'update_access')
        self.mock_object(utils, 'wait_for_access_update')
        mock_access_rules_status_update = self.mock_object(
            self.helper.access_helper,
            'get_and_update_share_instance_access_rules_status')
        mock_rules_update = self.mock_object(
            self.helper.access_helper,
            'get_and_update_share_instance_access_rules')

        # run
        self.helper._change_data_access_to_instance(
            self.share_instance, access_rule, deny=deny)

        # asserts
        if deny:
            mock_rules_update.assert_called_once_with(
                self.context, share_instance_id=self.share_instance['id'],
                filters={'access_id': [access_rule['id']]},
                updates={'state': constants.ACCESS_STATE_QUEUED_TO_DENY})

        else:
            self.assertFalse(mock_rules_update.called)
        share_rpc.ShareAPI.update_access.assert_called_once_with(
            self.context, self.share_instance)
        mock_access_rules_status_update.assert_called_once_with(
            self.context, status=constants.SHARE_INSTANCE_RULES_SYNCING,
            share_instance_id=self.share_instance['id'])
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
