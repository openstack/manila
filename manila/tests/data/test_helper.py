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
        self.access = db_utils.create_access(share_id=self.share['id'])
        self.helper = data_copy_helper.DataServiceHelper(
            self.context, db, self.share)

    def test_allow_data_access(self):

        access_create = {'access_type': self.access['access_type'],
                         'access_to': self.access['access_to'],
                         'access_level': self.access['access_level'],
                         'share_id': self.access['share_id']}

        # mocks
        self.mock_object(
            self.helper.db, 'share_access_get_all_by_type_and_access',
            mock.Mock(return_value=[self.access]))

        self.mock_object(self.helper, '_change_data_access_to_instance')

        self.mock_object(self.helper.db, 'share_access_create',
                         mock.Mock(return_value=self.access))

        # run
        self.helper._allow_data_access(
            self.access, self.share_instance['id'], self.share_instance['id'])

        # asserts
        self.helper.db.share_access_get_all_by_type_and_access.\
            assert_called_once_with(
                self.context, self.share['id'], self.access['access_type'],
                self.access['access_to'])

        self.helper.db.share_access_create.assert_called_once_with(
            self.context, access_create)

        self.helper._change_data_access_to_instance.assert_has_calls(
            [mock.call(self.share_instance['id'], self.access, allow=False),
             mock.call(self.share_instance['id'], self.access, allow=True),
             mock.call(self.share_instance['id'], self.access, allow=True)])

    def test_deny_access_to_data_service(self):

        # mocks
        self.mock_object(self.helper, '_change_data_access_to_instance')

        # run
        self.helper.deny_access_to_data_service(
            self.access, self.share_instance['id'])

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
        self.helper.cleanup_data_access(self.access, self.share_instance['id'])

        # asserts
        self.helper.deny_access_to_data_service.assert_called_once_with(
            self.access, self.share_instance['id'])

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

        self.mock_object(self.helper.db, 'share_instance_get',
                         mock.Mock(return_value=self.share_instance))

        if allow:
            self.mock_object(share_rpc.ShareAPI, 'allow_access')
        else:
            self.mock_object(share_rpc.ShareAPI, 'deny_access')

        self.mock_object(utils, 'wait_for_access_update')

        # run
        self.helper._change_data_access_to_instance(
            self.share_instance['id'], self.access, allow=allow)

        # asserts
        self.helper.db.share_instance_update_access_status.\
            assert_called_once_with(self.context, self.share_instance['id'],
                                    constants.STATUS_OUT_OF_SYNC)

        self.helper.db.share_instance_get.assert_called_once_with(
            self.context, self.share_instance['id'], with_share_data=True)

        if allow:
            share_rpc.ShareAPI.allow_access.assert_called_once_with(
                self.context, self.share_instance, self.access)
        else:
            share_rpc.ShareAPI.deny_access.assert_called_once_with(
                self.context, self.share_instance, self.access)

        utils.wait_for_access_update.assert_called_once_with(
            self.context, self.helper.db, self.share_instance,
            data_copy_helper.CONF.data_access_wait_access_rules_timeout)

    @ddt.data({'proto': 'GLUSTERFS', 'conf': None},
              {'proto': 'GLUSTERFS', 'conf': 'cert'},
              {'proto': 'OTHERS', 'conf': None},
              {'proto': 'OTHERS', 'conf': 'ip'})
    @ddt.unpack
    def test_allow_access_to_data_service(self, proto, conf):

        share = db_utils.create_share(share_proto=proto)

        access_allow = {'access_type': conf,
                        'access_to': conf,
                        'access_level': constants.ACCESS_LEVEL_RW}

        data_copy_helper.CONF.set_default('data_node_access_cert', conf)
        data_copy_helper.CONF.set_default('data_node_access_ip', conf)

        # mocks
        self.mock_object(self.helper, '_allow_data_access',
                         mock.Mock(return_value=self.access))

        # run and asserts
        if conf:
            result = self.helper.allow_access_to_data_service(
                share, 'ins1_id', 'ins2_id')
            self.assertEqual(self.access, result)
            self.helper._allow_data_access.assert_called_once_with(
                access_allow, 'ins1_id', 'ins2_id')
        else:
            self.assertRaises(exception.ShareDataCopyFailed,
                              self.helper.allow_access_to_data_service, share,
                              'ins1_id', 'ins2_id')

    def test_mount_share_instance(self):

        fake_path = ''.join(('/fake_path/', self.share_instance['id']))

        # mocks
        self.mock_object(utils, 'execute')
        self.mock_object(os.path, 'exists', mock.Mock(
            side_effect=[False, False, True]))
        self.mock_object(os, 'makedirs')

        # run
        self.helper.mount_share_instance(
            'mount %(path)s', '/fake_path', self.share_instance['id'])

        # asserts
        utils.execute.assert_called_once_with('mount', fake_path,
                                              run_as_root=True)

        os.makedirs.assert_called_once_with(fake_path)
        os.path.exists.assert_has_calls([
            mock.call(fake_path),
            mock.call(fake_path),
            mock.call(fake_path)
        ])

    def test_unmount_share_instance(self):

        fake_path = ''.join(('/fake_path/', self.share_instance['id']))

        # mocks
        self.mock_object(utils, 'execute')
        self.mock_object(os.path, 'exists', mock.Mock(
            side_effect=[True, True, False]))
        self.mock_object(os, 'rmdir')

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
