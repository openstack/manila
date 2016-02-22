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

import ddt
import mock

import time

from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.share import api as share_api
from manila.share import driver
from manila.share import migration
from manila import test
from manila.tests import db_utils
from manila import utils


@ddt.ddt
class ShareMigrationHelperTestCase(test.TestCase):
    """Tests ShareMigrationHelper."""

    def setUp(self):
        super(ShareMigrationHelperTestCase, self).setUp()
        self.share = db_utils.create_share()
        self.context = context.get_admin_context()
        self.helper = migration.ShareMigrationHelper(
            self.context, db,
            driver.CONF.migration_create_delete_share_timeout,
            driver.CONF.migration_wait_access_rules_timeout, self.share)

    def test_deny_rules_and_wait(self):
        saved_rules = [db_utils.create_access(share_id=self.share['id'])]

        fake_share_instances = [
            {"id": "1", "access_rules_status": constants.STATUS_OUT_OF_SYNC},
            {"id": "1", "access_rules_status": constants.STATUS_ACTIVE},
        ]

        self.mock_object(share_api.API, 'deny_access_to_instance')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=fake_share_instances))
        self.mock_object(time, 'sleep')

        self.helper.deny_rules_and_wait(
            self.context, self.share.instance, saved_rules)

        db.share_instance_get.assert_any_call(
            self.context, self.share.instance['id'])

    def test_add_rules_and_wait(self):

        fake_access_rules = [
            {'access_type': 'fake', 'access_level': 'ro', 'access_to': 'fake'},
            {'access_type': 'f0ke', 'access_level': 'rw', 'access_to': 'f0ke'},
        ]

        self.mock_object(share_api.API, 'allow_access_to_instance')
        self.mock_object(self.helper, 'wait_for_access_update')
        self.mock_object(db, 'share_access_create')

        self.helper.add_rules_and_wait(self.context, self.share.instance,
                                       fake_access_rules)

        share_api.API.allow_access_to_instance.assert_called_once_with(
            self.context, self.share.instance, mock.ANY
        )
        self.helper.wait_for_access_update.assert_called_once_with(
            self.share.instance
        )

    def test_delete_instance_and_wait(self):

        self.mock_object(share_api.API, 'delete_instance')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=[self.share.instance, None]))
        self.mock_object(time, 'sleep')

        self.helper.delete_instance_and_wait(self.context,
                                             self.share.instance)

        db.share_instance_get.assert_any_call(
            self.context, self.share.instance['id'])

    def test_delete_instance_and_wait_timeout(self):

        self.mock_object(share_api.API, 'delete_instance')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=[self.share.instance, None]))
        self.mock_object(time, 'sleep')

        now = time.time()
        timeout = now + 310

        self.mock_object(time, 'time',
                         mock.Mock(side_effect=[now, timeout]))

        self.assertRaises(exception.ShareMigrationFailed,
                          self.helper.delete_instance_and_wait,
                          self.context, self.share.instance)

        db.share_instance_get.assert_called_once_with(
            self.context, self.share.instance['id'])

    def test_delete_instance_and_wait_not_found(self):

        self.mock_object(share_api.API, 'delete_instance')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=exception.NotFound))
        self.mock_object(time, 'sleep')

        self.helper.delete_instance_and_wait(self.context,
                                             self.share.instance)

        db.share_instance_get.assert_called_once_with(
            self.context, self.share.instance['id'])

    def test_create_instance_and_wait(self):

        host = {'host': 'fake-host'}

        share_instance_creating = db_utils.create_share_instance(
            share_id=self.share['id'], status=constants.STATUS_CREATING,
            share_network_id='fake_network_id')
        share_instance_available = db_utils.create_share_instance(
            share_id=self.share['id'], status=constants.STATUS_AVAILABLE,
            share_network_id='fake_network_id')

        self.mock_object(share_api.API, 'create_instance',
                         mock.Mock(return_value=share_instance_creating))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=[share_instance_creating,
                                                share_instance_available]))
        self.mock_object(time, 'sleep')

        self.helper.create_instance_and_wait(
            self.context, self.share, share_instance_creating, host)

        db.share_instance_get.assert_any_call(
            self.context, share_instance_creating['id'], with_share_data=True)

    def test_create_instance_and_wait_status_error(self):

        host = {'host': 'fake-host'}

        share_instance_error = db_utils.create_share_instance(
            share_id=self.share['id'], status=constants.STATUS_ERROR,
            share_network_id='fake_network_id')

        self.mock_object(share_api.API, 'create_instance',
                         mock.Mock(return_value=share_instance_error))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=share_instance_error))
        self.mock_object(time, 'sleep')

        self.assertRaises(exception.ShareMigrationFailed,
                          self.helper.create_instance_and_wait,
                          self.context, self.share, share_instance_error, host)

        db.share_instance_get.assert_called_once_with(
            self.context, share_instance_error['id'], with_share_data=True)

    def test_create_instance_and_wait_timeout(self):

        host = {'host': 'fake-host'}

        share_instance_creating = db_utils.create_share_instance(
            share_id=self.share['id'], status=constants.STATUS_CREATING,
            share_network_id='fake_network_id')

        self.mock_object(share_api.API, 'create_instance',
                         mock.Mock(return_value=share_instance_creating))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=share_instance_creating))
        self.mock_object(time, 'sleep')

        now = time.time()
        timeout = now + 310

        self.mock_object(time, 'time',
                         mock.Mock(side_effect=[now, timeout]))

        self.assertRaises(exception.ShareMigrationFailed,
                          self.helper.create_instance_and_wait,
                          self.context, self.share, share_instance_creating,
                          host)

        db.share_instance_get.assert_called_once_with(
            self.context, share_instance_creating['id'], with_share_data=True)

    def test_wait_for_access_update(self):
        sid = 1
        fake_share_instances = [
            {'id': sid, 'access_rules_status': constants.STATUS_OUT_OF_SYNC},
            {'id': sid, 'access_rules_status': constants.STATUS_ACTIVE},
        ]

        self.mock_object(time, 'sleep')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=fake_share_instances))

        self.helper.wait_for_access_update(fake_share_instances[0])

        db.share_instance_get.assert_has_calls(
            [mock.call(mock.ANY, sid), mock.call(mock.ANY, sid)]
        )
        time.sleep.assert_called_once_with(1)

    @ddt.data(
        (
            {'id': '1', 'access_rules_status': constants.STATUS_ERROR},
            exception.ShareMigrationFailed
        ),
        (
            {'id': '1', 'access_rules_status': constants.STATUS_OUT_OF_SYNC},
            exception.ShareMigrationFailed
        ),
    )
    @ddt.unpack
    def test_wait_for_access_update_invalid(self, fake_instance, expected_exc):
        self.mock_object(time, 'sleep')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=fake_instance))

        now = time.time()
        timeout = now + 100

        self.mock_object(time, 'time',
                         mock.Mock(side_effect=[now, timeout]))

        self.assertRaises(expected_exc,
                          self.helper.wait_for_access_update, fake_instance)

    def test_allow_migration_access(self):
        access = {'access_to': 'fake_ip',
                  'access_type': 'fake_type',
                  'access_level': constants.ACCESS_LEVEL_RW}

        access_active = db_utils.create_access(share_id=self.share['id'])

        self.mock_object(self.helper, 'wait_for_access_update',
                         mock.Mock(return_value=access_active))

        self.mock_object(self.helper.db, 'share_access_create',
                         mock.Mock(return_value=access_active))
        self.mock_object(
            self.helper.db, 'share_access_get_all_by_type_and_access',
            mock.Mock(return_value=[]))
        self.mock_object(self.helper.api, 'allow_access_to_instance')

        result = self.helper.allow_migration_access(
            access, self.share.instance)

        self.assertEqual(access_active, result)

        self.helper.wait_for_access_update.assert_called_once_with(
            self.share.instance)

    def test_allow_migration_access_exists(self):
        access = {'access_to': 'fake_ip',
                  'access_type': 'fake_type',
                  'access_level': 'fake_level'}

        access_active = db_utils.create_access(share_id=self.share['id'],
                                               access_to='fake_ip')

        self.mock_object(self.helper.api, 'allow_access_to_instance')

        self.mock_object(
            self.helper.db, 'share_access_get_all_by_type_and_access',
            mock.Mock(return_value=[access_active]))

        result = self.helper.allow_migration_access(
            access, self.share.instance)

        self.assertEqual(access_active, result)

    def test_deny_migration_access(self):

        access = {'access_to': 'fake_ip',
                  'access_type': 'fake_type'}

        access_active = db_utils.create_access(share_id=self.share['id'],
                                               access_to='fake_ip')

        self.mock_object(self.helper.api, 'access_get',
                         mock.Mock(return_value=access_active))

        self.mock_object(self.helper.api, 'deny_access_to_instance')

        self.mock_object(self.helper, 'wait_for_access_update')

        self.helper.deny_migration_access(access_active, access,
                                          self.share.instance)

        self.helper.wait_for_access_update.assert_called_once_with(
            self.share.instance
        )

    def test_deny_migration_access_not_found(self):

        access = {'access_to': 'fake_ip',
                  'access_type': 'fake_type'}

        access_active = db_utils.create_access(share_id=self.share['id'],
                                               access_to='fake_ip')

        self.mock_object(self.helper.api, 'access_get',
                         mock.Mock(side_effect=exception.NotFound('fake')))

        self.helper.deny_migration_access(
            access_active, access, self.share.instance)

    def test_deny_migration_access_none(self):

        access = {'access_to': 'fake_ip',
                  'access_type': 'fake_type'}

        access_active = db_utils.create_access(share_id=self.share['id'],
                                               access_to='fake_ip')

        self.mock_object(self.helper.api, 'access_get_all',
                         mock.Mock(return_value=[access_active]))

        self.mock_object(self.helper.api, 'deny_access_to_instance')

        self.mock_object(self.helper, 'wait_for_access_update')

        self.helper.deny_migration_access(None, access, self.share.instance)

        self.helper.wait_for_access_update.assert_called_once_with(
            self.share.instance)

    def test_deny_migration_access_exception(self):

        access = {'access_to': 'fake_ip',
                  'access_type': 'fake_type'}

        access_active = db_utils.create_access(share_id=self.share['id'],
                                               access_to='fake_ip')

        self.mock_object(self.helper.api, 'access_get',
                         mock.Mock(return_value=access_active))

        self.mock_object(self.helper.api, 'deny_access_to_instance',
                         mock.Mock(side_effect=[exception.NotFound('fake')]))

        self.assertRaises(exception.NotFound,
                          self.helper.deny_migration_access, access_active,
                          access, self.share.instance)

    def test_cleanup_migration_access_exception(self):

        self.mock_object(self.helper, 'deny_migration_access',
                         mock.Mock(side_effect=Exception('fake')))

        self.helper.cleanup_migration_access(None, None, self.share.instance)

    def test_cleanup_temp_folder_exception(self):

        self.mock_object(utils, 'execute',
                         mock.Mock(side_effect=Exception('fake')))

        self.helper.cleanup_temp_folder(self.share.instance, None)

    def test_cleanup_unmount_temp_folder_exception(self):

        self.mock_object(utils, 'execute',
                         mock.Mock(side_effect=Exception('fake')))

        self.helper.cleanup_unmount_temp_folder(self.share.instance, None)

    def test_change_to_read_only(self):

        access_active = db_utils.create_access(share_id=self.share['id'],
                                               access_to='fake_ip')

        self.mock_object(db, 'share_access_get_all_for_share',
                         mock.Mock(return_value=[access_active]))

        self.mock_object(self.helper, 'deny_rules_and_wait')
        self.mock_object(self.helper, 'add_rules_and_wait')

        result = self.helper.change_to_read_only(True, self.share.instance)

        self.assertEqual([access_active], result)

        db.share_access_get_all_for_share.assert_called_once_with(
            self.context, self.share['id'])

        self.helper.deny_rules_and_wait.assert_called_once_with(
            self.context, self.share.instance, [access_active])
        self.helper.add_rules_and_wait.assert_called_once_with(
            self.context, self.share.instance, [access_active], 'ro')

    @ddt.data(None, 'new_instance')
    def test_revert_access_rules(self, new_instance):

        access_active = db_utils.create_access(share_id=self.share['id'],
                                               access_to='fake_ip')

        self.mock_object(db, 'share_access_get_all_for_share',
                         mock.Mock(return_value=[access_active]))

        self.mock_object(self.helper, 'deny_rules_and_wait')
        self.mock_object(self.helper, 'add_rules_and_wait')

        if new_instance:
            new_instance = self.share.instance
        self.helper.revert_access_rules(True, self.share.instance,
                                        new_instance, [access_active])

        db.share_access_get_all_for_share.assert_called_once_with(
            self.context, self.share['id'])

        self.helper.deny_rules_and_wait.assert_called_once_with(
            self.context, self.share.instance, [access_active])
        if new_instance:
            self.helper.add_rules_and_wait.assert_called_once_with(
                self.context, self.share.instance, [access_active])
