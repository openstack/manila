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
from manila.share import access as access_helper
from manila.share import api as share_api
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
        self.share_instance = db_utils.create_share_instance(
            share_id=self.share['id'],
            share_network_id='fake_network_id')
        self.access_helper = access_helper.ShareInstanceAccess(db, None)
        self.context = context.get_admin_context()
        self.helper = migration.ShareMigrationHelper(
            self.context, db, self.share, self.access_helper)

    def test_delete_instance_and_wait(self):

        # mocks
        self.mock_object(share_api.API, 'delete_instance')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=[self.share_instance,
                                                exception.NotFound()]))
        self.mock_object(time, 'sleep')

        # run
        self.helper.delete_instance_and_wait(self.share_instance)

        # asserts
        share_api.API.delete_instance.assert_called_once_with(
            self.context, self.share_instance, True)

        db.share_instance_get.assert_has_calls([
            mock.call(self.context, self.share_instance['id']),
            mock.call(self.context, self.share_instance['id'])])

        time.sleep.assert_called_once_with(1.414)

    def test_delete_instance_and_wait_timeout(self):

        # mocks
        self.mock_object(share_api.API, 'delete_instance')

        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=[self.share_instance, None]))
        self.mock_object(time, 'sleep')

        now = time.time()
        timeout = now + 310

        self.mock_object(time, 'time',
                         mock.Mock(side_effect=[now, timeout]))

        # run
        self.assertRaises(exception.ShareMigrationFailed,
                          self.helper.delete_instance_and_wait,
                          self.share_instance)

        # asserts
        share_api.API.delete_instance.assert_called_once_with(
            self.context, self.share_instance, True)

        db.share_instance_get.assert_called_once_with(
            self.context, self.share_instance['id'])

        time.time.assert_has_calls([mock.call(), mock.call()])

    def test_delete_instance_and_wait_not_found(self):

        # mocks
        self.mock_object(share_api.API, 'delete_instance')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=exception.NotFound))

        # run
        self.helper.delete_instance_and_wait(self.share_instance)

        # asserts
        share_api.API.delete_instance.assert_called_once_with(
            self.context, self.share_instance, True)

        db.share_instance_get.assert_called_once_with(
            self.context, self.share_instance['id'])

    def test_create_instance_and_wait(self):

        host = 'fake_host'

        share_instance_creating = db_utils.create_share_instance(
            share_id=self.share['id'], status=constants.STATUS_CREATING,
            share_network_id='fake_network_id')
        share_instance_available = db_utils.create_share_instance(
            share_id=self.share['id'], status=constants.STATUS_AVAILABLE,
            share_network_id='fake_network_id')

        # mocks
        self.mock_object(share_api.API, 'create_instance',
                         mock.Mock(return_value=share_instance_creating))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=[share_instance_creating,
                                                share_instance_available]))
        self.mock_object(time, 'sleep')

        # run
        self.helper.create_instance_and_wait(
            self.share, host, 'fake_net_id', 'fake_az_id', 'fake_type_id')

        # asserts
        share_api.API.create_instance.assert_called_once_with(
            self.context, self.share, 'fake_net_id', 'fake_host', 'fake_az_id',
            share_type_id='fake_type_id')

        db.share_instance_get.assert_has_calls([
            mock.call(self.context, share_instance_creating['id'],
                      with_share_data=True),
            mock.call(self.context, share_instance_creating['id'],
                      with_share_data=True)])

        time.sleep.assert_called_once_with(1.414)

    def test_create_instance_and_wait_status_error(self):

        host = 'fake_host'

        share_instance_error = db_utils.create_share_instance(
            share_id=self.share['id'], status=constants.STATUS_ERROR,
            share_network_id='fake_network_id')

        # mocks
        self.mock_object(share_api.API, 'create_instance',
                         mock.Mock(return_value=share_instance_error))
        self.mock_object(self.helper, 'cleanup_new_instance')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=share_instance_error))

        # run
        self.assertRaises(
            exception.ShareMigrationFailed,
            self.helper.create_instance_and_wait, self.share,
            host, 'fake_net_id', 'fake_az_id', 'fake_type_id')

        # asserts
        share_api.API.create_instance.assert_called_once_with(
            self.context, self.share, 'fake_net_id', 'fake_host', 'fake_az_id',
            share_type_id='fake_type_id')

        db.share_instance_get.assert_called_once_with(
            self.context, share_instance_error['id'], with_share_data=True)

        self.helper.cleanup_new_instance.assert_called_once_with(
            share_instance_error)

    def test_create_instance_and_wait_timeout(self):

        host = 'fake_host'

        share_instance_creating = db_utils.create_share_instance(
            share_id=self.share['id'], status=constants.STATUS_CREATING,
            share_network_id='fake_network_id')

        # mocks
        self.mock_object(share_api.API, 'create_instance',
                         mock.Mock(return_value=share_instance_creating))

        self.mock_object(self.helper, 'cleanup_new_instance')

        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=share_instance_creating))
        self.mock_object(time, 'sleep')

        now = time.time()
        timeout = now + 310

        self.mock_object(time, 'time', mock.Mock(side_effect=[now, timeout]))

        # run
        self.assertRaises(
            exception.ShareMigrationFailed,
            self.helper.create_instance_and_wait,  self.share,
            host, 'fake_net_id', 'fake_az_id', 'fake_type_id')

        # asserts
        share_api.API.create_instance.assert_called_once_with(
            self.context, self.share, 'fake_net_id', 'fake_host', 'fake_az_id',
            share_type_id='fake_type_id')

        db.share_instance_get.assert_called_once_with(
            self.context, share_instance_creating['id'], with_share_data=True)

        time.time.assert_has_calls([mock.call(), mock.call()])

        self.helper.cleanup_new_instance.assert_called_once_with(
            share_instance_creating)

    @ddt.data(constants.STATUS_ACTIVE, constants.STATUS_ERROR,
              constants.STATUS_CREATING)
    def test_wait_for_share_server(self, status):

        server = db_utils.create_share_server(status=status)

        # mocks
        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value=server))

        # run
        if status == constants.STATUS_ACTIVE:
            result = self.helper.wait_for_share_server('fake_server_id')
            self.assertEqual(server, result)
        elif status == constants.STATUS_ERROR:
            self.assertRaises(
                exception.ShareServerNotCreated,
                self.helper.wait_for_share_server, 'fake_server_id')
        else:
            self.mock_object(time, 'sleep')
            self.assertRaises(
                exception.ShareServerNotReady,
                self.helper.wait_for_share_server, 'fake_server_id')

        # asserts
        db.share_server_get.assert_called_with(self.context, 'fake_server_id')

    def test_revert_access_rules(self):

        share_instance = db_utils.create_share_instance(
            share_id=self.share['id'], status=constants.STATUS_AVAILABLE)

        access = db_utils.create_access(share_id=self.share['id'],
                                        access_to='fake_ip',
                                        access_level='rw')

        server = db_utils.create_share_server(share_id=self.share['id'])

        # mocks
        self.mock_object(self.access_helper, 'update_access_rules')
        get_and_update_call = self.mock_object(
            self.access_helper, 'get_and_update_share_instance_access_rules',
            mock.Mock(return_value=[access]))

        # run
        self.helper.revert_access_rules(share_instance, server)

        # asserts
        get_and_update_call.assert_called_once_with(
            self.context, share_instance_id=share_instance['id'],
            updates={'state': constants.ACCESS_STATE_QUEUED_TO_APPLY})
        self.access_helper.update_access_rules.assert_called_once_with(
            self.context, share_instance['id'], share_server=server)

    @ddt.data(True, False)
    def test_apply_new_access_rules_there_are_rules(self, prior_rules):

        new_share_instance = db_utils.create_share_instance(
            share_id=self.share['id'], status=constants.STATUS_AVAILABLE,
            access_rules_status='active')
        rules = None
        if prior_rules:
            rules = [
                db_utils.create_access(
                    share_id=self.share['id'], access_to='fake_ip')
            ]

        # mocks
        self.mock_object(db, 'share_instance_access_copy', mock.Mock(
            return_value=rules))
        self.mock_object(share_api.API, 'allow_access_to_instance')
        self.mock_object(utils, 'wait_for_access_update')

        # run
        self.helper.apply_new_access_rules(new_share_instance)

        # asserts
        db.share_instance_access_copy.assert_called_once_with(
            self.context, self.share['id'], new_share_instance['id'])
        if prior_rules:
            share_api.API.allow_access_to_instance.assert_called_with(
                self.context, new_share_instance)
            utils.wait_for_access_update.assert_called_with(
                self.context, db, new_share_instance,
                self.helper.migration_wait_access_rules_timeout)
        else:
            self.assertFalse(share_api.API.allow_access_to_instance.called)
            self.assertFalse(utils.wait_for_access_update.called)

    @ddt.data(None, Exception('fake'))
    def test_cleanup_new_instance(self, exc):

        # mocks
        self.mock_object(self.helper, 'delete_instance_and_wait',
                         mock.Mock(side_effect=exc))

        self.mock_object(migration.LOG, 'warning')

        # run
        self.helper.cleanup_new_instance(self.share_instance)

        # asserts
        self.helper.delete_instance_and_wait.assert_called_once_with(
            self.share_instance)

        if exc:
            self.assertEqual(1, migration.LOG.warning.call_count)

    @ddt.data(None, Exception('fake'))
    def test_cleanup_access_rules(self, exc):

        # mocks
        server = db_utils.create_share_server()
        self.mock_object(self.helper, 'revert_access_rules',
                         mock.Mock(side_effect=exc))

        self.mock_object(migration.LOG, 'warning')

        # run
        self.helper.cleanup_access_rules(self.share_instance, server)

        # asserts
        self.helper.revert_access_rules.assert_called_once_with(
            self.share_instance, server)

        if exc:
            self.assertEqual(1, migration.LOG.warning.call_count)
