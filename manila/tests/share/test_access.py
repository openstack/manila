# Copyright 2016 Hitachi Data Systems inc.
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

import mock

from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.share import access
from manila import test
from manila.tests import db_utils


class ShareInstanceAccessTestCase(test.TestCase):
    def setUp(self):
        super(ShareInstanceAccessTestCase, self).setUp()
        self.driver = self.mock_class("manila.share.driver.ShareDriver",
                                      mock.Mock())
        self.share_access_helper = access.ShareInstanceAccess(db, self.driver)
        self.context = context.get_admin_context()
        self.share = db_utils.create_share()
        self.share_instance = db_utils.create_share_instance(
            share_id=self.share['id'],
            access_rules_status=constants.STATUS_ERROR)

    def test_update_access_rules(self):
        original_rules = []

        self.mock_object(db, "share_instance_get", mock.Mock(
            return_value=self.share_instance))
        self.mock_object(db, "share_access_get_all_for_share",
                         mock.Mock(return_value=original_rules))
        self.mock_object(db, "share_instance_update_access_status",
                         mock.Mock())
        self.mock_object(self.driver, "update_access", mock.Mock())

        self.share_access_helper.update_access_rules(self.context,
                                                     self.share_instance['id'])

        self.driver.update_access.assert_called_with(
            self.context, self.share_instance, original_rules, add_rules=[],
            delete_rules=[], share_server=None)
        db.share_instance_update_access_status.assert_called_with(
            self.context, self.share_instance['id'], constants.STATUS_ACTIVE)

    def test_update_access_rules_fallback(self):
        add_rules = [db_utils.create_access(share_id=self.share['id'])]
        delete_rules = [db_utils.create_access(share_id=self.share['id'])]
        original_rules = [db_utils.create_access(share_id=self.share['id'])]

        self.mock_object(db, "share_instance_get", mock.Mock(
            return_value=self.share_instance))
        self.mock_object(db, "share_access_get_all_for_share",
                         mock.Mock(return_value=original_rules))
        self.mock_object(db, "share_access_get_all_for_instance",
                         mock.Mock(return_value=original_rules))
        self.mock_object(db, "share_instance_update_access_status",
                         mock.Mock())
        self.mock_object(self.driver, "update_access",
                         mock.Mock(side_effect=NotImplementedError))
        self.mock_object(self.driver, "allow_access",
                         mock.Mock())
        self.mock_object(self.driver, "deny_access",
                         mock.Mock())

        self.share_access_helper.update_access_rules(self.context,
                                                     self.share_instance['id'],
                                                     add_rules, delete_rules)

        self.driver.update_access.assert_called_with(
            self.context, self.share_instance, original_rules,
            add_rules=add_rules, delete_rules=[], share_server=None)
        self.driver.allow_access.assert_called_with(self.context,
                                                    self.share_instance,
                                                    add_rules[0],
                                                    share_server=None)
        self.driver.deny_access.assert_called_with(self.context,
                                                   self.share_instance,
                                                   delete_rules[0],
                                                   share_server=None)
        db.share_instance_update_access_status.assert_called_with(
            self.context, self.share_instance['id'], constants.STATUS_ACTIVE)

    def test_update_access_rules_exception(self):
        original_rules = []
        add_rules = [db_utils.create_access(share_id=self.share['id'])]
        delete_rules = 'all'

        self.mock_object(db, "share_instance_get", mock.Mock(
            return_value=self.share_instance))
        self.mock_object(db, "share_access_get_all_for_instance",
                         mock.Mock(return_value=original_rules))
        self.mock_object(db, "share_instance_update_access_status",
                         mock.Mock())
        self.mock_object(self.driver, "update_access",
                         mock.Mock(side_effect=exception.ManilaException))

        self.assertRaises(exception.ManilaException,
                          self.share_access_helper.update_access_rules,
                          self.context, self.share_instance['id'], add_rules,
                          delete_rules)

        self.driver.update_access.assert_called_with(
            self.context, self.share_instance, [], add_rules=add_rules,
            delete_rules=original_rules, share_server=None)

        db.share_instance_update_access_status.assert_called_with(
            self.context, self.share_instance['id'], constants.STATUS_ERROR)

    def test_update_access_rules_recursive_call(self):
        share_instance = db_utils.create_share_instance(
            access_rules_status=constants.STATUS_ACTIVE,
            share_id=self.share['id'])
        add_rules = [db_utils.create_access(
            share_id=self.share['id'])]
        original_rules = []

        self.mock_object(db, "share_instance_get", mock.Mock(
            return_value=share_instance))
        self.mock_object(db, "share_access_get_all_for_instance",
                         mock.Mock(return_value=original_rules))
        mock_update_access = self.mock_object(self.driver, "update_access")
        self.mock_object(self.share_access_helper, '_check_needs_refresh',
                         mock.Mock(side_effect=[True, False]))

        self.share_access_helper.update_access_rules(self.context,
                                                     share_instance['id'],
                                                     add_rules=add_rules)

        mock_update_access.assert_has_calls([
            mock.call(self.context, share_instance, original_rules,
                      add_rules=add_rules, delete_rules=[], share_server=None),
            mock.call(self.context, share_instance, original_rules,
                      add_rules=[], delete_rules=[], share_server=None)
        ])
