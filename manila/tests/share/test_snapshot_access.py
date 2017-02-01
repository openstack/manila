# Copyright (c) 2016 Hitachi Data Systems, Inc.
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

import copy
import ddt
import mock

from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.share import snapshot_access
from manila import test
from manila.tests import db_utils
from manila import utils


@ddt.ddt
class SnapshotAccessTestCase(test.TestCase):
    def setUp(self):
        super(SnapshotAccessTestCase, self).setUp()
        self.driver = self.mock_class("manila.share.driver.ShareDriver",
                                      mock.Mock())
        self.snapshot_access = snapshot_access.ShareSnapshotInstanceAccess(
            db, self.driver)
        self.context = context.get_admin_context()
        share = db_utils.create_share()
        self.snapshot = db_utils.create_snapshot(share_id=share['id'])
        self.snapshot_instance = db_utils.create_snapshot_instance(
            snapshot_id=self.snapshot['id'],
            share_instance_id=self.snapshot['share']['instance']['id'])

    @ddt.data(constants.ACCESS_STATE_QUEUED_TO_APPLY,
              constants.ACCESS_STATE_QUEUED_TO_DENY)
    def test_update_access_rules(self, state):

        rules = []
        for i in range(2):
            rules.append({
                'id': 'id-%s' % i,
                'state': state,
                'access_id': 'rule_id%s' % i
            })
        all_rules = copy.deepcopy(rules)
        all_rules.append({
            'id': 'id-3',
            'state': constants.ACCESS_STATE_ERROR,
            'access_id': 'rule_id3'
        })

        snapshot_instance_get = self.mock_object(
            db, 'share_snapshot_instance_get',
            mock.Mock(return_value=self.snapshot_instance))

        snap_get_all_for_snap_instance = self.mock_object(
            db, 'share_snapshot_access_get_all_for_snapshot_instance',
            mock.Mock(return_value=all_rules))

        self.mock_object(db, 'share_snapshot_instance_access_update')
        self.mock_object(self.driver, 'snapshot_update_access')
        self.mock_object(self.snapshot_access, '_check_needs_refresh',
                         mock.Mock(return_value=False))
        self.mock_object(db, 'share_snapshot_instance_access_delete')

        self.snapshot_access.update_access_rules(self.context,
                                                 self.snapshot_instance['id'])

        snapshot_instance_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            self.snapshot_instance['id'], with_share_data=True)
        snap_get_all_for_snap_instance.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            self.snapshot_instance['id'])
        if state == constants.ACCESS_STATE_QUEUED_TO_APPLY:
            self.driver.snapshot_update_access.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                self.snapshot_instance, rules, add_rules=rules,
                delete_rules=[], share_server=None)
        else:
            self.driver.snapshot_update_access.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                self.snapshot_instance, [], add_rules=[],
                delete_rules=rules, share_server=None)

    def test_update_access_rules_delete_all_rules(self):

        rules = []
        for i in range(2):
            rules.append({
                'id': 'id-%s' % i,
                'state': constants.ACCESS_STATE_QUEUED_TO_DENY,
                'access_id': 'rule_id%s' % i
            })

        snapshot_instance_get = self.mock_object(
            db, 'share_snapshot_instance_get',
            mock.Mock(return_value=self.snapshot_instance))

        snap_get_all_for_snap_instance = self.mock_object(
            db, 'share_snapshot_access_get_all_for_snapshot_instance',
            mock.Mock(side_effect=[rules, []]))

        self.mock_object(db, 'share_snapshot_instance_access_update')
        self.mock_object(self.driver, 'snapshot_update_access')
        self.mock_object(db, 'share_snapshot_instance_access_delete')

        self.snapshot_access.update_access_rules(self.context,
                                                 self.snapshot_instance['id'],
                                                 delete_all_rules=True)

        snapshot_instance_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            self.snapshot_instance['id'], with_share_data=True)
        snap_get_all_for_snap_instance.assert_called_with(
            utils.IsAMatcher(context.RequestContext),
            self.snapshot_instance['id'])
        self.driver.snapshot_update_access.assert_called_with(
            utils.IsAMatcher(context.RequestContext), self.snapshot_instance,
            [], add_rules=[], delete_rules=rules, share_server=None)

    def test_update_access_rules_exception(self):

        rules = []
        for i in range(2):
            rules.append({
                'id': 'id-%s' % i,
                'state': constants.ACCESS_STATE_APPLYING,
                'access_id': 'rule_id%s' % i
            })

        snapshot_instance_get = self.mock_object(
            db, 'share_snapshot_instance_get',
            mock.Mock(return_value=self.snapshot_instance))

        snap_get_all_for_snap_instance = self.mock_object(
            db, 'share_snapshot_access_get_all_for_snapshot_instance',
            mock.Mock(return_value=rules))

        self.mock_object(db, 'share_snapshot_instance_access_update')
        self.mock_object(self.driver, 'snapshot_update_access',
                         mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(exception.NotFound,
                          self.snapshot_access.update_access_rules,
                          self.context, self.snapshot_instance['id'])

        snapshot_instance_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            self.snapshot_instance['id'], with_share_data=True)
        snap_get_all_for_snap_instance.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            self.snapshot_instance['id'])

        self.driver.snapshot_update_access.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), self.snapshot_instance,
            rules, add_rules=rules, delete_rules=[], share_server=None)
