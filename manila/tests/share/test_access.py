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

import ddt
import mock
import random

import itertools
import six

from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.share import access
from manila import test
from manila.tests import db_utils
from manila import utils


class LockedOperationsTestCase(test.TestCase):

    class FakeAccessHelper(object):

        @access.locked_access_rules_operation
        def some_access_rules_operation(self, context, share_instance_id=None):
            pass

    def setUp(self):
        super(self.__class__, self).setUp()
        self.access_helper = self.FakeAccessHelper()
        self.context = context.RequestContext('fake_user', 'fake_project')
        self.lock_call = self.mock_object(
            utils, 'synchronized', mock.Mock(return_value=lambda f: f))

    def test_locked_access_rules_operation(self, **replica):

        self.access_helper.some_access_rules_operation(
            self.context, share_instance_id='FAKE_INSTANCE_ID')

        self.lock_call.assert_called_once_with(
            "locked_access_rules_operation_by_share_instance_FAKE_INSTANCE_ID",
            external=True)


@ddt.ddt
class ShareInstanceAccessDatabaseMixinTestCase(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.driver = mock.Mock()
        self.access_helper = access.ShareInstanceAccess(db, self.driver)
        self.context = context.RequestContext('fake_user', 'fake_project')
        self.mock_object(
            utils, 'synchronized', mock.Mock(return_value=lambda f: f))

    def test_get_and_update_access_rules_status_force_status(self):
        share = db_utils.create_share(
            access_rule_status=constants.STATUS_ACTIVE,
            status=constants.STATUS_AVAILABLE)
        share = db.share_get(self.context, share['id'])
        self.assertEqual(constants.STATUS_ACTIVE, share['access_rules_status'])

        self.access_helper.get_and_update_share_instance_access_rules_status(
            self.context, status=constants.SHARE_INSTANCE_RULES_SYNCING,
            share_instance_id=share['instance']['id'])

        share = db.share_get(self.context, share['id'])
        self.assertEqual(constants.SHARE_INSTANCE_RULES_SYNCING,
                         share['access_rules_status'])

    @ddt.data((constants.SHARE_INSTANCE_RULES_SYNCING, True),
              (constants.STATUS_ERROR, False))
    @ddt.unpack
    def test_get_and_update_access_rules_status_conditionally_change(
            self, initial_status, change_allowed):
        share = db_utils.create_share(access_rules_status=initial_status,
                                      status=constants.STATUS_AVAILABLE)
        share = db.share_get(self.context, share['id'])
        self.assertEqual(initial_status, share['access_rules_status'])

        conditionally_change = {
            constants.SHARE_INSTANCE_RULES_SYNCING: constants.STATUS_ACTIVE,
        }

        updated_instance = (
            self.access_helper.
            get_and_update_share_instance_access_rules_status(
                self.context, conditionally_change=conditionally_change,
                share_instance_id=share['instance']['id'])
        )

        share = db.share_get(self.context, share['id'])
        if change_allowed:
            self.assertEqual(constants.STATUS_ACTIVE,
                             share['access_rules_status'])
            self.assertIsNotNone(updated_instance)
        else:
            self.assertEqual(initial_status, share['access_rules_status'])
            self.assertIsNone(updated_instance)

    def test_get_and_update_all_access_rules_just_get(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        rule_1 = db_utils.create_access(share_id=share['id'])
        rule_2 = db_utils.create_access(share_id=share['id'])
        self.mock_object(db, 'share_instance_access_update')

        rules = self.access_helper.get_and_update_share_instance_access_rules(
            self.context, share_instance_id=share['instance']['id'])

        self.assertEqual(2, len(rules))
        rule_ids = [r['access_id'] for r in rules]
        self.assertIn(rule_1['id'], rule_ids)
        self.assertIn(rule_2['id'], rule_ids)
        self.assertFalse(db.share_instance_access_update.called)

    @ddt.data(
        ([constants.ACCESS_STATE_QUEUED_TO_APPLY], 2),
        ([constants.ACCESS_STATE_QUEUED_TO_APPLY,
          constants.STATUS_ACTIVE], 1),
        ([constants.ACCESS_STATE_APPLYING], 2),
        ([constants.ACCESS_STATE_APPLYING, constants.ACCESS_STATE_ERROR], 1),
        ([constants.ACCESS_STATE_ACTIVE, constants.ACCESS_STATE_DENYING], 0))
    @ddt.unpack
    def test_get_and_update_all_access_rules_updates_conditionally_changed(
            self, statuses, changes_allowed):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        db_utils.create_access(share_id=share['id'], state=statuses[0])
        db_utils.create_access(share_id=share['id'], state=statuses[-1])
        self.mock_object(db, 'share_instance_access_update', mock.Mock(
            side_effect=db.share_instance_access_update))
        updates = {
            'access_key': 'renfrow2stars'
        }
        expected_updates = {
            'access_key': 'renfrow2stars',
            'state': constants.ACCESS_STATE_QUEUED_TO_DENY,
        }
        conditionally_change = {
            constants.ACCESS_STATE_APPLYING:
                constants.ACCESS_STATE_QUEUED_TO_DENY,
            constants.ACCESS_STATE_QUEUED_TO_APPLY:
                constants.ACCESS_STATE_QUEUED_TO_DENY,
        }

        rules = self.access_helper.get_and_update_share_instance_access_rules(
            self.context, share_instance_id=share['instance']['id'],
            updates=updates, conditionally_change=conditionally_change)

        state_changed_rules = [
            r for r in rules if
            r['state'] == constants.ACCESS_STATE_QUEUED_TO_DENY
        ]
        self.assertEqual(changes_allowed, len(state_changed_rules))
        self.assertEqual(2, db.share_instance_access_update.call_count)
        db.share_instance_access_update.assert_has_calls([
            mock.call(self.context, mock.ANY, share['instance']['id'],
                      expected_updates),
        ] * changes_allowed)

    def test_get_and_update_access_rule_just_get(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        expected_rule = db_utils.create_access(share_id=share['id'])
        self.mock_object(db, 'share_instance_access_update')

        actual_rule = (
            self.access_helper.get_and_update_share_instance_access_rule(
                self.context, expected_rule['id'],
                share_instance_id=share['instance']['id'])
        )

        self.assertEqual(expected_rule['id'], actual_rule['access_id'])
        self.assertFalse(db.share_instance_access_update.called)

    @ddt.data(constants.ACCESS_STATE_APPLYING,
              constants.ACCESS_STATE_DENYING,
              constants.ACCESS_STATE_ACTIVE,
              constants.ACCESS_STATE_QUEUED_TO_APPLY)
    def test_get_and_update_access_rule_updates_conditionally_changed(
            self, initial_state):
        mock_debug_log = self.mock_object(access.LOG, 'debug')
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        rule = db_utils.create_access(share_id=share['id'],
                                      state=initial_state)
        self.mock_object(db, 'share_instance_access_update', mock.Mock(
            side_effect=db.share_instance_access_update))
        updates = {
            'access_key': 'renfrow2stars'
        }
        conditionally_change = {
            constants.ACCESS_STATE_APPLYING:
                constants.ACCESS_STATE_QUEUED_TO_DENY,
            constants.ACCESS_STATE_DENYING:
                constants.ACCESS_STATE_QUEUED_TO_DENY,
        }

        actual_rule = (
            self.access_helper.get_and_update_share_instance_access_rule(
                self.context, rule['id'], updates=updates,
                share_instance_id=share['instance']['id'],
                conditionally_change=conditionally_change)
        )
        self.assertEqual(rule['id'], actual_rule['access_id'])
        if 'ing' in initial_state:
            self.assertEqual(constants.ACCESS_STATE_QUEUED_TO_DENY,
                             actual_rule['state'])
            self.assertFalse(mock_debug_log.called)
        else:
            self.assertEqual(initial_state, actual_rule['state'])
            mock_debug_log.assert_called_once()


@ddt.ddt
class ShareInstanceAccessTestCase(test.TestCase):
    def setUp(self):
        super(ShareInstanceAccessTestCase, self).setUp()
        self.driver = self.mock_class("manila.share.driver.ShareDriver",
                                      mock.Mock())
        self.access_helper = access.ShareInstanceAccess(db, self.driver)
        self.context = context.RequestContext('fake_user', 'fake_project')

    @ddt.data(constants.ACCESS_STATE_APPLYING, constants.ACCESS_STATE_DENYING)
    def test_update_access_rules_an_update_is_in_progress(self, initial_state):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        share_instance = share['instance']
        db_utils.create_access(share_id=share['id'], state=initial_state)
        mock_debug_log = self.mock_object(access.LOG, 'debug')
        self.mock_object(self.access_helper, '_update_access_rules')
        get_and_update_call = self.mock_object(
            self.access_helper, 'get_and_update_share_instance_access_rules',
            mock.Mock(side_effect=self.access_helper.
                      get_and_update_share_instance_access_rules))

        retval = self.access_helper.update_access_rules(
            self.context, share_instance['id'])

        expected_filters = {
            'state': (constants.ACCESS_STATE_APPLYING,
                      constants.ACCESS_STATE_DENYING),
        }
        self.assertIsNone(retval)
        mock_debug_log.assert_called_once()
        get_and_update_call.assert_called_once_with(
            self.context, filters=expected_filters,
            share_instance_id=share_instance['id'])
        self.assertFalse(self.access_helper._update_access_rules.called)

    def test_update_access_rules_nothing_to_update(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        share_instance = share['instance']
        db_utils.create_access(share_id=share['id'],
                               state=constants.STATUS_ACTIVE)
        mock_debug_log = self.mock_object(access.LOG, 'debug')
        self.mock_object(self.access_helper, '_update_access_rules')
        get_and_update_call = self.mock_object(
            self.access_helper, 'get_and_update_share_instance_access_rules',
            mock.Mock(side_effect=self.access_helper.
                      get_and_update_share_instance_access_rules))

        retval = self.access_helper.update_access_rules(
            self.context, share_instance['id'])

        expected_rule_filter_1 = {
            'state': (constants.ACCESS_STATE_APPLYING,
                      constants.ACCESS_STATE_DENYING),
        }
        expected_rule_filter_2 = {
            'state': (constants.ACCESS_STATE_QUEUED_TO_APPLY,
                      constants.ACCESS_STATE_QUEUED_TO_DENY),
        }
        expected_conditionally_change = {
            constants.ACCESS_STATE_QUEUED_TO_APPLY:
                constants.ACCESS_STATE_APPLYING,
            constants.ACCESS_STATE_QUEUED_TO_DENY:
                constants.ACCESS_STATE_DENYING,
        }
        self.assertIsNone(retval)
        mock_debug_log.assert_called_once()
        get_and_update_call.assert_has_calls(
            [
                mock.call(self.context, filters=expected_rule_filter_1,
                          share_instance_id=share_instance['id']),
                mock.call(self.context, filters=expected_rule_filter_2,
                          share_instance_id=share_instance['id'],
                          conditionally_change=expected_conditionally_change),
            ])
        self.assertFalse(self.access_helper._update_access_rules.called)

    @ddt.data(True, False)
    def test_update_access_rules_delete_all_rules(self, delete_all_rules):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        share_instance = share['instance']
        db_utils.create_access(
            share_id=share['id'], state=constants.STATUS_ACTIVE)
        db_utils.create_access(
            share_id=share['id'], state=constants.ACCESS_STATE_QUEUED_TO_APPLY)
        db_utils.create_access(
            share_id=share['id'], state=constants.ACCESS_STATE_QUEUED_TO_DENY)
        mock_debug_log = self.mock_object(access.LOG, 'debug')
        self.mock_object(self.access_helper, '_update_access_rules')
        get_and_update_call = self.mock_object(
            self.access_helper, 'get_and_update_share_instance_access_rules',
            mock.Mock(side_effect=self.access_helper.
                      get_and_update_share_instance_access_rules))

        retval = self.access_helper.update_access_rules(
            self.context, share_instance['id'],
            delete_all_rules=delete_all_rules)

        expected_rule_filter_1 = {
            'state': (constants.ACCESS_STATE_APPLYING,
                      constants.ACCESS_STATE_DENYING),
        }
        expected_rule_filter_2 = {
            'state': (constants.ACCESS_STATE_QUEUED_TO_APPLY,
                      constants.ACCESS_STATE_QUEUED_TO_DENY),
        }
        expected_conditionally_change = {
            constants.ACCESS_STATE_QUEUED_TO_APPLY:
                constants.ACCESS_STATE_APPLYING,
            constants.ACCESS_STATE_QUEUED_TO_DENY:
                constants.ACCESS_STATE_DENYING,
        }
        expected_get_and_update_calls = []
        if delete_all_rules:
            deny_all_updates = {
                'state': constants.ACCESS_STATE_QUEUED_TO_DENY,
            }
            expected_get_and_update_calls = [
                mock.call(self.context, updates=deny_all_updates,
                          share_instance_id=share_instance['id']),
            ]
        expected_get_and_update_calls.extend([
            mock.call(self.context, filters=expected_rule_filter_1,
                      share_instance_id=share_instance['id']),
            mock.call(self.context, filters=expected_rule_filter_2,
                      share_instance_id=share_instance['id'],
                      conditionally_change=expected_conditionally_change),
        ])

        self.assertIsNone(retval)
        mock_debug_log.assert_called_once()
        get_and_update_call.assert_has_calls(expected_get_and_update_calls)
        self.access_helper._update_access_rules.assert_called_once_with(
            self.context, share_instance['id'], share_server=None)

    @ddt.data(*itertools.product(
        (True, False), (constants.ACCESS_STATE_ERROR,
                        constants.ACCESS_STATE_ACTIVE)))
    @ddt.unpack
    def test__update_access_rules_with_driver_updates(
            self, driver_returns_updates, access_state):
        expected_access_rules_status = (
            constants.STATUS_ACTIVE
            if access_state == constants.ACCESS_STATE_ACTIVE
            else constants.SHARE_INSTANCE_RULES_ERROR
        )
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            access_rules_status=expected_access_rules_status)
        share_instance_id = share['instance']['id']
        rule_1 = db_utils.create_access(
            share_id=share['id'], state=access_state)
        rule_1 = db.share_instance_access_get(
            self.context, rule_1['id'], share_instance_id)
        rule_2 = db_utils.create_access(
            share_id=share['id'], state=constants.ACCESS_STATE_APPLYING)
        rule_2 = db.share_instance_access_get(
            self.context, rule_2['id'], share_instance_id)
        rule_3 = db_utils.create_access(
            share_id=share['id'], state=constants.ACCESS_STATE_DENYING)
        rule_3 = db.share_instance_access_get(
            self.context, rule_3['id'], share_instance_id)
        if driver_returns_updates:
            driver_rule_updates = {
                rule_3['access_id']: {'access_key': 'alic3h4sAcc355'},
                rule_2['access_id']: {'state': access_state}
            }
        else:
            driver_rule_updates = None

        shr_instance_access_rules_status_update_call = self.mock_object(
            self.access_helper,
            'get_and_update_share_instance_access_rules_status',
            mock.Mock(side_effect=self.access_helper.
                      get_and_update_share_instance_access_rules_status))
        all_access_rules_update_call = self.mock_object(
            self.access_helper, 'get_and_update_share_instance_access_rules',
            mock.Mock(side_effect=self.access_helper.
                      get_and_update_share_instance_access_rules))
        one_access_rule_update_call = self.mock_object(
            self.access_helper, 'get_and_update_share_instance_access_rule',
            mock.Mock(side_effect=self.access_helper.
                      get_and_update_share_instance_access_rule))

        driver_call = self.mock_object(
            self.access_helper.driver, 'update_access',
            mock.Mock(return_value=driver_rule_updates))
        self.mock_object(self.access_helper, '_check_needs_refresh',
                         mock.Mock(return_value=False))

        retval = self.access_helper._update_access_rules(
            self.context, share_instance_id, share_server='fake_server')

        # Expected Values:
        if access_state != constants.ACCESS_STATE_ERROR:
            expected_rules_to_be_on_share = [r['id'] for r in (rule_1, rule_2)]
        else:
            expected_rules_to_be_on_share = [rule_2['id']]

        expected_filters_1 = {
            'state': (constants.ACCESS_STATE_APPLYING,
                      constants.ACCESS_STATE_ACTIVE,
                      constants.ACCESS_STATE_DENYING),
        }
        expected_filters_2 = {'state': constants.STATUS_ERROR}
        expected_get_and_update_calls = [
            mock.call(self.context, filters=expected_filters_1,
                      share_instance_id=share_instance_id),
            mock.call(self.context, filters=expected_filters_2,
                      share_instance_id=share_instance_id),
        ]
        expected_access_rules_status_change_cond1 = {
            constants.STATUS_ACTIVE: constants.SHARE_INSTANCE_RULES_SYNCING,
        }
        if access_state == constants.SHARE_INSTANCE_RULES_ERROR:
            expected_access_rules_status_change_cond2 = {
                constants.SHARE_INSTANCE_RULES_SYNCING:
                    constants.SHARE_INSTANCE_RULES_ERROR,
            }
        else:
            expected_access_rules_status_change_cond2 = {
                constants.SHARE_INSTANCE_RULES_SYNCING:
                    constants.STATUS_ACTIVE,
                constants.SHARE_INSTANCE_RULES_ERROR:
                    constants.STATUS_ACTIVE,
            }
        call_args = driver_call.call_args_list[0][0]
        call_kwargs = driver_call.call_args_list[0][1]
        access_rules_to_be_on_share = [r['id'] for r in call_args[2]]

        # Asserts
        self.assertIsNone(retval)
        self.assertEqual(share_instance_id, call_args[1]['id'])
        self.assertEqual(sorted(expected_rules_to_be_on_share),
                         sorted(access_rules_to_be_on_share))
        self.assertEqual(1, len(call_kwargs['add_rules']))
        self.assertEqual(rule_2['id'], call_kwargs['add_rules'][0]['id'])
        self.assertEqual(1, len(call_kwargs['delete_rules']))
        self.assertEqual(rule_3['id'], call_kwargs['delete_rules'][0]['id'])
        self.assertEqual('fake_server', call_kwargs['share_server'])
        shr_instance_access_rules_status_update_call.assert_has_calls([
            mock.call(
                self.context, share_instance_id=share_instance_id,
                conditionally_change=expected_access_rules_status_change_cond1
            ),
            mock.call(
                self.context, share_instance_id=share_instance_id,
                conditionally_change=expected_access_rules_status_change_cond2
            ),
        ])

        if driver_returns_updates:
            expected_conditional_state_updates = {
                constants.ACCESS_STATE_APPLYING: access_state,
                constants.ACCESS_STATE_DENYING: access_state,
                constants.ACCESS_STATE_ACTIVE: access_state,
            }
            expected_access_rule_update_calls = [
                mock.call(
                    self.context, rule_3['access_id'],
                    updates={'access_key': 'alic3h4sAcc355'},
                    share_instance_id=share_instance_id,
                    conditionally_change={}),
                mock.call(
                    self.context, rule_2['access_id'],
                    updates=mock.ANY, share_instance_id=share_instance_id,
                    conditionally_change=expected_conditional_state_updates)
            ]
            one_access_rule_update_call.assert_has_calls(
                expected_access_rule_update_calls, any_order=True)
        else:
            self.assertFalse(one_access_rule_update_call.called)
            expected_conditionally_change = {
                constants.ACCESS_STATE_APPLYING: constants.ACCESS_STATE_ACTIVE,
            }
            expected_get_and_update_calls.append(
                mock.call(self.context, share_instance_id=share_instance_id,
                          conditionally_change=expected_conditionally_change))

        all_access_rules_update_call.assert_has_calls(
            expected_get_and_update_calls, any_order=True)

        share_instance = db.share_instance_get(
            self.context, share_instance_id)
        self.assertEqual(expected_access_rules_status,
                         share_instance['access_rules_status'])

    @ddt.data(True, False)
    def test__update_access_rules_recursive_driver_exception(self, drv_exc):
        other = access.ShareInstanceAccess(db, None)
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            access_rules_status=constants.SHARE_INSTANCE_RULES_SYNCING)
        share_instance_id = share['instance']['id']
        rule_4 = []
        get_and_update_count = [1]
        drv_count = [1]

        def _get_and_update_side_effect(*args, **kwargs):
            # The third call to this method needs to create a new access rule
            mtd = other.get_and_update_share_instance_access_rules
            if get_and_update_count[0] == 3:
                rule_4.append(
                    db_utils.create_access(
                        state=constants.ACCESS_STATE_QUEUED_TO_APPLY,
                        share_id=share['id']))
            get_and_update_count[0] += 1
            return mtd(*args, **kwargs)

        def _driver_side_effect(*args, **kwargs):
            if drv_exc and drv_count[0] == 2:
                raise exception.ManilaException('fake')
            drv_count[0] += 1

        rule_kwargs = {'share_id': share['id'], 'access_level': 'rw'}
        rule_1 = db_utils.create_access(state=constants.ACCESS_STATE_APPLYING,
                                        **rule_kwargs)
        rule_2 = db_utils.create_access(state=constants.ACCESS_STATE_ACTIVE,
                                        **rule_kwargs)
        rule_3 = db_utils.create_access(state=constants.ACCESS_STATE_DENYING,
                                        **rule_kwargs)

        self.mock_object(self.access_helper,
                         'get_and_update_share_instance_access_rules',
                         mock.Mock(side_effect=_get_and_update_side_effect))
        self.mock_object(self.access_helper.driver, 'update_access',
                         mock.Mock(side_effect=_driver_side_effect))

        if drv_exc:
            self.assertRaises(exception.ManilaException,
                              self.access_helper._update_access_rules,
                              self.context, share_instance_id)
        else:
            retval = self.access_helper._update_access_rules(self.context,
                                                             share_instance_id)
            self.assertIsNone(retval)

        expected_filters_1 = {
            'state': (constants.ACCESS_STATE_APPLYING,
                      constants.ACCESS_STATE_ACTIVE,
                      constants.ACCESS_STATE_DENYING),
        }
        conditionally_change_2 = {
            constants.ACCESS_STATE_APPLYING: constants.ACCESS_STATE_ACTIVE,
        }
        expected_filters_3 = {
            'state': (constants.ACCESS_STATE_QUEUED_TO_APPLY,
                      constants.ACCESS_STATE_QUEUED_TO_DENY),
        }
        expected_conditionally_change_3 = {
            constants.ACCESS_STATE_QUEUED_TO_APPLY:
                constants.ACCESS_STATE_APPLYING,
            constants.ACCESS_STATE_QUEUED_TO_DENY:
                constants.ACCESS_STATE_DENYING,
        }
        expected_conditionally_change_4 = {
            constants.ACCESS_STATE_APPLYING: constants.ACCESS_STATE_ERROR,
            constants.ACCESS_STATE_DENYING: constants.ACCESS_STATE_ERROR,
        }
        expected_get_and_update_calls = [
            mock.call(self.context, filters=expected_filters_1,
                      share_instance_id=share_instance_id),
            mock.call(self.context, share_instance_id=share_instance_id,
                      conditionally_change=conditionally_change_2),
            mock.call(self.context, filters=expected_filters_3,
                      share_instance_id=share_instance_id,
                      conditionally_change=expected_conditionally_change_3),
            mock.call(self.context, filters=expected_filters_1,
                      share_instance_id=share_instance_id),
        ]

        if drv_exc:
            expected_get_and_update_calls.append(
                mock.call(
                    self.context, share_instance_id=share_instance_id,
                    conditionally_change=expected_conditionally_change_4))
        else:
            expected_get_and_update_calls.append(
                mock.call(self.context, share_instance_id=share_instance_id,
                          conditionally_change=conditionally_change_2))

        # Verify rule changes:
        # 'denying' rule must not exist
        self.assertRaises(exception.NotFound,
                          db.share_access_get,
                          self.context, rule_3['id'])
        # 'applying' rule must be set to 'active'
        rules_that_must_be_active = (rule_1, rule_2)
        if not drv_exc:
            rules_that_must_be_active += (rule_4[0], )
        for rule in rules_that_must_be_active:
            rule = db.share_access_get(self.context, rule['id'])
        self.assertEqual(constants.ACCESS_STATE_ACTIVE,
                         rule['state'])
        # access_rules_status must be as expected
        expected_access_rules_status = (
            constants.SHARE_INSTANCE_RULES_ERROR if drv_exc
            else constants.STATUS_ACTIVE)
        share_instance = db.share_instance_get(self.context, share_instance_id)
        self.assertEqual(
            expected_access_rules_status,
            share_instance['access_rules_status'])

    def test__update_access_rules_for_migration(self):
        share = db_utils.create_share()
        instance = db_utils.create_share_instance(
            status=constants.STATUS_MIGRATING,
            access_rules_status=constants.STATUS_ACTIVE,
            cast_rules_to_readonly=True,
            share_id=share['id'])
        rule_kwargs = {'share_id': share['id'], 'access_level': 'rw'}
        rule_1 = db_utils.create_access(
            state=constants.ACCESS_STATE_ACTIVE, **rule_kwargs)
        rule_1 = db.share_instance_access_get(
            self.context, rule_1['id'], instance['id'])
        rule_2 = db_utils.create_access(
            state=constants.ACCESS_STATE_APPLYING, share_id=share['id'],
            access_level='ro')
        rule_2 = db.share_instance_access_get(
            self.context, rule_2['id'], instance['id'])

        driver_call = self.mock_object(
            self.access_helper.driver, 'update_access',
            mock.Mock(return_value=None))
        self.mock_object(self.access_helper, '_check_needs_refresh',
                         mock.Mock(return_value=False))

        retval = self.access_helper._update_access_rules(
            self.context, instance['id'], share_server='fake_server')

        call_args = driver_call.call_args_list[0][0]
        call_kwargs = driver_call.call_args_list[0][1]
        access_rules_to_be_on_share = [r['id'] for r in call_args[2]]
        access_levels = [r['access_level'] for r in call_args[2]]
        expected_rules_to_be_on_share = ([rule_1['id'], rule_2['id']])

        self.assertIsNone(retval)
        self.assertEqual(instance['id'], call_args[1]['id'])
        self.assertEqual(sorted(expected_rules_to_be_on_share),
                         sorted(access_rules_to_be_on_share))
        self.assertEqual(['ro'] * len(expected_rules_to_be_on_share),
                         access_levels)
        self.assertEqual(0, len(call_kwargs['add_rules']))
        self.assertEqual(0, len(call_kwargs['delete_rules']))
        self.assertEqual('fake_server', call_kwargs['share_server'])

    @ddt.data(True, False)
    def test__check_needs_refresh(self, expected_needs_refresh):
        states = (
            [constants.ACCESS_STATE_QUEUED_TO_DENY,
             constants.ACCESS_STATE_QUEUED_TO_APPLY] if expected_needs_refresh
            else [constants.ACCESS_STATE_ACTIVE]
        )
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            access_rules_status=constants.SHARE_INSTANCE_RULES_SYNCING)
        share_instance_id = share['instance']['id']
        rule_kwargs = {'share_id': share['id'], 'access_level': 'rw'}
        rule_1 = db_utils.create_access(state=states[0], **rule_kwargs)
        db_utils.create_access(state=constants.ACCESS_STATE_ACTIVE,
                               **rule_kwargs)
        db_utils.create_access(state=constants.ACCESS_STATE_DENYING,
                               **rule_kwargs)
        rule_4 = db_utils.create_access(state=states[-1], **rule_kwargs)

        get_and_update_call = self.mock_object(
            self.access_helper, 'get_and_update_share_instance_access_rules',
            mock.Mock(side_effect=self.access_helper.
                      get_and_update_share_instance_access_rules))

        needs_refresh = self.access_helper._check_needs_refresh(
            self.context, share_instance_id)

        expected_filter = {
            'state': (constants.ACCESS_STATE_QUEUED_TO_APPLY,
                      constants.ACCESS_STATE_QUEUED_TO_DENY),
        }
        expected_conditionally_change = {
            constants.ACCESS_STATE_QUEUED_TO_APPLY:
                constants.ACCESS_STATE_APPLYING,
            constants.ACCESS_STATE_QUEUED_TO_DENY:
                constants.ACCESS_STATE_DENYING,
        }

        self.assertEqual(expected_needs_refresh, needs_refresh)
        get_and_update_call.assert_called_once_with(
            self.context, filters=expected_filter,
            share_instance_id=share_instance_id,
            conditionally_change=expected_conditionally_change)

        rule_1 = db.share_instance_access_get(
            self.context, rule_1['id'], share_instance_id)
        rule_4 = db.share_instance_access_get(
            self.context, rule_4['id'], share_instance_id)

        if expected_needs_refresh:
            self.assertEqual(constants.ACCESS_STATE_DENYING, rule_1['state'])
            self.assertEqual(constants.ACCESS_STATE_APPLYING, rule_4['state'])
        else:
            self.assertEqual(states[0], rule_1['state'])
            self.assertEqual(states[-1], rule_4['state'])

    @ddt.data(('nfs', True, False), ('nfs', False, True),
              ('cifs', True, False), ('cifs', False, False),
              ('cephx', True, False), ('cephx', False, False))
    @ddt.unpack
    def test__update_rules_through_share_driver(self, proto,
                                                enable_ipv6, filtered):
        self.driver.ipv6_implemented = enable_ipv6
        share_instance = {'share_proto': proto}
        pass_rules, fail_rules = self._get_pass_rules_and_fail_rules()
        pass_add_rules, fail_add_rules = self._get_pass_rules_and_fail_rules()
        pass_delete_rules, fail_delete_rules = (
            self._get_pass_rules_and_fail_rules())
        test_rules = pass_rules + fail_rules
        test_add_rules = pass_add_rules + fail_add_rules
        test_delete_rules = pass_delete_rules + fail_delete_rules

        fake_expect_driver_update_rules = pass_rules
        update_access_call = self.mock_object(
            self.access_helper.driver, 'update_access',
            mock.Mock(return_value=pass_rules))
        driver_update_rules = (
            self.access_helper._update_rules_through_share_driver(
                self.context, share_instance=share_instance,
                access_rules_to_be_on_share=test_rules,
                add_rules=test_add_rules,
                delete_rules=test_delete_rules,
                rules_to_be_removed_from_db=test_rules,
                share_server=None))

        if filtered:
            update_access_call.assert_called_once_with(
                self.context, share_instance,
                pass_rules, add_rules=pass_add_rules,
                delete_rules=pass_delete_rules, share_server=None)
        else:
            update_access_call.assert_called_once_with(
                self.context, share_instance, test_rules,
                add_rules=test_add_rules, delete_rules=test_delete_rules,
                share_server=None)
        self.assertEqual(fake_expect_driver_update_rules, driver_update_rules)

    def _get_pass_rules_and_fail_rules(self):
        random_value = six.text_type(random.randint(10, 32))
        pass_rules = [
            {
                'access_type': 'ip',
                'access_to': '1.1.1.' + random_value,
            },
            {
                'access_type': 'ip',
                'access_to': '1.1.%s.0/24' % random_value,
            },
            {
                'access_type': 'user',
                'access_to': 'fake_user' + random_value,
            },
        ]
        fail_rules = [
            {
                'access_type': 'ip',
                'access_to': '1001::' + random_value,
            },
            {
                'access_type': 'ip',
                'access_to': '%s::/64' % random_value,
            },
        ]
        return pass_rules, fail_rules
