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

from unittest import mock

import ddt
from oslo_config import cfg

from manila.common import constants
from manila import context
from manila import exception
from manila.lock import api as lock_api
from manila import policy
from manila import test
from manila.tests import utils as test_utils
from manila import utils

CONF = cfg.CONF


@ddt.ddt
class ResourceLockApiTest(test.TestCase):

    def setUp(self):
        super(ResourceLockApiTest, self).setUp()
        self.lock_api = lock_api.API()
        self.mock_object(self.lock_api, 'db')
        self.ctxt = context.RequestContext('fakeuser',
                                           'fakeproject',
                                           is_admin=False)
        self.mock_object(policy, 'check_policy')

    @ddt.data(
        test_utils.annotated(
            'admin_context',
            (context.RequestContext('fake', 'fake', is_admin=True), 'admin'),
        ),
        test_utils.annotated(
            'admin_also_service_context',
            (context.RequestContext('fake', 'fake', service_roles=['service'],
                                    is_admin=True), 'service'),
        ),
        test_utils.annotated(
            'service_context',
            (context.RequestContext('fake', 'fake', service_roles=['service'],
                                    is_admin=False), 'service'),
        ),
        test_utils.annotated(
            'user_context',
            (context.RequestContext('fake', 'fake', is_admin=False), 'user')
        ),
    )
    @ddt.unpack
    def test__get_lock_context(self, ctxt, expected_lock_context):
        result = self.lock_api._get_lock_context(ctxt)

        self.assertEqual(expected_lock_context, result['lock_context'])
        self.assertEqual(('fake', 'fake'),
                         (result['user_id'], result['project_id']))

    @ddt.data(
        test_utils.annotated(
            'user_manipulating_admin_lock',
            (context.RequestContext('fake', 'fake', is_admin=False), 'admin'),
        ),
        test_utils.annotated(
            'user_manipulating_service_lock',
            (context.RequestContext('fake', 'fake', is_admin=False),
             'service'),
        ),
        test_utils.annotated(
            'service_manipulating_admin_lock',
            (context.RequestContext('fake', 'fake', is_admin=False,
                                    service_roles=['service']), 'admin'),
        ),
    )
    @ddt.unpack
    def test__check_allow_lock_manipulation_not_allowed(self, ctxt, lock_ctxt):
        self.assertRaises(exception.NotAuthorized,
                          self.lock_api._check_allow_lock_manipulation,
                          ctxt, {'lock_context': lock_ctxt})

    @ddt.data(
        test_utils.annotated(
            'user_manipulating_user_lock',
            (context.RequestContext('fake', 'fake', is_admin=False), 'user'),
        ),
        test_utils.annotated(
            'service_manipulating_service_lock',
            (context.RequestContext(
                'fake', 'fake', is_admin=False, service_roles=['service']),
             'service'),
        ),
        test_utils.annotated(
            'service_manipulating_user_lock',
            (context.RequestContext(
                'fake', 'fake', is_admin=False, service_roles=['service']),
             'user'),
        ),
        test_utils.annotated(
            'admin_manipulating_service_lock',
            (context.RequestContext('fake', 'fake', is_admin=True), 'service'),
        ),
        test_utils.annotated(
            'admin_manipulating_user_lock',
            (context.RequestContext('fake', 'fake', is_admin=True), 'user'),
        ),
    )
    @ddt.unpack
    def test__check_allow_lock_manipulation_allowed(self, ctxt, lock_ctxt):

        result = self.lock_api._check_allow_lock_manipulation(
            ctxt,
            {'lock_context': lock_ctxt}
        )
        self.assertIsNone(result)

    @ddt.data(
        test_utils.annotated(
            'service_manipulating_user_lock',
            (context.RequestContext(
                'fake', 'fake', is_admin=False,
                service_roles=['service']),
             'user',
             'user_b'),
        ),
        test_utils.annotated(
            'admin_manipulating_user_lock',
            (context.RequestContext('fake', 'fake', is_admin=True),
             'admin',
             'user_a'),
        ),
        test_utils.annotated(
            'user_manipulating_locks_they_own',
            (context.RequestContext('user_a', 'fake', is_admin=False),
             'user',
             'user_a'),
        ),
        test_utils.annotated(
            'user_manipulating_other_users_lock',
            (context.RequestContext('user_a', 'fake', is_admin=False),
             'user',
             'user_b'),
        ),
    )
    @ddt.unpack
    def test_access_is_restricted(self, ctxt, lock_ctxt, lock_user):
        resource_lock = {
            'user_id': lock_user,
            'lock_context': lock_ctxt
        }
        is_restricted = (
            (not ctxt.is_admin and not ctxt.is_service)
            and lock_user != ctxt.user_id)
        expected_mock_policy = {}
        if is_restricted:
            expected_mock_policy['side_effect'] = exception.NotAuthorized
        self.mock_object(self.lock_api, '_check_allow_lock_manipulation')
        self.mock_object(policy, 'check_policy',
                         mock.Mock(**expected_mock_policy))

        result = self.lock_api.access_is_restricted(
            ctxt,
            resource_lock
        )
        self.assertEqual(is_restricted, result)

    def test_access_is_restricted_not_authorized(self):
        resource_lock = {
            'user_id': 'fakeuserid',
            'lock_context': 'user'
        }
        ctxt = context.RequestContext('fake', 'fake')
        self.mock_object(self.lock_api, '_check_allow_lock_manipulation',
                         mock.Mock(side_effect=exception.NotAuthorized()))

        result = self.lock_api.access_is_restricted(
            ctxt,
            resource_lock
        )
        self.assertTrue(result)

    def test_get_all_all_projects_ignored(self):
        self.mock_object(policy, 'check_policy', mock.Mock(return_value=False))
        self.mock_object(self.lock_api.db, 'resource_lock_get_all',
                         mock.Mock(return_value=('list of locks', None)))

        locks, count = self.lock_api.get_all(
            self.ctxt,
            search_opts={
                'all_projects': True,
                'project_id': '5dca5323e33b49fca4a5b261c72e612c',
            })
        self.lock_api.db.resource_lock_get_all.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            filters={},
            limit=None,
            offset=None,
            sort_key='created_at',
            sort_dir='desc',
            show_count=False,
        )
        self.assertEqual(('list of locks', None), (locks, count))

    def test_get_all_with_filters(self):
        self.mock_object(self.lock_api.db, 'resource_lock_get_all',
                         mock.Mock(return_value=('list of locks', 4)))
        search_opts = {
            'all_projects': True,
            'project_id': '5dca5323e33b49fca4a5b261c72e612c',
            'resource_type': 'snapshot',
        }
        locks = self.lock_api.get_all(
            self.ctxt,
            limit=3,
            offset=3,
            search_opts=search_opts,
            show_count=True
        )
        self.lock_api.db.resource_lock_get_all.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            filters=search_opts,
            limit=3,
            offset=3,
            sort_key='created_at',
            sort_dir='desc',
            show_count=True,
        )
        self.assertEqual('list of locks', locks[0])
        self.assertEqual(4, locks[1])

    def test_create_lock_resource_not_owned_by_user(self):
        self.mock_object(
            policy,
            'check_policy',
            mock.Mock(side_effect=exception.PolicyNotAuthorized(
                action="resource_lock:create")),
        )

        self.assertRaises(exception.PolicyNotAuthorized,
                          self.lock_api.create,
                          self.ctxt,
                          resource_id='19529cea-0471-4972-adaa-fee8694b7538',
                          resource_type='share',
                          resource_action='delete')
        self.lock_api.db.share_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            '19529cea-0471-4972-adaa-fee8694b7538',
        )
        self.lock_api.db.resource_lock_create.assert_not_called()

    @ddt.data(constants.STATUS_DELETING,
              constants.STATUS_ERROR_DELETING,
              constants.STATUS_UNMANAGING,
              constants.STATUS_MANAGE_ERROR_UNMANAGING,
              constants.STATUS_UNMANAGE_ERROR,
              constants.STATUS_UNMANAGED,
              constants.STATUS_DELETED)
    def test_create_lock_invalid_resource_status(self, status):
        self.mock_object(self.lock_api.db, 'resource_lock_create',
                         mock.Mock(return_value='created_obj'))
        self.mock_object(self.lock_api.db, 'share_get',
                         mock.Mock(return_value={'status': status}))

        self.assertRaises(exception.InvalidInput,
                          self.lock_api.create,
                          self.ctxt,
                          resource_id='7dab6090-1dfd-4829-bbaf-602fcd1c8248',
                          resource_action='delete',
                          resource_type='share')

        self.lock_api.db.resource_lock_create.assert_not_called()

    def test_create_lock_invalid_resource_soft_deleted(self):
        self.mock_object(self.lock_api.db, 'resource_lock_create',
                         mock.Mock(return_value='created_obj'))
        self.mock_object(self.lock_api.db, 'share_get',
                         mock.Mock(return_value={'is_soft_deleted': True}))

        self.assertRaises(exception.InvalidInput,
                          self.lock_api.create,
                          self.ctxt,
                          resource_id='0bbf0b62-cb29-4218-920b-3f62faa99ff8',
                          resource_action='delete',
                          resource_type='share')

        self.lock_api.db.resource_lock_create.assert_not_called()

    def test_create_lock(self):
        self.mock_object(self.lock_api.db, 'resource_lock_create',
                         mock.Mock(return_value='created_obj'))
        mock_share = {
            'id': 'cacac01c-853d-47f3-afcb-da4484bd09a5',
            'status': constants.STATUS_AVAILABLE,
            'is_soft_deleted': False,
        }
        self.mock_object(self.lock_api.db, 'share_get',
                         mock.Mock(return_value=mock_share))

        result = self.lock_api.create(
            self.ctxt,
            resource_id='cacac01c-853d-47f3-afcb-da4484bd09a5',
            resource_action='delete',
            resource_type='share',
        )

        self.assertEqual('created_obj', result)
        db_create_arg = self.lock_api.db.resource_lock_create.call_args[0][1]
        expected_create_arg = {
            'resource_id': 'cacac01c-853d-47f3-afcb-da4484bd09a5',
            'resource_action': 'delete',
            'user_id': 'fakeuser',
            'project_id': 'fakeproject',
            'lock_context': 'user',
            'lock_reason': None,
            'resource_type': constants.SHARE_RESOURCE_TYPE

        }
        self.assertEqual(expected_create_arg, db_create_arg)

    def test_create_access_show_lock(self):
        self.mock_object(self.lock_api.db, 'resource_lock_create',
                         mock.Mock(return_value='created_obj'))
        mock_access = {
            'id': 'cacac01c-853d-47f3-afcb-da4484bd09a5',
            'state': constants.STATUS_ACTIVE,
        }
        self.mock_object(self.lock_api.db, 'access_get',
                         mock.Mock(return_value=mock_access))
        self.mock_object(self.lock_api.db, 'resource_lock_get_all',
                         mock.Mock(return_value=['', 0]))
        self.mock_object(self.ctxt, 'elevated',
                         mock.Mock(return_value=self.ctxt))

        result = self.lock_api.create(
            self.ctxt,
            resource_id='cacac01c-853d-47f3-afcb-da4484bd09a5',
            resource_action=constants.RESOURCE_ACTION_SHOW,
            resource_type=constants.SHARE_ACCESS_RESOURCE_TYPE,
        )

        self.assertEqual('created_obj', result)
        db_create_arg = self.lock_api.db.resource_lock_create.call_args[0][1]
        resource_id = 'cacac01c-853d-47f3-afcb-da4484bd09a5'
        expected_create_arg = {
            'resource_id': resource_id,
            'resource_action': constants.RESOURCE_ACTION_SHOW,
            'user_id': 'fakeuser',
            'project_id': 'fakeproject',
            'lock_context': 'user',
            'lock_reason': None,
            'resource_type': constants.SHARE_ACCESS_RESOURCE_TYPE

        }
        self.assertEqual(expected_create_arg, db_create_arg)
        filters = {
            'resource_id': resource_id,
            'resource_action': constants.RESOURCE_ACTION_SHOW,
            'all_projects': True
        }
        self.lock_api.db.resource_lock_get_all.assert_called_once_with(
            self.ctxt, filters=filters)

    def test_create_visibility_lock_lock_exists(self):
        self.mock_object(self.lock_api.db, 'resource_lock_create',
                         mock.Mock(return_value='created_obj'))
        self.mock_object(self.lock_api.db, 'resource_lock_get_all',
                         mock.Mock(return_value=['visibility_lock', 1]))
        self.mock_object(self.ctxt, 'elevated',
                         mock.Mock(return_value=self.ctxt))

        self.assertRaises(
            exception.ResourceVisibilityLockExists,
            self.lock_api.create,
            self.ctxt,
            resource_id='cacac01c-853d-47f3-afcb-da4484bd09a5',
            resource_action=constants.RESOURCE_ACTION_SHOW,
            resource_type=constants.SHARE_ACCESS_RESOURCE_TYPE,
        )

        resource_id = 'cacac01c-853d-47f3-afcb-da4484bd09a5'
        filters = {
            'resource_id': resource_id,
            'resource_action': constants.RESOURCE_ACTION_SHOW,
            'all_projects': True
        }
        self.lock_api.db.resource_lock_get_all.assert_called_once_with(
            self.ctxt, filters=filters)

    @ddt.data(True, False)
    def test_update_lock_resource_not_allowed_with_policy_failure(
            self, policy_fails):
        lock = {'id': 'd767d3cd-1187-404a-a91f-8b172e0e768e'}
        if policy_fails:
            self.mock_object(
                policy,
                'check_policy',
                mock.Mock(
                    side_effect=exception.PolicyNotAuthorized(
                        action='resource_lock:update'),
                ),
            )
        self.mock_object(
            self.lock_api,
            '_check_allow_lock_manipulation',
            mock.Mock(
                side_effect=exception.NotAuthorized
            ),
        )

        self.assertRaises(exception.NotAuthorized,
                          self.lock_api.update,
                          self.ctxt,
                          lock,
                          {'foo': 'bar'})

    @ddt.data(constants.STATUS_DELETING,
              constants.STATUS_ERROR_DELETING,
              constants.STATUS_UNMANAGING,
              constants.STATUS_MANAGE_ERROR_UNMANAGING,
              constants.STATUS_UNMANAGE_ERROR,
              constants.STATUS_UNMANAGED,
              constants.STATUS_DELETED)
    def test_update_invalid_resource_status(self, status):
        lock = {
            'id': 'd767d3cd-1187-404a-a91f-8b172e0e768e',
            'resource_id': '266cf54f-f9cf-4d6c-94f3-7b67f00e0465',
            'resource_action': 'something',
            'resource_type': 'share',
        }
        self.mock_object(self.lock_api, '_check_allow_lock_manipulation')
        self.mock_object(self.lock_api.db,
                         'share_get',
                         mock.Mock(return_value={'status': status}))

        self.assertRaises(exception.InvalidInput,
                          self.lock_api.update,
                          self.ctxt,
                          lock,
                          {'resource_action': 'delete'})

        self.lock_api.db.resource_lock_update.assert_not_called()

    def test_update(self):
        self.mock_object(self.lock_api, '_check_allow_lock_manipulation')
        self.mock_object(self.lock_api.db, 'resource_lock_update',
                         mock.Mock(return_value='updated_obj'))
        lock = {'id': 'd767d3cd-1187-404a-a91f-8b172e0e768e'}

        result = self.lock_api.update(
            self.ctxt,
            lock,
            {'foo': 'bar'},
        )

        self.assertEqual('updated_obj', result)
        self.lock_api.db.resource_lock_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            'd767d3cd-1187-404a-a91f-8b172e0e768e',
            {'foo': 'bar'},
        )

    @ddt.data(True, False)
    def test_delete_not_allowed_with_policy_failure(self, policy_fails):
        self.mock_object(self.lock_api.db, 'resource_lock_get', mock.Mock(
            return_value={'id': 'd767d3cd-1187-404a-a91f-8b172e0e768e'}))
        if policy_fails:
            self.mock_object(
                policy,
                'check_policy',
                mock.Mock(
                    side_effect=exception.PolicyNotAuthorized(
                        action='resource_lock:delete'),
                ),
            )
        self.mock_object(
            self.lock_api,
            '_check_allow_lock_manipulation',
            mock.Mock(
                side_effect=exception.NotAuthorized
            ),
        )

        self.assertRaises(exception.NotAuthorized,
                          self.lock_api.delete,
                          self.ctxt,
                          'd767d3cd-1187-404a-a91f-8b172e0e768e')

        policy.check_policy.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            'resource_lock',
            'delete',
            {'id': 'd767d3cd-1187-404a-a91f-8b172e0e768e'},
        )
        self.assertEqual(not policy_fails,
                         self.lock_api._check_allow_lock_manipulation.called)
        self.lock_api.db.resource_lock_delete.assert_not_called()

    def test_delete(self):
        self.mock_object(self.lock_api.db, 'resource_lock_get', mock.Mock(
            return_value={'id': 'd767d3cd-1187-404a-a91f-8b172e0e768e'}))
        self.mock_object(self.lock_api, '_check_allow_lock_manipulation')

        result = self.lock_api.delete(self.ctxt,
                                      'd767d3cd-1187-404a-a91f-8b172e0e768e')
        self.assertIsNone(result)
        self.lock_api.db.resource_lock_delete.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            'd767d3cd-1187-404a-a91f-8b172e0e768e'
        )
