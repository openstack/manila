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
from unittest import mock

import ddt
from oslo_config import cfg
from oslo_utils import uuidutils
import webob

from manila.api.v2 import resource_locks
from manila import context
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila.tests.api.v2 import stubs
from manila.tests import utils as test_utils
from manila import utils

CONF = cfg.CONF


@ddt.ddt
class ResourceLockApiTest(test.TestCase):
    def setUp(self):
        super(ResourceLockApiTest, self).setUp()
        self.controller = resource_locks.ResourceLocksController()
        self.maxDiff = None
        self.ctxt = context.RequestContext('demo', 'fake', False)
        self.req = fakes.HTTPRequest.blank(
            '/resource-locks',
            version=resource_locks.RESOURCE_LOCKS_MIN_API_VERSION
        )
        self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True)
        )

    @ddt.data(
        test_utils.annotated(
            'no_body_content', {
                'body': {},
                'resource_type': 'share'
            }
        ),
        test_utils.annotated(
            'invalid_body', {
                'body': {
                    'share': 'somedata'
                },
                'resource_type': 'share'
            }
        ),
        test_utils.annotated(
            'invalid_action', {
                'body': {
                    'resource_lock': {
                        'resource_action': 'invalid_action',
                    }
                },
                'resource_type': 'share'
            },
        ),
        test_utils.annotated(
            'invalid_reason', {
                'body': {
                    'resource_lock': {
                        'lock_reason': 'xyzzyspoon!' * 94,
                    }
                },
                'resource_type': 'share'
            },
        ),
        test_utils.annotated(
            'disallowed_attributes', {
                'body': {
                    'resource_lock': {
                        'lock_reason': 'the reason is you',
                        'resource_action': 'delete',
                        'resource_id': uuidutils.generate_uuid(),
                    }
                },
                'resource_type': 'share'
            },
        ),
    )
    @ddt.unpack
    def test__check_body_for_update_invalid(self, body, resource_type):
        current_lock = {'resource_type': resource_type}
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._check_body,
                          body,
                          lock_to_update=current_lock)

    @ddt.data(
        test_utils.annotated('no_body_content', {}),
        test_utils.annotated('invalid_body', {'share': 'somedata'}),
        test_utils.annotated(
            'invalid_action', {
                'resource_lock': {
                    'resource_action': 'invalid_action',
                },
            },
        ),
        test_utils.annotated(
            'invalid_reason', {
                'resource_lock': {
                    'lock_reason': 'xyzzyspoon!' * 94,
                },
            },
        ),
        test_utils.annotated(
            'invalid_resource_id', {
                'resource_lock': {
                    'resource_id': 'invalid-id',
                    'resource_action': 'delete',
                },
            },
        ),
        test_utils.annotated(
            'invalid_resource_type', {
                'resource_lock': {
                    'resource_id': uuidutils.generate_uuid(),
                    'resource_type': 'invalid-resource-type',
                },
            },
        ),
    )
    def test__check_body_for_create_invalid(self, body):
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._check_body,
                          body)

    @ddt.data(
        test_utils.annotated(
            'action_and_lock_reason', {
                'body': {
                    'resource_lock': {
                        'resource_action': 'delete',
                        'lock_reason': 'the reason is you',
                    }
                },
                'resource_type': 'share',
            },
        ),
        test_utils.annotated(
            'lock_reason', {
                'body': {
                    'resource_lock': {
                        'lock_reason': 'tienes razon',
                    }
                },
                'resource_type': 'share',
            },
        ),
        test_utils.annotated(
            'resource_action', {
                'body': {
                    'resource_lock': {
                        'resource_action': 'delete',
                    }
                },
                'resource_type': 'access_rule',
            },
        ),
    )
    @ddt.unpack
    def test__check_body_for_update(self, body, resource_type):
        current_lock = copy.copy(body['resource_lock'])
        current_lock['resource_type'] = resource_type

        result = self.controller._check_body(
            body, lock_to_update=current_lock)

        self.assertIsNone(result)

    def test__check_body_for_create(self):
        body = {
            'resource_lock': {
                'resource_id': uuidutils.generate_uuid(),
                'resource_type': 'share',
            },
        }

        result = self.controller._check_body(body)

        self.assertIsNone(result)

    @ddt.data({'created_since': None, 'created_before': None},
              {'created_since': '2222-22-22', 'created_before': 'a_year_ago'},
              {'created_since': 'epoch'},
              {'created_before': 'december'})
    def test_index_invalid_time_filters(self, filters):
        url = '/resource-locks?'
        for key, value in filters.items():
            url += f'{key}={value}&'
        url.rstrip('&')
        req = fakes.HTTPRequest.blank(
            url, version=resource_locks.RESOURCE_LOCKS_MIN_API_VERSION)
        req.environ['manila.context'] = self.ctxt

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.index,
                          req)

    @ddt.data({'limit': 'a', 'offset': 'test'},
              {'limit': -1},
              {'with_count': 'oh-noes', 'limit': 0})
    def test_index_invalid_pagination(self, filters):
        url = '/resource-locks?'
        for key, value in filters.items():
            url += f'{key}={value}&'
        url.rstrip('&')

        req = fakes.HTTPRequest.blank(
            url, version=resource_locks.RESOURCE_LOCKS_MIN_API_VERSION)
        req.environ['manila.context'] = self.ctxt

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.index,
                          req)

    def test_index(self):
        url = ('/resource-locks?sort_dir=asc&sort_key=resource_id&limit=3'
               '&offset=1&project_id=f63f7a159f404cfc8604b7065c609691'
               '&with_count=1')
        req = fakes.HTTPRequest.blank(
            url, version=resource_locks.RESOURCE_LOCKS_MIN_API_VERSION)
        locks = [
            stubs.stub_lock('68e2e33d-0f0c-49b7-aee3-f0696ab90360'),
            stubs.stub_lock('93748a9f-6dfe-4baf-ad4c-b9c82d6063ef'),
            stubs.stub_lock('44f8dd68-2eeb-41df-b5d1-9e7654212527'),
        ]
        self.mock_object(self.controller.resource_locks_api,
                         'get_all',
                         mock.Mock(return_value=(locks, 3)))

        actual_locks = self.controller.index(req)

        expected_filters = {
            'project_id': 'f63f7a159f404cfc8604b7065c609691',
        }
        self.controller.resource_locks_api.get_all.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            search_opts=mock.ANY,
            limit=3,
            offset=1,
            sort_key='resource_id',
            sort_dir='asc',
            show_count=True,
        )
        # webob uses a "MultiDict" for request params
        actual_filters = {}
        call_args = self.controller.resource_locks_api.get_all.call_args[1]
        search_opts = call_args['search_opts']
        for key, value in search_opts.dict_of_lists().items():
            actual_filters[key] = value[0]

        self.assertEqual(expected_filters, actual_filters)
        self.assertEqual(3, len(actual_locks['resource_locks']))
        for lock in actual_locks['resource_locks']:
            for key in locks[0].keys():
                self.assertIn(key, lock)
            self.assertIn('links', lock)
        self.assertIn('resource_locks_links', actual_locks)
        self.assertEqual(3, actual_locks['count'])

    def test_show_not_found(self):
        url = '/resource-locks/fake-lock-id'
        req = fakes.HTTPRequest.blank(
            url, version=resource_locks.RESOURCE_LOCKS_MIN_API_VERSION)
        self.mock_object(
            self.controller.resource_locks_api, 'get',
            mock.Mock(side_effect=exception.ResourceLockNotFound(lock_id='1')))
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.show,
                          req,
                          'fake-lock-id')

    def test_show(self):
        url = '/resource-locks/c6aef27b-f583-48c7-aac1-bd8fb570ce16'
        req = fakes.HTTPRequest.blank(
            url, version=resource_locks.RESOURCE_LOCKS_MIN_API_VERSION)
        expected_lock = stubs.stub_lock(
            'c6aef27b-f583-48c7-aac1-bd8fb570ce16'
        )
        self.mock_object(
            self.controller.resource_locks_api,
            'get',
            mock.Mock(return_value=expected_lock)
        )

        actual_lock = self.controller.show(
            req, 'c6aef27b-f583-48c7-aac1-bd8fb570ce16')
        self.assertSubDictMatch(expected_lock, actual_lock['resource_lock'])
        self.assertIn('links', actual_lock['resource_lock'])

    def test_delete_not_found(self):
        url = '/resource-locks/fake-lock-id'
        req = fakes.HTTPRequest.blank(
            url, version=resource_locks.RESOURCE_LOCKS_MIN_API_VERSION)
        self.mock_object(
            self.controller.resource_locks_api,
            'delete',
            mock.Mock(side_effect=exception.ResourceLockNotFound(lock_id='1')),
        )
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.delete,
                          req,
                          'fake-lock-id')

    def test_delete(self):
        url = '/resource-locks/c6aef27b-f583-48c7-aac1-bd8fb570ce16'
        req = fakes.HTTPRequest.blank(
            url, version=resource_locks.RESOURCE_LOCKS_MIN_API_VERSION)
        self.mock_object(self.controller.resource_locks_api, 'delete')

        result = self.controller.delete(req,
                                        'c6aef27b-f583-48c7-aac1-bd8fb570ce16')
        self.assertEqual(204, result.status_int)

    def test_create_no_such_resource(self):
        self.mock_object(self.controller, '_check_body')
        body = {
            'resource_lock': {
                'resource_id': '27e14086-16e1-445b-ad32-b2ebb07225a8',
                'resource_type': 'share',
            },
        }
        self.mock_object(self.controller.resource_locks_api,
                         'create',
                         mock.Mock(side_effect=exception.NotFound))
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create,
                          self.req,
                          body)

    def test_create_visibility_already_locked(self):
        self.mock_object(self.controller, '_check_body')
        resource_id = '27e14086-16e1-445b-ad32-b2ebb07225a8'
        body = {
            'resource_lock': {
                'resource_id': resource_id,
                'resource_type': 'share',
            },
        }
        self.mock_object(
            self.controller.resource_locks_api,
            'create',
            mock.Mock(
                side_effect=exception.ResourceVisibilityLockExists(
                    resource_id=resource_id))
        )
        self.assertRaises(webob.exc.HTTPConflict,
                          self.controller.create,
                          self.req,
                          body)

    def test_create(self):
        self.mock_object(self.controller, '_check_body')
        expected_lock = stubs.stub_lock(
            '04512dae-18c2-45b5-bbab-50b775ba6f1d',
            lock_reason=None,
        )
        body = {
            'resource_lock': {
                'resource_id': expected_lock['resource_id'],
                'resource_type': expected_lock['resource_type'],
            },
        }
        self.mock_object(self.controller.resource_locks_api,
                         'create',
                         mock.Mock(return_value=expected_lock))

        actual_lock = self.controller.create(self.req, body)['resource_lock']

        self.controller.resource_locks_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            resource_id=expected_lock['resource_id'],
            resource_type=expected_lock['resource_type'],
            resource_action='delete',
            lock_reason=None,
        )
        self.assertSubDictMatch(expected_lock, actual_lock)
        self.assertIn('links', actual_lock)

    def test_update(self):
        expected_lock = stubs.stub_lock(
            '04512dae-18c2-45b5-bbab-50b775ba6f1d',
            lock_reason=None,
        )
        self.mock_object(self.controller, '_check_body')
        self.mock_object(self.controller.resource_locks_api, 'get',
                         mock.Mock(return_value=expected_lock))
        self.mock_object(self.controller.resource_locks_api,
                         'update',
                         mock.Mock(return_value=expected_lock))

        body = {
            'resource_lock': {
                'lock_reason': None
            },
        }

        actual_lock = self.controller.update(
            self.req,
            '04512dae-18c2-45b5-bbab-50b775ba6f1d',
            body
        )['resource_lock']

        self.controller.resource_locks_api.update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            expected_lock,
            {'lock_reason': None}
        )
        self.assertSubDictMatch(expected_lock, actual_lock)
