# Copyright 2015 Mirantis inc.
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
import webob

from manila.api.v1 import share_manage
from manila.db import api as db_api
from manila import exception
from manila import policy
from manila.share import api as share_api
from manila.share import share_types
from manila import test
from manila.tests.api import fakes
from manila import utils


def get_fake_manage_body(export_path='/fake', service_host='fake@host#POOL',
                         protocol='fake', share_type='fake', **kwargs):
    fake_share = {
        'export_path': export_path,
        'service_host': service_host,
        'protocol': protocol,
        'share_type': share_type,
    }
    fake_share.update(kwargs)
    return {'share': fake_share}


@ddt.ddt
class ShareManageTest(test.TestCase):
    """Share Manage Test."""
    def setUp(self):
        super(ShareManageTest, self).setUp()
        self.controller = share_manage.ShareManageController()
        self.resource_name = self.controller.resource_name
        self.request = fakes.HTTPRequest.blank('/share/manage',
                                               use_admin_context=True)
        self.context = self.request.environ['manila.context']
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))

    @ddt.data({},
              {'shares': {}},
              {'share': get_fake_manage_body('', None, None)})
    def test_share_manage_invalid_body(self, body):
        self.assertRaises(webob.exc.HTTPUnprocessableEntity,
                          self.controller.create,
                          self.request,
                          body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'manage')

    def test_share_manage_service_not_found(self):
        body = get_fake_manage_body()
        self.mock_object(db_api, 'service_get_by_host_and_topic', mock.Mock(
            side_effect=exception.ServiceNotFound(service_id='fake')))

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.create,
                          self.request,
                          body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'manage')

    def test_share_manage_share_type_not_found(self):
        body = get_fake_manage_body()
        self.mock_object(db_api, 'service_get_by_host_and_topic', mock.Mock())
        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))
        self.mock_object(db_api, 'share_type_get_by_name', mock.Mock(
            side_effect=exception.ShareTypeNotFoundByName(
                share_type_name='fake')))

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.create,
                          self.request,
                          body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'manage')

    def _setup_manage_mocks(self, service_is_up=True):
        self.mock_object(db_api, 'service_get_by_host_and_topic', mock.Mock(
            return_value={'host': 'fake'}))
        self.mock_object(share_types, 'get_share_type_by_name_or_id',
                         mock.Mock(return_value={'id': 'fake'}))
        self.mock_object(utils, 'service_is_up', mock.Mock(
            return_value=service_is_up))

    @ddt.data({'service_is_up': False, 'service_host': 'fake@host#POOL'},
              {'service_is_up': True, 'service_host': 'fake@host'})
    def test_share_manage_bad_request(self, settings):
        body = get_fake_manage_body(service_host=settings.pop('service_host'))
        self._setup_manage_mocks(**settings)

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create,
                          self.request,
                          body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'manage')

    def test_share_manage_duplicate_share(self):
        body = get_fake_manage_body()
        exc = exception.InvalidShare(reason="fake")
        self._setup_manage_mocks()
        self.mock_object(share_api.API, 'manage', mock.Mock(side_effect=exc))

        self.assertRaises(webob.exc.HTTPConflict,
                          self.controller.create,
                          self.request,
                          body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'manage')

    def test_share_manage_forbidden_manage(self):
        body = get_fake_manage_body()
        self._setup_manage_mocks()
        error = mock.Mock(side_effect=exception.PolicyNotAuthorized(action=''))
        self.mock_object(share_api.API, 'manage', error)

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller.create,
                          self.request,
                          body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'manage')

    def test_share_manage_forbidden_validate_service_host(self):
        body = get_fake_manage_body()
        self._setup_manage_mocks()
        error = mock.Mock(side_effect=exception.PolicyNotAuthorized(action=''))
        self.mock_object(utils, 'service_is_up', mock.Mock(side_effect=error))

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller.create,
                          self.request,
                          body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'manage')

    @ddt.data(
        get_fake_manage_body(name='foo', description='bar'),
        get_fake_manage_body(display_name='foo', description='bar'),
        get_fake_manage_body(name='foo', display_description='bar'),
        get_fake_manage_body(display_name='foo', display_description='bar'),
        get_fake_manage_body(display_name='foo', display_description='bar',
                             driver_options=dict(volume_id='quuz')),
    )
    def test_share_manage(self, data):
        self._setup_manage_mocks()
        return_share = {'share_type_id': '', 'id': 'fake'}
        self.mock_object(
            share_api.API, 'manage', mock.Mock(return_value=return_share))
        share = {
            'host': data['share']['service_host'],
            'export_location': data['share']['export_path'],
            'share_proto': data['share']['protocol'].upper(),
            'share_type_id': 'fake',
            'display_name': 'foo',
            'display_description': 'bar',
        }
        data['share']['is_public'] = 'foo'
        driver_options = data['share'].get('driver_options', {})

        actual_result = self.controller.create(self.request, data)

        share_api.API.manage.assert_called_once_with(
            mock.ANY, share, driver_options)
        self.assertIsNotNone(actual_result)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'manage')

    def test_wrong_permissions(self):
        body = get_fake_manage_body()
        fake_req = fakes.HTTPRequest.blank(
            '/share/manage', use_admin_context=False)

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller.create,
                          fake_req, body)
        self.mock_policy_check.assert_called_once_with(
            fake_req.environ['manila.context'], self.resource_name, 'manage')
