# Copyright 2019 NetApp, Inc.
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

from manila.api.v2 import share_servers
from manila.common import constants
from manila.db import api as db_api
from manila import exception
from manila import policy
from manila.share import api as share_api
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils
from manila import utils


@ddt.ddt
class ShareServerControllerTest(test.TestCase):
    """Share server api test"""

    def setUp(self):
        super(ShareServerControllerTest, self).setUp()
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.controller = share_servers.ShareServerController()
        self.resource_name = self.controller.resource_name

    @ddt.data(constants.STATUS_ACTIVE, constants.STATUS_ERROR,
              constants.STATUS_DELETING, constants.STATUS_CREATING,
              constants.STATUS_MANAGING, constants.STATUS_UNMANAGING,
              constants.STATUS_UNMANAGE_ERROR, constants.STATUS_MANAGE_ERROR)
    def test_share_server_reset_status(self, status):
        req = fakes.HTTPRequest.blank('/v2/share-servers/fake-share-server/',
                                      use_admin_context=True)
        body = {'reset_status': {'status': status}}

        context = req.environ['manila.context']
        mock_update = self.mock_object(db_api, 'share_server_update')

        result = self.controller.share_server_reset_status(
            req, 'fake_server_id', body)

        self.assertEqual(202, result.status_int)
        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'reset_status')
        mock_update.assert_called_once_with(
            context, 'fake_server_id', {'status': status})

    def test_share_reset_server_status_invalid(self):
        req = fakes.HTTPRequest.blank('/reset_status', use_admin_context=True)
        body = {'reset_status': {'status': constants.STATUS_EXTENDING}}
        context = req.environ['manila.context']

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.share_server_reset_status,
            req, id='fake_server_id', body=body)
        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'reset_status')

    def test_share_server_reset_status_no_body(self):
        req = fakes.HTTPRequest.blank('/reset_status', use_admin_context=True)
        context = req.environ['manila.context']

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.share_server_reset_status,
            req, id='fake_server_id', body={})
        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'reset_status')

    def test_share_server_reset_status_no_status(self):
        req = fakes.HTTPRequest.blank('/reset_status', use_admin_context=True)
        context = req.environ['manila.context']

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.share_server_reset_status,
            req, id='fake_server_id', body={'reset_status': {}})
        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'reset_status')

    def _setup_manage_test_request_body(self):
        body = {
            'share_network_id': 'fake_net_id',
            'host': 'fake_host',
            'identifier': 'fake_identifier',
            'driver_options': {'opt1': 'fake_opt1', 'opt2': 'fake_opt2'},
        }
        return body

    @ddt.data('fake_net_name', '')
    def test_manage(self, share_net_name):
        """Tests share server manage"""
        req = fakes.HTTPRequest.blank('/v2/share-servers/',
                                      use_admin_context=True,
                                      version="2.49")
        context = req.environ['manila.context']
        share_network = db_utils.create_share_network(name=share_net_name)
        share_server = db_utils.create_share_server(
            share_network_id=share_network['id'],
            host='fake_host',
            identifier='fake_identifier',
            is_auto_deletable=False)

        self.mock_object(db_api, 'share_network_get', mock.Mock(
            return_value=share_network))
        self.mock_object(utils, 'validate_service_host')

        body = {
            'share_server': self._setup_manage_test_request_body()
        }

        manage_share_server_mock = self.mock_object(
            share_api.API, 'manage_share_server',
            mock.Mock(return_value=share_server))

        result = self.controller.manage(req, body)
        expected_result = {
            'share_server': {
                'id': share_server['id'],
                'project_id': 'fake',
                'updated_at': None,
                'status': constants.STATUS_ACTIVE,
                'host': 'fake_host',
                'share_network_id': share_server['share_network_id'],
                'created_at': share_server['created_at'],
                'backend_details': {},
                'identifier': share_server['identifier'],
                'is_auto_deletable': share_server['is_auto_deletable'],
            }
        }
        if share_net_name != '':
            expected_result['share_server']['share_network_name'] = (
                'fake_net_name')
        else:
            expected_result['share_server']['share_network_name'] = (
                share_server['share_network_id'])

        req_params = body['share_server']
        manage_share_server_mock.assert_called_once_with(
            context, req_params['identifier'], req_params['host'],
            share_network, req_params['driver_options'])

        self.assertEqual(expected_result, result)

        self.mock_policy_check.assert_called_once_with(
            context, self.resource_name, 'manage_share_server')

    def test_manage_invalid(self):
        req = fakes.HTTPRequest.blank('/manage_share_server',
                                      use_admin_context=True)
        context = req.environ['manila.context']
        share_network = db_utils.create_share_network()

        body = {
            'share_server': self._setup_manage_test_request_body()
        }
        self.mock_object(utils, 'validate_service_host')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))

        manage_share_server_mock = self.mock_object(
            share_api.API, 'manage_share_server',
            mock.Mock(side_effect=exception.InvalidInput('foobar')))

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.manage, req, body)

        req_params = body['share_server']
        manage_share_server_mock.assert_called_once_with(
            context, req_params['identifier'], req_params['host'],
            share_network, req_params['driver_options'])

    def test_manage_forbidden(self):
        """Tests share server manage without admin privileges"""
        req = fakes.HTTPRequest.blank('/manage_share_server')
        self.mock_object(share_api.API, 'manage_share_server', mock.Mock())
        error = mock.Mock(side_effect=exception.PolicyNotAuthorized(action=''))
        self.mock_object(share_api.API, 'manage_share_server', error)

        body = {
            'share_server': self._setup_manage_test_request_body()
        }

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller.manage,
                          req,
                          body)

    def test__validate_manage_share_server_validate_no_body(self):
        """Tests share server manage"""
        req = fakes.HTTPRequest.blank('/manage')
        body = {}

        self.assertRaises(webob.exc.HTTPUnprocessableEntity,
                          self.controller.manage,
                          req,
                          body)

    @ddt.data({'empty': False, 'key': 'host'},
              {'empty': False, 'key': 'share_network_id'},
              {'empty': False, 'key': 'identifier'},
              {'empty': True, 'key': 'host'},
              {'empty': True, 'key': 'share_network_id'},
              {'empty': True, 'key': 'identifier'})
    @ddt.unpack
    def test__validate_manage_share_server_validate_without_parameters(
            self, empty, key):
        """Tests share server manage without some parameters"""
        req = fakes.HTTPRequest.blank('/manage_share_server')
        self.mock_object(share_api.API, 'manage_share_server', mock.Mock())

        body = {
            'share_server': self._setup_manage_test_request_body(),
        }

        if empty:
            body['share_server'][key] = None
        else:
            body['share_server'].pop(key)

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.manage,
                          req,
                          body)

    @ddt.data(
        (webob.exc.HTTPBadRequest, exception.ServiceNotFound('foobar')),
        (webob.exc.HTTPBadRequest, exception.ServiceIsDown('foobar')),
        (webob.exc.HTTPForbidden, exception.PolicyNotAuthorized('foobar')),
        (webob.exc.HTTPForbidden, exception.AdminRequired())
    )
    @ddt.unpack
    def test__validate_manage_share_server_validate_service_host(
            self, exception_to_raise, side_effect_exception):
        req = fakes.HTTPRequest.blank('/manage')
        context = req.environ['manila.context']
        error = mock.Mock(side_effect=side_effect_exception)
        self.mock_object(utils, 'validate_service_host', error)

        self.assertRaises(
            exception_to_raise, self.controller.manage, req,
            {'share_server': self._setup_manage_test_request_body()})

        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'manage_share_server')

    def test__validate_manage_share_server_share_network_not_found(self):
        req = fakes.HTTPRequest.blank('/manage')
        context = req.environ['manila.context']
        self.mock_object(utils, 'validate_service_host')
        error = mock.Mock(
            side_effect=exception.ShareNetworkNotFound(share_network_id="foo"))
        self.mock_object(db_api, 'share_network_get', error)
        body = self._setup_manage_test_request_body()

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.manage,
                          req,
                          {'share_server': body})

        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'manage_share_server')

    def test__validate_manage_share_server_driver_opts_not_instance_dict(self):
        req = fakes.HTTPRequest.blank('/manage')
        context = req.environ['manila.context']
        self.mock_object(utils, 'validate_service_host')
        self.mock_object(db_api, 'share_network_get')
        body = self._setup_manage_test_request_body()
        body['driver_options'] = 'incorrect'
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.manage,
                          req,
                          {'share_server': body})

        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'manage_share_server')

    def test__validate_manage_share_server_error_extract_host(self):
        req = fakes.HTTPRequest.blank('/manage')
        context = req.environ['manila.context']
        body = self._setup_manage_test_request_body()
        body['host'] = 'fake@backend#pool'
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.manage,
                          req,
                          {'share_server': body})

        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'manage_share_server')

    @ddt.data(True, False)
    def test_unmanage(self, force):
        server = self._setup_unmanage_tests()
        req = fakes.HTTPRequest.blank('/unmanage')
        context = req.environ['manila.context']
        mock_get = self.mock_object(
            db_api, 'share_server_get', mock.Mock(return_value=server))
        mock_unmanage = self.mock_object(
            share_api.API, 'unmanage_share_server',
            mock.Mock(return_value=202))
        body = {'unmanage': {'force': force}}
        resp = self.controller.unmanage(req, server['id'], body)

        self.assertEqual(202, resp.status_int)

        mock_get.assert_called_once_with(context, server['id'])
        mock_unmanage.assert_called_once_with(context, server, force=force)

    def test_unmanage_share_server_not_found(self):
        """Tests unmanaging share servers"""
        req = fakes.HTTPRequest.blank('/v2/share-servers/fake_server_id/')
        context = req.environ['manila.context']
        share_server_error = mock.Mock(
            side_effect=exception.ShareServerNotFound(
                share_server_id='fake_server_id'))
        get_mock = self.mock_object(
            db_api, 'share_server_get', share_server_error)
        body = {'unmanage': {'force': True}}

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.unmanage,
                          req,
                          'fake_server_id',
                          body)

        get_mock.assert_called_once_with(context, 'fake_server_id')

    @ddt.data(constants.STATUS_MANAGING, constants.STATUS_DELETING,
              constants.STATUS_CREATING, constants.STATUS_UNMANAGING)
    def test_unmanage_share_server_invalid_statuses(self, status):
        """Tests unmanaging share servers"""
        server = self._setup_unmanage_tests(status=status)
        get_mock = self.mock_object(db_api, 'share_server_get',
                                    mock.Mock(return_value=server))
        req = fakes.HTTPRequest.blank('/unmanage_share_server')
        context = req.environ['manila.context']
        body = {'unmanage': {'force': True}}

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.unmanage,
                          req,
                          server['id'],
                          body)

        get_mock.assert_called_once_with(context, server['id'])

    def _setup_unmanage_tests(self, status=constants.STATUS_ACTIVE):
        server = db_utils.create_share_server(
            id='fake_server_id', status=status)
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=server))
        return server

    @ddt.data(exception.ShareServerInUse, exception.PolicyNotAuthorized)
    def test_unmanage_share_server_badrequest(self, exc):
        req = fakes.HTTPRequest.blank('/unmanage')
        server = self._setup_unmanage_tests()
        context = req.environ['manila.context']
        error = mock.Mock(side_effect=exc('foobar'))
        mock_unmanage = self.mock_object(
            share_api.API, 'unmanage_share_server', error)
        body = {'unmanage': {'force': True}}

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.unmanage,
                          req,
                          'fake_server_id',
                          body)

        mock_unmanage.assert_called_once_with(context, server, force=True)
        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'unmanage_share_server')
