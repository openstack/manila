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

from unittest import mock

import ddt
import webob

from manila.api import common
from manila.api.v2 import share_servers
from manila.common import constants
from manila import context as ctx_api
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
                                      use_admin_context=True,
                                      version="2.49")
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
        req = fakes.HTTPRequest.blank('/reset_status', use_admin_context=True,
                                      version="2.49")
        body = {'reset_status': {'status': constants.STATUS_EXTENDING}}
        context = req.environ['manila.context']

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.share_server_reset_status,
            req, id='fake_server_id', body=body)
        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'reset_status')

    def test_share_server_reset_status_no_body(self):
        req = fakes.HTTPRequest.blank('/reset_status', use_admin_context=True,
                                      version="2.49")
        context = req.environ['manila.context']

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.share_server_reset_status,
            req, id='fake_server_id', body={})
        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'reset_status')

    def test_share_server_reset_status_no_status(self):
        req = fakes.HTTPRequest.blank('/reset_status', use_admin_context=True,
                                      version="2.49")
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
            'share_network_subnet_id': 'fake_subnet_id',
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
        share_net_subnet = [db_utils.create_share_network_subnet(
            share_network_id=share_network['id'])]
        share_server = db_utils.create_share_server(
            share_network_subnet_id=share_net_subnet[0]['id'],
            host='fake_host',
            identifier='fake_identifier',
            is_auto_deletable=False,
            share_network_subnets=share_net_subnet)

        self.mock_object(db_api, 'share_network_get', mock.Mock(
            return_value=share_network))
        self.mock_object(db_api, 'share_network_subnet_get_default_subnets',
                         mock.Mock(return_value=share_net_subnet))
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
                'updated_at': share_server['updated_at'],
                'status': constants.STATUS_ACTIVE,
                'host': 'fake_host',
                'share_network_id':
                    (share_server['share_network_subnets'][0]
                     ['share_network_id']),
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
                share_net_subnet[0]['share_network_id'])

        req_params = body['share_server']
        manage_share_server_mock.assert_called_once_with(
            context, req_params['identifier'], req_params['host'],
            share_net_subnet[0], req_params['driver_options'])

        self.assertEqual(expected_result, result)

        self.mock_policy_check.assert_called_once_with(
            context, self.resource_name, 'manage_share_server')

    def test_manage_invalid(self):
        req = fakes.HTTPRequest.blank('/manage_share_server',
                                      use_admin_context=True, version="2.49")
        share_network = db_utils.create_share_network()
        share_net_subnet = [db_utils.create_share_network_subnet(
            share_network_id=share_network['id'])]

        body = {
            'share_server': self._setup_manage_test_request_body()
        }
        body['share_server']['driver_options'] = []
        self.mock_object(utils, 'validate_service_host')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(db_api, 'share_network_subnet_get_default_subnets',
                         mock.Mock(return_value=share_net_subnet))

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.manage, req, body)

    def test_manage_forbidden(self):
        """Tests share server manage without admin privileges"""
        req = fakes.HTTPRequest.blank('/manage_share_server', version="2.49")
        error = mock.Mock(side_effect=exception.PolicyNotAuthorized(action=''))
        self.mock_object(share_api.API, 'manage_share_server', error)

        share_network = db_utils.create_share_network()
        share_net_subnet = [db_utils.create_share_network_subnet(
            share_network_id=share_network['id'])]

        self.mock_object(db_api, 'share_network_get', mock.Mock(
            return_value=share_network))
        self.mock_object(db_api, 'share_network_subnet_get_default_subnets',
                         mock.Mock(return_value=share_net_subnet))
        self.mock_object(utils, 'validate_service_host')

        body = {
            'share_server': self._setup_manage_test_request_body()
        }

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller.manage,
                          req,
                          body)

    def test__validate_manage_share_server_validate_no_body(self):
        """Tests share server manage"""
        req = fakes.HTTPRequest.blank('/manage', version="2.49")
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
        req = fakes.HTTPRequest.blank('/manage_share_server', version="2.49")
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
        req = fakes.HTTPRequest.blank('/manage', version="2.49")
        context = req.environ['manila.context']
        error = mock.Mock(side_effect=side_effect_exception)
        self.mock_object(utils, 'validate_service_host', error)

        share_network = db_utils.create_share_network()
        share_net_subnet = [db_utils.create_share_network_subnet(
            share_network_id=share_network['id'])]

        self.mock_object(db_api, 'share_network_get', mock.Mock(
            return_value=share_network))
        self.mock_object(db_api, 'share_network_subnet_get_default_subnets',
                         mock.Mock(return_value=share_net_subnet))
        self.mock_object(common, 'check_share_network_is_active',
                         mock.Mock(return_value=True))

        self.assertRaises(
            exception_to_raise, self.controller.manage, req,
            {'share_server': self._setup_manage_test_request_body()})

        common.check_share_network_is_active.assert_called_once_with(
            share_net_subnet[0]['share_network'])
        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'manage_share_server')

    def test__validate_manage_share_network_not_active(self):
        req = fakes.HTTPRequest.blank('/manage', version="2.49")
        context = req.environ['manila.context']

        share_network = db_utils.create_share_network()
        share_net_subnet = [db_utils.create_share_network_subnet(
            share_network_id=share_network['id'])]

        self.mock_object(db_api, 'share_network_get', mock.Mock(
            return_value=share_network))
        self.mock_object(db_api, 'share_network_subnet_get_default_subnets',
                         mock.Mock(return_value=share_net_subnet))
        self.mock_object(utils, 'validate_service_host')
        self.mock_object(common, 'check_share_network_is_active',
                         mock.Mock(side_effect=webob.exc.HTTPBadRequest()))

        self.assertRaises(
            webob.exc.HTTPBadRequest, self.controller.manage, req,
            {'share_server': self._setup_manage_test_request_body()})

        common.check_share_network_is_active.assert_called_once_with(
            share_net_subnet[0]['share_network'])
        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'manage_share_server')

    def test__validate_manage_share_server_share_network_not_found(self):
        req = fakes.HTTPRequest.blank('/manage', version="2.49")
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
        req = fakes.HTTPRequest.blank('/manage', version="2.49")
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
        req = fakes.HTTPRequest.blank('/manage', version="2.49")
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
    def test__validate_manage_share_server_error_subnet_not_found(
            self, body_contains_subnet):
        req = fakes.HTTPRequest.blank('/manage', version="2.51")
        context = req.environ['manila.context']
        share_network = db_utils.create_share_network()
        body = {'share_server': self._setup_manage_test_request_body()}
        share_net_subnet = [db_utils.create_share_network_subnet(
            share_network_id=share_network['id'])]
        body['share_server']['share_network_subnet_id'] = (
            share_net_subnet[0]['id'] if body_contains_subnet else None)

        self.mock_object(
            db_api, 'share_network_subnet_get_all_with_same_az',
            mock.Mock(side_effect=exception.ShareNetworkSubnetNotFound(
                share_network_subnet_id='fake')))
        self.mock_object(db_api, 'share_network_subnet_get_default_subnets',
                         mock.Mock(return_value=None))

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.manage,
                          req,
                          body)

        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'manage_share_server')
        if body_contains_subnet:
            (db_api.share_network_subnet_get_all_with_same_az.
             assert_called_once_with(context, share_net_subnet[0]['id']))
        else:
            (db_api.share_network_subnet_get_default_subnets
                .assert_called_once_with(
                    context, body['share_server']['share_network_id']))

    @ddt.data(True, False)
    def test__validate_manage_share_server_error_multiple_subnet(
            self, body_contains_subnet):
        req = fakes.HTTPRequest.blank('/manage', version="2.70")
        context = req.environ['manila.context']
        share_network = db_utils.create_share_network()
        body = {'share_server': self._setup_manage_test_request_body()}
        share_net_subnets = [
            db_utils.create_share_network_subnet(
                share_network_id=share_network['id']),
            db_utils.create_share_network_subnet(
                share_network_id=share_network['id'], id='fake_sns_id_2'),
        ]
        body['share_server']['share_network_subnet_id'] = (
            share_net_subnets[0]['id'] if body_contains_subnet else None)

        self.mock_object(
            db_api, 'share_network_subnet_get_all_with_same_az',
            mock.Mock(return_value=share_net_subnets))
        self.mock_object(db_api, 'share_network_subnet_get_default_subnets',
                         mock.Mock(return_value=share_net_subnets))

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.manage,
                          req,
                          body)

        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'manage_share_server')
        if body_contains_subnet:
            (db_api.share_network_subnet_get_all_with_same_az.
             assert_called_once_with(context, share_net_subnets[0]['id']))
        else:
            (db_api.share_network_subnet_get_default_subnets
                .assert_called_once_with(
                    context, body['share_server']['share_network_id']))

    @ddt.data(True, False)
    def test_unmanage(self, force):
        server = self._setup_unmanage_tests()
        req = fakes.HTTPRequest.blank('/unmanage', version="2.49")
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
        req = fakes.HTTPRequest.blank('/v2/share-servers/fake_server_id/',
                                      version="2.49")
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

    def test_unmanage_share_server_multiple_subnets_fail(self):
        """Tests unmanaging share servers"""
        server = self._setup_unmanage_tests(multiple_subnets=True)
        get_mock = self.mock_object(db_api, 'share_server_get',
                                    mock.Mock(return_value=server))
        req = fakes.HTTPRequest.blank('/unmanage_share_server', version="2.70")
        context = req.environ['manila.context']
        body = {'unmanage': {'force': True}}

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.unmanage,
                          req,
                          server['id'],
                          body)

        get_mock.assert_called_once_with(context, server['id'])

    @ddt.data(constants.STATUS_MANAGING, constants.STATUS_DELETING,
              constants.STATUS_CREATING, constants.STATUS_UNMANAGING)
    def test_unmanage_share_server_invalid_statuses(self, status):
        """Tests unmanaging share servers"""
        server = self._setup_unmanage_tests(status=status)
        get_mock = self.mock_object(db_api, 'share_server_get',
                                    mock.Mock(return_value=server))
        req = fakes.HTTPRequest.blank('/unmanage_share_server', version="2.49")
        context = req.environ['manila.context']
        body = {'unmanage': {'force': True}}

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.unmanage,
                          req,
                          server['id'],
                          body)

        get_mock.assert_called_once_with(context, server['id'])

    def _setup_unmanage_tests(self, status=constants.STATUS_ACTIVE,
                              multiple_subnets=False):
        share_network = db_utils.create_share_network()
        network_subnets = [db_utils.create_share_network_subnet(
            id='fake_sns_id', share_network_id=share_network['id'])]
        if multiple_subnets:
            share_network1 = db_utils.create_share_network()
            network_subnets.append(db_utils.create_share_network_subnet(
                share_network_id=share_network1['id'], id='fake_sns_id_2'))
        server = db_utils.create_share_server(
            id='fake_server_id', status=status,
            share_network_subnets=network_subnets)
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=server))
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(db_api, 'share_network_subnet_get',
                         mock.Mock(return_value=network_subnets))
        return server

    @ddt.data(exception.ShareServerInUse, exception.PolicyNotAuthorized)
    def test_unmanage_share_server_badrequest(self, exc):
        req = fakes.HTTPRequest.blank('/unmanage', version="2.49")
        server = self._setup_unmanage_tests()
        context = req.environ['manila.context']
        error = mock.Mock(side_effect=exc('foobar'))
        mock_unmanage = self.mock_object(
            share_api.API, 'unmanage_share_server', error)
        self.mock_object(common, 'check_share_network_is_active',
                         mock.Mock(return_value=True))
        body = {'unmanage': {'force': True}}

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.unmanage,
                          req,
                          'fake_server_id',
                          body)

        mock_unmanage.assert_called_once_with(context, server, force=True)
        db_api.share_network_get.assert_called()
        common.check_share_network_is_active.assert_called()
        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'unmanage_share_server')

    def test_unmanage_share_server_network_not_active(self):
        """Tests unmanaging share servers"""
        req = fakes.HTTPRequest.blank(
            '/v2/share-servers/fake_server_id/', version="2.63")
        context = req.environ['manila.context']
        share_server = db_utils.create_share_server()
        network_subnets = [db_utils.create_share_network_subnet()]
        share_server['share_network_subnets'] = network_subnets
        share_network = db_utils.create_share_network()
        get_mock = self.mock_object(
            db_api, 'share_server_get', mock.Mock(return_value=share_server))
        get_network_mock = self.mock_object(
            db_api, 'share_network_get',
            mock.Mock(return_value=share_network))
        is_active_mock = self.mock_object(
            common, 'check_share_network_is_active',
            mock.Mock(side_effect=webob.exc.HTTPBadRequest()))
        body = {'unmanage': {'force': True}}

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.unmanage,
                          req,
                          'fake_server_id',
                          body)
        get_mock.assert_called_once_with(context, 'fake_server_id')
        get_network_mock.assert_called_once_with(
            context,
            share_server['share_network_subnets'][0]['share_network_id'])
        is_active_mock.assert_called_once_with(share_network)

    def _get_server_migration_request(self, server_id, version='2.57'):
        req = fakes.HTTPRequest.blank(
            '/share-servers/%s/action' % server_id,
            use_admin_context=True, version=version)
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.api_version_request.experimental = True
        return req

    def test__share_server_migration_start(self):
        server = db_utils.create_share_server(id='fake_server_id',
                                              status=constants.STATUS_ACTIVE)
        share_network = db_utils.create_share_network()
        req = self._get_server_migration_request(server['id'])
        context = req.environ['manila.context']

        self.mock_object(db_api, 'share_network_get', mock.Mock(
            return_value=share_network))
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=server))
        self.mock_object(common, 'check_share_network_is_active',
                         mock.Mock(return_value=True))
        self.mock_object(share_api.API, 'share_server_migration_start')

        body = {
            'migration_start': {
                'host': 'fake_host',
                'preserve_snapshots': True,
                'writable': True,
                'nondisruptive': True,
                'new_share_network_id': 'fake_net_id',
            }
        }

        self.controller.share_server_migration_start(
            req, server['id'], body)

        db_api.share_server_get.assert_called_once_with(
            context, server['id'])
        share_api.API.share_server_migration_start.assert_called_once_with(
            context, server, 'fake_host', True, True, True,
            new_share_network=share_network)
        db_api.share_network_get.assert_called_once_with(
            context, 'fake_net_id')
        common.check_share_network_is_active.assert_called_once_with(
            share_network)

    @ddt.data({'api_exception': exception.ServiceIsDown(service='fake_srv'),
               'expected_exception': webob.exc.HTTPBadRequest},
              {'api_exception': exception.InvalidShareServer(
                  reason='fake_reason'),
               'expected_exception': webob.exc.HTTPConflict},
              {'api_exception': exception.InvalidInput(reason='fake_reason'),
               'expected_exception': webob.exc.HTTPBadRequest})
    @ddt.unpack
    def test__share_server_migration_start_conflict(self, api_exception,
                                                    expected_exception):
        share_network = db_utils.create_share_network()
        share_network_subnet = [db_utils.create_share_network_subnet(
            share_network_id=share_network['id'])]
        server = db_utils.create_share_server(
            id='fake_server_id', status=constants.STATUS_ACTIVE,
            share_network_subnet_id=share_network_subnet[0]['id'])
        server['share_network_subnets'] = share_network_subnet
        req = self._get_server_migration_request(server['id'])
        context = req.environ['manila.context']
        body = {
            'migration_start': {
                'host': 'fake_host',
                'preserve_snapshots': True,
                'writable': True,
                'nondisruptive': True
            }
        }
        self.mock_object(share_api.API, 'share_server_migration_start',
                         mock.Mock(side_effect=api_exception))
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=server))
        self.mock_object(common, 'check_share_network_is_active',
                         mock.Mock(return_value=True))
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))

        self.assertRaises(expected_exception,
                          self.controller.share_server_migration_start,
                          req, server['id'], body)

        db_api.share_server_get.assert_called_once_with(context,
                                                        server['id'])
        migration_start_params = body['migration_start']
        common.check_share_network_is_active.assert_called_once_with(
            share_network)
        db_api.share_network_get.assert_called_once_with(
            context, share_network['id'])
        share_api.API.share_server_migration_start.assert_called_once_with(
            context, server, migration_start_params['host'],
            migration_start_params['writable'],
            migration_start_params['nondisruptive'],
            migration_start_params['preserve_snapshots'],
            new_share_network=None)

    @ddt.data('host', 'body')
    def test__share_server_migration_start_missing_mandatory(self, param):
        server = db_utils.create_share_server(
            id='fake_server_id', status=constants.STATUS_ACTIVE)
        req = self._get_server_migration_request(server['id'])
        context = req.environ['manila.context']

        body = {
            'migration_start': {
                'host': 'fake_host',
                'preserve_metadata': True,
                'preserve_snapshots': True,
                'writable': True,
                'nondisruptive': True
            }
        }

        if param == 'body':
            body.pop('migration_start')
        else:
            body['migration_start'].pop(param)

        self.mock_object(share_api.API, 'share_server_migration_start')
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=server))

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            getattr(self.controller, 'share_server_migration_start'),
            req, server['id'], body)

        db_api.share_server_get.assert_called_once_with(context,
                                                        server['id'])

    @ddt.data('nondisruptive', 'writable', 'preserve_snapshots')
    def test__share_server_migration_start_non_boolean(self, param):
        server = db_utils.create_share_server(
            id='fake_server_id', status=constants.STATUS_ACTIVE)
        req = self._get_server_migration_request(server['id'])
        context = req.environ['manila.context']

        body = {
            'migration_start': {
                'host': 'fake_host',
                'preserve_snapshots': True,
                'writable': True,
                'nondisruptive': True
            }
        }

        body['migration_start'][param] = None

        self.mock_object(share_api.API, 'share_server_migration_start')
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=server))

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            getattr(self.controller, 'share_server_migration_start'),
            req, server['id'], body)

        db_api.share_server_get.assert_called_once_with(context,
                                                        server['id'])

    def test__share_server_migration_start_share_server_not_found(self):
        fake_id = 'fake_server_id'
        req = self._get_server_migration_request(fake_id)
        context = req.environ['manila.context']

        body = {'migration_start': {'host': 'fake_host'}}

        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(side_effect=exception.ShareServerNotFound(
                                   share_server_id=fake_id)))

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.share_server_migration_start,
                          req, fake_id, body)
        db_api.share_server_get.assert_called_once_with(context,
                                                        fake_id)

    def test__share_server_migration_start_new_share_network_not_found(self):
        server = db_utils.create_share_server(
            id='fake_server_id', status=constants.STATUS_ACTIVE)
        req = self._get_server_migration_request(server['id'])
        context = req.environ['manila.context']

        body = {
            'migration_start': {
                'host': 'fake_host',
                'preserve_metadata': True,
                'preserve_snapshots': True,
                'writable': True,
                'nondisruptive': True,
                'new_share_network_id': 'nonexistent'}}

        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(side_effect=exception.NotFound()))
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=server))

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.share_server_migration_start,
                          req, server['id'], body)
        db_api.share_network_get.assert_called_once_with(context,
                                                         'nonexistent')
        db_api.share_server_get.assert_called_once_with(context,
                                                        server['id'])

    def test__share_server_migration_start_host_with_pool(self):
        server = db_utils.create_share_server(id='fake_server_id',
                                              status=constants.STATUS_ACTIVE)
        req = self._get_server_migration_request(server['id'])

        body = {
            'migration_start': {
                'host': 'fake_host@fakebackend#pool',
                'preserve_snapshots': True,
                'writable': True,
                'nondisruptive': True,
                'new_share_network_id': 'fake_net_id',
            }
        }

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.share_server_migration_start,
                          req, server['id'], body)

    def test_share_server_migration_check_host_with_pool(self):
        server = db_utils.create_share_server(id='fake_server_id',
                                              status=constants.STATUS_ACTIVE)
        req = self._get_server_migration_request(server['id'])

        body = {
            'migration_start': {
                'host': 'fake_host@fakebackend#pool',
                'preserve_snapshots': True,
                'writable': True,
                'nondisruptive': True,
                'new_share_network_id': 'fake_net_id',
            }
        }

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.share_server_migration_check,
                          req, server['id'], body)

    @ddt.data(constants.TASK_STATE_MIGRATION_ERROR, None)
    def test_reset_task_state(self, task_state):
        server = db_utils.create_share_server(
            id='fake_server_id', status=constants.STATUS_ACTIVE)
        req = self._get_server_migration_request(server['id'])

        update = {'task_state': task_state}
        body = {'reset_task_state': update}

        self.mock_object(db_api, 'share_server_update')

        response = self.controller.share_server_reset_task_state(
            req, server['id'], body)

        self.assertEqual(202, response.status_int)

        db_api.share_server_update.assert_called_once_with(utils.IsAMatcher(
            ctx_api.RequestContext), server['id'], update)

    def test_reset_task_state_error_body(self):
        server = db_utils.create_share_server(
            id='fake_server_id', status=constants.STATUS_ACTIVE)
        req = self._get_server_migration_request(server['id'])

        update = {'error': 'error'}
        body = {'reset_task_state': update}

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.share_server_reset_task_state,
                          req, server['id'], body)

    def test_reset_task_state_error_invalid(self):
        server = db_utils.create_share_server(
            id='fake_server_id', status=constants.STATUS_ACTIVE)
        req = self._get_server_migration_request(server['id'])

        update = {'task_state': 'error'}
        body = {'reset_task_state': update}

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.share_server_reset_task_state,
                          req, server['id'], body)

    def test_reset_task_state_not_found(self):
        server = db_utils.create_share_server(
            id='fake_server_id', status=constants.STATUS_ACTIVE)
        req = self._get_server_migration_request(server['id'])

        update = {'task_state': constants.TASK_STATE_MIGRATION_ERROR}
        body = {'reset_task_state': update}

        self.mock_object(db_api, 'share_server_update',
                         mock.Mock(side_effect=exception.ShareServerNotFound(
                                   share_server_id='fake_server_id')))

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.share_server_reset_task_state,
                          req, server['id'], body)

        db_api.share_server_update.assert_called_once_with(utils.IsAMatcher(
            ctx_api.RequestContext), server['id'], update)

    def test_share_server_migration_complete(self):
        server = db_utils.create_share_server(
            id='fake_server_id', status=constants.STATUS_ACTIVE)
        req = self._get_server_migration_request(server['id'])
        context = req.environ['manila.context']

        body = {'migration_complete': None}
        api_return = {
            'destination_share_server_id': 'fake_destination_id'
        }

        self.mock_object(share_api.API, 'share_server_migration_complete',
                         mock.Mock(return_value=api_return))
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=server))

        result = self.controller.share_server_migration_complete(
            req, server['id'], body)

        self.assertEqual(api_return, result)
        share_api.API.share_server_migration_complete.assert_called_once_with(
            utils.IsAMatcher(ctx_api.RequestContext), server)
        db_api.share_server_get.assert_called_once_with(context,
                                                        server['id'])

    def test_share_server_migration_complete_not_found(self):
        fake_id = 'fake_server_id'
        req = self._get_server_migration_request(fake_id)
        context = req.environ['manila.context']

        body = {'migration_complete': None}

        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(side_effect=exception.ShareServerNotFound(
                                   share_server_id=fake_id)))
        self.mock_object(share_api.API, 'share_server_migration_complete')

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.share_server_migration_complete,
                          req, fake_id, body)
        db_api.share_server_get.assert_called_once_with(context,
                                                        fake_id)

    @ddt.data({'api_exception': exception.ServiceIsDown(service='fake_srv'),
               'expected_exception': webob.exc.HTTPBadRequest},
              {'api_exception': exception.InvalidShareServer(reason=""),
               'expected_exception': webob.exc.HTTPBadRequest})
    @ddt.unpack
    def test_share_server_migration_complete_exceptions(self, api_exception,
                                                        expected_exception):
        fake_id = 'fake_server_id'
        req = self._get_server_migration_request(fake_id)
        context = req.environ['manila.context']
        body = {'migration_complete': None}
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value='fake_share_server'))
        self.mock_object(share_api.API, 'share_server_migration_complete',
                         mock.Mock(side_effect=api_exception))

        self.assertRaises(expected_exception,
                          self.controller.share_server_migration_complete,
                          req, fake_id, body)

        db_api.share_server_get.assert_called_once_with(context,
                                                        fake_id)
        share_api.API.share_server_migration_complete.assert_called_once_with(
            context, 'fake_share_server')

    def test_share_server_migration_cancel(self):
        server = db_utils.create_share_server(
            id='fake_server_id', status=constants.STATUS_ACTIVE)
        req = self._get_server_migration_request(server['id'])
        context = req.environ['manila.context']

        body = {'migration_cancel': None}

        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=server))
        self.mock_object(share_api.API, 'share_server_migration_cancel')

        self.controller.share_server_migration_cancel(
            req, server['id'], body)

        share_api.API.share_server_migration_cancel.assert_called_once_with(
            utils.IsAMatcher(ctx_api.RequestContext), server)
        db_api.share_server_get.assert_called_once_with(context,
                                                        server['id'])

    def test_share_server_migration_cancel_not_found(self):
        fake_id = 'fake_server_id'
        req = self._get_server_migration_request(fake_id)
        context = req.environ['manila.context']

        body = {'migration_cancel': None}

        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(side_effect=exception.ShareServerNotFound(
                                   share_server_id=fake_id)))
        self.mock_object(share_api.API, 'share_server_migration_cancel')

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.share_server_migration_cancel,
                          req, fake_id, body)
        db_api.share_server_get.assert_called_once_with(context,
                                                        fake_id)

    @ddt.data({'api_exception': exception.ServiceIsDown(service='fake_srv'),
               'expected_exception': webob.exc.HTTPBadRequest},
              {'api_exception': exception.InvalidShareServer(reason=""),
               'expected_exception': webob.exc.HTTPBadRequest})
    @ddt.unpack
    def test_share_server_migration_cancel_exceptions(self, api_exception,
                                                      expected_exception):
        fake_id = 'fake_server_id'
        req = self._get_server_migration_request(fake_id)
        context = req.environ['manila.context']
        body = {'migration_complete': None}
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value='fake_share_server'))
        self.mock_object(share_api.API, 'share_server_migration_cancel',
                         mock.Mock(side_effect=api_exception))

        self.assertRaises(expected_exception,
                          self.controller.share_server_migration_cancel,
                          req, fake_id, body)

        db_api.share_server_get.assert_called_once_with(context,
                                                        fake_id)
        share_api.API.share_server_migration_cancel.assert_called_once_with(
            context, 'fake_share_server')

    def test_share_server_migration_get_progress(self):
        server = db_utils.create_share_server(
            id='fake_server_id',
            status=constants.STATUS_ACTIVE,
            task_state=constants.TASK_STATE_MIGRATION_SUCCESS)
        req = self._get_server_migration_request(server['id'])

        body = {'migration_get_progress': None}
        expected = {
            'total_progress': 'fake',
            'task_state': constants.TASK_STATE_MIGRATION_SUCCESS,
            'destination_share_server_id': 'fake_destination_server_id'
        }

        self.mock_object(share_api.API, 'share_server_migration_get_progress',
                         mock.Mock(return_value=expected))

        response = self.controller.share_server_migration_get_progress(
            req, server['id'], body)
        self.assertEqual(expected, response)
        (share_api.API.share_server_migration_get_progress.
            assert_called_once_with(utils.IsAMatcher(ctx_api.RequestContext),
                                    server['id']))

    @ddt.data({'api_exception': exception.ServiceIsDown(service='fake_srv'),
               'expected_exception': webob.exc.HTTPConflict},
              {'api_exception': exception.InvalidShareServer(reason=""),
               'expected_exception': webob.exc.HTTPBadRequest})
    @ddt.unpack
    def test_share_server_migration_get_progress_exceptions(
            self, api_exception, expected_exception):
        fake_id = 'fake_server_id'
        req = self._get_server_migration_request(fake_id)
        context = req.environ['manila.context']
        body = {'migration_complete': None}
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value='fake_share_server'))
        mock_get_progress = self.mock_object(
            share_api.API, 'share_server_migration_get_progress',
            mock.Mock(side_effect=api_exception))

        self.assertRaises(expected_exception,
                          self.controller.share_server_migration_get_progress,
                          req, fake_id, body)

        mock_get_progress.assert_called_once_with(context, fake_id)

    def test_share_server_migration_check(self):
        fake_id = 'fake_server_id'
        fake_share_server = db_utils.create_share_server(id=fake_id)
        fake_share_network = db_utils.create_share_network()
        req = self._get_server_migration_request(fake_id)
        context = req.environ['manila.context']
        requested_writable = False
        requested_nondisruptive = False
        requested_preserve_snapshots = False
        fake_host = 'fakehost@fakebackend'
        body = {
            'migration_check': {
                'writable': requested_writable,
                'nondisruptive': requested_nondisruptive,
                'preserve_snapshots': requested_preserve_snapshots,
                'new_share_network_id': fake_share_network['id'],
                'host': fake_host
            }
        }
        driver_result = {
            'compatible': False,
            'writable': False,
            'nondisruptive': True,
            'preserve_snapshots': False,
            'share_network_id': 'fake_network_uuid',
            'migration_cancel': False,
            'migration_get_progress': False,
        }

        mock_server_get = self.mock_object(
            db_api, 'share_server_get',
            mock.Mock(return_value=fake_share_server))
        mock_network_get = self.mock_object(
            db_api, 'share_network_get',
            mock.Mock(return_value=fake_share_network))
        self.mock_object(common, 'check_share_network_is_active',
                         mock.Mock(return_value=True))
        mock_migration_check = self.mock_object(
            share_api.API, 'share_server_migration_check',
            mock.Mock(return_value=driver_result))

        result = self.controller.share_server_migration_check(
            req, fake_id, body)

        expected_result_keys = ['compatible', 'requested_capabilities',
                                'supported_capabilities']
        [self.assertIn(key, result) for key in expected_result_keys]
        mock_server_get.assert_called_once_with(
            context, fake_share_server['id'])
        mock_network_get.assert_called_once_with(
            context, fake_share_network['id'])
        common.check_share_network_is_active.assert_called_once_with(
            fake_share_network)
        mock_migration_check.assert_called_once_with(
            context, fake_share_server, fake_host, requested_writable,
            requested_nondisruptive, requested_preserve_snapshots,
            new_share_network=fake_share_network)

    @ddt.data(
        (webob.exc.HTTPNotFound, True, False, {'migration_check': {}}),
        (webob.exc.HTTPBadRequest, False, True,
         {'migration_check': {'new_share_network_id': 'fake_id'}}),
        (webob.exc.HTTPBadRequest, False, False, None)
    )
    @ddt.unpack
    def test_share_server_migration_check_exception(
            self, exception_to_raise, raise_server_get_exception,
            raise_network_get_action, body):
        req = self._get_server_migration_request('fake_id')
        context = req.environ['manila.context']
        if body:
            body['migration_check']['writable'] = False
            body['migration_check']['nondisruptive'] = False
            body['migration_check']['preserve_snapshots'] = False
            body['migration_check']['host'] = 'fakehost@fakebackend'
        else:
            body = {}

        server_get = mock.Mock()
        network_get = mock.Mock()
        if raise_server_get_exception:
            server_get = mock.Mock(
                side_effect=exception.ShareServerNotFound(
                    share_server_id='fake'))
        if raise_network_get_action:
            network_get = mock.Mock(
                side_effect=exception.ShareNetworkNotFound(
                    share_network_id='fake'))

        mock_server_get = self.mock_object(
            db_api, 'share_server_get', server_get)

        mock_network_get = self.mock_object(
            db_api, 'share_network_get', network_get)

        self.assertRaises(
            exception_to_raise,
            self.controller.share_server_migration_check,
            req, 'fake_id', body
        )
        mock_server_get.assert_called_once_with(
            context, 'fake_id')
        if raise_network_get_action:
            mock_network_get.assert_called_once_with(context, 'fake_id')

    @ddt.data(
        {'api_exception': exception.ServiceIsDown(service='fake_srv'),
         'expected_exception': webob.exc.HTTPBadRequest},
        {'api_exception': exception.InvalidShareServer(reason=""),
         'expected_exception': webob.exc.HTTPBadRequest})
    @ddt.unpack
    def test_share_server_migration_complete_exceptions_from_api(
            self, api_exception, expected_exception):
        req = self._get_server_migration_request('fake_id')
        context = req.environ['manila.context']
        body = {
            'migration_check': {
                'writable': False,
                'nondisruptive': False,
                'preserve_snapshots': True,
                'host': 'fakehost@fakebackend',
            }
        }

        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value='fake_share_server'))

        self.mock_object(share_api.API, 'share_server_migration_complete',
                         mock.Mock(side_effect=api_exception))

        self.assertRaises(
            expected_exception,
            self.controller.share_server_migration_complete,
            req, 'fake_id', body
        )

        db_api.share_server_get.assert_called_once_with(context,
                                                        'fake_id')
        share_api.API.share_server_migration_complete.assert_called_once_with(
            context, 'fake_share_server', )
