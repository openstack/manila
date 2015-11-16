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
from oslo_config import cfg
from oslo_serialization import jsonutils
import six
import webob
from webob import exc as webob_exc

from manila.api.v1 import share_instances
from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils

CONF = cfg.CONF


@ddt.ddt
class ShareInstancesAPITest(test.TestCase):
    """Share instances API Test."""

    def setUp(self):
        super(self.__class__, self).setUp()
        self.controller = share_instances.ShareInstancesController()
        self.resource_name = self.controller.resource_name
        self.context = context.RequestContext('admin', 'fake', True)
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.member_context = context.RequestContext('fake', 'fake')

    def _get_context(self, role):
        return getattr(self, '%s_context' % role)

    def _setup_share_instance_data(self, instance=None):
        if instance is None:
            instance = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                             size='1').instance
        req = webob.Request.blank(
            '/v2/fake/share_instances/%s/action' % instance['id'])
        return instance, req

    def _get_request(self, uri, context=None):
        if context is None:
            context = self.admin_context
        req = fakes.HTTPRequest.blank('/shares', version="2.3")
        req.environ['manila.context'] = context
        return req

    def _validate_ids_in_share_instances_list(self, expected, actual):
        self.assertEqual(len(expected), len(actual))
        self.assertEqual([i['id'] for i in expected],
                         [i['id'] for i in actual])

    def test_index(self):
        req = self._get_request('/share_instances')
        req_context = req.environ['manila.context']
        share_instances_count = 3
        test_instances = [
            db_utils.create_share(size=s + 1).instance
            for s in range(0, share_instances_count)
        ]

        actual_result = self.controller.index(req)

        self._validate_ids_in_share_instances_list(
            test_instances, actual_result['share_instances'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'index')

    def test_show(self):
        test_instance = db_utils.create_share(size=1).instance
        id = test_instance['id']

        actual_result = self.controller.show(self._get_request('fake'), id)

        self.assertEqual(id, actual_result['share_instance']['id'])
        self.mock_policy_check.assert_called_once_with(
            self.admin_context, self.resource_name, 'show')

    def test_get_share_instances(self):
        test_share = db_utils.create_share(size=1)
        id = test_share['id']
        req = self._get_request('fake')
        req_context = req.environ['manila.context']
        share_policy_check_call = mock.call(
            req_context, 'share', 'get', mock.ANY)
        get_instances_policy_check_call = mock.call(
            req_context, 'share_instance', 'index')

        actual_result = self.controller.get_share_instances(req, id)

        self._validate_ids_in_share_instances_list(
            [test_share.instance],
            actual_result['share_instances']
        )
        self.mock_policy_check.assert_has_calls([
            get_instances_policy_check_call, share_policy_check_call])

    @ddt.data('show', 'get_share_instances')
    def test_not_found(self, target_method_name):
        method = getattr(self.controller, target_method_name)
        action = (target_method_name if target_method_name == 'show' else
                  'index')
        self.assertRaises(webob_exc.HTTPNotFound, method,
                          self._get_request('fake'), 'fake')
        self.mock_policy_check.assert_called_once_with(
            self.admin_context, self.resource_name, action)

    @ddt.data(('show', 2), ('get_share_instances', 2), ('index', 1))
    @ddt.unpack
    def test_access(self, target_method_name, args_count):
        user_context = context.RequestContext('fake', 'fake')
        req = self._get_request('fake', user_context)
        policy_exception = exception.PolicyNotAuthorized(
            action=target_method_name)
        target_method = getattr(self.controller, target_method_name)
        args = [i for i in range(1, args_count)]

        with mock.patch.object(policy, 'check_policy', mock.Mock(
                side_effect=policy_exception)):
            self.assertRaises(
                webob_exc.HTTPForbidden, target_method, req, *args)

    def _reset_status(self, ctxt, model, req, db_access_method,
                      valid_code, valid_status=None, body=None):
        if body is None:
            body = {'os-reset_status': {'status': constants.STATUS_ERROR}}
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.body = six.b(jsonutils.dumps(body))
        req.environ['manila.context'] = ctxt

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        # validate response code and model status
        self.assertEqual(valid_code, resp.status_int)

        if valid_code == 404:
            self.assertRaises(exception.NotFound,
                              db_access_method,
                              ctxt,
                              model['id'])
        else:
            actual_model = db_access_method(ctxt, model['id'])
            self.assertEqual(valid_status, actual_model['status'])

    @ddt.data(*fakes.fixture_reset_status_with_different_roles)
    @ddt.unpack
    def test_share_instances_reset_status_with_different_roles(self, role,
                                                               valid_code,
                                                               valid_status):
        ctxt = self._get_context(role)
        instance, req = self._setup_share_instance_data()
        req.headers['X-Openstack-Manila-Api-Version'] = '2.3'

        self._reset_status(ctxt, instance, req, db.share_instance_get,
                           valid_code, valid_status)

    @ddt.data(*fakes.fixture_invalid_reset_status_body)
    def test_share_instance_invalid_reset_status_body(self, body):
        instance, req = self._setup_share_instance_data()
        req.headers['X-Openstack-Manila-Api-Version'] = '2.3'

        self._reset_status(self.admin_context, instance, req,
                           db.share_instance_get, 400,
                           constants.STATUS_AVAILABLE, body)

    def _force_delete(self, ctxt, model, req, db_access_method, valid_code,
                      check_model_in_db=False):
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.headers['X-Openstack-Manila-Api-Version'] = '2.3'
        req.body = six.b(jsonutils.dumps({'os-force_delete': {}}))
        req.environ['manila.context'] = ctxt

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        # validate response
        self.assertEqual(valid_code, resp.status_int)

        if valid_code == 202 and check_model_in_db:
            self.assertRaises(exception.NotFound,
                              db_access_method,
                              ctxt,
                              model['id'])

    @ddt.data(*fakes.fixture_force_delete_with_different_roles)
    @ddt.unpack
    def test_instance_force_delete_with_different_roles(self, role, resp_code):
        instance, req = self._setup_share_instance_data()
        ctxt = self._get_context(role)

        self._force_delete(ctxt, instance, req, db.share_instance_get,
                           resp_code)

    def test_instance_force_delete_missing(self):
        instance, req = self._setup_share_instance_data(
            instance={'id': 'fake'})
        ctxt = self._get_context('admin')

        self._force_delete(ctxt, instance, req, db.share_instance_get, 404)
