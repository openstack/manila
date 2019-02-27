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
from webob import exc as webob_exc

from manila.api.openstack import api_version_request
from manila.api.v2 import share_instances
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
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.member_context = context.RequestContext('fake', 'fake')

    def _get_context(self, role):
        return getattr(self, '%s_context' % role)

    def _setup_share_instance_data(self, instance=None, version='2.7'):
        if instance is None:
            instance = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                             size='1').instance
        path = '/v2/fake/share_instances/%s/action' % instance['id']
        req = fakes.HTTPRequest.blank(path, script_name=path, version=version)
        return instance, req

    def _get_request(self, uri, context=None, version="2.3"):
        if context is None:
            context = self.admin_context
        req = fakes.HTTPRequest.blank(uri, version=version)
        req.environ['manila.context'] = context
        return req

    def _validate_ids_in_share_instances_list(self, expected, actual):
        self.assertEqual(len(expected), len(actual))
        self.assertEqual([i['id'] for i in expected],
                         [i['id'] for i in actual])

    @ddt.data("2.3", "2.34", "2.35")
    def test_index(self, version):
        url = '/share_instances'
        if (api_version_request.APIVersionRequest(version) >=
                api_version_request.APIVersionRequest('2.35')):
            url += "?export_location_path=/admin/export/location"
        req = self._get_request(url, version=version)
        req_context = req.environ['manila.context']
        share_instances_count = 3
        test_instances = [
            db_utils.create_share(size=s + 1).instance
            for s in range(0, share_instances_count)
        ]

        db.share_export_locations_update(
            self.admin_context, test_instances[0]['id'],
            '/admin/export/location', False)

        actual_result = self.controller.index(req)

        if (api_version_request.APIVersionRequest(version) >=
                api_version_request.APIVersionRequest('2.35')):
            test_instances = test_instances[:1]
        self._validate_ids_in_share_instances_list(
            test_instances, actual_result['share_instances'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'index')

    def test_index_with_limit(self):
        req = self._get_request('/share_instances')
        req_context = req.environ['manila.context']
        share_instances_count = 3
        test_instances = [
            db_utils.create_share(size=s + 1).instance
            for s in range(0, share_instances_count)
        ]
        expect_links = [
            {
                'href': (
                    'http://localhost/v1/fake/share_instances?'
                    'limit=3&marker=%s' % test_instances[2]['id']),
                'rel': 'next',
            }
        ]

        url = 'share_instances?limit=3'
        req = self._get_request(url)
        actual_result = self.controller.index(req)

        self._validate_ids_in_share_instances_list(
            test_instances, actual_result['share_instances'])
        self.assertEqual(expect_links, actual_result['share_instances_links'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'index')

    def test_show(self):
        test_instance = db_utils.create_share(size=1).instance
        id = test_instance['id']

        actual_result = self.controller.show(self._get_request('fake'), id)

        self.assertEqual(id, actual_result['share_instance']['id'])
        self.mock_policy_check.assert_called_once_with(
            self.admin_context, self.resource_name, 'show')

    def test_show_with_export_locations(self):
        test_instance = db_utils.create_share(size=1).instance
        req = self._get_request('fake', version="2.8")
        id = test_instance['id']

        actual_result = self.controller.show(req, id)

        self.assertEqual(id, actual_result['share_instance']['id'])
        self.assertIn("export_location", actual_result['share_instance'])
        self.assertIn("export_locations", actual_result['share_instance'])
        self.mock_policy_check.assert_called_once_with(
            self.admin_context, self.resource_name, 'show')

    def test_show_without_export_locations(self):
        test_instance = db_utils.create_share(size=1).instance
        req = self._get_request('fake', version="2.9")
        id = test_instance['id']

        actual_result = self.controller.show(req, id)

        self.assertEqual(id, actual_result['share_instance']['id'])
        self.assertNotIn("export_location", actual_result['share_instance'])
        self.assertNotIn("export_locations", actual_result['share_instance'])
        self.mock_policy_check.assert_called_once_with(
            self.admin_context, self.resource_name, 'show')

    def test_show_with_replica_state(self):
        test_instance = db_utils.create_share(size=1).instance
        req = self._get_request('fake', version="2.11")
        id = test_instance['id']

        actual_result = self.controller.show(req, id)

        self.assertEqual(id, actual_result['share_instance']['id'])
        self.assertIn("replica_state", actual_result['share_instance'])
        self.mock_policy_check.assert_called_once_with(
            self.admin_context, self.resource_name, 'show')

    @ddt.data("2.3", "2.8", "2.9", "2.11")
    def test_get_share_instances(self, version):
        test_share = db_utils.create_share(size=1)
        id = test_share['id']
        req = self._get_request('fake', version=version)
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
        self.assertEqual(1, len(actual_result.get("share_instances", 0)))
        for instance in actual_result["share_instances"]:
            if (api_version_request.APIVersionRequest(version) >
                    api_version_request.APIVersionRequest("2.8")):
                assert_method = self.assertNotIn
            else:
                assert_method = self.assertIn
            assert_method("export_location", instance)
            assert_method("export_locations", instance)
            if (api_version_request.APIVersionRequest(version) >
                    api_version_request.APIVersionRequest("2.10")):
                self.assertIn("replica_state", instance)
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
                      valid_code, valid_status=None, body=None, version='2.7'):
        if float(version) > 2.6:
            action_name = 'reset_status'
        else:
            action_name = 'os-reset_status'
        if body is None:
            body = {action_name: {'status': constants.STATUS_ERROR}}
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.headers['X-Openstack-Manila-Api-Version'] = version
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
                                                               valid_status,
                                                               version):
        ctxt = self._get_context(role)
        instance, req = self._setup_share_instance_data(version=version)

        self._reset_status(ctxt, instance, req, db.share_instance_get,
                           valid_code, valid_status, version=version)

    @ddt.data(*fakes.fixture_valid_reset_status_body)
    @ddt.unpack
    def test_share_instance_reset_status(self, body, version):
        instance, req = self._setup_share_instance_data()
        req.headers['X-Openstack-Manila-Api-Version'] = version

        if float(version) > 2.6:
            state = body['reset_status']['status']
        else:
            state = body['os-reset_status']['status']
        self._reset_status(self.admin_context, instance, req,
                           db.share_instance_get, 202,
                           state, body, version=version)

    @ddt.data(
        ({'os-reset_status': {'x-status': 'bad'}}, '2.6'),
        ({'os-reset_status': {'status': 'invalid'}}, '2.6'),
        ({'reset_status': {'x-status': 'bad'}}, '2.7'),
        ({'reset_status': {'status': 'invalid'}}, '2.7'),
    )
    @ddt.unpack
    def test_share_instance_invalid_reset_status_body(self, body, version):
        instance, req = self._setup_share_instance_data()
        req.headers['X-Openstack-Manila-Api-Version'] = version

        self._reset_status(self.admin_context, instance, req,
                           db.share_instance_get, 400,
                           constants.STATUS_AVAILABLE, body, version=version)

    def _force_delete(self, ctxt, model, req, db_access_method, valid_code,
                      check_model_in_db=False, version='2.7'):
        if float(version) > 2.6:
            action_name = 'force_delete'
        else:
            action_name = 'os-force_delete'
        body = {action_name: {'status': constants.STATUS_ERROR}}
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.headers['X-Openstack-Manila-Api-Version'] = version
        req.body = six.b(jsonutils.dumps(body))
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
    def test_instance_force_delete_with_different_roles(self, role, resp_code,
                                                        version):
        instance, req = self._setup_share_instance_data(version=version)
        ctxt = self._get_context(role)

        self._force_delete(ctxt, instance, req, db.share_instance_get,
                           resp_code, version=version)

    def test_instance_force_delete_missing(self):
        instance, req = self._setup_share_instance_data(
            instance={'id': 'fake'})
        ctxt = self._get_context('admin')

        self._force_delete(ctxt, instance, req, db.share_instance_get, 404)
