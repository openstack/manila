# Copyright 2016 Huawei Inc.
# All Rights Reserved.
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
from webob import exc

from manila.api.v2 import share_snapshot_instances
from manila.common import constants
from manila import context
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils
from manila.tests import fake_share

CONF = cfg.CONF


@ddt.ddt
class ShareSnapshotInstancesApiTest(test.TestCase):
    """Share snapshot instance Api Test."""
    def setUp(self):
        super(ShareSnapshotInstancesApiTest, self).setUp()
        self.controller = (share_snapshot_instances.
                           ShareSnapshotInstancesController())
        self.resource_name = self.controller.resource_name
        self.api_version = '2.19'
        self.snapshot_instances_req = fakes.HTTPRequest.blank(
            '/snapshot-instances', version=self.api_version)
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.member_context = context.RequestContext('fake', 'fake')
        self.snapshot_instances_req.environ['manila.context'] = (
            self.admin_context)
        self.snapshot_instances_req_admin = fakes.HTTPRequest.blank(
            '/snapshot-instances', version=self.api_version,
            use_admin_context=True)
        self.mock_policy_check = self.mock_object(policy, 'check_policy')

    def _get_fake_snapshot_instance(self, summary=False, **values):
        snapshot_instance = fake_share.fake_snapshot_instance(
            as_primitive=True)
        expected_keys = {
            'id',
            'snapshot_id',
            'status',
        }
        expected_snapshot_instance = {key: snapshot_instance[key] for key
                                      in snapshot_instance if key
                                      in expected_keys}

        if not summary:
            expected_snapshot_instance['share_id'] = (
                snapshot_instance.get('share_instance').get('share_id'))
            expected_snapshot_instance.update({
                'created_at': snapshot_instance.get('created_at'),
                'updated_at': snapshot_instance.get('updated_at'),
                'progress': snapshot_instance.get('progress'),
                'provider_location': snapshot_instance.get(
                    'provider_location'),
                'share_instance_id': snapshot_instance.get(
                    'share_instance_id'),
            })

        return snapshot_instance, expected_snapshot_instance

    def _setup_snapshot_instance_data(self, instance=None):
        if instance is None:
            share_instance = db_utils.create_share_instance(
                status=constants.STATUS_AVAILABLE,
                share_id='fake_share_id_1')
            instance = db_utils.create_snapshot_instance(
                'fake_snapshot_id_1',
                status=constants.STATUS_AVAILABLE,
                share_instance_id=share_instance['id'])

        path = '/v2/fake/snapshot-instances/%s/action' % instance['id']
        req = fakes.HTTPRequest.blank(path, version=self.api_version,
                                      script_name=path)
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.headers['X-Openstack-Manila-Api-Version'] = self.api_version

        return instance, req

    def _get_context(self, role):
        return getattr(self, '%s_context' % role)

    @ddt.data(None, 'FAKE_SNAPSHOT_ID')
    def test_list_snapshot_instances_summary(self, snapshot_id):
        snapshot_instance, expected_snapshot_instance = (
            self._get_fake_snapshot_instance(summary=True))
        self.mock_object(share_snapshot_instances.db,
                         'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=[snapshot_instance]))

        url = '/snapshot-instances'
        if snapshot_id:
            url += '?snapshot_id=%s' % snapshot_id

        req = fakes.HTTPRequest.blank(url, version=self.api_version)
        req_context = req.environ['manila.context']
        res_dict = self.controller.index(req)

        self.assertEqual([expected_snapshot_instance],
                         res_dict['snapshot_instances'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'index')

    def test_list_snapshot_instances_detail(self):
        snapshot_instance, expected_snapshot_instance = (
            self._get_fake_snapshot_instance())
        self.mock_object(share_snapshot_instances.db,
                         'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=[snapshot_instance]))

        res_dict = self.controller.detail(self.snapshot_instances_req)

        self.assertEqual([expected_snapshot_instance],
                         res_dict['snapshot_instances'])
        self.mock_policy_check.assert_called_once_with(
            self.admin_context, self.resource_name, 'detail')

    def test_list_snapshot_instances_detail_invalid_snapshot(self):
        self.mock_object(share_snapshot_instances.db,
                         'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=[]))

        req = self.snapshot_instances_req
        req.GET['snapshot_id'] = 'FAKE_SNAPSHOT_ID'

        res_dict = self.controller.detail(req)

        self.assertEqual([], res_dict['snapshot_instances'])
        self.mock_policy_check.assert_called_once_with(
            self.admin_context, self.resource_name, 'detail')

    def test_show(self):
        snapshot_instance, expected_snapshot_instance = (
            self._get_fake_snapshot_instance())
        self.mock_object(
            share_snapshot_instances.db, 'share_snapshot_instance_get',
            mock.Mock(return_value=snapshot_instance))

        res_dict = self.controller.show(self.snapshot_instances_req,
                                        snapshot_instance.get('id'))

        self.assertEqual(expected_snapshot_instance,
                         res_dict['snapshot_instance'])
        self.mock_policy_check.assert_called_once_with(
            self.admin_context, self.resource_name, 'show')

    def test_show_snapshot_instance_not_found(self):
        mock__view_builder_call = self.mock_object(
            share_snapshot_instances.instance_view.ViewBuilder, 'detail')
        fake_exception = exception.ShareSnapshotInstanceNotFound(
            instance_id='FAKE_SNAPSHOT_INSTANCE_ID')
        self.mock_object(share_snapshot_instances.db,
                         'share_snapshot_instance_get',
                         mock.Mock(side_effect=fake_exception))

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.show,
                          self.snapshot_instances_req,
                          'FAKE_SNAPSHOT_INSTANCE_ID')
        self.assertFalse(mock__view_builder_call.called)

    @ddt.data('index', 'detail', 'show', 'reset_status')
    def test_policy_not_authorized(self, method_name):

        method = getattr(self.controller, method_name)
        if method_name in ('index', 'detail'):
            arguments = {}
        else:
            arguments = {
                'id': 'FAKE_SNAPSHOT_ID',
                'body': {'FAKE_KEY': 'FAKE_VAL'},
            }

        noauthexc = exception.PolicyNotAuthorized(action=six.text_type(method))

        with mock.patch.object(
                policy, 'check_policy', mock.Mock(side_effect=noauthexc)):

            self.assertRaises(
                exc.HTTPForbidden, method, self.snapshot_instances_req,
                **arguments)

    @ddt.data('index', 'show', 'detail', 'reset_status')
    def test_upsupported_microversion(self, method_name):
        unsupported_microversions = ('1.0', '2.18')
        method = getattr(self.controller, method_name)
        arguments = {
            'id': 'FAKE_SNAPSHOT_ID',
        }
        if method_name in ('index'):
            arguments.clear()

        for microversion in unsupported_microversions:
            req = fakes.HTTPRequest.blank(
                '/snapshot-instances', version=microversion)
            self.assertRaises(exception.VersionNotFoundForAPIMethod,
                              method, req, **arguments)

    def _reset_status(self, context, instance, req,
                      valid_code=202, valid_status=None, body=None):
        if body is None:
            body = {'reset_status': {'status': constants.STATUS_ERROR}}

        req.body = six.b(jsonutils.dumps(body))
        req.environ['manila.context'] = context

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        # validate response code and model status
        self.assertEqual(valid_code, resp.status_int)

        if valid_code == 404:
            self.assertRaises(exception.ShareSnapshotInstanceNotFound,
                              (share_snapshot_instances.db.
                               share_snapshot_instance_get),
                              context,
                              instance['id'])
        else:
            actual_instance = (
                share_snapshot_instances.db.share_snapshot_instance_get(
                    context, instance['id']))
            self.assertEqual(valid_status, actual_instance['status'])

    @ddt.data(*fakes.fixture_reset_status_with_different_roles)
    @ddt.unpack
    def test_reset_status_with_different_roles(self, role, valid_code,
                                               valid_status, version):
        instance, action_req = self._setup_snapshot_instance_data()
        ctxt = self._get_context(role)
        self._reset_status(ctxt, instance, action_req,
                           valid_code=valid_code,
                           valid_status=valid_status)
