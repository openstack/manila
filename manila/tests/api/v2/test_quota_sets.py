# Copyright 2013 OpenStack Foundation
# Copyright (c) 2015 Mirantis inc.
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

"""
Tests for manila.api.v1.quota_sets.py
"""

import copy

import ddt
import mock
from oslo_config import cfg
import webob.exc
import webob.response

from manila.api.v2 import quota_sets
from manila import context
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila import utils

CONF = cfg.CONF

REQ = mock.MagicMock()
REQ.environ = {'manila.context': context.get_admin_context()}
REQ.environ['manila.context'].is_admin = True
REQ.environ['manila.context'].auth_token = 'foo_auth_token'
REQ.environ['manila.context'].project_id = 'foo_project_id'

REQ_WITH_USER = copy.deepcopy(REQ)
REQ_WITH_USER.environ['manila.context'].user_id = 'foo_user_id'
REQ_WITH_USER.environ['QUERY_STRING'] = 'user_id=foo_user_id'

REQ_MEMBER = copy.deepcopy(REQ)
REQ_MEMBER.environ['manila.context'].is_admin = False


@ddt.ddt
class QuotaSetsControllerTest(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.controller = quota_sets.QuotaSetsController()
        self.resource_name = self.controller.resource_name
        self.project_id = 'foo_project_id'
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))

    @ddt.data(
        {"shares": 3, "snapshots": 4, "gigabytes": 5,
         "snapshot_gigabytes": 6, "share_networks": 7},
        {"shares": -1, "snapshots": -1, "gigabytes": -1,
         "snapshot_gigabytes": -1, "share_networks": -1},
        {"shares": 13},
        {"snapshots": 24},
        {"gigabytes": 7},
        {"snapshot_gigabytes": 10001},
        {"share_networks": 12345},
    )
    def test_defaults(self, quotas):
        for k, v in quotas.items():
            CONF.set_default('quota_' + k, v)
        expected = {
            'quota_set': {
                'id': self.project_id,
                'shares': quotas.get('shares', 50),
                'gigabytes': quotas.get('gigabytes', 1000),
                'snapshots': quotas.get('snapshots', 50),
                'snapshot_gigabytes': quotas.get('snapshot_gigabytes', 1000),
                'share_networks': quotas.get('share_networks', 10),
            }
        }

        result = self.controller.defaults(REQ, self.project_id)

        self.assertEqual(expected, result)
        self.mock_policy_check.assert_called_once_with(
            REQ.environ['manila.context'], self.resource_name, 'show')

    @ddt.data(
        ('os-', '1.0', quota_sets.QuotaSetsControllerLegacy, 'defaults'),
        ('os-', '2.6', quota_sets.QuotaSetsControllerLegacy, 'defaults'),
        ('', '2.7', quota_sets.QuotaSetsController, 'defaults'),
        ('os-', '1.0', quota_sets.QuotaSetsControllerLegacy, 'show'),
        ('os-', '2.6', quota_sets.QuotaSetsControllerLegacy, 'show'),
        ('', '2.7', quota_sets.QuotaSetsController, 'show'),
    )
    @ddt.unpack
    def test_get_quotas_with_different_api_versions(self, url, version,
                                                    controller, method_name):
        expected = {
            'quota_set': {
                'id': self.project_id,
                'shares': 50,
                'gigabytes': 1000,
                'snapshots': 50,
                'snapshot_gigabytes': 1000,
                'share_networks': 10,
            }
        }
        req = fakes.HTTPRequest.blank(
            '/fooproject/%squota-sets' % url,
            version=version, use_admin_context=True)

        result = getattr(controller(), method_name)(req, self.project_id)

        self.assertEqual(expected, result)

    @ddt.data(REQ, REQ_WITH_USER)
    def test_show_quota(self, request):
        quotas = {
            "shares": 23,
            "snapshots": 34,
            "gigabytes": 45,
            "snapshot_gigabytes": 56,
            "share_networks": 67,
        }
        expected = {
            'quota_set': {
                'id': self.project_id,
                'shares': quotas.get('shares', 50),
                'gigabytes': quotas.get('gigabytes', 1000),
                'snapshots': quotas.get('snapshots', 50),
                'snapshot_gigabytes': quotas.get('snapshot_gigabytes', 1000),
                'share_networks': quotas.get('share_networks', 10),
            }
        }
        for k, v in quotas.items():
            CONF.set_default('quota_' + k, v)

        result = self.controller.show(request, self.project_id)

        self.assertEqual(expected, result)
        self.mock_policy_check.assert_called_once_with(
            request.environ['manila.context'], self.resource_name, 'show')

    def test_show_quota_not_authorized(self):
        self.mock_object(
            quota_sets.db,
            'authorize_project_context',
            mock.Mock(side_effect=exception.NotAuthorized))

        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.show,
            REQ, self.project_id)
        self.mock_policy_check.assert_called_once_with(
            REQ.environ['manila.context'], self.resource_name, 'show')

    @ddt.data(REQ, REQ_WITH_USER)
    def test_update_quota(self, request):
        CONF.set_default('quota_shares', 789)
        body = {'quota_set': {'tenant_id': self.project_id, 'shares': 788}}
        expected = {
            'quota_set': {
                'shares': body['quota_set']['shares'],
                'gigabytes': 1000,
                'snapshots': 50,
                'snapshot_gigabytes': 1000,
                'share_networks': 10,
            }
        }
        mock_policy_update_check_call = mock.call(
            request.environ['manila.context'], self.resource_name, 'update')
        mock_policy_show_check_call = mock.call(
            request.environ['manila.context'], self.resource_name, 'show')

        update_result = self.controller.update(
            request, self.project_id, body=body)

        self.assertEqual(expected, update_result)

        show_result = self.controller.show(request, self.project_id)

        expected['quota_set']['id'] = self.project_id
        self.assertEqual(expected, show_result)
        self.mock_policy_check.assert_has_calls([
            mock_policy_update_check_call, mock_policy_show_check_call])

    @ddt.data(-2, 'foo', {1: 2}, [1])
    def test_update_quota_with_invalid_value(self, value):
        body = {'quota_set': {'tenant_id': self.project_id, 'shares': value}}

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.update,
            REQ, self.project_id, body=body)
        self.mock_policy_check.assert_called_once_with(
            REQ.environ['manila.context'], self.resource_name, 'update')

    def test_user_quota_can_not_be_bigger_than_tenant_quota(self):
        value = 777
        CONF.set_default('quota_shares', value)
        body = {
            'quota_set': {
                'tenant_id': self.project_id,
                'shares': value + 1,
            }
        }

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.update,
            REQ_WITH_USER, self.project_id, body=body)
        self.mock_policy_check.assert_called_once_with(
            REQ_WITH_USER.environ['manila.context'], self.resource_name,
            'update')

    def test_update_inexistent_quota(self):
        body = {
            'quota_set': {
                'tenant_id': self.project_id,
                'fake_quota': 13,
            }
        }

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.update,
            REQ, self.project_id, body=body)
        self.mock_policy_check.assert_called_once_with(
            REQ.environ['manila.context'], self.resource_name, 'update')

    def test_update_quota_not_authorized(self):
        body = {'quota_set': {'tenant_id': self.project_id, 'shares': 13}}

        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.update,
            REQ_MEMBER, self.project_id, body=body)
        self.mock_policy_check.assert_called_once_with(
            REQ_MEMBER.environ['manila.context'], self.resource_name, 'update')

    @ddt.data(
        ('os-quota-sets', '1.0', quota_sets.QuotaSetsControllerLegacy),
        ('os-quota-sets', '2.6', quota_sets.QuotaSetsControllerLegacy),
        ('quota-sets', '2.7', quota_sets.QuotaSetsController),
    )
    @ddt.unpack
    def test_update_all_quotas_with_force(self, url, version, controller):
        req = fakes.HTTPRequest.blank(
            '/fooproject/%s' % url, version=version, use_admin_context=True)
        quotas = (
            ('quota_shares', 13),
            ('quota_gigabytes', 14),
            ('quota_snapshots', 15),
            ('quota_snapshot_gigabytes', 16),
            ('quota_share_networks', 17),
        )
        for quota, value in quotas:
            CONF.set_default(quota, value)
        expected = {
            'quota_set': {
                'tenant_id': self.project_id,
                'shares': quotas[0][1],
                'gigabytes': quotas[1][1],
                'snapshots': quotas[2][1],
                'snapshot_gigabytes': quotas[3][1],
                'share_networks': quotas[4][1],
                'force': True,
            }
        }

        update_result = controller().update(
            req, self.project_id, body=expected)

        expected['quota_set'].pop('force')
        expected['quota_set'].pop('tenant_id')
        self.assertEqual(expected, update_result)

        show_result = controller().show(req, self.project_id)

        expected['quota_set']['id'] = self.project_id
        self.assertEqual(expected, show_result)
        self.mock_policy_check.assert_has_calls([
            mock.call(req.environ['manila.context'],
                      self.resource_name, action)
            for action in ('update', 'show')
        ])

    @ddt.data(
        ('os-quota-sets', '1.0', quota_sets.QuotaSetsControllerLegacy),
        ('os-quota-sets', '2.6', quota_sets.QuotaSetsControllerLegacy),
        ('quota-sets', '2.7', quota_sets.QuotaSetsController),
    )
    @ddt.unpack
    def test_delete_tenant_quota(self, url, version, controller):
        self.mock_object(quota_sets.QUOTAS, 'destroy_all_by_project_and_user')
        self.mock_object(quota_sets.QUOTAS, 'destroy_all_by_project')
        req = fakes.HTTPRequest.blank(
            '/fooproject/%s' % url, version=version, use_admin_context=True)

        result = controller().delete(req, self.project_id)

        self.assertTrue(
            utils.IsAMatcher(webob.response.Response) == result
        )
        self.assertTrue(hasattr(result, 'status_code'))
        self.assertEqual(202, result.status_code)
        self.assertFalse(
            quota_sets.QUOTAS.destroy_all_by_project_and_user.called)
        quota_sets.QUOTAS.destroy_all_by_project.assert_called_once_with(
            req.environ['manila.context'], self.project_id)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'delete')

    def test_delete_user_quota(self):
        project_id = 'foo_project_id'
        self.mock_object(quota_sets.QUOTAS, 'destroy_all_by_project_and_user')
        self.mock_object(quota_sets.QUOTAS, 'destroy_all_by_project')

        result = self.controller.delete(REQ_WITH_USER, project_id)

        self.assertTrue(
            utils.IsAMatcher(webob.response.Response) == result
        )
        self.assertTrue(hasattr(result, 'status_code'))
        self.assertEqual(202, result.status_code)
        quota_sets.QUOTAS.destroy_all_by_project_and_user. \
            assert_called_once_with(
                REQ_WITH_USER.environ['manila.context'],
                project_id,
                REQ_WITH_USER.environ['manila.context'].user_id)
        self.assertFalse(quota_sets.QUOTAS.destroy_all_by_project.called)
        self.mock_policy_check.assert_called_once_with(
            REQ_WITH_USER.environ['manila.context'], self.resource_name,
            'delete')

    def test_delete_not_authorized(self):
        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.delete,
            REQ_MEMBER, self.project_id)
        self.mock_policy_check.assert_called_once_with(
            REQ_MEMBER.environ['manila.context'], self.resource_name, 'delete')

    @ddt.data(
        ('os-quota-sets', '2.7', quota_sets.QuotaSetsControllerLegacy),
        ('quota-sets', '2.6', quota_sets.QuotaSetsController),
        ('quota-sets', '2.0', quota_sets.QuotaSetsController),
    )
    @ddt.unpack
    def test_api_not_found(self, url, version, controller):
        req = fakes.HTTPRequest.blank('/fooproject/%s' % url, version=version)
        for method_name in ('show', 'defaults', 'delete'):
            self.assertRaises(
                exception.VersionNotFoundForAPIMethod,
                getattr(controller(), method_name),
                req, self.project_id)

    @ddt.data(
        ('os-quota-sets', '2.7', quota_sets.QuotaSetsControllerLegacy),
        ('quota-sets', '2.6', quota_sets.QuotaSetsController),
        ('quota-sets', '2.0', quota_sets.QuotaSetsController),
    )
    @ddt.unpack
    def test_update_api_not_found(self, url, version, controller):
        req = fakes.HTTPRequest.blank('/fooproject/%s' % url, version=version)
        self.assertRaises(
            exception.VersionNotFoundForAPIMethod,
            controller().update,
            req, self.project_id)
