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
Tests for manila.api.v1.quota_class_sets.py
"""

import copy

import ddt
import mock
from oslo_config import cfg
import webob.exc
import webob.response

from manila.api.v2 import quota_class_sets
from manila import context
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes

CONF = cfg.CONF

REQ = mock.MagicMock()
REQ.environ = {'manila.context': context.get_admin_context()}
REQ.environ['manila.context'].is_admin = True
REQ.environ['manila.context'].auth_token = 'foo_auth_token'
REQ.environ['manila.context'].project_id = 'foo_project_id'

REQ_MEMBER = copy.deepcopy(REQ)
REQ_MEMBER.environ['manila.context'].is_admin = False


@ddt.ddt
class QuotaSetsControllerTest(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.controller = quota_class_sets.QuotaClassSetsController()
        self.resource_name = self.controller.resource_name
        self.class_name = 'foo_class_name'
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))

    @ddt.data(
        ('os-', '1.0', quota_class_sets.QuotaClassSetsControllerLegacy),
        ('os-', '2.6', quota_class_sets.QuotaClassSetsControllerLegacy),
        ('', '2.7', quota_class_sets.QuotaClassSetsController),
    )
    @ddt.unpack
    def test_show_quota(self, url, version, controller):
        req = fakes.HTTPRequest.blank(
            '/fooproject/%squota-class-sets' % url,
            version=version, use_admin_context=True)
        quotas = {
            "shares": 23,
            "snapshots": 34,
            "gigabytes": 45,
            "snapshot_gigabytes": 56,
            "share_networks": 67,
        }
        expected = {
            'quota_class_set': {
                'id': self.class_name,
                'shares': quotas.get('shares', 50),
                'gigabytes': quotas.get('gigabytes', 1000),
                'snapshots': quotas.get('snapshots', 50),
                'snapshot_gigabytes': quotas.get('snapshot_gigabytes', 1000),
                'share_networks': quotas.get('share_networks', 10),
            }
        }
        for k, v in quotas.items():
            CONF.set_default('quota_' + k, v)

        result = controller().show(req, self.class_name)

        self.assertEqual(expected, result)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'show')

    def test_show_quota_not_authorized(self):
        self.mock_object(
            quota_class_sets.db,
            'authorize_quota_class_context',
            mock.Mock(side_effect=exception.NotAuthorized))

        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.show,
            REQ, self.class_name)
        self.mock_policy_check.assert_called_once_with(
            REQ.environ['manila.context'], self.resource_name, 'show')

    @ddt.data(
        ('os-', '1.0', quota_class_sets.QuotaClassSetsControllerLegacy),
        ('os-', '2.6', quota_class_sets.QuotaClassSetsControllerLegacy),
        ('', '2.7', quota_class_sets.QuotaClassSetsController),
    )
    @ddt.unpack
    def test_update_quota(self, url, version, controller):
        req = fakes.HTTPRequest.blank(
            '/fooproject/%squota-class-sets' % url,
            version=version, use_admin_context=True)
        CONF.set_default('quota_shares', 789)
        body = {
            'quota_class_set': {
                'class_name': self.class_name,
                'shares': 788,
            }
        }
        expected = {
            'quota_class_set': {
                'shares': body['quota_class_set']['shares'],
                'gigabytes': 1000,
                'snapshots': 50,
                'snapshot_gigabytes': 1000,
                'share_networks': 10,
            }
        }

        update_result = controller().update(
            req, self.class_name, body=body)

        self.assertEqual(expected, update_result)

        show_result = controller().show(req, self.class_name)

        expected['quota_class_set']['id'] = self.class_name
        self.assertEqual(expected, show_result)
        self.mock_policy_check.assert_has_calls([mock.call(
            req.environ['manila.context'], self.resource_name, action_name)
            for action_name in ('update', 'show')])

    def test_update_quota_not_authorized(self):
        body = {
            'quota_class_set': {
                'class_name': self.class_name,
                'shares': 13,
            }
        }

        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.update,
            REQ_MEMBER, self.class_name, body=body)
        self.mock_policy_check.assert_called_once_with(
            REQ_MEMBER.environ['manila.context'], self.resource_name, 'update')

    @ddt.data(
        ('os-', '2.7', quota_class_sets.QuotaClassSetsControllerLegacy),
        ('', '2.6', quota_class_sets.QuotaClassSetsController),
        ('', '2.0', quota_class_sets.QuotaClassSetsController),
    )
    @ddt.unpack
    def test_api_not_found(self, url, version, controller):
        req = fakes.HTTPRequest.blank(
            '/fooproject/%squota-class-sets' % url, version=version)
        for method_name in ('show', 'update'):
            self.assertRaises(
                exception.VersionNotFoundForAPIMethod,
                getattr(controller(), method_name),
                req, self.class_name)

    @ddt.data(
        ('os-', '2.7', quota_class_sets.QuotaClassSetsControllerLegacy),
        ('', '2.6', quota_class_sets.QuotaClassSetsController),
        ('', '2.0', quota_class_sets.QuotaClassSetsController),
    )
    @ddt.unpack
    def test_update_api_not_found(self, url, version, controller):
        req = fakes.HTTPRequest.blank(
            '/fooproject/%squota-class-sets' % url, version=version)
        self.assertRaises(
            exception.VersionNotFoundForAPIMethod,
            controller().update,
            req, self.class_name)
