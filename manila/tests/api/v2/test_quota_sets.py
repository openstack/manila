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
Tests for manila.api.v2.quota_sets.py
"""

import ddt
import mock
from oslo_config import cfg
import webob.exc
import webob.response

from manila.api.openstack import api_version_request as api_version
from manila.api.v2 import quota_sets
from manila import context
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila import utils

CONF = cfg.CONF


def _get_request(is_admin, user_in_url):
    req = mock.MagicMock(
        api_version_request=api_version.APIVersionRequest("2.40"))
    req.environ = {'manila.context': context.get_admin_context()}
    req.environ['manila.context'].is_admin = is_admin
    req.environ['manila.context'].auth_token = 'foo_auth_token'
    req.environ['manila.context'].project_id = 'foo_project_id'
    if user_in_url:
        req.environ['manila.context'].user_id = 'foo_user_id'
        req.environ['QUERY_STRING'] = 'user_id=foo_user_id'
    return req


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
        {"share_groups": 123456},
        {"share_group_snapshots": 123456},
    )
    def test_defaults(self, quotas):
        req = _get_request(True, False)
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
                'share_groups': quotas.get('share_groups', 50),
                'share_group_snapshots': quotas.get(
                    'share_group_snapshots', 50),
            }
        }

        result = self.controller.defaults(req, self.project_id)

        self.assertEqual(expected, result)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'show')

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

    @staticmethod
    def _get_share_type_request_object(microversion=None):
        req = _get_request(True, False)
        req.environ['QUERY_STRING'] = 'share_type=fake_share_type_name_or_id'
        req.api_version_request = api_version.APIVersionRequest(
            microversion or '2.39')
        return req

    @ddt.data('2.39', '2.40')
    def test_share_type_quota_detail(self, microversion):
        self.mock_object(
            quota_sets.db, 'share_type_get_by_name_or_id',
            mock.Mock(return_value={'id': 'fake_st_id'}))
        req = self._get_share_type_request_object(microversion)
        quotas = {
            "shares": 23,
            "snapshots": 34,
            "gigabytes": 45,
            "snapshot_gigabytes": 56,
        }
        expected = {'quota_set': {
            'id': self.project_id,
            'shares': {
                'in_use': 0,
                'limit': quotas['shares'],
                'reserved': 0,
            },
            'gigabytes': {
                'in_use': 0,
                'limit': quotas['gigabytes'],
                'reserved': 0,
            },
            'snapshots': {
                'in_use': 0,
                'limit': quotas['snapshots'],
                'reserved': 0,
            },
            'snapshot_gigabytes': {
                'in_use': 0,
                'limit': quotas['snapshot_gigabytes'],
                'reserved': 0,
            },
        }}

        for k, v in quotas.items():
            CONF.set_default('quota_' + k, v)

        result = self.controller.detail(req, self.project_id)

        self.assertEqual(expected, result)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'show')
        quota_sets.db.share_type_get_by_name_or_id.assert_called_once_with(
            req.environ['manila.context'], 'fake_share_type_name_or_id')

    @ddt.data('2.39', '2.40')
    def test_show_share_type_quota(self, microversion):
        self.mock_object(
            quota_sets.db, 'share_type_get_by_name_or_id',
            mock.Mock(return_value={'id': 'fake_st_id'}))
        req = self._get_share_type_request_object(microversion)
        quotas = {
            "shares": 23,
            "snapshots": 34,
            "gigabytes": 45,
            "snapshot_gigabytes": 56,
        }
        expected = {
            'quota_set': {
                'id': self.project_id,
                'shares': quotas.get('shares', 50),
                'gigabytes': quotas.get('gigabytes', 1000),
                'snapshots': quotas.get('snapshots', 50),
                'snapshot_gigabytes': quotas.get('snapshot_gigabytes', 1000),
            }
        }
        for k, v in quotas.items():
            CONF.set_default('quota_' + k, v)

        result = self.controller.show(req, self.project_id)

        self.assertEqual(expected, result)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'show')
        quota_sets.db.share_type_get_by_name_or_id.assert_called_once_with(
            req.environ['manila.context'], 'fake_share_type_name_or_id')

    @ddt.data('show', 'detail')
    def test_get_share_type_quota_with_old_microversion(self, method):
        req = self._get_share_type_request_object('2.38')
        self.assertRaises(
            webob.exc.HTTPBadRequest,
            getattr(self.controller, method),
            req, self.project_id)

    @ddt.data((None, None), (None, 'foo'), ('bar', None))
    @ddt.unpack
    def test__validate_user_id_and_share_type_args(self, user_id, st_id):
        result = self.controller._validate_user_id_and_share_type_args(
            user_id, st_id)

        self.assertIsNone(result)

    def test__validate_user_id_and_share_type_args_exception(self):
        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller._validate_user_id_and_share_type_args,
            'foo', 'bar')

    def test__get_share_type_id_found(self):
        self.mock_object(
            quota_sets.db, 'share_type_get_by_name_or_id',
            mock.Mock(return_value={'id': 'fake_st_id'}))
        ctxt = 'fake_context'
        share_type = 'fake_share_type_name_or_id'

        result = self.controller._get_share_type_id(ctxt, share_type)

        self.assertEqual('fake_st_id', result)

    def test__get_share_type_id_not_found(self):
        self.mock_object(
            quota_sets.db, 'share_type_get_by_name_or_id',
            mock.Mock(return_value=None))
        ctxt = 'fake_context'
        share_type = 'fake_share_type_name_or_id'

        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller._get_share_type_id,
            ctxt, share_type)

    def test__get_share_type_id_is_not_provided(self):
        self.mock_object(
            quota_sets.db, 'share_type_get_by_name_or_id',
            mock.Mock(return_value={'id': 'fake_st_id'}))
        ctxt = 'fake_context'

        result = self.controller._get_share_type_id(ctxt, None)

        self.assertIsNone(result)

    @ddt.data(
        {},
        {"quota_set": {}},
        {"quota_set": {"foo": "bar"}},
        {"foo": "bar"},
    )
    def test__ensure_share_group_related_args_are_absent_success(self, body):
        result = self.controller._ensure_share_group_related_args_are_absent(
            body)

        self.assertIsNone(result)

    @ddt.data(
        {"share_groups": 5},
        {"share_group_snapshots": 6},
        {"quota_set": {"share_groups": 7}},
        {"quota_set": {"share_group_snapshots": 8}},
    )
    def test__ensure_share_group_related_args_are_absent_error(self, body):
        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller._ensure_share_group_related_args_are_absent, body)

    @ddt.data(_get_request(True, True), _get_request(True, False))
    def test__ensure_share_type_arg_is_absent(self, req):
        result = self.controller._ensure_share_type_arg_is_absent(req)

        self.assertIsNone(result)

    def test__ensure_share_type_arg_is_absent_exception(self):
        req = self._get_share_type_request_object('2.39')

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller._ensure_share_type_arg_is_absent,
            req)

    @ddt.data(_get_request(True, True), _get_request(True, False))
    def test_quota_detail(self, request):
        request.api_version_request = api_version.APIVersionRequest('2.25')
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
                'shares': {'in_use': 0,
                           'limit': quotas['shares'],
                           'reserved': 0},
                'gigabytes': {'in_use': 0,
                              'limit': quotas['gigabytes'], 'reserved': 0},
                'snapshots': {'in_use': 0,
                              'limit': quotas['snapshots'], 'reserved': 0},
                'snapshot_gigabytes': {
                    'in_use': 0,
                    'limit': quotas['snapshot_gigabytes'],
                    'reserved': 0,
                },
                'share_networks': {
                    'in_use': 0,
                    'limit': quotas['share_networks'],
                    'reserved': 0
                },
            }
        }

        for k, v in quotas.items():
            CONF.set_default('quota_' + k, v)

        result = self.controller.detail(request, self.project_id)

        self.assertEqual(expected, result)
        self.mock_policy_check.assert_called_once_with(
            request.environ['manila.context'], self.resource_name, 'show')

    @ddt.data(_get_request(True, True), _get_request(True, False))
    def test_show_quota(self, request):
        quotas = {
            "shares": 23,
            "snapshots": 34,
            "gigabytes": 45,
            "snapshot_gigabytes": 56,
            "share_networks": 67,
            "share_groups": 53,
            "share_group_snapshots": 57,
        }
        expected = {
            'quota_set': {
                'id': self.project_id,
                'shares': quotas.get('shares', 50),
                'gigabytes': quotas.get('gigabytes', 1000),
                'snapshots': quotas.get('snapshots', 50),
                'snapshot_gigabytes': quotas.get('snapshot_gigabytes', 1000),
                'share_networks': quotas.get('share_networks', 10),
                'share_groups': quotas.get('share_groups', 50),
                'share_group_snapshots': quotas.get(
                    'share_group_snapshots', 50),
            }
        }
        for k, v in quotas.items():
            CONF.set_default('quota_' + k, v)

        result = self.controller.show(request, self.project_id)

        self.assertEqual(expected, result)
        self.mock_policy_check.assert_called_once_with(
            request.environ['manila.context'], self.resource_name, 'show')

    def test_show_quota_not_authorized(self):
        req = _get_request(True, False)
        self.mock_object(
            quota_sets.db,
            'authorize_project_context',
            mock.Mock(side_effect=exception.NotAuthorized))

        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.show,
            req, self.project_id)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'show')

    @ddt.data(_get_request(True, True), _get_request(True, False))
    def test_update_quota(self, request):
        self.mock_object(
            quota_sets.db, 'share_type_get_by_name_or_id',
            mock.Mock(
                return_value={'id': 'fake_st_id', 'name': 'fake_st_name'}))
        CONF.set_default('quota_shares', 789)
        body = {'quota_set': {'tenant_id': self.project_id, 'shares': 788}}
        expected = {
            'quota_set': {
                'shares': body['quota_set']['shares'],
                'gigabytes': 1000,
                'snapshots': 50,
                'snapshot_gigabytes': 1000,
                'share_networks': 10,
                'share_groups': 50,
                'share_group_snapshots': 50,
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
        quota_sets.db.share_type_get_by_name_or_id.assert_not_called()

    @ddt.data('2.39', '2.40')
    def test_update_share_type_quota(self, microversion):
        self.mock_object(
            quota_sets.db, 'share_type_get_by_name_or_id',
            mock.Mock(
                return_value={'id': 'fake_st_id', 'name': 'fake_st_name'}))
        req = self._get_share_type_request_object(microversion)

        CONF.set_default('quota_shares', 789)
        body = {'quota_set': {'tenant_id': self.project_id, 'shares': 788}}
        expected = {
            'quota_set': {
                'shares': body['quota_set']['shares'],
                'gigabytes': 1000,
                'snapshots': 50,
                'snapshot_gigabytes': 1000,
            }
        }

        update_result = self.controller.update(req, self.project_id, body=body)

        self.assertEqual(expected, update_result)
        quota_sets.db.share_type_get_by_name_or_id.assert_called_once_with(
            req.environ['manila.context'],
            req.environ['QUERY_STRING'].split('=')[-1])
        quota_sets.db.share_type_get_by_name_or_id.reset_mock()

        show_result = self.controller.show(req, self.project_id)

        expected['quota_set']['id'] = self.project_id
        self.assertEqual(expected, show_result)
        self.mock_policy_check.assert_has_calls([
            mock.call(req.environ['manila.context'], self.resource_name, key)
            for key in ('update', 'show')
        ])
        quota_sets.db.share_type_get_by_name_or_id.assert_called_once_with(
            req.environ['manila.context'],
            req.environ['QUERY_STRING'].split('=')[-1])

    def test_update_share_type_quota_using_too_old_microversion(self):
        self.mock_object(
            quota_sets.db, 'share_type_get_by_name_or_id',
            mock.Mock(
                return_value={'id': 'fake_st_id', 'name': 'fake_st_name'}))
        req = self._get_share_type_request_object('2.38')
        body = {'quota_set': {'tenant_id': self.project_id, 'shares': 788}}

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.update,
            req, self.project_id, body=body)

        quota_sets.db.share_type_get_by_name_or_id.assert_not_called()

    def test_update_share_type_quota_for_share_networks(self):
        self.mock_object(
            quota_sets.db, 'share_type_get_by_name_or_id',
            mock.Mock(
                return_value={'id': 'fake_st_id', 'name': 'fake_st_name'}))
        req = self._get_share_type_request_object('2.39')
        body = {'quota_set': {
            'tenant_id': self.project_id, 'share_networks': 788,
        }}

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.update,
            req, self.project_id, body=body)

        quota_sets.db.share_type_get_by_name_or_id.assert_called_once_with(
            req.environ['manila.context'],
            req.environ['QUERY_STRING'].split('=')[-1])

    @ddt.data(-2, 'foo', {1: 2}, [1])
    def test_update_quota_with_invalid_value(self, value):
        req = _get_request(True, False)
        body = {'quota_set': {'tenant_id': self.project_id, 'shares': value}}

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.update,
            req, self.project_id, body=body)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'update')

    def test_user_quota_can_not_be_bigger_than_tenant_quota(self):
        value = 777
        CONF.set_default('quota_shares', value)
        body = {
            'quota_set': {
                'tenant_id': self.project_id,
                'shares': value + 1,
            }
        }
        req = _get_request(True, True)

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.update,
            req, self.project_id, body=body)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'update')

    def test_update_inexistent_quota(self):
        body = {
            'quota_set': {
                'tenant_id': self.project_id,
                'fake_quota': 13,
            }
        }
        req = _get_request(True, False)

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.update,
            req, self.project_id, body=body)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'update')

    def test_update_quota_not_authorized(self):
        body = {'quota_set': {'tenant_id': self.project_id, 'shares': 13}}
        req = _get_request(False, False)

        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.update,
            req, self.project_id, body=body)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'update')

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
        req = _get_request(True, True)

        result = self.controller.delete(req, project_id)

        self.assertTrue(
            utils.IsAMatcher(webob.response.Response) == result
        )
        self.assertTrue(hasattr(result, 'status_code'))
        self.assertEqual(202, result.status_code)
        (quota_sets.QUOTAS.destroy_all_by_project_and_user.
            assert_called_once_with(
                req.environ['manila.context'],
                project_id,
                req.environ['manila.context'].user_id))
        self.assertFalse(quota_sets.QUOTAS.destroy_all_by_project.called)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'delete')

    def test_delete_share_type_quota(self):
        req = self._get_share_type_request_object('2.39')
        self.mock_object(quota_sets.QUOTAS, 'destroy_all_by_project')
        self.mock_object(quota_sets.QUOTAS, 'destroy_all_by_project_and_user')
        mock_delete_st_quotas = self.mock_object(
            quota_sets.QUOTAS, 'destroy_all_by_project_and_share_type')
        self.mock_object(
            quota_sets.db, 'share_type_get_by_name_or_id',
            mock.Mock(
                return_value={'id': 'fake_st_id', 'name': 'fake_st_name'}))

        result = self.controller.delete(req, self.project_id)

        self.assertEqual(utils.IsAMatcher(webob.response.Response), result)
        self.assertTrue(hasattr(result, 'status_code'))
        self.assertEqual(202, result.status_code)
        mock_delete_st_quotas.assert_called_once_with(
            req.environ['manila.context'], self.project_id, 'fake_st_id')
        quota_sets.QUOTAS.destroy_all_by_project.assert_not_called()
        quota_sets.QUOTAS.destroy_all_by_project_and_user.assert_not_called()
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'delete')
        quota_sets.db.share_type_get_by_name_or_id.assert_called_once_with(
            req.environ['manila.context'],
            req.environ['QUERY_STRING'].split('=')[-1])

    def test_delete_share_type_quota_using_too_old_microversion(self):
        self.mock_object(
            quota_sets.db, 'share_type_get_by_name_or_id',
            mock.Mock(
                return_value={'id': 'fake_st_id', 'name': 'fake_st_name'}))
        req = self._get_share_type_request_object('2.38')

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.delete,
            req, self.project_id)

        quota_sets.db.share_type_get_by_name_or_id.assert_not_called()

    def test_delete_not_authorized(self):
        req = _get_request(False, False)
        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.delete,
            req, self.project_id)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'delete')

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
