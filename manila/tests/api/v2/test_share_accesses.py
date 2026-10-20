# Copyright (c) 2018 Huawei Inc.
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
from webob import exc

from manila.api.v2 import share_accesses
from manila.common import constants
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils
from oslo_utils import uuidutils


@ddt.ddt
class ShareAccessesAPITest(test.TestCase):

    def _get_index_request(self, share_id=None, filters='', version="2.45",
                           use_admin_context=True):
        share_id = share_id or self.share['id']
        req = fakes.HTTPRequest.blank(
            '/v2/share-access-rules?share_id=%s' % share_id + filters,
            version=version, use_admin_context=use_admin_context)
        return req

    def _get_show_request(self, access_id=None, version="2.45",
                          use_admin_context=True):
        access_id = access_id or self.access['id']
        req = fakes.HTTPRequest.blank(
            '/v2/share-access-rules/%s' % access_id,
            version=version, use_admin_context=use_admin_context)
        return req

    def setUp(self):
        super(ShareAccessesAPITest, self).setUp()
        self.controller = (
            share_accesses.ShareAccessesController())
        self.resource_name = self.controller.resource_name
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.share = db_utils.create_share()
        self.access = db_utils.create_share_access(
            id=uuidutils.generate_uuid(),
            share_id=self.share['id'],
        )
        db_utils.create_share_access(
            id=uuidutils.generate_uuid(),
            share_id=self.share['id'],
            metadata={'k1': 'v1'}
        )

    @ddt.data({'role': 'admin', 'version': '2.45',
               'filters': '&metadata=%7B%27k1%27%3A+%27v1%27%7D'},
              {'role': 'user', 'version': '2.45', 'filters': ''})
    @ddt.unpack
    def test_list_and_show(self, role, version, filters):
        summary_keys = ['id', 'access_level', 'access_to',
                        'access_type', 'state', 'metadata']

        self._test_list_and_show(role, filters, version, summary_keys)

    def _test_list_and_show(self, role, filters, version, summary_keys):

        req = self._get_index_request(
            filters=filters, version=version,
            use_admin_context=(role == 'admin'))
        index_result = self.controller.index(req)

        self.assertIn('access_list', index_result)
        self.assertEqual(1, len(index_result))

        access_count = 1 if filters else 2
        self.assertEqual(access_count, len(index_result['access_list']))

        for index_access in index_result['access_list']:
            self.assertIn('id', index_access)
            req = self._get_show_request(
                index_access['id'], version=version,
                use_admin_context=(role == 'admin'))
            show_result = self.controller.show(req, index_access['id'])
            self.assertIn('access', show_result)
            self.assertEqual(1, len(show_result))

            show_el = show_result['access']

            # Ensure keys common to index & show results have matching values
            for key in summary_keys:
                self.assertEqual(index_access[key], show_el[key])

    @ddt.data(True, False)
    def test_list_accesses_restricted(self, restricted):
        req = self._get_index_request(version='2.82')
        rule_list = [{
            'access_to': '0.0.0.0/0',
            'id': 'fakeid',
            'access_key': 'fake_key'
        }]
        self.mock_object(
            self.controller.share_api, 'access_get_all',
            mock.Mock(return_value=rule_list))
        self.mock_object(
            self.controller, '_is_rule_restricted',
            mock.Mock(return_value=restricted))

        index_result = self.controller.index(req)

        self.assertIn('access_list', index_result)
        self.controller._is_rule_restricted.assert_called_once_with(
            req.environ['manila.context'], rule_list[0]['id'])
        if restricted:
            for access in index_result['access_list']:
                self.assertEqual('******', access['access_key'])
                self.assertEqual('******', access['access_to'])

    @ddt.data(True, False)
    def test_show_restricted(self, restricted):
        req = self._get_show_request(
            version='2.82', use_admin_context=False)
        self.mock_object(
            self.controller, '_is_rule_restricted',
            mock.Mock(return_value=restricted))

        show_result = self.controller.show(req, self.access['id'])

        expected_access_to = (
            '******' if restricted else self.access['access_to'])

        self.assertEqual(
            expected_access_to, show_result['access']['access_to'])

    @ddt.data(True, False)
    def test__is_rule_restricted(self, is_rule_restricted):
        req = self._get_show_request(
            version='2.82', use_admin_context=False)
        context = req.environ['manila.context']
        fake_lock = {
            'lock_context': 'user',
            'user_id': 'fake',
            'project_id': 'fake',
            'resource_id': 'fake',
            'resource_action': constants.RESOURCE_ACTION_DELETE,
            'lock_reason': 'fake reason',
        }
        lock = fake_lock if is_rule_restricted else {}
        locks = [lock]

        self.mock_object(
            self.controller.resource_locks_api, 'get_all',
            mock.Mock(return_value=(locks, len(locks))))
        self.mock_object(
            self.controller.resource_locks_api, 'access_is_restricted',
            mock.Mock(return_value=is_rule_restricted))

        result_rule_restricted = self.controller._is_rule_restricted(
            context, self.access['id'])

        self.assertEqual(
            is_rule_restricted, result_rule_restricted)

    def test_list_accesses_share_not_found(self):
        self.assertRaises(
            exc.HTTPBadRequest,
            self.controller.index,
            self._get_index_request(share_id='inexistent_share_id'))

    def test_list_accesses_share_req_share_id_not_exist(self):
        req = fakes.HTTPRequest.blank('/v2/share-access-rules?',
                                      version="2.45")
        self.assertRaises(exc.HTTPBadRequest, self.controller.index, req)

    def test_show_access_not_authorized(self):
        share = db_utils.create_share(
            project_id='c3c5ec1ccc4640d0af1914cbf11f05ad',
            is_public=False)
        access = db_utils.create_access(
            id='76699c6b-f3da-47d7-b468-364f1347ba04',
            share_id=share['id'])
        req = fakes.HTTPRequest.blank(
            '/v2/share-access-rules/%s' % access['id'],
            version="2.45")
        self.mock_object(
            policy, 'check_policy',
            mock.Mock(side_effect=[None, None, exception.NotAuthorized]))

        self.assertRaises(exception.NotAuthorized,
                          self.controller.show,
                          req,
                          access['id'])
        policy.check_policy.assert_has_calls([
            mock.call(req.environ['manila.context'],
                      'share_access_rule', 'get'),
            mock.call(req.environ['manila.context'],
                      'share', 'access_get'),
            mock.call(req.environ['manila.context'],
                      'share', 'get', mock.ANY, do_raise=False)])
        policy_check_call_args_list = policy.check_policy.call_args_list[2][0]
        share_being_checked = policy_check_call_args_list[3]
        self.assertEqual('c3c5ec1ccc4640d0af1914cbf11f05ad',
                         share_being_checked['project_id'])
        self.assertIs(False, share_being_checked['is_public'])

    def test_show_access_not_found(self):
        req = self._get_show_request('inexistent_id')
        print(req.environ)
        self.assertRaises(
            exc.HTTPNotFound,
            self.controller.show,
            req, 'inexistent_id')

    @ddt.data('1.0', '2.0', '2.8', '2.44')
    def test_list_with_unsupported_version(self, version):
        self.assertRaises(
            exception.VersionNotFoundForAPIMethod,
            self.controller.index,
            self._get_index_request(version=version))

    @ddt.data('1.0', '2.0', '2.44')
    def test_show_with_unsupported_version(self, version):
        self.assertRaises(
            exception.VersionNotFoundForAPIMethod,
            self.controller.show,
            self._get_show_request(version=version),
            self.access['id'])

    def _get_update_request(self, access_id=None):
        access_id = access_id or self.access['id']
        req = fakes.HTTPRequest.blank(
            '/v2/share-access-rules/%s' % access_id, version="2.88",
            experimental=True)
        return req

    def test_update_access_level(self):
        fake_access = mock.Mock(
            access_level='rw', share_id=self.share['id'])
        updated_access = mock.Mock(
            access_level='ro', share_id=self.share['id'])
        mock_get_access = self.mock_object(
            self.controller, '_get_share_access',
            mock.Mock(return_value=fake_access))
        mock_get = self.mock_object(
            self.controller.share_api, 'get',
            mock.Mock(return_value=self.share))
        mock_update = self.mock_object(
            self.controller.share_api, 'update_access',
            mock.Mock(return_value=updated_access))
        mock_view = self.mock_object(
            self.controller._view_builder, 'view',
            mock.Mock(return_value={'access': {'access_level': 'ro'}}))

        body = {'update_access': {'access_level': 'ro'}}
        req = self._get_update_request()
        context = req.environ['manila.context']
        ret = self.controller.update(req, self.access['id'], body=body)

        self.assertEqual('ro', ret['access']['access_level'])
        mock_get_access.assert_called_once_with(
            context, self.access['id'])
        mock_get.assert_called_once_with(
            context, self.share['id'], for_modification=True)
        mock_update.assert_called_once_with(
            context, self.share, fake_access, {'access_level': 'ro'})
        mock_view.assert_called_once_with(req, updated_access)

    def test_update_policy_not_authorized(self):
        fake_access = mock.Mock(
            access_level='rw', share_id=self.share['id'])
        self.mock_object(
            self.controller, '_get_share_access',
            mock.Mock(return_value=fake_access))
        self.mock_object(
            self.controller.share_api, 'get',
            mock.Mock(side_effect=exception.PolicyNotAuthorized(
                action='share:get')))

        body = {'update_access': {'access_level': 'ro'}}
        req = self._get_update_request()

        self.assertRaises(
            exception.PolicyNotAuthorized,
            self.controller.update,
            req, self.access['id'], body=body)

    def test_update_access_level_invalid_access_level(self):
        body = {'access': {'access_level': 'fake_access'}}
        self.assertRaises(
            exc.HTTPBadRequest,
            self.controller.update,
            self._get_update_request(), self.access['id'],
            body=body)

    def test_update_access_level_invalid_update_request(self):
        body = {'access': {'access_key': 'xxxx'}}
        self.assertRaises(
            exc.HTTPBadRequest,
            self.controller.update,
            self._get_update_request(), self.access['id'],
            body=body)
