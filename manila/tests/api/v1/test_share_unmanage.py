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

from manila.api.v1 import share_unmanage
from manila.common import constants
from manila import exception
from manila import policy
from manila.share import api as share_api
from manila import test
from manila.tests.api.contrib import stubs
from manila.tests.api import fakes


@ddt.ddt
class ShareUnmanageTest(test.TestCase):
    """Share Unmanage Test."""
    def setUp(self):
        super(ShareUnmanageTest, self).setUp()
        self.controller = share_unmanage.ShareUnmanageController()
        self.resource_name = self.controller.resource_name
        self.mock_object(share_api.API, 'get_all',
                         stubs.stub_get_all_shares)
        self.mock_object(share_api.API, 'get',
                         stubs.stub_share_get)
        self.mock_object(share_api.API, 'update', stubs.stub_share_update)
        self.mock_object(share_api.API, 'delete', stubs.stub_share_delete)
        self.mock_object(share_api.API, 'get_snapshot',
                         stubs.stub_snapshot_get)
        self.share_id = 'fake'
        self.request = fakes.HTTPRequest.blank(
            '/share/%s/unmanage' % self.share_id,
            use_admin_context=True
        )
        self.context = self.request.environ['manila.context']
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))

    def test_unmanage_share(self):
        share = dict(status=constants.STATUS_AVAILABLE, id='foo_id')
        self.mock_object(share_api.API, 'get', mock.Mock(return_value=share))
        self.mock_object(share_api.API, 'unmanage', mock.Mock())
        self.mock_object(
            self.controller.share_api.db, 'share_snapshot_get_all_for_share',
            mock.Mock(return_value=[]))

        actual_result = self.controller.unmanage(self.request, share['id'])

        self.assertEqual(202, actual_result.status_int)
        self.controller.share_api.db.share_snapshot_get_all_for_share.\
            assert_called_once_with(
                self.request.environ['manila.context'], share['id'])
        self.controller.share_api.get.assert_called_once_with(
            self.request.environ['manila.context'], share['id'])
        share_api.API.unmanage.assert_called_once_with(
            self.request.environ['manila.context'], share)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'unmanage')

    def test_unmanage_share_that_has_snapshots(self):
        share = dict(status=constants.STATUS_AVAILABLE, id='foo_id')
        snapshots = ['foo', 'bar']
        self.mock_object(self.controller.share_api, 'unmanage')
        self.mock_object(
            self.controller.share_api.db, 'share_snapshot_get_all_for_share',
            mock.Mock(return_value=snapshots))
        self.mock_object(
            self.controller.share_api, 'get',
            mock.Mock(return_value=share))

        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.unmanage, self.request, share['id'])

        self.assertFalse(self.controller.share_api.unmanage.called)
        self.controller.share_api.db.share_snapshot_get_all_for_share.\
            assert_called_once_with(
                self.request.environ['manila.context'], share['id'])
        self.controller.share_api.get.assert_called_once_with(
            self.request.environ['manila.context'], share['id'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'unmanage')

    def test_unmanage_share_based_on_share_server(self):
        share = dict(share_server_id='foo_id', id='bar_id')
        self.mock_object(
            self.controller.share_api, 'get',
            mock.Mock(return_value=share))

        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.unmanage, self.request, share['id'])

        self.controller.share_api.get.assert_called_once_with(
            self.request.environ['manila.context'], share['id'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'unmanage')

    @ddt.data(*constants.TRANSITIONAL_STATUSES)
    def test_unmanage_share_with_transitional_state(self, share_status):
        share = dict(status=share_status, id='foo_id')
        self.mock_object(
            self.controller.share_api, 'get',
            mock.Mock(return_value=share))

        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.unmanage, self.request, share['id'])

        self.controller.share_api.get.assert_called_once_with(
            self.request.environ['manila.context'], share['id'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'unmanage')

    def test_unmanage_share_not_found(self):
        self.mock_object(share_api.API, 'get', mock.Mock(
            side_effect=exception.NotFound))
        self.mock_object(share_api.API, 'unmanage', mock.Mock())

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.unmanage,
                          self.request, self.share_id)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'unmanage')

    @ddt.data(exception.InvalidShare(reason="fake"),
              exception.PolicyNotAuthorized(action="fake"),)
    def test_unmanage_share_invalid(self, side_effect):
        share = dict(status=constants.STATUS_AVAILABLE, id='foo_id')
        self.mock_object(share_api.API, 'get', mock.Mock(return_value=share))
        self.mock_object(share_api.API, 'unmanage', mock.Mock(
            side_effect=side_effect))

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller.unmanage,
                          self.request, self.share_id)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'unmanage')

    def test_wrong_permissions(self):
        share_id = 'fake'
        req = fakes.HTTPRequest.blank('/share/%s/unmanage' % share_id,
                                      use_admin_context=False)
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller.unmanage,
                          req,
                          share_id)
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'unmanage')
