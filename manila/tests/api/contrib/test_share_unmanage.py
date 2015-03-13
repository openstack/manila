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

from manila.api.contrib import share_unmanage
from manila import exception
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

    def test_unmanage_share(self):
        self.mock_object(share_api.API, 'get', mock.Mock(return_value={}))
        self.mock_object(share_api.API, 'unmanage', mock.Mock())

        actual_result = self.controller.unmanage(self.request, self.share_id)

        self.assertEqual(202, actual_result.status_int)

    def test_unmanage_share_not_found(self):
        self.mock_object(share_api.API, 'get', mock.Mock(
            side_effect=exception.NotFound))
        self.mock_object(share_api.API, 'unmanage', mock.Mock())

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.unmanage,
                          self.request, self.share_id)

    @ddt.data(exception.InvalidShare(reason="fake"),
              exception.PolicyNotAuthorized(action="fake"),)
    def test_unmanage_share_invalid(self, side_effect):
        self.mock_object(share_api.API, 'get', mock.Mock(return_value={}))
        self.mock_object(share_api.API, 'unmanage', mock.Mock(
            side_effect=side_effect))

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller.unmanage,
                          self.request, self.share_id)

    def test_wrong_permissions(self):
        share_id = 'fake'
        req = fakes.HTTPRequest.blank('/share/%s/unmanage' % share_id,
                                      use_admin_context=False)

        self.assertRaises(exception.PolicyNotAuthorized,
                          self.controller.unmanage,
                          req,
                          share_id)
