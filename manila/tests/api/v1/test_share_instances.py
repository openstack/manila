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
from oslo_config import cfg
from webob import exc as webob_exc

from manila.api.v1 import share_instances
from manila import context
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils

CONF = cfg.CONF


@ddt.ddt
class ShareInstancesApiTest(test.TestCase):
    """Share Api Test."""
    def setUp(self):
        super(ShareInstancesApiTest, self).setUp()
        self.controller = share_instances.ShareInstancesController()
        self.context = context.RequestContext('admin', 'fake', True)

    def _get_request(self, uri, context=None):
        if context is None:
            context = self.context
        req = fakes.HTTPRequest.blank('/shares', version="1.4")
        req.environ['manila.context'] = context
        return req

    def _validate_ids_in_share_instances_list(self, expected, actual):
        self.assertEqual(len(expected), len(actual))
        self.assertEqual([i['id'] for i in expected],
                         [i['id'] for i in actual])

    def test_index(self):
        req = self._get_request('/share_instances')
        share_instances_count = 3
        test_instances = [
            db_utils.create_share(size=s + 1).instance
            for s in range(0, share_instances_count)
        ]

        actual_result = self.controller.index(req)

        self._validate_ids_in_share_instances_list(
            test_instances, actual_result['share_instances'])

    def test_show(self):
        test_instance = db_utils.create_share(size=1).instance
        id = test_instance['id']

        actual_result = self.controller.show(self._get_request('fake'), id)

        self.assertEqual(id, actual_result['share_instance']['id'])

    def test_get_share_instances(self):
        test_share = db_utils.create_share(size=1)
        id = test_share['id']
        req = self._get_request('fake')

        actual_result = self.controller.get_share_instances(req, id)

        self._validate_ids_in_share_instances_list(
            [test_share.instance],
            actual_result['share_instances']
        )

    @ddt.data('show', 'get_share_instances')
    def test_not_found(self, target_method_name):
        method = getattr(self.controller, target_method_name)
        self.assertRaises(webob_exc.HTTPNotFound, method,
                          self._get_request('fake'), 'fake')

    @ddt.data(('show', 2), ('get_share_instances', 2), ('index', 1))
    @ddt.unpack
    def test_access(self, target_method_name, args_count):
        user_context = context.RequestContext('fake', 'fake')
        req = self._get_request('fake', user_context)
        target_method = getattr(self.controller, target_method_name)
        args = [i for i in range(1, args_count)]

        self.assertRaises(webob_exc.HTTPForbidden, target_method, req, *args)
