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
from webob import exc

from manila import context
from manila.services import api as service_api
from manila import test


class ServicesApiTest(test.TestCase):

    def setUp(self):
        super(ServicesApiTest, self).setUp()
        self.context = context.get_admin_context()
        self.share_rpcapi = mock.Mock()
        self.share_rpcapi.ensure_shares = mock.Mock()
        self.services_api = service_api.API()
        self.mock_object(
            self.services_api, 'share_rpcapi', self.share_rpcapi
        )

    def test_ensure_shares(self):
        host = 'fake_host@fakebackend'
        fake_service = {
            'id': 'fake_service_id',
            'state': 'up'
        }

        self.services_api.ensure_shares(self.context, fake_service, host)

        self.share_rpcapi.ensure_driver_resources.assert_called_once_with(
            self.context, host
        )

    def test_ensure_shares_host_down(self):
        host = 'fake_host@fakebackend'
        fake_service = {
            'id': 'fake_service_id',
            'state': 'down'
        }

        self.assertRaises(
            exc.HTTPConflict,
            self.services_api.ensure_shares,
            self.context,
            fake_service,
            host
        )

        self.share_rpcapi.ensure_shares.assert_not_called()
