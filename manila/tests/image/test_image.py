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

from manila import context
from manila.image import glance
from manila import test
from manila.tests import utils as test_utils


class FakeImageClient:

    class Image:

        def images(self, *args, **kwargs):
            return [{'id': 'id1'}, {'id': 'id2'}]

        def __getattr__(self, item):
            return None

    def __init__(self):
        self.image = self.Image()


class OpenStackClientTestCase(test.TestCase):

    @mock.patch('manila.image.glance.openstack.connection.Connection')
    @mock.patch('manila.image.glance.ks_loading.load_session_from_conf_options')  # noqa
    def test_auth(self, mock_load_session, mock_connection):
        mock_load_session.return_value = 'fake_session'
        fake_context = 'fake_context'
        data = {
            'glance': {
                'api_microversion': 'foo_api_microversion',
                'endpoint_type': 'internal',
                'region_name': 'foo_region_name'
            }
        }

        with test_utils.create_temp_config_with_opts(data):
            glance.openstackclient(fake_context)

        mock_connection.assert_called_once_with(
            session='fake_session',
            context=fake_context,
            image_version=data['glance']['api_microversion'],
            image_interface=data['glance']['endpoint_type'],
            region_name=data['glance']['region_name'],
        )


class ImageApiTestCase(test.TestCase):
    def setUp(self):
        super().setUp()

        self.api = glance.API()
        self.imageclient = FakeImageClient()
        self.ctx = context.get_admin_context()
        self.mock_object(glance, 'openstackclient',
                         mock.Mock(return_value=self.imageclient))

    def test_image_list(self):
        image_list = ['fake', 'image', 'list']

        class FakeImageClient(object):
            def images(self):
                return image_list

        self.imageclient.image = FakeImageClient()

        result = self.api.image_list(self.ctx)

        self.assertEqual(image_list, result)
