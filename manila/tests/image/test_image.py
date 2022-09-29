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


class FakeGlanceClient(object):

    class Image(object):

        def list(self, *args, **kwargs):
            return [{'id': 'id1'}, {'id': 'id2'}]

        def __getattr__(self, item):
            return None

    def __init__(self):
        self.image = self.Image()


def get_fake_auth_obj():
    return type('FakeAuthObj', (object, ), {'get_client': mock.Mock()})


class GlanceClientTestCase(test.TestCase):

    @mock.patch('manila.image.glance.AUTH_OBJ', None)
    def test_no_auth_obj(self):
        mock_client_loader = self.mock_object(
            glance.client_auth, 'AuthClientLoader')
        fake_context = 'fake_context'
        data = {
            'glance': {
                'api_microversion': 'foo_api_microversion',
                'endpoint_type': 'internal',
                'region_name': 'foo_region_name'
            }
        }

        with test_utils.create_temp_config_with_opts(data):
            glance.glanceclient(fake_context)

        mock_client_loader.assert_called_once_with(
            client_class=glance.glance_client.Client,
            cfg_group=glance.GLANCE_GROUP
        )
        mock_client_loader.return_value.get_client.assert_called_once_with(
            fake_context,
            version=data['glance']['api_microversion'],
            interface=data['glance']['endpoint_type'],
            region_name=data['glance']['region_name']
        )

    @mock.patch('manila.image.glance.AUTH_OBJ', get_fake_auth_obj())
    def test_with_auth_obj(self):
        fake_context = 'fake_context'
        data = {
            'glance': {
                'api_microversion': 'foo_api_microversion',
                'endpoint_type': 'internal',
                'region_name': 'foo_region_name'
            }
        }

        with test_utils.create_temp_config_with_opts(data):
            glance.glanceclient(fake_context)

        glance.AUTH_OBJ.get_client.assert_called_once_with(
            fake_context,
            version=data['glance']['api_microversion'],
            interface=data['glance']['endpoint_type'],
            region_name=data['glance']['region_name']
        )


class GlanceApiTestCase(test.TestCase):
    def setUp(self):
        super(GlanceApiTestCase, self).setUp()

        self.api = glance.API()
        self.glanceclient = FakeGlanceClient()
        self.ctx = context.get_admin_context()
        self.mock_object(glance, 'glanceclient',
                         mock.Mock(return_value=self.glanceclient))

    def test_image_list_glanceclient_has_no_proxy(self):
        image_list = ['fake', 'image', 'list']

        class FakeGlanceClient(object):
            def list(self):
                return image_list

        self.glanceclient.glance = FakeGlanceClient()

        result = self.api.image_list(self.ctx)

        self.assertEqual(image_list, result)

    def test_image_list_glanceclient_has_proxy(self):
        image_list1 = ['fake', 'image', 'list1']
        image_list2 = ['fake', 'image', 'list2']

        class FakeImagesClient(object):
            def list(self):
                return image_list1

        class FakeGlanceClient(object):
            def list(self):
                return image_list2

        self.glanceclient.images = FakeImagesClient()
        self.glanceclient.glance = FakeGlanceClient()

        result = self.api.image_list(self.ctx)

        self.assertEqual(image_list1, result)
