# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2011 OpenStack LLC.
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
import iso8601
import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
import webob

from manila.api import extensions
from manila.api.v1 import router
from manila import policy
from manila import test

CONF = cfg.CONF
NS = "{http://docs.openstack.org/common/api/v1.0}"


class ExtensionTestCase(test.TestCase):
    def setUp(self):
        super(ExtensionTestCase, self).setUp()
        ext_list = CONF.osapi_share_extension[:]
        fox = ('manila.tests.api.extensions.foxinsocks.Foxinsocks')
        if fox not in ext_list:
            ext_list.append(fox)
            self.flags(osapi_share_extension=ext_list)


class ExtensionControllerTest(ExtensionTestCase):

    def setUp(self):
        super(ExtensionControllerTest, self).setUp()
        self.ext_list = []
        self.ext_list.sort()

    def test_list_extensions_json(self):
        app = router.APIRouter()
        request = webob.Request.blank("/fake/extensions")
        response = request.get_response(app)
        self.assertEqual(200, response.status_int)

        # Make sure we have all the extensions, extra extensions being OK.
        data = jsonutils.loads(response.body)
        names = [str(x['name']) for x in data['extensions']
                 if str(x['name']) in self.ext_list]
        names.sort()
        self.assertEqual(self.ext_list, names)

        # Ensure all the timestamps are valid according to iso8601
        for ext in data['extensions']:
            iso8601.parse_date(ext['updated'])

        # Make sure that at least Fox in Sox is correct.
        (fox_ext, ) = [
            x for x in data['extensions'] if x['alias'] == 'FOXNSOX']
        self.assertEqual(
            {'name': 'Fox In Socks',
             'updated': '2011-01-22T13:25:27-06:00',
             'description': 'The Fox In Socks Extension.',
             'alias': 'FOXNSOX',
             'links': []},
            fox_ext)

        for ext in data['extensions']:
            url = '/fake/extensions/%s' % ext['alias']
            request = webob.Request.blank(url)
            response = request.get_response(app)
            output = jsonutils.loads(response.body)
            self.assertEqual(ext['alias'], output['extension']['alias'])

    def test_get_extension_json(self):
        app = router.APIRouter()
        request = webob.Request.blank("/fake/extensions/FOXNSOX")
        response = request.get_response(app)
        self.assertEqual(200, response.status_int)

        data = jsonutils.loads(response.body)
        self.assertEqual(
            {"name": "Fox In Socks",
             "updated": "2011-01-22T13:25:27-06:00",
             "description": "The Fox In Socks Extension.",
             "alias": "FOXNSOX",
             "links": []},
            data['extension'])

    def test_get_non_existing_extension_json(self):
        app = router.APIRouter()
        request = webob.Request.blank("/fake/extensions/4")
        response = request.get_response(app)
        self.assertEqual(404, response.status_int)


@ddt.ddt
class ExtensionAuthorizeTestCase(test.TestCase):

    @ddt.unpack
    @ddt.data({'action': 'fake', 'valid': 'api_extension:fake:fake'},
              {'action': None, 'valid': 'api_extension:fake'})
    def test_extension_authorizer(self, action, valid):
        self.mock_object(policy, 'enforce')
        target = 'fake'

        extensions.extension_authorizer('api', 'fake')(
            {}, target, action)

        policy.enforce.assert_called_once_with(mock.ANY, valid, target)

    def test_extension_authorizer_empty_target(self):
        self.mock_object(policy, 'enforce')
        target = None
        context = mock.Mock()
        context.project_id = 'fake'
        context.user_id = 'fake'

        extensions.extension_authorizer('api', 'fake')(
            context, target, 'fake')

        policy.enforce.assert_called_once_with(
            mock.ANY, mock.ANY, {'project_id': 'fake', 'user_id': 'fake'})
