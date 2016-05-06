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

import mock
from oslo_config import cfg
import webob

from manila.api.v2 import messages
from manila import context
from manila import exception
from manila.message import api as message_api
from manila.message import message_field
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila.tests.api.v2 import stubs

CONF = cfg.CONF


class MessageApiTest(test.TestCase):
    def setUp(self):
        super(MessageApiTest, self).setUp()
        self.controller = messages.MessagesController()

        self.maxDiff = None
        self.ctxt = context.RequestContext('admin', 'fake', True)
        self.mock_object(policy, 'check_policy',
                         mock.Mock(return_value=True))

    def _expected_message_from_controller(self, id):
        message = stubs.stub_message(id)
        links = [
            {'href': 'http://localhost/v2/fake/messages/%s' % id,
             'rel': 'self'},
            {'href': 'http://localhost/fake/messages/%s' % id,
             'rel': 'bookmark'},
        ]
        return {
            'message': {
                'id': message.get('id'),
                'project_id': message.get('project_id'),
                'user_message': "%s: %s" % (
                    message_field.translate_action(message.get('action_id')),
                    message_field.translate_detail(message.get('detail_id'))),
                'request_id': message.get('request_id'),
                'action_id': message.get('action_id'),
                'detail_id': message.get('detail_id'),
                'created_at': message.get('created_at'),
                'message_level': message.get('message_level'),
                'expires_at': message.get('expires_at'),
                'links': links,
                'resource_type': message.get('resource_type'),
                'resource_id': message.get('resource_id'),
            }
        }

    def test_show(self):
        self.mock_object(message_api.API, 'get', stubs.stub_message_get)

        req = fakes.HTTPRequest.blank(
            '/messages/%s' % fakes.FAKE_UUID,
            version=messages.MESSAGES_BASE_MICRO_VERSION,
            base_url='http://localhost/v2')
        req.environ['manila.context'] = self.ctxt

        res_dict = self.controller.show(req, fakes.FAKE_UUID)

        ex = self._expected_message_from_controller(fakes.FAKE_UUID)
        self.assertEqual(ex, res_dict)

    def test_show_with_resource(self):
        resource_type = "FAKE_RESOURCE"
        resource_id = "b1872cb2-4c5f-4072-9828-8a51b02926a3"
        fake_message = stubs.stub_message(fakes.FAKE_UUID,
                                          resource_type=resource_type,
                                          resource_id=resource_id)
        mock_get = mock.Mock(return_value=fake_message)
        self.mock_object(message_api.API, 'get', mock_get)

        req = fakes.HTTPRequest.blank(
            '/messages/%s' % fakes.FAKE_UUID,
            version=messages.MESSAGES_BASE_MICRO_VERSION,
            base_url='http://localhost/v2')
        req.environ['manila.context'] = self.ctxt

        res_dict = self.controller.show(req, fakes.FAKE_UUID)

        self.assertEqual(resource_type,
                         res_dict['message']['resource_type'])
        self.assertEqual(resource_id,
                         res_dict['message']['resource_id'])

    def test_show_not_found(self):
        fake_not_found = exception.MessageNotFound(message_id=fakes.FAKE_UUID)
        self.mock_object(message_api.API, 'get',
                         mock.Mock(side_effect=fake_not_found))

        req = fakes.HTTPRequest.blank(
            '/messages/%s' % fakes.FAKE_UUID,
            version=messages.MESSAGES_BASE_MICRO_VERSION,
            base_url='http://localhost/v2')
        req.environ['manila.context'] = self.ctxt

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.show,
                          req, fakes.FAKE_UUID)

    def test_show_pre_microversion(self):
        self.mock_object(message_api.API, 'get', stubs.stub_message_get)

        req = fakes.HTTPRequest.blank('/messages/%s' % fakes.FAKE_UUID,
                                      version='2.35',
                                      base_url='http://localhost/v2')
        req.environ['manila.context'] = self.ctxt

        self.assertRaises(exception.VersionNotFoundForAPIMethod,
                          self.controller.show, req, fakes.FAKE_UUID)

    def test_delete(self):
        self.mock_object(message_api.API, 'get', stubs.stub_message_get)
        self.mock_object(message_api.API, 'delete')

        req = fakes.HTTPRequest.blank(
            '/messages/%s' % fakes.FAKE_UUID,
            version=messages.MESSAGES_BASE_MICRO_VERSION)
        req.environ['manila.context'] = self.ctxt

        resp = self.controller.delete(req, fakes.FAKE_UUID)

        self.assertEqual(204, resp.status_int)
        self.assertTrue(message_api.API.delete.called)

    def test_delete_not_found(self):
        fake_not_found = exception.MessageNotFound(message_id=fakes.FAKE_UUID)
        self.mock_object(message_api.API, 'get',
                         mock.Mock(side_effect=fake_not_found))

        req = fakes.HTTPRequest.blank(
            '/messages/%s' % fakes.FAKE_UUID,
            version=messages.MESSAGES_BASE_MICRO_VERSION)

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.delete,
                          req, fakes.FAKE_UUID)

    def test_index(self):
        msg1 = stubs.stub_message(fakes.get_fake_uuid())
        msg2 = stubs.stub_message(fakes.get_fake_uuid())
        self.mock_object(message_api.API, 'get_all', mock.Mock(
                         return_value=[msg1, msg2]))
        req = fakes.HTTPRequest.blank(
            '/messages',
            version=messages.MESSAGES_BASE_MICRO_VERSION,
            base_url='http://localhost/v2')
        req.environ['manila.context'] = self.ctxt

        res_dict = self.controller.index(req)

        ex1 = self._expected_message_from_controller(msg1['id'])['message']
        ex2 = self._expected_message_from_controller(msg2['id'])['message']
        expected = {'messages': [ex1, ex2]}
        self.assertDictMatch(expected, res_dict)

    def test_index_with_limit_and_offset(self):
        msg1 = stubs.stub_message(fakes.get_fake_uuid())
        msg2 = stubs.stub_message(fakes.get_fake_uuid())
        self.mock_object(message_api.API, 'get_all', mock.Mock(
                         return_value=[msg1, msg2]))
        req = fakes.HTTPRequest.blank(
            '/messages?limit=1&offset=1',
            version=messages.MESSAGES_BASE_MICRO_VERSION,
            base_url='http://localhost/v2')
        req.environ['manila.context'] = self.ctxt

        res_dict = self.controller.index(req)

        ex2 = self._expected_message_from_controller(msg2['id'])['message']
        self.assertEqual([ex2], res_dict['messages'])
