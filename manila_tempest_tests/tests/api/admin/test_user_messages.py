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

from oslo_utils import timeutils
from oslo_utils import uuidutils
from tempest import config
from tempest.lib import decorators

from manila_tempest_tests.tests.api import base

CONF = config.CONF

MICROVERSION = '2.37'
MESSAGE_KEYS = (
    'created_at',
    'action_id',
    'detail_id',
    'expires_at',
    'id',
    'message_level',
    'request_id',
    'resource_type',
    'resource_id',
    'user_message',
    'project_id',
    'links',
)


@base.skip_if_microversion_lt(MICROVERSION)
class UserMessageTest(base.BaseSharesAdminTest):

    def setUp(self):
        super(UserMessageTest, self).setUp()
        self.message = self.create_user_message()

    @decorators.attr(type=[base.TAG_POSITIVE, base.TAG_API])
    def test_list_messages(self):
        body = self.shares_v2_client.list_messages()
        self.assertIsInstance(body, list)
        self.assertTrue(self.message['id'], [x['id'] for x in body])
        message = body[0]
        self.assertEqual(set(MESSAGE_KEYS), set(message.keys()))

    @decorators.attr(type=[base.TAG_POSITIVE, base.TAG_API])
    def test_list_messages_sorted_and_paginated(self):
        self.create_user_message()
        self.create_user_message()
        params = {'sort_key': 'resource_id', 'sort_dir': 'asc', 'limit': 2}
        body = self.shares_v2_client.list_messages(params=params)
        # tempest/lib/common/rest_client.py's _parse_resp checks
        # for number of keys in response's dict, if there is only single
        # key, it returns directly this key, otherwise it returns
        # parsed body. If limit param is used, then API returns
        # multiple keys in response ('messages' and 'message_links')
        messages = body['messages']
        self.assertIsInstance(messages, list)
        ids = [x['resource_id'] for x in messages]
        self.assertEqual(2, len(ids))
        self.assertEqual(ids, sorted(ids))

    @decorators.attr(type=[base.TAG_POSITIVE, base.TAG_API])
    def test_list_messages_filtered(self):
        self.create_user_message()
        params = {'resource_id': self.message['resource_id']}
        body = self.shares_v2_client.list_messages(params=params)
        self.assertIsInstance(body, list)
        ids = [x['id'] for x in body]
        self.assertEqual([self.message['id']], ids)

    @decorators.attr(type=[base.TAG_POSITIVE, base.TAG_API])
    def test_show_message(self):
        self.addCleanup(self.shares_v2_client.delete_message,
                        self.message['id'])

        message = self.shares_v2_client.get_message(self.message['id'])

        self.assertEqual(set(MESSAGE_KEYS), set(message.keys()))
        self.assertTrue(uuidutils.is_uuid_like(message['id']))
        self.assertEqual('001', message['action_id'])
        # don't check specific detail_id which may vary
        # depending on order of filters, we can still check
        # user_message
        self.assertIn(
            'No storage could be allocated for this share request',
            message['user_message'])
        self.assertEqual('SHARE', message['resource_type'])
        self.assertTrue(uuidutils.is_uuid_like(message['resource_id']))
        self.assertEqual('ERROR', message['message_level'])
        created_at = timeutils.parse_strtime(message['created_at'])
        expires_at = timeutils.parse_strtime(message['expires_at'])
        self.assertGreater(expires_at, created_at)
        self.assertEqual(set(MESSAGE_KEYS), set(message.keys()))

    @decorators.attr(type=[base.TAG_POSITIVE, base.TAG_API])
    def test_delete_message(self):
        self.shares_v2_client.delete_message(self.message['id'])
        self.shares_v2_client.wait_for_resource_deletion(
            message_id=self.message['id'])
