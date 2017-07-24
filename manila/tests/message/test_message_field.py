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

from manila import exception
from manila.message import message_field
from manila import test

CONF = cfg.CONF


@ddt.ddt
class MessageFieldTest(test.TestCase):

    @ddt.data(message_field.Action, message_field.Detail)
    def test_unique_ids(self, cls):
        """Assert that no action or detail id is duplicated."""
        ids = [name[0] for name in cls.ALL]
        self.assertEqual(len(ids), len(set(ids)))

    @ddt.data({'id': '001', 'content': 'allocate host'},
              {'id': 'invalid', 'content': None})
    @ddt.unpack
    def test_translate_action(self, id, content):
        result = message_field.translate_action(id)
        if content is None:
            content = 'unknown action'
        self.assertEqual(content, result)

    @ddt.data({'id': '001',
               'content': 'An unknown error occurred.'},
              {'id': '002',
               'content': 'No storage could be allocated for this share '
                          'request. Trying again with a different size or '
                          'share type may succeed.'},
              {'id': 'invalid', 'content': None})
    @ddt.unpack
    def test_translate_detail(self, id, content):
        result = message_field.translate_detail(id)
        if content is None:
            content = 'An unknown error occurred.'
        self.assertEqual(content, result)

    @ddt.data({'exception': exception.NoValidHost(reason='fake reason'),
               'detail': '', 'expected': '002'},
              {'exception': exception.NoValidHost(
                  detail_data={'last_filter': 'CapacityFilter'},
                  reason='fake reason'),
               'detail': '', 'expected': '009'},
              {'exception': exception.NoValidHost(
                  detail_data={'last_filter': 'FakeFilter'},
                  reason='fake reason'),
               'detail': '', 'expected': '002'},
              {'exception': None, 'detail': message_field.Detail.NO_VALID_HOST,
               'expected': '002'})
    @ddt.unpack
    def test_translate_detail_id(self, exception, detail, expected):
        result = message_field.translate_detail_id(exception, detail)
        self.assertEqual(expected, result)
