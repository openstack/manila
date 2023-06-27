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

import datetime
import iso8601

from manila.message import message_field
from manila.message import message_levels
from manila.tests.api import fakes


FAKE_UUID = fakes.FAKE_UUID


def stub_message(id, **kwargs):
    message = {
        'id': id,
        'project_id': 'fake_project',
        'action_id': message_field.Action.ALLOCATE_HOST[0],
        'message_level': message_levels.ERROR,
        'request_id': FAKE_UUID,
        'resource_type': message_field.Resource.SHARE,
        'resource_id': 'fake_uuid',
        'updated_at': datetime.datetime(1900, 1, 1, 1, 1, 1,
                                        tzinfo=iso8601.UTC),
        'created_at': datetime.datetime(1900, 1, 1, 1, 1, 1,
                                        tzinfo=iso8601.UTC),
        'expires_at': datetime.datetime(1900, 1, 1, 1, 1, 1,
                                        tzinfo=iso8601.UTC),
        'detail_id': message_field.Detail.NO_VALID_HOST[0],
    }

    message.update(kwargs)
    return message


def stub_message_get(self, context, message_id):
    return stub_message(message_id)


def stub_lock(id, **kwargs):
    lock = {
        'id': id,
        'project_id': 'f63f7a159f404cfc8604b7065c609691',
        'user_id': 'e78f4294e3534e00ae176bd989d6a682',
        'resource_id': 'c474badd-f06e-4ff9-ae26-daa00e19867b',
        'resource_action': 'delete',
        'resource_type': 'share',
        'lock_context': 'user',
        'lock_reason': 'for the tests',
        'updated_at': datetime.datetime(2023, 8, 10, 20, 4, 39,
                                        tzinfo=iso8601.UTC),
        'created_at': datetime.datetime(2023, 1, 10, 15, 3, 1,
                                        tzinfo=iso8601.UTC),
    }

    lock.update(kwargs)
    return lock
