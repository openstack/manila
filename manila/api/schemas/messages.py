# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import copy

from oslo_config import cfg

from manila.api.validation import parameter_types
from manila.api.validation import response_types

CONF = cfg.CONF


show_request_query = {
    'type': 'object',
    'properties': {},
    'required': [],
    # TODO(jonathan): Exclude additional query string parameters in a future
    # microversion
    'additionalProperties': True,
}

index_request_query = {
    'type': 'object',
    'properties': {
        'limit': parameter_types.single_param(
            parameter_types.non_negative_integer
        ),
        # NOTE(stephenfin): This is parsed by 'common.get_pagination_params'
        # but we ignore it. We may wish to uncomment this when that is no
        # longer the case
        # 'marker': parameter_types.multi_params({
        #     'type': ['string'],
        # }),
        'offset': parameter_types.single_param(
            parameter_types.non_negative_integer
        ),
        'sort_key': parameter_types.single_param({
            'type': 'string',
            'default': 'created_at',
            # TODO(stephenfin): These are the allowed (a.k.a. legal) filter
            # keys, but we currently ignore invalid keys. We should add this in
            # a future microversion.
            # 'enum': [
            #     'id',
            #     'project_id',
            #     'request_id',
            #     'resource_type',
            #     'action_id',
            #     'detail_id',
            #     'resource_id',
            #     'message_level',
            #     'expires_at',
            #     'created_at',
            # ],
        }),
        'sort_dir': parameter_types.single_param({
            'type': 'string',
            'default': 'desc',
            # TODO(stephenfin): This should be an enum, but we currently treat
            # anything != 'desc' as 'asc'. We should make this stricter in a
            # future microversion.
            # 'enum': ['asc', 'desc'],
        }),
        'action_id': parameter_types.single_param({
            'type': 'string',
        }),
        'detail_id': parameter_types.single_param({
            'type': 'string',
        }),
        # TODO(jonathan) add enum when more message level the 'ERROR'
        'message_level': parameter_types.single_param({
            'type': 'string',
        }),
        'request_id': parameter_types.single_param({
            'type': 'string',
        }),
        'resource_id': parameter_types.single_param({
            'type': 'string',
        }),
        'resource_type': parameter_types.multi_params({
            'type': 'string',
        }),
    },
    'required': [],
    # TODO(jonathan): Exclude additional query string parameters in a future
    # microversion
    'additionalProperties': True,
}

index_request_query_v252 = copy.deepcopy(index_request_query)
index_request_query_v252['properties'].update({
    'created_since': parameter_types.single_param({
        'type': 'string',
        'format': 'date-time',
    }),
    'created_before': parameter_types.single_param({
        'type': 'string',
        'format': 'date-time',
    }),
})


_messages_response = {
    'type': 'object',
    'properties': {
        'action_id': {'type': 'string'},
        'created_at': {'type': 'string', 'format': 'date-time'},
        'detail_id': {'type': 'string'},
        'expires_at': {'type': 'string', 'format': 'date-time'},
        'id': {'type': 'string', 'format': 'uuid'},
        'links': response_types.links,
        'message_level': {
            'type': 'string',
            'enum': ['ERROR'],
        },
        'project_id': {'type': 'string'},
        'request_id': {'type': 'string'},
        'resource_id': {'type': 'string', 'format': 'uuid'},
        'resource_type': {'type': 'string'},
        'user_message': {'type': 'string'},
    },
    'required': [
        'action_id',
        'created_at',
        'detail_id',
        'expires_at',
        'id',
        'links',
        'message_level',
        'project_id',
        'request_id',
        'resource_id',
        'resource_type',
        'user_message',
    ],
    'additionalProperties': False,
}

index_response_body = {
    'type': 'object',
    'properties': {
        'messages': {
            'type': 'array',
            'items': _messages_response,
        },
        'messages_links': response_types.collection_links,
    },
    'required': ['messages'],
    'additionalProperties': False,
}

show_response_body = {
    'type': 'object',
    'properties': {
        'message': _messages_response,
    },
    'required': ['message'],
    'additionalProperties': False,
}

delete_response_body = {
    'type': 'null',
}
