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

from oslo_config import cfg

from manila.api.validation import parameter_types
from manila.api.validation import response_types
from manila.common import constants

CONF = cfg.CONF

# TODO(stephenfin): Reject additional properties in a future microversion
create_request_body = {
    'type': 'object',
    'properties': {
        'resource_lock': {
            'type': 'object',
            'properties': {
                'resource_id': {
                    'type': 'string',
                    'format': 'uuid',
                },
                'lock_reason': {
                    'type': ['string', 'null'],
                    'maxLength': 1023,
                },
                'resource_type': {
                    'type': ['string', 'null'],
                    'enum': constants.RESOURCE_LOCK_RESOURCE_TYPES + (None,),
                    'default': constants.SHARE_RESOURCE_TYPE,
                },
                'resource_action': {
                    'type': ['string', 'null'],
                    'enum': constants.RESOURCE_LOCK_RESOURCE_ACTIONS + (None,),
                    'default': constants.RESOURCE_ACTION_DELETE,
                },
            },
            'required': ['resource_id'],
            'additionalProperties': False,
        },
    },
    'required': ['resource_lock'],
    'additionalProperties': True,
}

update_request_body = {
    'type': 'object',
    'properties': {
        'resource_lock': {
            'type': 'object',
            'properties': {
                'resource_action': {
                    'type': ['string', 'null'],
                    'enum': constants.RESOURCE_LOCK_RESOURCE_ACTIONS + (None,),
                },
                'lock_reason': {
                    'type': ['string', 'null'],
                    'maxLength': 1023,
                },
            },
            'additionalProperties': False,
        },
    },
    'required': ['resource_lock'],
    'additionalProperties': True,
}

index_request_query = {
    'type': 'object',
    'properties': {
        'limit': parameter_types.multi_params(
            parameter_types.non_negative_integer
        ),
        'marker': parameter_types.multi_params({
            'type': ['string'],
        }),
        'offset': parameter_types.multi_params(
            parameter_types.non_negative_integer
        ),
        'sort_key': parameter_types.multi_params({
            'type': 'string',
            'default': 'created_at',
        }),
        # TODO(stephenfin): Make this an enum of ['asc', 'desc']
        'sort_dir': parameter_types.multi_params({
            'type': 'string',
            'default': 'desc',
        }),
        'with_count': parameter_types.multi_params(parameter_types.boolean),
        'created_since': parameter_types.multi_params({
            'type': 'string',
            'format': 'date-time',
        }),
        'created_before': parameter_types.multi_params({
            'type': 'string',
            'format': 'date-time',
        }),
        'project_id': parameter_types.multi_params({
            'type': ['string', 'null'],
            'format': 'uuid',
        }),
        'user_id': parameter_types.multi_params({
            'type': ['string', 'null'],
            'format': 'uuid',
        }),
        'resource_id': parameter_types.multi_params({
            'type': ['string', 'null'],
            'format': 'uuid',
        }),
        'resource_action': parameter_types.multi_params({
            'type': ['string', 'null'],
            'enum': constants.RESOURCE_LOCK_RESOURCE_ACTIONS + (None,),
        }),
        'resource_type': parameter_types.multi_params({
            'type': ['string', 'null'],
            'enum': constants.RESOURCE_LOCK_RESOURCE_TYPES + (None,),
        }),
        'all_projects': parameter_types.multi_params(parameter_types.boolean),
        'lock_context': parameter_types.multi_params({
            'type': ['string', 'null'],
            'maxLength': 10,
        }),
        'lock_reason': parameter_types.multi_params({
            'type': ['string', 'null'],
            'maxLength': 1023,
        }),
    },
    # TODO(stephenfin): Exclude additional query string parameters in a future
    # microversion
    'additionalProperties': True,
}

show_request_query = {
    'type': 'object',
    'properties': {},
    # TODO(stephenfin): Exclude additional query string parameters in a future
    # microversion
    'additionalProperties': True,
}

_resource_lock_response = {
    'type': 'object',
    'properties': {
        'id': {
            'type': 'string',
            'format': 'uuid',
        },
        'user_id': {
            'type': 'string',
            'format': 'uuid',
        },
        'project_id': {
            'type': 'string',
            'format': 'uuid',
        },
        'lock_context': {
            'type': 'string',
        },
        'resource_type': {
            'type': 'string',
            'enum': constants.RESOURCE_LOCK_RESOURCE_TYPES,
        },
        'resource_id': {
            'type': 'string',
            'format': 'uuid',
        },
        'resource_action': {
            'type': 'string',
            'enum': constants.RESOURCE_LOCK_RESOURCE_ACTIONS,
        },
        'lock_reason': {
            'type': ['string', 'null'],
        },
        'created_at': {
            'type': 'string',
            'format': 'date-time',
        },
        'updated_at': {
            'type': ['string', 'null'],
            'format': 'date-time',
        },
        'links': response_types.links,
    },
}

create_response_body = {
    'type': 'object',
    'properties': {
        'resource_lock': _resource_lock_response,
    },
    'required': ['resource_lock'],
    'additionalProperties': False,
}

index_response_body = {
    'type': 'object',
    'properties': {
        'resource_locks': {
            'type': 'array',
            'items': _resource_lock_response,
        },
        'count': {
            'type': 'integer',
        },
        'resource_locks_links': response_types.collection_links,
    },
    'required': ['resource_locks'],
    'additionalProperties': False,
}

show_response_body = {
    'type': 'object',
    'properties': {
        'resource_lock': _resource_lock_response,
    },
    'required': ['resource_lock'],
    'additionalProperties': False,
}

update_response_body = {
    'type': 'object',
    'properties': {
        'resource_lock': _resource_lock_response,
    },
    'required': ['resource_lock'],
    'additionalProperties': False,
}

delete_response_body = {
    'type': 'null',
}
