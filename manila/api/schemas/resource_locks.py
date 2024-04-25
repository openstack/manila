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

from manila.api.validation import helpers
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
                    'description': helpers.description(
                        'resource_lock_resource_id'
                    ),
                },
                'lock_reason': {
                    'type': ['string', 'null'],
                    'maxLength': 1023,
                    'description': helpers.description(
                        'resource_lock_lock_reason_optional'
                    ),
                },
                'resource_type': {
                    'type': ['string', 'null'],
                    'enum': constants.RESOURCE_LOCK_RESOURCE_TYPES + (None,),
                    'default': constants.SHARE_RESOURCE_TYPE,
                    'description': helpers.description(
                        'resource_lock_resource_type'
                    ),
                },
                'resource_action': {
                    'type': ['string', 'null'],
                    'enum': constants.RESOURCE_LOCK_RESOURCE_ACTIONS + (None,),
                    'default': constants.RESOURCE_ACTION_DELETE,
                    'description': helpers.description(
                        'resource_lock_resource_action_create_optional'
                    ),
                },
            },
            'required': ['resource_id'],
            'additionalProperties': False,
            'description': helpers.description('resource_lock_object'),
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
                    'description': helpers.description(
                        'resource_lock_resource_action_optional'
                    ),
                },
                'lock_reason': {
                    'type': ['string', 'null'],
                    'maxLength': 1023,
                    'description': helpers.description(
                        'resource_lock_lock_reason_optional'
                    ),
                },
            },
            'additionalProperties': False,
            'description': helpers.description('resource_lock_object'),
        },
    },
    'required': ['resource_lock'],
    'additionalProperties': True,
}

index_request_query = {
    'type': 'object',
    'properties': {
        'limit': parameter_types.multi_params({
            **parameter_types.non_negative_integer,
            'description': helpers.description('limit'),
        }),
        # NOTE(stephenfin): This is parsed by 'common.get_pagination_params'
        # but we ignore it. We may wish to uncomment this when that is no
        # longer the case
        # 'marker': parameter_types.multi_params({
        #     'type': ['string'],
        # }),
        'offset': parameter_types.multi_params({
            **parameter_types.non_negative_integer,
            'description': helpers.description('offset'),
        }),
        'sort_key': parameter_types.multi_params({
            'type': 'string',
            'default': 'created_at',
            'description': helpers.description('sort_key_resource_locks'),
        }),
        # TODO(stephenfin): Make this an enum of ['asc', 'desc']
        'sort_dir': parameter_types.multi_params({
            'type': 'string',
            'default': 'desc',
            'description': helpers.description('sort_dir'),
        }),
        'with_count': parameter_types.multi_params(parameter_types.boolean),
        'created_since': parameter_types.multi_params({
            'type': 'string',
            'format': 'date-time',
            'description': helpers.description('created_since_query'),
        }),
        'created_before': parameter_types.multi_params({
            'type': 'string',
            'format': 'date-time',
            'description': helpers.description('created_before_query'),
        }),
        'project_id': parameter_types.multi_params({
            'type': ['string', 'null'],
            'format': 'uuid',
            'description': helpers.description(
                'resource_lock_project_id_query'
            ),
        }),
        'user_id': parameter_types.multi_params({
            'type': ['string', 'null'],
            'format': 'uuid',
            'description': helpers.description('resource_lock_user_id_query')
        }),
        'resource_id': parameter_types.multi_params({
            'type': ['string', 'null'],
            'format': 'uuid',
            'description': helpers.description(
                'resource_lock_resource_id_query'
            ),
        }),
        'resource_action': parameter_types.multi_params({
            'type': ['string', 'null'],
            'enum': constants.RESOURCE_LOCK_RESOURCE_ACTIONS + (None,),
            'description': helpers.description(
                'resource_lock_resource_action_query'
            ),
        }),
        'resource_type': parameter_types.multi_params({
            'type': ['string', 'null'],
            'enum': constants.RESOURCE_LOCK_RESOURCE_TYPES + (None,),
            'description': helpers.description(
                'resource_lock_resource_type_query'
            ),
        }),
        'all_projects': parameter_types.multi_params({
            **parameter_types.boolean,
            'description': helpers.description(
                'resource_lock_all_projects_query'
            ),
        }),
        'lock_context': parameter_types.multi_params({
            'type': ['string', 'null'],
            'maxLength': 10,
            'description': helpers.description(
                'resource_lock_lock_context_query'
            ),
        }),
        'lock_reason': parameter_types.multi_params({
            'type': ['string', 'null'],
            'maxLength': 1023,
            'description': helpers.description(
                'resource_lock_lock_reason_query'
            ),
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
            'description': helpers.description('resource_lock_id'),
        },
        'user_id': {
            'type': 'string',
            'format': 'uuid',
            'description': helpers.description('resource_lock_user_id'),
        },
        'project_id': {
            'type': 'string',
            'format': 'uuid',
            'description': helpers.description('resource_lock_project_id'),
        },
        'lock_context': {
            'type': 'string',
            'description': helpers.description('resource_lock_lock_context'),
        },
        'resource_type': {
            'type': 'string',
            'enum': constants.RESOURCE_LOCK_RESOURCE_TYPES,
            'description': helpers.description('resource_lock_resource_type'),
        },
        'resource_id': {
            'type': 'string',
            'format': 'uuid',
            'description': helpers.description('resource_lock_resource_id'),
        },
        'resource_action': {
            'type': 'string',
            'enum': constants.RESOURCE_LOCK_RESOURCE_ACTIONS,
            'description': helpers.description(
                'resource_lock_resource_action'
            ),
        },
        'lock_reason': {
            'type': ['string', 'null'],
            'description': helpers.description('resource_lock_lock_reason'),
        },
        'created_at': {
            'type': 'string',
            'format': 'date-time',
            'description': helpers.description('created_at'),
        },
        'updated_at': {
            'type': ['string', 'null'],
            'format': 'date-time',
            'description': helpers.description('updated_at'),
        },
        'links': response_types.links,
    },
    'description': helpers.description('resource_lock_object'),
    'required': [
        'id',
        'user_id',
        'project_id',
        'lock_context',
        'resource_type',
        'resource_id',
        'resource_action',
        'lock_reason',
        'created_at',
        'updated_at',
        'links',
    ],
    'additionalProperties': False,
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
            'description': helpers.description('count_without_min_version'),
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
