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

from manila.api.validation import helpers
from manila.api.validation import parameter_types
from manila.api.validation import response_types

CONF = cfg.CONF

# Base list snapshots query (v2.0+)
index_request_query = {
    'type': 'object',
    'properties': {
        # Pagination
        'limit': parameter_types.single_param(
            parameter_types.non_negative_integer
        ),
        'offset': parameter_types.single_param(
            parameter_types.non_negative_integer
        ),

        # Sorting
        'sort_key': parameter_types.single_param({
            'type': 'string',
            'minLength': 1,
            'maxLength': 255,
        }),
        'sort_dir': parameter_types.single_param({
            'type': 'string',
            'default': 'desc',
            'description': 'Sort direction',
        }),

        # Project Scoping
        'project_id': parameter_types.single_param({
            'type': 'string',
            'minLength': 1,
            'maxLength': 255,
        }),
        # Admin only
        'all_tenants': parameter_types.single_param({
            **parameter_types.boolean,
            'description': (
                "Set 1 to list resources for all projects;"
                "set 0 to list resources only for the current project"
            )
        }),

        # Basic filters
        'name': parameter_types.single_param({
            'type': 'string',
            'minLength': 1,
            'maxLength': 255,
        }),
        'description': parameter_types.single_param({
            'type': 'string',
            'minLength': 1,
            'maxLength': 255,
        }),
        'status': parameter_types.single_param({
            'type': 'string',
            'minLength': 1,
            'maxLength': 255,
        }),
        'share_id': parameter_types.single_param({
            'type': 'string',
            'minLength': 1,
            'maxLength': 255,
        }),
        'size': parameter_types.single_param(
            parameter_types.non_negative_integer,
        ),
    },
    'required': [],
    'additionalProperties': True,
}

# >= v2.36: like filters for name~/description~
index_request_query_v236 = copy.copy(index_request_query)
index_request_query_v236['properties'].update({
    'name~': parameter_types.single_param({
        'type': 'string',
        'minLength': 1,
        'maxLength': 255,
    }),
    'description~': parameter_types.single_param({
        'type': 'string',
        'minLength': 1,
        'maxLength': 255
    }),
})

# >= v2.73: metadata filter
index_request_query_v273 = copy.copy(index_request_query_v236)
index_request_query_v273['properties'].update({
    'metadata': parameter_types.single_param({
        'type': 'string',
        'minLength': 1,
        'maxLength': 4096,
    }),
})

# >= v2.79: with_count flag added on top
index_request_query_v279 = copy.copy(index_request_query_v273)
index_request_query_v279['properties'].update({
    'with_count': parameter_types.single_param({
        **parameter_types.boolean,
        'default': False,
        'description': "Show count in share snapshot list API response"
    }),
})

show_request_query = {
    'type': 'object',
    'properties': {},
    'required': [],
    'additionalProperties': True,
}

_snapshot_response = {
    'type': 'object',
    'properties': {
        'id': {'type': ['string', 'integer'],
               'description': "The UUID of the snapshot."},
        'links': response_types.links,
        'name': {'type': ['string', 'null'],
                 'description': "The user-defined name of the snapshot."},
    },
    'required': ['id', 'links', 'name'],
    'additionalProperties': False,
}

index_response_body = {
    'type': 'object',
    'properties': {
        'snapshots': {
            'type': 'array',
            'items': _snapshot_response,
        },
        'share_snapshots_links': response_types.collection_links,
        # >= v2.79 when with_count=True
        'count': {'type': 'integer', 'minimum': 0},
    },
    'required': ['snapshots'],
    'additionalProperties': False,
}

show_snapshot = {
    'type': 'object',
    'properties': {
        'id': {
            'type': ['string', 'integer'],
            'description': helpers.description('snapshot_id'),
        },
        'status': {
            'type': 'string',
            'description': helpers.description('snapshot_status'),
        },
        'share_id': {
            'type': 'string',
            'description': helpers.description('snapshot_share_id'),
        },
        'name': {
            'type': ['string', 'null'],
            'description': helpers.description('name'),
        },
        'description': {
            'type': ['string', 'null'],
            'description': helpers.description('description'),
        },
        'created_at': {
            'type': 'string',
            'description': helpers.description('created_at'),
        },
        'share_proto': {
            'type': 'string',
            'description': helpers.description('snapshot_share_protocol'),
        },
        'share_size': {
            'type': ['integer', 'null'],
            'description': helpers.description('snapshot_share_size'),
        },
        'size': {
            'type': ['integer', 'null'],
            'description': helpers.description('snapshot_size'),
        },
        'links': response_types.links,
    },
    'required': [
        'id', 'status', 'share_id', 'name', 'description',
        'created_at', 'share_proto', 'share_size', 'size', 'links',
    ],
    'additionalProperties': False,
}

# >= v2.12: provider_location added
show_snapshot_v212 = copy.deepcopy(show_snapshot)
show_snapshot_v212['properties'].update({
    'provider_location': {
        'type': ['string', 'null'],
        'description': helpers.description('snapshot_provider_location'),
    },
})

# >= v2.17: project_id and user_id added
show_snapshot_v217 = copy.deepcopy(show_snapshot_v212)
show_snapshot_v217['properties'].update({
    'project_id': {
        'type': 'string',
        'description': helpers.description('snapshot_project_id'),
    },
    'user_id': {
        'type': 'string',
        'description': helpers.description('snapshot_user_id'),
    },
})
show_snapshot_v217['required'].extend(['project_id', 'user_id'])

# >= v2.73: metadata added
show_snapshot_v273 = copy.deepcopy(show_snapshot_v217)
show_snapshot_v273['properties'].update({
    'metadata': {
        'type': 'object',
        'description': helpers.description('metadata'),
        'additionalProperties': {'type': 'string'},
    },
})

# Base show response
show_response = {
    'type': 'object',
    'properties': {
        'snapshot': show_snapshot,
    },
    'required': ['snapshot'],
    'additionalProperties': False,
}

# >= v2.12 show response
show_response_v212 = copy.deepcopy(show_response)
show_response_v212['properties'].update({
    'snapshot': show_snapshot_v212,
})

# >= v2.17 show response
show_response_v217 = copy.deepcopy(show_response_v212)
show_response_v217['properties'].update({
    'snapshot': show_snapshot_v217,
})

# >= v2.73 show response
show_response_v273 = copy.deepcopy(show_response_v217)
show_response_v273['properties'].update({
    'snapshot': show_snapshot_v273,
})
