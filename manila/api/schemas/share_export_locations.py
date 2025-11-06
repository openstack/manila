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
from manila.api.validation import parameter_types

empty_query_schema = {}

show_metadata_request_body = {
    'type': 'object',
    'properties': {
        'key': {
            'type': 'string',
        }
    },
    # TODO(jonathan): Exclude additional query string parameters in a future
    #  micro-version
    'required': ['key'],
    'additionalProperties': True
}

update_metadata_request_body = {
    'type': 'object',
    'properties': {
        'metadata': parameter_types.metadata,
    },
    # TODO(jonathan): Exclude additional query string parameters in a future
    #  micro-version
    'required': ['metadata'],
    'additionalProperties': True
}

create_metadata_response_body = {
    'type': 'object',
    'properties': {
        'metadata': parameter_types.metadata,
    },
    # TODO(jonathan): Exclude additional query string parameters in a future
    #  micro-version
    'required': ['metadata'],
    'additionalProperties': True
}

delete_metadata_request_body = {
    'type': 'object',
    'properties': {
        'key': {
            'type': 'string',
        }
    },
    # TODO(jonathan): Exclude additional query string parameters in a future
    #  micro-version
    'required': ['key'],
    'additionalProperties': True
}

index_response_body = {
    'type': 'object',
    'properties': {
        'export_locations': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'id': {
                        'type': 'string',
                        'x-openstack': {'apiref': 'export_location_id'},
                    },
                    'is_admin_only': {
                        'type': 'boolean',
                        'x-openstack': {
                            'apiref': 'export_location_is_admin_only'},
                    },
                    'path': {
                        'type': 'string',
                        'x-openstack': {'apiref': 'export_location_path'},
                    },
                    'share_instance_id': {
                        'type': 'string',
                        'x-openstack': {'apiref': 'share_instance_id'},
                    },
                },
                'required': ['id', 'path'],
                'additionalProperties': False,
            },
        }
    },
    'required': ['export_locations'],
    'additionalProperties': False,
    'x-openstack': {'apiref': 'export_locations'},
}

index_response_body_v214 = copy.deepcopy(index_response_body)
index_response_body_v214['properties']['export_locations']['items'][
    'properties'
].update(
    {
        'preferred': {
            'type': 'boolean',
            'x-openstack': {'apiref': 'export_location_preferred'},
        }
    }
)
index_response_body_v214['properties']['export_locations']['items'][
    'required'].append('preferred')

index_response_body_v287 = copy.deepcopy(index_response_body_v214)
index_response_body_v287['properties']['export_locations']['items'][
    'properties'
].update({
    'metadata': {
        'type': 'object',
        'patternProperties': {
            '^[a-zA-Z0-9-_:. ]{1,255}$': {
                'type': 'string',
                }
            },
        }
    })
index_response_body_v287['properties']['export_locations']['items'][
    'required'].append('metadata')

show_response_body = {
    'type': 'object',
    'properties': {
        'export_location': {
            'type': 'object',
            'properties': {
                'created_at': {
                    'type': 'string',
                    'format': 'date-time',
                    'readonly': True,
                    'x-openstack': {
                        'apiref': 'created_at',
                    },
                },
                'id': {
                    'type': 'string',
                    'readonly': True,
                    'x-openstack': {
                        'apiref': 'export_location_id',
                    },
                },
                'is_admin_only': {
                    'type': 'boolean',
                    'x-openstack': {
                        'apiref': 'export_location_is_admin_only',
                    },
                },
                'path': {
                    'type': 'string',
                    'x-openstack': {
                        'apiref': 'export_location_path',
                    },
                },
                'updated_at': {
                    'type': 'string',
                    'format': 'date-time',
                    'readonly': True,
                    'x-openstack': {
                        'apiref': 'updated_at',
                    },
                },
                'share_instance_id': {
                    'type': 'string',
                    'x-openstack': {
                        'apiref': 'share_instance_id',
                    },
                },
            },
            'required': [
                'created_at',
                'id',
                'path',
                'updated_at',
            ],
            'additionalProperties': False,
            'x-openstack': {
                'apiref': 'export_location',
            },
        }
    },
    'required': ['export_location'],
    'additionalProperties': False,
}

show_response_body_v214 = copy.deepcopy(show_response_body)
_ex_loc = show_response_body_v214['properties']['export_location']
_ex_loc['properties'].update(
    {
        'preferred': {
            'type': 'boolean',
            'x-openstack': {
                'apiref': 'export_location_preferred'},
        }
    }
)
_ex_loc['required'].append('preferred')

show_response_body_v287 = copy.deepcopy(show_response_body_v214)
show_response_body_v287['properties']['export_location']['properties'].update({
    'metadata': parameter_types.metadata
})
(show_response_body_v287['properties']['export_location']['required']
 .append('metadata'))

show_metadata_response_body = {
    'type': 'object',
    'properties': {
        'meta': parameter_types.metadata
    },
    'required': ['meta'],
    'additionalProperties': False,
}

update_metadata_response_body = {
    'type': 'object',
    'properties': {
        'metadata': parameter_types.metadata,
    },
    'required': ['metadata'],
    'additionalProperties': False,
}
create_metadata_response_body = {
    'type': 'object',
    'properties': {
        'metadata': parameter_types.metadata,
    },
    'required': ['metadata'],
    'additionalProperties': False,
}

delete_metadata_response_body = {}
