#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
import copy

from manila.api.validation import helpers

metadata_response_body = {
    'type': 'object',
    'properties': {
        'metadata': {
            'type': ['object', 'null'],
            'patternProperties': {
                '^[a-zA-Z0-9-_:. ]{1,255}$': {
                    'type': 'string',
                },
            },
            'additionalProperties': False,
        },
    },
    'required': ['metadata'],
    'additionalProperties': False,
}

index_response_body = {
    "type": "object",
    "properties": {
        "export_locations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": helpers.description(
                            'export_location_id',
                        ),
                    },
                    "share_instance_id": {
                        "type": "string",
                        "description": helpers.description(
                            'export_location_share_instance_id',
                        ),
                    },
                    "path": {
                        "type": "string",
                        "description": helpers.description(
                            'export_location_path',
                        ),
                    },
                    "is_admin_only": {
                        "type": "boolean",
                        "description": helpers.description(
                            'export_location_is_admin_only',
                        ),
                    },
                },
                "required": ["id", "path"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["export_locations"],
    "additionalProperties": False,
}

index_response_body_v214 = copy.deepcopy(index_response_body)
index_response_body_v214['properties'][
    'export_locations'
]['items']['properties'].update({
    'preferred': {
        'type': 'boolean',
        'description': helpers.description('export_location_preferred'),
    },
})

index_response_body_v214['properties'][
    'export_locations'
]['items']['required'].append('preferred')
index_response_body_v287 = copy.deepcopy(index_response_body_v214)
index_response_body_v287['properties'][
    'export_locations'
]['items']['properties'].update({
    'metadata': {
        'type': 'object',
        'patternProperties': {
            '^[a-zA-Z0-9-_:. ]{1,255}$': {
                'type': 'string',
            },
        },
        'additionalProperties': False,
    },
})
index_response_body_v287['properties'][
    'export_locations'
]['items']['required'].append('metadata')
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
                    'description': helpers.description('created_at'),
                },
                'id': {
                    'type': 'string',
                    'readonly': True,
                    'description': helpers.description(
                        'export_location_id',
                    ),
                },
                'is_admin_only': {
                    'type': 'boolean',
                    'description': helpers.description(
                        'export_location_is_admin_only',
                    ),
                },
                'path': {
                    'type': 'string',
                    'description': helpers.description(
                        'export_location_path',
                    ),
                },
                'updated_at': {
                    'type': 'string',
                    'format': 'date-time',
                    'readonly': True,
                    'description': helpers.description('updated_at'),
                },
                'share_instance_id': {
                    'type': 'string',
                    'description': helpers.description(
                        'export_location_share_instance_id',
                    ),
                },
            },
            'required': [
                'created_at',
                'id',
                'path',
                'updated_at',
            ],
            'additionalProperties': False,
            'description': helpers.description('export_location'),
        },
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
            'description': helpers.description('export_location_preferred'),
        },
    },
)
_ex_loc['required'].append('preferred')

show_response_body_v287 = copy.deepcopy(show_response_body_v214)
show_response_body_v287['properties']['export_location'][
    'properties'].update({
        'metadata': {
            'type': 'object',
            'patternProperties': {
                '^[a-zA-Z0-9-_:. ]{1,255}$': {
                    'type': 'string',
                },
            },
            'additionalProperties': False,
        },
    },
)
show_response_body_v287['properties']['export_location'][
    'required'].append('metadata')
