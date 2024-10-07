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


soft_delete_request_body = {
    'type': 'object',
    'properties': {
        # TODO(stephenfin): We should restrict this to 'null' in a future
        # microversion
        'soft_delete': {},
    },
    'required': ['soft_delete'],
    'additionalProperties': False,
}

restore_request_body = {
    'type': 'object',
    'properties': {
        # TODO(stephenfin): We should restrict this to 'null' in a future
        # microversion
        'restore': {},
    },
    'required': ['restore'],
    'additionalProperties': False,
}

extend_request_body = {
    'type': 'object',
    'properties': {
        'os-extend': {
            'type': 'object',
            'properties': {
                'new_size': parameter_types.non_negative_integer,
            },
            'required': ['new_size'],
            # TODO(stephenfin): Set to False in a future microversion
            'additionalProperties': True,
        }
    },
    'required': ['os-extend'],
    'additionalProperties': False,
}

extend_request_body_v27 = copy.deepcopy(extend_request_body)
extend_request_body_v27['properties']['extend'] = (
    extend_request_body_v27['properties'].pop('os-extend')
)
extend_request_body_v27['required'] = ['extend']

extend_request_body_v264 = copy.deepcopy(extend_request_body_v27)
extend_request_body_v264['properties']['extend']['properties'].update({
    'force': parameter_types.boolean
})

shrink_request_body = {
    'type': 'object',
    'properties': {
        'os-shrink': {
            'type': 'object',
            'properties': {
                'new_size': parameter_types.non_negative_integer,
            },
            'required': ['new_size'],
            # TODO(stephenfin): Set to False in a future microversion
            'additionalProperties': True,
        }
    },
    'required': ['os-shrink'],
    'additionalProperties': False,
}

shrink_request_body_v27 = copy.deepcopy(shrink_request_body)
shrink_request_body_v27['properties']['shrink'] = (
    shrink_request_body_v27['properties'].pop('os-shrink')
)
shrink_request_body_v27['required'] = ['shrink']

soft_delete_response_body = {'type': 'null'}

restore_response_body = {'type': 'null'}

extend_response_body = {'type': 'null'}

shrink_response_body = {'type': 'null'}
