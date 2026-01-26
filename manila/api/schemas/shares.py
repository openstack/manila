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
from manila.common import constants


_status = {
    'type': 'string',
    'enum': list(constants.SHARE_STATUSES),
}

reset_status_request_body = {
    'type': 'object',
    'properties': {
        'os-reset_status': {
            'type': 'object',
            'properties': {
                # TODO(stephenfin): Remove the os-status in a future
                # microversion and make 'status' required
                'os-status': _status,
                'status': _status,
            },
            'required': [],
            # TODO(stephenfin): Set to False in a future microversion
            'additionalProperties': True,
        },
    },
    'required': ['os-reset_status'],
    'additionalProperties': False,
}

reset_status_request_body_v27 = copy.deepcopy(reset_status_request_body)
reset_status_request_body_v27['properties']['reset_status'] = (
    reset_status_request_body_v27['properties'].pop('os-reset_status')
)
reset_status_request_body_v27['required'] = ['reset_status']

force_delete_request_body = {
    'type': 'object',
    'properties': {
        # TODO(stephenfin): We should restrict this to 'null' in a future
        # microversion
        'os-force_delete': {},
    },
    'required': ['os-force_delete'],
    'additionalProperties': False,
}

force_delete_request_body_v27 = copy.deepcopy(force_delete_request_body)
force_delete_request_body_v27['properties']['force_delete'] = (
    force_delete_request_body_v27['properties'].pop('os-force_delete')
)
force_delete_request_body_v27['required'] = ['force_delete']

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

migration_start_request_body = {
    'type': 'object',
    'properties': {
        'migration_start': {
            'type': 'object',
            'properties': {
                'force_host_assisted_migration': parameter_types.boolean,
                # TODO(stephenfin): Add pattern for `host@backend#pool`
                'host': {'type': 'string'},
                # TODO(stephenfin): Should we enforce format=uuid here?
                'new_share_network_id': {'type': ['string', 'null']},
                'new_share_type_id': {'type': ['string', 'null']},
                'nondisruptive': parameter_types.boolean,
                'preserve_metadata': parameter_types.boolean,
                'preserve_snapshots': parameter_types.boolean,
                'writable': parameter_types.boolean,
            },
            'required': [
                'host',
                'nondisruptive',
                'preserve_metadata',
                'preserve_snapshots',
                'writable',
            ],
            # TODO(stephenfin): Set to False in a future microversion
            'additionalProperties': True,
        },
    },
    'required': ['migration_start'],
    'additionalProperties': False,
}


migration_complete_request_body = {
    'type': 'object',
    'properties': {
        # TODO(stephenfin): We should restrict this to 'null' in a future
        # microversion
        'migration_complete': {},
    },
    'required': ['migration_complete'],
    'additionalProperties': False,
}

migration_cancel_request_body = {
    'type': 'object',
    'properties': {
        # TODO(stephenfin): We should restrict this to 'null' in a future
        # microversion
        'migration_cancel': {},
    },
    'required': ['migration_cancel'],
    'additionalProperties': False,
}

migration_get_progress_request_body = {
    'type': 'object',
    'properties': {
        # TODO(stephenfin): We should restrict this to 'null' in a future
        # microversion
        'migration_get_progress': {},
    },
    'required': ['migration_get_progress'],
    'additionalProperties': False,
}

_task_state = {
    'type': ['string', 'null'],
    'enum': constants.TASK_STATE_STATUSES,
}

reset_task_state_request_body = {
    'type': 'object',
    'properties': {
        'reset_task_state': {
            'type': 'object',
            'properties': {
                # TODO(stephenfin): Remove os-task_state field in a future
                # microversion and make task_state required
                'os-task_state': _task_state,
                'task_state': _task_state,
            },
            'required': [],
            # TODO(stephenfin): Set to False in a future microversion
            'additionalProperties': True,
        },
    },
    'required': ['reset_task_state'],
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

unmanage_request_body = {
    'type': 'object',
    'properties': {
        # TODO(stephenfin): We should restrict this to 'null' in a future
        # microversion
        'unmanage': {},
    },
    'required': ['unmanage'],
    'additionalProperties': False,
}

revert_request_body = {
    'type': 'object',
    'properties': {
        # TODO(stephenfin): We should restrict this to 'null' in a future
        # microversion
        'revert': {
            'type': 'object',
            'properties': {
                'snapshot_id': {
                    'type': 'string', 'format': 'uuid'
                },
            },
            'required': ['snapshot_id'],
            # TODO(stephenfin): Set to False in a future microversion
            'additionalProperties': True,
        },
    },
    'required': ['revert'],
    'additionalProperties': False,
}

reset_status_response_body = {'type': 'null'}

force_delete_response_body = {'type': 'null'}

soft_delete_response_body = {'type': 'null'}

restore_response_body = {'type': 'null'}

migration_start_response_body = {'type': 'null'}

migration_complete_response_body = {'type': 'null'}

migration_cancel_response_body = {'type': 'null'}

migration_get_progress_response_body = {
    'type': 'object',
    'properties': {
        'task_state': {

        },
        'total_progress': {'type': 'integer', 'min': 0, 'max': 100},
    },
    'required': ['task_state', 'total_progress'],
    'additionalProperties': False,
}

migration_get_progress_response_body_v259 = copy.deepcopy(
    migration_get_progress_response_body
)
migration_get_progress_response_body_v259['properties'].update({
    # TODO(stephenfin): What is the type of this?
    'details': {},
})
migration_get_progress_response_body_v259['required'].append('details')

reset_task_state_response_body = {'type': 'null'}

extend_response_body = {'type': 'null'}

shrink_response_body = {'type': 'null'}

unmanage_response_body = {'type': 'null'}

revert_response_body = {'type': 'null'}
