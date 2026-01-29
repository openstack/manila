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


from manila.api.validation import helpers
from manila.api.validation import parameter_types

_request_quota_prop = {
    'type': 'object',
    'properties': {
        'gigabytes': {
            'type': 'integer',
            'description': helpers.description('quota_gigabytes_request'),
        },
        'shares': {
            'type': 'integer',
            'description': helpers.description('quota_shares_request'),
        },
        'share_networks': {
            'type': 'integer',
            'description': helpers.description('quota_share_networks_request'),
        },
        'share_groups': {
            'type': 'integer',
            'description': helpers.description('quota_share_groups_request'),
        },
        'snapshot_gigabytes': {
            'type': 'integer',
            'description': helpers.description(
                'quota_snapshot_gigabytes_request'
            ),
        },
        'snapshots': {
            'type': 'integer',
            'description': helpers.description('quota_snapshots_request'),
        },
    },
    'description': helpers.description('quota_class_set'),
    # TODO(jonathan): Exclude additional query string parameters
    #  in a future microversion
    'additionalProperties': True,
}
_request_quota_prop_v253 = copy.deepcopy(_request_quota_prop)
_request_quota_prop_v253['properties'].update(
    {
        'share_replicas': {
            'type': 'integer',
            'description': helpers.description('quota_share_replicas_request'),
        },
        'replica_gigabytes': {
            'type': 'integer',
            'description': helpers.description(
                'quota_replica_gigabytes_request'
            ),
        },
    }
)

_request_quota_prop_v262 = copy.deepcopy(_request_quota_prop_v253)
_request_quota_prop_v262['properties'].update(
    {
        'per_share_gigabytes': parameter_types.single_param(
            {
                'type': 'integer',
                'description': helpers.description(
                    'quota_per_share_gigabytes_request'
                ),
            }
        )
    }
)

_request_quota_prop_v280 = copy.deepcopy(_request_quota_prop_v262)
_request_quota_prop_v280['properties'].update(
    {
        'backups': parameter_types.single_param({
            'type': 'integer',
            'description': helpers.description('quota_backups_request'),
        }),
        'backup_gigabytes': parameter_types.single_param(
            {
                'type': 'integer',
                'description': helpers.description(
                    'quota_backup_gigabytes_request'
                ),
            }
        ),
    }
)

_request_quota_prop_v290 = copy.deepcopy(_request_quota_prop_v280)
_request_quota_prop_v290['properties'].update(
    {
        'encryption_keys': parameter_types.single_param({
            'type': 'integer',
            'description': helpers.description(
                'quota_encryption_keys_request'
            ),
        }),
    }
)

show_request_query = {
    'type': 'object',
    'properties': {},
    # TODO(jonathan): Exclude additional query string parameters
    #  in a future microversion
    'additionalProperties': True,
}
update_request_body = {
    'type': 'object',
    'properties': {
        'quota_class_set': _request_quota_prop,
    },
    'description': helpers.description('quota_class_set'),
    'required': ['quota_class_set'],
    # TODO(jonathan): Exclude additional query string parameters
    #  in a future microversion
    'additionalProperties': True,
}

update_request_body_v253 = {
    'type': 'object',
    'properties': {
        'quota_class_set': _request_quota_prop_v253,
    },
    'description': helpers.description('quota_class_set'),
    'required': ['quota_class_set'],
    # TODO(jonathan): Exclude additional query string parameters
    #  in a future microversion
    'additionalProperties': True,
}

update_request_body_v262 = {
    'type': 'object',
    'properties': {
        'quota_class_set': _request_quota_prop_v262,
    },
    'description': helpers.description('quota_class_set'),
    'required': ['quota_class_set'],
    # TODO(jonathan): Exclude additional query string parameters
    #  in a future microversion
    'additionalProperties': True,
}

update_request_body_v280 = {
    'type': 'object',
    'properties': {
        'quota_class_set': _request_quota_prop_v280,
    },
    'description': helpers.description('quota_class_set'),
    'required': ['quota_class_set'],
    # TODO(jonathan): Exclude additional query string parameters
    #  in a future microversion
    'additionalProperties': True,
}

update_request_body_v290 = {
    'type': 'object',
    'properties': {
        'quota_class_set': _request_quota_prop_v290,
    },
    'description': helpers.description('quota_class_set'),
    'required': ['quota_class_set'],
    # TODO(jonathan): Exclude additional query string parameters
    #  in a future microversion
    'additionalProperties': True,
}


_rsp_quota_prop = {
    'type': 'object',
    'properties': {
        'quota_class_set': {
            'type': 'object',
            'properties': {
                'gigabytes': {
                    'type': 'integer',
                    'description': helpers.description('quota_gigabytes'),
                },
                'id': {
                    'type': 'string',
                    'description': helpers.description('quota_class_id'),
                },
                'snapshots': {
                    'type': 'integer',
                    'description': helpers.description('quota_snapshots'),
                },
                'snapshot_gigabytes': {
                    'type': 'integer',
                    'description': helpers.description(
                        'quota_snapshot_gigabytes'
                    ),
                },
                'shares': {
                    'type': 'integer',
                    'description': helpers.description('quota_shares'),
                },
                'share_networks': {
                    'type': 'integer',
                    'description': helpers.description(
                        'quota_share_networks_default'
                    ),
                },
            },
            'required': [
                'gigabytes',
                'snapshots',
                'snapshot_gigabytes',
                'shares',
                'share_networks',
            ],
            'additionalProperties': False,
        },
    },
    'description': helpers.description('quota_class_set'),
    'required': ['quota_class_set'],
    'additionalProperties': False,
}

_rsp_quota_prop_v240 = copy.deepcopy(_rsp_quota_prop)
_rsp_quota_prop_v240['properties']['quota_class_set']['properties'].update(
    {
        'share_group_snapshots': {
            'type': 'integer',
            'description': helpers.description('quota_share_group_snapshots'),
        },
        'share_groups': {
            'type': 'integer',
            'description': helpers.description('quota_share_groups'),
        },
    }
)
(
    _rsp_quota_prop_v240['properties']['quota_class_set']['required'].extend(
        ['share_group_snapshots', 'share_groups']
    )
)

_rsp_quota_prop_v253 = copy.deepcopy(_rsp_quota_prop_v240)
_rsp_quota_prop_v253['properties']['quota_class_set']['properties'].update(
    {
        'share_replicas': {
            'type': 'integer',
            'description': helpers.description('quota_share_replicas'),
        },
        'replica_gigabytes': {
            'type': 'integer',
            'description': helpers.description('quota_replica_gigabytes'),
        },
    }
)
(_rsp_quota_prop_v253['properties']['quota_class_set']['required']
 .extend(['share_replicas', 'replica_gigabytes']))

_rsp_quota_prop_v262 = copy.deepcopy(_rsp_quota_prop_v253)
_rsp_quota_prop_v262['properties']['quota_class_set']['properties'].update(
    {
        'per_share_gigabytes': {
            'type': 'integer',
            'description': helpers.description('quota_per_share_gigabytes'),
        }
    }
)
(_rsp_quota_prop_v262['properties']['quota_class_set']['required']
 .append('per_share_gigabytes'))

_rsp_quota_prop_v280 = copy.deepcopy(_rsp_quota_prop_v262)
_rsp_quota_prop_v280['properties']['quota_class_set']['properties'].update(
    {
        'backups': {
            'type': 'integer',
            'description': helpers.description('quota_backups'),
        },
        'backup_gigabytes': {
            'type': 'integer',
            'description': helpers.description('quota_backup_gigabytes'),
        },
    }
)
(_rsp_quota_prop_v280['properties']['quota_class_set']['required']
 .extend(['backups', 'backup_gigabytes']))

_rsp_quota_prop_v290 = copy.deepcopy(_rsp_quota_prop_v280)
_rsp_quota_prop_v290['properties']['quota_class_set']['properties'].update(
    {
        'encryption_keys': {
            'type': 'integer',
            'description': helpers.description('quota_encryption_keys'),
        },
    }
)
(_rsp_quota_prop_v290['properties']['quota_class_set']['required']
 .append('encryption_keys'))

show_response_body = _rsp_quota_prop
show_response_body_v240 = _rsp_quota_prop_v240
show_response_body_v253 = _rsp_quota_prop_v253
show_response_body_v262 = _rsp_quota_prop_v262
show_response_body_v280 = _rsp_quota_prop_v280
show_response_body_v290 = _rsp_quota_prop_v290

update_response_body = _rsp_quota_prop
update_response_body_v240 = _rsp_quota_prop_v240
update_response_body_v253 = _rsp_quota_prop_v253
update_response_body_v262 = _rsp_quota_prop_v262
update_response_body_v280 = _rsp_quota_prop_v280
update_response_body_v290 = _rsp_quota_prop_v290
