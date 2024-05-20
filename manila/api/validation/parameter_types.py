# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Common parameter types for validating API requests."""

from manila.common import constants


def single_param(schema):
    """Macro function to support query params that allow only one value."""
    ret = multi_params(schema)
    ret['maxItems'] = 1
    return ret


def multi_params(schema):
    """Macro function to support query params that allow multiple values."""
    return {'type': 'array', 'items': schema}


boolean = {
    'type': ['boolean', 'string'],
    'enum': [
        True,
        'True',
        'TRUE',
        'true',
        '1',
        'ON',
        'On',
        'on',
        'YES',
        'Yes',
        'yes',
        'y',
        't',
        False,
        'False',
        'FALSE',
        'false',
        '0',
        'OFF',
        'Off',
        'off',
        'NO',
        'No',
        'no',
        'n',
        'f',
    ],
}

positive_integer = {
    'type': ['integer', 'string'],
    'pattern': '^[0-9]*$',
    'minimum': 1,
    'maximum': constants.DB_MAX_INT,
    'minLength': 1,
}

non_negative_integer = {
    'type': ['integer', 'string'],
    'pattern': '^[0-9]*$',
    'minimum': 0,
    'maximum': constants.DB_MAX_INT,
    'minLength': 1,
}
