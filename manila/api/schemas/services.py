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

from manila.api.validation import helpers


ensure_shares_request_body = {
    'type': 'object',
    'properties': {
        'ensure_shares': {
            'type': 'object',
            'properties': {
                'host': {
                    'type': 'string',
                    'description': helpers.description(
                        'service_ensure_shares_host_request'
                    ),
                },
            },
            'required': ['host'],
            'additionalProperties': False,
        },
    },
    'required': ['ensure_shares'],
    'additionalProperties': False,
}
ensure_shares_response_body = {
    'type': 'null',
}
