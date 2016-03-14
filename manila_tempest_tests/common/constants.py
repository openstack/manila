#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

STATUS_ERROR = 'error'
STATUS_AVAILABLE = 'available'
STATUS_ERROR_DELETING = 'error_deleting'

TEMPEST_MANILA_PREFIX = 'tempest-manila'
REPLICATION_STYLE_READABLE = 'readable'
REPLICATION_STYLE_WRITABLE = 'writable'
REPLICATION_STYLE_DR = 'dr'
REPLICATION_TYPE_CHOICES = (
    REPLICATION_STYLE_READABLE,
    REPLICATION_STYLE_WRITABLE,
    REPLICATION_STYLE_DR,
)
REPLICATION_PROMOTION_CHOICES = (
    REPLICATION_STYLE_READABLE,
    REPLICATION_STYLE_DR,
)
REPLICATION_STATE_ACTIVE = 'active'
REPLICATION_STATE_IN_SYNC = 'in_sync'
REPLICATION_STATE_OUT_OF_SYNC = 'out_of_sync'

RULE_STATE_ACTIVE = 'active'
RULE_STATE_OUT_OF_SYNC = 'out_of_sync'
RULE_STATE_ERROR = 'error'
