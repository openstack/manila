# Copyright (c) 2020 NetApp, Inc.
# All Rights Reserved.
#
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

import copy

from manila.api import common


class ViewBuilder(common.ViewBuilder):
    """Model share server migration view data response as a python dictionary.

    """

    _collection_name = 'share_server_migration'
    _detail_version_modifiers = []

    def get_progress(self, request, params):
        """View of share server migration job progress."""
        result = {
            'total_progress': params['total_progress'],
            'task_state': params['task_state'],
            'destination_share_server_id':
                params['destination_share_server_id'],
        }

        self.update_versioned_resource_dict(request, result, params)
        return result

    def build_check_migration(self, request, params, result):
        """View of share server migration check."""
        requested_capabilities = {
            'writable': params['writable'],
            'nondisruptive': params['nondisruptive'],
            'preserve_snapshots': params['preserve_snapshots'],
            'share_network_id': params['new_share_network_id'],
            'host': params['host'],
        }
        supported_capabilities = {
            'writable': result['writable'],
            'nondisruptive': result['nondisruptive'],
            'preserve_snapshots': result['preserve_snapshots'],
            'share_network_id': result['share_network_id'],
            'migration_cancel': result['migration_cancel'],
            'migration_get_progress': result['migration_get_progress']
        }
        view = {
            'compatible': result['compatible'],
            'requested_capabilities': requested_capabilities,
            'supported_capabilities': supported_capabilities,
        }
        capabilities = {
            'requested': copy.copy(params),
            'supported': copy.copy(result)
        }
        self.update_versioned_resource_dict(request, view, capabilities)
        return view

    def migration_complete(self, request, params):
        """View of share server migration complete command."""
        result = {
            'destination_share_server_id':
                params['destination_share_server_id'],
        }

        self.update_versioned_resource_dict(request, result, params)
        return result
