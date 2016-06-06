# Copyright (c) 2016 Hitachi Data Systems.
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

from manila.api import common


class ViewBuilder(common.ViewBuilder):
    """Model share migration view data response as a python dictionary."""

    _collection_name = 'share_migration'
    _detail_version_modifiers = []

    def get_progress(self, request, share, progress):
        """View of share migration job progress."""
        result = {
            'total_progress': progress['total_progress'],
            'task_state': share['task_state'],
        }
        self.update_versioned_resource_dict(request, result, progress)
        return result
