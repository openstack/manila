# Copyright 2023 Cloudification GmbH.
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
from manila import policy


class BackupViewBuilder(common.ViewBuilder):
    """Model a server API response as a python dictionary."""

    _collection_name = 'share_backups'
    _collection_links = 'share_backup_links'

    def summary_list(self, request, backups):
        """Summary view of a list of backups."""
        return self._list_view(self.summary, request, backups)

    def detail_list(self, request, backups):
        """Detailed view of a list of backups."""
        return self._list_view(self.detail, request, backups)

    def summary(self, request, backup):
        """Generic, non-detailed view of a share backup."""

        backup_dict = {
            'id': backup.get('id'),
            'name': backup.get('display_name'),
            'share_id': backup.get('share_id'),
            'status': backup.get('status'),
        }
        return {'share_backup': backup_dict}

    def restore_summary(self, request, restore):
        """Generic, non-detailed view of a restore."""
        return {
            'restore': {
                'backup_id': restore['backup_id'],
                'share_id': restore['share_id'],
            },
        }

    def detail(self, request, backup):
        """Detailed view of a single backup."""
        context = request.environ['manila.context']
        backup_dict = {
            'id': backup.get('id'),
            'name': backup.get('display_name'),
            'share_id': backup.get('share_id'),
            'status': backup.get('status'),
            'description': backup.get('display_description'),
            'size': backup.get('size'),
            'created_at': backup.get('created_at'),
            'updated_at': backup.get('updated_at'),
            'availability_zone': backup.get('availability_zone'),
            'progress': backup.get('progress'),
            'restore_progress': backup.get('restore_progress'),
        }

        if policy.check_is_host_admin(context):
            backup_dict['host'] = backup.get('host')
            backup_dict['topic'] = backup.get('topic')

        return {'share_backup': backup_dict}

    def _list_view(self, func, request, backups):
        """Provide a view for a list of backups."""

        backups_list = [func(request, backup)['share_backup']
                        for backup in backups]

        backup_links = self._get_collection_links(
            request, backups, self._collection_name)
        backups_dict = {self._collection_name: backups_list}

        if backup_links:
            backups_dict[self._collection_links] = backup_links

        return backups_dict
