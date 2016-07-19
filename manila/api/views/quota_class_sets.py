# Copyright (c) 2015 Mirantis inc.
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

    _collection_name = "quota_class_set"
    _detail_version_modifiers = [
        "add_share_group_quotas",
        "add_share_replica_quotas",
        "add_per_share_gigabytes_quotas",
        "add_share_backup_quotas",
    ]

    def detail_list(self, request, quota_class_set, quota_class=None):
        """Detailed view of quota class set."""
        keys = (
            'shares',
            'gigabytes',
            'snapshots',
            'snapshot_gigabytes',
            'share_networks',
        )
        view = {key: quota_class_set.get(key) for key in keys}
        if quota_class:
            view['id'] = quota_class
        self.update_versioned_resource_dict(request, view, quota_class_set)
        return {self._collection_name: view}

    @common.ViewBuilder.versioned_method("2.40")
    def add_share_group_quotas(self, context, view, quota_class_set):
        share_groups = quota_class_set.get('share_groups')
        share_group_snapshots = quota_class_set.get('share_group_snapshots')
        if share_groups is not None:
            view['share_groups'] = share_groups
        if share_group_snapshots is not None:
            view['share_group_snapshots'] = share_group_snapshots

    @common.ViewBuilder.versioned_method("2.53")
    def add_share_replica_quotas(self, context, view, quota_class_set):
        view['share_replicas'] = quota_class_set.get('share_replicas')
        view['replica_gigabytes'] = quota_class_set.get('replica_gigabytes')

    @common.ViewBuilder.versioned_method("2.62")
    def add_per_share_gigabytes_quotas(self, context, view, quota_class_set):
        view['per_share_gigabytes'] = quota_class_set.get(
            'per_share_gigabytes')

    @common.ViewBuilder.versioned_method("2.80")
    def add_share_backup_quotas(self, context, view, quota_class_set):
        view['backups'] = quota_class_set.get('backups')
        view['backup_gigabytes'] = quota_class_set.get('backup_gigabytes')
