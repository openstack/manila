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

    def detail_list(self, quota_set, quota_class=None):
        """Detailed view of quota class set."""
        keys = (
            'shares',
            'gigabytes',
            'snapshots',
            'snapshot_gigabytes',
            'share_networks',
        )
        view = {key: quota_set.get(key) for key in keys}
        if quota_class:
            view['id'] = quota_class
        return {self._collection_name: view}
