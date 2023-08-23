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
    """Model a resource lock API response as a python dictionary."""

    _collection_name = "resource_locks"

    def index(self, request, resource_locks, count=None):
        """Show a list of resource locks."""
        return self._list_view(self.detail,
                               request,
                               resource_locks,
                               count=count)

    def detail(self, request, resource_lock):
        """Detailed view of a single resource lock."""
        lock_ref = {
            'id': resource_lock.get('id'),
            'user_id': resource_lock.get('user_id'),
            'project_id': resource_lock.get('project_id'),
            'lock_context': resource_lock.get('lock_context'),
            'resource_type': resource_lock.get('resource_type'),
            'resource_id': resource_lock.get('resource_id'),
            'resource_action': resource_lock.get('resource_action'),
            'lock_reason': resource_lock.get('lock_reason'),
            'created_at': resource_lock.get('created_at'),
            'updated_at': resource_lock.get('updated_at'),
            'links': self._get_links(request, resource_lock['id']),
        }
        return {'resource_lock': lock_ref}

    def _list_view(self, func, request, resource_locks,
                   coll_name=_collection_name, count=None):
        """Provide a view for a list of resource_locks.

        :param func: Function used to format the lock data
        :param request: API request
        :param resource_locks: List of locks in dictionary format
        :param coll_name: Name of collection, used to generate the next link
                          for a pagination query
        :returns: lock data in dictionary format
        """
        locks_list = [
            func(request, lock)['resource_lock']
            for lock in resource_locks
        ]
        locks_links = self._get_collection_links(request,
                                                 resource_locks,
                                                 coll_name)
        locks_dict = dict({"resource_locks": locks_list})

        if count:
            locks_dict['count'] = count

        if locks_links:
            locks_dict['resource_locks_links'] = locks_links

        return locks_dict
