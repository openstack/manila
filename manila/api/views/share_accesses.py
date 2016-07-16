# Copyright (c) 2016 Red Hat, Inc.
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
    """Model a share access API response as a python dictionary."""

    _collection_name = 'share_accesses'
    _detail_version_modifiers = [
        "add_access_key",
    ]

    def list_view(self, request, accesses):
        """View of a list of share accesses."""
        return {'access_list': [self.summary_view(request, access)['access']
                                for access in accesses]}

    def summary_view(self, request, access):
        """Summarized view of a single share access."""
        access_dict = {
            'id': access.get('id'),
            'access_level': access.get('access_level'),
            'access_to': access.get('access_to'),
            'access_type': access.get('access_type'),
            'state': access.get('state'),
        }
        self.update_versioned_resource_dict(
            request, access_dict, access)
        return {'access': access_dict}

    def view(self, request, access):
        """Generic view of a single share access."""
        access_dict = {
            'id': access.get('id'),
            'share_id': access.get('share_id'),
            'access_level': access.get('access_level'),
            'access_to': access.get('access_to'),
            'access_type': access.get('access_type'),
            'state': access.get('state'),
        }
        self.update_versioned_resource_dict(
            request, access_dict, access)
        return {'access': access_dict}

    @common.ViewBuilder.versioned_method("2.21")
    def add_access_key(self, context, access_dict, access):
        access_dict['access_key'] = access.get('access_key')
