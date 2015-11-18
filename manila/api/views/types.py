# Copyright 2012 Openstack Foundation.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from manila.api import common
from manila.share import share_types


class ViewBuilder(common.ViewBuilder):

    _collection_name = 'types'

    def show(self, request, share_type, brief=False):
        """Trim away extraneous share type attributes."""

        extra_specs = share_type.get('extra_specs', {})
        required_extra_specs = share_type.get('required_extra_specs', {})

        # Remove non-tenant-visible extra specs in a non-admin context
        if not request.environ['manila.context'].is_admin:
            extra_spec_names = share_types.get_tenant_visible_extra_specs()
            extra_specs = self._filter_extra_specs(extra_specs,
                                                   extra_spec_names)
            required_extra_specs = self._filter_extra_specs(
                required_extra_specs, extra_spec_names)

        trimmed = {
            'id': share_type.get('id'),
            'name': share_type.get('name'),
            'os-share-type-access:is_public': share_type.get(
                'is_public', True),
            'extra_specs': extra_specs,
            'required_extra_specs': required_extra_specs,
        }
        if brief:
            return trimmed
        else:
            return dict(volume_type=trimmed, share_type=trimmed)

    def index(self, request, share_types):
        """Index over trimmed share types."""
        share_types_list = [self.show(request, share_type, True)
                            for share_type in share_types]
        return dict(volume_types=share_types_list,
                    share_types=share_types_list)

    def _filter_extra_specs(self, extra_specs, valid_keys):
        return {key: value for key, value in extra_specs.items()
                if key in valid_keys}
