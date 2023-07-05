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
from manila.common import constants
from manila.share import api as share_api


class ViewBuilder(common.ViewBuilder):
    """Model a share access API response as a python dictionary."""

    _collection_name = 'share_accesses'
    _detail_version_modifiers = [
        "add_access_key",
        "translate_transitional_statuses",
        "add_created_at_and_updated_at",
        "add_access_rule_metadata_field",
    ]

    def list_view(self, request, accesses):
        """View of a list of share accesses."""
        return {'access_list': [self.summary_view(request, access)['access']
                                for access in accesses]}

    def _redact_restricted_fields(self, access, access_dict):
        if access.get('restricted', False):
            fields_to_redact = ['access_key', 'access_to']
            for field in fields_to_redact:
                access_dict[field] = '******'
        return access_dict

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
        access_dict = self._redact_restricted_fields(access, access_dict)
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
        access_dict = self._redact_restricted_fields(access, access_dict)
        return {'access': access_dict}

    def view_metadata(self, request, metadata):
        """View of a share access rule metadata."""
        return {'metadata': metadata}

    @common.ViewBuilder.versioned_method("2.21")
    def add_access_key(self, context, access_dict, access):
        access_dict['access_key'] = access.get('access_key')

    @common.ViewBuilder.versioned_method("2.33")
    def add_created_at_and_updated_at(self, context, access_dict, access):
        access_dict['created_at'] = access.get('created_at')
        access_dict['updated_at'] = access.get('updated_at')

    @common.ViewBuilder.versioned_method("2.45")
    def add_access_rule_metadata_field(self, context, access_dict, access):
        metadata = access.get('share_access_rules_metadata') or {}
        metadata = {item['key']: item['value'] for item in metadata}
        access_dict['metadata'] = metadata

    @common.ViewBuilder.versioned_method("1.0", "2.27")
    def translate_transitional_statuses(self, context, access_dict, access):
        """In 2.28, the per access rule status was (re)introduced."""
        api = share_api.API()
        share = api.get(context, access['share_id'])

        if (share['access_rules_status'] ==
                constants.SHARE_INSTANCE_RULES_SYNCING):
            access_dict['state'] = constants.STATUS_NEW
        else:
            access_dict['state'] = share['access_rules_status']
