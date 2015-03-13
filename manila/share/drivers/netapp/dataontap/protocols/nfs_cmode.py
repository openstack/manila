# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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
"""
NetApp NFS protocol helper class.
"""

from oslo_log import log

from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.protocols import base
from manila.share.drivers.netapp import utils as na_utils


LOG = log.getLogger(__name__)


class NetAppCmodeNFSHelper(base.NetAppBaseHelper):
    """Netapp specific cluster-mode NFS sharing driver."""

    @na_utils.trace
    def create_share(self, share_name, export_addresses):
        """Creates NFS share."""
        export_path = self._client.get_volume_junction_path(share_name)
        return [':'.join([export_address, export_path])
                for export_address in export_addresses]

    @na_utils.trace
    def delete_share(self, share):
        """Deletes NFS share."""
        target, export_path = self._get_export_location(share)
        LOG.debug('Deleting NFS rules for share %s', share['id'])
        self._client.remove_nfs_export_rules(export_path)

    @na_utils.trace
    def allow_access(self, context, share, access):
        """Allows access to a given NFS storage."""
        new_rules = access['access_to']
        existing_rules = self._get_existing_rules(share)

        if not isinstance(new_rules, list):
            new_rules = [new_rules]

        rules = existing_rules + new_rules
        try:
            self._modify_rule(share, rules)
        except netapp_api.NaApiError:
            self._modify_rule(share, existing_rules)

    @na_utils.trace
    def deny_access(self, context, share, access):
        """Denies access to a given NFS storage."""
        access_to = access['access_to']
        existing_rules = self._get_existing_rules(share)

        if not isinstance(access_to, list):
            access_to = [access_to]

        for deny_rule in access_to:
            if deny_rule in existing_rules:
                existing_rules.remove(deny_rule)

        self._modify_rule(share, existing_rules)

    @na_utils.trace
    def get_target(self, share):
        """Returns ID of target OnTap device based on export location."""
        return self._get_export_location(share)[0]

    @na_utils.trace
    def _modify_rule(self, share, rules):
        """Modifies access rule for a given NFS share."""
        target, export_path = self._get_export_location(share)
        self._client.add_nfs_export_rules(export_path, rules)

    @na_utils.trace
    def _get_existing_rules(self, share):
        """Returns available access rules for a given NFS share."""
        target, export_path = self._get_export_location(share)
        existing_rules = self._client.get_nfs_export_rules(export_path)

        LOG.debug('Found existing rules %(rules)r for share %(share)s',
                  {'rules': existing_rules, 'share': share['id']})

        return existing_rules

    @staticmethod
    def _get_export_location(share):
        """Returns IP address and export location of a NFS share."""
        export_location = share['export_location'] or ':'
        return export_location.split(':')
