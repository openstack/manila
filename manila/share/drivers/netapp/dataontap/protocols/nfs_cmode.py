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

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share.drivers.netapp.dataontap.protocols import base
from manila.share.drivers.netapp import utils as na_utils


LOG = log.getLogger(__name__)


class NetAppCmodeNFSHelper(base.NetAppBaseHelper):
    """Netapp specific cluster-mode NFS sharing driver."""

    @na_utils.trace
    def create_share(self, share, share_name, export_addresses):
        """Creates NFS share."""
        self._client.clear_nfs_export_policy_for_volume(share_name)
        self._ensure_export_policy(share, share_name)
        export_path = self._client.get_volume_junction_path(share_name)
        return [':'.join([export_address, export_path])
                for export_address in export_addresses]

    @na_utils.trace
    def delete_share(self, share, share_name):
        """Deletes NFS share."""
        LOG.debug('Deleting NFS export policy for share %s', share['id'])
        export_policy_name = self._get_export_policy_name(share)
        self._client.clear_nfs_export_policy_for_volume(share_name)
        self._client.soft_delete_nfs_export_policy(export_policy_name)

    @na_utils.trace
    def allow_access(self, context, share, share_name, access):
        """Allows access to a given NFS share."""
        if access['access_type'] != 'ip':
            msg = _("Cluster Mode supports only 'ip' type for share access"
                    " rules with NFS protocol.")
            raise exception.InvalidShareAccess(reason=msg)

        self._ensure_export_policy(share, share_name)
        export_policy_name = self._get_export_policy_name(share)
        rule = access['access_to']

        if access['access_level'] == constants.ACCESS_LEVEL_RW:
            readonly = False
        elif access['access_level'] == constants.ACCESS_LEVEL_RO:
            readonly = True
        else:
            raise exception.InvalidShareAccessLevel(
                level=access['access_level'])

        self._client.add_nfs_export_rule(export_policy_name, rule, readonly)

    @na_utils.trace
    def deny_access(self, context, share, share_name, access):
        """Denies access to a given NFS share."""
        if access['access_type'] != 'ip':
            return

        self._ensure_export_policy(share, share_name)
        export_policy_name = self._get_export_policy_name(share)
        rule = access['access_to']
        self._client.remove_nfs_export_rule(export_policy_name, rule)

    @na_utils.trace
    def get_target(self, share):
        """Returns ID of target OnTap device based on export location."""
        return self._get_export_location(share)[0]

    @na_utils.trace
    def get_share_name_for_share(self, share):
        """Returns the flexvol name that hosts a share."""
        _, volume_junction_path = self._get_export_location(share)
        volume = self._client.get_volume_at_junction_path(volume_junction_path)
        return volume.get('name') if volume else None

    @staticmethod
    def _get_export_location(share):
        """Returns IP address and export location of an NFS share."""
        export_location = share['export_location'] or ':'
        return export_location.rsplit(':', 1)

    @staticmethod
    def _get_export_policy_name(share):
        """Builds export policy name for an NFS share."""
        return 'policy_' + share['id'].replace('-', '_')

    @na_utils.trace
    def _ensure_export_policy(self, share, share_name):
        """Ensures a flexvol/share has an export policy.

        This method ensures a flexvol has an export policy with a name
        containing the share ID.  For legacy reasons, this may not
        always be the case.
        """
        expected_export_policy = self._get_export_policy_name(share)
        actual_export_policy = self._client.get_nfs_export_policy_for_volume(
            share_name)

        if actual_export_policy == expected_export_policy:
            return
        elif actual_export_policy == 'default':
            self._client.create_nfs_export_policy(expected_export_policy)
            self._client.set_nfs_export_policy_for_volume(
                share_name, expected_export_policy)
        else:
            self._client.rename_nfs_export_policy(actual_export_policy,
                                                  expected_export_policy)
