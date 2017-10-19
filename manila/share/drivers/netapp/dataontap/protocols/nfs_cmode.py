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
NetApp cDOT NFS protocol helper class.
"""

import uuid

from oslo_log import log
import six

from manila.common import constants
from manila import exception
from manila.share.drivers.netapp.dataontap.protocols import base
from manila.share.drivers.netapp import utils as na_utils


LOG = log.getLogger(__name__)


class NetAppCmodeNFSHelper(base.NetAppBaseHelper):
    """NetApp cDOT NFS protocol helper class."""

    @staticmethod
    def _escaped_address(address):
        if ':' in address:
            return '[%s]' % address
        else:
            return address

    @na_utils.trace
    def create_share(self, share, share_name,
                     clear_current_export_policy=True):
        """Creates NFS share."""
        if clear_current_export_policy:
            self._client.clear_nfs_export_policy_for_volume(share_name)
        self._ensure_export_policy(share, share_name)
        export_path = self._client.get_volume_junction_path(share_name)

        # Return a callback that may be used for generating export paths
        # for this share.
        return (lambda export_address, export_path=export_path:
                ':'.join([self._escaped_address(export_address),
                          export_path]))

    @na_utils.trace
    @base.access_rules_synchronized
    def delete_share(self, share, share_name):
        """Deletes NFS share."""
        LOG.debug('Deleting NFS export policy for share %s', share['id'])
        export_policy_name = self._get_export_policy_name(share)
        self._client.clear_nfs_export_policy_for_volume(share_name)
        self._client.soft_delete_nfs_export_policy(export_policy_name)

    @na_utils.trace
    @base.access_rules_synchronized
    def update_access(self, share, share_name, rules):
        """Replaces the list of access rules known to the backend storage."""

        # Ensure rules are valid
        for rule in rules:
            self._validate_access_rule(rule)

        # Sort rules by ascending network size
        new_rules = {rule['access_to']: rule['access_level'] for rule in rules}
        addresses = sorted(new_rules, reverse=True)

        # Ensure current export policy has the name we expect
        self._ensure_export_policy(share, share_name)
        export_policy_name = self._get_export_policy_name(share)

        # Make temp policy names so this non-atomic workflow remains resilient
        # across process interruptions.
        temp_new_export_policy_name = self._get_temp_export_policy_name()
        temp_old_export_policy_name = self._get_temp_export_policy_name()

        # Create new export policy
        self._client.create_nfs_export_policy(temp_new_export_policy_name)

        # Add new rules to new policy
        for address in addresses:
            self._client.add_nfs_export_rule(
                temp_new_export_policy_name, address,
                self._is_readonly(new_rules[address]))

        # Rename policy currently in force
        LOG.info('Renaming NFS export policy for share %(share)s to '
                 '%(policy)s.',
                 {'share': share_name, 'policy': temp_old_export_policy_name})
        self._client.rename_nfs_export_policy(export_policy_name,
                                              temp_old_export_policy_name)

        # Switch share to the new policy
        LOG.info('Setting NFS export policy for share %(share)s to '
                 '%(policy)s.',
                 {'share': share_name, 'policy': temp_new_export_policy_name})
        self._client.set_nfs_export_policy_for_volume(
            share_name, temp_new_export_policy_name)

        # Delete old policy
        self._client.soft_delete_nfs_export_policy(temp_old_export_policy_name)

        # Rename new policy to its final name
        LOG.info('Renaming NFS export policy for share %(share)s to '
                 '%(policy)s.',
                 {'share': share_name, 'policy': export_policy_name})
        self._client.rename_nfs_export_policy(temp_new_export_policy_name,
                                              export_policy_name)

    @na_utils.trace
    def _validate_access_rule(self, rule):
        """Checks whether access rule type and level are valid."""

        if rule['access_type'] != 'ip':
            msg = ("Clustered Data ONTAP supports only 'ip' type for share "
                   "access rules with NFS protocol.")
            raise exception.InvalidShareAccess(reason=msg)

        if rule['access_level'] not in constants.ACCESS_LEVELS:
            raise exception.InvalidShareAccessLevel(level=rule['access_level'])

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
    def _get_temp_export_policy_name():
        """Builds export policy name for an NFS share."""
        return 'temp_' + six.text_type(uuid.uuid1()).replace('-', '_')

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
