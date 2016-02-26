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
NetApp cDOT CIFS protocol helper class.
"""

import re

from oslo_log import log

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share.drivers.netapp.dataontap.protocols import base
from manila.share.drivers.netapp import utils as na_utils


LOG = log.getLogger(__name__)


class NetAppCmodeCIFSHelper(base.NetAppBaseHelper):
    """NetApp cDOT CIFS protocol helper class."""

    @na_utils.trace
    def create_share(self, share, share_name):
        """Creates CIFS share on Data ONTAP Vserver."""
        self._client.create_cifs_share(share_name)
        self._client.remove_cifs_share_access(share_name, 'Everyone')

        # Return a callback that may be used for generating export paths
        # for this share.
        return (lambda export_address, share_name=share_name:
                r'\\%s\%s' % (export_address, share_name))

    @na_utils.trace
    def delete_share(self, share, share_name):
        """Deletes CIFS share on Data ONTAP Vserver."""
        host_ip, share_name = self._get_export_location(share)
        self._client.remove_cifs_share(share_name)

    @na_utils.trace
    @base.access_rules_synchronized
    def update_access(self, share, share_name, rules):
        """Replaces the list of access rules known to the backend storage."""

        # Ensure rules are valid
        for rule in rules:
            self._validate_access_rule(rule)

        new_rules = {rule['access_to']: rule['access_level'] for rule in rules}

        # Get rules from share
        existing_rules = self._get_access_rules(share, share_name)

        # Update rules in an order that will prevent transient disruptions
        self._handle_added_rules(share_name, existing_rules, new_rules)
        self._handle_ro_to_rw_rules(share_name, existing_rules, new_rules)
        self._handle_rw_to_ro_rules(share_name, existing_rules, new_rules)
        self._handle_deleted_rules(share_name, existing_rules, new_rules)

    @na_utils.trace
    def _validate_access_rule(self, rule):
        """Checks whether access rule type and level are valid."""

        if rule['access_type'] != 'user':
            msg = _("Clustered Data ONTAP supports only 'user' type for "
                    "share access rules with CIFS protocol.")
            raise exception.InvalidShareAccess(reason=msg)

        if rule['access_level'] not in constants.ACCESS_LEVELS:
            raise exception.InvalidShareAccessLevel(level=rule['access_level'])

    @na_utils.trace
    def _handle_added_rules(self, share_name, existing_rules, new_rules):
        """Updates access rules added between two rule sets."""
        added_rules = {
            user_or_group: permission
            for user_or_group, permission in new_rules.items()
            if user_or_group not in existing_rules
        }

        for user_or_group, permission in added_rules.items():
            self._client.add_cifs_share_access(
                share_name, user_or_group, self._is_readonly(permission))

    @na_utils.trace
    def _handle_ro_to_rw_rules(self, share_name, existing_rules, new_rules):
        """Updates access rules modified (RO-->RW) between two rule sets."""
        modified_rules = {
            user_or_group: permission
            for user_or_group, permission in new_rules.items()
            if (user_or_group in existing_rules and
                permission == constants.ACCESS_LEVEL_RW and
                existing_rules[user_or_group] != 'full_control')
        }

        for user_or_group, permission in modified_rules.items():
            self._client.modify_cifs_share_access(
                share_name, user_or_group, self._is_readonly(permission))

    @na_utils.trace
    def _handle_rw_to_ro_rules(self, share_name, existing_rules, new_rules):
        """Returns access rules modified (RW-->RO) between two rule sets."""
        modified_rules = {
            user_or_group: permission
            for user_or_group, permission in new_rules.items()
            if (user_or_group in existing_rules and
                permission == constants.ACCESS_LEVEL_RO and
                existing_rules[user_or_group] != 'read')
        }

        for user_or_group, permission in modified_rules.items():
            self._client.modify_cifs_share_access(
                share_name, user_or_group, self._is_readonly(permission))

    @na_utils.trace
    def _handle_deleted_rules(self, share_name, existing_rules, new_rules):
        """Returns access rules deleted between two rule sets."""
        deleted_rules = {
            user_or_group: permission
            for user_or_group, permission in existing_rules.items()
            if user_or_group not in new_rules
        }

        for user_or_group, permission in deleted_rules.items():
            self._client.remove_cifs_share_access(share_name, user_or_group)

    @na_utils.trace
    def _get_access_rules(self, share, share_name):
        """Returns the list of access rules known to the backend storage."""
        return self._client.get_cifs_share_access(share_name)

    @na_utils.trace
    def get_target(self, share):
        """Returns OnTap target IP based on share export location."""
        return self._get_export_location(share)[0]

    @na_utils.trace
    def get_share_name_for_share(self, share):
        """Returns the flexvol name that hosts a share."""
        _, share_name = self._get_export_location(share)
        return share_name

    @staticmethod
    def _get_export_location(share):
        """Returns host ip and share name for a given CIFS share."""
        export_location = share['export_location'] or '\\\\\\'
        regex = r'^(?:\\\\|//)(?P<host_ip>.*)(?:\\|/)(?P<share_name>.*)$'
        match = re.match(regex, export_location)
        if match:
            return match.group('host_ip'), match.group('share_name')
        else:
            return '', ''
