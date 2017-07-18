# Copyright (c) 2015 Cloudbase Solutions SRL
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

import json
import os

from oslo_log import log

from manila.common import constants
from manila import exception
from manila.share.drivers import helpers
from manila.share.drivers.windows import windows_utils

LOG = log.getLogger(__name__)


class WindowsSMBHelper(helpers.CIFSHelperBase):
    _SHARE_ACCESS_RIGHT_MAP = {
        constants.ACCESS_LEVEL_RW: "Change",
        constants.ACCESS_LEVEL_RO: "Read"}

    _NULL_SID = "S-1-0-0"

    _WIN_ACL_ALLOW = 0
    _WIN_ACL_DENY = 1

    _WIN_ACCESS_RIGHT_FULL = 0
    _WIN_ACCESS_RIGHT_CHANGE = 1
    _WIN_ACCESS_RIGHT_READ = 2
    _WIN_ACCESS_RIGHT_CUSTOM = 3

    _ACCESS_LEVEL_CUSTOM = 'custom'

    _WIN_ACL_MAP = {
        _WIN_ACCESS_RIGHT_CHANGE: constants.ACCESS_LEVEL_RW,
        _WIN_ACCESS_RIGHT_FULL: constants.ACCESS_LEVEL_RW,
        _WIN_ACCESS_RIGHT_READ: constants.ACCESS_LEVEL_RO,
        _WIN_ACCESS_RIGHT_CUSTOM: _ACCESS_LEVEL_CUSTOM,
    }

    _SUPPORTED_ACCESS_LEVELS = (constants.ACCESS_LEVEL_RO,
                                constants.ACCESS_LEVEL_RW)
    _SUPPORTED_ACCESS_TYPES = ('user', )

    def __init__(self, remote_execute, configuration):
        self._remote_exec = remote_execute
        self.configuration = configuration
        self._windows_utils = windows_utils.WindowsUtils(
            remote_execute=remote_execute)

    def init_helper(self, server):
        self._remote_exec(server, "Get-SmbShare")

    def create_exports(self, server, share_name, recreate=False):
        export_location = '\\\\%s\\%s' % (server['public_address'],
                                          share_name)
        if not self._share_exists(server, share_name):
            share_path = self._windows_utils.normalize_path(
                os.path.join(self.configuration.share_mount_path,
                             share_name))
            # If no access rules are requested, 'Everyone' will have read
            # access, by default. We set read access for the 'NULL SID' in
            # order to avoid this.
            cmd = ['New-SmbShare', '-Name', share_name, '-Path', share_path,
                   '-ReadAccess', "*%s" % self._NULL_SID]
            self._remote_exec(server, cmd)
        else:
            LOG.info("Skipping creating export %s as it already exists.",
                     share_name)
        return self.get_exports_for_share(server, export_location)

    def remove_exports(self, server, share_name):
        if self._share_exists(server, share_name):
            cmd = ['Remove-SmbShare', '-Name', share_name, "-Force"]
            self._remote_exec(server, cmd)
        else:
            LOG.debug("Skipping removing export %s as it does not exist.",
                      share_name)

    def _get_volume_path_by_share_name(self, server, share_name):
        share_path = self._get_share_path_by_name(server, share_name)
        volume_path = self._windows_utils.get_volume_path_by_mount_path(
            server, share_path)
        return volume_path

    def _get_acls(self, server, share_name):
        cmd = ('Get-SmbShareAccess -Name %(share_name)s | '
               'Select-Object @("Name", "AccountName", '
               '"AccessControlType", "AccessRight") | '
               'ConvertTo-JSON -Compress' % {'share_name': share_name})
        (out, err) = self._remote_exec(server, cmd)

        if not out.strip():
            return []

        raw_acls = json.loads(out)
        if isinstance(raw_acls, dict):
            return [raw_acls]
        return raw_acls

    def get_access_rules(self, server, share_name):
        raw_acls = self._get_acls(server, share_name)
        acls = []

        for raw_acl in raw_acls:
            access_to = raw_acl['AccountName']
            access_right = raw_acl['AccessRight']
            access_level = self._WIN_ACL_MAP[access_right]
            access_allow = raw_acl["AccessControlType"] == self._WIN_ACL_ALLOW

            if not access_allow:
                if access_to.lower() == 'everyone' and len(raw_acls) == 1:
                    LOG.debug("No access rules are set yet for share %s",
                              share_name)
                else:
                    LOG.warning(
                        "Found explicit deny ACE rule that was not "
                        "created by Manila and will be ignored: %s",
                        raw_acl)
                continue
            if access_level == self._ACCESS_LEVEL_CUSTOM:
                LOG.warning(
                    "Found 'custom' ACE rule that will be ignored: %s",
                    raw_acl)
                continue
            elif access_right == self._WIN_ACCESS_RIGHT_FULL:
                LOG.warning(
                    "Account '%(access_to)s' was given full access "
                    "right on share %(share_name)s. Manila only "
                    "grants 'change' access.",
                    {'access_to': access_to,
                     'share_name': share_name})

            acl = {
                'access_to': access_to,
                'access_level': access_level,
                'access_type': 'user',
            }
            acls.append(acl)
        return acls

    def _grant_share_access(self, server, share_name, access_level, access_to):
        access_right = self._SHARE_ACCESS_RIGHT_MAP[access_level]
        cmd = ["Grant-SmbShareAccess", "-Name", share_name,
               "-AccessRight", access_right,
               "-AccountName", "'%s'" % access_to, "-Force"]
        self._remote_exec(server, cmd)
        self._refresh_acl(server, share_name)
        LOG.info("Granted %(access_level)s access to '%(access_to)s' "
                 "on share %(share_name)s",
                 {'access_level': access_level,
                  'access_to': access_to,
                  'share_name': share_name})

    def _refresh_acl(self, server, share_name):
        cmd = ['Set-SmbPathAcl', '-ShareName', share_name]
        self._remote_exec(server, cmd)

    def _revoke_share_access(self, server, share_name, access_to):
        cmd = ['Revoke-SmbShareAccess', '-Name', share_name,
               '-AccountName', '"%s"' % access_to, '-Force']
        self._remote_exec(server, cmd)
        self._refresh_acl(server, share_name)
        LOG.info("Revoked access to '%(access_to)s' "
                 "on share %(share_name)s",
                 {'access_to': access_to,
                  'share_name': share_name})

    def update_access(self, server, share_name, access_rules, add_rules,
                      delete_rules):
        self.validate_access_rules(
            access_rules + add_rules,
            self._SUPPORTED_ACCESS_TYPES,
            self._SUPPORTED_ACCESS_LEVELS)

        if not (add_rules or delete_rules):
            existing_rules = self.get_access_rules(server, share_name)
            add_rules, delete_rules = self._get_rule_updates(
                existing_rules=existing_rules,
                requested_rules=access_rules)
            LOG.debug(("Missing rules: %(add_rules)s, "
                       "superfluous rules: %(delete_rules)s"),
                      {'add_rules': add_rules,
                       'delete_rules': delete_rules})

        # Some rules may have changed, so we'll
        # treat the deleted rules first.
        for deleted_rule in delete_rules:
            try:
                self.validate_access_rules(
                    [deleted_rule],
                    self._SUPPORTED_ACCESS_TYPES,
                    self._SUPPORTED_ACCESS_LEVELS)
            except (exception.InvalidShareAccess,
                    exception.InvalidShareAccessLevel):
                # This check will allow invalid rules to be deleted.
                LOG.warning(
                    "Unsupported access level %(level)s or access type "
                    "%(type)s, skipping removal of access rule to "
                    "%(to)s.", {'level': deleted_rule['access_level'],
                                'type': deleted_rule['access_type'],
                                'to': deleted_rule['access_to']})
                continue
            self._revoke_share_access(server, share_name,
                                      deleted_rule['access_to'])

        for added_rule in add_rules:
            self._grant_share_access(server, share_name,
                                     added_rule['access_level'],
                                     added_rule['access_to'])

    def _subtract_access_rules(self, access_rules, subtracted_rules):
        # Account names are case insensitive on Windows.
        filter_rules = lambda rules: [
            {'access_to': access_rule['access_to'].lower(),
             'access_level': access_rule['access_level'],
             'access_type': access_rule['access_type']}
            for access_rule in rules]

        return [rule for rule in filter_rules(access_rules)
                if rule not in filter_rules(subtracted_rules)]

    def _get_rule_updates(self, existing_rules, requested_rules):
        added_rules = self._subtract_access_rules(requested_rules,
                                                  existing_rules)
        deleted_rules = self._subtract_access_rules(existing_rules,
                                                    requested_rules)
        return added_rules, deleted_rules

    def _get_share_name(self, export_location):
        return self._windows_utils.normalize_path(
            export_location).split('\\')[-1]

    def _get_export_location_template(self, old_export_location):
        share_name = self._get_share_name(old_export_location)
        return '\\\\%s' + ('\\%s' % share_name)

    def _get_share_path_by_name(self, server, share_name,
                                ignore_missing=False):
        cmd = ('Get-SmbShare -Name %s | '
               'Select-Object -ExpandProperty Path' % share_name)

        check_exit_code = not ignore_missing
        (share_path, err) = self._remote_exec(server, cmd,
                                              check_exit_code=check_exit_code)
        return share_path.strip() if share_path else None

    def get_share_path_by_export_location(self, server, export_location):
        share_name = self._get_share_name(export_location)
        return self._get_share_path_by_name(server, share_name)

    def _share_exists(self, server, share_name):
        share_path = self._get_share_path_by_name(server, share_name,
                                                  ignore_missing=True)
        return bool(share_path)
