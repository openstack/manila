# Copyright (c) 2016 Mirantis, Inc.
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

from oslo_log import log

from manila.common import constants as const
from manila import exception
from manila.i18n import _

LOG = log.getLogger(__name__)


class DockerCIFSHelper(object):
    def __init__(self, container_helper, *args, **kwargs):
        super(DockerCIFSHelper, self).__init__()
        self.share = kwargs.get("share")
        self.conf = kwargs.get("config")
        self.container = container_helper

    def create_share(self, server_id):
        export_locations = []
        share_name = self.share.share_id
        cmd = ["net", "conf", "addshare", share_name,
               "/shares/%s" % share_name, "writeable=y"]
        if self.conf.container_cifs_guest_ok:
            cmd.append("guest_ok=y")
        else:
            cmd.append("guest_ok=n")
        self.container.execute(server_id, cmd)
        parameters = {
            "browseable": "yes",
            "create mask": "0755",
            "read only": "no",
        }
        for param, value in parameters.items():
            self.container.execute(
                server_id,
                ["net", "conf", "setparm", share_name, param, value]
            )
        # TODO(tbarron): pass configured address family when we support IPv6
        addresses = self.container.fetch_container_addresses(
            server_id, address_family="inet")
        for address in addresses:
            export_location = {
                "is_admin_only": False,
                "path": "//%(ip_address)s/%(share_name)s" %
                {
                    "ip_address": address,
                    "share_name": share_name
                },
                "preferred": False
            }
            export_locations.append(export_location)
        return export_locations

    def delete_share(self, server_id, share_name, ignore_errors=False):
        self.container.execute(
            server_id,
            ["net", "conf", "delshare", share_name],
            ignore_errors=ignore_errors
        )

    def _get_access_group(self, access_level):
        if access_level == const.ACCESS_LEVEL_RO:
            access = "read list"
        elif access_level == const.ACCESS_LEVEL_RW:
            access = "valid users"
        else:
            raise exception.InvalidShareAccessLevel(level=access_level)
        return access

    def _get_existing_users(self, server_id, share_name, access):
        result = self.container.execute(
            server_id,
            ["net", "conf", "getparm", share_name, access],
            ignore_errors=True
        )
        if result:
            return result[0].rstrip('\n')
        else:
            return ""

    def _set_users(self, server_id, share_name, access, users_to_set):
        self.container.execute(
            server_id,
            ["net", "conf", "setparm", share_name, access, users_to_set]
        )

    def _allow_access(self, share_name, server_id, user_to_allow,
                      access_level):
        access = self._get_access_group(access_level)
        try:
            existing_users = self._get_existing_users(server_id, share_name,
                                                      access)
        except TypeError:
            users_to_allow = user_to_allow
        else:
            users_to_allow = " ".join([existing_users, user_to_allow])
        self._set_users(server_id, share_name, access, users_to_allow)

    def _deny_access(self, share_name, server_id, user_to_deny,
                     access_level):
        access = self._get_access_group(access_level)
        try:
            existing_users = self._get_existing_users(server_id, share_name,
                                                      access)
        except TypeError:
            LOG.warning("Can't access smbd at share %s.", share_name)
            return
        else:
            allowed_users = " ".join(sorted(set(existing_users.split()) -
                                     set([user_to_deny])))
            if allowed_users != existing_users:
                self._set_users(server_id, share_name, access, allowed_users)

    def update_access(self, server_id, share_name, access_rules,
                      add_rules=None, delete_rules=None):

        def _rule_updater(rules, action, override_type_check=False):
            for rule in rules:
                access_level = rule['access_level']
                access_type = rule['access_type']
                # (aovchinnikov): override_type_check is used to ensure
                # broken rules deletion.
                if access_type == 'user' or override_type_check:
                    action(share_name, server_id, rule['access_to'],
                           access_level)
                else:
                    msg = _("Access type '%s' is not supported by the "
                            "driver.") % access_type
                    raise exception.InvalidShareAccess(reason=msg)

        if not (add_rules or delete_rules):
            # clean all users first.
            self.container.execute(
                server_id,
                ["net", "conf", "setparm", share_name, "valid users", ""]
            )
            _rule_updater(access_rules or [], self._allow_access)
            return
        _rule_updater(add_rules or [], self._allow_access)
        _rule_updater(delete_rules or [], self._deny_access,
                      override_type_check=True)
