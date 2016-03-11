# Copyright (c) 2015 Hitachi Data Systems.
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
"""Helper class for Share Migration."""

import time

from oslo_config import cfg
from oslo_log import log

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.i18n import _LW
from manila.share import api as share_api
import manila.utils as utils


LOG = log.getLogger(__name__)

migration_opts = [
    cfg.IntOpt(
        'migration_wait_access_rules_timeout',
        default=180,
        help="Time to wait for access rules to be allowed/denied on backends "
             "when migrating shares using generic approach (seconds)."),
    cfg.IntOpt(
        'migration_create_delete_share_timeout',
        default=300,
        help='Timeout for creating and deleting share instances '
             'when performing share migration (seconds).'),
]

CONF = cfg.CONF
CONF.register_opts(migration_opts)


class ShareMigrationHelper(object):

    def __init__(self, context, db, share):

        self.db = db
        self.share = share
        self.context = context
        self.api = share_api.API()

        self.migration_create_delete_share_timeout = (
            CONF.migration_create_delete_share_timeout)
        self.migration_wait_access_rules_timeout = (
            CONF.migration_wait_access_rules_timeout)

    def delete_instance_and_wait(self, share_instance):

        self.api.delete_instance(self.context, share_instance, True)

        # Wait for deletion.
        starttime = time.time()
        deadline = starttime + self.migration_create_delete_share_timeout
        tries = 0
        instance = "Something not None"
        while instance is not None:
            try:
                instance = self.db.share_instance_get(self.context,
                                                      share_instance['id'])
                tries += 1
                now = time.time()
                if now > deadline:
                    msg = _("Timeout trying to delete instance "
                            "%s") % share_instance['id']
                    raise exception.ShareMigrationFailed(reason=msg)
            except exception.NotFound:
                instance = None
            else:
                time.sleep(tries ** 2)

    def create_instance_and_wait(self, share, share_instance, host):

        new_share_instance = self.api.create_instance(
            self.context, share, share_instance['share_network_id'],
            host['host'])

        # Wait for new_share_instance to become ready
        starttime = time.time()
        deadline = starttime + self.migration_create_delete_share_timeout
        new_share_instance = self.db.share_instance_get(
            self.context, new_share_instance['id'], with_share_data=True)
        tries = 0
        while new_share_instance['status'] != constants.STATUS_AVAILABLE:
            tries += 1
            now = time.time()
            if new_share_instance['status'] == constants.STATUS_ERROR:
                msg = _("Failed to create new share instance"
                        " (from %(share_id)s) on "
                        "destination host %(host_name)s") % {
                    'share_id': share['id'], 'host_name': host['host']}
                self.cleanup_new_instance(new_share_instance)
                raise exception.ShareMigrationFailed(reason=msg)
            elif now > deadline:
                msg = _("Timeout creating new share instance "
                        "(from %(share_id)s) on "
                        "destination host %(host_name)s") % {
                    'share_id': share['id'], 'host_name': host['host']}
                self.cleanup_new_instance(new_share_instance)
                raise exception.ShareMigrationFailed(reason=msg)
            else:
                time.sleep(tries ** 2)
            new_share_instance = self.db.share_instance_get(
                self.context, new_share_instance['id'], with_share_data=True)

        return new_share_instance

    # NOTE(ganso): Cleanup methods do not throw exceptions, since the
    # exceptions that should be thrown are the ones that call the cleanup

    def cleanup_new_instance(self, new_instance):

        try:
            self.delete_instance_and_wait(new_instance)
        except Exception:
            LOG.warning(_LW("Failed to cleanup new instance during generic"
                        " migration for share %s."), self.share['id'])

    def cleanup_access_rules(self, share_instance, share_server, driver):
        try:
            self.revert_access_rules(share_instance, share_server, driver)
        except Exception:
            LOG.warning(_LW("Failed to cleanup access rules during generic"
                        " migration for share %s."), self.share['id'])

    def change_to_read_only(self, share_instance, share_server,
                            readonly_support, driver):

        # NOTE(ganso): If the share does not allow readonly mode we
        # should remove all access rules and prevent any access

        rules = self.db.share_access_get_all_for_instance(
            self.context, share_instance['id'])

        if len(rules) > 0:

            if readonly_support:

                LOG.debug("Changing all of share %s access rules "
                          "to read-only.", self.share['id'])

                for rule in rules:
                    rule['access_level'] = 'ro'

                driver.update_access(self.context, share_instance, rules,
                                     add_rules=[], delete_rules=[],
                                     share_server=share_server)
            else:

                LOG.debug("Removing all access rules for migration of "
                          "share %s." % self.share['id'])

                driver.update_access(self.context, share_instance, [],
                                     add_rules=[], delete_rules=rules,
                                     share_server=share_server)

    def revert_access_rules(self, share_instance, share_server, driver):

        rules = self.db.share_access_get_all_for_instance(
            self.context, share_instance['id'])

        if len(rules) > 0:
            LOG.debug("Restoring all of share %s access rules according to "
                      "DB.", self.share['id'])

            driver.update_access(self.context, share_instance, rules,
                                 add_rules=[], delete_rules=[],
                                 share_server=share_server)

    def apply_new_access_rules(self, new_share_instance):

        self.db.share_instance_access_copy(self.context, self.share['id'],
                                           new_share_instance['id'])

        rules = self.db.share_access_get_all_for_instance(
            self.context, new_share_instance['id'])

        if len(rules) > 0:
            LOG.debug("Restoring all of share %s access rules according to "
                      "DB.", self.share['id'])

            self.api.allow_access_to_instance(self.context, new_share_instance,
                                              rules)
            utils.wait_for_access_update(
                self.context, self.db, new_share_instance,
                self.migration_wait_access_rules_timeout)
