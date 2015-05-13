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

from oslo_log import log
import six

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LW
from manila.share import api as share_api
from manila import utils

LOG = log.getLogger(__name__)


class ShareMigrationHelper(object):

    def __init__(self, context, db, create_delete_timeout, access_rule_timeout,
                 share):

        self.db = db
        self.share = share
        self.context = context
        self.api = share_api.API()
        self.migration_create_delete_share_timeout = create_delete_timeout
        self.migration_wait_access_rules_timeout = access_rule_timeout

    def delete_instance_and_wait(self, context, share_instance):

        self.api.delete_instance(context, share_instance, True)

        # Wait for deletion.
        starttime = time.time()
        deadline = starttime + self.migration_create_delete_share_timeout
        tries = -1
        instance = "Something not None"
        while instance:
            try:
                instance = self.db.share_instance_get(context,
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

    def create_instance_and_wait(self, context, share, share_instance, host):

        api = share_api.API()

        new_share_instance = api.create_instance(
            context, share, share_instance['share_network_id'], host['host'])

        # Wait for new_share_instance to become ready
        starttime = time.time()
        deadline = starttime + self.migration_create_delete_share_timeout
        new_share_instance = self.db.share_instance_get(
            context, new_share_instance['id'], with_share_data=True)
        tries = 0
        while new_share_instance['status'] != constants.STATUS_AVAILABLE:
            tries += 1
            now = time.time()
            if new_share_instance['status'] == constants.STATUS_ERROR:
                msg = _("Failed to create new share instance"
                        " (from %(share_id)s) on "
                        "destination host %(host_name)s") % {
                    'share_id': share['id'], 'host_name': host['host']}
                raise exception.ShareMigrationFailed(reason=msg)
            elif now > deadline:
                msg = _("Timeout creating new share instance "
                        "(from %(share_id)s) on "
                        "destination host %(host_name)s") % {
                    'share_id': share['id'], 'host_name': host['host']}
                raise exception.ShareMigrationFailed(reason=msg)
            else:
                time.sleep(tries ** 2)
            new_share_instance = self.db.share_instance_get(
                context, new_share_instance['id'], with_share_data=True)

        return new_share_instance

    def deny_rules_and_wait(self, context, share, saved_rules):

        api = share_api.API()

        # Deny each one.
        for instance in share.instances:
            for access in saved_rules:
                api.deny_access_to_instance(context, instance, access)

        # Wait for all rules to be cleared.
        starttime = time.time()
        deadline = starttime + self.migration_wait_access_rules_timeout
        tries = 0
        rules = self.db.share_access_get_all_for_share(context, share['id'])
        while len(rules) > 0:
            tries += 1
            now = time.time()
            if now > deadline:
                msg = _("Timeout removing access rules from share "
                        "%(share_id)s. Timeout was %(timeout)s seconds.") % {
                    'share_id': share['id'],
                    'timeout': self.migration_wait_access_rules_timeout}
                raise exception.ShareMigrationFailed(reason=msg)
            else:
                time.sleep(tries ** 2)
            rules = self.db.share_access_get_all_for_share(
                context, share['id'])

    def add_rules_and_wait(self, context, share, saved_rules,
                           access_level=None):

        for access in saved_rules:
            if access_level:
                level = access_level
            else:
                level = access['access_level']
            self.api.allow_access(context, share, access['access_type'],
                                  access['access_to'], level)

        starttime = time.time()
        deadline = starttime + self.migration_wait_access_rules_timeout
        rules_added = False
        tries = 0
        rules = self.db.share_access_get_all_for_share(context, share['id'])
        while not rules_added:
            rules_added = True
            tries += 1
            now = time.time()
            for access in rules:
                if access['state'] != constants.STATUS_ACTIVE:
                    rules_added = False
            if rules_added:
                break
            if now > deadline:
                msg = _("Timeout adding access rules for share "
                        "%(share_id)s. Timeout was %(timeout)s seconds.") % {
                    'share_id': share['id'],
                    'timeout': self.migration_wait_access_rules_timeout}
                raise exception.ShareMigrationFailed(reason=msg)
            else:
                time.sleep(tries ** 2)
            rules = self.db.share_access_get_all_for_share(
                context, share['id'])

    def wait_for_allow_access(self, access_ref):

        starttime = time.time()
        deadline = starttime + self.migration_wait_access_rules_timeout
        tries = 0
        rule = self.api.access_get(self.context, access_ref['id'])
        while rule['state'] != constants.STATUS_ACTIVE:
            tries += 1
            now = time.time()
            if rule['state'] == constants.STATUS_ERROR:
                msg = _("Failed to allow access"
                        " on share %s") % self.share['id']
                raise exception.ShareMigrationFailed(reason=msg)
            elif now > deadline:
                msg = _("Timeout trying to allow access"
                        " on share %(share_id)s. Timeout "
                        "was %(timeout)s seconds.") % {
                    'share_id': self.share['id'],
                    'timeout': self.migration_wait_access_rules_timeout}
                raise exception.ShareMigrationFailed(reason=msg)
            else:
                time.sleep(tries ** 2)
            rule = self.api.access_get(self.context, access_ref['id'])

        return rule

    def wait_for_deny_access(self, access_ref):

        starttime = time.time()
        deadline = starttime + self.migration_wait_access_rules_timeout
        tries = -1
        rule = "Something not None"
        while rule:
            try:
                rule = self.api.access_get(self.context, access_ref['id'])
                tries += 1
                now = time.time()
                if now > deadline:
                    msg = _("Timeout trying to deny access"
                            " on share %(share_id)s. Timeout "
                            "was %(timeout)s seconds.") % {
                        'share_id': self.share['id'],
                        'timeout': self.migration_wait_access_rules_timeout}
                    raise exception.ShareMigrationFailed(reason=msg)
            except exception.NotFound:
                rule = None
            else:
                time.sleep(tries ** 2)

    def allow_migration_access(self, access):
        allowed = False
        access_ref = None
        try:
            access_ref = self.api.allow_access(
                self.context, self.share,
                access['access_type'], access['access_to'])
            allowed = True
        except exception.ShareAccessExists:
            LOG.warning(_LW("Access rule already allowed. "
                            "Access %(access_to)s - Share "
                            "%(share_id)s") % {
                                'access_to': access['access_to'],
                                'share_id': self.share['id']})
            access_list = self.api.access_get_all(self.context, self.share)
            for access_item in access_list:
                if access_item['access_to'] == access['access_to']:
                    access_ref = access_item

        if access_ref and allowed:
            access_ref = self.wait_for_allow_access(access_ref)

        return access_ref

    def deny_migration_access(self, access_ref, access, throw_not_found=True):
        denied = False
        if access_ref:
            try:
                # Update status
                access_ref = self.api.access_get(
                    self.context, access_ref['id'])
            except exception.NotFound:
                access_ref = None
                LOG.warning(_LW("Access rule not found. "
                                "Access %(access_to)s - Share "
                                "%(share_id)s") % {
                                    'access_to': access['access_to'],
                                    'share_id': self.share['id']})
        else:
            access_list = self.api.access_get_all(self.context, self.share)
            for access_item in access_list:
                if access_item['access_to'] == access['access_to']:
                    access_ref = access_item
                    break
        if access_ref:
            try:
                self.api.deny_access(self.context, self.share, access_ref)
                denied = True
            except (exception.InvalidShareAccess, exception.NotFound) as e:
                LOG.exception(six.text_type(e))
                LOG.warning(_LW("Access rule not found. "
                                "Access %(access_to)s - Share "
                                "%(share_id)s") % {
                                    'access_to': access['access_to'],
                                    'share_id': self.share['id']})
                if throw_not_found:
                    raise

            if denied:
                self.wait_for_deny_access(access_ref)

    # NOTE(ganso): Cleanup methods do not throw exception, since the
    # exceptions that should be thrown are the ones that call the cleanup

    def cleanup_migration_access(self, access_ref, access):

        try:
            self.deny_migration_access(access_ref, access)
        except Exception as mae:
            LOG.exception(six.text_type(mae))
            LOG.error(_LE("Could not cleanup access rule of share "
                          "%s") % self.share['id'])

    def cleanup_temp_folder(self, instance, mount_path):

        try:
            utils.execute('rmdir', mount_path + instance['id'],
                          check_exit_code=False)

        except Exception as tfe:
            LOG.exception(six.text_type(tfe))
            LOG.error(_LE("Could not cleanup instance %(instance_id)s "
                          "temporary folders for migration of "
                          "share %(share_id)s") % {
                              'instance_id': instance['id'],
                              'share_id': self.share['id']})

    def cleanup_unmount_temp_folder(self, instance, migration_info):

        try:
            utils.execute(*migration_info['umount'], run_as_root=True)
        except Exception as utfe:
            LOG.exception(six.text_type(utfe))
            LOG.error(_LE("Could not unmount folder of instance"
                          " %(instance_id)s for migration of "
                          "share %(share_id)s") % {
                              'instance_id': instance['id'],
                              'share_id': self.share['id']})

    def change_to_read_only(self, readonly_support):

        # NOTE(ganso): If the share does not allow readonly mode we
        # should remove all access rules and prevent any access

        saved_rules = self.db.share_access_get_all_for_share(
            self.context, self.share['id'])

        self.deny_rules_and_wait(self.context, self.share, saved_rules)

        if readonly_support:

            LOG.debug("Changing all of share %s access rules "
                      "to read-only." % self.share['id'])

            self.add_rules_and_wait(self.context, self.share,
                                    saved_rules, 'ro')

        return saved_rules

    def revert_access_rules(self, readonly_support, saved_rules):

        if readonly_support:

            readonly_rules = self.db.share_access_get_all_for_share(
                self.context, self.share['id'])

            LOG.debug("Removing all of share %s read-only "
                      "access rules." % self.share['id'])

            self.deny_rules_and_wait(self.context, self.share, readonly_rules)

        self.add_rules_and_wait(self.context, self.share, saved_rules)
