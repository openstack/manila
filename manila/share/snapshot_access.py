# Copyright (c) 2016 Hitachi Data Systems
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

from manila.common import constants
from manila import utils

LOG = log.getLogger(__name__)


class ShareSnapshotInstanceAccess(object):

    def __init__(self, db, driver):
        self.db = db
        self.driver = driver

    def update_access_rules(self, context, snapshot_instance_id,
                            delete_all_rules=False, share_server=None):
        """Update driver and database access rules for given snapshot instance.

        :param context: current context
        :param snapshot_instance_id: Id of the snapshot instance model
        :param delete_all_rules: Whether all rules should be deleted.
        :param share_server: Share server model or None
        """
        snapshot_instance = self.db.share_snapshot_instance_get(
            context, snapshot_instance_id, with_share_data=True)
        snapshot_id = snapshot_instance['snapshot_id']

        @utils.synchronized(
            "update_access_rules_for_snapshot_%s" % snapshot_id, external=True)
        def _update_access_rules_locked(*args, **kwargs):
            return self._update_access_rules(*args, **kwargs)

        _update_access_rules_locked(
            context=context,
            snapshot_instance=snapshot_instance,
            delete_all_rules=delete_all_rules,
            share_server=share_server,
        )

    def _update_access_rules(self, context, snapshot_instance,
                             delete_all_rules=None, share_server=None):

        # NOTE(ganso): First let's get all the rules and the mappings.

        rules = self.db.share_snapshot_access_get_all_for_snapshot_instance(
            context, snapshot_instance['id'])

        add_rules = []
        delete_rules = []

        if delete_all_rules:
            # NOTE(ganso): We want to delete all rules.
            delete_rules = rules
            rules_to_be_on_snapshot = []
            # NOTE(ganso): We select all deletable mappings.
            for rule in rules:
                # NOTE(ganso): No need to update the state if already set.
                if rule['state'] != constants.ACCESS_STATE_DENYING:
                    self.db.share_snapshot_instance_access_update(
                        context, rule['access_id'], snapshot_instance['id'],
                        {'state': constants.ACCESS_STATE_DENYING})

        else:

            # NOTE(ganso): error'ed rules are to be left alone until
            # reset back to "queued_to_deny" by API.
            rules_to_be_on_snapshot = [
                r for r in rules if r['state'] not in (
                    constants.ACCESS_STATE_QUEUED_TO_DENY,
                    # NOTE(ganso): We select denying rules as a recovery
                    # mechanism for invalid rules during a restart.
                    constants.ACCESS_STATE_DENYING,
                    # NOTE(ganso): We do not re-send error-ed access rules to
                    # drivers.
                    constants.ACCESS_STATE_ERROR
                )
            ]

            # NOTE(ganso): Process queued rules
            for rule in rules:
                # NOTE(ganso): We are barely handling recovery, so if any rule
                # exists in 'applying' or 'denying' state, we add them again.
                if rule['state'] in (constants.ACCESS_STATE_QUEUED_TO_APPLY,
                                     constants.ACCESS_STATE_APPLYING):
                    if rule['state'] == (
                            constants.ACCESS_STATE_QUEUED_TO_APPLY):
                        self.db.share_snapshot_instance_access_update(
                            context, rule['access_id'],
                            snapshot_instance['id'],
                            {'state': constants.ACCESS_STATE_APPLYING})
                    add_rules.append(rule)
                elif rule['state'] in (
                        constants.ACCESS_STATE_QUEUED_TO_DENY,
                        constants.ACCESS_STATE_DENYING):
                    if rule['state'] == (
                            constants.ACCESS_STATE_QUEUED_TO_DENY):
                        self.db.share_snapshot_instance_access_update(
                            context, rule['access_id'],
                            snapshot_instance['id'],
                            {'state': constants.ACCESS_STATE_DENYING})
                    delete_rules.append(rule)

        try:
            self.driver.snapshot_update_access(
                context,
                snapshot_instance,
                rules_to_be_on_snapshot,
                add_rules=add_rules,
                delete_rules=delete_rules,
                share_server=share_server)

            # NOTE(ganso): successfully added rules transition to "active".
            for rule in add_rules:
                self.db.share_snapshot_instance_access_update(
                    context, rule['access_id'], snapshot_instance['id'],
                    {'state': constants.STATUS_ACTIVE})

        except Exception:
            # NOTE(ganso): if we failed, we set all the transitional rules
            # to ERROR.
            for rule in add_rules + delete_rules:
                self.db.share_snapshot_instance_access_update(
                    context, rule['access_id'], snapshot_instance['id'],
                    {'state': constants.STATUS_ERROR})
            raise

        self._remove_access_rules(
            context, delete_rules, snapshot_instance['id'])

        if self._check_needs_refresh(context, snapshot_instance['id']):
            self._update_access_rules(context, snapshot_instance,
                                      share_server=share_server)
        else:
            LOG.info("Access rules were successfully applied for "
                     "snapshot instance: %s", snapshot_instance['id'])

    def _check_needs_refresh(self, context, snapshot_instance_id):

        rules = self.db.share_snapshot_access_get_all_for_snapshot_instance(
            context, snapshot_instance_id)

        return (any(rule['state'] in (
            constants.ACCESS_STATE_QUEUED_TO_APPLY,
            constants.ACCESS_STATE_QUEUED_TO_DENY)
            for rule in rules))

    def _remove_access_rules(self, context, rules, snapshot_instance_id):
        if not rules:
            return

        for rule in rules:
            self.db.share_snapshot_instance_access_delete(
                context, rule['access_id'], snapshot_instance_id)

    def get_snapshot_instance_access_rules(self, context,
                                           snapshot_instance_id):
        return self.db.share_snapshot_access_get_all_for_snapshot_instance(
            context, snapshot_instance_id)
