# Copyright (c) 2015 Mirantis Inc.
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
import six

from manila.common import constants
from manila.i18n import _LI

LOG = log.getLogger(__name__)


class ShareInstanceAccess(object):

    def __init__(self, db, driver):
        self.db = db
        self.driver = driver

    def update_access_rules(self, context, share_instance_id, add_rules=None,
                            delete_rules=None, share_server=None):
        """Update access rules in driver and database for given share instance.

        :param context: current context
        :param share_instance_id: Id of the share instance model
        :param add_rules: list with ShareAccessMapping models or None - rules
        which should be added
        :param delete_rules: list with ShareAccessMapping models, "all", None
        - rules which should be deleted. If "all" is provided - all rules will
        be deleted.
        :param share_server: Share server model or None
        """
        self.db.share_instance_update_access_status(
            context,
            share_instance_id,
            constants.STATUS_UPDATING
        )

        share_instance = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)

        add_rules = add_rules or []
        delete_rules = delete_rules or []
        remove_rules = None

        if six.text_type(delete_rules).lower() == "all":
            # NOTE(ganso): if we are deleting an instance or clearing all
            # the rules, we want to remove only the ones related
            # to this instance.
            delete_rules = self.db.share_access_get_all_for_instance(
                context, share_instance['id'])
            rules = []
        else:
            rules = self.db.share_access_get_all_for_instance(
                context, share_instance['id'])
            if delete_rules:
                delete_ids = [rule['id'] for rule in delete_rules]
                rules = list(filter(lambda r: r['id'] not in delete_ids,
                                    rules))
                # NOTE(ganso): trigger maintenance mode
                if share_instance['access_rules_status'] == (
                        constants.STATUS_ERROR):
                    remove_rules = delete_rules
                    delete_rules = []

        try:
            try:
                self.driver.update_access(
                    context,
                    share_instance,
                    rules,
                    add_rules=add_rules,
                    delete_rules=delete_rules,
                    share_server=share_server
                )
            except NotImplementedError:
                # NOTE(u_glide): Fallback to legacy allow_access/deny_access
                # for drivers without update_access() method support

                self._update_access_fallback(add_rules, context, delete_rules,
                                             remove_rules, share_instance,
                                             share_server)
        except Exception:
            self.db.share_instance_update_access_status(
                context,
                share_instance['id'],
                constants.STATUS_ERROR)
            raise

        # NOTE(ganso): remove rules after maintenance is complete
        if remove_rules:
            delete_rules = remove_rules

        self._remove_access_rules(context, delete_rules, share_instance['id'])

        share_instance = self.db.share_instance_get(context, share_instance_id,
                                                    with_share_data=True)

        if self._check_needs_refresh(context, rules, share_instance):
            self.update_access_rules(context, share_instance_id,
                                     share_server=share_server)
        else:
            self.db.share_instance_update_access_status(
                context,
                share_instance['id'],
                constants.STATUS_ACTIVE
            )

            LOG.info(_LI("Access rules were successfully applied for "
                         "share instance: %s"),
                     share_instance['id'])

    def _check_needs_refresh(self, context, rules, share_instance):
        rule_ids = set([rule['id'] for rule in rules])
        queried_rules = self.db.share_access_get_all_for_instance(
            context, share_instance['id'])
        queried_ids = set([rule['id'] for rule in queried_rules])

        access_rules_status = share_instance['access_rules_status']

        return (access_rules_status == constants.STATUS_UPDATING_MULTIPLE or
                rule_ids != queried_ids)

    def _update_access_fallback(self, add_rules, context, delete_rules,
                                remove_rules, share_instance, share_server):
        for rule in add_rules:
            LOG.info(
                _LI("Applying access rule '%(rule)s' for share "
                    "instance '%(instance)s'"),
                {'rule': rule['id'], 'instance': share_instance['id']}
            )

            self.driver.allow_access(
                context,
                share_instance,
                rule,
                share_server=share_server
            )

        # NOTE(ganso): Fallback mode temporary compatibility workaround
        if remove_rules:
            delete_rules = remove_rules
        for rule in delete_rules:
            LOG.info(
                _LI("Denying access rule '%(rule)s' from share "
                    "instance '%(instance)s'"),
                {'rule': rule['id'], 'instance': share_instance['id']}
            )

            self.driver.deny_access(
                context,
                share_instance,
                rule,
                share_server=share_server
            )

    def _remove_access_rules(self, context, access_rules, share_instance_id):
        if not access_rules:
            return

        for rule in access_rules:
            access_mapping = self.db.share_instance_access_get(
                context, rule['id'], share_instance_id)

            self.db.share_instance_access_delete(context, access_mapping['id'])
