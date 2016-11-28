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
from manila import exception
from manila.i18n import _, _LI
from manila import utils

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
        share_instance = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)
        share_id = share_instance["share_id"]

        @utils.synchronized(
            "update_access_rules_for_share_%s" % share_id, external=True)
        def _update_access_rules_locked(*args, **kwargs):
            return self._update_access_rules(*args, **kwargs)

        _update_access_rules_locked(
            context=context,
            share_instance_id=share_instance_id,
            add_rules=add_rules,
            delete_rules=delete_rules,
            share_server=share_server,
        )

    def _update_access_rules(self, context, share_instance_id, add_rules=None,
                             delete_rules=None, share_server=None):
        # Reget share instance
        share_instance = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)

        # NOTE (rraja): preserve error state to trigger maintenance mode
        if share_instance['access_rules_status'] != constants.STATUS_ERROR:
            self.db.share_instance_update_access_status(
                context,
                share_instance_id,
                constants.STATUS_UPDATING)

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
            _rules = self.db.share_access_get_all_for_instance(
                context, share_instance['id'])
            rules = _rules
            if delete_rules:
                delete_ids = [rule['id'] for rule in delete_rules]
                rules = list(filter(lambda r: r['id'] not in delete_ids,
                                    rules))
                # NOTE(ganso): trigger maintenance mode
                if share_instance['access_rules_status'] == (
                        constants.STATUS_ERROR):
                    remove_rules = [
                        rule for rule in _rules
                        if rule["id"] in delete_ids]
                    delete_rules = []

        # NOTE(ganso): up to here we are certain of the rules that we are
        # supposed to pass to drivers. 'rules' variable is used for validating
        # the refresh mechanism later, according to the 'supposed' rules.
        driver_rules = rules

        if share_instance['status'] == constants.STATUS_MIGRATING:
            # NOTE(ganso): If the share instance is the source in a migration,
            # it should have all its rules cast to read-only.

            readonly_support = self.driver.configuration.safe_get(
                'migration_readonly_rules_support')

            # NOTE(ganso): If the backend supports read-only rules, then all
            # rules are cast to read-only here and passed to drivers.
            if readonly_support:
                for rule in driver_rules + add_rules:
                    rule['access_level'] = constants.ACCESS_LEVEL_RO
                LOG.debug("All access rules of share instance %s are being "
                          "cast to read-only for migration.",
                          share_instance['id'])
            # NOTE(ganso): If the backend does not support read-only rules, we
            # will remove all access to the share and have only the access
            # requested by the Data Service for migration as RW.
            else:
                LOG.debug("All previously existing access rules of share "
                          "instance %s are being removed for migration, as "
                          "driver does not support read-only mode rules.",
                          share_instance['id'])
                driver_rules = add_rules

        try:
            access_keys = None
            try:
                access_keys = self.driver.update_access(
                    context,
                    share_instance,
                    driver_rules,
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

            if access_keys:
                self._validate_access_keys(rules, add_rules, delete_rules,
                                           access_keys)

                for access_id, access_key in access_keys.items():
                    self.db.share_access_update_access_key(
                        context, access_id, access_key)

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
            self._update_access_rules(context, share_instance_id,
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

    @staticmethod
    def _validate_access_keys(access_rules, add_rules, delete_rules,
                              access_keys):
        if not isinstance(access_keys, dict):
            msg = _("The access keys must be supplied as a dictionary that "
                    "maps rule IDs to access keys.")
            raise exception.Invalid(message=msg)

        actual_rule_ids = sorted(access_keys)
        expected_rule_ids = []
        if not (add_rules or delete_rules):
            expected_rule_ids = [rule['id'] for rule in access_rules]
        else:
            expected_rule_ids = [rule['id'] for rule in add_rules]
        if actual_rule_ids != sorted(expected_rule_ids):
            msg = (_("The rule IDs supplied: %(actual)s do not match the "
                     "rule IDs that are expected: %(expected)s.")
                   % {'actual': actual_rule_ids,
                      'expected': expected_rule_ids})
            raise exception.Invalid(message=msg)

        for access_key in access_keys.values():
            if not isinstance(access_key, six.string_types):
                msg = (_("Access key %s is not string type.") % access_key)
                raise exception.Invalid(message=msg)

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
