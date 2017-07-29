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

import copy
import ipaddress

from oslo_log import log

from manila.common import constants
from manila.i18n import _
from manila import utils

import six

LOG = log.getLogger(__name__)


def locked_access_rules_operation(operation):
    """Lock decorator for access rules operations.

    Takes a named lock prior to executing the operation. The lock is
    named with the ID of the share instance to which the access rule belongs.

    Intended use:
    If an database operation to retrieve or update access rules uses this
    decorator, it will block actions on all access rules of the share
    instance until the named lock is free. This is used to avoid race
    conditions while performing access rules updates on a given share instance.
    """

    def wrapped(*args, **kwargs):
        instance_id = kwargs.get('share_instance_id')

        @utils.synchronized(
            "locked_access_rules_operation_by_share_instance_%s" % instance_id,
            external=True)
        def locked_operation(*_args, **_kwargs):
            return operation(*_args, **_kwargs)

        return locked_operation(*args, **kwargs)

    return wrapped


class ShareInstanceAccessDatabaseMixin(object):

    @locked_access_rules_operation
    def get_and_update_share_instance_access_rules_status(
            self, context, status=None, conditionally_change=None,
            share_instance_id=None):
        """Get and update the access_rules_status of a share instance.

        :param status: Set this parameter only if you want to
            omit the conditionally_change parameter; i.e, if you want to
            force a state change on the share instance regardless of the prior
            state.
        :param conditionally_change: Set this parameter to a dictionary of rule
            state transitions to be made. The key is the expected
            access_rules_status and the value is the state to transition the
            access_rules_status to. If the state is not as expected,
            no transition is performed. Default is {}, which means no state
            transitions will be made.
        :returns share_instance: if an update was made.
        """
        if status is not None:
            updates = {'access_rules_status': status}
        elif conditionally_change:
            share_instance = self.db.share_instance_get(
                context, share_instance_id)
            access_rules_status = share_instance['access_rules_status']
            try:
                updates = {
                    'access_rules_status':
                        conditionally_change[access_rules_status],
                }
            except KeyError:
                updates = {}
        else:
            updates = {}
        if updates:
            share_instance = self.db.share_instance_update(
                context, share_instance_id, updates, with_share_data=True)
            return share_instance

    @locked_access_rules_operation
    def get_and_update_share_instance_access_rules(self, context,
                                                   filters=None, updates=None,
                                                   conditionally_change=None,
                                                   share_instance_id=None):
        """Get and conditionally update all access rules of a share instance.

        :param updates: Set this parameter to a dictionary of key:value
            pairs corresponding to the keys in the ShareInstanceAccessMapping
            model. Include 'state' in this dictionary only if you want to
            omit the conditionally_change parameter; i.e, if you want to
            force a state change on all filtered rules regardless of the prior
            state. This parameter is always honored, regardless of whether
            conditionally_change allows for a state transition as desired.

            Example::

            {
                'access_key': 'bob007680048318f4239dfc1c192d5',
                'access_level': 'ro',
            }

        :param conditionally_change: Set this parameter to a dictionary of rule
            state transitions to be made. The key is the expected state of
            the access rule the value is the state to transition the
            access rule to. If the state is not as expected, no transition is
            performed. Default is {}, which means no state transitions
            will be made.

            Example::

            {
                'queued_to_apply': 'applying',
                'queued_to_deny': 'denying',
            }

        """
        instance_rules = self.db.share_access_get_all_for_instance(
            context, share_instance_id, filters=filters)

        if instance_rules and (updates or conditionally_change):
            if not updates:
                updates = {}
            if not conditionally_change:
                conditionally_change = {}
            for rule in instance_rules:
                mapping_state = rule['state']
                rule_updates = copy.deepcopy(updates)
                try:
                    rule_updates['state'] = conditionally_change[mapping_state]
                except KeyError:
                    pass
                if rule_updates:
                    self.db.share_instance_access_update(
                        context, rule['access_id'], share_instance_id,
                        rule_updates)

            # Refresh the rules after the updates
            rules_to_get = {
                'access_id': tuple([i['access_id'] for i in instance_rules]),
            }
            instance_rules = self.db.share_access_get_all_for_instance(
                context, share_instance_id, filters=rules_to_get)

        return instance_rules

    def get_share_instance_access_rules(self, context, filters=None,
                                        share_instance_id=None):
        return self.get_and_update_share_instance_access_rules(
            context, filters, None, None, share_instance_id)

    @locked_access_rules_operation
    def get_and_update_share_instance_access_rule(self, context, rule_id,
                                                  updates=None,
                                                  share_instance_id=None,
                                                  conditionally_change=None):
        """Get and conditionally update a given share instance access rule.

        :param updates: Set this parameter to a dictionary of key:value
            pairs corresponding to the keys in the ShareInstanceAccessMapping
            model. Include 'state' in this dictionary only if you want to
            omit the conditionally_change parameter; i.e, if you want to
            force a state change regardless of the prior state.
        :param conditionally_change: Set this parameter to a dictionary of rule
            state transitions to be made. The key is the expected state of
            the access rule the value is the state to transition the
            access rule to. If the state is not as expected, no transition is
            performed. Default is {}, which means no state transitions
            will be made.

            Example::

            {
                'queued_to_apply': 'applying',
                'queued_to_deny': 'denying',
            }
        """
        instance_rule_mapping = self.db.share_instance_access_get(
            context, rule_id, share_instance_id)

        if not updates:
            updates = {}
        if conditionally_change:
            mapping_state = instance_rule_mapping['state']
            try:
                updated_state = conditionally_change[mapping_state]
                updates.update({'state': updated_state})
            except KeyError:
                msg = ("The state of the access rule %(rule_id)s (allowing "
                       "access to share instance %(si)s) was not updated "
                       "because its state was modified by another operation.")
                msg_payload = {
                    'si': share_instance_id,
                    'rule_id': rule_id,
                }
                LOG.debug(msg, msg_payload)
        if updates:
            self.db.share_instance_access_update(
                context, rule_id, share_instance_id, updates)

            # Refresh the rule after update
            instance_rule_mapping = self.db.share_instance_access_get(
                context, rule_id, share_instance_id)

        return instance_rule_mapping

    @locked_access_rules_operation
    def delete_share_instance_access_rules(self, context, access_rules,
                                           share_instance_id=None):
        for rule in access_rules:
            self.db.share_instance_access_delete(context, rule['id'])


class ShareInstanceAccess(ShareInstanceAccessDatabaseMixin):

    def __init__(self, db, driver):
        self.db = db
        self.driver = driver

    def update_access_rules(self, context, share_instance_id,
                            delete_all_rules=False, share_server=None):
        """Update access rules for a given share instance.

        :param context: request context
        :param share_instance_id: ID of the share instance
        :param delete_all_rules: set this parameter to True if all
        existing access rules must be denied for a given share instance
        :param share_server: Share server model or None
        """
        share_instance = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)
        msg_payload = {
            'si': share_instance_id,
            'shr': share_instance['share_id'],
        }

        if delete_all_rules:
            updates = {
                'state': constants.ACCESS_STATE_QUEUED_TO_DENY,
            }
            self.get_and_update_share_instance_access_rules(
                context, updates=updates, share_instance_id=share_instance_id)

        # Is there a sync in progress? If yes, ignore the incoming request.
        rule_filter = {
            'state': (constants.ACCESS_STATE_APPLYING,
                      constants.ACCESS_STATE_DENYING),
        }
        syncing_rules = self.get_and_update_share_instance_access_rules(
            context, filters=rule_filter, share_instance_id=share_instance_id)

        if syncing_rules:
            msg = ("Access rules are being synced for share instance "
                   "%(si)s belonging to share %(shr)s, any rule changes will "
                   "be applied shortly.")
            LOG.debug(msg, msg_payload)
        else:
            rules_to_apply_or_deny = (
                self._update_and_get_unsynced_access_rules_from_db(
                    context, share_instance_id)
            )
            if rules_to_apply_or_deny:
                msg = ("Updating access rules for share instance %(si)s "
                       "belonging to share %(shr)s.")
                LOG.debug(msg, msg_payload)
                self._update_access_rules(context, share_instance_id,
                                          share_server=share_server)
            else:
                msg = ("All access rules have been synced for share instance "
                       "%(si)s belonging to share %(shr)s.")
                LOG.debug(msg, msg_payload)

    def _update_access_rules(self, context, share_instance_id,
                             share_server=None):
        # Refresh the share instance model
        share_instance = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)

        conditionally_change = {
            constants.STATUS_ACTIVE: constants.SHARE_INSTANCE_RULES_SYNCING,
        }
        share_instance = (
            self.get_and_update_share_instance_access_rules_status(
                context, conditionally_change=conditionally_change,
                share_instance_id=share_instance_id) or share_instance
        )

        rules_to_be_removed_from_db = []
        # Populate rules to send to the driver
        (access_rules_to_be_on_share, add_rules, delete_rules) = (
            self._get_rules_to_send_to_driver(context, share_instance)
        )

        if share_instance['cast_rules_to_readonly']:
            # Ensure read/only semantics for a migrating instances
            access_rules_to_be_on_share = self._set_rules_to_readonly(
                access_rules_to_be_on_share, share_instance)
            add_rules = []
            rules_to_be_removed_from_db = delete_rules
            delete_rules = []

        try:
            driver_rule_updates = self._update_rules_through_share_driver(
                context, share_instance, access_rules_to_be_on_share,
                add_rules, delete_rules, rules_to_be_removed_from_db,
                share_server)

            self._process_driver_rule_updates(
                context, driver_rule_updates, share_instance_id)

            # Update access rules that are still in 'applying' state
            conditionally_change = {
                constants.ACCESS_STATE_APPLYING: constants.ACCESS_STATE_ACTIVE,
            }
            self.get_and_update_share_instance_access_rules(
                context, share_instance_id=share_instance_id,
                conditionally_change=conditionally_change)

        except Exception:
            conditionally_change_rule_state = {
                constants.ACCESS_STATE_APPLYING: constants.ACCESS_STATE_ERROR,
                constants.ACCESS_STATE_DENYING: constants.ACCESS_STATE_ERROR,
            }
            self.get_and_update_share_instance_access_rules(
                context, share_instance_id=share_instance_id,
                conditionally_change=conditionally_change_rule_state)

            conditionally_change_access_rules_status = {
                constants.ACCESS_STATE_ACTIVE: constants.STATUS_ERROR,
                constants.SHARE_INSTANCE_RULES_SYNCING: constants.STATUS_ERROR,
            }
            self.get_and_update_share_instance_access_rules_status(
                context, share_instance_id=share_instance_id,
                conditionally_change=conditionally_change_access_rules_status)
            raise

        if rules_to_be_removed_from_db:
            delete_rules = rules_to_be_removed_from_db

        self.delete_share_instance_access_rules(
            context, delete_rules, share_instance_id=share_instance['id'])

        self._loop_for_refresh_else_update_access_rules_status(
            context, share_instance_id, share_server)

        msg = _("Access rules were successfully modified for share instance "
                "%(si)s belonging to share %(shr)s.")
        msg_payload = {
            'si': share_instance['id'],
            'shr': share_instance['share_id'],
        }
        LOG.info(msg, msg_payload)

    def _update_rules_through_share_driver(self, context, share_instance,
                                           access_rules_to_be_on_share,
                                           add_rules, delete_rules,
                                           rules_to_be_removed_from_db,
                                           share_server):
        driver_rule_updates = {}
        share_protocol = share_instance['share_proto'].lower()
        if (not self.driver.ipv6_implemented and
                share_protocol == 'nfs'):
            add_rules = self._filter_ipv6_rules(add_rules)
            delete_rules = self._filter_ipv6_rules(delete_rules)
            access_rules_to_be_on_share = self._filter_ipv6_rules(
                access_rules_to_be_on_share)
        try:
            driver_rule_updates = self.driver.update_access(
                context,
                share_instance,
                access_rules_to_be_on_share,
                add_rules=add_rules,
                delete_rules=delete_rules,
                share_server=share_server
            ) or {}
        except NotImplementedError:
            # NOTE(u_glide): Fallback to legacy allow_access/deny_access
            # for drivers without update_access() method support
            self._update_access_fallback(context, add_rules, delete_rules,
                                         rules_to_be_removed_from_db,
                                         share_instance,
                                         share_server)
        return driver_rule_updates

    def _loop_for_refresh_else_update_access_rules_status(self, context,
                                                          share_instance_id,
                                                          share_server):
        # Do we need to re-sync or apply any new changes?
        if self._check_needs_refresh(context, share_instance_id):
            self._update_access_rules(context, share_instance_id,
                                      share_server=share_server)
        else:
            # Switch the share instance's access_rules_status to 'active'
            # if there are no more rules in 'error' state, else, ensure
            # 'error' state.
            rule_filter = {'state': constants.STATUS_ERROR}
            rules_in_error_state = (
                self.get_and_update_share_instance_access_rules(
                    context, filters=rule_filter,
                    share_instance_id=share_instance_id)
            )
            if not rules_in_error_state:
                conditionally_change = {
                    constants.SHARE_INSTANCE_RULES_SYNCING:
                        constants.STATUS_ACTIVE,
                    constants.SHARE_INSTANCE_RULES_ERROR:
                        constants.STATUS_ACTIVE,
                }
                self.get_and_update_share_instance_access_rules_status(
                    context, conditionally_change=conditionally_change,
                    share_instance_id=share_instance_id)
            else:
                conditionally_change = {
                    constants.SHARE_INSTANCE_RULES_SYNCING:
                        constants.SHARE_INSTANCE_RULES_ERROR,
                }
                self.get_and_update_share_instance_access_rules_status(
                    context, conditionally_change=conditionally_change,
                    share_instance_id=share_instance_id)

    def _process_driver_rule_updates(self, context, driver_rule_updates,
                                     share_instance_id):
        for rule_id, rule_updates in driver_rule_updates.items():
            if 'state' in rule_updates:
                # We allow updates *only* if the state is unchanged from
                # the time this update was initiated. It is possible
                # that the access rule was denied at the API prior to
                # the driver reporting that the access rule was added
                # successfully.
                state = rule_updates.pop('state')
                conditional_state_updates = {
                    constants.ACCESS_STATE_APPLYING: state,
                    constants.ACCESS_STATE_DENYING: state,
                    constants.ACCESS_STATE_ACTIVE: state,
                }
            else:
                conditional_state_updates = {}
            self.get_and_update_share_instance_access_rule(
                context, rule_id, updates=rule_updates,
                share_instance_id=share_instance_id,
                conditionally_change=conditional_state_updates)

    @staticmethod
    def _set_rules_to_readonly(access_rules_to_be_on_share, share_instance):

        LOG.debug("All access rules of share instance %s are being "
                  "cast to read-only for a migration or because the "
                  "instance is a readable replica.",
                  share_instance['id'])

        for rule in access_rules_to_be_on_share:
            rule['access_level'] = constants.ACCESS_LEVEL_RO

        return access_rules_to_be_on_share

    @staticmethod
    def _filter_ipv6_rules(rules):
        filtered = []
        for rule in rules:
            if rule['access_type'] == 'ip':
                ip_version = ipaddress.ip_network(
                    six.text_type(rule['access_to'])).version
                if 6 == ip_version:
                    continue
            filtered.append(rule)
        return filtered

    def _get_rules_to_send_to_driver(self, context, share_instance):
        add_rules = []
        delete_rules = []
        access_filters = {
            'state': (constants.ACCESS_STATE_APPLYING,
                      constants.ACCESS_STATE_ACTIVE,
                      constants.ACCESS_STATE_DENYING),
        }
        existing_rules_in_db = self.get_and_update_share_instance_access_rules(
            context, filters=access_filters,
            share_instance_id=share_instance['id'])
        # Update queued rules to transitional states
        for rule in existing_rules_in_db:

            if rule['state'] == constants.ACCESS_STATE_APPLYING:
                add_rules.append(rule)
            elif rule['state'] == constants.ACCESS_STATE_DENYING:
                delete_rules.append(rule)
        delete_rule_ids = [r['id'] for r in delete_rules]
        access_rules_to_be_on_share = [
            r for r in existing_rules_in_db if r['id'] not in delete_rule_ids
        ]
        return access_rules_to_be_on_share, add_rules, delete_rules

    def _check_needs_refresh(self, context, share_instance_id):
        rules_to_apply_or_deny = (
            self._update_and_get_unsynced_access_rules_from_db(
                context, share_instance_id)
        )
        return any(rules_to_apply_or_deny)

    def _update_access_fallback(self, context, add_rules, delete_rules,
                                remove_rules, share_instance, share_server):
        for rule in add_rules:
            LOG.info(
                "Applying access rule '%(rule)s' for share "
                "instance '%(instance)s'",
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
            delete_rules.extend(remove_rules)

        for rule in delete_rules:
            LOG.info(
                "Denying access rule '%(rule)s' from share "
                "instance '%(instance)s'",
                {'rule': rule['id'], 'instance': share_instance['id']}
            )

            self.driver.deny_access(
                context,
                share_instance,
                rule,
                share_server=share_server
            )

    def _update_and_get_unsynced_access_rules_from_db(self, context,
                                                      share_instance_id):
        rule_filter = {
            'state': (constants.ACCESS_STATE_QUEUED_TO_APPLY,
                      constants.ACCESS_STATE_QUEUED_TO_DENY),
        }
        conditionally_change = {
            constants.ACCESS_STATE_QUEUED_TO_APPLY:
                constants.ACCESS_STATE_APPLYING,
            constants.ACCESS_STATE_QUEUED_TO_DENY:
                constants.ACCESS_STATE_DENYING,
        }
        rules_to_apply_or_deny = (
            self.get_and_update_share_instance_access_rules(
                context, filters=rule_filter,
                share_instance_id=share_instance_id,
                conditionally_change=conditionally_change)
        )
        return rules_to_apply_or_deny

    def reset_applying_rules(self, context, share_instance_id):
        conditional_updates = {
            constants.ACCESS_STATE_APPLYING:
                constants.ACCESS_STATE_QUEUED_TO_APPLY,
            constants.ACCESS_STATE_DENYING:
                constants.ACCESS_STATE_QUEUED_TO_DENY,
        }
        self.get_and_update_share_instance_access_rules(
            context, share_instance_id=share_instance_id,
            conditionally_change=conditional_updates)
