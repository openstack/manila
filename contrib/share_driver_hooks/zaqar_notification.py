# Copyright (c) 2015 Mirantis, Inc.
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
from oslo_utils import timeutils

from manila import exception
from manila.share import api
from manila.share import hook
from manila.share.hooks import zaqarclientwrapper  # noqa

CONF = zaqarclientwrapper.CONF
LOG = log.getLogger(__name__)
ZAQARCLIENT = zaqarclientwrapper.ZAQARCLIENT


class ZaqarNotification(hook.HookBase):
    share_api = api.API()

    def _access_changed_trigger(self, context, func_name,
                                access_rules_ids, share_instance_id):

        access = [self.db.share_access_get(context, rule_id)
                  for rule_id in access_rules_ids]

        share_instance = self.db.share_instance_get(context, share_instance_id)

        share = self.share_api.get(context, share_id=share_instance.share_id)

        def rules_view(rules):
            result = []

            for rule in rules:
                access_instance = None

                for ins in rule.instance_mappings:
                    if ins.share_instance_id == share_instance_id:
                        access_instance = ins
                        break
                    else:
                        raise exception.InstanceNotFound(
                            instance_id=share_instance_id)

                result.append({
                    'access_id': rule.id,
                    'access_instance_id': access_instance.id,
                    'access_type': rule.access_type,
                    'access_to': rule.access_to,
                    'access_level': rule.access_level,
                })
            return result

        is_allow_operation = 'allow' in func_name
        results = {
            'share_id': share.share_id,
            'share_instance_id': share_instance_id,
            'export_locations': [
                el.path for el in share_instance.export_locations],
            'share_proto': share.share_proto,
            'access_rules': rules_view(access),
            'is_allow_operation': is_allow_operation,
            'availability_zone': share_instance.availability_zone,
        }
        LOG.debug(results)
        return results

    def _execute_pre_hook(self, context, func_name, *args, **kwargs):
        LOG.debug("\n PRE zaqar notification has been called for "
                  "method '%s'.\n", func_name)
        if func_name == "deny_access":
            LOG.debug("\nSending notification about denied access.\n")
            data = self._access_changed_trigger(
                context,
                func_name,
                kwargs.get('access_rules'),
                kwargs.get('share_instance_id'),
            )
            self._send_notification(data)

    def _execute_post_hook(self, context, func_name, pre_hook_data,
                           driver_action_results, *args, **kwargs):
        LOG.debug("\n POST zaqar notification has been called for "
                  "method '%s'.\n", func_name)
        if func_name == "allow_access":
            LOG.debug("\nSending notification about allowed access.\n")
            data = self._access_changed_trigger(
                context,
                func_name,
                kwargs.get('access_rules'),
                kwargs.get('share_instance_id'),
            )
            self._send_notification(data)

    def _send_notification(self, data):
        for queue_name in CONF.zaqar.zaqar_queues:
            ZAQARCLIENT.queue_name = queue_name
            message = {
                "body": {
                    "example_message": (
                        "message generated at '%s'" % timeutils.utcnow()),
                    "data": data,
                }
            }
            LOG.debug(
                "\n Sending message %(m)s to '%(q)s' queue using '%(u)s' user "
                "and '%(p)s' project.", {
                    'm': message,
                    'q': queue_name,
                    'u': CONF.zaqar.zaqar_username,
                    'p': CONF.zaqar.zaqar_project_name,
                }
            )
            queue = ZAQARCLIENT.queue(queue_name)
            queue.post(message)

    def _execute_periodic_hook(self, context, periodic_hook_data,
                               *args, **kwargs):
        LOG.debug("Periodic zaqar notification has been called. (Placeholder)")
