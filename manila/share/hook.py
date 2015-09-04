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

"""
Module with hook interface for actions performed by share driver.

All available hooks are placed in manila/share/hooks dir.

Hooks are used by share services and can serve several use cases such as
any kind of notification and performing additional backend-specific actions.
"""

import abc

from oslo_config import cfg
from oslo_log import log
import six

from manila import context as ctxt
from manila.i18n import _LW


hook_options = [
    cfg.BoolOpt(
        "enable_pre_hooks",
        default=False,
        help="Whether to enable pre hooks or not.",
        deprecated_group='DEFAULT'),
    cfg.BoolOpt(
        "enable_post_hooks",
        default=False,
        help="Whether to enable post hooks or not.",
        deprecated_group='DEFAULT'),
    cfg.BoolOpt(
        "enable_periodic_hooks",
        default=False,
        help="Whether to enable periodic hooks or not.",
        deprecated_group='DEFAULT'),
    cfg.BoolOpt(
        "suppress_pre_hooks_errors",
        default=False,
        help="Whether to suppress pre hook errors (allow driver perform "
             "actions) or not.",
        deprecated_group='DEFAULT'),
    cfg.BoolOpt(
        "suppress_post_hooks_errors",
        default=False,
        help="Whether to suppress post hook errors (allow driver's results "
             "to pass through) or not.",
        deprecated_group='DEFAULT'),
    cfg.FloatOpt(
        "periodic_hooks_interval",
        default=300.0,
        help="Interval in seconds between execution of periodic hooks. "
             "Used when option 'enable_periodic_hooks' is set to True. "
             "Default is 300.",
        deprecated_group='DEFAULT'),
]

CONF = cfg.CONF
CONF.register_opts(hook_options)
LOG = log.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class HookBase(object):

    def get_config_option(self, key):
        if self.configuration:
            return self.configuration.safe_get(key)
        return CONF.get(key)

    def __init__(self, configuration, host):
        self.host = host
        self.configuration = configuration
        if self.configuration:
            self.configuration.append_config_values(hook_options)

        self.pre_hooks_enabled = self.get_config_option("enable_pre_hooks")
        self.post_hooks_enabled = self.get_config_option("enable_post_hooks")
        self.periodic_hooks_enabled = self.get_config_option(
            "enable_periodic_hooks")
        self.suppress_pre_hooks_errors = self.get_config_option(
            "suppress_pre_hooks_errors")
        self.suppress_post_hooks_errors = self.get_config_option(
            "suppress_post_hooks_errors")

    def execute_pre_hook(self, context=None, func_name=None, *args, **kwargs):
        """Hook called before driver's action."""
        if not self.pre_hooks_enabled:
            return
        LOG.debug("Running 'pre hook'.")
        context = context or ctxt.get_admin_context()
        try:
            pre_data = self._execute_pre_hook(
                context=context,
                func_name=func_name,
                *args, **kwargs)
        except Exception as e:
            if self.suppress_pre_hooks_errors:
                LOG.warning(_LW("\nSuppressed exception in pre hook. %s\n"), e)
                pre_data = e
            else:
                raise
        return pre_data

    def execute_post_hook(self, context=None, func_name=None,
                          pre_hook_data=None, driver_action_results=None,
                          *args, **kwargs):
        """Hook called after driver's action."""
        if not self.post_hooks_enabled:
            return
        LOG.debug("Running 'post hook'.")
        context = context or ctxt.get_admin_context()

        try:
            post_data = self._execute_post_hook(
                context=context,
                func_name=func_name,
                pre_hook_data=pre_hook_data,
                driver_action_results=driver_action_results,
                *args, **kwargs)
        except Exception as e:
            if self.suppress_post_hooks_errors:
                LOG.warning(
                    _LW("\nSuppressed exception in post hook. %s\n"), e)
                post_data = e
            else:
                raise
        return post_data

    def execute_periodic_hook(self, context, periodic_hook_data,
                              *args, **kwargs):
        """Hook called on periodic basis."""
        if not self.periodic_hooks_enabled:
            return
        LOG.debug("Running 'periodic hook'.")
        context = context or ctxt.get_admin_context()
        return self._execute_periodic_hook(
            context, periodic_hook_data, *args, **kwargs)

    @abc.abstractmethod
    def _execute_pre_hook(self, context, func_name, *args, **kwargs):
        """Redefine this method for pre hook action."""

    @abc.abstractmethod
    def _execute_post_hook(self, context, func_name, pre_hook_data,
                           driver_action_results, *args, **kwargs):
        """Redefine this method for post hook action."""

    @abc.abstractmethod
    def _execute_periodic_hook(self, context, periodic_hook_data,
                               *args, **kwargs):
        """Redefine this method for periodic hook action."""
