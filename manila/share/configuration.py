#
# Copyright (c) 2012 Rackspace Hosting
# Copyright (c) 2013 NetApp
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
Configuration support for all drivers.

This module allows support for setting configurations either from default
or from a particular CONF group, to be able to set multiple configurations
for a given set of values.

For instance, two generic configurations can be set by naming them in groups as

 [generic1]
 share_backend_name=generic-backend-1
 ...

 [generic2]
 share_backend_name=generic-backend-2
 ...

And the configuration group name will be passed in so that all calls to
configuration.volume_group within that instance will be mapped to the proper
named group.

This class also ensures the implementation's configuration is grafted into the
option group. This is due to the way cfg works. All cfg options must be defined
and registered in the group in which they are used.
"""

from oslo_config import cfg

CONF = cfg.CONF


class Configuration(object):

    def __init__(self, share_opts, config_group=None):
        """Graft config values into config group.

        This takes care of grafting the implementation's config values
        into the config group.
        """
        self.config_group = config_group

        # set the local conf so that __call__'s know what to use
        if self.config_group:
            self._ensure_config_values(share_opts)
            self.local_conf = CONF._get(self.config_group)
        else:
            self.local_conf = CONF

    def _ensure_config_values(self, share_opts):
        CONF.register_opts(share_opts,
                           group=self.config_group)

    def append_config_values(self, share_opts):
        self._ensure_config_values(share_opts)

    def safe_get(self, value):
        try:
            return self.__getattr__(value)
        except cfg.NoSuchOptError:
            return None

    def __getattr__(self, value):
        return getattr(self.local_conf, value)
