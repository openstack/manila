# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 Mirantis Inc.
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

from __future__ import print_function

from oslo.config import cfg

from tempest import config

service_available_group = cfg.OptGroup(name="service_available",
                                       title="Available OpenStack Services")

ServiceAvailableGroup = [
    cfg.BoolOpt('manila',
                default=True,
                help="Whether or not manila is expected to be available"),
]

shares_group = cfg.OptGroup(name="shares",
                            title="Shares Service Options")

SharesGroup = [
    cfg.StrOpt('share_protocol',
               default="nfs",
               help="File share type by default"),
    cfg.IntOpt('build_interval',
               default=10,
               help='Time in seconds between volume availability checks.'),
    cfg.IntOpt('build_timeout',
               default=300,
               help='Timeout in seconds to wait for a volume to become'
                    'available.'),
    cfg.StrOpt('catalog_type',
               default="share",
               help='Catalog type of the Shares service.'),
    cfg.BoolOpt('only_admin_or_owner_for_action',
                default=True,
                help='This flag use tests that verify policy.json rules'),
]


# this should never be called outside of this class
class TempestConfigPrivateManila(config.TempestConfigPrivate):

    # manila's config wrap over standard config
    def __init__(self, parse_conf=True):
        super(TempestConfigPrivateManila, self).__init__()
        config.register_opt_group(cfg.CONF, service_available_group,
                                  ServiceAvailableGroup)
        config.register_opt_group(cfg.CONF, shares_group, SharesGroup)
        self.shares = cfg.CONF.shares


class TempestConfigProxyManila(object):
    _config = None

    def __getattr__(self, attr):
        if not self._config:
            self._config = TempestConfigPrivateManila()

        return getattr(self._config, attr)


CONF = TempestConfigProxyManila()
