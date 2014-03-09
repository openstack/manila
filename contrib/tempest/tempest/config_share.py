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
    cfg.BoolOpt("manila",
                default=True,
                help="Whether or not manila is expected to be available"),
]

share_group = cfg.OptGroup(name="share", title="Share Service Options")

ShareGroup = [
    cfg.StrOpt("catalog_type",
               default="share",
               help="Catalog type of the Share service."),
    cfg.StrOpt('endpoint_type',
               default='publicURL',
               choices=['public', 'admin', 'internal',
                        'publicURL', 'adminURL', 'internalURL'],
               help="The endpoint type to use for the share service."),
    cfg.BoolOpt("multitenancy_enabled",
                default=True,
                help="This option used to determine backend driver type, "
                     "multitenant driver uses share-networks, but "
                     "single-tenant doesn't."),
    cfg.ListOpt("enable_protocols",
                default=["nfs", "cifs"],
                help="First value of list is protocol by default, "
                     "items of list show enabled protocols at all."),
    cfg.ListOpt("enable_ip_rules_for_protocols",
                default=["nfs", ],
                help="Selection of protocols, that should "
                     "be covered with ip rule tests"),
    cfg.ListOpt("enable_sid_rules_for_protocols",
                default=[],
                help="Selection of protocols, that should "
                     "be covered with sid rule tests"),
    cfg.StrOpt("username_for_sid_rules",
               default="Administrator",
               help="Username, that will be used in sid tests. "
                    "In case of active directory it should be existed"),
    cfg.StrOpt("share_network_id",
               default="",
               help="Some backend drivers requires share network "
                    "for share creation. Share network id, that will be "
                    "used for shares. If not set, it won't be used."),
    cfg.StrOpt("alt_share_network_id",
               default="",
               help="Share network id, that will be used for shares"
                    " in alt tenant. If not set, it won't be used"),
    cfg.StrOpt("admin_share_network_id",
               default="",
               help="Share network id, that will be used for shares"
                    " in admin tenant. If not set, it won't be used"),
    cfg.IntOpt("build_interval",
               default=10,
               help="Time in seconds between volume availability checks."),
    cfg.IntOpt("build_timeout",
               default=300,
               help="Timeout in seconds to wait for a volume to become"
                    "available."),
]


class TempestConfigPrivateManila(config.TempestConfigPrivate):

    # manila's config wrap over standard config
    def __init__(self, parse_conf=True):
        super(TempestConfigPrivateManila, self).__init__()
        config.register_opt_group(cfg.CONF, service_available_group,
                                  ServiceAvailableGroup)
        config.register_opt_group(cfg.CONF, share_group, ShareGroup)
        self.share = cfg.CONF.share


class TempestConfigProxyManila(object):
    _config = None

    def __getattr__(self, attr):
        if not self._config:
            self._config = TempestConfigPrivateManila()

        return getattr(self._config, attr)


CONF = TempestConfigProxyManila()
