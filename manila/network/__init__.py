# Copyright 2013 OpenStack Foundation
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
import abc

from oslo_config import cfg
from oslo_utils import importutils
import six

from manila.db import base as db_base
from manila import exception
from manila.i18n import _

network_opts = [
    cfg.StrOpt(
        'network_api_class',
        default='manila.network.neutron.'
                'neutron_network_plugin.NeutronNetworkPlugin',
        deprecated_group='DEFAULT',
        help='The full class name of the Networking API class to use.'),
]

network_base_opts = [
    cfg.BoolOpt(
        'network_plugin_ipv4_enabled',
        default=True,
        help="Whether to support IPv4 network resource, Default=True."),
    cfg.BoolOpt(
        'network_plugin_ipv6_enabled',
        default=False,
        help="Whether to support IPv6 network resource, Default=False. "
             "If this option is True, the value of "
             "'network_plugin_ipv4_enabled' will be ignored."),
]

CONF = cfg.CONF


def API(config_group_name=None, label='user'):
    """Selects class and config group of network plugin.

    :param config_group_name: name of config group to be used for
                              registration of networking opts.
    :returns: instance of networking plugin class
    """
    CONF.register_opts(network_opts, group=config_group_name)
    if config_group_name:
        network_api_class = getattr(CONF, config_group_name).network_api_class
    else:
        network_api_class = CONF.network_api_class
    cls = importutils.import_class(network_api_class)
    return cls(config_group_name=config_group_name, label=label)


@six.add_metaclass(abc.ABCMeta)
class NetworkBaseAPI(db_base.Base):
    """User network plugin for setting up main net interfaces."""

    def __init__(self, config_group_name=None, db_driver=None):
        if config_group_name:
            CONF.register_opts(network_base_opts,
                               group=config_group_name)
        else:
            CONF.register_opts(network_base_opts)
        self.configuration = getattr(CONF,
                                     six.text_type(config_group_name), CONF)
        super(NetworkBaseAPI, self).__init__(db_driver=db_driver)

    def _verify_share_network(self, share_server_id, share_network):
        if share_network is None:
            msg = _("'Share network' is not provided for setting up "
                    "network interfaces for 'Share server' "
                    "'%s'.") % share_server_id
            raise exception.NetworkBadConfigurationException(reason=msg)

    def update_network_allocation(self, context, share_server):
        """Update network allocation.

        Optional method to be called by the manager after share server creation
        which can be overloaded in case the port state has to be updated.

        :param context: RequestContext object
        :param share_server: share server object
        :return: list of updated ports or None if nothing was updated
        """

    @abc.abstractmethod
    def allocate_network(self, context, share_server, share_network=None,
                         **kwargs):
        pass

    @abc.abstractmethod
    def deallocate_network(self, context, share_server_id):
        pass

    @property
    def enabled_ip_versions(self):
        if not hasattr(self, '_enabled_ip_versions'):
            self._enabled_ip_versions = set()
            if self.configuration.network_plugin_ipv6_enabled:
                self._enabled_ip_versions.add(6)
            if self.configuration.network_plugin_ipv4_enabled:
                self._enabled_ip_versions.add(4)
            if not self._enabled_ip_versions:
                msg = _("Either 'network_plugin_ipv4_enabled' or "
                        "'network_plugin_ipv6_enabled' "
                        "should be configured to 'True'.")
                raise exception.NetworkBadConfigurationException(reason=msg)
        return self._enabled_ip_versions
