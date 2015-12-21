# Copyright 2015 Mirantis, Inc.
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

import netaddr
from oslo_config import cfg
from oslo_log import log
import six

from manila.common import constants
from manila.compute import nova
import manila.context
from manila import exception
from manila.i18n import _
from manila import network
from manila import utils

nova_single_network_plugin_opts = [
    cfg.StrOpt(
        'nova_single_network_plugin_net_id',
        help="Default Nova network that will be used for share servers. "
             "This opt is used only with class 'NovaSingleNetworkPlugin'.",
        deprecated_group='DEFAULT'),
]

CONF = cfg.CONF
LOG = log.getLogger(__name__)


class NovaNetworkPlugin(network.NetworkBaseAPI):
    """Nova network plugin for share drivers.

    This plugin uses Nova networks provided within 'share-network' entities.
    """

    def __init__(self, config_group_name=None, db_driver=None, label=None):
        super(NovaNetworkPlugin, self).__init__(db_driver=db_driver)
        self.config_group_name = config_group_name or 'DEFAULT'
        self._label = label or 'user'
        self.admin_context = manila.context.get_admin_context()
        self.nova_api = nova.API()

    @property
    def label(self):
        return self._label

    @utils.synchronized(
        "allocate_network_for_nova_network_plugin", external=True)
    def allocate_network(self, context, share_server, share_network, **kwargs):
        # NOTE(vponomaryov): This one is made as wrapper for inheritance
        # purposes to avoid deadlock.
        return self._allocate_network(
            context, share_server, share_network, **kwargs)

    def _allocate_network(
            self, context, share_server, share_network, **kwargs):
        """Allocate network resources using one Nova network."""
        allocations = []
        allocation_count = kwargs.get('count', 1)
        if allocation_count < 1:
            return allocations
        nova_net_id = share_network.get('nova_net_id')
        if not nova_net_id:
            raise exception.NetworkException(
                _("'nova_net_id' is not provided with share network."))
        # NOTE(vponomaryov): nova network should be taken using admin context
        # because several required attrs of network are available
        # only for admins.
        nova_net = self.nova_api.network_get(self.admin_context, nova_net_id)
        self._save_network_info(context, nova_net, share_network)
        ip_addresses = self._get_available_ips(
            context, nova_net, allocation_count)
        for ip_address in ip_addresses:
            data = {
                'share_server_id': share_server['id'],
                'ip_address': ip_address,
                'status': constants.STATUS_ACTIVE,
                'label': self.label,
                'cidr': share_network['cidr'],
                'ip_version': share_network['ip_version'],
                'segmentation_id': share_network['segmentation_id'],
                'network_type': share_network['network_type'],
            }
            self.nova_api.fixed_ip_reserve(self.admin_context, ip_address)
            allocations.append(
                self.db.network_allocation_create(context, data))
        return allocations

    def _get_available_ips(self, context, nova_net, amount):
        """Returns unused IP addresses from provided Nova network.

        :param context: RequestContext instance
        :param nova_net: dict -- dictionary with data of nova network
        :param amount: int - amount of IP addresses to return
        :returns: IP addresses as list of text types
        :raises: exception.NetworkBadConfigurationException
        """
        cidr = nova_net['cidr'] or nova_net['cidr_v6']
        reserved = (
            six.text_type(netaddr.IPNetwork(cidr).network),
            nova_net['gateway'],
            nova_net['gateway_v6'],
            nova_net['dhcp_server'],
            nova_net['broadcast'],
            nova_net['vpn_private_address'],
            nova_net['vpn_public_address'],
            nova_net['dns1'],
            nova_net['dns2'])

        ips = []
        iterator = netaddr.iter_unique_ips(cidr)

        for ip in iterator:
            ip = six.text_type(ip)

            if ip in reserved:
                # This IP address is reserved for service needs
                continue
            elif self.db.network_allocations_get_by_ip_address(context, ip):
                # Some existing share server already uses this IP address
                continue
            fixed_ip = self.nova_api.fixed_ip_get(self.admin_context, ip)
            if fixed_ip.get('host') or fixed_ip.get('hostname'):
                # Some Nova VM already uses this IP address
                continue

            ips.append(ip)
            if len(ips) == amount:
                return ips
        msg = _("No available IP addresses left in network '%(net_id)s' with "
                "CIDR %(cidr)s. Requested amount of IPs to be provided "
                "'%(amount)s', available only '%(available)s'") % dict(
                    net_id=nova_net['id'], cidr=cidr, amount=amount,
                    available=len(ips))
        LOG.error(msg)
        raise exception.NetworkBadConfigurationException(reason=msg)

    def _save_network_info(self, context, nova_net, share_network):
        """Update 'share-network' with plugin specific data."""
        data = {
            'cidr': (nova_net['cidr'] or nova_net['cidr_v6']),
            'ip_version': (4 if nova_net['cidr'] else 6),
            'segmentation_id': nova_net['vlan'],
            'network_type': ('vlan' if nova_net['vlan'] else 'flat'),
        }
        share_network.update(data)
        if self.label != 'admin':
            self.db.share_network_update(context, share_network['id'], data)

    def deallocate_network(self, context, share_server_id):
        """Deallocate network resources for share server."""
        allocations = self.db.network_allocations_get_for_share_server(
            context, share_server_id)
        for allocation in allocations:
            self.db.network_allocation_delete(context, allocation['id'])
            self.nova_api.fixed_ip_unreserve(
                self.admin_context, allocation['ip_address'])


class NovaSingleNetworkPlugin(NovaNetworkPlugin):
    """Nova network plugin for share drivers.

    This plugin uses only one network that is predefined within config
    option 'nova_single_network_plugin_net_id' and stores all required info
    in provided 'share-network' that, further, can be used by share drivers.
    """

    def __init__(self, *args, **kwargs):
        super(NovaSingleNetworkPlugin, self).__init__(*args, **kwargs)
        CONF.register_opts(
            nova_single_network_plugin_opts,
            group=self.config_group_name)
        self.net_id = getattr(CONF, self.config_group_name,
                              CONF).nova_single_network_plugin_net_id
        if not self.net_id:
            msg = _("Nova network is not set")
            LOG.error(msg)
            raise exception.NetworkBadConfigurationException(reason=msg)

    @utils.synchronized(
        "allocate_network_for_nova_network_plugin", external=True)
    def allocate_network(self, context, share_server, share_network, **kwargs):
        if self.label != 'admin':
            share_network = self._update_share_network_net_data(
                context, share_network)
        else:
            share_network = {'nova_net_id': self.net_id}
        return self._allocate_network(
            context, share_server, share_network, **kwargs)

    def _update_share_network_net_data(self, context, share_network):
        neutron_data = share_network.get(
            'neutron_net_id', share_network.get('neutron_subnet_id'))
        if neutron_data:
            msg = _("'share-network' with id '%s' should not contain Neutron "
                    "data. Either remove it or use another "
                    "'share-network'") % share_network['id']
            LOG.error(msg)
            raise exception.NetworkBadConfigurationException(reason=msg)
        nova_net_id = share_network.get('nova_net_id')
        if nova_net_id and nova_net_id != self.net_id:
            msg = _("'share-network' with id '%(sn_id)s' already contains "
                    "Nova network id '%(provided)s' that is different from "
                    "what is defined in config '%(allowed)s'. Either remove "
                    "incorrect network id or set it the same") % dict(
                        sn_id=share_network['id'], provided=nova_net_id,
                        allowed=self.net_id)
            LOG.error(msg)
            raise exception.NetworkBadConfigurationException(reason=msg)
        elif not nova_net_id:
            share_network = self.db.share_network_update(
                context, share_network['id'], dict(nova_net_id=self.net_id))
        return share_network
