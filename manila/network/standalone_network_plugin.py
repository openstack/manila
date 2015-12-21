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
from manila import exception
from manila.i18n import _
from manila import network
from manila import utils

standalone_network_plugin_opts = [
    cfg.StrOpt(
        'standalone_network_plugin_gateway',
        help="Gateway IPv4 address that should be used. Required.",
        deprecated_group='DEFAULT'),
    cfg.StrOpt(
        'standalone_network_plugin_mask',
        help="Network mask that will be used. Can be either decimal "
             "like '24' or binary like '255.255.255.0'. Required.",
        deprecated_group='DEFAULT'),
    cfg.StrOpt(
        'standalone_network_plugin_network_type',
        help="Network type, such as 'flat', 'vlan', 'vxlan' or 'gre'. "
             "Empty value is alias for 'flat'. "
             "It will be assigned to share-network and share drivers will be "
             "able to use this for network interfaces within provisioned "
             "share servers. Optional.",
        choices=['flat', 'vlan', 'vxlan', 'gre'],
        deprecated_group='DEFAULT'),
    cfg.IntOpt(
        'standalone_network_plugin_segmentation_id',
        help="Set it if network has segmentation (VLAN, VXLAN, etc...). "
             "It will be assigned to share-network and share drivers will be "
             "able to use this for network interfaces within provisioned "
             "share servers. Optional. Example: 1001",
        deprecated_group='DEFAULT'),
    cfg.ListOpt(
        'standalone_network_plugin_allowed_ip_ranges',
        help="Can be IP address, range of IP addresses or list of addresses "
             "or ranges. Contains addresses from IP network that are allowed "
             "to be used. If empty, then will be assumed that all host "
             "addresses from network can be used. Optional. "
             "Examples: 10.0.0.10 or 10.0.0.10-10.0.0.20 or "
             "10.0.0.10-10.0.0.20,10.0.0.30-10.0.0.40,10.0.0.50",
        deprecated_group='DEFAULT'),
    cfg.IntOpt(
        'standalone_network_plugin_ip_version',
        default=4,
        help="IP version of network. Optional."
             "Allowed values are '4' and '6'. Default value is '4'.",
        deprecated_group='DEFAULT'),
]

CONF = cfg.CONF
LOG = log.getLogger(__name__)


class StandaloneNetworkPlugin(network.NetworkBaseAPI):
    """Standalone network plugin for share drivers.

    This network plugin can be used with any network platform.
    It can serve flat networks as well as segmented.
    It does not require some specific network services in OpenStack like
    Neutron or Nova.
    The only thing that plugin does is reservation and release of IP addresses
    from some network.
    """

    def __init__(self, config_group_name=None, db_driver=None, label='user'):
        super(StandaloneNetworkPlugin, self).__init__(db_driver=db_driver)
        self.config_group_name = config_group_name or 'DEFAULT'
        CONF.register_opts(
            standalone_network_plugin_opts,
            group=self.config_group_name)
        self.configuration = getattr(CONF, self.config_group_name, CONF)
        self._set_persistent_network_data()
        self._label = label
        LOG.debug(
            "\nStandalone network plugin data for config group "
            "'%(config_group)s': \n"
            "IP version - %(ip_version)s\n"
            "Used network - %(net)s\n"
            "Used gateway - %(gateway)s\n"
            "Used network type - %(network_type)s\n"
            "Used segmentation ID - %(segmentation_id)s\n"
            "Allowed CIDRs - %(cidrs)s\n"
            "Original allowed IP ranges - %(ip_ranges)s\n"
            "Reserved IP addresses - %(reserved)s\n",
            dict(
                config_group=self.config_group_name,
                ip_version=self.ip_version,
                net=six.text_type(self.net),
                gateway=self.gateway,
                network_type=self.network_type,
                segmentation_id=self.segmentation_id,
                cidrs=self.allowed_cidrs,
                ip_ranges=self.allowed_ip_ranges,
                reserved=self.reserved_addresses))

    @property
    def label(self):
        return self._label

    def _set_persistent_network_data(self):
        """Sets persistent data for whole plugin."""
        self.network_type = (
            self.configuration.standalone_network_plugin_network_type)
        self.segmentation_id = (
            self.configuration.standalone_network_plugin_segmentation_id)
        self.gateway = self.configuration.standalone_network_plugin_gateway
        self.mask = self.configuration.standalone_network_plugin_mask
        self.allowed_ip_ranges = (
            self.configuration.standalone_network_plugin_allowed_ip_ranges)
        self.ip_version = int(
            self.configuration.standalone_network_plugin_ip_version)
        self.net = self._get_network()
        self.allowed_cidrs = self._get_list_of_allowed_addresses()
        self.reserved_addresses = (
            six.text_type(self.net.network),
            self.gateway,
            six.text_type(self.net.broadcast))

    def _get_network(self):
        """Returns IPNetwork object calculated from gateway and netmask."""
        if not isinstance(self.gateway, six.string_types):
            raise exception.NetworkBadConfigurationException(
                _("Configuration option 'standalone_network_plugin_gateway' "
                  "is required and has improper value '%s'.") % self.gateway)
        if not isinstance(self.mask, six.string_types):
            raise exception.NetworkBadConfigurationException(
                _("Configuration option 'standalone_network_plugin_mask' is "
                  "required and has improper value '%s'.") % self.mask)
        try:
            return netaddr.IPNetwork(self.gateway + '/' + self.mask)
        except netaddr.AddrFormatError as e:
            raise exception.NetworkBadConfigurationException(
                reason=e)

    def _get_list_of_allowed_addresses(self):
        """Returns list of CIDRs that can be used for getting IP addresses.

        Reads information provided via configuration, such as gateway,
        netmask, segmentation ID and allowed IP ranges, then performs
        validation of provided data.

        :returns: list of CIDRs as text types.
        :raises: exception.NetworkBadConfigurationException
        """
        cidrs = []
        if self.allowed_ip_ranges:
            for ip_range in self.allowed_ip_ranges:
                ip_range_start = ip_range_end = None
                if utils.is_valid_ip_address(ip_range, self.ip_version):
                    ip_range_start = ip_range_end = ip_range
                elif '-' in ip_range:
                    ip_range_list = ip_range.split('-')
                    if len(ip_range_list) == 2:
                        ip_range_start = ip_range_list[0]
                        ip_range_end = ip_range_list[1]
                        for ip in ip_range_list:
                            utils.is_valid_ip_address(ip, self.ip_version)
                    else:
                        msg = _("Wrong value for IP range "
                                "'%s' was provided.") % ip_range
                        raise exception.NetworkBadConfigurationException(
                            reason=msg)
                else:
                    msg = _("Config option "
                            "'standalone_network_plugin_allowed_ip_ranges' "
                            "has incorrect value "
                            "'%s'") % self.allowed_ip_ranges
                    raise exception.NetworkBadConfigurationException(
                        reason=msg)

                range_instance = netaddr.IPRange(ip_range_start, ip_range_end)

                if range_instance not in self.net:
                    data = dict(
                        range=six.text_type(range_instance),
                        net=six.text_type(self.net),
                        gateway=self.gateway,
                        netmask=self.net.netmask)
                    msg = _("One of provided allowed IP ranges ('%(range)s') "
                            "does not fit network '%(net)s' combined from "
                            "gateway '%(gateway)s' and netmask "
                            "'%(netmask)s'.") % data
                    raise exception.NetworkBadConfigurationException(
                        reason=msg)

                cidrs.extend(
                    six.text_type(cidr) for cidr in range_instance.cidrs())
        else:
            if self.net.version != self.ip_version:
                msg = _("Configured invalid IP version '%(conf_v)s', network "
                        "has version ""'%(net_v)s'") % dict(
                            conf_v=self.ip_version, net_v=self.net.version)
                raise exception.NetworkBadConfigurationException(reason=msg)
            cidrs.append(six.text_type(self.net))

        return cidrs

    def _get_available_ips(self, context, amount):
        """Returns IP addresses from allowed IP range if there are unused IPs.

        :returns: IP addresses as list of text types
        :raises: exception.NetworkBadConfigurationException
        """
        ips = []
        if amount < 1:
            return ips
        iterator = netaddr.iter_unique_ips(*self.allowed_cidrs)
        for ip in iterator:
            ip = six.text_type(ip)
            if (ip in self.reserved_addresses or
                    self.db.network_allocations_get_by_ip_address(context,
                                                                  ip)):
                continue
            else:
                ips.append(ip)
            if len(ips) == amount:
                return ips
        msg = _("No available IP addresses left in CIDRs %(cidrs)s. "
                "Requested amount of IPs to be provided '%(amount)s', "
                "available only '%(available)s'.") % {
                    'cidrs': self.allowed_cidrs,
                    'amount': amount,
                    'available': len(ips)}
        raise exception.NetworkBadConfigurationException(reason=msg)

    def _save_network_info(self, context, share_network):
        """Update share-network with plugin specific data."""
        data = {
            'network_type': self.network_type,
            'segmentation_id': self.segmentation_id,
            'cidr': six.text_type(self.net.cidr),
            'ip_version': self.ip_version,
        }
        share_network.update(data)
        if self.label != 'admin':
            self.db.share_network_update(context, share_network['id'], data)

    @utils.synchronized(
        "allocate_network_for_standalone_network_plugin", external=True)
    def allocate_network(self, context, share_server, share_network=None,
                         **kwargs):
        """Allocate network resources using one dedicated network.

        This one has interprocess lock to avoid concurrency in creation of
        share servers with same IP addresses using different share-networks.
        """
        allocation_count = kwargs.get('count', 1)
        if self.label != 'admin':
            self._verify_share_network(share_server['id'], share_network)
        else:
            share_network = share_network or {}
        self._save_network_info(context, share_network)
        allocations = []
        ip_addresses = self._get_available_ips(context, allocation_count)
        for ip_address in ip_addresses:
            data = {
                'share_server_id': share_server['id'],
                'ip_address': ip_address,
                'status': constants.STATUS_ACTIVE,
                'label': self.label,
                'network_type': share_network['network_type'],
                'segmentation_id': share_network['segmentation_id'],
                'cidr': share_network['cidr'],
                'ip_version': share_network['ip_version'],
            }
            allocations.append(
                self.db.network_allocation_create(context, data))
        return allocations

    def deallocate_network(self, context, share_server_id):
        """Deallocate network resources for share server."""
        allocations = self.db.network_allocations_get_for_share_server(
            context, share_server_id)
        for allocation in allocations:
            self.db.network_allocation_delete(context, allocation['id'])
