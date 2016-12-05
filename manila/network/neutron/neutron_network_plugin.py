# Copyright 2013 OpenStack Foundation
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

import ipaddress
import six
import socket

from oslo_config import cfg
from oslo_log import log

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila import network
from manila.network.neutron import api as neutron_api
from manila.network.neutron import constants as neutron_constants
from manila import utils

LOG = log.getLogger(__name__)

neutron_network_plugin_opts = [
    cfg.StrOpt(
        'neutron_physical_net_name',
        help="The name of the physical network to determine which net segment "
             "is used. This opt is optional and will only be used for "
             "networks configured with multiple segments.",
        deprecated_group='DEFAULT'),
]

neutron_single_network_plugin_opts = [
    cfg.StrOpt(
        'neutron_net_id',
        help="Default Neutron network that will be used for share server "
             "creation. This opt is used only with "
             "class 'NeutronSingleNetworkPlugin'.",
        deprecated_group='DEFAULT'),
    cfg.StrOpt(
        'neutron_subnet_id',
        help="Default Neutron subnet that will be used for share server "
             "creation. Should be assigned to network defined in opt "
             "'neutron_net_id'. This opt is used only with "
             "class 'NeutronSingleNetworkPlugin'.",
        deprecated_group='DEFAULT'),
]

neutron_bind_network_plugin_opts = [
    cfg.StrOpt(
        'neutron_vnic_type',
        help="vNIC type used for binding.",
        choices=['baremetal', 'normal', 'direct',
                 'direct-physical', 'macvtap'],
        default='baremetal'),
    cfg.StrOpt(
        "neutron_host_id",
        help="Host ID to be used when creating neutron port. If not set "
             "host is set to manila-share host by default.",
        default=socket.gethostname()),
]

neutron_binding_profile = [
    cfg.ListOpt(
        "neutron_binding_profiles",
        help="A list of binding profiles to be used during port binding. This "
        "option can be used with the NeutronBindNetworkPlugin. The value for "
        "this option has to be a comma separated list of names that "
        "correspond to each binding profile. Each binding profile needs to be "
        "specified as an individual configuration section using the binding "
        "profile name as the section name."),
]

neutron_binding_profile_opts = [
    cfg.StrOpt(
        'neutron_switch_id',
        help="Switch ID for binding profile."),
    cfg.StrOpt(
        'neutron_port_id',
        help="Port ID on the given switch.",),
    cfg.DictOpt(
        'neutron_switch_info',
        help="Switch label. For example: 'switch_ip: 10.4.30.5'. Multiple "
             "key-value pairs separated by commas are accepted.",),
]

CONF = cfg.CONF


class NeutronNetworkPlugin(network.NetworkBaseAPI):

    def __init__(self, *args, **kwargs):
        db_driver = kwargs.pop('db_driver', None)
        config_group_name = kwargs.get('config_group_name', 'DEFAULT')
        super(NeutronNetworkPlugin,
              self).__init__(config_group_name=config_group_name,
                             db_driver=db_driver)
        self._neutron_api = None
        self._neutron_api_args = args
        self._neutron_api_kwargs = kwargs
        self._label = kwargs.pop('label', 'user')
        CONF.register_opts(
            neutron_network_plugin_opts,
            group=self.neutron_api.config_group_name)

    @property
    def label(self):
        return self._label

    @property
    @utils.synchronized("instantiate_neutron_api")
    def neutron_api(self):
        if not self._neutron_api:
            self._neutron_api = neutron_api.API(*self._neutron_api_args,
                                                **self._neutron_api_kwargs)
        return self._neutron_api

    def _store_neutron_net_info(self, context, share_network):
        self._save_neutron_network_data(context, share_network)
        self._save_neutron_subnet_data(context, share_network)

    def allocate_network(self, context, share_server, share_network=None,
                         **kwargs):
        """Allocate network resources using given network information.

        Create neutron ports for a given neutron network and subnet,
        create manila db records for allocated neutron ports.

        :param context: RequestContext object
        :param share_network: share network data
        :param kwargs: allocations parameters given by the back-end
                       driver. Supported params:
                       'count' - how many allocations should be created
                       'device_owner' - set owner for network allocations
        :rtype: list of :class: 'dict'
        """
        if not self._has_provider_network_extension():
            msg = "%s extension required" % neutron_constants.PROVIDER_NW_EXT
            raise exception.NetworkBadConfigurationException(reason=msg)

        self._verify_share_network(share_server['id'], share_network)
        self._store_neutron_net_info(context, share_network)

        allocation_count = kwargs.get('count', 1)
        device_owner = kwargs.get('device_owner', 'share')

        ports = []
        for __ in range(0, allocation_count):
            ports.append(self._create_port(context, share_server,
                                           share_network, device_owner))

        return ports

    def _get_matched_ip_address(self, fixed_ips, ip_version):
        """Get first ip address which matches the specified ip_version."""

        for ip in fixed_ips:
            try:
                address = ipaddress.ip_address(six.text_type(ip['ip_address']))
                if address.version == ip_version:
                    return ip['ip_address']
            except ValueError:
                LOG.error("%(address)s isn't a valid ip "
                          "address, omitted."), {'address':
                                                 ip['ip_address']}
        msg = _("Can not find any IP address with configured IP "
                "version %(version)s in share-network.") % {'version':
                                                            ip_version}
        raise exception.NetworkBadConfigurationException(reason=msg)

    def deallocate_network(self, context, share_server_id):
        """Deallocate neutron network resources for the given share server.

        Delete previously allocated neutron ports, delete manila db
        records for deleted ports.

        :param context: RequestContext object
        :param share_server_id: id of share server
        :rtype: None
        """
        ports = self.db.network_allocations_get_for_share_server(
            context, share_server_id)

        for port in ports:
            self._delete_port(context, port)

    def _get_port_create_args(self, share_server, share_network,
                              device_owner):
        return {
            "network_id": share_network['neutron_net_id'],
            "subnet_id": share_network['neutron_subnet_id'],
            "device_owner": 'manila:' + device_owner,
            "device_id": share_server.get('id'),
        }

    def _create_port(self, context, share_server, share_network, device_owner):
        create_args = self._get_port_create_args(share_server, share_network,
                                                 device_owner)

        port = self.neutron_api.create_port(
            share_network['project_id'], **create_args)

        ip_address = self._get_matched_ip_address(port['fixed_ips'],
                                                  share_network['ip_version'])
        port_dict = {
            'id': port['id'],
            'share_server_id': share_server['id'],
            'ip_address': ip_address,
            'gateway': share_network['gateway'],
            'mac_address': port['mac_address'],
            'status': constants.STATUS_ACTIVE,
            'label': self.label,
            'network_type': share_network.get('network_type'),
            'segmentation_id': share_network.get('segmentation_id'),
            'ip_version': share_network['ip_version'],
            'cidr': share_network['cidr'],
            'mtu': share_network['mtu'],
        }
        return self.db.network_allocation_create(context, port_dict)

    def _delete_port(self, context, port):
        try:
            self.neutron_api.delete_port(port['id'])
        except exception.NetworkException:
            self.db.network_allocation_update(
                context, port['id'], {'status': constants.STATUS_ERROR})
            raise
        else:
            self.db.network_allocation_delete(context, port['id'])

    def _has_provider_network_extension(self):
        extensions = self.neutron_api.list_extensions()
        return neutron_constants.PROVIDER_NW_EXT in extensions

    def _is_neutron_multi_segment(self, share_network, net_info=None):
        if net_info is None:
            net_info = self.neutron_api.get_network(
                share_network['neutron_net_id'])
        return 'segments' in net_info

    def _save_neutron_network_data(self, context, share_network):
        net_info = self.neutron_api.get_network(
            share_network['neutron_net_id'])
        segmentation_id = None
        network_type = None

        if self._is_neutron_multi_segment(share_network, net_info):
            # we have a multi segment network and need to identify the
            # lowest segment used for binding
            phy_nets = []
            phy = self.neutron_api.configuration.neutron_physical_net_name
            if not phy:
                msg = "Cannot identify segment used for binding. Please add "
                "neutron_physical_net_name in configuration."
                raise exception.NetworkBadConfigurationException(reason=msg)
            for segment in net_info['segments']:
                phy_nets.append(segment['provider:physical_network'])
                if segment['provider:physical_network'] == phy:
                    segmentation_id = segment['provider:segmentation_id']
                    network_type = segment['provider:network_type']
            if not (segmentation_id and network_type):
                msg = ("No matching neutron_physical_net_name found for %s "
                       "(found: %s)." % (phy, phy_nets))
                raise exception.NetworkBadConfigurationException(reason=msg)
        else:
            network_type = net_info['provider:network_type']
            segmentation_id = net_info['provider:segmentation_id']

        provider_nw_dict = {
            'network_type': network_type,
            'segmentation_id': segmentation_id,
            'mtu':  net_info['mtu'],
        }
        share_network.update(provider_nw_dict)

        if self.label != 'admin':
            self.db.share_network_update(
                context, share_network['id'], provider_nw_dict)

    def _save_neutron_subnet_data(self, context, share_network):
        subnet_info = self.neutron_api.get_subnet(
            share_network['neutron_subnet_id'])

        subnet_values = {
            'cidr': subnet_info['cidr'],
            'gateway': subnet_info['gateway_ip'],
            'ip_version': subnet_info['ip_version']
        }
        share_network.update(subnet_values)

        if self.label != 'admin':
            self.db.share_network_update(
                context, share_network['id'], subnet_values)


class NeutronSingleNetworkPlugin(NeutronNetworkPlugin):

    def __init__(self, *args, **kwargs):
        super(NeutronSingleNetworkPlugin, self).__init__(*args, **kwargs)
        CONF.register_opts(
            neutron_single_network_plugin_opts,
            group=self.neutron_api.config_group_name)
        self.net = self.neutron_api.configuration.neutron_net_id
        self.subnet = self.neutron_api.configuration.neutron_subnet_id
        self._verify_net_and_subnet()

    def allocate_network(self, context, share_server, share_network=None,
                         **kwargs):
        if self.label != 'admin':
            share_network = self._update_share_network_net_data(
                context, share_network)
        else:
            share_network = {
                'project_id': self.neutron_api.admin_project_id,
                'neutron_net_id': self.net,
                'neutron_subnet_id': self.subnet,
            }
        return super(NeutronSingleNetworkPlugin, self).allocate_network(
            context, share_server, share_network, **kwargs)

    def _verify_net_and_subnet(self):
        data = dict(net=self.net, subnet=self.subnet)
        if self.net and self.subnet:
            net = self.neutron_api.get_network(self.net)
            if not (net.get('subnets') and data['subnet'] in net['subnets']):
                raise exception.NetworkBadConfigurationException(
                    "Subnet '%(subnet)s' does not belong to "
                    "network '%(net)s'." % data)
        else:
            raise exception.NetworkBadConfigurationException(
                "Neutron net and subnet are expected to be both set. "
                "Got: net=%(net)s and subnet=%(subnet)s." % data)

    def _update_share_network_net_data(self, context, share_network):
        upd = dict()

        if not share_network.get('neutron_net_id') == self.net:
            if share_network.get('neutron_net_id') is not None:
                raise exception.NetworkBadConfigurationException(
                    "Using neutron net id different from None or value "
                    "specified in the config is forbidden for "
                    "NeutronSingleNetworkPlugin. Allowed values: (%(net)s, "
                    "None), received value: %(err)s" % {
                        "net": self.net,
                        "err": share_network.get('neutron_net_id')})
            upd['neutron_net_id'] = self.net
        if not share_network.get('neutron_subnet_id') == self.subnet:
            if share_network.get('neutron_subnet_id') is not None:
                raise exception.NetworkBadConfigurationException(
                    "Using neutron subnet id different from None or value "
                    "specified in the config is forbidden for "
                    "NeutronSingleNetworkPlugin. Allowed values: (%(snet)s, "
                    "None), received value: %(err)s" % {
                        "snet": self.subnet,
                        "err": share_network.get('neutron_subnet_id')})
            upd['neutron_subnet_id'] = self.subnet
        if upd:
            share_network = self.db.share_network_update(
                context, share_network['id'], upd)
        return share_network


class NeutronBindNetworkPlugin(NeutronNetworkPlugin):
    def __init__(self, *args, **kwargs):
        super(NeutronBindNetworkPlugin, self).__init__(*args, **kwargs)

        self.binding_profiles = []
        CONF.register_opts(
            neutron_binding_profile,
            group=self.neutron_api.config_group_name)
        conf = CONF[self.neutron_api.config_group_name]
        if conf.neutron_binding_profiles:
            for profile in conf.neutron_binding_profiles:
                CONF.register_opts(neutron_binding_profile_opts, group=profile)
                self.binding_profiles.append(profile)

        CONF.register_opts(
            neutron_bind_network_plugin_opts,
            group=self.neutron_api.config_group_name)
        self.config = self.neutron_api.configuration

    def update_network_allocation(self, context, share_server):
        if self.config.neutron_vnic_type == 'normal':
            ports = self.db.network_allocations_get_for_share_server(
                context,
                share_server['id'])
            self._wait_for_ports_bind(ports, share_server)
            return ports

    @utils.retry(exception.NetworkBindException, retries=20)
    def _wait_for_ports_bind(self, ports, share_server):
        inactive_ports = []
        for port in ports:
            port = self._neutron_api.show_port(port['id'])
            if (port['status'] == neutron_constants.PORT_STATUS_ERROR or
                    ('binding:vif_type' in port and
                     port['binding:vif_type'] ==
                     neutron_constants.VIF_TYPE_BINDING_FAILED)):
                msg = _("Port binding %s failed.") % port['id']
                raise exception.NetworkException(msg)
            elif port['status'] != neutron_constants.PORT_STATUS_ACTIVE:
                LOG.debug("The port %(id)s is in state %(state)s. "
                          "Wait for active state.", {
                              "id": port['id'],
                              "state": port['status']})
                inactive_ports.append(port['id'])
        if len(inactive_ports) == 0:
            return
        msg = _("Ports are not fully bound for share server "
                "'%(s_id)s' (inactive ports: %(ports)s)") % {
            "s_id": share_server['id'],
            "ports": inactive_ports}
        raise exception.NetworkBindException(msg)

    def _get_port_create_args(self, share_server, share_network,
                              device_owner):
        arguments = super(
            NeutronBindNetworkPlugin, self)._get_port_create_args(
                share_network, share_network, device_owner)
        arguments['host_id'] = self.config.neutron_host_id
        arguments['binding:vnic_type'] = self.config.neutron_vnic_type
        if self.binding_profiles:
            local_links = []
            for profile in self.binding_profiles:
                local_links.append({
                    'switch_id': CONF[profile]['neutron_switch_id'],
                    'port_id': CONF[profile]['neutron_port_id'],
                    'switch_info': CONF[profile]['neutron_switch_info'],
                })

            arguments['binding:profile'] = {
                "local_link_information": local_links}
        return arguments

    def _store_neutron_net_info(self, context, share_network):
        """Store the Neutron network info.

        In case of dynamic multi segments the segment is determined while
        binding the port. Therefore this method will return for multi segments
        network without storing network information.

        Instead, multi segments network will wait until ports are bound and
        then store network information (see allocate_network()).
        """
        if self._is_neutron_multi_segment(share_network):
            # In case of dynamic multi segment the segment is determined while
            # binding the port
            return
        super(NeutronBindNetworkPlugin, self)._store_neutron_net_info(
            context, share_network)

    def allocate_network(self, context, share_server, share_network=None,
                         **kwargs):
        ports = super(NeutronBindNetworkPlugin, self).allocate_network(
            context, share_server, share_network, **kwargs)
        # If vnic type is 'normal' we expect a neutron agent to bind the
        # ports. This action requires a vnic to be spawned by the driver.
        # Therefore we do not wait for the port binding here, but
        # return the unbound ports and expect the share manager to call
        # update_network_allocation after the share server was created, in
        # order to update the ports with the correct binding.
        if self.config.neutron_vnic_type != 'normal':
            self._wait_for_ports_bind(ports, share_server)
            if self._is_neutron_multi_segment(share_network):
                # update segment information after port bind
                super(NeutronBindNetworkPlugin, self)._store_neutron_net_info(
                    context, share_network)
                for num, port in enumerate(ports):
                    port_info = {
                        'network_type': share_network['network_type'],
                        'segmentation_id': share_network['segmentation_id'],
                        'cidr': share_network['cidr'],
                        'ip_version': share_network['ip_version'],
                    }
                    ports[num] = self.db.network_allocation_update(
                        context, port['id'], port_info)
        return ports


class NeutronBindSingleNetworkPlugin(NeutronSingleNetworkPlugin,
                                     NeutronBindNetworkPlugin):
    pass
