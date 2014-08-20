# Copyright 2013 Openstack Foundation
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

from oslo.config import cfg

from manila.common import constants
from manila.db import base as db_base
from manila import exception
from manila import network as manila_network
from manila.network.neutron import api as neutron_api
from manila.network.neutron import constants as neutron_constants
from manila.openstack.common import log as logging

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class NeutronNetworkPlugin(manila_network.NetworkBaseAPI, db_base.Base):

    def __init__(self):
        super(NeutronNetworkPlugin, self).__init__()
        self.neutron_api = neutron_api.API()

    def allocate_network(self, context, share_server, share_network, **kwargs):
        """Allocate network resources using given network information: create
        neutron ports for a given neutron network and subnet, create manila db
        records for allocated neutron ports.

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

        self._save_neutron_network_data(context, share_network)
        self._save_neutron_subnet_data(context, share_network)

        allocation_count = kwargs.get('count', 1)
        device_owner = kwargs.get('device_owner', 'share')

        ports = []
        for __ in range(0, allocation_count):
            ports.append(self._create_port(context, share_server,
                                           share_network, device_owner))

        return ports

    def deallocate_network(self, context, share_server):
        """Deallocate neutron network resources for the given network info:
        delete previously allocated neutron ports, delete manila db records for
        deleted ports.

        :param context: RequestContext object
        :param share_network: share network data
        :rtype: None
        """
        ports = self.db.network_allocations_get_for_share_server(
            context, share_server['id'])

        for port in ports:
            self._delete_port(context, port)

    def _create_port(self, context, share_server, share_network, device_owner):
        port = self.neutron_api.create_port(
            share_network['project_id'],
            network_id=share_network['neutron_net_id'],
            subnet_id=share_network['neutron_subnet_id'],
            device_owner='manila:' + device_owner)
        port_dict = {
            'id': port['id'],
            'share_server_id': share_server['id'],
            'ip_address': port['fixed_ips'][0]['ip_address'],
            'mac_address': port['mac_address'],
            'status': constants.STATUS_ACTIVE,
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
        extentions = self.neutron_api.list_extensions()
        return neutron_constants.PROVIDER_NW_EXT in extentions

    def _save_neutron_network_data(self, context, share_network):
        net_info = self.neutron_api.get_network(
            share_network['neutron_net_id'])

        provider_nw_dict = {
            'network_type': net_info['provider:network_type'],
            'segmentation_id': net_info['provider:segmentation_id']
        }

        self.db.share_network_update(context,
                                     share_network['id'],
                                     provider_nw_dict)

    def _save_neutron_subnet_data(self, context, share_network):
        subnet_info = self.neutron_api.get_subnet(
            share_network['neutron_subnet_id'])

        subnet_values = {
            'cidr': subnet_info['cidr'],
            'ip_version': subnet_info['ip_version']
        }

        self.db.share_network_update(context,
                                     share_network['id'],
                                     subnet_values)
