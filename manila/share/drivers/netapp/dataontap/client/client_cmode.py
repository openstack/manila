# Copyright (c) 2014 Alex Meade.  All rights reserved.
# Copyright (c) 2015 Clinton Knight.  All rights reserved.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
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


import copy
import hashlib
import time

from oslo_log import log
from oslo_utils import strutils
from oslo_utils import units
import six

from manila import exception
from manila.i18n import _, _LE, _LW
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_base
from manila.share.drivers.netapp import utils as na_utils


LOG = log.getLogger(__name__)
DELETED_PREFIX = 'deleted_manila_'
DEFAULT_IPSPACE = 'Default'
DEFAULT_BROADCAST_DOMAIN = 'OpenStack'


class NetAppCmodeClient(client_base.NetAppBaseClient):

    def __init__(self, **kwargs):
        super(NetAppCmodeClient, self).__init__(**kwargs)
        self.vserver = kwargs.get('vserver')
        self.connection.set_vserver(self.vserver)

        # Default values to run first api.
        self.connection.set_api_version(1, 15)
        (major, minor) = self.get_ontapi_version(cached=False)
        self.connection.set_api_version(major, minor)

        self._init_features()

    def _init_features(self):
        """Initialize cDOT feature support map."""
        super(NetAppCmodeClient, self)._init_features()

        ontapi_version = self.get_ontapi_version(cached=True)
        ontapi_1_30 = ontapi_version >= (1, 30)

        self.features.add_feature('BROADCAST_DOMAINS', supported=ontapi_1_30)
        self.features.add_feature('IPSPACES', supported=ontapi_1_30)
        self.features.add_feature('SUBNETS', supported=ontapi_1_30)

    def _invoke_vserver_api(self, na_element, vserver):
        server = copy.copy(self.connection)
        server.set_vserver(vserver)
        result = server.invoke_successfully(na_element, True)
        return result

    def _has_records(self, api_result_element):
        if (not api_result_element.get_child_content('num-records') or
                api_result_element.get_child_content('num-records') == '0'):
            return False
        else:
            return True

    def set_vserver(self, vserver):
        self.vserver = vserver
        self.connection.set_vserver(vserver)

    @na_utils.trace
    def create_vserver(self, vserver_name, root_volume_aggregate_name,
                       root_volume_name, aggregate_names, ipspace_name):
        """Creates new vserver and assigns aggregates."""
        create_args = {
            'vserver-name': vserver_name,
            'root-volume-security-style': 'unix',
            'root-volume-aggregate': root_volume_aggregate_name,
            'root-volume': root_volume_name,
            'name-server-switch': {
                'nsswitch': 'file',
            },
        }

        if ipspace_name:
            if not self.features.IPSPACES:
                msg = 'IPSpaces are not supported on this backend.'
                raise exception.NetAppException(msg)
            else:
                create_args['ipspace'] = ipspace_name

        self.send_request('vserver-create', create_args)

        aggr_list = [{'aggr-name': aggr_name} for aggr_name in aggregate_names]
        modify_args = {
            'aggr-list': aggr_list,
            'vserver-name': vserver_name,
        }
        self.send_request('vserver-modify', modify_args)

    @na_utils.trace
    def vserver_exists(self, vserver_name):
        """Checks if Vserver exists."""
        LOG.debug('Checking if Vserver %s exists', vserver_name)

        api_args = {
            'query': {
                'vserver-info': {
                    'vserver-name': vserver_name,
                },
            },
            'desired-attributes': {
                'vserver-info': {
                    'vserver-name': None,
                },
            },
        }
        result = self.send_request('vserver-get-iter', api_args)
        return self._has_records(result)

    @na_utils.trace
    def get_vserver_root_volume_name(self, vserver_name):
        """Get the root volume name of the vserver."""
        api_args = {
            'query': {
                'vserver-info': {
                    'vserver-name': vserver_name,
                },
            },
            'desired-attributes': {
                'vserver-info': {
                    'root-volume': None,
                },
            },
        }
        vserver_info = self.send_request('vserver-get-iter', api_args)

        try:
            root_volume_name = vserver_info.get_child_by_name(
                'attributes-list').get_child_by_name(
                    'vserver-info').get_child_content('root-volume')
        except AttributeError:
            msg = _('Could not determine root volume name '
                    'for Vserver %s.') % vserver_name
            raise exception.NetAppException(msg)
        return root_volume_name

    @na_utils.trace
    def get_vserver_ipspace(self, vserver_name):
        """Get the IPspace of the vserver, or None if not supported."""
        if not self.features.IPSPACES:
            return None

        api_args = {
            'query': {
                'vserver-info': {
                    'vserver-name': vserver_name,
                },
            },
            'desired-attributes': {
                'vserver-info': {
                    'ipspace': None,
                },
            },
        }
        vserver_info = self.send_request('vserver-get-iter', api_args)

        try:
            ipspace = vserver_info.get_child_by_name(
                'attributes-list').get_child_by_name(
                    'vserver-info').get_child_content('ipspace')
        except AttributeError:
            msg = _('Could not determine IPspace for Vserver %s.')
            raise exception.NetAppException(msg % vserver_name)
        return ipspace

    @na_utils.trace
    def ipspace_has_data_vservers(self, ipspace_name):
        """Check whether an IPspace has any data Vservers assigned to it."""
        if not self.features.IPSPACES:
            return False

        api_args = {
            'query': {
                'vserver-info': {
                    'ipspace': ipspace_name,
                    'vserver-type': 'data'
                },
            },
            'desired-attributes': {
                'vserver-info': {
                    'vserver-name': None,
                },
            },
        }
        result = self.send_request('vserver-get-iter', api_args)
        return self._has_records(result)

    @na_utils.trace
    def list_vservers(self, vserver_type='data'):
        """Get the names of vservers present, optionally filtered by type."""
        query = {
            'vserver-info': {
                'vserver-type': vserver_type,
            }
        } if vserver_type else None

        api_args = {
            'desired-attributes': {
                'vserver-info': {
                    'vserver-name': None,
                },
            },
        }
        if query:
            api_args['query'] = query

        result = self.send_request('vserver-get-iter', api_args)
        vserver_info_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        return [vserver_info.get_child_content('vserver-name')
                for vserver_info in vserver_info_list.get_children()]

    @na_utils.trace
    def get_vserver_volume_count(self, max_records=20):
        """Get the number of volumes present on a cluster or vserver.

        Call this on a vserver client to see how many volumes exist
        on that vserver.
        """
        api_args = {
            'max-records': max_records,
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': None,
                    },
                },
            },
        }
        volumes_data = self.send_request('volume-get-iter', api_args)
        return int(volumes_data.get_child_content('num-records'))

    @na_utils.trace
    def delete_vserver(self, vserver_name, vserver_client,
                       security_services=None):
        """Delete Vserver.

        Checks if Vserver exists and does not have active shares.
        Offlines and destroys root volumes.  Deletes Vserver.
        """
        if not self.vserver_exists(vserver_name):
            LOG.error(_LE("Vserver %s does not exist."), vserver_name)
            return

        root_volume_name = self.get_vserver_root_volume_name(vserver_name)
        volumes_count = vserver_client.get_vserver_volume_count(max_records=2)

        if volumes_count == 1:
            try:
                vserver_client.offline_volume(root_volume_name)
            except netapp_api.NaApiError as e:
                if e.code == netapp_api.EVOLUMEOFFLINE:
                    LOG.error(_LE("Volume %s is already offline."),
                              root_volume_name)
                else:
                    raise e
            vserver_client.delete_volume(root_volume_name)

        elif volumes_count > 1:
            msg = _("Cannot delete Vserver. Vserver %s has shares.")
            raise exception.NetAppException(msg % vserver_name)

        if security_services:
            self._terminate_vserver_services(vserver_name, vserver_client,
                                             security_services)

        self.send_request('vserver-destroy', {'vserver-name': vserver_name})

    @na_utils.trace
    def _terminate_vserver_services(self, vserver_name, vserver_client,
                                    security_services):
        for service in security_services:
            if service['type'] == 'active_directory':
                api_args = {
                    'admin-password': service['password'],
                    'admin-username': service['user'],
                }
                try:
                    vserver_client.send_request('cifs-server-delete', api_args)
                except netapp_api.NaApiError as e:
                    if e.code == netapp_api.EOBJECTNOTFOUND:
                        LOG.error(_LE('CIFS server does not exist for '
                                      'Vserver %s.'), vserver_name)
                    else:
                        vserver_client.send_request('cifs-server-delete')

    @na_utils.trace
    def list_cluster_nodes(self):
        """Get all available cluster nodes."""
        api_args = {
            'desired-attributes': {
                'node-details-info': {
                    'node': None,
                },
            },
        }
        result = self.send_request('system-node-get-iter', api_args)
        nodes_info_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        return [node_info.get_child_content('node') for node_info
                in nodes_info_list.get_children()]

    @na_utils.trace
    def list_node_data_ports(self, node):
        ports = self.get_node_data_ports(node)
        return [port.get('port') for port in ports]

    @na_utils.trace
    def get_node_data_ports(self, node):
        """Get applicable data ports on the node."""
        api_args = {
            'query': {
                'net-port-info': {
                    'node': node,
                    'link-status': 'up',
                    'port-type': 'physical|if_group',
                    'role': 'data',
                },
            },
            'desired-attributes': {
                'net-port-info': {
                    'port': None,
                    'node': None,
                    'operational-speed': None,
                    'ifgrp-port': None,
                },
            },
        }
        result = self.send_request('net-port-get-iter', api_args)
        net_port_info_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')

        ports = []
        for port_info in net_port_info_list.get_children():

            # Skip physical ports that are part of interface groups.
            if port_info.get_child_content('ifgrp-port'):
                continue

            port = {
                'node': port_info.get_child_content('node'),
                'port': port_info.get_child_content('port'),
                'speed': port_info.get_child_content('operational-speed'),
            }
            ports.append(port)

        return self._sort_data_ports_by_speed(ports)

    @na_utils.trace
    def _sort_data_ports_by_speed(self, ports):

        def sort_key(port):
            value = port.get('speed')
            if not (value and isinstance(value, six.string_types)):
                return 0
            elif value.isdigit():
                return int(value)
            elif value == 'auto':
                return 3
            elif value == 'undef':
                return 2
            else:
                return 1

        return sorted(ports, key=sort_key, reverse=True)

    @na_utils.trace
    def list_aggregates(self):
        """Get names of all aggregates."""
        try:
            api_args = {
                'desired-attributes': {
                    'aggr-attributes': {
                        'aggregate-name': None,
                    },
                },
            }
            result = self.send_request('aggr-get-iter', api_args)
            aggr_list = result.get_child_by_name(
                'attributes-list').get_children()
        except AttributeError:
            msg = _("Could not list aggregates.")
            raise exception.NetAppException(msg)
        return [aggr.get_child_content('aggregate-name') for aggr
                in aggr_list]

    @na_utils.trace
    def list_vserver_aggregates(self):
        """Returns a list of aggregates available to a vserver.

        This must be called against a Vserver LIF.
        """
        return list(self.get_vserver_aggregate_capacities().keys())

    @na_utils.trace
    def create_network_interface(self, ip, netmask, vlan, node, port,
                                 vserver_name, allocation_id,
                                 lif_name_template, ipspace_name):
        """Creates LIF on VLAN port."""

        home_port_name = port
        if vlan:
            self._create_vlan(node, port, vlan)
            home_port_name = '%(port)s-%(tag)s' % {'port': port, 'tag': vlan}

        if self.features.BROADCAST_DOMAINS:
            self._ensure_broadcast_domain_for_port(node, home_port_name,
                                                   ipspace=ipspace_name)

        interface_name = (lif_name_template %
                          {'node': node, 'net_allocation_id': allocation_id})

        LOG.debug('Creating LIF %(lif)s for Vserver %(vserver)s ',
                  {'lif': interface_name, 'vserver': vserver_name})

        api_args = {
            'address': ip,
            'administrative-status': 'up',
            'data-protocols': [
                {'data-protocol': 'nfs'},
                {'data-protocol': 'cifs'},
            ],
            'home-node': node,
            'home-port': home_port_name,
            'netmask': netmask,
            'interface-name': interface_name,
            'role': 'data',
            'vserver': vserver_name,
        }
        self.send_request('net-interface-create', api_args)

    @na_utils.trace
    def _create_vlan(self, node, port, vlan):
        try:
            api_args = {
                'vlan-info': {
                    'parent-interface': port,
                    'node': node,
                    'vlanid': vlan,
                },
            }
            self.send_request('net-vlan-create', api_args)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EDUPLICATEENTRY:
                LOG.debug('VLAN %(vlan)s already exists on port %(port)s',
                          {'vlan': vlan, 'port': port})
            else:
                msg = _('Failed to create VLAN %(vlan)s on '
                        'port %(port)s. %(err_msg)s')
                msg_args = {'vlan': vlan, 'port': port, 'err_msg': e.message}
                raise exception.NetAppException(msg % msg_args)

    @na_utils.trace
    def _ensure_broadcast_domain_for_port(self, node, port,
                                          domain=DEFAULT_BROADCAST_DOMAIN,
                                          ipspace=DEFAULT_IPSPACE):
        """Ensure a port is in a broadcast domain.  Create one if necessary.

        If the IPspace:domain pair match for the given port, which commonly
        happens in multi-node clusters, then there isn't anything to do.
        Otherwise, we can assume the IPspace is correct and extant by this
        point, so the remaining task is to remove the port from any domain it
        is already in, create the desired domain if it doesn't exist, and add
        the port to the desired domain.
        """

        port_info = self._get_broadcast_domain_for_port(node, port)

        # Port already in desired ipspace and broadcast domain.
        if (port_info['ipspace'] == ipspace
                and port_info['broadcast-domain'] == domain):
            return

        # If in another broadcast domain, remove port from it.
        if port_info['broadcast-domain']:
            self._remove_port_from_broadcast_domain(
                node, port, port_info['broadcast-domain'],
                port_info['ipspace'])

        # If desired broadcast domain doesn't exist, create it.
        if not self._broadcast_domain_exists(domain, ipspace):
            self._create_broadcast_domain(domain, ipspace)

        # Move the port into the broadcast domain where it is needed.
        self._add_port_to_broadcast_domain(node, port, domain, ipspace)

    @na_utils.trace
    def _get_broadcast_domain_for_port(self, node, port):
        """Get broadcast domain for a specific port."""
        api_args = {
            'query': {
                'net-port-info': {
                    'node': node,
                    'port': port,
                },
            },
            'desired-attributes': {
                'net-port-info': {
                    'broadcast-domain': None,
                    'ipspace': None,
                },
            },
        }
        result = self.send_request('net-port-get-iter', api_args)

        net_port_info_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        port_info = net_port_info_list.get_children()
        if not port_info:
            msg = _('Could not find port %(port)s on node %(node)s.')
            msg_args = {'port': port, 'node': node}
            raise exception.NetAppException(msg % msg_args)

        port = {
            'broadcast-domain':
            port_info[0].get_child_content('broadcast-domain'),
            'ipspace': port_info[0].get_child_content('ipspace')
        }
        return port

    @na_utils.trace
    def _broadcast_domain_exists(self, domain, ipspace):
        """Check if a broadcast domain exists."""
        api_args = {
            'query': {
                'net-port-broadcast-domain-info': {
                    'ipspace': ipspace,
                    'broadcast-domain': domain,
                },
            },
            'desired-attributes': {
                'net-port-broadcast-domain-info': None,
            },
        }
        result = self.send_request('net-port-broadcast-domain-get-iter',
                                   api_args)
        return self._has_records(result)

    @na_utils.trace
    def _create_broadcast_domain(self, domain, ipspace, mtu=1500):
        """Create a broadcast domain."""
        api_args = {
            'ipspace': ipspace,
            'broadcast-domain': domain,
            'mtu': mtu,
        }
        self.send_request('net-port-broadcast-domain-create', api_args)

    @na_utils.trace
    def _delete_broadcast_domain(self, domain, ipspace):
        """Delete a broadcast domain."""
        api_args = {
            'ipspace': ipspace,
            'broadcast-domain': domain,
        }
        self.send_request('net-port-broadcast-domain-destroy', api_args)

    def _delete_broadcast_domains_for_ipspace(self, ipspace_name):
        """Deletes all broadcast domains in an IPspace."""
        ipspaces = self.get_ipspaces(ipspace_name=ipspace_name)
        if not ipspaces:
            return

        ipspace = ipspaces[0]
        for broadcast_domain_name in ipspace['broadcast-domains']:
            self._delete_broadcast_domain(broadcast_domain_name, ipspace_name)

    @na_utils.trace
    def _add_port_to_broadcast_domain(self, node, port, domain, ipspace):

        qualified_port_name = ':'.join([node, port])
        try:
            api_args = {
                'ipspace': ipspace,
                'broadcast-domain': domain,
                'ports': {
                    'net-qualified-port-name': qualified_port_name,
                }
            }
            self.send_request('net-port-broadcast-domain-add-ports', api_args)
        except netapp_api.NaApiError as e:
            if e.code == (netapp_api.
                          E_VIFMGR_PORT_ALREADY_ASSIGNED_TO_BROADCAST_DOMAIN):
                LOG.debug('Port %(port)s already exists in broadcast domain '
                          '%(domain)s', {'port': port, 'domain': domain})
            else:
                msg = _('Failed to add port %(port)s to broadcast domain '
                        '%(domain)s. %(err_msg)s')
                msg_args = {
                    'port': qualified_port_name,
                    'domain': domain,
                    'err_msg': e.message,
                }
                raise exception.NetAppException(msg % msg_args)

    @na_utils.trace
    def _remove_port_from_broadcast_domain(self, node, port, domain, ipspace):

        qualified_port_name = ':'.join([node, port])
        api_args = {
            'ipspace': ipspace,
            'broadcast-domain': domain,
            'ports': {
                'net-qualified-port-name': qualified_port_name,
            }
        }
        self.send_request('net-port-broadcast-domain-remove-ports', api_args)

    @na_utils.trace
    def network_interface_exists(self, vserver_name, node, port, ip, netmask,
                                 vlan):
        """Checks if LIF exists."""

        home_port_name = (port if not vlan else
                          '%(port)s-%(tag)s' % {'port': port, 'tag': vlan})

        api_args = {
            'query': {
                'net-interface-info': {
                    'address': ip,
                    'home-node': node,
                    'home-port': home_port_name,
                    'netmask': netmask,
                    'vserver': vserver_name,
                },
            },
            'desired-attributes': {
                'net-interface-info': {
                    'interface-name': None,
                },
            },
        }
        result = self.send_request('net-interface-get-iter', api_args)
        return self._has_records(result)

    @na_utils.trace
    def list_network_interfaces(self):
        """Get the names of available LIFs."""
        api_args = {
            'desired-attributes': {
                'net-interface-info': {
                    'interface-name': None,
                },
            },
        }
        result = self.send_request('net-interface-get-iter', api_args)
        lif_info_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        return [lif_info.get_child_content('interface-name') for lif_info
                in lif_info_list.get_children()]

    @na_utils.trace
    def get_network_interfaces(self, protocols=None):
        """Get available LIFs."""
        protocols = na_utils.convert_to_list(protocols)
        protocols = [protocol.lower() for protocol in protocols]

        api_args = {
            'query': {
                'net-interface-info': {
                    'data-protocols': {
                        'data-protocol': '|'.join(protocols),
                    }
                }
            }
        } if protocols else None

        result = self.send_request('net-interface-get-iter', api_args)
        lif_info_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')

        interfaces = []
        for lif_info in lif_info_list.get_children():
            lif = {
                'address': lif_info.get_child_content('address'),
                'home-node': lif_info.get_child_content('home-node'),
                'home-port': lif_info.get_child_content('home-port'),
                'interface-name': lif_info.get_child_content('interface-name'),
                'netmask': lif_info.get_child_content('netmask'),
                'role': lif_info.get_child_content('role'),
                'vserver': lif_info.get_child_content('vserver'),
            }
            interfaces.append(lif)

        return interfaces

    @na_utils.trace
    def delete_network_interface(self, interface_name):
        """Deletes LIF."""
        api_args = {'vserver': None, 'interface-name': interface_name}
        self.send_request('net-interface-delete', api_args)

    @na_utils.trace
    def get_ipspaces(self, ipspace_name=None, max_records=1000):
        """Gets one or more IPSpaces."""

        if not self.features.IPSPACES:
            return []

        api_args = {'max-records': max_records}
        if ipspace_name:
            api_args['query'] = {
                'net-ipspaces-info': {
                    'ipspace': ipspace_name,
                }
            }

        result = self.send_request('net-ipspaces-get-iter', api_args)
        if not self._has_records(result):
            return []

        ipspaces = []

        for net_ipspaces_info in result.get_child_by_name(
                'attributes-list').get_children():

            ipspace = {
                'ports': [],
                'vservers': [],
                'broadcast-domains': [],
            }

            ports = net_ipspaces_info.get_child_by_name(
                'ports') or netapp_api.NaElement('none')
            for port in ports.get_children():
                ipspace['ports'].append(port.get_content())

            vservers = net_ipspaces_info.get_child_by_name(
                'vservers') or netapp_api.NaElement('none')
            for vserver in vservers.get_children():
                ipspace['vservers'].append(vserver.get_content())

            broadcast_domains = net_ipspaces_info.get_child_by_name(
                'broadcast-domains') or netapp_api.NaElement('none')
            for broadcast_domain in broadcast_domains.get_children():
                ipspace['broadcast-domains'].append(
                    broadcast_domain.get_content())

            ipspace['ipspace'] = net_ipspaces_info.get_child_content('ipspace')
            ipspace['id'] = net_ipspaces_info.get_child_content('id')
            ipspace['uuid'] = net_ipspaces_info.get_child_content('uuid')

            ipspaces.append(ipspace)

        return ipspaces

    @na_utils.trace
    def ipspace_exists(self, ipspace_name):
        """Checks if IPspace exists."""

        if not self.features.IPSPACES:
            return False

        api_args = {
            'query': {
                'net-ipspaces-info': {
                    'ipspace': ipspace_name,
                },
            },
            'desired-attributes': {
                'net-ipspaces-info': {
                    'ipspace': None,
                },
            },
        }
        result = self.send_request('net-ipspaces-get-iter', api_args)
        return self._has_records(result)

    @na_utils.trace
    def create_ipspace(self, ipspace_name):
        """Creates an IPspace."""
        api_args = {'ipspace': ipspace_name}
        self.send_request('net-ipspaces-create', api_args)

    @na_utils.trace
    def delete_ipspace(self, ipspace_name):
        """Deletes an IPspace."""

        self._delete_broadcast_domains_for_ipspace(ipspace_name)

        api_args = {'ipspace': ipspace_name}
        self.send_request('net-ipspaces-destroy', api_args)

    @na_utils.trace
    def add_vserver_to_ipspace(self, ipspace_name, vserver_name):
        """Assigns a vserver to an IPspace."""
        api_args = {'ipspace': ipspace_name, 'vserver': vserver_name}
        self.send_request('net-ipspaces-assign-vserver', api_args)

    @na_utils.trace
    def get_node_for_aggregate(self, aggregate_name):
        """Get home node for the specified aggregate.

        This API could return None, most notably if it was sent
        to a Vserver LIF, so the caller must be able to handle that case.
        """

        if not aggregate_name:
            return None

        desired_attributes = {
            'aggr-attributes': {
                'aggregate-name': None,
                'aggr-ownership-attributes': {
                    'home-name': None,
                },
            },
        }

        try:
            aggrs = self._get_aggregates(aggregate_names=[aggregate_name],
                                         desired_attributes=desired_attributes)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EAPINOTFOUND:
                return None
            else:
                raise e

        if len(aggrs) < 1:
            return None

        aggr_ownership_attrs = aggrs[0].get_child_by_name(
            'aggr-ownership-attributes') or netapp_api.NaElement('none')
        return aggr_ownership_attrs.get_child_content('home-name')

    @na_utils.trace
    def get_cluster_aggregate_capacities(self, aggregate_names):
        """Calculates capacity of one or more aggregates.

        Returns dictionary of aggregate capacity metrics.
        'size-used' is the actual space consumed on the aggregate.
        'size-available' is the actual space remaining.
        'size-total' is the defined total aggregate size, such that
        used + available = total.
        """

        if aggregate_names is not None and len(aggregate_names) == 0:
            return {}

        desired_attributes = {
            'aggr-attributes': {
                'aggregate-name': None,
                'aggr-space-attributes': {
                    'size-available': None,
                    'size-total': None,
                    'size-used': None,
                },
            },
        }
        aggrs = self._get_aggregates(aggregate_names=aggregate_names,
                                     desired_attributes=desired_attributes)
        aggr_space_dict = dict()
        for aggr in aggrs:
            aggr_name = aggr.get_child_content('aggregate-name')
            aggr_space_attrs = aggr.get_child_by_name('aggr-space-attributes')

            aggr_space_dict[aggr_name] = {
                'available':
                int(aggr_space_attrs.get_child_content('size-available')),
                'total':
                int(aggr_space_attrs.get_child_content('size-total')),
                'used':
                int(aggr_space_attrs.get_child_content('size-used')),
            }
        return aggr_space_dict

    @na_utils.trace
    def get_vserver_aggregate_capacities(self, aggregate_names=None):
        """Calculates capacity of one or more aggregates for a vserver.

        Returns dictionary of aggregate capacity metrics.  This must
        be called against a Vserver LIF.
        """

        if aggregate_names is not None and len(aggregate_names) == 0:
            return {}

        api_args = {
            'desired-attributes': {
                'vserver-info': {
                    'vserver-name': None,
                    'vserver-aggr-info-list': {
                        'vserver-aggr-info': {
                            'aggr-name': None,
                            'aggr-availsize': None,
                        },
                    },
                },
            },
        }
        result = self.send_request('vserver-get', api_args)
        attributes = result.get_child_by_name('attributes')
        if not attributes:
            raise exception.NetAppException('Failed to read Vserver info')

        vserver_info = attributes.get_child_by_name('vserver-info')
        vserver_name = vserver_info.get_child_content('vserver-name')
        vserver_aggr_info_element = vserver_info.get_child_by_name(
            'vserver-aggr-info-list') or netapp_api.NaElement('none')
        vserver_aggr_info_list = vserver_aggr_info_element.get_children()

        if not vserver_aggr_info_list:
            LOG.warning(_LW('No aggregates assigned to Vserver %s.'),
                        vserver_name)

        # Return dict of key-value pair of aggr_name:aggr_size_available.
        aggr_space_dict = {}

        for aggr_info in vserver_aggr_info_list:
            aggr_name = aggr_info.get_child_content('aggr-name')

            if aggregate_names is None or aggr_name in aggregate_names:
                aggr_size = int(aggr_info.get_child_content('aggr-availsize'))
                aggr_space_dict[aggr_name] = {'available': aggr_size}

        LOG.debug('Found available Vserver aggregates: %s', aggr_space_dict)
        return aggr_space_dict

    @na_utils.trace
    def _get_aggregates(self, aggregate_names=None, desired_attributes=None):

        query = {
            'aggr-attributes': {
                'aggregate-name': '|'.join(aggregate_names),
            }
        } if aggregate_names else None

        api_args = {}
        if query:
            api_args['query'] = query
        if desired_attributes:
            api_args['desired-attributes'] = desired_attributes

        result = self.send_request('aggr-get-iter', api_args)
        if not self._has_records(result):
            return []
        else:
            return result.get_child_by_name('attributes-list').get_children()

    @na_utils.trace
    def setup_security_services(self, security_services, vserver_client,
                                vserver_name):
        api_args = {
            'name-mapping-switch': [
                {'nmswitch': 'ldap'},
                {'nmswitch': 'file'}
            ],
            'name-server-switch': [
                {'nsswitch': 'ldap'},
                {'nsswitch': 'file'}
            ],
            'vserver-name': vserver_name,
        }
        self.send_request('vserver-modify', api_args)

        for security_service in security_services:
            if security_service['type'].lower() == 'ldap':
                vserver_client.configure_ldap(security_service)

            elif security_service['type'].lower() == 'active_directory':
                vserver_client.configure_active_directory(security_service,
                                                          vserver_name)

            elif security_service['type'].lower() == 'kerberos':
                self.create_kerberos_realm(security_service)
                vserver_client.configure_kerberos(security_service,
                                                  vserver_name)

            else:
                msg = _('Unsupported security service type %s for '
                        'Data ONTAP driver')
                raise exception.NetAppException(msg % security_service['type'])

    @na_utils.trace
    def enable_nfs(self):
        """Enables NFS on Vserver."""
        self.send_request('nfs-enable')
        self.send_request('nfs-service-modify', {'is-nfsv40-enabled': 'true'})

        api_args = {
            'client-match': '0.0.0.0/0',
            'policy-name': 'default',
            'ro-rule': {
                'security-flavor': 'any',
            },
            'rw-rule': {
                'security-flavor': 'never',
            },
        }
        self.send_request('export-rule-create', api_args)

    @na_utils.trace
    def configure_ldap(self, security_service):
        """Configures LDAP on Vserver."""
        config_name = hashlib.md5(six.b(security_service['id'])).hexdigest()
        api_args = {
            'ldap-client-config': config_name,
            'servers': {
                'ip-address': security_service['server'],
            },
            'tcp-port': '389',
            'schema': 'RFC-2307',
            'bind-password': security_service['password'],
        }
        self.send_request('ldap-client-create', api_args)

        api_args = {'client-config': config_name, 'client-enabled': 'true'}
        self.send_request('ldap-config-create', api_args)

    @na_utils.trace
    def configure_active_directory(self, security_service, vserver_name):
        """Configures AD on Vserver."""
        self.configure_dns(security_service)

        # 'cifs-server' is CIFS Server NetBIOS Name, max length is 15.
        # Should be unique within each domain (data['domain']).
        cifs_server = (vserver_name[0:7] + '..' + vserver_name[-6:]).upper()
        api_args = {
            'admin-username': security_service['user'],
            'admin-password': security_service['password'],
            'force-account-overwrite': 'true',
            'cifs-server': cifs_server,
            'domain': security_service['domain'],
        }
        try:
            LOG.debug("Trying to setup CIFS server with data: %s", api_args)
            self.send_request('cifs-server-create', api_args)
        except netapp_api.NaApiError as e:
            msg = _("Failed to create CIFS server entry. %s")
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def create_kerberos_realm(self, security_service):
        """Creates Kerberos realm on cluster."""

        api_args = {
            'admin-server-ip': security_service['server'],
            'admin-server-port': '749',
            'clock-skew': '5',
            'comment': '',
            'config-name': security_service['id'],
            'kdc-ip': security_service['server'],
            'kdc-port': '88',
            'kdc-vendor': 'other',
            'password-server-ip': security_service['server'],
            'password-server-port': '464',
            'realm': security_service['domain'].upper(),
        }
        try:
            self.send_request('kerberos-realm-create', api_args)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EDUPLICATEENTRY:
                LOG.debug('Kerberos realm config already exists.')
            else:
                msg = _('Failed to create Kerberos realm. %s')
                raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def configure_kerberos(self, security_service, vserver_name):
        """Configures Kerberos for NFS on Vserver."""

        self.configure_dns(security_service)
        spn = self._get_kerberos_service_principal_name(
            security_service, vserver_name)

        lifs = self.list_network_interfaces()
        if not lifs:
            msg = _("Cannot set up Kerberos. There are no LIFs configured.")
            raise exception.NetAppException(msg)

        for lif_name in lifs:
            api_args = {
                'admin-password': security_service['password'],
                'admin-user-name': security_service['user'],
                'interface-name': lif_name,
                'is-kerberos-enabled': 'true',
                'service-principal-name': spn,
            }
            self.send_request('kerberos-config-modify', api_args)

    @na_utils.trace
    def _get_kerberos_service_principal_name(self, security_service,
                                             vserver_name):
        return 'nfs/' + vserver_name.replace('_', '-') + '.' + \
               security_service['domain'] + '@' + \
               security_service['domain'].upper()

    @na_utils.trace
    def configure_dns(self, security_service):
        api_args = {
            'domains': {
                'string': security_service['domain'],
            },
            'name-servers': {
                'ip-address': security_service['dns_ip'],
            },
            'dns-state': 'enabled',
        }
        try:
            self.send_request('net-dns-create', api_args)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EDUPLICATEENTRY:
                LOG.error(_LE("DNS exists for Vserver."))
            else:
                msg = _("Failed to configure DNS. %s")
                raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def create_volume(self, aggregate_name, volume_name, size_gb,
                      thin_provisioned=False, snapshot_policy=None,
                      language=None, dedup_enabled=False,
                      compression_enabled=False, max_files=None,
                      snapshot_reserve=None):

        """Creates a volume."""
        api_args = {
            'containing-aggr-name': aggregate_name,
            'size': six.text_type(size_gb) + 'g',
            'volume': volume_name,
            'junction-path': '/%s' % volume_name,
        }
        if thin_provisioned:
            api_args['space-reserve'] = 'none'
        if snapshot_policy is not None:
            api_args['snapshot-policy'] = snapshot_policy
        if language is not None:
            api_args['language-code'] = language
        if snapshot_reserve is not None:
            api_args['percentage-snapshot-reserve'] = six.text_type(
                snapshot_reserve)
        self.send_request('volume-create', api_args)

        # cDOT compression requires that deduplication be enabled.
        if dedup_enabled or compression_enabled:
            self.enable_dedup(volume_name)
        if compression_enabled:
            self.enable_compression(volume_name)
        if max_files is not None:
            self.set_volume_max_files(volume_name, max_files)

    @na_utils.trace
    def enable_dedup(self, volume_name):
        """Enable deduplication on volume."""
        api_args = {'path': '/vol/%s' % volume_name}
        self.send_request('sis-enable', api_args)

    @na_utils.trace
    def disable_dedup(self, volume_name):
        """Disable deduplication on volume."""
        api_args = {'path': '/vol/%s' % volume_name}
        self.send_request('sis-disable', api_args)

    @na_utils.trace
    def enable_compression(self, volume_name):
        """Enable compression on volume."""
        api_args = {
            'path': '/vol/%s' % volume_name,
            'enable-compression': 'true'
        }
        self.send_request('sis-set-config', api_args)

    @na_utils.trace
    def disable_compression(self, volume_name):
        """Disable compression on volume."""
        api_args = {
            'path': '/vol/%s' % volume_name,
            'enable-compression': 'false'
        }
        self.send_request('sis-set-config', api_args)

    @na_utils.trace
    def get_volume_efficiency_status(self, volume_name):
        """Get dedupe & compression status for a volume."""
        api_args = {
            'query': {
                'sis-status-info': {
                    'path': '/vol/%s' % volume_name,
                },
            },
            'desired-attributes': {
                'sis-status-info': {
                    'state': None,
                    'is-compression-enabled': None,
                },
            },
        }
        result = self.send_request('sis-get-iter', api_args)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        sis_status_info = attributes_list.get_child_by_name(
            'sis-status-info') or netapp_api.NaElement('none')

        return {
            'dedupe': True if 'enabled' == sis_status_info.get_child_content(
                'state') else False,
            'compression': True if 'true' == sis_status_info.get_child_content(
                'is-compression-enabled') else False,
        }

    @na_utils.trace
    def set_volume_max_files(self, volume_name, max_files):
        """Set flexvol file limit."""
        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': volume_name,
                    },
                },
            },
            'attributes': {
                'volume-attributes': {
                    'volume-inode-attributes': {
                        'files-total': max_files,
                    },
                },
            },
        }
        self.send_request('volume-modify-iter', api_args)

    @na_utils.trace
    def set_volume_size(self, volume_name, size_gb):
        """Set volume size."""
        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': volume_name,
                    },
                },
            },
            'attributes': {
                'volume-attributes': {
                    'volume-space-attributes': {
                        'size': int(size_gb) * units.Gi,
                    },
                },
            },
        }
        result = self.send_request('volume-modify-iter', api_args)
        failures = result.get_child_content('num-failed')
        if failures and int(failures) > 0:
            failure_list = result.get_child_by_name(
                'failure-list') or netapp_api.NaElement('none')
            errors = failure_list.get_children()
            if errors:
                raise netapp_api.NaApiError(
                    errors[0].get_child_content('error-code'),
                    errors[0].get_child_content('error-message'))

    @na_utils.trace
    def set_volume_name(self, volume_name, new_volume_name):
        """Set flexvol name."""
        api_args = {
            'volume': volume_name,
            'new-volume-name': new_volume_name,
        }
        self.send_request('volume-rename', api_args)

    @na_utils.trace
    def manage_volume(self, aggregate_name, volume_name,
                      thin_provisioned=False, snapshot_policy=None,
                      language=None, dedup_enabled=False,
                      compression_enabled=False, max_files=None):
        """Update volume as needed to bring under management as a share."""
        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'containing-aggregate-name': aggregate_name,
                        'name': volume_name,
                    },
                },
            },
            'attributes': {
                'volume-attributes': {
                    'volume-inode-attributes': {},
                    'volume-language-attributes': {},
                    'volume-snapshot-attributes': {},
                    'volume-space-attributes': {
                        'space-guarantee': ('none' if thin_provisioned else
                                            'volume')
                    },
                },
            },
        }
        if language:
            api_args['attributes']['volume-attributes'][
                'volume-language-attributes']['language'] = language
        if max_files:
            api_args['attributes']['volume-attributes'][
                'volume-inode-attributes']['files-total'] = max_files
        if snapshot_policy:
            api_args['attributes']['volume-attributes'][
                'volume-snapshot-attributes'][
                    'snapshot-policy'] = snapshot_policy

        self.send_request('volume-modify-iter', api_args)

        # Efficiency options must be handled separately
        self.update_volume_efficiency_attributes(volume_name,
                                                 dedup_enabled,
                                                 compression_enabled)

    @na_utils.trace
    def update_volume_efficiency_attributes(self, volume_name, dedup_enabled,
                                            compression_enabled):
        """Update dedupe & compression attributes to match desired values."""
        efficiency_status = self.get_volume_efficiency_status(volume_name)

        if efficiency_status['compression'] != compression_enabled:
            if compression_enabled:
                self.enable_compression(volume_name)
            else:
                self.disable_compression(volume_name)

        if efficiency_status['dedupe'] != dedup_enabled:
            if dedup_enabled:
                self.enable_dedup(volume_name)
            else:
                self.disable_dedup(volume_name)

    @na_utils.trace
    def volume_exists(self, volume_name):
        """Checks if volume exists."""
        LOG.debug('Checking if volume %s exists', volume_name)

        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': volume_name,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': None,
                    },
                },
            },
        }
        result = self.send_request('volume-get-iter', api_args)
        return self._has_records(result)

    @na_utils.trace
    def get_aggregate_for_volume(self, volume_name):
        """Get the name of the aggregate containing a volume."""

        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': volume_name,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'containing-aggregate-name': None,
                        'name': None,
                    },
                },
            },
        }
        result = self.send_request('volume-get-iter', api_args)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        volume_attributes = attributes_list.get_child_by_name(
            'volume-attributes') or netapp_api.NaElement('none')
        volume_id_attributes = volume_attributes.get_child_by_name(
            'volume-id-attributes') or netapp_api.NaElement('none')

        aggregate = volume_id_attributes.get_child_content(
            'containing-aggregate-name')

        if not aggregate:
            msg = _('Could not find aggregate for volume %s.')
            raise exception.NetAppException(msg % volume_name)

        return aggregate

    @na_utils.trace
    def volume_has_luns(self, volume_name):
        """Checks if volume has LUNs."""
        LOG.debug('Checking if volume %s has LUNs', volume_name)

        api_args = {
            'query': {
                'lun-info': {
                    'volume': volume_name,
                },
            },
            'desired-attributes': {
                'lun-info': {
                    'path': None,
                },
            },
        }
        result = self.send_request('lun-get-iter', api_args)
        return self._has_records(result)

    @na_utils.trace
    def volume_has_junctioned_volumes(self, volume_name):
        """Checks if volume has volumes mounted beneath its junction path."""
        junction_path = self.get_volume_junction_path(volume_name)
        if not junction_path:
            return False

        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'junction-path': junction_path + '/*',
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': None,
                    },
                },
            },
        }
        result = self.send_request('volume-get-iter', api_args)
        return self._has_records(result)

    @na_utils.trace
    def get_volume_at_junction_path(self, junction_path):
        """Returns the volume with the specified junction path, if present."""
        if not junction_path:
            return None

        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'junction-path': junction_path,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'containing-aggregate-name': None,
                        'junction-path': None,
                        'name': None,
                        'type': None,
                        'style': None,
                    },
                    'volume-space-attributes': {
                        'size': None,
                    }
                },
            },
        }
        result = self.send_request('volume-get-iter', api_args)
        if not self._has_records(result):
            return None

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        volume_attributes = attributes_list.get_child_by_name(
            'volume-attributes') or netapp_api.NaElement('none')
        volume_id_attributes = volume_attributes.get_child_by_name(
            'volume-id-attributes') or netapp_api.NaElement('none')
        volume_space_attributes = volume_attributes.get_child_by_name(
            'volume-space-attributes') or netapp_api.NaElement('none')

        volume = {
            'aggregate': volume_id_attributes.get_child_content(
                'containing-aggregate-name'),
            'junction-path': volume_id_attributes.get_child_content(
                'junction-path'),
            'name': volume_id_attributes.get_child_content('name'),
            'type': volume_id_attributes.get_child_content('type'),
            'style': volume_id_attributes.get_child_content('style'),
            'size': volume_space_attributes.get_child_content('size'),
        }
        return volume

    @na_utils.trace
    def get_volume_to_manage(self, aggregate_name, volume_name):
        """Get flexvol to be managed by Manila."""

        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'containing-aggregate-name': aggregate_name,
                        'name': volume_name,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'containing-aggregate-name': None,
                        'junction-path': None,
                        'name': None,
                        'type': None,
                        'style': None,
                    },
                    'volume-space-attributes': {
                        'size': None,
                    }
                },
            },
        }
        result = self.send_request('volume-get-iter', api_args)
        if not self._has_records(result):
            return None

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        volume_attributes = attributes_list.get_child_by_name(
            'volume-attributes') or netapp_api.NaElement('none')
        volume_id_attributes = volume_attributes.get_child_by_name(
            'volume-id-attributes') or netapp_api.NaElement('none')
        volume_space_attributes = volume_attributes.get_child_by_name(
            'volume-space-attributes') or netapp_api.NaElement('none')

        volume = {
            'aggregate': volume_id_attributes.get_child_content(
                'containing-aggregate-name'),
            'junction-path': volume_id_attributes.get_child_content(
                'junction-path'),
            'name': volume_id_attributes.get_child_content('name'),
            'type': volume_id_attributes.get_child_content('type'),
            'style': volume_id_attributes.get_child_content('style'),
            'size': volume_space_attributes.get_child_content('size'),
        }
        return volume

    @na_utils.trace
    def create_volume_clone(self, volume_name, parent_volume_name,
                            parent_snapshot_name=None):
        """Clones a volume."""
        api_args = {
            'volume': volume_name,
            'parent-volume': parent_volume_name,
            'parent-snapshot': parent_snapshot_name,
            'junction-path': '/%s' % volume_name,
        }
        self.send_request('volume-clone-create', api_args)

    @na_utils.trace
    def split_volume_clone(self, volume_name):
        """Begins splitting a clone from its parent."""
        api_args = {'volume': volume_name}
        self.send_request('volume-clone-split-start', api_args)

    @na_utils.trace
    def get_volume_junction_path(self, volume_name, is_style_cifs=False):
        """Gets a volume junction path."""
        api_args = {
            'volume': volume_name,
            'is-style-cifs': six.text_type(is_style_cifs).lower(),
        }
        result = self.send_request('volume-get-volume-path', api_args)
        return result.get_child_content('junction')

    @na_utils.trace
    def mount_volume(self, volume_name, junction_path=None):
        """Mounts a volume on a junction path."""
        api_args = {
            'volume-name': volume_name,
            'junction-path': (junction_path if junction_path
                              else '/%s' % volume_name)
        }
        self.send_request('volume-mount', api_args)

    @na_utils.trace
    def offline_volume(self, volume_name):
        """Offlines a volume."""
        try:
            self.send_request('volume-offline', {'name': volume_name})
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EVOLUMEOFFLINE:
                return
            raise

    @na_utils.trace
    def _unmount_volume(self, volume_name, force=False):
        """Unmounts a volume."""
        api_args = {
            'volume-name': volume_name,
            'force': six.text_type(force).lower(),
        }
        try:
            self.send_request('volume-unmount', api_args)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EVOL_NOT_MOUNTED:
                return
            raise

    @na_utils.trace
    def unmount_volume(self, volume_name, force=False, wait_seconds=30):
        """Unmounts a volume, retrying if a clone split is ongoing.

        NOTE(cknight): While unlikely to happen in normal operation, any client
        that tries to delete volumes immediately after creating volume clones
        is likely to experience failures if cDOT isn't quite ready for the
        delete.  The volume unmount is the first operation in the delete
        path that fails in this case, and there is no proactive check we can
        use to reliably predict the failure.  And there isn't a specific error
        code from volume-unmount, so we have to check for a generic error code
        plus certain language in the error code.  It's ugly, but it works, and
        it's better than hard-coding a fixed delay.
        """

        # Do the unmount, handling split-related errors with retries.
        retry_interval = 3  # seconds
        for retry in range(int(wait_seconds / retry_interval)):
            try:
                self._unmount_volume(volume_name, force=force)
                LOG.debug('Volume %s unmounted.', volume_name)
                return
            except netapp_api.NaApiError as e:
                if e.code == netapp_api.EAPIERROR and 'job ID' in e.message:
                    msg = _LW('Could not unmount volume %(volume)s due to '
                              'ongoing volume operation: %(exception)s')
                    msg_args = {'volume': volume_name, 'exception': e}
                    LOG.warning(msg, msg_args)
                    time.sleep(retry_interval)
                    continue
                raise

        msg = _('Failed to unmount volume %(volume)s after '
                'waiting for %(wait_seconds)s seconds.')
        msg_args = {'volume': volume_name, 'wait_seconds': wait_seconds}
        LOG.error(msg, msg_args)
        raise exception.NetAppException(msg % msg_args)

    @na_utils.trace
    def delete_volume(self, volume_name):
        """Deletes a volume."""
        self.send_request('volume-destroy', {'name': volume_name})

    @na_utils.trace
    def create_snapshot(self, volume_name, snapshot_name):
        """Creates a volume snapshot."""
        api_args = {'volume': volume_name, 'snapshot': snapshot_name}
        self.send_request('snapshot-create', api_args)

    @na_utils.trace
    def get_snapshot(self, volume_name, snapshot_name):
        """Gets a single snapshot."""
        api_args = {
            'query': {
                'snapshot-info': {
                    'name': snapshot_name,
                    'volume': volume_name,
                },
            },
            'desired-attributes': {
                'snapshot-info': {
                    'name': None,
                    'volume': None,
                    'busy': None,
                    'snapshot-owners-list': {
                        'snapshot-owner': None,
                    }
                },
            },
        }
        result = self.send_request('snapshot-get-iter', api_args)

        error_record_list = result.get_child_by_name(
            'volume-errors') or netapp_api.NaElement('none')
        errors = error_record_list.get_children()

        if errors:
            error = errors[0]
            error_code = error.get_child_content('errno')
            error_reason = error.get_child_content('reason')
            msg = _('Could not read information for snapshot %(name)s. '
                    'Code: %(code)s. Reason: %(reason)s')
            msg_args = {
                'name': snapshot_name,
                'code': error_code,
                'reason': error_reason
            }
            if error_code == netapp_api.ESNAPSHOTNOTALLOWED:
                raise exception.SnapshotUnavailable(msg % msg_args)
            else:
                raise exception.NetAppException(msg % msg_args)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        snapshot_info_list = attributes_list.get_children()

        if not self._has_records(result):
            raise exception.SnapshotNotFound(name=snapshot_name)
        elif len(snapshot_info_list) > 1:
            msg = _('Could not find unique snapshot %(snap)s on '
                    'volume %(vol)s.')
            msg_args = {'snap': snapshot_name, 'vol': volume_name}
            raise exception.NetAppException(msg % msg_args)

        snapshot_info = snapshot_info_list[0]
        snapshot = {
            'name': snapshot_info.get_child_content('name'),
            'volume': snapshot_info.get_child_content('volume'),
            'busy': strutils.bool_from_string(
                snapshot_info.get_child_content('busy')),
        }

        snapshot_owners_list = snapshot_info.get_child_by_name(
            'snapshot-owners-list') or netapp_api.NaElement('none')
        snapshot_owners = set([
            snapshot_owner.get_child_content('owner')
            for snapshot_owner in snapshot_owners_list.get_children()])
        snapshot['owners'] = snapshot_owners

        return snapshot

    @na_utils.trace
    def delete_snapshot(self, volume_name, snapshot_name):
        """Deletes a volume snapshot."""
        api_args = {'volume': volume_name, 'snapshot': snapshot_name}
        self.send_request('snapshot-delete', api_args)

    @na_utils.trace
    def create_cg_snapshot(self, volume_names, snapshot_name):
        """Creates a consistency group snapshot of one or more flexvols."""
        cg_id = self._start_cg_snapshot(volume_names, snapshot_name)
        if not cg_id:
            msg = _('Could not start consistency group snapshot %s.')
            raise exception.NetAppException(msg % snapshot_name)
        self._commit_cg_snapshot(cg_id)

    @na_utils.trace
    def _start_cg_snapshot(self, volume_names, snapshot_name):
        api_args = {
            'snapshot': snapshot_name,
            'timeout': 'relaxed',
            'volumes': [
                {'volume-name': volume_name} for volume_name in volume_names
            ],
        }
        result = self.send_request('cg-start', api_args)
        return result.get_child_content('cg-id')

    @na_utils.trace
    def _commit_cg_snapshot(self, cg_id):
        api_args = {'cg-id': cg_id}
        self.send_request('cg-commit', api_args)

    @na_utils.trace
    def create_cifs_share(self, share_name):
        share_path = '/%s' % share_name
        api_args = {'path': share_path, 'share-name': share_name}
        self.send_request('cifs-share-create', api_args)

    @na_utils.trace
    def add_cifs_share_access(self, share_name, user_name, readonly):
        api_args = {
            'permission': 'read' if readonly else 'full_control',
            'share': share_name,
            'user-or-group': user_name,
        }
        self.send_request('cifs-share-access-control-create', api_args)

    @na_utils.trace
    def remove_cifs_share_access(self, share_name, user_name):
        api_args = {'user-or-group': user_name, 'share': share_name}
        self.send_request('cifs-share-access-control-delete', api_args)

    @na_utils.trace
    def remove_cifs_share(self, share_name):
        self.send_request('cifs-share-delete', {'share-name': share_name})

    @na_utils.trace
    def add_nfs_export_rule(self, policy_name, rule, readonly):
        rule_indices = self._get_nfs_export_rule_indices(policy_name, rule)
        if not rule_indices:
            self._add_nfs_export_rule(policy_name, rule, readonly)
        else:
            # Update first rule and delete the rest
            self._update_nfs_export_rule(
                policy_name, rule, readonly, rule_indices.pop(0))
            self._remove_nfs_export_rules(policy_name, rule_indices)

    @na_utils.trace
    def _add_nfs_export_rule(self, policy_name, rule, readonly):
        api_args = {
            'policy-name': policy_name,
            'client-match': rule,
            'ro-rule': {
                'security-flavor': 'sys',
            },
            'rw-rule': {
                'security-flavor': 'sys' if not readonly else 'never',
            },
            'super-user-security': {
                'security-flavor': 'sys',
            },
        }
        self.send_request('export-rule-create', api_args)

    @na_utils.trace
    def _update_nfs_export_rule(self, policy_name, rule, readonly, rule_index):
        api_args = {
            'policy-name': policy_name,
            'rule-index': rule_index,
            'client-match': rule,
            'ro-rule': {
                'security-flavor': 'sys'
            },
            'rw-rule': {
                'security-flavor': 'sys' if not readonly else 'never'
            },
            'super-user-security': {
                'security-flavor': 'sys'
            },
        }
        self.send_request('export-rule-modify', api_args)

    @na_utils.trace
    def _get_nfs_export_rule_indices(self, policy_name, rule):
        api_args = {
            'query': {
                'export-rule-info': {
                    'policy-name': policy_name,
                    'client-match': rule,
                },
            },
            'desired-attributes': {
                'export-rule-info': {
                    'vserver-name': None,
                    'policy-name': None,
                    'client-match': None,
                    'rule-index': None,
                },
            },
        }
        result = self.send_request('export-rule-get-iter', api_args)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        export_rule_info_list = attributes_list.get_children()

        rule_indices = [int(export_rule_info.get_child_content('rule-index'))
                        for export_rule_info in export_rule_info_list]
        rule_indices.sort()
        return [six.text_type(rule_index) for rule_index in rule_indices]

    @na_utils.trace
    def remove_nfs_export_rule(self, policy_name, rule):
        rule_indices = self._get_nfs_export_rule_indices(policy_name, rule)
        self._remove_nfs_export_rules(policy_name, rule_indices)

    @na_utils.trace
    def _remove_nfs_export_rules(self, policy_name, rule_indices):
        for rule_index in rule_indices:
            api_args = {
                'policy-name': policy_name,
                'rule-index': rule_index
            }
            try:
                self.send_request('export-rule-destroy', api_args)
            except netapp_api.NaApiError as e:
                if e.code != netapp_api.EOBJECTNOTFOUND:
                    raise

    @na_utils.trace
    def clear_nfs_export_policy_for_volume(self, volume_name):
        self.set_nfs_export_policy_for_volume(volume_name, 'default')

    @na_utils.trace
    def set_nfs_export_policy_for_volume(self, volume_name, policy_name):
        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': volume_name,
                    },
                },
            },
            'attributes': {
                'volume-attributes': {
                    'volume-export-attributes': {
                        'policy': policy_name,
                    },
                },
            },
        }
        self.send_request('volume-modify-iter', api_args)

    @na_utils.trace
    def get_nfs_export_policy_for_volume(self, volume_name):
        """Get the name of the export policy for a volume."""

        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': volume_name,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-export-attributes': {
                        'policy': None,
                    },
                },
            },
        }
        result = self.send_request('volume-get-iter', api_args)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        volume_attributes = attributes_list.get_child_by_name(
            'volume-attributes') or netapp_api.NaElement('none')
        volume_export_attributes = volume_attributes.get_child_by_name(
            'volume-export-attributes') or netapp_api.NaElement('none')

        export_policy = volume_export_attributes.get_child_content('policy')

        if not export_policy:
            msg = _('Could not find export policy for volume %s.')
            raise exception.NetAppException(msg % volume_name)

        return export_policy

    @na_utils.trace
    def create_nfs_export_policy(self, policy_name):
        api_args = {'policy-name': policy_name}
        try:
            self.send_request('export-policy-create', api_args)
        except netapp_api.NaApiError as e:
            if e.code != netapp_api.EDUPLICATEENTRY:
                raise

    @na_utils.trace
    def soft_delete_nfs_export_policy(self, policy_name):
        try:
            self.delete_nfs_export_policy(policy_name)
        except netapp_api.NaApiError:
            # NOTE(cknight): Policy deletion can fail if called too soon after
            # removing from a flexvol.  So rename for later harvesting.
            self.rename_nfs_export_policy(policy_name,
                                          DELETED_PREFIX + policy_name)

    @na_utils.trace
    def delete_nfs_export_policy(self, policy_name):
        api_args = {'policy-name': policy_name}
        try:
            self.send_request('export-policy-destroy', api_args)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EOBJECTNOTFOUND:
                return
            raise

    @na_utils.trace
    def rename_nfs_export_policy(self, policy_name, new_policy_name):
        api_args = {
            'policy-name': policy_name,
            'new-policy-name': new_policy_name
        }
        self.send_request('export-policy-rename', api_args)

    @na_utils.trace
    def prune_deleted_nfs_export_policies(self):
        deleted_policy_map = self._get_deleted_nfs_export_policies()
        for vserver in deleted_policy_map:
            client = copy.deepcopy(self)
            client.set_vserver(vserver)
            for policy in deleted_policy_map[vserver]:
                try:
                    client.delete_nfs_export_policy(policy)
                except netapp_api.NaApiError:
                    LOG.debug('Could not delete export policy %s.' % policy)

    @na_utils.trace
    def _get_deleted_nfs_export_policies(self):
        api_args = {
            'query': {
                'export-policy-info': {
                    'policy-name': DELETED_PREFIX + '*',
                },
            },
            'desired-attributes': {
                'export-policy-info': {
                    'policy-name': None,
                    'vserver': None,
                },
            },
        }
        result = self.send_request('export-policy-get-iter', api_args)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')

        policy_map = {}
        for export_info in attributes_list.get_children():
            vserver = export_info.get_child_content('vserver')
            policies = policy_map.get(vserver, [])
            policies.append(export_info.get_child_content('policy-name'))
            policy_map[vserver] = policies

        return policy_map

    @na_utils.trace
    def _get_ems_log_destination_vserver(self):
        """Returns the best vserver destination for EMS messages."""
        major, minor = self.get_ontapi_version(cached=True)

        if (major > 1) or (major == 1 and minor > 15):
            # Prefer admin Vserver (requires cluster credentials).
            admin_vservers = self.list_vservers(vserver_type='admin')
            if admin_vservers:
                return admin_vservers[0]

            # Fall back to data Vserver.
            data_vservers = self.list_vservers(vserver_type='data')
            if data_vservers:
                return data_vservers[0]

        # If older API version, or no other Vservers found, use node Vserver.
        node_vservers = self.list_vservers(vserver_type='node')
        if node_vservers:
            return node_vservers[0]

        raise exception.NotFound("No Vserver found to receive EMS messages.")

    @na_utils.trace
    def send_ems_log_message(self, message_dict):
        """Sends a message to the Data ONTAP EMS log."""

        node_client = copy.deepcopy(self)
        node_client.connection.set_timeout(25)

        try:
            node_client.set_vserver(self._get_ems_log_destination_vserver())
            node_client.send_request('ems-autosupport-log', message_dict)
            LOG.debug('EMS executed successfully.')
        except netapp_api.NaApiError as e:
            LOG.warning(_LW('Failed to invoke EMS. %s') % e)

    @na_utils.trace
    def get_aggregate_raid_types(self, aggregate_names):
        """Get the RAID type of one or more aggregates."""

        desired_attributes = {
            'aggr-attributes': {
                'aggregate-name': None,
                'aggr-raid-attributes': {
                    'raid-type': None,
                },
            },
        }
        aggr_list = self._get_aggregates(aggregate_names=aggregate_names,
                                         desired_attributes=desired_attributes)

        aggr_raid_dict = {}
        for aggr in aggr_list:
            aggr_name = aggr.get_child_content('aggregate-name')
            aggr_raid_attrs = aggr.get_child_by_name('aggr-raid-attributes')

            aggr_raid_dict[aggr_name] = aggr_raid_attrs.get_child_content(
                'raid-type')

        return aggr_raid_dict

    @na_utils.trace
    def get_aggregate_disk_types(self, aggregate_names):
        """Get the disk type of one or more aggregates."""

        aggr_disk_type_dict = {}

        for aggregate_name in aggregate_names:

            # Only get 1 disk, since apart from hybrid aggregates all disks
            # must be the same type.
            api_args = {
                'max-records': 1,
                'query': {
                    'storage-disk-info': {
                        'disk-raid-info': {
                            'disk-aggregate-info': {
                                'aggregate-name': aggregate_name,
                            },
                        },
                    },
                },
                'desired-attributes': {
                    'storage-disk-info': {
                        'disk-raid-info': {
                            'effective-disk-type': None,
                        },
                    },
                },
            }
            result = self.send_request('storage-disk-get-iter', api_args)

            attributes_list = result.get_child_by_name(
                'attributes-list') or netapp_api.NaElement('none')
            storage_disk_info_list = attributes_list.get_children()

            if len(storage_disk_info_list) >= 1:
                storage_disk_info = storage_disk_info_list[0]
                disk_raid_info = storage_disk_info.get_child_by_name(
                    'disk-raid-info')
                if disk_raid_info:
                    disk_type = disk_raid_info.get_child_content(
                        'effective-disk-type')
                    if disk_type:
                        aggr_disk_type_dict[aggregate_name] = disk_type

        return aggr_disk_type_dict

    @na_utils.trace
    def check_for_cluster_credentials(self):
        try:
            self.list_cluster_nodes()
            # API succeeded, so definitely a cluster management LIF
            return True
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EAPINOTFOUND:
                LOG.debug('Not connected to cluster management LIF.')
                return False
            else:
                raise e
