# Copyright (c) 2014 Alex Meade.  All rights reserved.
# Copyright (c) 2015 Clinton Knight.  All rights reserved.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
# Copyright (c) 2018 Jose Porrua.  All rights reserved.
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
import re
import time

from oslo_log import log
from oslo_utils import strutils
from oslo_utils import units
import six

from manila import exception
from manila.i18n import _
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_base
from manila.share.drivers.netapp import utils as na_utils


LOG = log.getLogger(__name__)
DELETED_PREFIX = 'deleted_manila_'
DEFAULT_IPSPACE = 'Default'
DEFAULT_MAX_PAGE_LENGTH = 50
CUTOVER_ACTION_MAP = {
    'defer': 'defer_on_failure',
    'abort': 'abort_on_failure',
    'force': 'force',
    'wait': 'wait',
}


class NetAppCmodeClient(client_base.NetAppBaseClient):

    def __init__(self, **kwargs):
        super(NetAppCmodeClient, self).__init__(**kwargs)
        self.vserver = kwargs.get('vserver')
        self.connection.set_vserver(self.vserver)

        # Default values to run first api.
        self.connection.set_api_version(1, 15)
        (major, minor) = self.get_ontapi_version(cached=False)
        self.connection.set_api_version(major, minor)
        system_version = self.get_system_version(cached=False)
        self.connection.set_system_version(system_version)

        self._init_features()

    def _init_features(self):
        """Initialize cDOT feature support map."""
        super(NetAppCmodeClient, self)._init_features()

        ontapi_version = self.get_ontapi_version(cached=True)
        ontapi_1_20 = ontapi_version >= (1, 20)
        ontapi_1_2x = (1, 20) <= ontapi_version < (1, 30)
        ontapi_1_30 = ontapi_version >= (1, 30)
        ontapi_1_110 = ontapi_version >= (1, 110)

        self.features.add_feature('SNAPMIRROR_V2', supported=ontapi_1_20)
        self.features.add_feature('SYSTEM_METRICS', supported=ontapi_1_2x)
        self.features.add_feature('SYSTEM_CONSTITUENT_METRICS',
                                  supported=ontapi_1_30)
        self.features.add_feature('BROADCAST_DOMAINS', supported=ontapi_1_30)
        self.features.add_feature('IPSPACES', supported=ontapi_1_30)
        self.features.add_feature('SUBNETS', supported=ontapi_1_30)
        self.features.add_feature('CLUSTER_PEER_POLICY', supported=ontapi_1_30)
        self.features.add_feature('ADVANCED_DISK_PARTITIONING',
                                  supported=ontapi_1_30)
        self.features.add_feature('FLEXVOL_ENCRYPTION', supported=ontapi_1_110)

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

    def _get_record_count(self, api_result_element):
        try:
            return int(api_result_element.get_child_content('num-records'))
        except TypeError:
            msg = _('Missing record count for NetApp iterator API invocation.')
            raise exception.NetAppException(msg)

    def set_vserver(self, vserver):
        self.vserver = vserver
        self.connection.set_vserver(vserver)

    def send_iter_request(self, api_name, api_args=None,
                          max_page_length=DEFAULT_MAX_PAGE_LENGTH):
        """Invoke an iterator-style getter API."""

        if not api_args:
            api_args = {}

        api_args['max-records'] = max_page_length

        # Get first page
        result = self.send_request(api_name, api_args)

        # Most commonly, we can just return here if there is no more data
        next_tag = result.get_child_content('next-tag')
        if not next_tag:
            return result

        # Ensure pagination data is valid and prepare to store remaining pages
        num_records = self._get_record_count(result)
        attributes_list = result.get_child_by_name('attributes-list')
        if not attributes_list:
            msg = _('Missing attributes list for API %s.') % api_name
            raise exception.NetAppException(msg)

        # Get remaining pages, saving data into first page
        while next_tag is not None:
            next_api_args = copy.deepcopy(api_args)
            next_api_args['tag'] = next_tag
            next_result = self.send_request(api_name, next_api_args)

            next_attributes_list = next_result.get_child_by_name(
                'attributes-list') or netapp_api.NaElement('none')

            for record in next_attributes_list.get_children():
                attributes_list.add_child_elem(record)

            num_records += self._get_record_count(next_result)
            next_tag = next_result.get_child_content('next-tag')

        result.get_child_by_name('num-records').set_content(
            six.text_type(num_records))
        result.get_child_by_name('next-tag').set_content('')
        return result

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
        result = self.send_iter_request('vserver-get-iter', api_args)
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
        vserver_info = self.send_iter_request('vserver-get-iter', api_args)

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
        vserver_info = self.send_iter_request('vserver-get-iter', api_args)

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
        result = self.send_iter_request('vserver-get-iter', api_args)
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

        result = self.send_iter_request('vserver-get-iter', api_args)
        vserver_info_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        return [vserver_info.get_child_content('vserver-name')
                for vserver_info in vserver_info_list.get_children()]

    @na_utils.trace
    def get_vserver_volume_count(self):
        """Get the number of volumes present on a cluster or vserver.

        Call this on a vserver client to see how many volumes exist
        on that vserver.
        """
        api_args = {
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': None,
                    },
                },
            },
        }
        volumes_data = self.send_iter_request('volume-get-iter', api_args)
        return self._get_record_count(volumes_data)

    @na_utils.trace
    def delete_vserver(self, vserver_name, vserver_client,
                       security_services=None):
        """Delete Vserver.

        Checks if Vserver exists and does not have active shares.
        Offlines and destroys root volumes.  Deletes Vserver.
        """
        if not self.vserver_exists(vserver_name):
            LOG.error("Vserver %s does not exist.", vserver_name)
            return

        root_volume_name = self.get_vserver_root_volume_name(vserver_name)
        volumes_count = vserver_client.get_vserver_volume_count()

        if volumes_count == 1:
            try:
                vserver_client.offline_volume(root_volume_name)
            except netapp_api.NaApiError as e:
                if e.code == netapp_api.EVOLUMEOFFLINE:
                    LOG.error("Volume %s is already offline.",
                              root_volume_name)
                else:
                    raise
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
                        LOG.error('CIFS server does not exist for '
                                  'Vserver %s.', vserver_name)
                    else:
                        vserver_client.send_request('cifs-server-delete')

    @na_utils.trace
    def is_nve_supported(self):
        """Determine whether NVE is supported on this platform and version."""
        nodes = self.list_cluster_nodes()
        system_version = self.get_system_version()
        version = system_version.get('version')
        version_tuple = system_version.get('version-tuple')

        # NVE requires an ONTAP version >= 9.1. Also, not all platforms
        # support this feature. NVE is not supported if the version
        # includes the substring '<1no-DARE>' (no Data At Rest Encryption).
        if version_tuple >= (9, 1, 0) and "<1no-DARE>" not in version:
            if nodes is not None:
                return self.get_security_key_manager_nve_support(nodes[0])
            else:
                LOG.debug('Cluster credentials are required in order to '
                          'determine whether NetApp Volume Encryption is '
                          'supported or not on this platform.')
                return False
        else:
            LOG.debug('NetApp Volume Encryption is not supported on this '
                      'ONTAP version: %(version)s, %(version_tuple)s. ',
                      {'version': version, 'version_tuple': version_tuple})
            return False

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
        result = self.send_iter_request('system-node-get-iter', api_args)
        nodes_info_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        return [node_info.get_child_content('node') for node_info
                in nodes_info_list.get_children()]

    @na_utils.trace
    def get_security_key_manager_nve_support(self, node):
        """Determine whether the cluster platform supports Volume Encryption"""
        api_args = {'node': node}
        try:
            result = self.send_request(
                'security-key-manager-volume-encryption-supported', api_args)
            vol_encryption_supported = result.get_child_content(
                'vol-encryption-supported') or 'false'
        except netapp_api.NaApiError as e:
            LOG.debug("NVE disabled due to error code: %s - %s",
                      e.code, e.message)
            return False

        return strutils.bool_from_string(vol_encryption_supported)

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
        result = self.send_iter_request('net-port-get-iter', api_args)
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
    def list_root_aggregates(self):
        """Get names of all aggregates that contain node root volumes."""

        desired_attributes = {
            'aggr-attributes': {
                'aggregate-name': None,
                'aggr-raid-attributes': {
                    'has-local-root': None,
                    'has-partner-root': None,
                },
            },
        }
        aggrs = self._get_aggregates(desired_attributes=desired_attributes)

        root_aggregates = []
        for aggr in aggrs:
            aggr_name = aggr.get_child_content('aggregate-name')
            aggr_raid_attrs = aggr.get_child_by_name('aggr-raid-attributes')

            local_root = strutils.bool_from_string(
                aggr_raid_attrs.get_child_content('has-local-root'))
            partner_root = strutils.bool_from_string(
                aggr_raid_attrs.get_child_content('has-partner-root'))

            if local_root or partner_root:
                root_aggregates.append(aggr_name)

        return root_aggregates

    @na_utils.trace
    def list_non_root_aggregates(self):
        """Get names of all aggregates that don't contain node root volumes."""

        query = {
            'aggr-attributes': {
                'aggr-raid-attributes': {
                    'has-local-root': 'false',
                    'has-partner-root': 'false',
                }
            },
        }
        return self._list_aggregates(query=query)

    @na_utils.trace
    def _list_aggregates(self, query=None):
        """Get names of all aggregates."""
        try:
            api_args = {
                'desired-attributes': {
                    'aggr-attributes': {
                        'aggregate-name': None,
                    },
                },
            }
            if query:
                api_args['query'] = query
            result = self.send_iter_request('aggr-get-iter', api_args)
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
                                 vserver_name, lif_name, ipspace_name, mtu):
        """Creates LIF on VLAN port."""

        home_port_name = port
        if vlan:
            self._create_vlan(node, port, vlan)
            home_port_name = '%(port)s-%(tag)s' % {'port': port, 'tag': vlan}

        if self.features.BROADCAST_DOMAINS:
            self._ensure_broadcast_domain_for_port(
                node, home_port_name, mtu, ipspace=ipspace_name)

        LOG.debug('Creating LIF %(lif)s for Vserver %(vserver)s ',
                  {'lif': lif_name, 'vserver': vserver_name})

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
            'interface-name': lif_name,
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
    def delete_vlan(self, node, port, vlan):
        try:
            api_args = {
                'vlan-info': {
                    'parent-interface': port,
                    'node': node,
                    'vlanid': vlan,
                },
            }
            self.send_request('net-vlan-delete', api_args)
        except netapp_api.NaApiError as e:
            p = re.compile('port already has a lif bound.*', re.IGNORECASE)
            if (e.code == netapp_api.EAPIERROR and re.match(p, e.message)):
                LOG.debug('VLAN %(vlan)s on port %(port)s node %(node)s '
                          'still used by LIF and cannot be deleted.',
                          {'vlan': vlan, 'port': port, 'node': node})
            else:
                msg = _('Failed to delete VLAN %(vlan)s on '
                        'port %(port)s node %(node)s: %(err_msg)s')
                msg_args = {
                    'vlan': vlan,
                    'port': port,
                    'node': node,
                    'err_msg': e.message
                }
                raise exception.NetAppException(msg % msg_args)

    @na_utils.trace
    def create_route(self, gateway, destination=None):
        if not gateway:
            return
        if not destination:
            if ':' in gateway:
                destination = '::/0'
            else:
                destination = '0.0.0.0/0'
        try:
            api_args = {
                'destination': destination,
                'gateway': gateway,
                'return-record': 'true',
            }
            self.send_request('net-routes-create', api_args)
        except netapp_api.NaApiError as e:
            p = re.compile('.*Duplicate route exists.*', re.IGNORECASE)
            if (e.code == netapp_api.EAPIERROR and re.match(p, e.message)):
                LOG.debug('Route to %(destination)s via gateway %(gateway)s '
                          'exists.',
                          {'destination': destination, 'gateway': gateway})
            else:
                msg = _('Failed to create a route to %(destination)s via '
                        'gateway %(gateway)s: %(err_msg)s')
                msg_args = {
                    'destination': destination,
                    'gateway': gateway,
                    'err_msg': e.message,
                }
                raise exception.NetAppException(msg % msg_args)

    @na_utils.trace
    def _ensure_broadcast_domain_for_port(self, node, port, mtu,
                                          ipspace=DEFAULT_IPSPACE):
        """Ensure a port is in a broadcast domain.  Create one if necessary.

        If the IPspace:domain pair match for the given port, which commonly
        happens in multi-node clusters, then there isn't anything to do.
        Otherwise, we can assume the IPspace is correct and extant by this
        point, so the remaining task is to remove the port from any domain it
        is already in, create the domain for the IPspace if it doesn't exist,
        and add the port to this domain.
        """

        # Derive the broadcast domain name from the IPspace name since they
        # need to be 1-1 and the default for both is the same name, 'Default'.
        domain = re.sub(r'ipspace', 'domain', ipspace)

        port_info = self._get_broadcast_domain_for_port(node, port)

        # Port already in desired ipspace and broadcast domain.
        if (port_info['ipspace'] == ipspace
                and port_info['broadcast-domain'] == domain):
            self._modify_broadcast_domain(domain, ipspace, mtu)
            return

        # If in another broadcast domain, remove port from it.
        if port_info['broadcast-domain']:
            self._remove_port_from_broadcast_domain(
                node, port, port_info['broadcast-domain'],
                port_info['ipspace'])

        # If desired broadcast domain doesn't exist, create it.
        if not self._broadcast_domain_exists(domain, ipspace):
            self._create_broadcast_domain(domain, ipspace, mtu)
        else:
            self._modify_broadcast_domain(domain, ipspace, mtu)

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
        result = self.send_iter_request('net-port-get-iter', api_args)

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
        result = self.send_iter_request('net-port-broadcast-domain-get-iter',
                                        api_args)
        return self._has_records(result)

    @na_utils.trace
    def _create_broadcast_domain(self, domain, ipspace, mtu):
        """Create a broadcast domain."""
        api_args = {
            'ipspace': ipspace,
            'broadcast-domain': domain,
            'mtu': mtu,
        }
        self.send_request('net-port-broadcast-domain-create', api_args)

    @na_utils.trace
    def _modify_broadcast_domain(self, domain, ipspace, mtu):
        """Modify a broadcast domain."""
        api_args = {
            'ipspace': ipspace,
            'broadcast-domain': domain,
            'mtu': mtu,
        }
        self.send_request('net-port-broadcast-domain-modify', api_args)

    @na_utils.trace
    def _delete_broadcast_domain(self, domain, ipspace):
        """Delete a broadcast domain."""
        api_args = {
            'ipspace': ipspace,
            'broadcast-domain': domain,
        }
        self.send_request('net-port-broadcast-domain-destroy', api_args)

    @na_utils.trace
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
        result = self.send_iter_request('net-interface-get-iter', api_args)
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
        result = self.send_iter_request('net-interface-get-iter', api_args)
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

        result = self.send_iter_request('net-interface-get-iter', api_args)
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
    def get_ipspaces(self, ipspace_name=None):
        """Gets one or more IPSpaces."""

        if not self.features.IPSPACES:
            return []

        api_args = {}
        if ipspace_name:
            api_args['query'] = {
                'net-ipspaces-info': {
                    'ipspace': ipspace_name,
                }
            }

        result = self.send_iter_request('net-ipspaces-get-iter', api_args)
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
        result = self.send_iter_request('net-ipspaces-get-iter', api_args)
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
                raise

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
            LOG.warning('No aggregates assigned to Vserver %s.',
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

        result = self.send_iter_request('aggr-get-iter', api_args)
        if not self._has_records(result):
            return []
        else:
            return result.get_child_by_name('attributes-list').get_children()

    def get_performance_instance_uuids(self, object_name, node_name):
        """Get UUIDs of performance instances for a cluster node."""

        api_args = {
            'objectname': object_name,
            'query': {
                'instance-info': {
                    'uuid': node_name + ':*',
                }
            }
        }

        result = self.send_request('perf-object-instance-list-info-iter',
                                   api_args)

        uuids = []

        instances = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('None')

        for instance_info in instances.get_children():
            uuids.append(instance_info.get_child_content('uuid'))

        return uuids

    def get_performance_counter_info(self, object_name, counter_name):
        """Gets info about one or more Data ONTAP performance counters."""

        api_args = {'objectname': object_name}
        result = self.send_request('perf-object-counter-list-info', api_args)

        counters = result.get_child_by_name(
            'counters') or netapp_api.NaElement('None')

        for counter in counters.get_children():

            if counter.get_child_content('name') == counter_name:

                labels = []
                label_list = counter.get_child_by_name(
                    'labels') or netapp_api.NaElement('None')
                for label in label_list.get_children():
                    labels.extend(label.get_content().split(','))
                base_counter = counter.get_child_content('base-counter')

                return {
                    'name': counter_name,
                    'labels': labels,
                    'base-counter': base_counter,
                }
        else:
            raise exception.NotFound(_('Counter %s not found') % counter_name)

    def get_performance_counters(self, object_name, instance_uuids,
                                 counter_names):
        """Gets one or more cDOT performance counters."""

        api_args = {
            'objectname': object_name,
            'instance-uuids': [
                {'instance-uuid': instance_uuid}
                for instance_uuid in instance_uuids
            ],
            'counters': [
                {'counter': counter} for counter in counter_names
            ],
        }

        result = self.send_request('perf-object-get-instances', api_args)

        counter_data = []

        timestamp = result.get_child_content('timestamp')

        instances = result.get_child_by_name(
            'instances') or netapp_api.NaElement('None')
        for instance in instances.get_children():

            instance_name = instance.get_child_content('name')
            instance_uuid = instance.get_child_content('uuid')
            node_name = instance_uuid.split(':')[0]

            counters = instance.get_child_by_name(
                'counters') or netapp_api.NaElement('None')
            for counter in counters.get_children():

                counter_name = counter.get_child_content('name')
                counter_value = counter.get_child_content('value')

                counter_data.append({
                    'instance-name': instance_name,
                    'instance-uuid': instance_uuid,
                    'node-name': node_name,
                    'timestamp': timestamp,
                    counter_name: counter_value,
                })

        return counter_data

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
    def enable_nfs(self, versions):
        """Enables NFS on Vserver."""
        self.send_request('nfs-enable')
        self._enable_nfs_protocols(versions)
        self._create_default_nfs_export_rules()

    @na_utils.trace
    def _enable_nfs_protocols(self, versions):
        """Set the enabled NFS protocol versions."""
        nfs3 = 'true' if 'nfs3' in versions else 'false'
        nfs40 = 'true' if 'nfs4.0' in versions else 'false'
        nfs41 = 'true' if 'nfs4.1' in versions else 'false'

        nfs_service_modify_args = {
            'is-nfsv3-enabled': nfs3,
            'is-nfsv40-enabled': nfs40,
            'is-nfsv41-enabled': nfs41,
        }
        self.send_request('nfs-service-modify', nfs_service_modify_args)

    @na_utils.trace
    def _create_default_nfs_export_rules(self):
        """Create the default export rule for the NFS service."""

        export_rule_create_args = {
            'client-match': '0.0.0.0/0',
            'policy-name': 'default',
            'ro-rule': {
                'security-flavor': 'any',
            },
            'rw-rule': {
                'security-flavor': 'never',
            },
        }
        self.send_request('export-rule-create', export_rule_create_args)
        export_rule_create_args['client-match'] = '::/0'
        self.send_request('export-rule-create', export_rule_create_args)

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
        return ('nfs/' + vserver_name.replace('_', '-') + '.' +
                security_service['domain'] + '@' +
                security_service['domain'].upper())

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
                LOG.error("DNS exists for Vserver.")
            else:
                msg = _("Failed to configure DNS. %s")
                raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def create_volume(self, aggregate_name, volume_name, size_gb,
                      thin_provisioned=False, snapshot_policy=None,
                      language=None, dedup_enabled=False,
                      compression_enabled=False, max_files=None,
                      snapshot_reserve=None, volume_type='rw',
                      qos_policy_group=None,
                      encrypt=False, **options):
        """Creates a volume."""
        api_args = {
            'containing-aggr-name': aggregate_name,
            'size': six.text_type(size_gb) + 'g',
            'volume': volume_name,
            'volume-type': volume_type,
        }
        if volume_type != 'dp':
            api_args['junction-path'] = '/%s' % volume_name
        if thin_provisioned:
            api_args['space-reserve'] = 'none'
        if snapshot_policy is not None:
            api_args['snapshot-policy'] = snapshot_policy
        if language is not None:
            api_args['language-code'] = language
        if snapshot_reserve is not None:
            api_args['percentage-snapshot-reserve'] = six.text_type(
                snapshot_reserve)
        if qos_policy_group is not None:
            api_args['qos-policy-group-name'] = qos_policy_group

        if encrypt is True:
            if not self.features.FLEXVOL_ENCRYPTION:
                msg = 'Flexvol encryption is not supported on this backend.'
                raise exception.NetAppException(msg)
            else:
                api_args['encrypt'] = 'true'

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
        result = self.send_iter_request('sis-get-iter', api_args)

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
    def set_volume_security_style(self, volume_name, security_style='unix'):
        """Set volume security style"""
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
                    'volume-security-attributes': {
                        'style': security_style,
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
    def modify_volume(self, aggregate_name, volume_name,
                      thin_provisioned=False, snapshot_policy=None,
                      language=None, dedup_enabled=False,
                      compression_enabled=False, max_files=None,
                      qos_policy_group=None, **options):
        """Update backend volume for a share as necessary."""
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
                                            'volume'),
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
        if qos_policy_group:
            api_args['attributes']['volume-attributes'][
                'volume-qos-attributes'] = {
                'policy-group-name': qos_policy_group,
            }

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
        result = self.send_iter_request('volume-get-iter', api_args)
        return self._has_records(result)

    @na_utils.trace
    def is_flexvol_encrypted(self, volume_name, vserver_name):
        """Checks whether the volume is encrypted or not."""

        if not self.features.FLEXVOL_ENCRYPTION:
            return False

        api_args = {
            'query': {
                'volume-attributes': {
                    'encrypt': 'true',
                    'volume-id-attributes': {
                        'name': volume_name,
                        'owning-vserver-name': vserver_name,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'encrypt': None,
                },
            },
        }
        result = self.send_iter_request('volume-get-iter', api_args)
        if self._has_records(result):
            attributes_list = result.get_child_by_name(
                'attributes-list') or netapp_api.NaElement('none')
            volume_attributes = attributes_list.get_child_by_name(
                'volume-attributes') or netapp_api.NaElement('none')
            encrypt = volume_attributes.get_child_content('encrypt')
            if encrypt:
                return True

        return False

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
        result = self.send_iter_request('volume-get-iter', api_args)

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
        result = self.send_iter_request('lun-get-iter', api_args)
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
        result = self.send_iter_request('volume-get-iter', api_args)
        return self._has_records(result)

    @na_utils.trace
    def get_volume(self, volume_name):
        """Returns the volume with the specified name, if present."""

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
                        'junction-path': None,
                        'name': None,
                        'owning-vserver-name': None,
                        'type': None,
                        'style': None,
                    },
                    'volume-qos-attributes': {
                        'policy-group-name': None,
                    },
                    'volume-space-attributes': {
                        'size': None,
                    },
                },
            },
        }
        result = self.send_request('volume-get-iter', api_args)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        volume_attributes_list = attributes_list.get_children()

        if not self._has_records(result):
            raise exception.StorageResourceNotFound(name=volume_name)
        elif len(volume_attributes_list) > 1:
            msg = _('Could not find unique volume %(vol)s.')
            msg_args = {'vol': volume_name}
            raise exception.NetAppException(msg % msg_args)

        volume_attributes = volume_attributes_list[0]

        volume_id_attributes = volume_attributes.get_child_by_name(
            'volume-id-attributes') or netapp_api.NaElement('none')
        volume_qos_attributes = volume_attributes.get_child_by_name(
            'volume-qos-attributes') or netapp_api.NaElement('none')
        volume_space_attributes = volume_attributes.get_child_by_name(
            'volume-space-attributes') or netapp_api.NaElement('none')

        volume = {
            'aggregate': volume_id_attributes.get_child_content(
                'containing-aggregate-name'),
            'junction-path': volume_id_attributes.get_child_content(
                'junction-path'),
            'name': volume_id_attributes.get_child_content('name'),
            'owning-vserver-name': volume_id_attributes.get_child_content(
                'owning-vserver-name'),
            'type': volume_id_attributes.get_child_content('type'),
            'style': volume_id_attributes.get_child_content('style'),
            'size': volume_space_attributes.get_child_content('size'),
            'qos-policy-group-name': volume_qos_attributes.get_child_content(
                'policy-group-name')
        }
        return volume

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
        result = self.send_iter_request('volume-get-iter', api_args)
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
                        'owning-vserver-name': None,
                    },
                    'volume-qos-attributes': {
                        'policy-group-name': None,
                    },
                    'volume-space-attributes': {
                        'size': None,
                    },
                },
            },
        }
        result = self.send_iter_request('volume-get-iter', api_args)
        if not self._has_records(result):
            return None

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        volume_attributes = attributes_list.get_child_by_name(
            'volume-attributes') or netapp_api.NaElement('none')
        volume_id_attributes = volume_attributes.get_child_by_name(
            'volume-id-attributes') or netapp_api.NaElement('none')
        volume_qos_attributes = volume_attributes.get_child_by_name(
            'volume-qos-attributes') or netapp_api.NaElement('none')
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
            'owning-vserver-name': volume_id_attributes.get_child_content(
                'owning-vserver-name'),
            'size': volume_space_attributes.get_child_content('size'),
            'qos-policy-group-name': volume_qos_attributes.get_child_content(
                'policy-group-name')

        }
        return volume

    @na_utils.trace
    def create_volume_clone(self, volume_name, parent_volume_name,
                            parent_snapshot_name=None, split=False,
                            qos_policy_group=None, **options):
        """Clones a volume."""
        api_args = {
            'volume': volume_name,
            'parent-volume': parent_volume_name,
            'parent-snapshot': parent_snapshot_name,
            'junction-path': '/%s' % volume_name,
        }

        if qos_policy_group is not None:
            api_args['qos-policy-group-name'] = qos_policy_group

        self.send_request('volume-clone-create', api_args)

        if split:
            self.split_volume_clone(volume_name)

    @na_utils.trace
    def split_volume_clone(self, volume_name):
        """Begins splitting a clone from its parent."""
        try:
            api_args = {'volume': volume_name}
            self.send_request('volume-clone-split-start', api_args)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EVOL_CLONE_BEING_SPLIT:
                return
            raise

    @na_utils.trace
    def get_clone_children_for_snapshot(self, volume_name, snapshot_name):
        """Returns volumes that are keeping a snapshot locked."""

        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-clone-attributes': {
                        'volume-clone-parent-attributes': {
                            'name': volume_name,
                            'snapshot-name': snapshot_name,
                        },
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
        result = self.send_iter_request('volume-get-iter', api_args)
        if not self._has_records(result):
            return []

        volume_list = []
        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')

        for volume_attributes in attributes_list.get_children():

            volume_id_attributes = volume_attributes.get_child_by_name(
                'volume-id-attributes') or netapp_api.NaElement('none')

            volume_list.append({
                'name': volume_id_attributes.get_child_content('name'),
            })

        return volume_list

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
                    msg = ('Could not unmount volume %(volume)s due to '
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
    def snapshot_exists(self, snapshot_name, volume_name):
        """Checks if Snapshot exists for a specified volume."""
        LOG.debug('Checking if snapshot %(snapshot)s exists for '
                  'volume %(volume)s',
                  {'snapshot': snapshot_name, 'volume': volume_name})

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

        return self._has_records(result)

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
                    'access-time': None,
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
            raise exception.SnapshotResourceNotFound(name=snapshot_name)
        elif len(snapshot_info_list) > 1:
            msg = _('Could not find unique snapshot %(snap)s on '
                    'volume %(vol)s.')
            msg_args = {'snap': snapshot_name, 'vol': volume_name}
            raise exception.NetAppException(msg % msg_args)

        snapshot_info = snapshot_info_list[0]
        snapshot = {
            'access-time': snapshot_info.get_child_content('access-time'),
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
    def rename_snapshot(self, volume_name, snapshot_name, new_snapshot_name):
        api_args = {
            'volume': volume_name,
            'current-name': snapshot_name,
            'new-name': new_snapshot_name
        }
        self.send_request('snapshot-rename', api_args)

    @na_utils.trace
    def restore_snapshot(self, volume_name, snapshot_name):
        """Reverts a volume to the specified snapshot."""
        api_args = {
            'volume': volume_name,
            'snapshot': snapshot_name,
        }
        self.send_request('snapshot-restore-volume', api_args)

    @na_utils.trace
    def delete_snapshot(self, volume_name, snapshot_name, ignore_owners=False):
        """Deletes a volume snapshot."""

        ignore_owners = ('true' if strutils.bool_from_string(ignore_owners)
                         else 'false')

        api_args = {
            'volume': volume_name,
            'snapshot': snapshot_name,
            'ignore-owners': ignore_owners,
        }
        self.send_request('snapshot-delete', api_args)

    @na_utils.trace
    def soft_delete_snapshot(self, volume_name, snapshot_name):
        """Deletes a volume snapshot, or renames it if delete fails."""
        try:
            self.delete_snapshot(volume_name, snapshot_name)
        except netapp_api.NaApiError:
            self.rename_snapshot(volume_name,
                                 snapshot_name,
                                 DELETED_PREFIX + snapshot_name)
            msg = _('Soft-deleted snapshot %(snapshot)s on volume %(volume)s.')
            msg_args = {'snapshot': snapshot_name, 'volume': volume_name}
            LOG.info(msg, msg_args)

    @na_utils.trace
    def prune_deleted_snapshots(self):
        """Deletes non-busy snapshots that were previously soft-deleted."""

        deleted_snapshots_map = self._get_deleted_snapshots()

        for vserver in deleted_snapshots_map:
            client = copy.deepcopy(self)
            client.set_vserver(vserver)

            for snapshot in deleted_snapshots_map[vserver]:
                try:
                    client.delete_snapshot(snapshot['volume'],
                                           snapshot['name'])
                except netapp_api.NaApiError:
                    msg = _('Could not delete snapshot %(snap)s on '
                            'volume %(volume)s.')
                    msg_args = {
                        'snap': snapshot['name'],
                        'volume': snapshot['volume'],
                    }
                    LOG.exception(msg, msg_args)

    @na_utils.trace
    def _get_deleted_snapshots(self):
        """Returns non-busy, soft-deleted snapshots suitable for reaping."""
        api_args = {
            'query': {
                'snapshot-info': {
                    'name': DELETED_PREFIX + '*',
                    'busy': 'false',
                },
            },
            'desired-attributes': {
                'snapshot-info': {
                    'name': None,
                    'vserver': None,
                    'volume': None,
                },
            },
        }
        result = self.send_iter_request('snapshot-get-iter', api_args)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')

        # Build a map of snapshots, one list of snapshots per vserver
        snapshot_map = {}
        for snapshot_info in attributes_list.get_children():
            vserver = snapshot_info.get_child_content('vserver')
            snapshot_list = snapshot_map.get(vserver, [])
            snapshot_list.append({
                'name': snapshot_info.get_child_content('name'),
                'volume': snapshot_info.get_child_content('volume'),
                'vserver': vserver,
            })
            snapshot_map[vserver] = snapshot_list

        return snapshot_map

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
    def get_cifs_share_access(self, share_name):
        api_args = {
            'query': {
                'cifs-share-access-control': {
                    'share': share_name,
                },
            },
            'desired-attributes': {
                'cifs-share-access-control': {
                    'user-or-group': None,
                    'permission': None,
                },
            },
        }
        result = self.send_iter_request('cifs-share-access-control-get-iter',
                                        api_args)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')

        rules = {}

        for rule in attributes_list.get_children():
            user_or_group = rule.get_child_content('user-or-group')
            permission = rule.get_child_content('permission')
            rules[user_or_group] = permission

        return rules

    @na_utils.trace
    def add_cifs_share_access(self, share_name, user_name, readonly):
        api_args = {
            'permission': 'read' if readonly else 'full_control',
            'share': share_name,
            'user-or-group': user_name,
        }
        self.send_request('cifs-share-access-control-create', api_args)

    @na_utils.trace
    def modify_cifs_share_access(self, share_name, user_name, readonly):
        api_args = {
            'permission': 'read' if readonly else 'full_control',
            'share': share_name,
            'user-or-group': user_name,
        }
        self.send_request('cifs-share-access-control-modify', api_args)

    @na_utils.trace
    def remove_cifs_share_access(self, share_name, user_name):
        api_args = {'user-or-group': user_name, 'share': share_name}
        self.send_request('cifs-share-access-control-delete', api_args)

    @na_utils.trace
    def remove_cifs_share(self, share_name):
        self.send_request('cifs-share-delete', {'share-name': share_name})

    @na_utils.trace
    def add_nfs_export_rule(self, policy_name, client_match, readonly):
        rule_indices = self._get_nfs_export_rule_indices(policy_name,
                                                         client_match)
        if not rule_indices:
            self._add_nfs_export_rule(policy_name, client_match, readonly)
        else:
            # Update first rule and delete the rest
            self._update_nfs_export_rule(
                policy_name, client_match, readonly, rule_indices.pop(0))
            self._remove_nfs_export_rules(policy_name, rule_indices)

    @na_utils.trace
    def _add_nfs_export_rule(self, policy_name, client_match, readonly):
        api_args = {
            'policy-name': policy_name,
            'client-match': client_match,
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
    def _update_nfs_export_rule(self, policy_name, client_match, readonly,
                                rule_index):
        api_args = {
            'policy-name': policy_name,
            'rule-index': rule_index,
            'client-match': client_match,
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
    def _get_nfs_export_rule_indices(self, policy_name, client_match):
        api_args = {
            'query': {
                'export-rule-info': {
                    'policy-name': policy_name,
                    'client-match': client_match,
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
        result = self.send_iter_request('export-rule-get-iter', api_args)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        export_rule_info_list = attributes_list.get_children()

        rule_indices = [int(export_rule_info.get_child_content('rule-index'))
                        for export_rule_info in export_rule_info_list]
        rule_indices.sort()
        return [six.text_type(rule_index) for rule_index in rule_indices]

    @na_utils.trace
    def remove_nfs_export_rule(self, policy_name, client_match):
        rule_indices = self._get_nfs_export_rule_indices(policy_name,
                                                         client_match)
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
    def set_qos_policy_group_for_volume(self, volume_name,
                                        qos_policy_group_name):
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
                    'volume-qos-attributes': {
                        'policy-group-name': qos_policy_group_name,
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
        result = self.send_iter_request('volume-get-iter', api_args)

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
                    LOG.debug('Could not delete export policy %s.', policy)

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
        result = self.send_iter_request('export-policy-get-iter', api_args)

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

        # NOTE(cknight): Cannot use deepcopy on the connection context
        node_client = copy.copy(self)
        node_client.connection = copy.copy(self.connection)
        node_client.connection.set_timeout(25)

        try:
            node_client.set_vserver(self._get_ems_log_destination_vserver())
            node_client.send_request('ems-autosupport-log', message_dict)
            LOG.debug('EMS executed successfully.')
        except netapp_api.NaApiError as e:
            LOG.warning('Failed to invoke EMS. %s', e)

    @na_utils.trace
    def get_aggregate(self, aggregate_name):
        """Get aggregate attributes needed for the storage service catalog."""

        if not aggregate_name:
            return {}

        desired_attributes = {
            'aggr-attributes': {
                'aggregate-name': None,
                'aggr-raid-attributes': {
                    'raid-type': None,
                    'is-hybrid': None,
                },
            },
        }

        try:
            aggrs = self._get_aggregates(aggregate_names=[aggregate_name],
                                         desired_attributes=desired_attributes)
        except netapp_api.NaApiError:
            msg = _('Failed to get info for aggregate %s.')
            LOG.exception(msg, aggregate_name)
            return {}

        if len(aggrs) < 1:
            return {}

        aggr_attributes = aggrs[0]
        aggr_raid_attrs = aggr_attributes.get_child_by_name(
            'aggr-raid-attributes') or netapp_api.NaElement('none')

        aggregate = {
            'name': aggr_attributes.get_child_content('aggregate-name'),
            'raid-type': aggr_raid_attrs.get_child_content('raid-type'),
            'is-hybrid': strutils.bool_from_string(
                aggr_raid_attrs.get_child_content('is-hybrid')),
        }

        return aggregate

    @na_utils.trace
    def get_aggregate_disk_types(self, aggregate_name):
        """Get the disk type(s) of an aggregate."""

        disk_types = set()
        disk_types.update(self._get_aggregate_disk_types(aggregate_name))
        if self.features.ADVANCED_DISK_PARTITIONING:
            disk_types.update(self._get_aggregate_disk_types(aggregate_name,
                                                             shared=True))

        return list(disk_types) if disk_types else None

    @na_utils.trace
    def _get_aggregate_disk_types(self, aggregate_name, shared=False):
        """Get the disk type(s) of an aggregate."""

        disk_types = set()

        if shared:
            disk_raid_info = {
                'disk-shared-info': {
                    'aggregate-list': {
                        'shared-aggregate-info': {
                            'aggregate-name': aggregate_name,
                        },
                    },
                },
            }
        else:
            disk_raid_info = {
                'disk-aggregate-info': {
                    'aggregate-name': aggregate_name,
                },
            }

        api_args = {
            'query': {
                'storage-disk-info': {
                    'disk-raid-info': disk_raid_info,
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

        try:
            result = self.send_iter_request('storage-disk-get-iter', api_args)
        except netapp_api.NaApiError:
            msg = _('Failed to get disk info for aggregate %s.')
            LOG.exception(msg, aggregate_name)
            return disk_types

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')

        for storage_disk_info in attributes_list.get_children():

                disk_raid_info = storage_disk_info.get_child_by_name(
                    'disk-raid-info') or netapp_api.NaElement('none')
                disk_type = disk_raid_info.get_child_content(
                    'effective-disk-type')
                if disk_type:
                    disk_types.add(disk_type)

        return disk_types

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
                raise

    @na_utils.trace
    def create_cluster_peer(self, addresses, username=None, password=None,
                            passphrase=None):
        """Creates a cluster peer relationship."""

        api_args = {
            'peer-addresses': [
                {'remote-inet-address': address} for address in addresses
            ],
        }
        if username:
            api_args['user-name'] = username
        if password:
            api_args['password'] = password
        if passphrase:
            api_args['passphrase'] = passphrase

        self.send_request('cluster-peer-create', api_args)

    @na_utils.trace
    def get_cluster_peers(self, remote_cluster_name=None):
        """Gets one or more cluster peer relationships."""

        api_args = {}
        if remote_cluster_name:
            api_args['query'] = {
                'cluster-peer-info': {
                    'remote-cluster-name': remote_cluster_name,
                }
            }

        result = self.send_iter_request('cluster-peer-get-iter', api_args)
        if not self._has_records(result):
            return []

        cluster_peers = []

        for cluster_peer_info in result.get_child_by_name(
                'attributes-list').get_children():

            cluster_peer = {
                'active-addresses': [],
                'peer-addresses': []
            }

            active_addresses = cluster_peer_info.get_child_by_name(
                'active-addresses') or netapp_api.NaElement('none')
            for address in active_addresses.get_children():
                cluster_peer['active-addresses'].append(address.get_content())

            peer_addresses = cluster_peer_info.get_child_by_name(
                'peer-addresses') or netapp_api.NaElement('none')
            for address in peer_addresses.get_children():
                cluster_peer['peer-addresses'].append(address.get_content())

            cluster_peer['availability'] = cluster_peer_info.get_child_content(
                'availability')
            cluster_peer['cluster-name'] = cluster_peer_info.get_child_content(
                'cluster-name')
            cluster_peer['cluster-uuid'] = cluster_peer_info.get_child_content(
                'cluster-uuid')
            cluster_peer['remote-cluster-name'] = (
                cluster_peer_info.get_child_content('remote-cluster-name'))
            cluster_peer['serial-number'] = (
                cluster_peer_info.get_child_content('serial-number'))
            cluster_peer['timeout'] = cluster_peer_info.get_child_content(
                'timeout')

            cluster_peers.append(cluster_peer)

        return cluster_peers

    @na_utils.trace
    def delete_cluster_peer(self, cluster_name):
        """Deletes a cluster peer relationship."""

        api_args = {'cluster-name': cluster_name}
        self.send_request('cluster-peer-delete', api_args)

    @na_utils.trace
    def get_cluster_peer_policy(self):
        """Gets the cluster peering policy configuration."""

        if not self.features.CLUSTER_PEER_POLICY:
            return {}

        result = self.send_request('cluster-peer-policy-get')

        attributes = result.get_child_by_name(
            'attributes') or netapp_api.NaElement('none')
        cluster_peer_policy = attributes.get_child_by_name(
            'cluster-peer-policy') or netapp_api.NaElement('none')

        policy = {
            'is-unauthenticated-access-permitted':
            cluster_peer_policy.get_child_content(
                'is-unauthenticated-access-permitted'),
            'passphrase-minimum-length':
            cluster_peer_policy.get_child_content(
                'passphrase-minimum-length'),
        }

        if policy['is-unauthenticated-access-permitted'] is not None:
            policy['is-unauthenticated-access-permitted'] = (
                strutils.bool_from_string(
                    policy['is-unauthenticated-access-permitted']))
        if policy['passphrase-minimum-length'] is not None:
            policy['passphrase-minimum-length'] = int(
                policy['passphrase-minimum-length'])

        return policy

    @na_utils.trace
    def set_cluster_peer_policy(self, is_unauthenticated_access_permitted=None,
                                passphrase_minimum_length=None):
        """Modifies the cluster peering policy configuration."""

        if not self.features.CLUSTER_PEER_POLICY:
            return

        if (is_unauthenticated_access_permitted is None and
                passphrase_minimum_length is None):
            return

        api_args = {}
        if is_unauthenticated_access_permitted is not None:
            api_args['is-unauthenticated-access-permitted'] = (
                'true' if strutils.bool_from_string(
                    is_unauthenticated_access_permitted) else 'false')
        if passphrase_minimum_length is not None:
            api_args['passphrase-minlength'] = six.text_type(
                passphrase_minimum_length)

        self.send_request('cluster-peer-policy-modify', api_args)

    @na_utils.trace
    def create_vserver_peer(self, vserver_name, peer_vserver_name):
        """Creates a Vserver peer relationship for SnapMirrors."""
        api_args = {
            'vserver': vserver_name,
            'peer-vserver': peer_vserver_name,
            'applications': [
                {'vserver-peer-application': 'snapmirror'},
            ],
        }
        self.send_request('vserver-peer-create', api_args)

    @na_utils.trace
    def delete_vserver_peer(self, vserver_name, peer_vserver_name):
        """Deletes a Vserver peer relationship."""

        api_args = {'vserver': vserver_name, 'peer-vserver': peer_vserver_name}
        self.send_request('vserver-peer-delete', api_args)

    @na_utils.trace
    def accept_vserver_peer(self, vserver_name, peer_vserver_name):
        """Accepts a pending Vserver peer relationship."""

        api_args = {'vserver': vserver_name, 'peer-vserver': peer_vserver_name}
        self.send_request('vserver-peer-accept', api_args)

    @na_utils.trace
    def get_vserver_peers(self, vserver_name=None, peer_vserver_name=None):
        """Gets one or more Vserver peer relationships."""

        api_args = None
        if vserver_name or peer_vserver_name:
            api_args = {'query': {'vserver-peer-info': {}}}
            if vserver_name:
                api_args['query']['vserver-peer-info']['vserver'] = (
                    vserver_name)
            if peer_vserver_name:
                api_args['query']['vserver-peer-info']['peer-vserver'] = (
                    peer_vserver_name)

        result = self.send_iter_request('vserver-peer-get-iter', api_args)
        if not self._has_records(result):
            return []

        vserver_peers = []

        for vserver_peer_info in result.get_child_by_name(
                'attributes-list').get_children():

            vserver_peer = {
                'vserver': vserver_peer_info.get_child_content('vserver'),
                'peer-vserver':
                vserver_peer_info.get_child_content('peer-vserver'),
                'peer-state':
                vserver_peer_info.get_child_content('peer-state'),
                'peer-cluster':
                vserver_peer_info.get_child_content('peer-cluster'),
            }
            vserver_peers.append(vserver_peer)

        return vserver_peers

    def _ensure_snapmirror_v2(self):
        """Verify support for SnapMirror control plane v2."""
        if not self.features.SNAPMIRROR_V2:
            msg = _('SnapMirror features require Data ONTAP 8.2 or later.')
            raise exception.NetAppException(msg)

    @na_utils.trace
    def create_snapmirror(self, source_vserver, source_volume,
                          destination_vserver, destination_volume,
                          schedule=None, policy=None,
                          relationship_type='data_protection'):
        """Creates a SnapMirror relationship (cDOT 8.2 or later only)."""
        self._ensure_snapmirror_v2()

        api_args = {
            'source-volume': source_volume,
            'source-vserver': source_vserver,
            'destination-volume': destination_volume,
            'destination-vserver': destination_vserver,
            'relationship-type': relationship_type,
        }
        if schedule:
            api_args['schedule'] = schedule
        if policy:
            api_args['policy'] = policy

        try:
            self.send_request('snapmirror-create', api_args)
        except netapp_api.NaApiError as e:
            if e.code != netapp_api.ERELATION_EXISTS:
                raise

    @na_utils.trace
    def initialize_snapmirror(self, source_vserver, source_volume,
                              destination_vserver, destination_volume,
                              source_snapshot=None, transfer_priority=None):
        """Initializes a SnapMirror relationship (cDOT 8.2 or later only)."""
        self._ensure_snapmirror_v2()

        api_args = {
            'source-volume': source_volume,
            'source-vserver': source_vserver,
            'destination-volume': destination_volume,
            'destination-vserver': destination_vserver,
        }
        if source_snapshot:
            api_args['source-snapshot'] = source_snapshot
        if transfer_priority:
            api_args['transfer-priority'] = transfer_priority

        result = self.send_request('snapmirror-initialize', api_args)

        result_info = {}
        result_info['operation-id'] = result.get_child_content(
            'result-operation-id')
        result_info['status'] = result.get_child_content('result-status')
        result_info['jobid'] = result.get_child_content('result-jobid')
        result_info['error-code'] = result.get_child_content(
            'result-error-code')
        result_info['error-message'] = result.get_child_content(
            'result-error-message')

        return result_info

    @na_utils.trace
    def release_snapmirror(self, source_vserver, source_volume,
                           destination_vserver, destination_volume,
                           relationship_info_only=False):
        """Removes a SnapMirror relationship on the source endpoint."""
        self._ensure_snapmirror_v2()

        api_args = {
            'query': {
                'snapmirror-destination-info': {
                    'source-volume': source_volume,
                    'source-vserver': source_vserver,
                    'destination-volume': destination_volume,
                    'destination-vserver': destination_vserver,
                    'relationship-info-only': ('true' if relationship_info_only
                                               else 'false'),
                }
            }
        }
        self.send_request('snapmirror-release-iter', api_args)

    @na_utils.trace
    def quiesce_snapmirror(self, source_vserver, source_volume,
                           destination_vserver, destination_volume):
        """Disables future transfers to a SnapMirror destination."""
        self._ensure_snapmirror_v2()

        api_args = {
            'source-volume': source_volume,
            'source-vserver': source_vserver,
            'destination-volume': destination_volume,
            'destination-vserver': destination_vserver,
        }
        self.send_request('snapmirror-quiesce', api_args)

    @na_utils.trace
    def abort_snapmirror(self, source_vserver, source_volume,
                         destination_vserver, destination_volume,
                         clear_checkpoint=False):
        """Stops ongoing transfers for a SnapMirror relationship."""
        self._ensure_snapmirror_v2()

        api_args = {
            'source-volume': source_volume,
            'source-vserver': source_vserver,
            'destination-volume': destination_volume,
            'destination-vserver': destination_vserver,
            'clear-checkpoint': 'true' if clear_checkpoint else 'false',
        }
        try:
            self.send_request('snapmirror-abort', api_args)
        except netapp_api.NaApiError as e:
            if e.code != netapp_api.ENOTRANSFER_IN_PROGRESS:
                raise

    @na_utils.trace
    def break_snapmirror(self, source_vserver, source_volume,
                         destination_vserver, destination_volume):
        """Breaks a data protection SnapMirror relationship."""
        self._ensure_snapmirror_v2()

        api_args = {
            'source-volume': source_volume,
            'source-vserver': source_vserver,
            'destination-volume': destination_volume,
            'destination-vserver': destination_vserver,
        }
        self.send_request('snapmirror-break', api_args)

    @na_utils.trace
    def modify_snapmirror(self, source_vserver, source_volume,
                          destination_vserver, destination_volume,
                          schedule=None, policy=None, tries=None,
                          max_transfer_rate=None):
        """Modifies a SnapMirror relationship."""
        self._ensure_snapmirror_v2()

        api_args = {
            'source-volume': source_volume,
            'source-vserver': source_vserver,
            'destination-volume': destination_volume,
            'destination-vserver': destination_vserver,
        }
        if schedule:
            api_args['schedule'] = schedule
        if policy:
            api_args['policy'] = policy
        if tries is not None:
            api_args['tries'] = tries
        if max_transfer_rate is not None:
            api_args['max-transfer-rate'] = max_transfer_rate

        self.send_request('snapmirror-modify', api_args)

    @na_utils.trace
    def delete_snapmirror(self, source_vserver, source_volume,
                          destination_vserver, destination_volume):
        """Destroys a SnapMirror relationship."""
        self._ensure_snapmirror_v2()

        api_args = {
            'query': {
                'snapmirror-info': {
                    'source-volume': source_volume,
                    'source-vserver': source_vserver,
                    'destination-volume': destination_volume,
                    'destination-vserver': destination_vserver,
                }
            }
        }
        self.send_request('snapmirror-destroy-iter', api_args)

    @na_utils.trace
    def update_snapmirror(self, source_vserver, source_volume,
                          destination_vserver, destination_volume):
        """Schedules a snapmirror update."""
        self._ensure_snapmirror_v2()

        api_args = {
            'source-volume': source_volume,
            'source-vserver': source_vserver,
            'destination-volume': destination_volume,
            'destination-vserver': destination_vserver,
        }
        try:
            self.send_request('snapmirror-update', api_args)
        except netapp_api.NaApiError as e:
            if (e.code != netapp_api.ETRANSFER_IN_PROGRESS and
                    e.code != netapp_api.EANOTHER_OP_ACTIVE):
                raise

    @na_utils.trace
    def resume_snapmirror(self, source_vserver, source_volume,
                          destination_vserver, destination_volume):
        """Resume a SnapMirror relationship if it is quiesced."""
        self._ensure_snapmirror_v2()

        api_args = {
            'source-volume': source_volume,
            'source-vserver': source_vserver,
            'destination-volume': destination_volume,
            'destination-vserver': destination_vserver,
        }
        try:
            self.send_request('snapmirror-resume', api_args)
        except netapp_api.NaApiError as e:
            if e.code != netapp_api.ERELATION_NOT_QUIESCED:
                raise

    @na_utils.trace
    def resync_snapmirror(self, source_vserver, source_volume,
                          destination_vserver, destination_volume):
        """Resync a SnapMirror relationship."""
        self._ensure_snapmirror_v2()

        api_args = {
            'source-volume': source_volume,
            'source-vserver': source_vserver,
            'destination-volume': destination_volume,
            'destination-vserver': destination_vserver,
        }
        self.send_request('snapmirror-resync', api_args)

    @na_utils.trace
    def _get_snapmirrors(self, source_vserver=None, source_volume=None,
                         destination_vserver=None, destination_volume=None,
                         desired_attributes=None):

        query = None
        if (source_vserver or source_volume or destination_vserver or
                destination_volume):
            query = {'snapmirror-info': {}}
            if source_volume:
                query['snapmirror-info']['source-volume'] = source_volume
            if destination_volume:
                query['snapmirror-info']['destination-volume'] = (
                    destination_volume)
            if source_vserver:
                query['snapmirror-info']['source-vserver'] = source_vserver
            if destination_vserver:
                query['snapmirror-info']['destination-vserver'] = (
                    destination_vserver)

        api_args = {}
        if query:
            api_args['query'] = query
        if desired_attributes:
            api_args['desired-attributes'] = desired_attributes

        result = self.send_iter_request('snapmirror-get-iter', api_args)
        if not self._has_records(result):
            return []
        else:
            return result.get_child_by_name('attributes-list').get_children()

    @na_utils.trace
    def get_snapmirrors(self, source_vserver, source_volume,
                        destination_vserver, destination_volume,
                        desired_attributes=None):
        """Gets one or more SnapMirror relationships.

        Either the source or destination info may be omitted.
        Desired attributes should be a flat list of attribute names.
        """
        self._ensure_snapmirror_v2()

        if desired_attributes is not None:
            desired_attributes = {
                'snapmirror-info': {attr: None for attr in desired_attributes},
            }

        result = self._get_snapmirrors(
            source_vserver=source_vserver,
            source_volume=source_volume,
            destination_vserver=destination_vserver,
            destination_volume=destination_volume,
            desired_attributes=desired_attributes)

        snapmirrors = []

        for snapmirror_info in result:
            snapmirror = {}
            for child in snapmirror_info.get_children():
                name = self._strip_xml_namespace(child.get_name())
                snapmirror[name] = child.get_content()
            snapmirrors.append(snapmirror)

        return snapmirrors

    def volume_has_snapmirror_relationships(self, volume):
        """Return True if snapmirror relationships exist for a given volume.

        If we have snapmirror control plane license, we can verify whether
        the given volume is part of any snapmirror relationships.
        """
        try:
            # Check if volume is a source snapmirror volume
            snapmirrors = self.get_snapmirrors(
                volume['owning-vserver-name'], volume['name'], None, None)
            # Check if volume is a destination snapmirror volume
            if not snapmirrors:
                snapmirrors = self.get_snapmirrors(
                    None, None, volume['owning-vserver-name'], volume['name'])

            has_snapmirrors = len(snapmirrors) > 0
        except netapp_api.NaApiError:
            msg = ("Could not determine if volume %s is part of "
                   "existing snapmirror relationships.")
            LOG.exception(msg, volume['name'])
            has_snapmirrors = False

        return has_snapmirrors

    def list_snapmirror_snapshots(self, volume_name, newer_than=None):
        """Gets SnapMirror snapshots on a volume."""
        api_args = {
            'query': {
                'snapshot-info': {
                    'dependency': 'snapmirror',
                    'volume': volume_name,
                },
            },
        }
        if newer_than:
            api_args['query']['snapshot-info'][
                'access-time'] = '>' + newer_than

        result = self.send_iter_request('snapshot-get-iter', api_args)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')

        return [snapshot_info.get_child_content('name')
                for snapshot_info in attributes_list.get_children()]

    @na_utils.trace
    def start_volume_move(self, volume_name, vserver, destination_aggregate,
                          cutover_action='wait', encrypt_destination=None):
        """Moves a FlexVol across Vserver aggregates.

        Requires cluster-scoped credentials.
        """
        self._send_volume_move_request(
            volume_name, vserver,
            destination_aggregate,
            cutover_action=cutover_action,
            encrypt_destination=encrypt_destination)

    @na_utils.trace
    def check_volume_move(self, volume_name, vserver, destination_aggregate,
                          encrypt_destination=None):
        """Moves a FlexVol across Vserver aggregates.

        Requires cluster-scoped credentials.
        """
        self._send_volume_move_request(
            volume_name,
            vserver,
            destination_aggregate,
            validation_only=True,
            encrypt_destination=encrypt_destination)

    @na_utils.trace
    def _send_volume_move_request(self, volume_name, vserver,
                                  destination_aggregate,
                                  cutover_action='wait',
                                  validation_only=False,
                                  encrypt_destination=None):
        """Send request to check if vol move is possible, or start it.

        :param volume_name: Name of the FlexVol to be moved.
        :param destination_aggregate: Name of the destination aggregate
        :param cutover_action: can have one of ['force', 'defer', 'abort',
            'wait']. 'force' will force a cutover despite errors (causing
            possible client disruptions), 'wait' will wait for cutover to be
            triggered manually. 'abort' will rollback move on errors on
            cutover, 'defer' will attempt a cutover, but wait for manual
            intervention in case of errors.
        :param validation_only: If set to True, only validates if the volume
            move is possible, does not trigger data copy.
        :param encrypt_destination: If set to True, it encrypts the Flexvol
            after the volume move is complete.
        """
        api_args = {
            'source-volume': volume_name,
            'vserver': vserver,
            'dest-aggr': destination_aggregate,
            'cutover-action': CUTOVER_ACTION_MAP[cutover_action],
        }

        if self.features.FLEXVOL_ENCRYPTION and encrypt_destination:
            api_args['encrypt-destination'] = 'true'
        elif encrypt_destination:
            msg = 'Flexvol encryption is not supported on this backend.'
            raise exception.NetAppException(msg)
        else:
            api_args['encrypt-destination'] = 'false'

        if validation_only:
            api_args['perform-validation-only'] = 'true'
        self.send_request('volume-move-start', api_args)

    @na_utils.trace
    def abort_volume_move(self, volume_name, vserver):
        """Aborts an existing volume move operation."""
        api_args = {
            'source-volume': volume_name,
            'vserver': vserver,
        }
        self.send_request('volume-move-trigger-abort', api_args)

    @na_utils.trace
    def trigger_volume_move_cutover(self, volume_name, vserver, force=True):
        """Triggers the cut-over for a volume in data motion."""
        api_args = {
            'source-volume': volume_name,
            'vserver': vserver,
            'force': 'true' if force else 'false',
        }
        self.send_request('volume-move-trigger-cutover', api_args)

    @na_utils.trace
    def get_volume_move_status(self, volume_name, vserver):
        """Gets the current state of a volume move operation."""
        api_args = {
            'query': {
                'volume-move-info': {
                    'volume': volume_name,
                    'vserver': vserver,
                },
            },
            'desired-attributes': {
                'volume-move-info': {
                    'percent-complete': None,
                    'estimated-completion-time': None,
                    'state': None,
                    'details': None,
                    'cutover-action': None,
                    'phase': None,
                },
            },
        }
        result = self.send_iter_request('volume-move-get-iter', api_args)

        if not self._has_records(result):
            msg = _("Volume %(vol)s in Vserver %(server)s is not part of any "
                    "data motion operations.")
            msg_args = {'vol': volume_name, 'server': vserver}
            raise exception.NetAppException(msg % msg_args)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        volume_move_info = attributes_list.get_child_by_name(
            'volume-move-info') or netapp_api.NaElement('none')

        status_info = {
            'percent-complete': volume_move_info.get_child_content(
                'percent-complete'),
            'estimated-completion-time': volume_move_info.get_child_content(
                'estimated-completion-time'),
            'state': volume_move_info.get_child_content('state'),
            'details': volume_move_info.get_child_content('details'),
            'cutover-action': volume_move_info.get_child_content(
                'cutover-action'),
            'phase': volume_move_info.get_child_content('phase'),
        }
        return status_info

    @na_utils.trace
    def qos_policy_group_exists(self, qos_policy_group_name):
        """Checks if a QoS policy group exists."""
        try:
            self.qos_policy_group_get(qos_policy_group_name)
        except exception.NetAppException:
            return False
        return True

    @na_utils.trace
    def qos_policy_group_get(self, qos_policy_group_name):
        """Checks if a QoS policy group exists."""
        api_args = {
            'query': {
                'qos-policy-group-info': {
                    'policy-group': qos_policy_group_name,
                },
            },
            'desired-attributes': {
                'qos-policy-group-info': {
                    'policy-group': None,
                    'vserver': None,
                    'max-throughput': None,
                    'num-workloads': None
                },
            },
        }

        try:
            result = self.send_request('qos-policy-group-get-iter',
                                       api_args,
                                       False)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EAPINOTFOUND:
                msg = _("Configured ONTAP login user cannot retrieve "
                        "QoS policies.")
                LOG.error(msg)
                raise exception.NetAppException(msg)
            else:
                raise
        if not self._has_records(result):
            msg = _("No QoS policy group found with name %s.")
            raise exception.NetAppException(msg % qos_policy_group_name)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')

        qos_policy_group_info = attributes_list.get_child_by_name(
            'qos-policy-group-info') or netapp_api.NaElement('none')

        policy_info = {
            'policy-group': qos_policy_group_info.get_child_content(
                'policy-group'),
            'vserver': qos_policy_group_info.get_child_content('vserver'),
            'max-throughput': qos_policy_group_info.get_child_content(
                'max-throughput'),
            'num-workloads': int(qos_policy_group_info.get_child_content(
                'num-workloads')),
        }
        return policy_info

    @na_utils.trace
    def qos_policy_group_create(self, qos_policy_group_name, vserver,
                                max_throughput=None):
        """Creates a QoS policy group."""
        api_args = {
            'policy-group': qos_policy_group_name,
            'vserver': vserver,
        }
        if max_throughput:
            api_args['max-throughput'] = max_throughput
        return self.send_request('qos-policy-group-create', api_args, False)

    @na_utils.trace
    def qos_policy_group_modify(self, qos_policy_group_name, max_throughput):
        """Modifies a QoS policy group."""
        api_args = {
            'policy-group': qos_policy_group_name,
            'max-throughput': max_throughput,
        }
        return self.send_request('qos-policy-group-modify', api_args, False)

    @na_utils.trace
    def qos_policy_group_delete(self, qos_policy_group_name):
        """Attempts to delete a QoS policy group."""
        api_args = {'policy-group': qos_policy_group_name}
        return self.send_request('qos-policy-group-delete', api_args, False)

    @na_utils.trace
    def qos_policy_group_rename(self, qos_policy_group_name, new_name):
        """Renames a QoS policy group."""
        api_args = {
            'policy-group-name': qos_policy_group_name,
            'new-name': new_name,
        }
        return self.send_request('qos-policy-group-rename', api_args, False)

    @na_utils.trace
    def mark_qos_policy_group_for_deletion(self, qos_policy_group_name):
        """Soft delete backing QoS policy group for a manila share."""
        # NOTE(gouthamr): ONTAP deletes storage objects asynchronously. As
        # long as garbage collection hasn't occurred, assigned QoS policy may
        # still be tagged "in use". So, we rename the QoS policy group using a
        # specific pattern and later attempt on a best effort basis to
        # delete any QoS policy groups matching that pattern.

        if self.qos_policy_group_exists(qos_policy_group_name):
            new_name = DELETED_PREFIX + qos_policy_group_name
            try:
                self.qos_policy_group_rename(qos_policy_group_name, new_name)
            except netapp_api.NaApiError as ex:
                msg = ('Rename failure in cleanup of cDOT QoS policy '
                       'group %(name)s: %(ex)s')
                msg_args = {'name': qos_policy_group_name, 'ex': ex}
                LOG.warning(msg, msg_args)
            # Attempt to delete any QoS policies named "deleted_manila-*".
            self.remove_unused_qos_policy_groups()

    @na_utils.trace
    def remove_unused_qos_policy_groups(self):
        """Deletes all QoS policy groups that are marked for deletion."""
        api_args = {
            'query': {
                'qos-policy-group-info': {
                    'policy-group': '%s*' % DELETED_PREFIX,
                }
            },
            'max-records': 3500,
            'continue-on-failure': 'true',
            'return-success-list': 'false',
            'return-failure-list': 'false',
        }

        try:
            self.send_request('qos-policy-group-delete-iter', api_args, False)
        except netapp_api.NaApiError as ex:
            msg = 'Could not delete QoS policy groups. Details: %(ex)s'
            msg_args = {'ex': ex}
            LOG.debug(msg, msg_args)

    @na_utils.trace
    def get_net_options(self):
        result = self.send_request('net-options-get', None, False)
        options = result.get_child_by_name('net-options')
        ipv6_enabled = False
        ipv6_info = options.get_child_by_name('ipv6-options-info')
        if ipv6_info:
            ipv6_enabled = ipv6_info.get_child_content('enabled') == 'true'
        return {
            'ipv6-enabled': ipv6_enabled,
        }
