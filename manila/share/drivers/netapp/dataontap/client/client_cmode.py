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
from oslo_utils import uuidutils

from manila import exception
from manila.i18n import _
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_base
from manila.share.drivers.netapp import utils as na_utils
from manila import utils as manila_utils


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
        ontapi_1_120 = ontapi_version >= (1, 120)
        ontapi_1_140 = ontapi_version >= (1, 140)
        ontapi_1_150 = ontapi_version >= (1, 150)
        ontapi_1_180 = ontapi_version >= (1, 180)
        ontapi_1_191 = ontapi_version >= (1, 191)
        ontap_9_10 = self.get_system_version()['version-tuple'] >= (9, 10, 0)

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
        self.features.add_feature('KERBEROS_VSERVER', supported=ontapi_1_30)
        self.features.add_feature('FLEXVOL_ENCRYPTION', supported=ontapi_1_110)
        self.features.add_feature('SVM_DR', supported=ontapi_1_140)
        self.features.add_feature('ADAPTIVE_QOS', supported=ontapi_1_140)
        self.features.add_feature('TRANSFER_LIMIT_NFS_CONFIG',
                                  supported=ontapi_1_140)
        self.features.add_feature('CIFS_DC_ADD_SKIP_CHECK',
                                  supported=ontapi_1_150)
        self.features.add_feature('LDAP_LDAP_SERVERS',
                                  supported=ontapi_1_120)
        self.features.add_feature('FLEXGROUP', supported=ontapi_1_180)
        self.features.add_feature('FLEXGROUP_FAN_OUT', supported=ontapi_1_191)
        self.features.add_feature('SVM_MIGRATE', supported=ontap_9_10)

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
                          max_page_length=DEFAULT_MAX_PAGE_LENGTH,
                          enable_tunneling=True):
        """Invoke an iterator-style getter API."""

        if not api_args:
            api_args = {}

        api_args['max-records'] = max_page_length

        # Get first page
        result = self.send_request(api_name, api_args,
                                   enable_tunneling=enable_tunneling)

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
            next_result = self.send_request(api_name, next_api_args,
                                            enable_tunneling=enable_tunneling)

            next_attributes_list = next_result.get_child_by_name(
                'attributes-list') or netapp_api.NaElement('none')

            for record in next_attributes_list.get_children():
                attributes_list.add_child_elem(record)

            num_records += self._get_record_count(next_result)
            next_tag = next_result.get_child_content('next-tag')

        result.get_child_by_name('num-records').set_content(
            str(num_records))
        result.get_child_by_name('next-tag').set_content('')
        return result

    @na_utils.trace
    def create_vserver(self, vserver_name, root_volume_aggregate_name,
                       root_volume_name, aggregate_names, ipspace_name,
                       security_cert_expire_days):
        """Creates new vserver and assigns aggregates."""
        self._create_vserver(
            vserver_name, aggregate_names, ipspace_name,
            root_volume_name=root_volume_name,
            root_volume_aggregate_name=root_volume_aggregate_name,
            root_volume_security_style='unix',
            name_server_switch='file')
        self._modify_security_cert(vserver_name, security_cert_expire_days)

    @na_utils.trace
    def create_vserver_dp_destination(self, vserver_name, aggregate_names,
                                      ipspace_name):
        """Creates new 'dp_destination' vserver and assigns aggregates."""
        self._create_vserver(
            vserver_name, aggregate_names, ipspace_name,
            subtype='dp_destination')

    @na_utils.trace
    def _create_vserver(self, vserver_name, aggregate_names, ipspace_name,
                        root_volume_name=None, root_volume_aggregate_name=None,
                        root_volume_security_style=None,
                        name_server_switch=None, subtype=None):
        """Creates new vserver and assigns aggregates."""
        create_args = {
            'vserver-name': vserver_name,
        }
        if root_volume_name:
            create_args['root-volume'] = root_volume_name
        if root_volume_aggregate_name:
            create_args['root-volume-aggregate'] = root_volume_aggregate_name
        if root_volume_security_style:
            create_args['root-volume-security-style'] = (
                root_volume_security_style)
        if name_server_switch:
            create_args['name-server-switch'] = {
                'nsswitch': name_server_switch}
        if subtype:
            create_args['vserver-subtype'] = subtype

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
    def _modify_security_cert(self, vserver_name, security_cert_expire_days):
        """Create new security certificate with given expire days."""

        # Do not modify security certificate if specified expire days are
        # equal to default security certificate expire days i.e. 365.
        if security_cert_expire_days == 365:
            return

        api_args = {
            'query': {
                'certificate-info': {
                    'vserver': vserver_name,
                    'common-name': vserver_name,
                    'certificate-authority': vserver_name,
                    'type': 'server',
                },
            },
            'desired-attributes': {
                'certificate-info': {
                    'serial-number': None,
                },
            },
        }
        result = self.send_iter_request('security-certificate-get-iter',
                                        api_args)
        try:
            old_certificate_info_list = result.get_child_by_name(
                'attributes-list')
        except AttributeError:
            LOG.warning('Could not retrieve certificate-info for vserver '
                        '%(server)s.', {'server': vserver_name})
            return

        old_serial_nums = []
        for certificate_info in old_certificate_info_list.get_children():
            serial_num = certificate_info.get_child_content('serial-number')
            old_serial_nums.append(serial_num)

        try:
            create_args = {
                'vserver': vserver_name,
                'common-name': vserver_name,
                'type': 'server',
                'expire-days': security_cert_expire_days,
            }
            self.send_request('security-certificate-create', create_args)
        except netapp_api.NaApiError as e:
            LOG.warning("Failed to create new security certificate: %s - %s",
                        e.code, e.message)
            return

        api_args = {
            'query': {
                'certificate-info': {
                    'vserver': vserver_name,
                    'common-name': vserver_name,
                    'certificate-authority': vserver_name,
                    'type': 'server',
                },
            },
            'desired-attributes': {
                'certificate-info': {
                    'serial-number': None,
                },
            },
        }

        result = self.send_iter_request('security-certificate-get-iter',
                                        api_args)
        try:
            new_certificate_info_list = result.get_child_by_name(
                'attributes-list')
        except AttributeError:
            LOG.warning('Could not retrieve certificate-info for vserver '
                        '%(server)s.', {'server': vserver_name})
            return

        for certificate_info in new_certificate_info_list.get_children():
            serial_num = certificate_info.get_child_content('serial-number')
            if serial_num not in old_serial_nums:
                try:
                    ssl_modify_args = {
                        'certificate-authority': vserver_name,
                        'common-name': vserver_name,
                        'certificate-serial-number': serial_num,
                        'vserver': vserver_name,
                        'client-authentication-enabled': 'false',
                        'server-authentication-enabled': 'true',
                    }
                    self.send_request('security-ssl-modify', ssl_modify_args)
                except netapp_api.NaApiError as e:
                    LOG.debug('Failed to modify SSL for security certificate '
                              'with serial number %s: %s - %s', serial_num,
                              e.code, e.message)

        # Delete all old security certificates
        for certificate_info in old_certificate_info_list.get_children():
            serial_num = certificate_info.get_child_content('serial-number')
            delete_args = {
                'certificate-authority': vserver_name,
                'common-name': vserver_name,
                'serial-number': serial_num,
                'type': 'server',
                'vserver': vserver_name,
            }
            try:
                self.send_request('security-certificate-delete', delete_args)
            except netapp_api.NaApiError as e:
                LOG.warning('Failed to delete security certificate with '
                            'serial number %s: %s - %s', serial_num, e.code,
                            e.message)

    @na_utils.trace
    def get_vserver_info(self, vserver_name):
        """Retrieves Vserver info."""
        LOG.debug('Retrieving Vserver %s information.', vserver_name)

        api_args = {
            'query': {
                'vserver-info': {
                    'vserver-name': vserver_name,
                },
            },
            'desired-attributes': {
                'vserver-info': {
                    'vserver-name': None,
                    'vserver-subtype': None,
                    'state': None,
                    'operational-state': None,
                },
            },
        }
        result = self.send_iter_request('vserver-get-iter', api_args)
        if not self._has_records(result):
            return
        try:
            vserver_info = result.get_child_by_name(
                'attributes-list').get_child_by_name(
                'vserver-info')
            vserver_subtype = vserver_info.get_child_content(
                'vserver-subtype')
            vserver_op_state = vserver_info.get_child_content(
                'operational-state')
            vserver_state = vserver_info.get_child_content('state')
        except AttributeError:
            msg = _('Could not retrieve vserver-info for %s.') % vserver_name
            raise exception.NetAppException(msg)

        vserver_info = {
            'name': vserver_name,
            'subtype': vserver_subtype,
            'operational_state': vserver_op_state,
            'state': vserver_state,
        }
        return vserver_info

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
        try:
            result = self.send_iter_request('vserver-get-iter', api_args,
                                            enable_tunneling=False)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EVSERVERNOTFOUND:
                return False
            else:
                raise
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
        """Deletes a Vserver.

        Checks if Vserver exists and does not have active shares.
        Offlines and destroys root volumes.  Deletes Vserver.
        """
        vserver_info = self.get_vserver_info(vserver_name)
        if vserver_info is None:
            LOG.error("Vserver %s does not exist.", vserver_name)
            return

        is_dp_destination = vserver_info.get('subtype') == 'dp_destination'
        root_volume_name = self.get_vserver_root_volume_name(vserver_name)
        volumes_count = vserver_client.get_vserver_volume_count()

        # NOTE(dviroel): 'dp_destination' vservers don't allow to delete its
        # root volume. We can just call vserver-destroy directly.
        if volumes_count == 1 and not is_dp_destination:
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

        if security_services and not is_dp_destination:
            self._terminate_vserver_services(vserver_name, vserver_client,
                                             security_services)

        self.send_request('vserver-destroy', {'vserver-name': vserver_name})

    @na_utils.trace
    def _terminate_vserver_services(self, vserver_name, vserver_client,
                                    security_services):
        for service in security_services:
            if service['type'].lower() == 'active_directory':
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
                        LOG.debug('Retrying CIFS server delete with force flag'
                                  ' for Vserver %s.', vserver_name)
                        api_args = {
                            'force-account-delete': 'true'
                        }
                        vserver_client.send_request('cifs-server-delete',
                                                    api_args)
            elif service['type'].lower() == 'kerberos':
                vserver_client.disable_kerberos(service)

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
            if not (value and isinstance(value, str)):
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
    def create_port_and_broadcast_domain(self, node, port, vlan, mtu, ipspace):
        home_port_name = port
        if vlan:
            self._create_vlan(node, port, vlan)
            home_port_name = '%(port)s-%(tag)s' % {'port': port, 'tag': vlan}

        if self.features.BROADCAST_DOMAINS:
            self._ensure_broadcast_domain_for_port(
                node, home_port_name, mtu, ipspace=ipspace)

        return home_port_name

    @na_utils.trace
    def create_network_interface(self, ip, netmask, node, port,
                                 vserver_name, lif_name):
        """Creates LIF on VLAN port."""
        LOG.debug('Creating LIF %(lif)s for Vserver %(vserver)s '
                  'node/port %(node)s:%(port)s.',
                  {'lif': lif_name, 'vserver': vserver_name, 'node': node,
                   'port': port})

        api_args = {
            'address': ip,
            'administrative-status': 'up',
            'data-protocols': [
                {'data-protocol': 'nfs'},
                {'data-protocol': 'cifs'},
            ],
            'home-node': node,
            'home-port': port,
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
                                 vlan=None, home_port=None):
        """Checks if LIF exists."""
        if not home_port:
            home_port = port if not vlan else f'{port}-{vlan}'

        api_args = {
            'query': {
                'net-interface-info': {
                    'address': ip,
                    'home-node': node,
                    'home-port': home_port,
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
    def disable_network_interface(self, vserver_name, interface_name):
        api_args = {
            'administrative-status': 'down',
            'interface-name': interface_name,
            'vserver': vserver_name,
        }
        self.send_request('net-interface-modify', api_args)

    @na_utils.trace
    def delete_network_interface(self, vserver_name, interface_name):
        self.disable_network_interface(vserver_name, interface_name)
        api_args = {
            'interface-name': interface_name,
            'vserver': vserver_name
        }
        self.send_request('net-interface-delete', api_args)

    @na_utils.trace
    def get_ipspace_name_for_vlan_port(self, vlan_node, vlan_port, vlan_id):
        """Gets IPSpace name for specified VLAN"""

        if not self.features.IPSPACES:
            return None

        port = vlan_port if not vlan_id else '%(port)s-%(id)s' % {
            'port': vlan_port,
            'id': vlan_id,
        }
        api_args = {'node': vlan_node, 'port': port}

        try:
            result = self.send_request('net-port-get', api_args)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EOBJECTNOTFOUND:
                msg = _('No pre-existing port or ipspace was found for '
                        '%(port)s, will attempt to create one.')
                msg_args = {'port': port}
                LOG.debug(msg, msg_args)
                return None
            else:
                raise

        attributes = result.get_child_by_name('attributes')
        net_port_info = attributes.get_child_by_name('net-port-info')
        ipspace_name = net_port_info.get_child_content('ipspace')

        return ipspace_name

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
                                vserver_name, timeout=30):
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
                vserver_client.configure_ldap(security_service,
                                              timeout=timeout)

            elif security_service['type'].lower() == 'active_directory':
                vserver_client.configure_active_directory(security_service,
                                                          vserver_name)
                vserver_client.configure_cifs_options(security_service)

            elif security_service['type'].lower() == 'kerberos':
                vserver_client.create_kerberos_realm(security_service)
                vserver_client.configure_kerberos(security_service,
                                                  vserver_name)

            else:
                msg = _('Unsupported security service type %s for '
                        'Data ONTAP driver')
                raise exception.NetAppException(msg % security_service['type'])

    @na_utils.trace
    def enable_nfs(self, versions, nfs_config=None):
        """Enables NFS on Vserver."""
        self.send_request('nfs-enable')
        self._enable_nfs_protocols(versions)

        if nfs_config:
            self._configure_nfs(nfs_config)

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
            'showmount': 'true',
            'is-v3-ms-dos-client-enabled': 'true',
            'is-nfsv3-connection-drop-enabled': 'false',
            'enable-ejukebox': 'false',
        }
        self.send_request('nfs-service-modify', nfs_service_modify_args)

    @na_utils.trace
    def _configure_nfs(self, nfs_config):
        """Sets the nfs configuraton"""
        self.send_request('nfs-service-modify', nfs_config)

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
    def _create_ldap_client(self, security_service):
        ad_domain = security_service.get('domain')
        ldap_servers = security_service.get('server')
        bind_dn = security_service.get('user')
        ldap_schema = 'RFC-2307'

        if ad_domain:
            if ldap_servers:
                msg = _("LDAP client cannot be configured with both 'server' "
                        "and 'domain' parameters. Use 'server' for Linux/Unix "
                        "LDAP servers or 'domain' for Active Directory LDAP "
                        "servers.")
                LOG.exception(msg)
                raise exception.NetAppException(msg)
            # RFC2307bis, for MS Active Directory LDAP server
            ldap_schema = 'MS-AD-BIS'
            bind_dn = (security_service.get('user') + '@' + ad_domain)
        else:
            if not ldap_servers:
                msg = _("LDAP client cannot be configured without 'server' "
                        "or 'domain' parameters. Use 'server' for Linux/Unix "
                        "LDAP servers or 'domain' for Active Directory LDAP "
                        "server.")
                LOG.exception(msg)
                raise exception.NetAppException(msg)

        if security_service.get('dns_ip'):
            self.configure_dns(security_service)

        config_name = hashlib.md5(
            security_service['id'].encode("latin-1")).hexdigest()
        api_args = {
            'ldap-client-config': config_name,
            'tcp-port': '389',
            'schema': ldap_schema,
            'bind-dn': bind_dn,
            'bind-password': security_service.get('password'),
        }

        if security_service.get('ou'):
            api_args['base-dn'] = security_service['ou']
        if ad_domain:
            # Active Directory LDAP server
            api_args['ad-domain'] = ad_domain
        else:
            # Linux/Unix LDAP servers
            if self.features.LDAP_LDAP_SERVERS:
                servers_key, servers_key_type = 'ldap-servers', 'string'
            else:
                servers_key, servers_key_type = 'servers', 'ip-address'

            api_args[servers_key] = []
            for server in ldap_servers.split(','):
                api_args[servers_key].append(
                    {servers_key_type: server.strip()})

        self.send_request('ldap-client-create', api_args)

    @na_utils.trace
    def _enable_ldap_client(self, client_config_name, timeout=30):
        # ONTAP ldap query timeout is 3 seconds by default
        interval = 3
        retries = int(timeout / interval) or 1
        api_args = {'client-config': client_config_name,
                    'client-enabled': 'true'}

        @manila_utils.retry(retry_param=exception.ShareBackendException,
                            interval=interval,
                            retries=retries,
                            backoff_rate=1)
        def try_enable_ldap_client():
            try:
                self.send_request('ldap-config-create', api_args)
            except netapp_api.NaApiError as e:
                msg = _('Unable to enable ldap client configuration. Will '
                        'retry the operation. Error details: %s') % e.message
                LOG.warning(msg)
                raise exception.ShareBackendException(msg=msg)

        try:
            try_enable_ldap_client()
        except exception.ShareBackendException:
            msg = _("Unable to enable ldap client configuration %s. "
                    "Retries exhausted. Aborting.") % client_config_name
            LOG.exception(msg)
            raise exception.NetAppException(message=msg)

    @na_utils.trace
    def _delete_ldap_client(self, security_service):
        config_name = (
            hashlib.md5(security_service['id'].encode("latin-1")).hexdigest())
        api_args = {'ldap-client-config': config_name}
        self.send_request('ldap-client-delete', api_args)

    @na_utils.trace
    def configure_ldap(self, security_service, timeout=30):
        """Configures LDAP on Vserver."""
        config_name = hashlib.md5(
            security_service['id'].encode("latin-1")).hexdigest()
        self._create_ldap_client(security_service)
        self._enable_ldap_client(config_name, timeout=timeout)

    @na_utils.trace
    def modify_ldap(self, new_security_service, current_security_service):
        """Modifies LDAP client on a Vserver."""
        # Create a new ldap client
        self._create_ldap_client(new_security_service)

        # Delete current ldap config
        try:
            self.send_request('ldap-config-delete')
        except netapp_api.NaApiError as e:
            if e.code != netapp_api.EOBJECTNOTFOUND:
                # Delete previously created ldap client
                self._delete_ldap_client(new_security_service)

                msg = _("An error occurred while deleting original LDAP "
                        "configuration. %s")
                raise exception.NetAppException(msg % e.message)
            else:
                msg = _("Original LDAP configuration was not found. "
                        "LDAP modification will continue.")
                LOG.debug(msg)

        new_config_name = (
            hashlib.md5(
                new_security_service['id'].encode("latin-1")).hexdigest())
        # Create ldap config with the new client
        api_args = {'client-config': new_config_name, 'client-enabled': 'true'}
        self.send_request('ldap-config-create', api_args)

        # Delete old client configuration
        try:
            self._delete_ldap_client(current_security_service)
        except netapp_api.NaApiError as e:
            if e.code != netapp_api.EOBJECTNOTFOUND:
                current_config_name = (
                    hashlib.md5(
                        current_security_service['id'].encode(
                            "latin-1")).hexdigest())
                msg = _("An error occurred while deleting original LDAP "
                        "client configuration %(current_config)s. "
                        "Error details: %(e_msg)s")
                msg_args = {
                    'current_config': current_config_name,
                    'e_msg': e.message,
                }
                LOG.warning(msg, msg_args)
            else:
                msg = _("Original LDAP client configuration was not found.")
                LOG.debug(msg)

    @na_utils.trace
    def _get_cifs_server_name(self, vserver_name):
        # 'cifs-server' is CIFS Server NetBIOS Name, max length is 15.
        # Should be unique within each domain (data['domain']).
        # Cut to 15 char with begin and end, attempt to make valid DNS hostname
        cifs_server = (vserver_name[0:8] +
                       '-' +
                       vserver_name[-6:]).replace('_', '-').upper()
        return cifs_server

    @na_utils.trace
    def configure_active_directory(self, security_service, vserver_name):
        """Configures AD on Vserver."""
        self.configure_dns(security_service)
        self.set_preferred_dc(security_service)

        cifs_server = self._get_cifs_server_name(vserver_name)

        api_args = {
            'admin-username': security_service['user'],
            'admin-password': security_service['password'],
            'force-account-overwrite': 'true',
            'cifs-server': cifs_server,
            'domain': security_service['domain'],
        }

        if security_service['ou'] is not None:
            api_args['organizational-unit'] = security_service['ou']
        if security_service.get('default_ad_site'):
            api_args['default-site'] = security_service['default_ad_site']

        try:
            LOG.debug("Trying to setup CIFS server with data: %s", api_args)
            self.send_request('cifs-server-create', api_args)
        except netapp_api.NaApiError as e:
            msg = _("Failed to create CIFS server entry. %s")
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def modify_active_directory_security_service(
            self, vserver_name, differring_keys, new_security_service,
            current_security_service):
        cifs_server = self._get_cifs_server_name(vserver_name)

        current_user_name = current_security_service['user']
        new_username = new_security_service['user']

        current_cifs_username = cifs_server + '\\' + current_user_name

        if 'password' in differring_keys:
            api_args = {
                'user-name': current_cifs_username,
                'user-password': new_security_service['password']
            }
            try:
                self.send_request('cifs-local-user-set-password', api_args)
            except netapp_api.NaApiError as e:
                msg = _("Failed to modify existing CIFS server password. %s")
                raise exception.NetAppException(msg % e.message)

        if 'user' in differring_keys:
            api_args = {
                'user-name': current_cifs_username,
                'new-user-name': new_username
            }
            try:
                self.send_request('cifs-local-user-rename', api_args)
            except netapp_api.NaApiError as e:
                msg = _("Failed to modify existing CIFS server user-name. %s")
                raise exception.NetAppException(msg % e.message)

        if 'default_ad_site' in differring_keys:
            if new_security_service['default_ad_site'] is not None:
                cifs_server = self._get_cifs_server_name(vserver_name)
                api_args = {
                    'admin-username': new_security_service['user'],
                    'admin-password': new_security_service['password'],
                    'force-account-overwrite': 'true',
                    'cifs-server': cifs_server,
                    'default-site': new_security_service['default_ad_site']
                }
                try:
                    LOG.debug("Trying to modify CIFS server with data: %s",
                              api_args)
                    self.send_request('cifs-server-modify', api_args)
                except netapp_api.NaApiError as e:
                    msg = _("Failed to modify CIFS server entry. %s")
                    raise exception.NetAppException(msg % e.message)
                self.configure_cifs_options(new_security_service)

        if 'server' in differring_keys:
            if current_security_service['server'] is not None:
                self.remove_preferred_dcs(current_security_service)

            if new_security_service['server'] is not None:
                self.set_preferred_dc(new_security_service)
                self.configure_cifs_options(new_security_service)

    @na_utils.trace
    def create_kerberos_realm(self, security_service):
        """Creates Kerberos realm on cluster."""

        if not self.features.KERBEROS_VSERVER:
            msg = _('Kerberos realms owned by Vserver are supported on ONTAP '
                    '8.3 or later.')
            raise exception.NetAppException(msg)

        api_args = {
            'admin-server-ip': security_service['server'],
            'admin-server-port': '749',
            'clock-skew': '5',
            'comment': '',
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

        if not self.features.KERBEROS_VSERVER:
            msg = _('Kerberos realms owned by Vserver are supported on ONTAP '
                    '8.3 or later.')
            raise exception.NetAppException(msg)

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
                'service-principal-name': spn
            }

            self.send_request('kerberos-config-modify', api_args)

    @na_utils.trace
    def _get_kerberos_service_principal_name(self, security_service,
                                             vserver_name):
        return ('nfs/' + vserver_name.replace('_', '-') + '.' +
                security_service['domain'] + '@' +
                security_service['domain'].upper())

    @na_utils.trace
    def update_kerberos_realm(self, security_service):
        """Update Kerberos realm info. Only KDC IP can be changed."""
        if not self.features.KERBEROS_VSERVER:
            msg = _('Kerberos realms owned by Vserver are supported on ONTAP '
                    '8.3 or later.')
            raise exception.NetAppException(msg)

        api_args = {
            'admin-server-ip': security_service['server'],
            'kdc-ip': security_service['server'],
            'password-server-ip': security_service['server'],
            'realm': security_service['domain'].upper(),
        }
        try:
            self.send_request('kerberos-realm-modify', api_args)
        except netapp_api.NaApiError as e:
            msg = _('Failed to update Kerberos realm. %s')
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def disable_kerberos(self, security_service):
        """Disable Kerberos in all Vserver LIFs."""

        lifs = self.list_network_interfaces()
        # NOTE(dviroel): If the Vserver has no LIFs, there are no Kerberos
        # to be disabled.
        for lif_name in lifs:
            api_args = {
                'admin-password': security_service['password'],
                'admin-user-name': security_service['user'],
                'interface-name': lif_name,
                'is-kerberos-enabled': 'false',
            }
            try:
                self.send_request('kerberos-config-modify', api_args)
            except netapp_api.NaApiError as e:
                disabled_msg = "Kerberos is already disabled"
                if (e.code == netapp_api.EAPIERROR and
                        disabled_msg in e.message):
                    # NOTE(dviroel): do not raise an error for 'Kerberos is
                    # already disabled in this LIF'.
                    continue
                msg = _("Failed to disable Kerberos: %s.")
                raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def is_kerberos_enabled(self):
        """Check if Kerberos in enabled in all LIFs."""

        if not self.features.KERBEROS_VSERVER:
            msg = _('Kerberos realms owned by Vserver are supported on ONTAP '
                    '8.3 or later.')
            raise exception.NetAppException(msg)

        lifs = self.list_network_interfaces()
        if not lifs:
            LOG.debug("There are no LIFs configured for this Vserver. "
                      "Kerberos is disabled.")
            return False

        # NOTE(dviroel): All LIFs must have kerberos enabled
        for lif in lifs:
            api_args = {
                'interface-name': lif,
                'desired-attributes': {
                    'kerberos-config-info': {
                        'is-kerberos-enabled': None,
                    }
                }
            }
            result = self.send_request('kerberos-config-get', api_args)

            attributes = result.get_child_by_name('attributes')
            kerberos_info = attributes.get_child_by_name(
                'kerberos-config-info')
            kerberos_enabled = kerberos_info.get_child_content(
                'is-kerberos-enabled')
            if kerberos_enabled == 'false':
                return False

        return True

    @na_utils.trace
    def configure_dns(self, security_service):
        """Configure DNS address and servers for a vserver."""
        api_args = {
            'domains': [],
            'name-servers': [],
            'dns-state': 'enabled',
        }
        # NOTE(dviroel): Read the current dns configuration and merge with the
        # new one. This scenario is expected when 2 security services provide
        # a DNS configuration, like 'active_directory' and 'ldap'.
        current_dns_config = self.get_dns_config()
        domains = set(current_dns_config.get('domains', []))
        dns_ips = set(current_dns_config.get('dns-ips', []))

        domains.add(security_service['domain'])
        for domain in domains:
            api_args['domains'].append({'string': domain})

        for dns_ip in security_service['dns_ip'].split(','):
            dns_ips.add(dns_ip.strip())
        for dns_ip in dns_ips:
            api_args['name-servers'].append({'ip-address': dns_ip})

        try:
            if current_dns_config:
                self.send_request('net-dns-modify', api_args)
            else:
                self.send_request('net-dns-create', api_args)
        except netapp_api.NaApiError as e:
            msg = _("Failed to configure DNS. %s")
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def get_dns_config(self):
        """Read DNS servers and domains currently configured in the vserver·"""
        api_args = {}
        try:
            result = self.send_request('net-dns-get', api_args)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EOBJECTNOTFOUND:
                return {}
            msg = _("Failed to retrieve DNS configuration. %s")
            raise exception.NetAppException(msg % e.message)

        dns_config = {}
        attributes = result.get_child_by_name('attributes')
        dns_info = attributes.get_child_by_name('net-dns-info')

        dns_config['dns-state'] = dns_info.get_child_content(
            'dns-state')
        domains = dns_info.get_child_by_name(
            'domains') or netapp_api.NaElement('None')
        dns_config['domains'] = [domain.get_content()
                                 for domain in domains.get_children()]

        servers = dns_info.get_child_by_name(
            'name-servers') or netapp_api.NaElement('None')
        dns_config['dns-ips'] = [server.get_content()
                                 for server in servers.get_children()]
        return dns_config

    @na_utils.trace
    def update_dns_configuration(self, dns_ips, domains):
        """Overrides DNS configuration with the specified IPs and domains."""
        current_dns_config = self.get_dns_config()
        api_args = {
            'domains': [],
            'name-servers': [],
            'dns-state': 'enabled',
        }
        for domain in domains:
            api_args['domains'].append({'string': domain})

        for dns_ip in dns_ips:
            api_args['name-servers'].append({'ip-address': dns_ip})

        empty_dns_config = (not api_args['domains'] and
                            not api_args['name-servers'])
        if current_dns_config:
            api_name, api_args = (
                ('net-dns-destroy', {}) if empty_dns_config
                else ('net-dns-modify', api_args))
        else:
            api_name, api_args = 'net-dns-create', api_args

        try:
            self.send_request(api_name, api_args)
        except netapp_api.NaApiError as e:
            msg = _("Failed to update DNS configuration. %s")
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def configure_cifs_options(self, security_service):
        if security_service.get('server'):
            api_args = {'mode': 'none'}
        elif security_service.get('default_ad_site'):
            api_args = {'mode': 'site'}
        else:
            api_args = {'mode': 'all'}

        try:
            self.send_request(
                'cifs-domain-server-discovery-mode-modify',
                api_args)
        except netapp_api.NaApiError as e:
            msg = ('Failed to set cifs domain server discovery mode to '
                   '%(mode)s. Exception: %(exception)s')
            msg_args = {'mode': api_args['mode'], 'exception': e.message}
            LOG.warning(msg, msg_args)

    @na_utils.trace
    def set_preferred_dc(self, security_service):
        # server is optional
        if not security_service['server']:
            return

        api_args = {
            'preferred-dc': [],
            'domain': security_service['domain'],
        }

        for dc_ip in security_service['server'].split(','):
            api_args['preferred-dc'].append({'string': dc_ip.strip()})

        if self.features.CIFS_DC_ADD_SKIP_CHECK:
            api_args['skip-config-validation'] = 'false'

        try:
            self.send_request('cifs-domain-preferred-dc-add', api_args)
        except netapp_api.NaApiError as e:
            msg = _("Failed to set preferred DC. %s")
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def remove_preferred_dcs(self, security_service):
        """Drops all preferred DCs at once."""

        api_args = {
            'domain': security_service['domain'],
        }

        try:
            self.send_request('cifs-domain-preferred-dc-remove', api_args)
        except netapp_api.NaApiError as e:
            msg = _("Failed to unset preferred DCs. %s")
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def create_volume(self, aggregate_name, volume_name, size_gb,
                      thin_provisioned=False, snapshot_policy=None,
                      language=None, dedup_enabled=False,
                      compression_enabled=False, max_files=None,
                      snapshot_reserve=None, volume_type='rw',
                      qos_policy_group=None, adaptive_qos_policy_group=None,
                      encrypt=False, **options):
        """Creates a volume."""
        if adaptive_qos_policy_group and not self.features.ADAPTIVE_QOS:
            msg = 'Adaptive QoS not supported on this backend ONTAP version.'
            raise exception.NetAppException(msg)

        api_args = {
            'containing-aggr-name': aggregate_name,
            'size': str(size_gb) + 'g',
            'volume': volume_name,
        }
        api_args.update(self._get_create_volume_api_args(
            volume_name, thin_provisioned, snapshot_policy, language,
            snapshot_reserve, volume_type, qos_policy_group, encrypt,
            adaptive_qos_policy_group))

        self.send_request('volume-create', api_args)

        self.update_volume_efficiency_attributes(volume_name,
                                                 dedup_enabled,
                                                 compression_enabled)
        if max_files is not None:
            self.set_volume_max_files(volume_name, max_files)

    @na_utils.trace
    def create_volume_async(self, aggregate_list, volume_name, size_gb,
                            thin_provisioned=False, snapshot_policy=None,
                            language=None, snapshot_reserve=None,
                            volume_type='rw', qos_policy_group=None,
                            encrypt=False, adaptive_qos_policy_group=None,
                            auto_provisioned=False, **options):
        """Creates a volume asynchronously."""

        if adaptive_qos_policy_group and not self.features.ADAPTIVE_QOS:
            msg = 'Adaptive QoS not supported on this backend ONTAP version.'
            raise exception.NetAppException(msg)

        api_args = {
            'size': size_gb * units.Gi,
            'volume-name': volume_name,
        }
        if auto_provisioned:
            api_args['auto-provision-as'] = 'flexgroup'
        else:
            api_args['aggr-list'] = [{'aggr-name': aggr}
                                     for aggr in aggregate_list]
        api_args.update(self._get_create_volume_api_args(
            volume_name, thin_provisioned, snapshot_policy, language,
            snapshot_reserve, volume_type, qos_policy_group, encrypt,
            adaptive_qos_policy_group))

        result = self.send_request('volume-create-async', api_args)
        job_info = {
            'jobid': result.get_child_content('result-jobid'),
            'error-code': result.get_child_content('result-error-code'),
            'error-message': result.get_child_content('result-error-message')
        }

        return job_info

    def _get_create_volume_api_args(self, volume_name, thin_provisioned,
                                    snapshot_policy, language,
                                    snapshot_reserve, volume_type,
                                    qos_policy_group, encrypt,
                                    adaptive_qos_policy_group):
        api_args = {
            'volume-type': volume_type,
            'space-reserve': ('none' if thin_provisioned else 'volume'),
        }
        if volume_type != 'dp':
            api_args['junction-path'] = '/%s' % volume_name
        if snapshot_policy is not None:
            api_args['snapshot-policy'] = snapshot_policy
        if language is not None:
            api_args['language-code'] = language
        if snapshot_reserve is not None:
            api_args['percentage-snapshot-reserve'] = str(snapshot_reserve)
        if qos_policy_group is not None:
            api_args['qos-policy-group-name'] = qos_policy_group
        if adaptive_qos_policy_group is not None:
            api_args['qos-adaptive-policy-group-name'] = (
                adaptive_qos_policy_group)

        if encrypt is True:
            if not self.features.FLEXVOL_ENCRYPTION:
                msg = 'Flexvol encryption is not supported on this backend.'
                raise exception.NetAppException(msg)
            else:
                api_args['encrypt'] = 'true'
        else:
            api_args['encrypt'] = 'false'

        return api_args

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
    def enable_dedupe_async(self, volume_name):
        """Enable deduplication on FlexVol/FlexGroup volume asynchronously."""
        api_args = {'volume-name': volume_name}
        self.connection.send_request('sis-enable-async', api_args)

    @na_utils.trace
    def disable_dedupe_async(self, volume_name):
        """Disable deduplication on FlexVol/FlexGroup volume asynchronously."""
        api_args = {'volume-name': volume_name}
        self.connection.send_request('sis-disable-async', api_args)

    @na_utils.trace
    def enable_compression_async(self, volume_name):
        """Enable compression on FlexVol/FlexGroup volume asynchronously."""
        api_args = {
            'volume-name': volume_name,
            'enable-compression': 'true'
        }
        self.connection.send_request('sis-set-config-async', api_args)

    @na_utils.trace
    def disable_compression_async(self, volume_name):
        """Disable compression on FlexVol/FlexGroup volume asynchronously."""
        api_args = {
            'volume-name': volume_name,
            'enable-compression': 'false'
        }
        self.connection.send_request('sis-set-config-async', api_args)

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
        try:
            result = self.send_iter_request('sis-get-iter', api_args)
            attributes_list = result.get_child_by_name(
                'attributes-list') or netapp_api.NaElement('none')
            sis_status_info = attributes_list.get_child_by_name(
                'sis-status-info') or netapp_api.NaElement('none')
        except exception.NetAppException:
            msg = _('Failed to get volume efficiency status for %s.')
            LOG.error(msg, volume_name)
            sis_status_info = netapp_api.NaElement('none')

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
    def set_volume_snapdir_access(self, volume_name, hide_snapdir):
        """Set volume snapshot directory visibility."""
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
                    'volume-snapshot-attributes': {
                        'snapdir-access-enabled': str(
                            not hide_snapdir).lower(),
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
    def set_volume_filesys_size_fixed(self,
                                      volume_name, filesys_size_fixed=False):
        """Set volume file system size fixed to true/false."""
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
                        'is-filesys-size-fixed': str(
                            filesys_size_fixed).lower(),
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
    def rename_vserver(self, vserver_name, new_vserver_name):
        """Rename a vserver."""
        api_args = {
            'vserver-name': vserver_name,
            'new-name': new_vserver_name,
        }
        self.send_request('vserver-rename', api_args)

    @na_utils.trace
    def modify_volume(self, aggregate_name, volume_name,
                      thin_provisioned=False, snapshot_policy=None,
                      language=None, dedup_enabled=False,
                      compression_enabled=False, max_files=None,
                      qos_policy_group=None, hide_snapdir=None,
                      autosize_attributes=None,
                      adaptive_qos_policy_group=None, **options):
        """Update backend volume for a share as necessary.

        :param aggregate_name: either a list or a string. List for aggregate
            names where the FlexGroup resides, while a string for the aggregate
            name where FlexVol volume is.
        :param volume_name: name of the modified volume.
        :param thin_provisioned: volume is thin.
        :param snapshot_policy: policy of volume snapshot.
        :param language: language of the volume.
        :param dedup_enabled: is the deduplication enabled for the volume.
        :param compression_enabled: is the compression enabled for the volume.
        :param max_files: number of maximum files in the volume.
        :param qos_policy_group: name of the QoS policy.
        :param hide_snapdir: hide snapshot directory.
        :param autosize_attributes: autosize for the volume.
        :param adaptive_qos_policy_group: name of the adaptive QoS policy.
        """

        if adaptive_qos_policy_group and not self.features.ADAPTIVE_QOS:
            msg = 'Adaptive QoS not supported on this backend ONTAP version.'
            raise exception.NetAppException(msg)

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
                    'volume-inode-attributes': {},
                    'volume-language-attributes': {},
                    'volume-snapshot-attributes': {},
                    'volume-autosize-attributes': (autosize_attributes
                                                   if autosize_attributes
                                                   else {}),
                    'volume-space-attributes': {
                        'space-guarantee': ('none' if thin_provisioned else
                                            'volume'),
                    },
                },
            },
        }
        if isinstance(aggregate_name, str):
            is_flexgroup = False
            api_args['query']['volume-attributes']['volume-id-attributes'][
                'containing-aggregate-name'] = aggregate_name
        elif isinstance(aggregate_name, list):
            is_flexgroup = True
            aggr_list = [{'aggr-name': aggr_name} for aggr_name in
                         aggregate_name]
            api_args['query']['volume-attributes']['volume-id-attributes'][
                'aggr-list'] = aggr_list
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
        if adaptive_qos_policy_group:
            api_args['attributes']['volume-attributes'][
                'volume-qos-attributes'] = {
                'adaptive-policy-group-name': adaptive_qos_policy_group,
            }
        if hide_snapdir in (True, False):
            # Value of hide_snapdir needs to be inverted for ZAPI parameter
            api_args['attributes']['volume-attributes'][
                'volume-snapshot-attributes'][
                'snapdir-access-enabled'] = str(
                not hide_snapdir).lower()

        self.send_request('volume-modify-iter', api_args)

        # Efficiency options must be handled separately
        self.update_volume_efficiency_attributes(volume_name,
                                                 dedup_enabled,
                                                 compression_enabled,
                                                 is_flexgroup=is_flexgroup)

    @na_utils.trace
    def update_volume_efficiency_attributes(self, volume_name, dedup_enabled,
                                            compression_enabled,
                                            is_flexgroup=False):
        """Update dedupe & compression attributes to match desired values."""
        efficiency_status = self.get_volume_efficiency_status(volume_name)

        # cDOT compression requires dedup to be enabled
        dedup_enabled = dedup_enabled or compression_enabled

        # enable/disable dedup if needed
        if dedup_enabled and not efficiency_status['dedupe']:
            if is_flexgroup:
                self.enable_dedupe_async(volume_name)
            else:
                self.enable_dedup(volume_name)
        elif not dedup_enabled and efficiency_status['dedupe']:
            if is_flexgroup:
                self.disable_dedupe_async(volume_name)
            else:
                self.disable_dedup(volume_name)

        # enable/disable compression if needed
        if compression_enabled and not efficiency_status['compression']:
            if is_flexgroup:
                self.enable_compression_async(volume_name)
            else:
                self.enable_compression(volume_name)
        elif not compression_enabled and efficiency_status['compression']:
            if is_flexgroup:
                self.disable_compression_async(volume_name)
            else:
                self.disable_compression(volume_name)

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
                        'aggr-list': {
                            'aggr-name': None,
                        },
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
            aggr_list_attr = volume_id_attributes.get_child_by_name(
                'aggr-list') or netapp_api.NaElement('none')
            aggregate = [aggr_elem.get_content()
                         for aggr_elem in aggr_list_attr.get_children()]

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
    def volume_has_junctioned_volumes(self, junction_path):
        """Checks if volume has volumes mounted beneath its junction path."""
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
    def get_volume_autosize_attributes(self, volume_name):
        """Returns autosize attributes for a given volume name."""
        api_args = {
            'volume': volume_name,
        }

        result = self.send_request('volume-autosize-get', api_args)
        # NOTE(dviroel): 'is-enabled' is deprecated since ONTAP 8.2, use 'mode'
        # to identify if autosize is enabled or not.
        return {
            'mode': result.get_child_content('mode'),
            'grow-threshold-percent': result.get_child_content(
                'grow-threshold-percent'),
            'shrink-threshold-percent': result.get_child_content(
                'shrink-threshold-percent'),
            'maximum-size': result.get_child_content('maximum-size'),
            'minimum-size': result.get_child_content('minimum-size'),
        }

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
                        'aggr-list': {
                            'aggr-name': None,
                        },
                        'containing-aggregate-name': None,
                        'junction-path': None,
                        'name': None,
                        'owning-vserver-name': None,
                        'type': None,
                        'style': None,
                        'style-extended': None,
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

        aggregate = volume_id_attributes.get_child_content(
            'containing-aggregate-name')
        aggregate_list = []
        if not aggregate:
            aggregate = ''
            aggr_list_attr = volume_id_attributes.get_child_by_name(
                'aggr-list') or netapp_api.NaElement('none')
            aggregate_list = [aggr_elem.get_content()
                              for aggr_elem in aggr_list_attr.get_children()]

        volume = {
            'aggregate': aggregate,
            'aggr-list': aggregate_list,
            'junction-path': volume_id_attributes.get_child_content(
                'junction-path'),
            'name': volume_id_attributes.get_child_content('name'),
            'owning-vserver-name': volume_id_attributes.get_child_content(
                'owning-vserver-name'),
            'type': volume_id_attributes.get_child_content('type'),
            'style': volume_id_attributes.get_child_content('style'),
            'size': volume_space_attributes.get_child_content('size'),
            'qos-policy-group-name': volume_qos_attributes.get_child_content(
                'policy-group-name'),
            'style-extended': volume_id_attributes.get_child_content(
                'style-extended')
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
                        'style-extended': '%s|%s' % (
                            na_utils.FLEXGROUP_STYLE_EXTENDED,
                            na_utils.FLEXVOL_STYLE_EXTENDED),
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
            return None

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        volume_attributes = attributes_list.get_child_by_name(
            'volume-attributes') or netapp_api.NaElement('none')
        volume_id_attributes = volume_attributes.get_child_by_name(
            'volume-id-attributes') or netapp_api.NaElement('none')

        volume = {
            'name': volume_id_attributes.get_child_content('name'),
        }
        return volume

    @na_utils.trace
    def get_volume_to_manage(self, aggregate_name, volume_name):
        """Get flexvol to be managed by Manila.

        :param aggregate_name: either a list or a string. List for aggregate
            names where the FlexGroup resides, while a string for the aggregate
            name where FlexVol volume is.
        :param volume_name: name of the managed volume.
        """

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
                        'aggr-list': {
                            'aggr-name': None,
                        },
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
        if isinstance(aggregate_name, str):
            api_args['query']['volume-attributes']['volume-id-attributes'][
                'containing-aggregate-name'] = aggregate_name
        elif isinstance(aggregate_name, list):
            aggr_list = [{'aggr-name': aggr_name} for aggr_name in
                         aggregate_name]
            api_args['query']['volume-attributes']['volume-id-attributes'][
                'aggr-list'] = aggr_list

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

        aggregate = volume_id_attributes.get_child_content(
            'containing-aggregate-name')
        aggregate_list = []
        if not aggregate:
            aggregate = ''
            aggr_list_attr = volume_id_attributes.get_child_by_name(
                'aggr-list') or netapp_api.NaElement('none')
            aggregate_list = [aggr_elem.get_content()
                              for aggr_elem in aggr_list_attr.get_children()]

        volume = {
            'aggregate': aggregate,
            'aggr-list': aggregate_list,
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
                            qos_policy_group=None,
                            adaptive_qos_policy_group=None, **options):
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

        if adaptive_qos_policy_group is not None:
            self.set_qos_adaptive_policy_group_for_volume(
                volume_name, adaptive_qos_policy_group)

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
    def check_volume_clone_split_completed(self, volume_name):
        """Check if volume clone split operation already finished"""
        return self.get_volume_clone_parent_snaphot(volume_name) is None

    @na_utils.trace
    def get_volume_clone_parent_snaphot(self, volume_name):
        """Gets volume's clone parent.

        Return the snapshot name of a volume's clone parent, or None if it
        doesn't exist.
        """
        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': volume_name
                    }
                }
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-clone-attributes': {
                        'volume-clone-parent-attributes': {
                            'snapshot-name': ''
                        }
                    }
                }
            }
        }
        result = self.send_iter_request('volume-get-iter', api_args)
        if not self._has_records(result):
            return None

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        volume_attributes = attributes_list.get_child_by_name(
            'volume-attributes') or netapp_api.NaElement('none')
        vol_clone_attrs = volume_attributes.get_child_by_name(
            'volume-clone-attributes') or netapp_api.NaElement('none')
        vol_clone_parent_atts = vol_clone_attrs.get_child_by_name(
            'volume-clone-parent-attributes') or netapp_api.NaElement(
            'none')
        snapshot_name = vol_clone_parent_atts.get_child_content(
            'snapshot-name')
        return snapshot_name

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
            'is-style-cifs': str(is_style_cifs).lower(),
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
            'force': str(force).lower(),
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
        snapshot['locked_by_clone'] = snapshot['owners'] == {'volume clone'}

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
    def create_cifs_share(self, share_name, path):
        api_args = {'path': path, 'share-name': share_name}
        self.send_request('cifs-share-create', api_args)

    @na_utils.trace
    def cifs_share_exists(self, share_name):
        """Check that a cifs share already exists"""
        share_path = '/%s' % share_name
        api_args = {
            'query': {
                'cifs-share': {
                    'share-name': share_name,
                    'path': share_path,
                },
            },
            'desired-attributes': {
                'cifs-share': {
                    'share-name': None
                }
            },
        }
        result = self.send_iter_request('cifs-share-get-iter', api_args)
        return self._has_records(result)

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
        try:
            self.send_request('cifs-share-delete', {'share-name': share_name})
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EOBJECTNOTFOUND:
                return
            raise

    @na_utils.trace
    def add_nfs_export_rule(self, policy_name, client_match, readonly,
                            auth_methods):
        rule_indices = self._get_nfs_export_rule_indices(policy_name,
                                                         client_match)
        if not rule_indices:
            self._add_nfs_export_rule(policy_name, client_match, readonly,
                                      auth_methods)
        else:
            # Update first rule and delete the rest
            self._update_nfs_export_rule(
                policy_name, client_match, readonly, rule_indices.pop(0),
                auth_methods)
            self._remove_nfs_export_rules(policy_name, rule_indices)

    @na_utils.trace
    def _add_nfs_export_rule(self, policy_name, client_match, readonly,
                             auth_methods):
        api_args = {
            'policy-name': policy_name,
            'client-match': client_match,
            'ro-rule': [],
            'rw-rule': [],
            'super-user-security': [],
        }
        for am in auth_methods:
            api_args['ro-rule'].append({'security-flavor': am})
            api_args['rw-rule'].append({'security-flavor': am})
            api_args['super-user-security'].append({'security-flavor': am})
        if readonly:
            # readonly, overwrite with auth method 'never'
            api_args['rw-rule'] = [{'security-flavor': 'never'}]

        self.send_request('export-rule-create', api_args)

    @na_utils.trace
    def _update_nfs_export_rule(self, policy_name, client_match, readonly,
                                rule_index, auth_methods):
        api_args = {
            'policy-name': policy_name,
            'rule-index': rule_index,
            'client-match': client_match,
            'ro-rule': [],
            'rw-rule': [],
            'super-user-security': [],
        }
        for am in auth_methods:
            api_args['ro-rule'].append({'security-flavor': am})
            api_args['rw-rule'].append({'security-flavor': am})
            api_args['super-user-security'].append({'security-flavor': am})
        if readonly:
            api_args['rw-rule'] = [{'security-flavor': 'never'}]

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
        return [str(rule_index) for rule_index in rule_indices]

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
    def set_qos_adaptive_policy_group_for_volume(self, volume_name,
                                                 qos_policy_group_name):
        if not self.features.ADAPTIVE_QOS:
            msg = 'Adaptive QoS not supported on this backend ONTAP version.'
            raise exception.NetAppException(msg)

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
                        'adaptive-policy-group-name': qos_policy_group_name,
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
        node_client.connection = copy.copy(self.connection.get_client())
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
    def get_cluster_name(self):
        """Gets cluster name."""
        api_args = {
            'desired-attributes': {
                'cluster-identity-info': {
                    'cluster-name': None,
                }
            }
        }
        result = self.send_request('cluster-identity-get', api_args,
                                   enable_tunneling=False)
        attributes = result.get_child_by_name('attributes')
        cluster_identity = attributes.get_child_by_name(
            'cluster-identity-info')
        return cluster_identity.get_child_content('cluster-name')

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

        self.send_request('cluster-peer-create', api_args,
                          enable_tunneling=False)

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
        self.send_request('cluster-peer-delete', api_args,
                          enable_tunneling=False)

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
            api_args['passphrase-minlength'] = str(
                passphrase_minimum_length)

        self.send_request('cluster-peer-policy-modify', api_args)

    @na_utils.trace
    def create_vserver_peer(self, vserver_name, peer_vserver_name,
                            peer_cluster_name=None):
        """Creates a Vserver peer relationship for SnapMirrors."""
        api_args = {
            'vserver': vserver_name,
            'peer-vserver': peer_vserver_name,
            'applications': [
                {'vserver-peer-application': 'snapmirror'},
            ],
        }
        if peer_cluster_name:
            api_args['peer-cluster'] = peer_cluster_name
        self.send_request('vserver-peer-create', api_args,
                          enable_tunneling=False)

    @na_utils.trace
    def delete_vserver_peer(self, vserver_name, peer_vserver_name):
        """Deletes a Vserver peer relationship."""

        api_args = {'vserver': vserver_name, 'peer-vserver': peer_vserver_name}
        self.send_request('vserver-peer-delete', api_args,
                          enable_tunneling=False)

    @na_utils.trace
    def accept_vserver_peer(self, vserver_name, peer_vserver_name):
        """Accepts a pending Vserver peer relationship."""

        api_args = {'vserver': vserver_name, 'peer-vserver': peer_vserver_name}
        self.send_request('vserver-peer-accept', api_args,
                          enable_tunneling=False)

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
    def create_snapmirror_vol(self, source_vserver, source_volume,
                              destination_vserver, destination_volume,
                              relationship_type, schedule=None,
                              policy=na_utils.MIRROR_ALL_SNAP_POLICY):
        """Creates a SnapMirror relationship between volumes."""
        self._create_snapmirror(source_vserver, destination_vserver,
                                source_volume=source_volume,
                                destination_volume=destination_volume,
                                schedule=schedule, policy=policy,
                                relationship_type=relationship_type)

    @na_utils.trace
    def create_snapmirror_svm(self, source_vserver, destination_vserver,
                              schedule=None, policy=None,
                              relationship_type=na_utils.DATA_PROTECTION_TYPE,
                              identity_preserve=True,
                              max_transfer_rate=None):
        """Creates a SnapMirror relationship between vServers."""
        self._create_snapmirror(source_vserver, destination_vserver,
                                schedule=schedule, policy=policy,
                                relationship_type=relationship_type,
                                identity_preserve=identity_preserve,
                                max_transfer_rate=max_transfer_rate)

    @na_utils.trace
    def _create_snapmirror(self, source_vserver, destination_vserver,
                           source_volume=None, destination_volume=None,
                           schedule=None, policy=None,
                           relationship_type=na_utils.DATA_PROTECTION_TYPE,
                           identity_preserve=None, max_transfer_rate=None):
        """Creates a SnapMirror relationship (cDOT 8.2 or later only)."""
        self._ensure_snapmirror_v2()

        api_args = {
            'source-vserver': source_vserver,
            'destination-vserver': destination_vserver,
            'relationship-type': relationship_type,
        }
        if source_volume:
            api_args['source-volume'] = source_volume
        if destination_volume:
            api_args['destination-volume'] = destination_volume
        if schedule:
            api_args['schedule'] = schedule
        if policy:
            api_args['policy'] = policy
        if identity_preserve is not None:
            api_args['identity-preserve'] = (
                'true' if identity_preserve is True else 'false')
        if max_transfer_rate is not None:
            api_args['max-transfer-rate'] = max_transfer_rate

        try:
            self.send_request('snapmirror-create', api_args)
        except netapp_api.NaApiError as e:
            if e.code != netapp_api.ERELATION_EXISTS:
                raise

    def _build_snapmirror_request(self, source_path=None, dest_path=None,
                                  source_vserver=None, dest_vserver=None,
                                  source_volume=None, dest_volume=None):
        """Build a default SnapMirror request."""

        req_args = {}
        if source_path:
            req_args['source-location'] = source_path
        if dest_path:
            req_args['destination-location'] = dest_path
        if source_vserver:
            req_args['source-vserver'] = source_vserver
        if source_volume:
            req_args['source-volume'] = source_volume
        if dest_vserver:
            req_args['destination-vserver'] = dest_vserver
        if dest_volume:
            req_args['destination-volume'] = dest_volume

        return req_args

    @na_utils.trace
    def initialize_snapmirror_vol(self, source_vserver, source_volume,
                                  dest_vserver, dest_volume,
                                  source_snapshot=None,
                                  transfer_priority=None):
        """Initializes a SnapMirror relationship between volumes."""
        return self._initialize_snapmirror(
            source_vserver=source_vserver, dest_vserver=dest_vserver,
            source_volume=source_volume, dest_volume=dest_volume,
            source_snapshot=source_snapshot,
            transfer_priority=transfer_priority)

    @na_utils.trace
    def initialize_snapmirror_svm(self, source_vserver, dest_vserver,
                                  transfer_priority=None):
        """Initializes a SnapMirror relationship between vServer."""
        source_path = source_vserver + ':'
        dest_path = dest_vserver + ':'
        return self._initialize_snapmirror(source_path=source_path,
                                           dest_path=dest_path,
                                           transfer_priority=transfer_priority)

    @na_utils.trace
    def _initialize_snapmirror(self, source_path=None, dest_path=None,
                               source_vserver=None, dest_vserver=None,
                               source_volume=None, dest_volume=None,
                               source_snapshot=None, transfer_priority=None):
        """Initializes a SnapMirror relationship."""
        self._ensure_snapmirror_v2()

        api_args = self._build_snapmirror_request(
            source_path, dest_path, source_vserver,
            dest_vserver, source_volume, dest_volume)
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
    def release_snapmirror_vol(self, source_vserver, source_volume,
                               dest_vserver, dest_volume,
                               relationship_info_only=False):
        """Removes a SnapMirror relationship on the source endpoint."""

        self._ensure_snapmirror_v2()
        snapmirror_destinations_list = self.get_snapmirror_destinations(
            source_vserver=source_vserver,
            dest_vserver=dest_vserver,
            source_volume=source_volume,
            dest_volume=dest_volume,
            desired_attributes=['relationship-id'])

        if len(snapmirror_destinations_list) > 1:
            msg = ("Expected snapmirror relationship to be unique. "
                   "List returned: %s." % snapmirror_destinations_list)
            raise exception.NetAppException(msg)

        api_args = self._build_snapmirror_request(
            source_vserver=source_vserver, dest_vserver=dest_vserver,
            source_volume=source_volume, dest_volume=dest_volume)
        api_args['relationship-info-only'] = (
            'true' if relationship_info_only else 'false')

        # NOTE(nahimsouza): This verification is needed because an empty list
        # is returned in snapmirror_destinations_list when a single share is
        # created with only one replica and this replica is deleted, thus there
        # will be no relationship-id in that case.
        if len(snapmirror_destinations_list) == 1:
            api_args['relationship-id'] = (
                snapmirror_destinations_list[0]['relationship-id'])

        self.send_request('snapmirror-release', api_args,
                          enable_tunneling=True)

    @na_utils.trace
    def release_snapmirror_svm(self, source_vserver, dest_vserver,
                               relationship_info_only=False):
        """Removes a SnapMirror relationship on the source endpoint."""
        source_path = source_vserver + ':'
        dest_path = dest_vserver + ':'
        dest_info = self._build_snapmirror_request(
            source_path=source_path, dest_path=dest_path)
        self._ensure_snapmirror_v2()
        api_args = {
            'query': {
                'snapmirror-destination-info': dest_info,
            },
            'relationship-info-only': (
                'true' if relationship_info_only else 'false'),
        }
        self.send_request('snapmirror-release-iter', api_args,
                          enable_tunneling=False)

    @na_utils.trace
    def quiesce_snapmirror_vol(self, source_vserver, source_volume,
                               dest_vserver, dest_volume):
        """Disables future transfers to a SnapMirror destination."""
        self._quiesce_snapmirror(source_vserver=source_vserver,
                                 dest_vserver=dest_vserver,
                                 source_volume=source_volume,
                                 dest_volume=dest_volume)

    @na_utils.trace
    def quiesce_snapmirror_svm(self, source_vserver, dest_vserver):
        """Disables future transfers to a SnapMirror destination."""
        source_path = source_vserver + ':'
        dest_path = dest_vserver + ':'
        self._quiesce_snapmirror(source_path=source_path, dest_path=dest_path)

    @na_utils.trace
    def _quiesce_snapmirror(self, source_path=None, dest_path=None,
                            source_vserver=None, dest_vserver=None,
                            source_volume=None, dest_volume=None):
        """Disables future transfers to a SnapMirror destination."""
        self._ensure_snapmirror_v2()

        api_args = self._build_snapmirror_request(
            source_path, dest_path, source_vserver,
            dest_vserver, source_volume, dest_volume)

        self.send_request('snapmirror-quiesce', api_args)

    @na_utils.trace
    def abort_snapmirror_vol(self, source_vserver, source_volume,
                             dest_vserver, dest_volume,
                             clear_checkpoint=False):
        """Stops ongoing transfers for a SnapMirror relationship."""
        self._abort_snapmirror(source_vserver=source_vserver,
                               dest_vserver=dest_vserver,
                               source_volume=source_volume,
                               dest_volume=dest_volume,
                               clear_checkpoint=clear_checkpoint)

    @na_utils.trace
    def abort_snapmirror_svm(self, source_vserver, dest_vserver,
                             clear_checkpoint=False):
        """Stops ongoing transfers for a SnapMirror relationship."""
        source_path = source_vserver + ':'
        dest_path = dest_vserver + ':'
        self._abort_snapmirror(source_path=source_path, dest_path=dest_path,
                               clear_checkpoint=clear_checkpoint)

    @na_utils.trace
    def _abort_snapmirror(self, source_path=None, dest_path=None,
                          source_vserver=None, dest_vserver=None,
                          source_volume=None, dest_volume=None,
                          clear_checkpoint=False):
        """Stops ongoing transfers for a SnapMirror relationship."""
        self._ensure_snapmirror_v2()

        api_args = self._build_snapmirror_request(
            source_path, dest_path, source_vserver,
            dest_vserver, source_volume, dest_volume)
        api_args['clear-checkpoint'] = 'true' if clear_checkpoint else 'false'

        try:
            self.send_request('snapmirror-abort', api_args)
        except netapp_api.NaApiError as e:
            if e.code != netapp_api.ENOTRANSFER_IN_PROGRESS:
                raise

    @na_utils.trace
    def break_snapmirror_vol(self, source_vserver, source_volume,
                             dest_vserver, dest_volume):
        """Breaks a data protection SnapMirror relationship."""
        self._break_snapmirror(source_vserver=source_vserver,
                               dest_vserver=dest_vserver,
                               source_volume=source_volume,
                               dest_volume=dest_volume)

    @na_utils.trace
    def break_snapmirror_svm(self, source_vserver=None, dest_vserver=None):
        """Breaks a data protection SnapMirror relationship."""
        source_path = source_vserver + ':' if source_vserver else None
        dest_path = dest_vserver + ':' if dest_vserver else None
        self._break_snapmirror(source_path=source_path, dest_path=dest_path)

    @na_utils.trace
    def _break_snapmirror(self, source_path=None, dest_path=None,
                          source_vserver=None, dest_vserver=None,
                          source_volume=None, dest_volume=None):
        """Breaks a data protection SnapMirror relationship."""
        self._ensure_snapmirror_v2()

        api_args = self._build_snapmirror_request(
            source_path, dest_path, source_vserver,
            dest_vserver, source_volume, dest_volume)
        try:
            self.send_request('snapmirror-break', api_args)
        except netapp_api.NaApiError as e:
            break_in_progress = 'SnapMirror operation status is "Breaking"'
            if not (e.code == netapp_api.ESVMDR_CANNOT_PERFORM_OP_FOR_STATUS
                    and break_in_progress in e.message):
                raise

    @na_utils.trace
    def modify_snapmirror_vol(self, source_vserver, source_volume,
                              dest_vserver, dest_volume,
                              schedule=None, policy=None, tries=None,
                              max_transfer_rate=None):
        """Modifies a SnapMirror relationship between volumes."""
        self._modify_snapmirror(source_vserver=source_vserver,
                                dest_vserver=dest_vserver,
                                source_volume=source_volume,
                                dest_volume=dest_volume,
                                schedule=schedule, policy=policy, tries=tries,
                                max_transfer_rate=max_transfer_rate)

    @na_utils.trace
    def _modify_snapmirror(self, source_path=None, dest_path=None,
                           source_vserver=None, dest_vserver=None,
                           source_volume=None, dest_volume=None,
                           schedule=None, policy=None, tries=None,
                           max_transfer_rate=None):
        """Modifies a SnapMirror relationship."""
        self._ensure_snapmirror_v2()

        api_args = self._build_snapmirror_request(
            source_path, dest_path, source_vserver,
            dest_vserver, source_volume, dest_volume)
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
    def delete_snapmirror_vol(self, source_vserver, source_volume,
                              dest_vserver, dest_volume):
        """Destroys a SnapMirror relationship between volumes."""
        self._delete_snapmirror(source_vserver=source_vserver,
                                dest_vserver=dest_vserver,
                                source_volume=source_volume,
                                dest_volume=dest_volume)

    @na_utils.trace
    def delete_snapmirror_svm(self, source_vserver, dest_vserver):
        """Destroys a SnapMirror relationship between vServers."""
        source_path = source_vserver + ':'
        dest_path = dest_vserver + ':'
        self._delete_snapmirror(source_path=source_path, dest_path=dest_path)

    @na_utils.trace
    def _delete_snapmirror(self, source_path=None, dest_path=None,
                           source_vserver=None, dest_vserver=None,
                           source_volume=None, dest_volume=None):
        """Destroys a SnapMirror relationship."""
        self._ensure_snapmirror_v2()

        snapmirror_info = self._build_snapmirror_request(
            source_path, dest_path, source_vserver,
            dest_vserver, source_volume, dest_volume)

        api_args = {
            'query': {
                'snapmirror-info': snapmirror_info
            }
        }
        self.send_request('snapmirror-destroy-iter', api_args)

    @na_utils.trace
    def update_snapmirror_vol(self, source_vserver, source_volume,
                              dest_vserver, dest_volume):
        """Schedules a snapmirror update between volumes."""
        self._update_snapmirror(source_vserver=source_vserver,
                                dest_vserver=dest_vserver,
                                source_volume=source_volume,
                                dest_volume=dest_volume)

    @na_utils.trace
    def update_snapmirror_svm(self, source_vserver, dest_vserver):
        """Schedules a snapmirror update between vServers."""
        source_path = source_vserver + ':'
        dest_path = dest_vserver + ':'
        self._update_snapmirror(source_path=source_path, dest_path=dest_path)

    @na_utils.trace
    def _update_snapmirror(self, source_path=None, dest_path=None,
                           source_vserver=None, dest_vserver=None,
                           source_volume=None, dest_volume=None):
        """Schedules a snapmirror update."""
        self._ensure_snapmirror_v2()

        api_args = self._build_snapmirror_request(
            source_path, dest_path, source_vserver,
            dest_vserver, source_volume, dest_volume)

        try:
            self.send_request('snapmirror-update', api_args)
        except netapp_api.NaApiError as e:
            if (e.code != netapp_api.ETRANSFER_IN_PROGRESS and
                    e.code != netapp_api.EANOTHER_OP_ACTIVE):
                raise

    @na_utils.trace
    def resume_snapmirror_vol(self, source_vserver, source_volume,
                              dest_vserver, dest_volume):
        """Resume a SnapMirror relationship if it is quiesced."""
        self._resume_snapmirror(source_vserver=source_vserver,
                                dest_vserver=dest_vserver,
                                source_volume=source_volume,
                                dest_volume=dest_volume)

    @na_utils.trace
    def resume_snapmirror_svm(self, source_vserver, dest_vserver):
        """Resume a SnapMirror relationship if it is quiesced."""
        source_path = source_vserver + ':'
        dest_path = dest_vserver + ':'
        self._resume_snapmirror(source_path=source_path, dest_path=dest_path)

    @na_utils.trace
    def _resume_snapmirror(self, source_path=None, dest_path=None,
                           source_vserver=None, dest_vserver=None,
                           source_volume=None, dest_volume=None):
        """Resume a SnapMirror relationship if it is quiesced."""
        self._ensure_snapmirror_v2()

        api_args = self._build_snapmirror_request(
            source_path, dest_path, source_vserver,
            dest_vserver, source_volume, dest_volume)

        try:
            self.send_request('snapmirror-resume', api_args)
        except netapp_api.NaApiError as e:
            if e.code != netapp_api.ERELATION_NOT_QUIESCED:
                raise

    @na_utils.trace
    def resync_snapmirror_vol(self, source_vserver, source_volume,
                              dest_vserver, dest_volume):
        """Resync a SnapMirror relationship between volumes."""
        self._resync_snapmirror(source_vserver=source_vserver,
                                dest_vserver=dest_vserver,
                                source_volume=source_volume,
                                dest_volume=dest_volume)

    @na_utils.trace
    def resync_snapmirror_svm(self, source_vserver, dest_vserver):
        """Resync a SnapMirror relationship between vServers."""
        source_path = source_vserver + ':'
        dest_path = dest_vserver + ':'
        self._resync_snapmirror(source_path=source_path, dest_path=dest_path)

    @na_utils.trace
    def _resync_snapmirror(self, source_path=None, dest_path=None,
                           source_vserver=None, dest_vserver=None,
                           source_volume=None, dest_volume=None):
        """Resync a SnapMirror relationship."""
        self._ensure_snapmirror_v2()

        api_args = self._build_snapmirror_request(
            source_path, dest_path, source_vserver,
            dest_vserver, source_volume, dest_volume)

        self.send_request('snapmirror-resync', api_args)

    @na_utils.trace
    def _get_snapmirrors(self, source_path=None, dest_path=None,
                         source_vserver=None, source_volume=None,
                         dest_vserver=None, dest_volume=None,
                         desired_attributes=None):
        """Gets one or more SnapMirror relationships."""

        snapmirror_info = self._build_snapmirror_request(
            source_path, dest_path, source_vserver,
            dest_vserver, source_volume, dest_volume)
        api_args = {}
        if snapmirror_info:
            api_args['query'] = {
                'snapmirror-info': snapmirror_info
            }
        if desired_attributes:
            api_args['desired-attributes'] = desired_attributes

        result = self.send_iter_request('snapmirror-get-iter', api_args)
        if not self._has_records(result):
            return []
        else:
            return result.get_child_by_name('attributes-list').get_children()

    @na_utils.trace
    def get_snapmirrors_svm(self, source_vserver=None, dest_vserver=None,
                            desired_attributes=None):
        source_path = source_vserver + ':' if source_vserver else None
        dest_path = dest_vserver + ':' if dest_vserver else None
        return self.get_snapmirrors(source_path=source_path,
                                    dest_path=dest_path,
                                    desired_attributes=desired_attributes)

    @na_utils.trace
    def get_snapmirrors(self, source_path=None, dest_path=None,
                        source_vserver=None, dest_vserver=None,
                        source_volume=None, dest_volume=None,
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
            source_path=source_path,
            dest_path=dest_path,
            source_vserver=source_vserver,
            source_volume=source_volume,
            dest_vserver=dest_vserver,
            dest_volume=dest_volume,
            desired_attributes=desired_attributes)

        snapmirrors = []

        for snapmirror_info in result:
            snapmirror = {}
            for child in snapmirror_info.get_children():
                name = self._strip_xml_namespace(child.get_name())
                snapmirror[name] = child.get_content()
            snapmirrors.append(snapmirror)

        return snapmirrors

    @na_utils.trace
    def _get_snapmirror_destinations(self, source_path=None, dest_path=None,
                                     source_vserver=None, source_volume=None,
                                     dest_vserver=None, dest_volume=None,
                                     desired_attributes=None):
        """Gets one or more SnapMirror at source endpoint."""

        snapmirror_info = self._build_snapmirror_request(
            source_path, dest_path, source_vserver,
            dest_vserver, source_volume, dest_volume)
        api_args = {}
        if snapmirror_info:
            api_args['query'] = {
                'snapmirror-destination-info': snapmirror_info
            }
        if desired_attributes:
            api_args['desired-attributes'] = desired_attributes

        result = self.send_iter_request('snapmirror-get-destination-iter',
                                        api_args)
        if not self._has_records(result):
            return []
        else:
            return result.get_child_by_name('attributes-list').get_children()

    @na_utils.trace
    def get_snapmirror_destinations(self, source_path=None, dest_path=None,
                                    source_vserver=None, dest_vserver=None,
                                    source_volume=None, dest_volume=None,
                                    desired_attributes=None):
        """Gets one or more SnapMirror relationships in the source endpoint.

        Either the source or destination info may be omitted.
        Desired attributes should be a flat list of attribute names.
        """
        self._ensure_snapmirror_v2()

        if desired_attributes is not None:
            desired_attributes = {
                'snapmirror-destination-info': {
                    attr: None for attr in desired_attributes},
            }

        result = self._get_snapmirror_destinations(
            source_path=source_path,
            dest_path=dest_path,
            source_vserver=source_vserver,
            source_volume=source_volume,
            dest_vserver=dest_vserver,
            dest_volume=dest_volume,
            desired_attributes=desired_attributes)

        snapmirrors = []

        for snapmirror_info in result:
            snapmirror = {}
            for child in snapmirror_info.get_children():
                name = self._strip_xml_namespace(child.get_name())
                snapmirror[name] = child.get_content()
            snapmirrors.append(snapmirror)

        return snapmirrors

    @na_utils.trace
    def get_snapmirror_destinations_svm(self, source_vserver=None,
                                        dest_vserver=None,
                                        desired_attributes=None):
        source_path = source_vserver + ':' if source_vserver else None
        dest_path = dest_vserver + ':' if dest_vserver else None
        return self.get_snapmirror_destinations(
            source_path=source_path, dest_path=dest_path,
            desired_attributes=desired_attributes)

    def volume_has_snapmirror_relationships(self, volume):
        """Return True if snapmirror relationships exist for a given volume.

        If we have snapmirror control plane license, we can verify whether
        the given volume is part of any snapmirror relationships.
        """
        try:
            # Check if volume is a source snapmirror volume
            snapmirrors = self.get_snapmirrors(
                source_vserver=volume['owning-vserver-name'],
                source_volume=volume['name'])
            # Check if volume is a destination snapmirror volume
            if not snapmirrors:
                snapmirrors = self.get_snapmirrors(
                    dest_vserver=volume['owning-vserver-name'],
                    dest_volume=volume['name'])

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
    def create_snapmirror_policy(self, policy_name, type='async_mirror',
                                 discard_network_info=True,
                                 preserve_snapshots=True):
        """Creates a SnapMirror policy for a vServer."""
        self._ensure_snapmirror_v2()

        api_args = {
            'policy-name': policy_name,
            'type': type,
        }

        if discard_network_info:
            api_args['discard-configs'] = {
                'svmdr-config-obj': 'network'
            }

        self.send_request('snapmirror-policy-create', api_args)

        if preserve_snapshots:
            api_args = {
                'policy-name': policy_name,
                'snapmirror-label': 'all_source_snapshots',
                'keep': '1',
                'preserve': 'false'
            }

            self.send_request('snapmirror-policy-add-rule', api_args)

    @na_utils.trace
    def delete_snapmirror_policy(self, policy_name):
        """Deletes a SnapMirror policy."""

        api_args = {
            'policy-name': policy_name,
        }
        try:
            self.send_request('snapmirror-policy-delete', api_args)
        except netapp_api.NaApiError as e:
            if e.code != netapp_api.EOBJECTNOTFOUND:
                raise

    @na_utils.trace
    def get_snapmirror_policies(self, vserver_name):
        """Get all SnapMirror policies associated to a vServer."""

        api_args = {
            'query': {
                'snapmirror-policy-info': {
                    'vserver-name': vserver_name,
                },
            },
            'desired-attributes': {
                'snapmirror-policy-info': {
                    'policy-name': None,
                },
            },
        }
        result = self.send_iter_request('snapmirror-policy-get-iter', api_args)
        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')

        return [policy_info.get_child_content('policy-name')
                for policy_info in attributes_list.get_children()]

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

        if self.features.FLEXVOL_ENCRYPTION:
            if encrypt_destination:
                api_args['encrypt-destination'] = 'true'
            else:
                api_args['encrypt-destination'] = 'false'
        elif encrypt_destination:
            msg = 'Flexvol encryption is not supported on this backend.'
            raise exception.NetAppException(msg)

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
        if qos_policy_group_name == new_name:
            return
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

    @na_utils.trace
    def rehost_volume(self, volume_name, vserver, destination_vserver):
        """Rehosts a volume from one Vserver into another Vserver.

        :param volume_name: Name of the FlexVol to be rehosted.
        :param vserver: Source Vserver name to which target volume belongs.
        :param destination_vserver: Destination Vserver name where target
        volume must reside after successful volume rehost operation.
        """
        api_args = {
            'volume': volume_name,
            'vserver': vserver,
            'destination-vserver': destination_vserver,
        }
        self.send_request('volume-rehost', api_args)

    @na_utils.trace
    def get_nfs_config(self, desired_args, vserver):
        """Gets the NFS config of the given vserver with the desired params"""
        api_args = {
            'query': {
                'nfs-info': {
                    'vserver': vserver,
                },
            },
        }
        nfs_info = {}
        for arg in desired_args:
            nfs_info[arg] = None

        if nfs_info:
            api_args['desired-attributes'] = {'nfs-info': nfs_info}

        result = self.send_request('nfs-service-get-iter', api_args)
        child_elem = result.get_child_by_name('attributes-list')

        return self.parse_nfs_config(child_elem, desired_args)

    @na_utils.trace
    def get_nfs_config_default(self, desired_args):
        """Gets the default NFS config with the desired params"""
        result = self.send_request('nfs-service-get-create-defaults', None)
        child_elem = result.get_child_by_name('defaults')

        return self.parse_nfs_config(child_elem, desired_args)

    @na_utils.trace
    def parse_nfs_config(self, parent_elem, desired_args):
        """Parse the get NFS config operation returning the desired params"""
        nfs_info_elem = parent_elem.get_child_by_name('nfs-info')

        nfs_config = {}
        for arg in desired_args:
            nfs_config[arg] = nfs_info_elem.get_child_content(arg)

        return nfs_config

    @na_utils.trace
    def start_vserver(self, vserver, force=None):
        """Starts a vServer."""
        api_args = {
            'vserver-name': vserver,
        }
        if force is not None:
            api_args['force'] = 'true' if force is True else 'false'

        try:
            self.send_request('vserver-start', api_args,
                              enable_tunneling=False)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EVSERVERALREADYSTARTED:
                msg = _("Vserver %s is already started.")
                LOG.debug(msg, vserver)
            else:
                raise

    @na_utils.trace
    def stop_vserver(self, vserver):
        """Stops a vServer."""
        api_args = {
            'vserver-name': vserver,
        }

        self.send_request('vserver-stop', api_args, enable_tunneling=False)

    def is_svm_dr_supported(self):
        return self.features.SVM_DR

    def create_fpolicy_event(self, share_name, event_name, protocol,
                             file_operations):
        """Creates a new fpolicy policy event.

        :param event_name: name of the new fpolicy event
        :param protocol: name of protocol for which event is created. Possible
            values are: 'nfsv3', 'nfsv4' or 'cifs'.
        :param file_operations: name of file operations to be monitored. Values
            should be provided as list of strings.
        :param share_name: name of share associated with the vserver where the
            fpolicy event should be added.
        """
        api_args = {
            'event-name': event_name,
            'protocol': protocol,
            'file-operations': [],
        }
        for file_op in file_operations:
            api_args['file-operations'].append({'fpolicy-operation': file_op})

        self.send_request('fpolicy-policy-event-create', api_args)

    def delete_fpolicy_event(self, share_name, event_name):
        """Deletes a fpolicy policy event.

        :param event_name: name of the event to be deleted
        :param share_name: name of share associated with the vserver where the
            fpolicy event should be deleted.
        """
        try:
            self.send_request('fpolicy-policy-event-delete',
                              {'event-name': event_name})
        except netapp_api.NaApiError as e:
            if e.code in [netapp_api.EEVENTNOTFOUND,
                          netapp_api.EOBJECTNOTFOUND]:
                msg = _("FPolicy event %s not found.")
                LOG.debug(msg, event_name)
            else:
                raise exception.NetAppException(message=e.message)

    def get_fpolicy_events(self, event_name=None, protocol=None,
                           file_operations=None):
        """Retrives a list of fpolicy events.

        :param event_name: name of the fpolicy event
        :param protocol: name of protocol. Possible values are: 'nfsv3',
            'nfsv4' or 'cifs'.
        :param file_operations: name of file operations to be monitored. Values
            should be provided as list of strings.
        :returns List of policy events or empty list
        """
        event_options_config = {}
        if event_name:
            event_options_config['event-name'] = event_name
        if protocol:
            event_options_config['protocol'] = protocol
        if file_operations:
            event_options_config['file-operations'] = []
            for file_op in file_operations:
                event_options_config['file-operations'].append(
                    {'fpolicy-operation': file_op})

        api_args = {
            'query': {
                'fpolicy-event-options-config': event_options_config,
            },
        }
        result = self.send_iter_request('fpolicy-policy-event-get-iter',
                                        api_args)

        fpolicy_events = []
        if self._has_records(result):
            try:
                fpolicy_events = []
                attributes_list = result.get_child_by_name(
                    'attributes-list') or netapp_api.NaElement('none')
                for event_info in attributes_list.get_children():
                    name = event_info.get_child_content('event-name')
                    proto = event_info.get_child_content('protocol')
                    file_operations_child = event_info.get_child_by_name(
                        'file-operations') or netapp_api.NaElement('none')
                    operations = [operation.get_content()
                                  for operation in
                                  file_operations_child.get_children()]

                    fpolicy_events.append({
                        'event-name': name,
                        'protocol': proto,
                        'file-operations': operations
                    })
            except AttributeError:
                msg = _('Could not retrieve fpolicy policy event information.')
                raise exception.NetAppException(msg)

        return fpolicy_events

    def create_fpolicy_policy(self, fpolicy_name, share_name, events,
                              engine='native'):
        """Creates a fpolicy policy resource.

        :param fpolicy_name: name of the fpolicy policy to be created.
        :param share_name: name of the share to be associated with the new
            fpolicy policy.
        :param events: list of event names for file access monitoring.
        :param engine: name of the engine to be used.
        """
        api_args = {
            'policy-name': fpolicy_name,
            'events': [],
            'engine-name': engine
        }
        for event in events:
            api_args['events'].append({'event-name': event})

        self.send_request('fpolicy-policy-create', api_args)

    def delete_fpolicy_policy(self, share_name, policy_name):
        """Deletes a fpolicy policy event.

        :param policy_name: name of the policy to be deleted.
        """
        try:
            self.send_request('fpolicy-policy-delete',
                              {'policy-name': policy_name})
        except netapp_api.NaApiError as e:
            if e.code in [netapp_api.EPOLICYNOTFOUND,
                          netapp_api.EOBJECTNOTFOUND]:
                msg = _("FPolicy policy %s not found.")
                LOG.debug(msg, policy_name)
            else:
                raise exception.NetAppException(message=e.message)

    def get_fpolicy_policies(self, share_name, policy_name=None,
                             engine_name='native', event_names=[]):
        """Retrieve one or more fpolicy policies.

        :param policy_name: name of the policy to be retrieved
        :param engine_name: name of the engine
        :param share_name: name of the share associated with the fpolicy
            policy.
        :param event_names: list of event names that must be associated to the
            fpolicy policy
        :return: list of fpolicy policies or empty list
        """
        policy_info = {}
        if policy_name:
            policy_info['policy-name'] = policy_name
        if engine_name:
            policy_info['engine-name'] = engine_name
        if event_names:
            policy_info['events'] = []
            for event_name in event_names:
                policy_info['events'].append({'event-name': event_name})

        api_args = {
            'query': {
                'fpolicy-policy-info': policy_info,
            },
        }
        result = self.send_iter_request('fpolicy-policy-get-iter', api_args)

        fpolicy_policies = []
        if self._has_records(result):
            try:
                attributes_list = result.get_child_by_name(
                    'attributes-list') or netapp_api.NaElement('none')
                for policy_info in attributes_list.get_children():
                    name = policy_info.get_child_content('policy-name')
                    engine = policy_info.get_child_content('engine-name')
                    events_child = policy_info.get_child_by_name(
                        'events') or netapp_api.NaElement('none')
                    events = [event.get_content()
                              for event in events_child.get_children()]

                    fpolicy_policies.append({
                        'policy-name': name,
                        'engine-name': engine,
                        'events': events
                    })
            except AttributeError:
                msg = _('Could not retrieve fpolicy policy information.')
                raise exception.NetAppException(message=msg)

        return fpolicy_policies

    def create_fpolicy_scope(self, policy_name, share_name,
                             extensions_to_include=None,
                             extensions_to_exclude=None):
        """Assings a file scope to an existing fpolicy policy.

        :param policy_name: name of the policy to associate with the new scope.
        :param share_name: name of the share to be associated with the new
            scope.
        :param extensions_to_include: file extensions included for screening.
            Values should be provided as comma separated list
        :param extensions_to_exclude: file extensions excluded for screening.
            Values should be provided as comma separated list
        """
        api_args = {
            'policy-name': policy_name,
            'shares-to-include': {
                'string': share_name,
            },
            'file-extensions-to-include': [],
            'file-extensions-to-exclude': [],
        }
        if extensions_to_include:
            for file_ext in extensions_to_include.split(','):
                api_args['file-extensions-to-include'].append(
                    {'string': file_ext.strip()})

        if extensions_to_exclude:
            for file_ext in extensions_to_exclude.split(','):
                api_args['file-extensions-to-exclude'].append(
                    {'string': file_ext.strip()})

        self.send_request('fpolicy-policy-scope-create', api_args)

    def modify_fpolicy_scope(self, share_name, policy_name,
                             shares_to_include=[], extensions_to_include=None,
                             extensions_to_exclude=None):
        """Modify an existing fpolicy scope.

        :param policy_name: name of the policy associated to the scope.
        :param share_name: name of the share associated with the fpolicy scope.
        :param shares_to_include: list of shares to include for file access
            monitoring.
        :param extensions_to_include: file extensions included for screening.
            Values should be provided as comma separated list
        :param extensions_to_exclude: file extensions excluded for screening.
            Values should be provided as comma separated list
        """
        api_args = {
            'policy-name': policy_name,
        }
        if extensions_to_include:
            api_args['file-extensions-to-include'] = []
            for file_ext in extensions_to_include.split(','):
                api_args['file-extensions-to-include'].append(
                    {'string': file_ext.strip()})

        if extensions_to_exclude:
            api_args['file-extensions-to-exclude'] = []
            for file_ext in extensions_to_exclude.split(','):
                api_args['file-extensions-to-exclude'].append(
                    {'string': file_ext.strip()})

        if shares_to_include:
            api_args['shares-to-include'] = [
                {'string': share} for share in shares_to_include
            ]

        self.send_request('fpolicy-policy-scope-modify', api_args)

    def delete_fpolicy_scope(self, policy_name):
        """Deletes a fpolicy policy scope.

        :param policy_name: name of the policy associated to the scope to be
            deleted.
        """
        try:
            self.send_request('fpolicy-policy-scope-delete',
                              {'policy-name': policy_name})
        except netapp_api.NaApiError as e:
            if e.code in [netapp_api.ESCOPENOTFOUND,
                          netapp_api.EOBJECTNOTFOUND]:
                msg = _("FPolicy scope %s not found.")
                LOG.debug(msg, policy_name)
            else:
                raise exception.NetAppException(message=e.message)

    def get_fpolicy_scopes(self, share_name, policy_name=None,
                           extensions_to_include=None,
                           extensions_to_exclude=None,
                           shares_to_include=None):
        """Retrieve fpolicy scopes.

        :param policy_name: name of the policy associated with a scope.
        :param share_name: name of the share associated with the fpolicy scope.
        :param extensions_to_include: file extensions included for screening.
            Values should be provided as comma separated list
        :param extensions_to_exclude: file extensions excluded for screening.
            Values should be provided as comma separated list
        :param shares_to_include: list of shares to include for file access
            monitoring.
        :return: list of fpolicy scopes or empty list
        """
        policy_scope_info = {}
        if policy_name:
            policy_scope_info['policy-name'] = policy_name

        if shares_to_include:
            policy_scope_info['shares-to-include'] = [
                {'string': share} for share in shares_to_include
            ]
        if extensions_to_include:
            policy_scope_info['file-extensions-to-include'] = []
            for file_op in extensions_to_include.split(','):
                policy_scope_info['file-extensions-to-include'].append(
                    {'string': file_op.strip()})
        if extensions_to_exclude:
            policy_scope_info['file-extensions-to-exclude'] = []
            for file_op in extensions_to_exclude.split(','):
                policy_scope_info['file-extensions-to-exclude'].append(
                    {'string': file_op.strip()})

        api_args = {
            'query': {
                'fpolicy-scope-config': policy_scope_info,
            },
        }
        result = self.send_iter_request('fpolicy-policy-scope-get-iter',
                                        api_args)

        fpolicy_scopes = []
        if self._has_records(result):
            try:
                fpolicy_scopes = []
                attributes_list = result.get_child_by_name(
                    'attributes-list') or netapp_api.NaElement('none')
                for policy_scope in attributes_list.get_children():
                    name = policy_scope.get_child_content('policy-name')
                    ext_include_child = policy_scope.get_child_by_name(
                        'file-extensions-to-include') or netapp_api.NaElement(
                        'none')
                    ext_include = [ext.get_content()
                                   for ext in ext_include_child.get_children()]
                    ext_exclude_child = policy_scope.get_child_by_name(
                        'file-extensions-to-exclude') or netapp_api.NaElement(
                        'none')
                    ext_exclude = [ext.get_content()
                                   for ext in ext_exclude_child.get_children()]
                    shares_child = policy_scope.get_child_by_name(
                        'shares-to-include') or netapp_api.NaElement('none')
                    shares_include = [ext.get_content()
                                      for ext in shares_child.get_children()]
                    fpolicy_scopes.append({
                        'policy-name': name,
                        'file-extensions-to-include': ext_include,
                        'file-extensions-to-exclude': ext_exclude,
                        'shares-to-include': shares_include,
                    })
            except AttributeError:
                msg = _('Could not retrieve fpolicy policy information.')
                raise exception.NetAppException(msg)

        return fpolicy_scopes

    def enable_fpolicy_policy(self, share_name, policy_name, sequence_number):
        """Enables a specific named policy.

        :param policy_name: name of the policy to be enabled
        :param share_name: name of the share associated with the vserver and
            the fpolicy
        :param sequence_number: policy sequence number
        """
        api_args = {
            'policy-name': policy_name,
            'sequence-number': sequence_number,
        }

        self.send_request('fpolicy-enable-policy', api_args)

    def disable_fpolicy_policy(self, policy_name):
        """Disables a specific policy.

        :param policy_name: name of the policy to be disabled
        """
        try:
            self.send_request('fpolicy-disable-policy',
                              {'policy-name': policy_name})
        except netapp_api.NaApiError as e:
            disabled = "policy is already disabled"
            if (e.code in [netapp_api.EPOLICYNOTFOUND,
                           netapp_api.EOBJECTNOTFOUND] or
                    (e.code == netapp_api.EINVALIDINPUTERROR and
                     disabled in e.message)):
                msg = _("FPolicy policy %s not found or already disabled.")
                LOG.debug(msg, policy_name)
            else:
                raise exception.NetAppException(message=e.message)

    def get_fpolicy_policies_status(self, share_name, policy_name=None,
                                    status='true'):
        policy_status_info = {}
        if policy_name:
            policy_status_info['policy-name'] = policy_name
            policy_status_info['status'] = status
        api_args = {
            'query': {
                'fpolicy-policy-status-info': policy_status_info,
            },
        }
        result = self.send_iter_request('fpolicy-policy-status-get-iter',
                                        api_args)

        fpolicy_status = []
        if self._has_records(result):
            try:
                fpolicy_status = []
                attributes_list = result.get_child_by_name(
                    'attributes-list') or netapp_api.NaElement('none')
                for policy_status in attributes_list.get_children():
                    name = policy_status.get_child_content('policy-name')
                    status = policy_status.get_child_content('status')
                    seq = policy_status.get_child_content('sequence-number')
                    fpolicy_status.append({
                        'policy-name': name,
                        'status': strutils.bool_from_string(status),
                        'sequence-number': seq
                    })
            except AttributeError:
                msg = _('Could not retrieve fpolicy status information.')
                raise exception.NetAppException(msg)

        return fpolicy_status

    @na_utils.trace
    def is_svm_migrate_supported(self):
        """Checks if the cluster supports SVM Migrate."""
        return self.features.SVM_MIGRATE

    def get_volume_state(self, name):
        """Returns volume state for a given name"""

        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': name,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-state-attributes': {
                        'state': None
                    }
                }
            },
        }

        result = self.send_iter_request('volume-get-iter', api_args)

        volume_state = ''
        if self._has_records(result):
            attributes_list = result.get_child_by_name(
                'attributes-list') or netapp_api.NaElement('none')
            volume_attributes = attributes_list.get_child_by_name(
                'volume-attributes') or netapp_api.NaElement('none')
            volume_state_attributes = volume_attributes.get_child_by_name(
                'volume-state-attributes') or netapp_api.NaElement('none')
            volume_state = volume_state_attributes.get_child_content('state')

        return volume_state

    @na_utils.trace
    def is_flexgroup_volume(self, volume_name):
        """Determines if the ONTAP volume is FlexGroup."""

        if not self.is_flexgroup_supported():
            return False

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
                        'style-extended': None,
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
            msg = _('More than one volume with volume name %(vol)s found.')
            msg_args = {'vol': volume_name}
            raise exception.NetAppException(msg % msg_args)

        volume_attributes = volume_attributes_list[0]

        volume_id_attributes = volume_attributes.get_child_by_name(
            'volume-id-attributes') or netapp_api.NaElement('none')

        return na_utils.is_style_extended_flexgroup(
            volume_id_attributes.get_child_content('style-extended'))

    @na_utils.trace
    def is_flexgroup_supported(self):
        return self.features.FLEXGROUP

    @na_utils.trace
    def is_flexgroup_fan_out_supported(self):
        return self.features.FLEXGROUP_FAN_OUT

    @na_utils.trace
    def get_job_state(self, job_id):
        """Returns job state for a given job id."""

        api_args = {
            'query': {
                'job-info': {
                    'job-id': job_id,
                },
            },
            'desired-attributes': {
                'job-info': {
                    'job-state': None,
                },
            },
        }

        result = self.send_iter_request('job-get-iter', api_args,
                                        enable_tunneling=False)

        attributes_list = result.get_child_by_name(
            'attributes-list') or netapp_api.NaElement('none')
        job_info_list = attributes_list.get_children()
        if not self._has_records(result):
            msg = _('Could not find job with ID %(id)s.')
            msg_args = {'id': job_id}
            raise exception.NetAppException(msg % msg_args)
        elif len(job_info_list) > 1:
            msg = _('Could not find unique job for ID %(id)s.')
            msg_args = {'id': job_id}
            raise exception.NetAppException(msg % msg_args)

        return job_info_list[0].get_child_content('job-state')

    @na_utils.trace
    def create_fpolicy_policy_with_scope(self, fpolicy_name, share_name,
                                         events, engine='native',
                                         extensions_to_include=None,
                                         extensions_to_exclude=None):

        # Create a fpolicy policy
        self.create_fpolicy_policy(fpolicy_name, share_name, events,
                                   engine='native')
        # Assign a scope to the fpolicy policy
        self.create_fpolicy_scope(fpolicy_name, share_name,
                                  extensions_to_include,
                                  extensions_to_exclude)

    @na_utils.trace
    def check_snaprestore_license(self):
        """Check SnapRestore license for SVM scoped user."""
        # NOTE(felipe_rodrigues): workaround to find out whether the
        # backend has the license: since without cluster credentials it
        # cannot retrieve the ontap licenses, it sends a fake ONTAP
        # "snapshot-restore-volume" request which is only available when
        # the license exists. By the got error, it checks whether license
        # is installed or not.
        try:
            self.restore_snapshot(
                "fake_%s" % uuidutils.generate_uuid(dashed=False), "")
        except netapp_api.NaApiError as e:
            no_license = 'is not licensed'
            LOG.debug('Fake restore_snapshot request failed: %s', e)
            return not (e.code == netapp_api.EAPIERROR and
                        no_license in e.message)

        # since it passed an empty snapshot, it should never get here
        msg = _("Caught an unexpected behavior: the fake restore to "
                "snapshot request using 'fake' volume and empty string "
                "snapshot as argument has not failed.")
        LOG.exception(msg)
        raise exception.NetAppException(msg)

    # ------------------------ REST CALLS ONLY ------------------------

    # NOTE(nahimsouza): For ONTAP 9.12.1 and newer, if the option
    # `netapp_use_legacy_client` is False, REST API client will be used. This
    # code was kept here to avoid breaking the SVM migrate feature on older
    # ONTAP versions. In the future, when ZAPI is deprecated, this code can
    # also be removed.

    @na_utils.trace
    def _format_request(self, request_data, headers={}, query={},
                        url_params={}):
        """Receives the request data and formats it into a request pattern.

        :param request_data: the body to be sent to the request.
        :param headers: additional headers to the request.
        :param query: filters to the request.
        :param url_params: parameters to be added to the request.
        """
        request = {
            "body": request_data,
            "headers": headers,
            "query": query,
            "url_params": url_params
        }
        return request

    @na_utils.trace
    def svm_migration_start(
            self, source_cluster_name, source_share_server_name,
            dest_aggregates, dest_ipspace=None, check_only=False):
        """Send a request to start the SVM migration in the backend.

        :param source_cluster_name: the name of the source cluster.
        :param source_share_server_name: the name of the source server.
        :param dest_aggregates: the aggregates where volumes will be placed in
        the migration.
        :param dest_ipspace: created IPspace for the migration.
        :param check_only: If the call will only check the feasibility.
         deleted after the cutover or not.
        """
        request = {
            "auto_cutover": False,
            "auto_source_cleanup": True,
            "check_only": check_only,
            "source": {
                "cluster": {"name": source_cluster_name},
                "svm": {"name": source_share_server_name},
            },
            "destination": {
                "volume_placement": {
                    "aggregates": dest_aggregates,
                },
            },
        }

        if dest_ipspace:
            ipspace_data = {
                "ipspace": {
                    "name": dest_ipspace,
                }
            }
            request["destination"].update(ipspace_data)

        api_args = self._format_request(request)

        return self.send_request(
            'svm-migration-start', api_args=api_args, use_zapi=False)

    @na_utils.trace
    def get_migration_check_job_state(self, job_id):
        """Get the job state of a share server migration.

        :param job_id: id of the job to be searched.
        """
        try:
            job = self.get_job(job_id)
            return job
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.ENFS_V4_0_ENABLED_MIGRATION_FAILURE:
                msg = _(
                    'NFS v4.0 is not supported while migrating vservers.')
                LOG.error(msg)
                raise exception.NetAppException(message=e.message)
            if e.code == netapp_api.EVSERVER_MIGRATION_TO_NON_AFF_CLUSTER:
                msg = _('Both source and destination clusters must be AFF '
                        'systems.')
                LOG.error(msg)
                raise exception.NetAppException(message=e.message)
            msg = (_('Failed to check migration support. Reason: '
                     '%s' % e.message))
            raise exception.NetAppException(msg)

    @na_utils.trace
    def svm_migrate_complete(self, migration_id):
        """Send a request to complete the SVM migration.

        :param migration_id: the id of the migration provided by the storage.
        """
        request = {
            "action": "cutover"
        }
        url_params = {
            "svm_migration_id": migration_id
        }
        api_args = self._format_request(
            request, url_params=url_params)

        return self.send_request(
            'svm-migration-complete', api_args=api_args, use_zapi=False)

    @na_utils.trace
    def svm_migrate_cancel(self, migration_id):
        """Send a request to cancel the SVM migration.

        :param migration_id: the id of the migration provided by the storage.
        """
        request = {}
        url_params = {
            "svm_migration_id": migration_id
        }
        api_args = self._format_request(request, url_params=url_params)
        return self.send_request(
            'svm-migration-cancel', api_args=api_args, use_zapi=False)

    @na_utils.trace
    def svm_migration_get(self, migration_id):
        """Send a request to get the progress of the SVM migration.

        :param migration_id: the id of the migration provided by the storage.
        """
        request = {}
        url_params = {
            "svm_migration_id": migration_id
        }
        api_args = self._format_request(request, url_params=url_params)
        return self.send_request(
            'svm-migration-get', api_args=api_args, use_zapi=False)

    @na_utils.trace
    def svm_migrate_pause(self, migration_id):
        """Send a request to pause a migration.

        :param migration_id: the id of the migration provided by the storage.
        """
        request = {
            "action": "pause"
        }
        url_params = {
            "svm_migration_id": migration_id
        }
        api_args = self._format_request(
            request, url_params=url_params)
        return self.send_request(
            'svm-migration-pause', api_args=api_args, use_zapi=False)

    @na_utils.trace
    def get_job(self, job_uuid):
        """Get a job in ONTAP.

        :param job_uuid: uuid of the job to be searched.
        """
        request = {}
        url_params = {
            "job_uuid": job_uuid
        }

        api_args = self._format_request(request, url_params=url_params)

        return self.send_request(
            'get-job', api_args=api_args, use_zapi=False)

    @na_utils.trace
    def get_svm_volumes_total_size(self, svm_name):
        """Gets volumes sizes sum (GB) from all volumes in SVM by svm_name"""

        request = {}

        query = {
            'svm.name': svm_name,
            'fields': 'size'
        }

        api_args = self._format_request(request, query=query)

        response = self.send_request(
            'svm-migration-get-progress', api_args=api_args, use_zapi=False)

        svm_volumes = response.get('records', [])

        if len(svm_volumes) > 0:
            total_volumes_size = 0
            for volume in svm_volumes:
                # Root volumes are not taking account because they are part of
                # SVM creation.
                if volume['name'] != 'root':
                    total_volumes_size = total_volumes_size + volume['size']
        else:
            return 0

        # Convert Bytes to GBs.
        return (total_volumes_size / 1024**3)
