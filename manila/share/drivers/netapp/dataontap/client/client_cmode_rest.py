# Copyright (c) 2023 NetApp, Inc. All rights reserved.
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
from datetime import datetime
from http import client as http_client
import math
import re
import time

from oslo_log import log
from oslo_utils import excutils
from oslo_utils import strutils
from oslo_utils import units

from manila import exception
from manila.i18n import _
from manila.share.drivers.netapp.dataontap.client import client_base
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.client import rest_api as netapp_api
from manila.share.drivers.netapp import utils as na_utils
from manila import utils

LOG = log.getLogger(__name__)
DELETED_PREFIX = 'deleted_manila_'
DEFAULT_IPSPACE = 'Default'
DEFAULT_MAX_PAGE_LENGTH = 10000
CIFS_USER_GROUP_TYPE = 'windows'
SNAPSHOT_CLONE_OWNER = 'volume_clone'
CUTOVER_ACTION_MAP = {
    'defer': 'defer_on_failure',
    'abort': 'abort_on_failure',
    'force': 'force',
    'wait': 'wait',
}
DEFAULT_TIMEOUT = 15
DEFAULT_TCP_MAX_XFER_SIZE = 65536
DEFAULT_UDP_MAX_XFER_SIZE = 32768
DEFAULT_SECURITY_CERT_EXPIRE_DAYS = 365


class NetAppRestClient(object):

    def __init__(self, **kwargs):

        self.connection = netapp_api.RestNaServer(
            host=kwargs['hostname'],
            transport_type=kwargs['transport_type'],
            ssl_cert_path=kwargs['ssl_cert_path'],
            port=kwargs['port'],
            username=kwargs['username'],
            password=kwargs['password'],
            trace=kwargs.get('trace', False),
            api_trace_pattern=kwargs.get('api_trace_pattern',
                                         na_utils.API_TRACE_PATTERN))

        self.async_rest_timeout = kwargs['async_rest_timeout']

        self.vserver = kwargs.get('vserver')

        self.connection.set_vserver(self.vserver)

        # NOTE(nahimsouza): Set this flag to False to ensure get_ontap_version
        # will be called without SVM tunneling. This is necessary because
        # requests with SVM scoped account can not be tunneled in REST API.
        self._have_cluster_creds = False
        ontap_version = self.get_ontap_version(cached=False)
        if ontap_version['version-tuple'] < (9, 12, 1):
            msg = _('This driver can communicate with ONTAP via REST APIs '
                    'exclusively only when paired with a NetApp ONTAP storage '
                    'system running release 9.12.1 or newer. '
                    'To use ZAPI and supported REST APIs instead, '
                    'set "netapp_use_legacy_client" to True.')
            raise exception.NetAppException(msg)
        self.connection.set_ontap_version(ontap_version)

        # NOTE(nahimsouza): ZAPI Client is needed to implement the fallback
        # when a REST method is not supported.
        self.zapi_client = client_cmode.NetAppCmodeClient(**kwargs)

        self._have_cluster_creds = self._check_for_cluster_credentials()

        self._init_features()

    def _init_features(self):
        """Initialize feature support map."""
        self.features = client_base.Features()

        # NOTE(felipe_rodrigues): REST client only runs with ONTAP 9.11.1 or
        # upper, so all features below are supported with this client.
        self.features.add_feature('SNAPMIRROR_V2', supported=True)
        self.features.add_feature('SYSTEM_METRICS', supported=True)
        self.features.add_feature('SYSTEM_CONSTITUENT_METRICS',
                                  supported=True)
        self.features.add_feature('BROADCAST_DOMAINS', supported=True)
        self.features.add_feature('IPSPACES', supported=True)
        self.features.add_feature('SUBNETS', supported=True)
        self.features.add_feature('CLUSTER_PEER_POLICY', supported=True)
        self.features.add_feature('ADVANCED_DISK_PARTITIONING',
                                  supported=True)
        self.features.add_feature('KERBEROS_VSERVER', supported=True)
        self.features.add_feature('FLEXVOL_ENCRYPTION', supported=True)
        self.features.add_feature('SVM_DR', supported=True)
        self.features.add_feature('ADAPTIVE_QOS', supported=True)
        self.features.add_feature('TRANSFER_LIMIT_NFS_CONFIG',
                                  supported=True)
        self.features.add_feature('CIFS_DC_ADD_SKIP_CHECK',
                                  supported=True)
        self.features.add_feature('LDAP_LDAP_SERVERS',
                                  supported=True)
        self.features.add_feature('FLEXGROUP', supported=True)
        self.features.add_feature('FLEXGROUP_FAN_OUT', supported=True)
        self.features.add_feature('SVM_MIGRATE', supported=True)

    def __getattr__(self, name):
        """If method is not implemented for REST, try to call the ZAPI."""
        LOG.debug("The %s call is not supported for REST, falling back to "
                  "ZAPI.", name)
        # Don't use self.zapi_client to avoid reentrant call to __getattr__()
        zapi_client = object.__getattribute__(self, 'zapi_client')
        return getattr(zapi_client, name)

    def _wait_job_result(self, job_url):

        interval = 2
        retries = (self.async_rest_timeout / interval)

        @utils.retry(netapp_api.NaRetryableError, interval=interval,
                     retries=retries, backoff_rate=1)
        def _waiter():
            response = self.send_request(job_url, 'get',
                                         enable_tunneling=False)

            job_state = response.get('state')
            if job_state == 'success':
                return response
            elif job_state == 'failure':
                message = response['error']['message']
                code = response['error']['code']
                raise netapp_api.NaRetryableError(message=message, code=code)

            msg_args = {'job': job_url, 'state': job_state}
            LOG.debug("Job %(job)s has not finished: %(state)s", msg_args)
            raise netapp_api.NaRetryableError(message='Job is running.')

        try:
            return _waiter()
        except netapp_api.NaRetryableError:
            msg = _("Job %s did not reach the expected state. Retries "
                    "exhausted. Aborting.") % job_url
            raise na_utils.NetAppDriverException(msg)

    def send_request(self, action_url, method, body=None, query=None,
                     enable_tunneling=True,
                     max_page_length=DEFAULT_MAX_PAGE_LENGTH,
                     wait_on_accepted=True):

        """Sends REST request to ONTAP.

        :param action_url: action URL for the request
        :param method: HTTP method for the request ('get', 'post', 'put',
            'delete' or 'patch')
        :param body: dict of arguments to be passed as request body
        :param query: dict of arguments to be passed as query string
        :param enable_tunneling: enable tunneling to the ONTAP host
        :param max_page_length: size of the page during pagination
        :param wait_on_accepted: if True, wait until the job finishes when
            HTTP code 202 (Accepted) is returned

        :returns: parsed REST response
        """

        # NOTE(felipe_rodrigues): disable tunneling when running in SVM scoped
        # context, otherwise REST API fails.
        if not self._have_cluster_creds:
            enable_tunneling = False

        response = None

        if method == 'get':
            response = self.get_records(
                action_url, query, enable_tunneling, max_page_length)
        else:
            code, response = self.connection.invoke_successfully(
                action_url, method, body=body, query=query,
                enable_tunneling=enable_tunneling)

            if code == http_client.ACCEPTED and wait_on_accepted:
                # get job URL and discard '/api'
                job_url = response['job']['_links']['self']['href'][4:]
                response = self._wait_job_result(job_url)

        return response

    def get_records(self, action_url, query=None, enable_tunneling=True,
                    max_page_length=DEFAULT_MAX_PAGE_LENGTH):
        """Retrieves ONTAP resources using pagination REST request.

        :param action_url: action URL for the request
        :param query: dict of arguments to be passed as query string
        :param enable_tunneling: enable tunneling to the ONTAP host
        :param max_page_length: size of the page during pagination

        :returns: dict containing records and num_records
        """

        # NOTE(felipe_rodrigues): disable tunneling when running in SVM scoped
        # context, otherwise REST API fails.
        if not self._have_cluster_creds:
            enable_tunneling = False

        # Initialize query variable if it is None
        query = query if query else {}
        query['max_records'] = max_page_length

        _, response = self.connection.invoke_successfully(
            action_url, 'get', query=query,
            enable_tunneling=enable_tunneling)

        # NOTE(nahimsouza): if all records are returned in the first call,
        # 'next_url' will be None.
        next_url = response.get('_links', {}).get('next', {}).get('href')
        next_url = next_url[4:] if next_url else None  # discard '/api'

        # Get remaining pages, saving data into first page
        while next_url:
            # NOTE(nahimsouza): clean the 'query', because the parameters are
            # already included in 'next_url'.
            _, next_response = self.connection.invoke_successfully(
                next_url, 'get', query=None,
                enable_tunneling=enable_tunneling)

            response['num_records'] += next_response.get('num_records', 0)
            response['records'].extend(next_response.get('records'))

            next_url = (
                next_response.get('_links', {}).get('next', {}).get('href'))
            next_url = next_url[4:] if next_url else None  # discard '/api'

        return response

    @na_utils.trace
    def get_ontap_version(self, cached=True):
        """Get the current Data ONTAP version."""

        if cached:
            return self.connection.get_ontap_version()

        query = {
            'fields': 'version'
        }

        try:
            response = self.send_request('/cluster/nodes', 'get', query=query,
                                         enable_tunneling=False)
            records = response.get('records')[0]

            return {
                'version': records['version']['full'],
                'version-tuple': (records['version']['generation'],
                                  records['version']['major'],
                                  records['version']['minor']),
            }
        except netapp_api.api.NaApiError as e:
            if e.code != netapp_api.EREST_NOT_AUTHORIZED:
                raise

            # NOTE(nahimsouza): SVM scoped account is not authorized to access
            # the /cluster/nodes endpoint, that's why we use /private/cli

            response = self.send_request('/private/cli/version', 'get',
                                         query=query)
            # Response is formatted as:
            # 'NetApp Release 9.12.1: Wed Feb 01 01:10:18 UTC 2023'
            version_full = response['records'][0]['version']['full']
            version_parsed = re.findall(r'\d+\.\d+\.\d+', version_full)[0]
            version_splited = version_parsed.split('.')
            return {
                'version': version_full,
                'version-tuple': (int(version_splited[0]),
                                  int(version_splited[1]),
                                  int(version_splited[2])),
            }

    @na_utils.trace
    def get_job(self, job_uuid):
        """Get a job in ONTAP.

        :param job_uuid: uuid of the job to be searched.
        """
        action_url = f'/cluster/jobs/{job_uuid}'
        return self.send_request(action_url, 'get', enable_tunneling=False)

    @na_utils.trace
    def _has_records(self, api_response):
        """Check if API response contains any records."""
        if (not api_response['num_records'] or
                api_response['num_records'] == 0):
            return False
        else:
            return True

    @na_utils.trace
    def get_licenses(self):
        """Get list of ONTAP licenses."""
        try:
            result = self.send_request('/cluster/licensing/licenses', 'get')
        except netapp_api.api.NaApiError:
            with excutils.save_and_reraise_exception():
                LOG.exception("Could not get list of ONTAP licenses.")

        return sorted(
            [license['name'] for license in result.get('records', [])])

    @na_utils.trace
    def _get_security_key_manager_nve_support(self):
        """Determine whether the cluster platform supports Volume Encryption"""

        query = {'fields': 'volume_encryption.*'}

        try:
            response = self.send_request('/security/key-managers',
                                         'get', query=query)
            records = response.get('records', [])
            if records:
                if records[0]['volume_encryption']['supported']:
                    return True
        except netapp_api.api.NaApiError as e:
            LOG.debug("NVE disabled due to error code: %s - %s",
                      e.code, e.message)
            return False

        LOG.debug("NVE disabled - Key management is not "
                  "configured on the admin Vserver.")
        return False

    @na_utils.trace
    def is_nve_supported(self):
        """Determine whether NVE is supported on this platform."""

        nodes = self.list_cluster_nodes()
        system_version = self.get_ontap_version()
        version = system_version.get('version')

        # Not all platforms support this feature. NVE is not supported if the
        # version includes the substring '<1no-DARE>' (no Data At Rest
        # Encryption).
        if "<1no-DARE>" not in version:
            if nodes is not None:
                return self._get_security_key_manager_nve_support()
            else:
                LOG.warning('Cluster credentials are required in order to '
                            'determine whether NetApp Volume Encryption is '
                            'supported or not on this platform.')
                return False
        else:
            LOG.warning('NetApp Volume Encryption is not supported on this '
                        'ONTAP version: %(version)s. ', {'version': version})
            return False

    @na_utils.trace
    def check_for_cluster_credentials(self):
        """Check if credentials to connect to ONTAP from cached value."""
        return self._have_cluster_creds

    @na_utils.trace
    def _check_for_cluster_credentials(self):
        """Check if credentials to connect to ONTAP are defined correctly."""
        try:
            self.list_cluster_nodes()
            # API succeeded, so definitely a cluster management LIF
            return True
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_NOT_AUTHORIZED:
                LOG.debug('Not connected to cluster management LIF.')
                return False
            else:
                raise

    @na_utils.trace
    def list_cluster_nodes(self):
        """Get all available cluster nodes."""

        result = self.send_request('/cluster/nodes', 'get')
        return [node['name'] for node in result.get('records', [])]

    @na_utils.trace
    def _get_volume_by_args(self, vol_name=None, aggregate_name=None,
                            vol_path=None, vserver=None, fields=None,
                            is_root=None):
        """Get info from a single volume according to the args."""

        query = {
            'style': 'flex*',  # Match both 'flexvol' and 'flexgroup'
            'error_state.is_inconsistent': 'false',
            'fields': 'name,style,svm.name,svm.uuid'
        }

        if vol_name:
            query['name'] = vol_name
        if aggregate_name:
            query['aggregates.name'] = aggregate_name
        if vol_path:
            query['nas.path'] = vol_path
        if vserver:
            query['svm.name'] = vserver
        if fields:
            query['fields'] = fields
        if is_root is not None:
            query['is_svm_root'] = is_root

        volumes_response = self.send_request(
            '/storage/volumes/', 'get', query=query)

        records = volumes_response.get('records', [])
        if len(records) != 1:
            msg = _('Could not find unique share. Shares found: %(shares)s.')
            msg_args = {'shares': records}
            raise exception.NetAppException(message=msg % msg_args)

        return records[0]

    @na_utils.trace
    def restore_snapshot(self, volume_name, snapshot_name):
        """Reverts a volume to the specified snapshot."""

        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        body = {
            'restore_to.snapshot.name': snapshot_name
        }

        # Update volume
        self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

    @na_utils.trace
    def vserver_exists(self, vserver_name):
        """Checks if Vserver exists."""
        LOG.debug('Checking if Vserver %s exists', vserver_name)

        query = {
            'name': vserver_name
        }

        try:
            result = self.send_request('/svm/svms', 'get', query=query,
                                       enable_tunneling=False)
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_VSERVER_NOT_FOUND:
                return False
            else:
                raise
        return self._has_records(result)

    @na_utils.trace
    def list_root_aggregates(self):
        """Get names of all aggregates that contain node root volumes."""
        response = self.send_request('/private/cli/aggr', 'get',
                                     query={'root': 'true'})
        return [aggr['aggregate'] for aggr in response['records']]

    @na_utils.trace
    def list_non_root_aggregates(self):
        """Get names of all aggregates that don't contain node root volumes."""

        # NOTE(nahimsouza): According to REST API doc, only data aggregates are
        # returned by the /storage/aggregates endpoint, which means no System
        # owned root aggregate will be included in the output. Also, note that
        # this call does not work for users with SVM scoped account.
        response = self.send_request('/storage/aggregates', 'get')
        aggr_list = response['records']

        return [aggr['name'] for aggr in aggr_list]

    @na_utils.trace
    def get_cluster_aggregate_capacities(self, aggregate_names):
        """Calculates capacity of one or more aggregates.

        Returns dictionary of aggregate capacity metrics.
        'used' is the actual space consumed on the aggregate.
        'available' is the actual space remaining.
        'size' is the defined total aggregate size, such that
        used + available = total.
        """
        if aggregate_names is not None and len(aggregate_names) == 0:
            return {}

        fields = 'name,space'
        aggrs = self._get_aggregates(aggregate_names=aggregate_names,
                                     fields=fields)
        aggr_space_dict = dict()
        for aggr in aggrs:
            aggr_name = aggr['name']
            aggr_space_attrs = aggr['space']

            aggr_space_dict[aggr_name] = {
                'available':
                    int(aggr_space_attrs["block_storage"]["available"]),
                'total':
                    int(aggr_space_attrs["block_storage"]["size"]),
                'used':
                    int(aggr_space_attrs["block_storage"]["used"]),
            }
        return aggr_space_dict

    @na_utils.trace
    def _get_aggregates(self, aggregate_names=None, fields=None):
        """Get a list of aggregates and their attributes.

        :param aggregate_names: List of aggregate names.
        :param fields: List of fields to be retrieved from each aggregate.

        :return: List of aggregates.
        """

        query = {}
        if aggregate_names:
            query['name'] = ','.join(aggregate_names)

        if fields:
            query['fields'] = fields

        # NOTE(nahimsouza): This endpoint returns only data aggregates. Also,
        # it does not work with SVM scoped account.
        response = self.send_request('/storage/aggregates', 'get', query=query)

        if not self._has_records(response):
            return []
        else:
            return response.get('records', [])

    @na_utils.trace
    def get_aggregate(self, aggregate_name):
        """Get aggregate attributes needed for the storage service catalog."""

        if not aggregate_name:
            return {}

        fields = ('name,block_storage.primary.raid_type,'
                  'block_storage.storage_type')

        try:
            aggrs = self._get_aggregates(aggregate_names=[aggregate_name],
                                         fields=fields)
        except netapp_api.api.NaApiError:
            LOG.exception('Failed to get info for aggregate %s.',
                          aggregate_name)
            return {}

        if len(aggrs) == 0:
            return {}

        aggr_attributes = aggrs[0]

        aggregate = {
            'name': aggr_attributes['name'],
            'raid-type':
                aggr_attributes['block_storage']['primary']['raid_type'],
            'is-hybrid':
                aggr_attributes['block_storage']['storage_type'] == 'hybrid',
        }

        return aggregate

    @na_utils.trace
    def get_node_for_aggregate(self, aggregate_name):
        """Get home node for the specified aggregate.

        This API could return None, most notably if it was sent
        to a Vserver LIF, so the caller must be able to handle that case.
        """

        if not aggregate_name:
            return None

        fields = 'name,home_node.name'

        try:
            aggrs = self._get_aggregates(aggregate_names=[aggregate_name],
                                         fields=fields)
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_NOT_AUTHORIZED:
                LOG.debug("Could not get the home node of aggregate %s: "
                          "command not authorized.", aggregate_name)
                return None
            else:
                raise

        return aggrs[0]['home_node']['name'] if aggrs else None

    @na_utils.trace
    def get_aggregate_disk_types(self, aggregate_name):
        """Get the disk type(s) of an aggregate."""

        disk_types = set()
        disk_types.update(self._get_aggregate_disk_types(aggregate_name))

        return list(disk_types) if disk_types else None

    @na_utils.trace
    def _get_aggregate_disk_types(self, aggregate_name):
        """Get the disk type(s) of an aggregate (may be a list)."""

        disk_types = set()

        query = {
            'aggregates.name': aggregate_name,
            'fields': 'effective_type'
        }

        try:
            response = self.send_request(
                '/storage/disks', 'get', query=query)
        except netapp_api.api.NaApiError:
            LOG.exception('Failed to get disk info for aggregate %s.',
                          aggregate_name)

            return disk_types

        for storage_disk_info in response['records']:
            disk_types.add(storage_disk_info['effective_type'])

        return disk_types

    @na_utils.trace
    def volume_exists(self, volume_name):
        """Checks if volume exists."""
        LOG.debug('Checking if volume %s exists', volume_name)

        query = {
            'name': volume_name
        }

        result = self.send_request(
            '/storage/volumes', 'get', query=query)
        return self._has_records(result)

    @na_utils.trace
    def list_vserver_aggregates(self):
        """Returns a list of aggregates available to a vserver.

        This must be called against a Vserver LIF.
        """
        return list(self.get_vserver_aggregate_capacities().keys())

    @na_utils.trace
    def get_vserver_aggregate_capacities(self, aggregate_names=None):
        """Calculates capacity of one or more aggregates for a vserver.

        Returns dictionary of aggregate capacity metrics. This must
        be called against a Vserver LIF.
        """

        if aggregate_names is not None and len(aggregate_names) == 0:
            return {}

        query = {
            'fields': 'name,aggregates.name,aggregates.available_size'
        }
        response = self.send_request('/svm/svms', 'get', query=query)

        if not response['records']:
            msg = _('Could not find information of vserver.')
            raise exception.NetAppException(message=msg)
        vserver = response['records'][0]

        aggr_space_dict = dict()
        for aggr in vserver.get('aggregates', []):
            available_size = aggr.get('available_size')
            if available_size is None:
                # NOTE(felipe_rodrigues): available_size not returned means
                # the vserver does not have any aggregate assigned to it. REST
                # API returns all non root aggregates of the cluster to vserver
                # that does not have any, but without the space information.
                LOG.warning('No aggregates assigned to Vserver %s.',
                            vserver['name'])
                return {}

            aggr_name = aggr['name']
            if aggregate_names is None or aggr_name in aggregate_names:
                aggr_space_dict[aggr['name']] = {'available': available_size}

        if not aggr_space_dict:
            LOG.warning('No aggregates assigned to Vserver %s.',
                        vserver['name'])
            return {}

        LOG.debug('Found available Vserver aggregates: %s.', aggr_space_dict)
        return aggr_space_dict

    @na_utils.trace
    def qos_policy_group_create(self, qos_policy_group_name, vserver,
                                max_throughput=None):
        """Creates a QoS policy group."""

        body = {
            'name': qos_policy_group_name,
            'svm.name': vserver,
        }
        if max_throughput:
            value = max_throughput.lower()
            if 'iops' in max_throughput:
                value = value.replace('iops', '')
                value = int(value)
                body['fixed.max_throughput_iops'] = value
            else:
                value = value.replace('b/s', '')
                value = int(value)
                body['fixed.max_throughput_mbps'] = math.ceil(value /
                                                              units.Mi)
        return self.send_request('/storage/qos/policies', 'post',
                                 body=body)

    @na_utils.trace
    def list_network_interfaces(self):
        """Get the names of available LIFs."""

        query = {
            'fields': 'name'
        }

        result = self.send_request('/network/ip/interfaces', 'get',
                                   query=query)

        if self._has_records(result):
            return [lif['name'] for lif in result.get('records', [])]

    @na_utils.trace
    def get_network_interfaces(self, protocols=None):
        """Get available LIFs."""

        protocols = na_utils.convert_to_list(protocols)
        protocols = [f"data_{protocol.lower()}" for protocol in protocols]

        if protocols:
            query = {
                'services': ','.join(protocols),
                'fields': 'ip.address,location.home_node.name,'
                          'location.home_port.name,ip.netmask,'
                          'services,svm.name'
            }
        else:
            query = {
                'fields': 'ip.address,location.home_node.name,'
                          'location.home_port.name,ip.netmask,'
                          'services,svm.name'
            }

        result = self.send_request('/network/ip/interfaces', 'get',
                                   query=query)

        interfaces = []
        for lif_info in result.get('records', []):
            lif = {
                'uuid': lif_info['uuid'],
                'address': lif_info['ip']['address'],
                'home-node': lif_info['location']['home_node']['name'],
                'home-port': lif_info['location']['home_port']['name'],
                'interface-name': lif_info['name'],
                'netmask': lif_info['ip']['netmask'],
                'role': lif_info['services'],
                'vserver': lif_info['svm']['name'],
            }
            interfaces.append(lif)
        return interfaces

    @na_utils.trace
    def clear_nfs_export_policy_for_volume(self, volume_name):
        """Clear NFS export policy for volume, i.e. sets it to default."""
        self.set_nfs_export_policy_for_volume(volume_name, 'default')

    @na_utils.trace
    def set_nfs_export_policy_for_volume(self, volume_name, policy_name):
        """Set NFS the export policy for the specified volume."""
        query = {"name": volume_name}
        body = {'nas.export_policy.name': policy_name}

        try:
            self.send_request('/storage/volumes/', 'patch', query=query,
                              body=body)
        except netapp_api.api.NaApiError as e:
            # NOTE(nahimsouza): Since this error is ignored in ZAPI, we are
            # replicating the behavior here.
            if e.code == netapp_api.EREST_CANNOT_MODITY_OFFLINE_VOLUME:
                LOG.debug('Cannot modify offline volume: %s', volume_name)
                return

    @na_utils.trace
    def create_nfs_export_policy(self, policy_name):
        """Create an NFS export policy."""
        body = {'name': policy_name}
        try:
            self.send_request('/protocols/nfs/export-policies', 'post',
                              body=body)
        except netapp_api.api.NaApiError as e:
            if e.code != netapp_api.EREST_DUPLICATE_ENTRY:
                msg = _("Create NFS export policy %s fail.")
                LOG.debug(msg, policy_name)
                raise

    @na_utils.trace
    def soft_delete_nfs_export_policy(self, policy_name):
        """Try to delete export policy or mark it to be deleted later."""
        try:
            self.delete_nfs_export_policy(policy_name)
        except netapp_api.api.NaApiError:
            # NOTE(cknight): Policy deletion can fail if called too soon after
            # removing from a flexvol. So rename for later harvesting.
            LOG.warning("Fail to delete NFS export policy %s."
                        "Export policy will be renamed instead.", policy_name)
            self.rename_nfs_export_policy(policy_name,
                                          DELETED_PREFIX + policy_name)

    @na_utils.trace
    def rename_nfs_export_policy(self, policy_name, new_policy_name):
        """Rename NFS export policy."""
        response = self.send_request(
            '/protocols/nfs/export-policies', 'get',
            query={'name': policy_name})

        if not self._has_records(response):
            msg = _('Could not rename policy %(policy_name)s. '
                    'Entry does not exist.')
            msg_args = {'policy_name': policy_name}
            raise exception.NetAppException(msg % msg_args)

        uuid = response['records'][0]['id']
        body = {'name': new_policy_name}
        self.send_request(f'/protocols/nfs/export-policies/{uuid}',
                          'patch', body=body)

    @na_utils.trace
    def get_volume_junction_path(self, volume_name, is_style_cifs=False):
        """Gets a volume junction path."""
        query = {
            'name': volume_name,
            'fields': 'nas.path'
        }
        result = self.send_request('/storage/volumes/', 'get', query=query)
        return result['records'][0]['nas']['path']

    @na_utils.trace
    def get_volume(self, volume_name):
        """Returns the volume with the specified name, if present."""
        query = {
            'name': volume_name,
            'fields': 'aggregates.name,nas.path,name,svm.name,type,style,'
                      'qos.policy.name,space.size'
        }

        result = self.send_request('/storage/volumes', 'get', query=query)

        if not self._has_records(result):
            raise exception.StorageResourceNotFound(name=volume_name)
        elif result['num_records'] > 1:
            msg = _('Could not find unique volume %(vol)s.')
            msg_args = {'vol': volume_name}
            raise exception.NetAppException(msg % msg_args)

        volume_infos = result['records'][0]
        aggregates = volume_infos.get('aggregates', [])

        if len(aggregates) == 0:
            aggregate = ''
            aggregate_list = []
        else:
            aggregate = aggregates[0]['name']
            aggregate_list = [aggr['name'] for aggr in aggregates]

        volume = {
            'aggregate': aggregate,
            'aggr-list': aggregate_list,
            'junction-path': volume_infos.get('nas', {}).get('path'),
            'name': volume_infos.get('name'),
            'owning-vserver-name': volume_infos.get('svm', {}).get('name'),
            'type': volume_infos.get('type'),
            'style': volume_infos.get('style'),
            'size': volume_infos.get('space', {}).get('size'),
            'qos-policy-group-name': (
                volume_infos.get('qos', {}).get('policy', {}).get('name')),
            'style-extended': volume_infos.get('style')
        }
        return volume

    @na_utils.trace
    def cifs_share_exists(self, share_name):
        """Check that a CIFS share already exists."""
        share_path = f'/{share_name}'
        query = {
            'name': share_name,
            'path': share_path,
        }
        result = self.send_request('/protocols/cifs/shares', 'get',
                                   query=query)
        return self._has_records(result)

    @na_utils.trace
    def create_cifs_share(self, share_name, path):
        """Create a CIFS share."""
        body = {
            'name': share_name,
            'path': path,
            'svm.name': self.vserver,
        }
        self.send_request('/protocols/cifs/shares', 'post', body=body)

    @na_utils.trace
    def set_volume_security_style(self, volume_name, security_style='unix'):
        """Set volume security style"""

        query = {
            'name': volume_name,
        }
        body = {
            'nas.security_style': security_style
        }
        self.send_request('/storage/volumes', 'patch', body=body, query=query)

    @na_utils.trace
    def remove_cifs_share_access(self, share_name, user_name):
        """Remove CIFS share access."""
        query = {
            'name': share_name,
            'fields': 'svm.uuid'
        }
        get_uuid = self.send_request('/protocols/cifs/shares', 'get',
                                     query=query)
        svm_uuid = get_uuid['records'][0]['svm']['uuid']

        self.send_request(
            f'/protocols/cifs/shares/{svm_uuid}/{share_name}'
            f'/acls/{user_name}/{CIFS_USER_GROUP_TYPE}', 'delete')

    # TODO(caique): when ZAPI is dropped, this method should be removed and
    # the callers should start calling directly the "create_volume_async"
    @na_utils.trace
    def create_volume(self, aggregate_name, volume_name, size_gb,
                      thin_provisioned=False, snapshot_policy=None,
                      language=None, dedup_enabled=False,
                      compression_enabled=False, max_files=None,
                      snapshot_reserve=None, volume_type='rw',
                      qos_policy_group=None, adaptive_qos_policy_group=None,
                      encrypt=False, **options):
        """Creates a FlexVol volume synchronously."""

        # NOTE(nahimsouza): In REST API, both FlexVol and FlexGroup volumes are
        # created asynchronously. However, we kept the synchronous process for
        # FlexVols to replicate the behavior from ZAPI and avoid changes in the
        # layers above.
        self.create_volume_async(
            [aggregate_name], volume_name, size_gb, is_flexgroup=False,
            thin_provisioned=thin_provisioned, snapshot_policy=snapshot_policy,
            language=language, max_files=max_files,
            snapshot_reserve=snapshot_reserve, volume_type=volume_type,
            qos_policy_group=qos_policy_group, encrypt=encrypt,
            adaptive_qos_policy_group=adaptive_qos_policy_group, **options)

        self.update_volume_efficiency_attributes(volume_name,
                                                 dedup_enabled,
                                                 compression_enabled)
        if max_files is not None:
            self.set_volume_max_files(volume_name, max_files)

    @na_utils.trace
    def create_volume_async(self, aggregate_list, volume_name, size_gb,
                            is_flexgroup=False, thin_provisioned=False,
                            snapshot_policy=None,
                            language=None, snapshot_reserve=None,
                            volume_type='rw', qos_policy_group=None,
                            encrypt=False, adaptive_qos_policy_group=None,
                            auto_provisioned=False, **options):
        """Creates FlexGroup/FlexVol volumes.

        If the parameter `is_flexgroup` is False, the creation process is
        made synchronously to replicate ZAPI behavior for FlexVol creation.

        """

        body = {
            'size': size_gb * units.Gi,
            'name': volume_name,
        }

        body['style'] = 'flexgroup' if is_flexgroup else 'flexvol'

        if aggregate_list and not auto_provisioned:
            body['aggregates'] = [{'name': aggr} for aggr in aggregate_list]

        body.update(self._get_create_volume_body(
            volume_name, thin_provisioned, snapshot_policy, language,
            snapshot_reserve, volume_type, qos_policy_group, encrypt,
            adaptive_qos_policy_group))

        # NOTE(nahimsouza): When a volume is not a FlexGroup, volume creation
        # is made synchronously to replicate old ZAPI behavior. When ZAPI is
        # deprecated, this can be changed to be made asynchronously.
        wait_on_accepted = (not is_flexgroup)
        result = self.send_request('/storage/volumes', 'post', body=body,
                                   wait_on_accepted=wait_on_accepted)

        job_info = {
            'jobid': result.get('job', {}).get('uuid', {}),
            # NOTE(caiquemello): remove error-code and error-message
            # when zapi is dropped.
            'error-code': '',
            'error-message': ''
        }

        return job_info

    @na_utils.trace
    def _get_create_volume_body(self, volume_name, thin_provisioned,
                                snapshot_policy, language, snapshot_reserve,
                                volume_type, qos_policy_group, encrypt,
                                adaptive_qos_policy_group):
        """Builds the body to volume creation request."""

        body = {
            'type': volume_type,
            'guarantee.type': ('none' if thin_provisioned else 'volume'),
            'svm.name': self.connection.get_vserver()
        }
        if volume_type != 'dp':
            body['nas.path'] = f'/{volume_name}'
        if snapshot_policy is not None:
            body['snapshot_policy.name'] = snapshot_policy
        if language is not None:
            body['language'] = language
        if snapshot_reserve is not None:
            body['space.snapshot.reserve_percent'] = str(snapshot_reserve)
        if qos_policy_group is not None:
            body['qos.policy.name'] = qos_policy_group
        if adaptive_qos_policy_group is not None:
            body['qos.policy.name'] = adaptive_qos_policy_group

        if encrypt is True:
            if not self.features.FLEXVOL_ENCRYPTION:
                msg = 'Flexvol encryption is not supported on this backend.'
                raise exception.NetAppException(msg)
            else:
                body['encryption.enabled'] = 'true'
        else:
            body['encryption.enabled'] = 'false'

        return body

    @na_utils.trace
    def get_job_state(self, job_id):
        """Returns job state for a given job id."""
        query = {
            'uuid': job_id,
            'fields': 'state'
        }

        result = self.send_request('/cluster/jobs/', 'get', query=query,
                                   enable_tunneling=False)

        job_info = result.get('records', [])

        if not self._has_records(result):
            msg = _('Could not find job with ID %(id)s.')
            msg_args = {'id': job_id}
            raise exception.NetAppException(msg % msg_args)
        elif len(job_info) > 1:
            msg = _('Could not find unique job for ID %(id)s.')
            msg_args = {'id': job_id}
            raise exception.NetAppException(msg % msg_args)

        return job_info[0]['state']

    @na_utils.trace
    def get_volume_efficiency_status(self, volume_name):
        """Get dedupe & compression status for a volume."""
        query = {
            'efficiency.volume_path': f'/vol/{volume_name}',
            'fields': 'efficiency.state,efficiency.compression'
        }
        dedupe = False
        compression = False
        try:
            response = self.send_request('/storage/volumes', 'get',
                                         query=query)
            if self._has_records(response):
                efficiency = response['records'][0]['efficiency']
                dedupe = (efficiency['state'] == 'enabled')
                compression = (efficiency['compression'] != 'none')
        except netapp_api.api.NaApiError:
            msg = _('Failed to get volume efficiency status for %s.')
            LOG.error(msg, volume_name)

        return {
            'dedupe': dedupe,
            'compression': compression,
        }

    @na_utils.trace
    def update_volume_efficiency_attributes(self, volume_name, dedup_enabled,
                                            compression_enabled,
                                            is_flexgroup=None):
        """Update dedupe & compression attributes to match desired values."""

        efficiency_status = self.get_volume_efficiency_status(volume_name)
        # cDOT compression requires dedup to be enabled
        dedup_enabled = dedup_enabled or compression_enabled
        # enable/disable dedup if needed
        if dedup_enabled and not efficiency_status['dedupe']:
            self.enable_dedupe_async(volume_name)
        elif not dedup_enabled and efficiency_status['dedupe']:
            self.disable_dedupe_async(volume_name)
        # enable/disable compression if needed
        if compression_enabled and not efficiency_status['compression']:
            self.enable_compression_async(volume_name)
        elif not compression_enabled and efficiency_status['compression']:
            self.disable_compression_async(volume_name)

    @na_utils.trace
    def enable_dedupe_async(self, volume_name):
        """Enable deduplication on FlexVol/FlexGroup volume asynchronously."""

        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        body = {
            'efficiency': {'dedupe': 'background'}
        }
        # update volume efficiency
        self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

    @na_utils.trace
    def disable_dedupe_async(self, volume_name):
        """Disable deduplication on FlexVol/FlexGroup volume asynchronously."""

        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        body = {
            'efficiency': {'dedupe': 'none'}
        }
        # update volume efficiency
        self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

    @na_utils.trace
    def enable_compression_async(self, volume_name):
        """Enable compression on FlexVol/FlexGroup volume asynchronously."""
        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        body = {
            'efficiency': {'compression': 'background'}
        }
        # update volume efficiency
        self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

    @na_utils.trace
    def disable_compression_async(self, volume_name):
        """Disable compression on FlexVol/FlexGroup volume asynchronously."""

        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        body = {
            'efficiency': {'compression': 'none'}
        }
        # update volume efficiency
        self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

    @na_utils.trace
    def set_volume_max_files(self, volume_name, max_files):
        """Set share file limit."""

        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        body = {
            'files.maximum': int(max_files)
        }

        self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

    @na_utils.trace
    def set_volume_snapdir_access(self, volume_name, hide_snapdir):
        """Set volume snapshot directory visibility."""

        try:
            volume = self._get_volume_by_args(vol_name=volume_name)
        except exception.NetAppException:
            msg = _('Could not find volume %s to set snapdir access')
            LOG.error(msg, volume_name)
            raise exception.SnapshotResourceNotFound(name=volume_name)

        uuid = volume['uuid']

        body = {
            'snapshot_directory_access_enabled': str(not hide_snapdir).lower()
        }

        self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

    @na_utils.trace
    def get_fpolicy_scopes(self, share_name, policy_name=None,
                           extensions_to_include=None,
                           extensions_to_exclude=None, shares_to_include=None):
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
        try:
            volume = self._get_volume_by_args(vol_name=share_name)
            svm_uuid = volume['svm']['uuid']

        except exception.NetAppException:
            LOG.debug('Could not find fpolicy. Share not found: %s.',
                      share_name)
            return []

        query = {}
        if policy_name:
            query['name'] = policy_name

        if shares_to_include:
            query['scope.include_shares'] = ','.join(
                [str(share) for share in shares_to_include])
        if extensions_to_include:
            query['scope.include_extension'] = ','.join(
                [str(ext_include) for ext_include in extensions_to_include])
        if extensions_to_exclude:
            query['scope.exclude_extension'] = ','.join(
                [str(ext_exclude) for ext_exclude in extensions_to_exclude])

        result = self.send_request(
            f'/protocols/fpolicy/{svm_uuid}/policies', 'get', query=query)

        fpolicy_scopes = []
        if self._has_records(result):
            for fpolicy_scope_result in result['records']:
                name = fpolicy_scope_result['name']
                policy_scope = fpolicy_scope_result.get('scope')
                if policy_scope:
                    ext_include = policy_scope.get('include_extension', [])
                    ext_exclude = policy_scope.get('exclude_extension', [])
                    shares_include = policy_scope.get('include_shares', [])

                    fpolicy_scopes.append({
                        'policy-name': name,
                        'file-extensions-to-include': ext_include,
                        'file-extensions-to-exclude': ext_exclude,
                        'shares-to-include': shares_include,
                    })

        return fpolicy_scopes

    @na_utils.trace
    def get_fpolicy_policies_status(self, share_name, policy_name=None,
                                    status='true'):
        """Get fpolicy polices status currently configured in the vserver·"""
        volume = self._get_volume_by_args(vol_name=share_name)
        svm_uuid = volume['svm']['uuid']
        query = {}
        if policy_name:
            query['name'] = policy_name
            query['enabled'] = status

        result = self.send_request(
            f'/protocols/fpolicy/{svm_uuid}/policies', 'get', query=query)

        fpolicy_status = []
        if self._has_records(result):
            for fpolicy_status_result in result['records']:
                name = fpolicy_status_result['name']
                status = fpolicy_status_result.get('enabled', '')
                seq = fpolicy_status_result.get('priority', '')
                fpolicy_status.append({
                    'policy-name': name,
                    'status': strutils.bool_from_string(status),
                    'sequence-number': int(seq)
                })

        return fpolicy_status

    @na_utils.trace
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
        volume = self._get_volume_by_args(vol_name=share_name)
        svm_uuid = volume['svm']['uuid']
        query = {}

        if policy_name:
            query['name'] = policy_name
        if engine_name:
            query['engine.name'] = engine_name
        if event_names:
            query['events'] = ','.join(
                [str(events) for events in event_names])

        result = self.send_request(
            f'/protocols/fpolicy/{svm_uuid}/policies', 'get', query=query)

        fpolicy_policies = []
        if self._has_records(result):
            for fpolicy_policies_result in result['records']:
                name = fpolicy_policies_result['name']
                engine = (fpolicy_policies_result.get(
                    'engine', {}).get('name', ''))
                events = ([event['name'] for event in
                           fpolicy_policies_result.get('events', [])])
                fpolicy_policies.append({
                    'policy-name': name,
                    'engine-name': engine,
                    'events': events
                })

        return fpolicy_policies

    @na_utils.trace
    def get_fpolicy_events(self, share_name, event_name=None, protocol=None,
                           file_operations=None):
        """Retrives a list of fpolicy events.

        :param event_name: name of the fpolicy event
        :param protocol: name of protocol. Possible values are: 'nfsv3',
            'nfsv4' or 'cifs'.
        :param file_operations: name of file operations to be monitored. Values
            should be provided as list of strings.
        :returns List of policy events or empty list
        """
        volume = self._get_volume_by_args(vol_name=share_name)
        svm_uuid = volume['svm']['uuid']
        query = {}
        if event_name:
            query['name'] = event_name
        if protocol:
            query['protocol'] = protocol
        if file_operations:
            query['fields'] = (','.join([str(f'file_operations.{file_op}')
                                         for file_op in file_operations]))

        result = self.send_request(
            f'/protocols/fpolicy/{svm_uuid}/events', 'get', query=query)

        fpolicy_events = []
        if self._has_records(result):
            for fpolicy_events_result in result['records']:
                name = fpolicy_events_result['name']
                proto = fpolicy_events_result.get('protocol', '')

                file_operations = []
                operations = fpolicy_events_result.get('file_operations', {})
                for key, value in operations.items():
                    if value:
                        file_operations.append(key)

                fpolicy_events.append({
                    'event-name': name,
                    'protocol': proto,
                    'file-operations': file_operations
                })

        return fpolicy_events

    @na_utils.trace
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
        volume = self._get_volume_by_args(vol_name=share_name)
        svm_uuid = volume['svm']['uuid']
        body = {
            'name': event_name,
            'protocol': protocol,
        }
        for file_op in file_operations:
            body[f'file_operations.{file_op}'] = 'true'

        self.send_request(f'/protocols/fpolicy/{svm_uuid}/events', 'post',
                          body=body)

    @na_utils.trace
    def delete_fpolicy_event(self, share_name, event_name):
        """Deletes a fpolicy policy event.

        :param event_name: name of the event to be deleted
        :param share_name: name of share associated with the vserver where the
            fpolicy event should be deleted.
        """
        try:
            volume = self._get_volume_by_args(vol_name=share_name)
            svm_uuid = volume['svm']['uuid']
        except exception.NetAppException:
            msg = _("FPolicy event %s not found.")
            LOG.debug(msg, event_name)
            return
        try:
            self.send_request(
                f'/protocols/fpolicy/{svm_uuid}/events/{event_name}', 'delete')
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_ENTRY_NOT_FOUND:
                msg = _("FPolicy event %s not found.")
                LOG.debug(msg, event_name)
            else:
                raise exception.NetAppException(message=e.message)

    @na_utils.trace
    def delete_fpolicy_policy(self, share_name, policy_name):
        """Deletes a fpolicy policy.

        :param policy_name: name of the policy to be deleted.
        """
        try:
            volume = self._get_volume_by_args(vol_name=share_name)
            svm_uuid = volume['svm']['uuid']
        except exception.NetAppException:
            msg = _("FPolicy policy %s not found.")
            LOG.debug(msg, policy_name)
            return
        try:
            self.send_request(
                f'/protocols/fpolicy/{svm_uuid}/policies/{policy_name}',
                'delete')
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_ENTRY_NOT_FOUND:
                msg = _("FPolicy policy %s not found.")
                LOG.debug(msg, policy_name)
            else:
                raise exception.NetAppException(message=e.message)

    @na_utils.trace
    def enable_fpolicy_policy(self, share_name, policy_name, sequence_number):
        """Enables a specific named policy.

        :param policy_name: name of the policy to be enabled
        :param share_name: name of the share associated with the vserver and
            the fpolicy
        :param sequence_number: policy sequence number
        """
        volume = self._get_volume_by_args(vol_name=share_name)
        svm_uuid = volume['svm']['uuid']
        body = {
            'priority': sequence_number,
        }

        self.send_request(
            f'/protocols/fpolicy/{svm_uuid}/policies/{policy_name}', 'patch',
            body=body)

    @na_utils.trace
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
        volume = self._get_volume_by_args(vol_name=share_name)
        svm_uuid = volume['svm']['uuid']

        body = {}
        if policy_name:
            body['name'] = policy_name

        if shares_to_include:
            body['scope.include_shares'] = ','.join(
                [str(share) for share in shares_to_include])
        if extensions_to_include:
            body['scope.include_extension'] = ','.join(
                [str(ext_include) for ext_include in extensions_to_include])
        if extensions_to_exclude:
            body['scope.exclude_extension'] = ','.join(
                [str(ext_exclude) for ext_exclude in extensions_to_exclude])

        self.send_request(f'/protocols/fpolicy/{svm_uuid}/policies/',
                          'patch', body=body)

    @na_utils.trace
    def create_fpolicy_policy_with_scope(self, fpolicy_name, share_name,
                                         events, engine='native',
                                         extensions_to_include=None,
                                         extensions_to_exclude=None):
        """Creates a fpolicy policy resource with scopes.

        :param fpolicy_name: name of the fpolicy policy to be created.
        :param share_name: name of the share to be associated with the new
            scope.
        :param events: list of event names for file access monitoring.
        :param engine: name of the engine to be used.
        :param extensions_to_include: file extensions included for screening.
            Values should be provided as comma separated list
        :param extensions_to_exclude: file extensions excluded for screening.
            Values should be provided as comma separated list
        """
        volume = self._get_volume_by_args(vol_name=share_name)
        svm_uuid = volume['svm']['uuid']

        body = {
            'name': fpolicy_name,
            'events.name': events,
            'engine.name': engine,
            'scope.include_shares': [share_name]
        }

        if extensions_to_include:
            body['scope.include_extension'] = extensions_to_include.split(',')
        if extensions_to_exclude:
            body['scope.exclude_extension'] = extensions_to_exclude.split(',')

        self.send_request(f'/protocols/fpolicy/{svm_uuid}/policies', 'post',
                          body=body)

    @na_utils.trace
    def delete_nfs_export_policy(self, policy_name):
        """Delete NFS export policy."""

        # Get policy id.
        query = {
            'name': policy_name,
        }
        response = self.send_request('/protocols/nfs/export-policies', 'get',
                                     query=query)
        if not response.get('records'):
            return
        policy_id = response.get('records')[0]['id']

        # Remove policy.
        self.send_request(f'/protocols/nfs/export-policies/{policy_id}',
                          'delete')

    @na_utils.trace
    def remove_cifs_share(self, share_name):
        """Remove CIFS share from the CIFS server."""

        # Get SVM UUID.
        query = {
            'name': self.vserver,
            'fields': 'uuid'
        }
        res = self.send_request('/svm/svms', 'get', query=query)
        if not res.get('records'):
            msg = _('Vserver %s not found.') % self.vserver
            raise exception.NetAppException(msg)
        svm_id = res.get('records')[0]['uuid']

        # Remove CIFS share.
        try:
            self.send_request(f'/protocols/cifs/shares/{svm_id}/{share_name}',
                              'delete')
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_ENTRY_NOT_FOUND:
                return
            raise

    @na_utils.trace
    def _unmount_volume(self, volume_name):
        """Unmounts a volume."""
        # Get volume UUID.
        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        # Unmount volume async operation.
        body = {"nas": {"path": ""}}
        self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

    @na_utils.trace
    # TODO(felipe_rodrigues): remove the force parameter when ZAPI is dropped.
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
                self._unmount_volume(volume_name)
                LOG.debug('Volume %s unmounted.', volume_name)
                return
            except netapp_api.api.NaApiError as e:
                if (e.code == netapp_api.EREST_UNMOUNT_FAILED_LOCK
                        and 'job ID' in e.message):
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
    def offline_volume(self, volume_name):
        """Offlines a volume."""
        # Get volume UUID.
        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        body = {'state': 'offline'}
        self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

    @na_utils.trace
    def delete_volume(self, volume_name):
        """Deletes a volume."""
        # Get volume UUID.
        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        # delete volume async operation.
        self.send_request(f'/storage/volumes/{uuid}', 'delete')

    @na_utils.trace
    def qos_policy_group_get(self, qos_policy_group_name):
        """Checks if a QoS policy group exists."""

        query = {
            'name': qos_policy_group_name,
            'fields': 'name,object_count,fixed.max_throughput_iops,'
                      'fixed.max_throughput_mbps,svm.name',
        }
        try:
            res = self.send_request('/storage/qos/policies', 'get',
                                    query=query)
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_NOT_AUTHORIZED:
                msg = _("Configured ONTAP login user cannot retrieve "
                        "QoS policies.")
                LOG.error(msg)
                raise exception.NetAppException(msg)
            else:
                raise

        if not res.get('records'):
            msg = _('QoS %s not found.') % qos_policy_group_name
            raise exception.NetAppException(msg)

        qos_policy_group_info = res.get('records')[0]
        policy_info = {
            'policy-group': qos_policy_group_info.get('name'),
            'vserver': qos_policy_group_info.get('svm', {}).get('name'),
            'num-workloads': int(qos_policy_group_info.get('object_count')),
        }

        iops = qos_policy_group_info.get('fixed', {}).get(
            'max_throughput_iops')
        mbps = qos_policy_group_info.get('fixed', {}).get(
            'max_throughput_mbps')

        if iops:
            policy_info['max-throughput'] = f'{iops}iops'
        elif mbps:
            policy_info['max-throughput'] = f'{mbps * 1024 * 1024}b/s'
        else:
            policy_info['max-throughput'] = None

        return policy_info

    @na_utils.trace
    def qos_policy_group_exists(self, qos_policy_group_name):
        """Checks if a QoS policy group exists."""
        try:
            self.qos_policy_group_get(qos_policy_group_name)
        except exception.NetAppException:
            return False
        return True

    @na_utils.trace
    def qos_policy_group_rename(self, qos_policy_group_name, new_name):
        """Renames a QoS policy group."""
        if qos_policy_group_name == new_name:
            return
        # Get QoS UUID.
        query = {
            'name': qos_policy_group_name,
            'fields': 'uuid',
        }
        res = self.send_request('/storage/qos/policies', 'get', query=query)
        if not res.get('records'):
            msg = _('QoS %s not found.') % qos_policy_group_name
            raise exception.NetAppException(msg)
        uuid = res.get('records')[0]['uuid']

        body = {"name": new_name}
        self.send_request(f'/storage/qos/policies/{uuid}', 'patch',
                          body=body)

    @na_utils.trace
    def remove_unused_qos_policy_groups(self):
        """Deletes all QoS policy groups that are marked for deletion."""
        # Get QoS policies.
        query = {
            'name': '%s*' % DELETED_PREFIX,
            'fields': 'uuid,name',
        }
        res = self.send_request('/storage/qos/policies', 'get', query=query)
        for qos in res.get('records'):
            uuid = qos['uuid']
            try:
                self.send_request(f'/storage/qos/policies/{uuid}', 'delete')
            except netapp_api.api.NaApiError as ex:
                msg = ('Could not delete QoS policy group %(qos_name)s. '
                       'Details: %(ex)s')
                msg_args = {'qos_name': qos['name'], 'ex': ex}
                LOG.debug(msg, msg_args)

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
            except netapp_api.api.NaApiError as ex:
                msg = ('Rename failure in cleanup of cDOT QoS policy '
                       'group %(name)s: %(ex)s')
                msg_args = {'name': qos_policy_group_name, 'ex': ex}
                LOG.warning(msg, msg_args)
            # Attempt to delete any QoS policies named "deleted_manila-*".
            self.remove_unused_qos_policy_groups()

    @na_utils.trace
    def qos_policy_group_modify(self, qos_policy_group_name, max_throughput):
        """Modifies a QoS policy group."""

        query = {
            'name': qos_policy_group_name,
        }
        body = {}
        value = max_throughput.lower()
        if 'iops' in value:
            value = value.replace('iops', '')
            value = int(value)
            body['fixed.max_throughput_iops'] = value
            body['fixed.max_throughput_mbps'] = 0
        elif 'b/s' in value:
            value = value.replace('b/s', '')
            value = int(value)
            body['fixed.max_throughput_mbps'] = math.ceil(value /
                                                          units.Mi)
            body['fixed.max_throughput_iops'] = 0
        res = self.send_request('/storage/qos/policies', 'get', query=query)
        if not res.get('records'):
            msg = ('QoS %s not found.') % qos_policy_group_name
            raise exception.NetAppException(msg)
        uuid = res.get('records')[0]['uuid']
        self.send_request(f'/storage/qos/policies/{uuid}', 'patch',
                          body=body)

    @na_utils.trace
    def set_volume_size(self, volume_name, size_gb):
        """Set volume size."""

        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        body = {
            'space.size': int(size_gb) * units.Gi
        }

        self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

    @na_utils.trace
    def set_volume_filesys_size_fixed(self,
                                      volume_name,
                                      filesys_size_fixed=False):
        """Set volume file system size fixed to true/false."""
        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']
        body = {
            'space.filesystem_size_fixed': filesys_size_fixed
        }
        self.send_request(f'/storage/volumes/{uuid}',
                          'patch', body=body)

    @na_utils.trace
    def create_snapshot(self, volume_name, snapshot_name):
        """Creates a volume snapshot."""

        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']
        body = {
            'name': snapshot_name,
        }
        self.send_request(f'/storage/volumes/{uuid}/snapshots', 'post',
                          body=body)

    @na_utils.trace
    def is_flexgroup_supported(self):
        return self.features.FLEXGROUP

    @na_utils.trace
    def is_flexgroup_volume(self, volume_name):
        """Determines if the ONTAP volume is FlexGroup."""

        query = {
            'name': volume_name,
            'fields': 'style'
        }
        result = self.send_request('/storage/volumes/', 'get', query=query)

        if not self._has_records(result):
            raise exception.StorageResourceNotFound(name=volume_name)

        vols = result.get('records', [])
        if len(vols) > 1:
            msg = _('More than one volume with volume name %(vol)s found.')
            msg_args = {'vol': volume_name}
            raise exception.NetAppException(msg % msg_args)

        return na_utils.is_style_extended_flexgroup(vols[0]['style'])

    @staticmethod
    def _is_busy_snapshot(snapshot_owners):
        """Checks if the owners means that the snapshot is busy.

        Snapshot is busy when any of the owners doesn't end with 'dependent'.
        """

        for owner in snapshot_owners:
            if not owner.endswith('dependent'):
                return True

        return False

    @na_utils.trace
    def get_snapshot(self, volume_name, snapshot_name):
        """Gets a single snapshot."""
        try:
            volume = self._get_volume_by_args(vol_name=volume_name)
        except exception.NetAppException:
            msg = _('Could not find volume %s to get snapshot')
            LOG.error(msg, volume_name)
            raise exception.SnapshotResourceNotFound(name=snapshot_name)

        uuid = volume['uuid']
        query = {
            'name': snapshot_name,
            'fields': 'name,volume,create_time,owners'
        }
        result = self.send_request(f'/storage/volumes/{uuid}/snapshots', 'get',
                                   query=query)

        if not self._has_records(result):
            raise exception.SnapshotResourceNotFound(name=snapshot_name)

        snapshots = result.get('records', [])
        if len(snapshots) > 1:
            msg = _('Could not find unique snapshot %(snap)s on '
                    'volume %(vol)s.')
            msg_args = {'snap': snapshot_name, 'vol': volume_name}
            raise exception.NetAppException(msg % msg_args)

        snapshot_info = snapshots[0]
        # NOTE(felipe_rodrigues): even requesting the field owners, it is not
        # sent back in case no owners.
        owners = set(snapshot_info.get('owners', []))
        return {
            'access-time': snapshot_info['create_time'],
            'name': snapshot_info['name'],
            'volume': snapshot_info['volume']['name'],
            'owners': owners,
            'busy': self._is_busy_snapshot(owners),
            'locked_by_clone': SNAPSHOT_CLONE_OWNER in owners,
        }

    @na_utils.trace
    def get_clone_children_for_snapshot(self, volume_name, snapshot_name):
        """Returns volumes that are keeping a snapshot locked."""

        query = {
            'clone.parent_snapshot.name': snapshot_name,
            'clone.parent_volume.name': volume_name,
            'fields': 'name'
        }
        result = self.get_records('/storage/volumes', query=query)

        return [{'name': volume['name']}
                for volume in result.get('records', [])]

    @na_utils.trace
    def split_volume_clone(self, volume_name):
        """Begins splitting a clone from its parent."""

        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']
        body = {
            'clone.split_initiated': 'true',
        }
        self.send_request(f'/storage/volumes/{uuid}', 'patch',
                          body=body, wait_on_accepted=False)

    @na_utils.trace
    def delete_snapshot(self, volume_name, snapshot_name, ignore_owners=False):
        """Deletes a volume snapshot."""

        try:
            volume = self._get_volume_by_args(vol_name=volume_name)
        except exception.NetAppException:
            msg = _('Could not find volume %s to delete snapshot')
            LOG.warning(msg, volume_name)
            return
        uuid = volume['uuid']

        query = {
            'name': snapshot_name,
            'fields': 'uuid'
        }
        snapshot = self.send_request(f'/storage/volumes/{uuid}/snapshots',
                                     'get', query=query)
        if self._has_records(snapshot):
            snapshot_uuid = snapshot['records'][0]['uuid']
            # NOTE(rfluisa): The CLI passthrough was used here, because the
            # REST API endpoint used to delete snapshots does not an equivalent
            #  to the ignore_owners field

            if ignore_owners:
                query_cli = {
                    'vserver': self.vserver,
                    'volume': volume_name,
                    'snapshot': snapshot_name,
                    'ignore-owners': 'true'
                }
                self.send_request(
                    '/private/cli/snapshot', 'delete', query=query_cli)
            else:
                self.send_request(
                    f'/storage/volumes/{uuid}/snapshots/{snapshot_uuid}',
                    'delete')

    @na_utils.trace
    def rename_snapshot(self, volume_name, snapshot_name, new_snapshot_name):
        """Renames the snapshot."""

        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']
        query = {
            'name': snapshot_name,
        }
        body = {
            'name': new_snapshot_name,
        }
        self.send_request(f'/storage/volumes/{uuid}/snapshots', 'patch',
                          query=query, body=body)

    @na_utils.trace
    def _get_soft_deleted_snapshots(self):
        """Returns non-busy, soft-deleted snapshots suitable for reaping."""

        query = {
            'name': DELETED_PREFIX + '*',
            'fields': 'uuid,volume,owners,svm.name'
        }
        result = self.get_records('/storage/volumes/*/snapshots', query=query)

        snapshot_map = {}
        for snapshot_info in result.get('records', []):
            if self._is_busy_snapshot(snapshot_info['owners']):
                continue

            vserver = snapshot_info['svm']['name']
            snapshot_list = snapshot_map.get(vserver, [])
            snapshot_list.append({
                'uuid': snapshot_info['uuid'],
                'volume_uuid': snapshot_info['volume']['uuid'],
            })
            snapshot_map[vserver] = snapshot_list

        return snapshot_map

    @na_utils.trace
    def prune_deleted_snapshots(self):
        """Deletes non-busy snapshots that were previously soft-deleted."""

        deleted_snapshots_map = self._get_soft_deleted_snapshots()

        for vserver in deleted_snapshots_map:
            client = copy.deepcopy(self)
            client.set_vserver(vserver)

            for snapshot in deleted_snapshots_map[vserver]:
                try:
                    vol_uuid = snapshot['volume_uuid']
                    snap_uuid = snapshot['uuid']
                    self.send_request(f'/storage/volumes/{vol_uuid}/snapshots/'
                                      f'{snap_uuid}', 'delete')
                except netapp_api.api.NaApiError:
                    msg = _('Could not delete snapshot %(snap)s on '
                            'volume %(volume)s.')
                    msg_args = {
                        'snap': snapshot['uuid'],
                        'volume': snapshot['volume_uuid'],
                    }
                    LOG.exception(msg, msg_args)

    @na_utils.trace
    def snapshot_exists(self, snapshot_name, volume_name):
        """Checks if Snapshot exists for a specified volume."""
        LOG.debug('Checking if snapshot %(snapshot)s exists for '
                  'volume %(volume)s',
                  {'snapshot': snapshot_name, 'volume': volume_name})

        volume = self._get_volume_by_args(vol_name=volume_name,
                                          fields='uuid,state')

        if volume['state'] == 'offline':
            msg = _('Could not read information for snapshot %(name)s. '
                    'Volume %(volume)s is offline.')
            msg_args = {
                'name': snapshot_name,
                'volume': volume_name,
            }
            LOG.debug(msg, msg_args)
            raise exception.SnapshotUnavailable(msg % msg_args)

        query = {'name': snapshot_name}
        vol_uuid = volume['uuid']
        result = self.send_request(
            f'/storage/volumes/{vol_uuid}/snapshots/', 'get', query=query)

        return self._has_records(result)

    @na_utils.trace
    def volume_has_luns(self, volume_name):
        """Checks if volume has LUNs."""
        LOG.debug('Checking if volume %s has LUNs', volume_name)

        query = {
            'location.volume.name': volume_name,
        }

        response = self.send_request('/storage/luns/', 'get', query=query)

        return self._has_records(response)

    @na_utils.trace
    def volume_has_junctioned_volumes(self, junction_path):
        """Checks if volume has volumes mounted beneath its junction path."""
        if not junction_path:
            return False

        query = {
            'nas.path': junction_path + '/*'
        }

        response = self.send_request('/storage/volumes/', 'get', query=query)
        return self._has_records(response)

    @na_utils.trace
    def set_volume_name(self, volume_name, new_volume_name):
        """Set volume name."""
        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        body = {
            'name': new_volume_name
        }

        self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

    @na_utils.trace
    def mount_volume(self, volume_name, junction_path=None):
        """Mounts a volume on a junction path."""
        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        body = {
            'nas.path': (junction_path if junction_path
                         else '/%s' % volume_name)
        }

        try:
            self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)
        except netapp_api.api.NaApiError as e:
            # NOTE(rfluisa): This verification was added to keep the error code
            # compatible with the one that was returned by ZAPI
            if e.code == netapp_api.EREST_SNAPMIRROR_INITIALIZING:
                raise netapp_api.api.NaApiError(message=e.message,
                                                code=netapp_api.api.EAPIERROR)
            raise

    @na_utils.trace
    def get_volume_at_junction_path(self, junction_path):
        """Returns the volume with the specified junction path, if present."""
        if not junction_path:
            return None

        query = {
            'nas.path': junction_path,
            'fields': 'name',
        }

        response = self.send_request('/storage/volumes/', 'get', query=query)

        if not self._has_records(response):
            return None

        vol = response.get('records')[0]

        volume = {
            'name': vol.get('name'),
        }
        return volume

    @na_utils.trace
    def get_aggregate_for_volume(self, volume_name):
        """Get the name of the aggregate containing a volume."""

        query = {
            'name': volume_name,
            'fields': 'aggregates',
        }

        res = self.send_request('/storage/volumes/', 'get', query=query)

        aggregate = res.get('aggregates')

        if not aggregate:
            msg = _('Could not find aggregate for volume %s.')
            raise exception.NetAppException(msg % volume_name)

        aggregate_size = len(res.get('aggregates'))

        if aggregate_size > 1:
            aggregate = [aggr.get('name') for aggr in res.get('aggregates')]

        return aggregate

    @na_utils.trace
    def get_volume_to_manage(self, aggregate_name, volume_name):
        """Get existing volume info to be managed."""

        query = {
            'name': volume_name,
            'fields': 'name,aggregates.name,nas.path,name,type,style,'
                      'svm.name,qos.policy.name,space.size',
            'aggregates.name': aggregate_name
        }

        response = self.send_request('/storage/volumes', 'get', query=query)
        if not self._has_records(response):
            return None

        res = response.get('records', [])[0]
        aggregate = ''
        aggr_list = []
        aggregate_size = len(res.get('aggregates', []))
        if aggregate_size == 1:
            aggregate = res.get('aggregates', [])[0].get('name', '')
        else:
            aggr_list = [aggr.get('name') for aggr in res.get('aggregates')]

        volume = {
            'aggregate': aggregate,
            'aggr-list': aggr_list,
            'junction-path': res.get('nas', {}).get('path', ''),
            'name': res.get('name'),
            'type': res.get('type'),
            # NOTE(caiquemello): REST no longer uses flex or infinitevol as
            # styles. In onder to keep compatibility style is set to 'flex'.
            'style': 'flex',
            'owning-vserver-name': res.get('svm', {}).get('name', ''),
            'size': res.get('space', {}).get('size', 0),
            'qos-policy-group-name': (
                res.get('qos', {}).get('policy', {}).get('name', ''))
        }

        return volume

    @na_utils.trace
    def _parse_timestamp(self, time_str):
        """Parse timestamp string into a number."""

        try:
            dt = datetime.fromisoformat(time_str)
            return dt.timestamp()
        except Exception:
            LOG.debug("Failed to parse timestamp: %s", time_str)
            raise

    @na_utils.trace
    def _get_snapmirrors(self, source_path=None, dest_path=None,
                         source_vserver=None, source_volume=None,
                         dest_vserver=None, dest_volume=None,
                         list_destinations_only=False,
                         enable_tunneling=True,
                         desired_attributes=None):
        """Get a list of snapmirrors."""

        fields = ['state', 'source.svm.name', 'source.path',
                  'destination.svm.name', 'destination.path',
                  'transfer.end_time', 'uuid', 'policy.type',
                  'transfer_schedule.name', 'transfer.state']

        query = {}
        query['fields'] = ','.join(fields)

        if source_path:
            query['source.path'] = source_path
        else:
            query_src_vol = source_volume if source_volume else '*'
            query_src_vserver = source_vserver if source_vserver else '*'
            query['source.path'] = query_src_vserver + ':' + query_src_vol

        if dest_path:
            query['destination.path'] = dest_path
        else:
            query_dst_vol = dest_volume if dest_volume else '*'
            query_dst_vserver = dest_vserver if dest_vserver else '*'
            query['destination.path'] = query_dst_vserver + ':' + query_dst_vol

        if list_destinations_only:
            query['list_destinations_only'] = 'true'

        response = self.send_request(
            '/snapmirror/relationships', 'get', query=query,
            enable_tunneling=enable_tunneling)

        snapmirrors = []
        for record in response.get('records', []):
            snapmirrors.append({
                'relationship-status': (
                    'idle'
                    if record.get('state') == 'snapmirrored'
                    else record.get('state')),
                'transferring-state': record.get('transfer', {}).get('state'),
                'mirror-state': record.get('state'),
                'schedule': record['transfer_schedule']['name'],
                'source-vserver': record['source']['svm']['name'],
                'source-volume': (record['source']['path'].split(':')[1] if
                                  record.get('source') else None),
                'destination-vserver': record['destination']['svm']['name'],
                'destination-volume': (
                    record['destination']['path'].split(':')[1]
                    if record.get('destination') else None),
                'last-transfer-end-timestamp':
                    (self._parse_timestamp(record['transfer']['end_time']) if
                     record.get('transfer', {}).get('end_time') else 0),
                'uuid': record['uuid'],
                'policy-type': record.get('policy', {}).get('type')
            })

        return snapmirrors

    @na_utils.trace
    def get_snapmirrors_svm(self, source_vserver=None, dest_vserver=None,
                            desired_attributes=None):
        """Get all snapmirrors from specified SVMs source/destination."""
        source_path = source_vserver + ':*' if source_vserver else None
        dest_path = dest_vserver + ':*' if dest_vserver else None
        return self.get_snapmirrors(source_path=source_path,
                                    dest_path=dest_path,
                                    desired_attributes=desired_attributes)

    @na_utils.trace
    def get_snapmirrors(self, source_path=None, dest_path=None,
                        source_vserver=None, dest_vserver=None,
                        source_volume=None, dest_volume=None,
                        desired_attributes=None, enable_tunneling=None,
                        list_destinations_only=None):
        """Gets one or more SnapMirror relationships.

        Either the source or destination info may be omitted.
        Desired attributes exists only to keep consistency with ZAPI client
        signature and has no effect in the output.
        """

        snapmirrors = self._get_snapmirrors(
            source_path=source_path,
            dest_path=dest_path,
            source_vserver=source_vserver,
            source_volume=source_volume,
            dest_vserver=dest_vserver,
            dest_volume=dest_volume,
            enable_tunneling=enable_tunneling,
            list_destinations_only=list_destinations_only)

        return snapmirrors

    @na_utils.trace
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
        except netapp_api.api.NaApiError:
            msg = ("Could not determine if volume %s is part of "
                   "existing snapmirror relationships.")
            LOG.exception(msg, volume['name'])
            has_snapmirrors = False

        return has_snapmirrors

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

        body = {
            'guarantee': {'type': 'none' if thin_provisioned else 'volume'}
        }

        if autosize_attributes:
            attributes = autosize_attributes
            body['autosize'] = {
                'mode': attributes['mode'],
                'grow_threshold': attributes['grow-threshold-percent'],
                'shrink_threshold': attributes['shrink-threshold-percent'],
                'maximum': attributes['maximum-size'],
                'minimum': attributes['minimum-size'],
            }

        if language:
            body['language'] = language

        if max_files:
            body['files'] = {'maximum': max_files}

        if snapshot_policy:
            body['snapshot_policy'] = {'name': snapshot_policy}

        qos_policy_name = qos_policy_group or adaptive_qos_policy_group
        if qos_policy_name:
            body['qos'] = {'policy': {'name': qos_policy_name}}

        if hide_snapdir in (True, False):
            # Value of hide_snapdir needs to be inverted for ZAPI parameter
            body['snapshot_directory_access_enabled'] = (
                str(not hide_snapdir).lower())

        aggregates = None
        if isinstance(aggregate_name, list):
            is_flexgroup = True
            aggregates = ','.join(aggregate_name)
        else:
            is_flexgroup = False
            aggregates = aggregate_name

        volume = self._get_volume_by_args(vol_name=volume_name,
                                          aggregate_name=aggregates)

        self.send_request('/storage/volumes/' + volume['uuid'],
                          'patch', body=body)

        # Efficiency options must be handled separately
        self.update_volume_efficiency_attributes(volume_name,
                                                 dedup_enabled,
                                                 compression_enabled,
                                                 is_flexgroup=is_flexgroup)

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
        :param cutover_action: can have one of [cutover_wait]. 'cutover_wait'
        to go into cutover manually.
        :param validation_only: If set to True, only validates if the volume
            move is possible, does not trigger data copy.
        :param encrypt_destination: If set to True, it encrypts the Flexvol
            after the volume move is complete.
        """
        body = {
            'movement.destination_aggregate.name': destination_aggregate,
        }
        # NOTE(caiquemello): In REST 'cutover_action'was deprecated. Now the
        # equivalant behavior is represented by 'movement.state'. The
        # equivalent in ZAPI for 'defer_on_failure' is the default value
        # for 'movement.state' in REST. So, there is no need to set 'defer' in
        # the body. Remove this behavior when ZAPI is removed.
        if cutover_action != 'defer':
            body['movement.state'] = CUTOVER_ACTION_MAP[cutover_action]

        query = {
            'name': volume_name,
        }

        if encrypt_destination is True:
            body['encryption.enabled'] = 'true'
        elif encrypt_destination is False:
            body['encryption.enabled'] = 'false'

        if validation_only:
            body['validate_only'] = 'true'

        self.send_request('/storage/volumes/', 'patch', query=query, body=body,
                          wait_on_accepted=False)

    @na_utils.trace
    def get_nfs_export_policy_for_volume(self, volume_name):
        """Get the actual export policy for a share."""

        query = {
            'name': volume_name,
            'fields': 'nas.export_policy.name'
        }

        response = self.send_request('/storage/volumes/', 'get', query=query)

        if not self._has_records(response):
            msg = _('Could not find export policy for volume %s.')
            raise exception.NetAppException(msg % volume_name)

        volume = response['records'][0]
        return volume['nas']['export_policy']['name']

    @na_utils.trace
    def get_unique_export_policy_id(self, policy_name):
        """Get export policy uuid for a given policy name"""

        get_uuid = self.send_request(
            '/protocols/nfs/export-policies', 'get',
            query={'name': policy_name})

        if not self._has_records(get_uuid):
            msg = _('Could not find export policy with name %s.')
            raise exception.NetAppException(msg % policy_name)

        uuid = get_uuid['records'][0]['id']
        return uuid

    @na_utils.trace
    def _get_nfs_export_rule_indices(self, policy_name, client_match):
        """Get index of the rule within the export policy."""

        uuid = self.get_unique_export_policy_id(policy_name)

        query = {
            'clients.match': client_match,
            'fields': 'clients.match,index'
        }

        response = self.send_request(
            f'/protocols/nfs/export-policies/{uuid}/rules',
            'get', query=query)

        rules = response['records']
        indices = [rule['index'] for rule in rules]
        indices.sort()
        return [str(i) for i in indices]

    @na_utils.trace
    def _add_nfs_export_rule(self, policy_name, client_match, readonly,
                             auth_methods):
        """Add rule to NFS export policy."""
        uuid = self.get_unique_export_policy_id(policy_name)
        body = {
            'clients': [{'match': client_match}],
            'ro_rule': [],
            'rw_rule': [],
            'superuser': []
        }

        for am in auth_methods:
            body['ro_rule'].append(am)
            body['rw_rule'].append(am)
            body['superuser'].append(am)
        if readonly:
            # readonly, overwrite with auth method 'never'
            body['rw_rule'] = ['never']

        self.send_request(f'/protocols/nfs/export-policies/{uuid}/rules',
                          'post', body=body)

    @na_utils.trace
    def _update_nfs_export_rule(self, policy_name, client_match, readonly,
                                rule_index, auth_methods):
        """Update rule of NFS export policy."""
        uuid = self.get_unique_export_policy_id(policy_name)
        body = {
            'client_match': client_match,
            'ro_rule': [],
            'rw_rule': [],
            'superuser': []
        }

        for am in auth_methods:
            body['ro_rule'].append(am)
            body['rw_rule'].append(am)
            body['superuser'].append(am)
        if readonly:
            # readonly, overwrite with auth method 'never'
            body['rw_rule'] = ['never']

        self.send_request(
            f'/protocols/nfs/export-policies/{uuid}/rules/{rule_index}',
            'patch', body=body)

    @na_utils.trace
    def _remove_nfs_export_rules(self, policy_name, rule_indices):
        """Remove rule from NFS export policy."""
        uuid = self.get_unique_export_policy_id(policy_name)
        for index in rule_indices:
            body = {
                'index': index
            }
            try:
                self.send_request(
                    f'/protocols/nfs/export-policies/{uuid}/rules/{index}',
                    'delete', body=body)
            except netapp_api.api.NaApiError as e:
                if e.code != netapp_api.EREST_ENTRY_NOT_FOUND:
                    msg = _("Fail to delete export rule %s.")
                    LOG.debug(msg, policy_name)
                    raise

    @na_utils.trace
    def get_cifs_share_access(self, share_name):
        """Get CIFS share access rules."""
        query = {
            'name': share_name,
        }
        get_uuid = self.send_request('/protocols/cifs/shares', 'get',
                                     query=query)
        svm_uuid = get_uuid['records'][0]['svm']['uuid']
        query = {'fields': 'user_or_group,permission'}
        result = self.send_request(
            f'/protocols/cifs/shares/{svm_uuid}/{share_name}/acls',
            'get', query=query)

        rules = {}
        for records in result["records"]:
            user_or_group = records['user_or_group']
            permission = records['permission']
            rules[user_or_group] = permission

        return rules

    @na_utils.trace
    def add_cifs_share_access(self, share_name, user_name, readonly):
        """Add CIFS share access rules."""
        query = {
            'name': share_name
        }

        get_uuid = self.send_request('/protocols/cifs/shares', 'get',
                                     query=query)
        svm_uuid = get_uuid['records'][0]['svm']['uuid']

        body = {
            'permission': 'read' if readonly else 'full_control',
            'user_or_group': user_name,
        }

        self.send_request(
            f'/protocols/cifs/shares/{svm_uuid}/{share_name}/acls',
            'post', body=body)

    @na_utils.trace
    def modify_cifs_share_access(self, share_name, user_name, readonly):
        """Modify CIFS share access rules."""
        query = {
            'name': share_name
        }

        get_uuid = self.send_request('/protocols/cifs/shares', 'get',
                                     query=query)
        svm_uuid = get_uuid['records'][0]['svm']['uuid']

        body = {
            'permission': 'read' if readonly else 'full_control',
        }

        self.send_request(
            f'/protocols/cifs/shares/{svm_uuid}/{share_name}'
            f'/acls/{user_name}/{CIFS_USER_GROUP_TYPE}', 'patch', body=body)

    @na_utils.trace
    def check_snaprestore_license(self):
        """Check SnapRestore license for SVM scoped user."""
        try:
            body = {
                'restore_to.snapshot.name': ''
            }
            query = {
                # NOTE(felipe_rodrigues): Acting over all volumes to prevent
                # entry not found error. So, the error comes either by license
                # not installed or snapshot not specified.
                'name': '*'
            }
            self.send_request('/storage/volumes', 'patch', body=body,
                              query=query)
        except netapp_api.api.NaApiError as e:
            LOG.debug('Fake restore snapshot request failed: %s', e)
            if e.code == netapp_api.EREST_LICENSE_NOT_INSTALLED:
                return False
            elif e.code == netapp_api.EREST_SNAPSHOT_NOT_SPECIFIED:
                return True
            else:
                # unexpected error.
                raise e

        # since it passed an empty snapshot, it should never get here.
        msg = _("Caught an unexpected behavior: the fake restore to "
                "snapshot request using all volumes and empty string "
                "snapshot as argument has not failed.")
        LOG.exception(msg)
        raise exception.NetAppException(msg)

    @na_utils.trace
    def trigger_volume_move_cutover(self, volume_name, vserver, force=True):
        """Triggers the cut-over for a volume in data motion."""
        query = {
            'name': volume_name
        }
        body = {
            'movement.state': 'cutover'
        }
        self.send_request('/storage/volumes/', 'patch',
                          query=query, body=body)

    @na_utils.trace
    def abort_volume_move(self, volume_name, vserver):
        """Abort volume move operation."""
        volume = self._get_volume_by_args(vol_name=volume_name)
        vol_uuid = volume['uuid']
        self.send_request(f'/storage/volumes/{vol_uuid}', 'patch')

    @na_utils.trace
    def get_volume_move_status(self, volume_name, vserver):
        """Gets the current state of a volume move operation."""

        fields = 'movement.percent_complete,movement.state'

        query = {
            'name': volume_name,
            'svm.name': vserver,
            'fields': fields
        }

        result = self.send_request('/storage/volumes/', 'get', query=query)

        if not self._has_records(result):
            msg = ("Volume %(vol)s in Vserver %(server)s is not part of any "
                   "data motion operations.")
            msg_args = {'vol': volume_name, 'server': vserver}
            raise exception.NetAppException(msg % msg_args)

        volume_move_info = result.get('records')[0]
        volume_movement = volume_move_info['movement']

        status_info = {
            'percent-complete': volume_movement.get('percent_complete', 0),
            'estimated-completion-time': '',
            'state': volume_movement['state'],
            'details': '',
            'cutover-action': '',
            'phase': volume_movement['state'],
        }

        return status_info

    @na_utils.trace
    def list_snapmirror_snapshots(self, volume_name, newer_than=None):
        """Gets SnapMirror snapshots on a volume."""

        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        query = {
            'owners': 'snapmirror_dependent',
        }

        if newer_than:
            query['create_time'] = '>' + newer_than

        response = self.send_request(
            f'/storage/volumes/{uuid}/snapshots/',
            'get', query=query)

        return [snapshot_info['name']
                for snapshot_info in response['records']]

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
    def _abort_snapmirror(self, source_path=None, dest_path=None,
                          source_vserver=None, dest_vserver=None,
                          source_volume=None, dest_volume=None,
                          clear_checkpoint=False):
        """Stops ongoing transfers for a SnapMirror relationship."""

        snapmirror = self.get_snapmirrors(
            source_path=source_path,
            dest_path=dest_path,
            source_vserver=source_vserver,
            source_volume=source_volume,
            dest_vserver=dest_vserver,
            dest_volume=dest_volume)
        if snapmirror:
            snapmirror_uuid = snapmirror[0]['uuid']

            query = {'state': 'transferring'}
            transfers = self.send_request('/snapmirror/relationships/' +
                                          snapmirror_uuid + '/transfers/',
                                          'get', query=query)

            if not transfers.get('records'):
                raise netapp_api.api.NaApiError(
                    code=netapp_api.EREST_ENTRY_NOT_FOUND)

            body = {'state': 'hard_aborted' if clear_checkpoint else 'aborted'}

            for transfer in transfers['records']:
                transfer_uuid = transfer['uuid']
                self.send_request('/snapmirror/relationships/' +
                                  snapmirror_uuid + '/transfers/' +
                                  transfer_uuid, 'patch', body=body)

    @na_utils.trace
    def delete_snapmirror_vol(self, source_vserver, source_volume,
                              dest_vserver, dest_volume):
        """Destroys a SnapMirror relationship between volumes."""
        self._delete_snapmirror(source_vserver=source_vserver,
                                dest_vserver=dest_vserver,
                                source_volume=source_volume,
                                dest_volume=dest_volume)

    @na_utils.trace
    def _delete_snapmirror(self, source_vserver=None, source_volume=None,
                           dest_vserver=None, dest_volume=None):
        """Deletes an SnapMirror relationship on destination."""
        query_uuid = {}
        query_uuid['source.path'] = source_vserver + ':' + source_volume
        query_uuid['destination.path'] = (dest_vserver + ':' +
                                          dest_volume)
        query_uuid['fields'] = 'uuid'

        response = self.send_request('/snapmirror/relationships/', 'get',
                                     query=query_uuid)

        records = response.get('records')

        if records:
            # 'destination_only' deletes the snapmirror on destination
            # but does not release it on source.
            query_delete = {"destination_only": "true"}

            snapmirror_uuid = records[0].get('uuid')
            self.send_request('/snapmirror/relationships/' +
                              snapmirror_uuid, 'delete',
                              query=query_delete)

    @na_utils.trace
    def get_snapmirror_destinations(self, source_path=None, dest_path=None,
                                    source_vserver=None, source_volume=None,
                                    dest_vserver=None, dest_volume=None,
                                    desired_attributes=None,
                                    enable_tunneling=None):
        """Gets one or more SnapMirror at source endpoint."""

        snapmirrors = self.get_snapmirrors(
            source_path=source_path,
            dest_path=dest_path,
            source_vserver=source_vserver,
            source_volume=source_volume,
            dest_vserver=dest_vserver,
            dest_volume=dest_volume,
            # NOTE (nahimsouza): From ONTAP 9.12.1 the snapmirror destinations
            # can only be retrieved with no tunneling.
            enable_tunneling=False,
            list_destinations_only=True)

        return snapmirrors

    @na_utils.trace
    def release_snapmirror_vol(self, source_vserver, source_volume,
                               dest_vserver, dest_volume,
                               relationship_info_only=False):
        """Removes a SnapMirror relationship on the source endpoint."""
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

        query = {}
        if relationship_info_only:
            query["source_info_only"] = 'true'
        else:
            query["source_only"] = 'true'

        if len(snapmirror_destinations_list) == 1:
            uuid = snapmirror_destinations_list[0].get("uuid")
            self.send_request(f'/snapmirror/relationships/{uuid}', 'delete',
                              query=query)

    @na_utils.trace
    def disable_fpolicy_policy(self, policy_name):
        """Disables a specific policy.

        :param policy_name: name of the policy to be disabled
        """
        # Get SVM UUID.
        query = {
            'name': self.vserver,
            'fields': 'uuid'
        }
        res = self.send_request('/svm/svms', 'get', query=query,
                                enable_tunneling=False)
        if not res.get('records'):
            msg = _('Vserver %s not found.') % self.vserver
            raise exception.NetAppException(msg)
        svm_id = res.get('records')[0]['uuid']
        try:
            self.send_request(f'/protocols/fpolicy/{svm_id}/policies'
                              f'/{policy_name}', 'patch')
        except netapp_api.api.NaApiError as e:
            if (e.code in [netapp_api.EREST_POLICY_ALREADY_DISABLED,
                           netapp_api.EREST_FPOLICY_MODIF_POLICY_DISABLED,
                           netapp_api.EREST_ENTRY_NOT_FOUND]):
                msg = _("FPolicy policy %s not found or already disabled.")
                LOG.debug(msg, policy_name)
            else:
                raise exception.NetAppException(message=e.message)

    @na_utils.trace
    def delete_fpolicy_scope(self, policy_name):
        """Delete fpolicy scope

        This method is not implemented since the REST API design does not allow
        for the deletion of the scope only. When deleting a fpolicy policy, the
        scope will be deleted along with it.
        """
        pass

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
    def _create_snapmirror(self, source_vserver, destination_vserver,
                           source_volume=None, destination_volume=None,
                           schedule=None, policy=None,
                           relationship_type=na_utils.DATA_PROTECTION_TYPE,
                           identity_preserve=None, max_transfer_rate=None):
        """Creates a SnapMirror relationship."""

        # NOTE(nahimsouza): Extended Data Protection (XDP) SnapMirror
        # relationships are the only relationship types that are supported
        # through the REST API. The arg relationship_type was kept due to
        # compatibility with ZAPI implementation.

        # NOTE(nahimsouza): The argument identity_preserve is always None
        # and it is not available on REST API. It was kept in the signature
        # due to compatilbity with ZAPI implementation.

        # TODO(nahimsouza): Tests what happens if volume is None. This happens
        # when a snapmirror from SVM is created.
        body = {
            'source': {
                'path': source_vserver + ':' + source_volume
            },
            'destination': {
                'path': destination_vserver + ':' + destination_volume
            }
        }

        if schedule:
            body['transfer_schedule.name'] = schedule

        if policy:
            body['policy.name'] = policy

        if max_transfer_rate is not None:
            body['throttle'] = max_transfer_rate

        try:
            self.send_request('/snapmirror/relationships/', 'post', body=body)
        except netapp_api.api.NaApiError as e:
            if e.code != netapp_api.EREST_ERELATION_EXISTS:
                LOG.debug('Failed to create snapmirror. Error: %s. Code: %s',
                          e.message, e.code)
                raise

    def _set_snapmirror_state(self, state, source_path, destination_path,
                              source_vserver, source_volume,
                              destination_vserver, destination_volume,
                              wait_result=True, schedule=None):
        """Change the snapmirror state between two volumes."""

        snapmirror = self.get_snapmirrors(source_path=source_path,
                                          dest_path=destination_path,
                                          source_vserver=source_vserver,
                                          source_volume=source_volume,
                                          dest_vserver=destination_vserver,
                                          dest_volume=destination_volume)

        if not snapmirror:
            msg = _('Failed to get information about relationship between '
                    'source %(src_vserver)s:%(src_volume)s and '
                    'destination %(dst_vserver)s:%(dst_volume)s.') % {
                'src_vserver': source_vserver,
                'src_volume': source_volume,
                'dst_vserver': destination_vserver,
                'dst_volume': destination_volume}

            raise na_utils.NetAppDriverException(msg)

        uuid = snapmirror[0]['uuid']
        body = {}
        if state:
            body.update({'state': state})
        if schedule:
            body.update({"transfer_schedule": {'name': schedule}})

        result = self.send_request(f'/snapmirror/relationships/{uuid}',
                                   'patch', body=body,
                                   wait_on_accepted=wait_result)

        job = result['job']
        job_info = {
            'operation-id': None,
            'status': None,
            'jobid': job.get('uuid'),
            'error-code': None,
            'error-message': None,
            'relationship-uuid': uuid,
        }

        return job_info

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
    def _initialize_snapmirror(self, source_path=None, dest_path=None,
                               source_vserver=None, dest_vserver=None,
                               source_volume=None, dest_volume=None,
                               source_snapshot=None, transfer_priority=None):
        """Initializes a SnapMirror relationship."""

        # NOTE(nahimsouza): The args source_snapshot and transfer_priority are
        # always None and they are not available on REST API, they were
        # kept in the signature due to compatilbity with ZAPI implementation.

        return self._set_snapmirror_state(
            'snapmirrored', source_path, dest_path,
            source_vserver, source_volume,
            dest_vserver, dest_volume, wait_result=False)

    @na_utils.trace
    def modify_snapmirror_vol(self, source_vserver, source_volume,
                              dest_vserver, dest_volume,
                              schedule=None, policy=None, tries=None,
                              max_transfer_rate=None):
        """Modifies a SnapMirror relationship between volumes."""
        return self._modify_snapmirror(
            source_vserver=source_vserver, dest_vserver=dest_vserver,
            source_volume=source_volume, dest_volume=dest_volume,
            schedule=schedule)

    @na_utils.trace
    def _modify_snapmirror(self, source_path=None, dest_path=None,
                           source_vserver=None, dest_vserver=None,
                           source_volume=None, dest_volume=None,
                           schedule=None):
        """Modifies a SnapMirror relationship."""
        return self._set_snapmirror_state(
            None, source_path, dest_path,
            source_vserver, source_volume,
            dest_vserver, dest_volume, wait_result=False,
            schedule=schedule)

    @na_utils.trace
    def create_volume_clone(self, volume_name, parent_volume_name,
                            parent_snapshot_name=None, split=False,
                            qos_policy_group=None,
                            adaptive_qos_policy_group=None,
                            **options):
        """Create volume clone in the same aggregate as parent volume."""

        body = {
            'name': volume_name,
            'clone.parent_volume.name': parent_volume_name,
            'clone.parent_snapshot.name': parent_snapshot_name,
            'nas.path': '/%s' % volume_name,
            'clone.is_flexclone': 'true',
            'svm.name': self.connection.get_vserver(),
        }

        self.send_request('/storage/volumes', 'post', body=body)

        # NOTE(nahimsouza): QoS policy can not be set during the cloning
        # process, so we need to make a separate request.
        if qos_policy_group is not None:
            volume = self._get_volume_by_args(vol_name=volume_name)
            uuid = volume['uuid']
            body = {
                'qos.policy.name': qos_policy_group,
            }
            self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

        if split:
            self.split_volume_clone(volume_name)

        if adaptive_qos_policy_group is not None:
            self.set_qos_adaptive_policy_group_for_volume(
                volume_name, adaptive_qos_policy_group)

    @na_utils.trace
    def quiesce_snapmirror_vol(self, source_vserver, source_volume,
                               dest_vserver, dest_volume):
        """Disables future transfers to a SnapMirror destination."""
        self._quiesce_snapmirror(source_vserver=source_vserver,
                                 dest_vserver=dest_vserver,
                                 source_volume=source_volume,
                                 dest_volume=dest_volume)

    @na_utils.trace
    def _quiesce_snapmirror(self, source_path=None, dest_path=None,
                            source_vserver=None, dest_vserver=None,
                            source_volume=None, dest_volume=None):
        """Disables future transfers to a SnapMirror destination."""

        snapmirror = self.get_snapmirrors(
            source_path=source_path,
            dest_path=dest_path,
            source_vserver=source_vserver,
            source_volume=source_volume,
            dest_vserver=dest_vserver,
            dest_volume=dest_volume)

        if snapmirror:
            uuid = snapmirror[0]['uuid']
            body = {'state': 'paused'}

            self.send_request(f'/snapmirror/relationships/{uuid}', 'patch',
                              body=body)

    @na_utils.trace
    def break_snapmirror_vol(self, source_vserver, source_volume,
                             dest_vserver, dest_volume):
        """Breaks a data protection SnapMirror relationship."""
        self._break_snapmirror(source_vserver=source_vserver,
                               dest_vserver=dest_vserver,
                               source_volume=source_volume,
                               dest_volume=dest_volume)

    @na_utils.trace
    def _break_snapmirror(self, source_path=None, dest_path=None,
                          source_vserver=None, dest_vserver=None,
                          source_volume=None, dest_volume=None):
        """Breaks a data protection SnapMirror relationship."""

        interval = 2
        retries = (10 / interval)

        @utils.retry(netapp_api.NaRetryableError, interval=interval,
                     retries=retries, backoff_rate=1)
        def _waiter():
            snapmirror = self.get_snapmirrors(
                source_path=source_path,
                dest_path=dest_path,
                source_vserver=source_vserver,
                source_volume=source_volume,
                dest_vserver=dest_vserver,
                dest_volume=dest_volume)

            snapmirror_state = snapmirror[0].get('transferring-state')
            if snapmirror_state == 'success':
                uuid = snapmirror[0]['uuid']
                body = {'state': 'broken_off'}
                self.send_request(f'/snapmirror/relationships/{uuid}', 'patch',
                                  body=body)
                return
            else:
                message = 'Waiting for transfer state to be SUCCESS.'
                code = ''
                raise netapp_api.NaRetryableError(message=message, code=code)

        try:
            return _waiter()
        except netapp_api.NaRetryableError:
            msg = _("Transfer state did not reach the expected state. Retries "
                    "exhausted. Aborting.")
            raise na_utils.NetAppDriverException(msg)

    @na_utils.trace
    def resume_snapmirror_vol(self, source_vserver, source_volume,
                              dest_vserver, dest_volume):
        """Resume a SnapMirror relationship if it is quiesced."""
        self._resume_snapmirror(source_vserver=source_vserver,
                                dest_vserver=dest_vserver,
                                source_volume=source_volume,
                                dest_volume=dest_volume)

    @na_utils.trace
    def resync_snapmirror_vol(self, source_vserver, source_volume,
                              dest_vserver, dest_volume):
        """Resync a SnapMirror relationship between volumes."""
        self._resync_snapmirror(source_vserver=source_vserver,
                                dest_vserver=dest_vserver,
                                source_volume=source_volume,
                                dest_volume=dest_volume)

    @na_utils.trace
    def _resume_snapmirror(self, source_path=None, dest_path=None,
                           source_vserver=None, dest_vserver=None,
                           source_volume=None, dest_volume=None):
        """Resume a SnapMirror relationship if it is quiesced."""
        response = self.get_snapmirrors(source_path=source_path,
                                        dest_path=dest_path,
                                        source_vserver=source_vserver,
                                        dest_vserver=dest_vserver,
                                        source_volume=source_volume,
                                        dest_volume=dest_volume)

        if not response:
            # NOTE(nahimsouza): As ZAPI returns this error code, it was kept
            # to avoid changes in the layer above.
            raise netapp_api.api.NaApiError(
                code=netapp_api.api.EOBJECTNOTFOUND)

        snapmirror_uuid = response[0]['uuid']
        snapmirror_policy = response[0]['policy-type']

        body_resync = {}
        if snapmirror_policy == 'async':
            body_resync['state'] = 'snapmirrored'
        elif snapmirror_policy == 'sync':
            body_resync['state'] = 'in_sync'

        self.send_request('/snapmirror/relationships/' +
                          snapmirror_uuid, 'patch',
                          body=body_resync, wait_on_accepted=False)

    @na_utils.trace
    def _resync_snapmirror(self, source_path=None, dest_path=None,
                           source_vserver=None, dest_vserver=None,
                           source_volume=None, dest_volume=None):
        """Resync a SnapMirror relationship."""
        # We reuse the resume operation for resync since both are handled in
        # the same way in the REST API, by setting the snapmirror relationship
        # to the snapmirrored state.
        self._resume_snapmirror(source_path, dest_path,
                                source_vserver, dest_vserver,
                                source_volume, dest_volume)

    @na_utils.trace
    def add_nfs_export_rule(self, policy_name, client_match, readonly,
                            auth_methods):
        """Add rule to NFS export policy."""
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
    def set_qos_policy_group_for_volume(self, volume_name,
                                        qos_policy_group_name):
        """Set QoS policy group for volume."""
        volume = self._get_volume_by_args(vol_name=volume_name)
        uuid = volume['uuid']

        body = {
            'qos.policy.name': qos_policy_group_name
        }

        self.send_request(f'/storage/volumes/{uuid}', 'patch', body=body)

    @na_utils.trace
    def update_snapmirror_vol(self, source_vserver, source_volume,
                              dest_vserver, dest_volume):
        """Schedules a snapmirror update between volumes."""
        self._update_snapmirror(source_vserver=source_vserver,
                                dest_vserver=dest_vserver,
                                source_volume=source_volume,
                                dest_volume=dest_volume)

    @na_utils.trace
    def _update_snapmirror(self, source_path=None, dest_path=None,
                           source_vserver=None, dest_vserver=None,
                           source_volume=None, dest_volume=None):
        """Update a snapmirror relationship asynchronously."""
        snapmirrors = self.get_snapmirrors(source_path=source_path,
                                           dest_path=dest_path,
                                           source_vserver=source_vserver,
                                           dest_vserver=dest_vserver,
                                           source_volume=source_volume,
                                           dest_volume=dest_volume)

        if not snapmirrors:
            msg = _('Failed to get snapmirror relationship information')
            raise na_utils.NetAppDriverException(msg)

        snapmirror_uuid = snapmirrors[0]['uuid']

        # NOTE(nahimsouza): A POST with an empty body starts the update
        # snapmirror operation.
        try:
            self.send_request('/snapmirror/relationships/' +
                              snapmirror_uuid + '/transfers/', 'post',
                              wait_on_accepted=False)
        except netapp_api.api.NaApiError as e:
            transfer_in_progress = 'Another transfer is in progress'

            if (e.code == netapp_api.EREST_SNAPMIRROR_NOT_INITIALIZED and
                    transfer_in_progress in e.message):
                # NOTE (nahimsouza): Raise this message to keep compatibility
                # with ZAPI and avoid change the driver layer.
                raise netapp_api.api.NaApiError(message='not initialized',
                                                code=netapp_api.api.EAPIERROR)

            if not (e.code == netapp_api.EREST_UPDATE_SNAPMIRROR_FAILED
                    and transfer_in_progress in e.message):
                raise

    @na_utils.trace
    def get_cluster_name(self):
        """Gets cluster name."""

        result = self.send_request('/cluster', 'get', enable_tunneling=False)
        return result.get('name')

    @na_utils.trace
    def check_volume_clone_split_completed(self, volume_name):
        """Check if volume clone split operation already finished."""
        volume = self._get_volume_by_args(vol_name=volume_name,
                                          fields='clone.is_flexclone')

        return volume['clone']['is_flexclone'] is False

    @na_utils.trace
    def rehost_volume(self, volume_name, vserver, destination_vserver):
        """Rehosts a volume from one Vserver into another Vserver.

        :param volume_name: Name of the FlexVol to be rehosted.
        :param vserver: Source Vserver name to which target volume belongs.
        :param destination_vserver: Destination Vserver name where target
        volume must reside after successful volume rehost operation.
        """
        # TODO(raffaelacunha): As soon NetApp REST API supports "volume_rehost"
        # the current endpoint (using CLI passthrough) must be replaced.
        body = {
            "vserver": vserver,
            "volume": volume_name,
            "destination_vserver": destination_vserver
        }
        self.send_request('/private/cli/volume/rehost', 'post', body=body)

    @na_utils.trace
    def get_net_options(self):
        """Retrives the IPv6 support."""

        return {
            'ipv6-enabled': True,
        }

    @na_utils.trace
    def set_qos_adaptive_policy_group_for_volume(self, volume_name,
                                                 qos_policy_group_name):
        """Set QoS adaptive policy group for volume."""

        # NOTE(renanpiranguinho): For REST API, adaptive QoS is set the same
        # way as normal QoS.
        self.set_qos_policy_group_for_volume(volume_name,
                                             qos_policy_group_name)

    def get_performance_counter_info(self, object_name, counter_name):
        """Gets info about one or more Data ONTAP performance counters."""

        # NOTE(nahimsouza): This conversion is nedeed because different names
        # are used in ZAPI and we want to avoid changes in the driver for now.
        rest_counter_names = {
            'domain_busy': 'domain_busy_percent',
            'processor_elapsed_time': 'elapsed_time',
            'avg_processor_busy': 'average_processor_busy_percent',
        }

        rest_counter_name = counter_name
        if counter_name in rest_counter_names:
            rest_counter_name = rest_counter_names[counter_name]

        # Get counter table info
        query = {
            'counter_schemas.name': rest_counter_name,
            'fields': 'counter_schemas.*'
        }

        try:
            table = self.send_request(
                f'/cluster/counter/tables/{object_name}',
                'get', query=query)

            name = counter_name  # use the original name (ZAPI compatible)
            base_counter = table['counter_schemas'][0]['denominator']['name']

            query = {
                'counters.name': rest_counter_name,
                'fields': 'counters.*'
            }

            response = self.send_request(
                f'/cluster/counter/tables/{object_name}/rows',
                'get', query=query, enable_tunneling=False)

            table_rows = response.get('records', [])
            labels = []
            if len(table_rows) != 0:
                labels = table_rows[0]['counters'][0].get('labels', [])

                # NOTE(nahimsouza): Values have a different format on REST API
                # and we want to keep compatibility with ZAPI for a while
                if object_name == 'wafl' and counter_name == 'cp_phase_times':
                    # discard the prefix 'cp_'
                    labels = [label[3:] for label in labels]

            return {
                'name': name,
                'labels': labels,
                'base-counter': base_counter,
            }
        except netapp_api.api.NaApiError:
            raise exception.NotFound(_('Counter %s not found') % counter_name)

    def get_performance_instance_uuids(self, object_name, node_name):
        """Get UUIDs of performance instances for a cluster node."""

        query = {
            'id': node_name + ':*',
        }

        response = self.send_request(
            f'/cluster/counter/tables/{object_name}/rows',
            'get', query=query, enable_tunneling=False)

        records = response.get('records', [])

        uuids = []
        for record in records:
            uuids.append(record['id'])

        return uuids

    def get_performance_counters(self, object_name, instance_uuids,
                                 counter_names):
        """Gets more cDOT performance counters."""

        # NOTE(nahimsouza): This conversion is nedeed because different names
        # are used in ZAPI and we want to avoid changes in the driver for now.
        rest_counter_names = {
            'domain_busy': 'domain_busy_percent',
            'processor_elapsed_time': 'elapsed_time',
            'avg_processor_busy': 'average_processor_busy_percent',
        }

        zapi_counter_names = {
            'domain_busy_percent': 'domain_busy',
            'elapsed_time': 'processor_elapsed_time',
            'average_processor_busy_percent': 'avg_processor_busy',
        }

        for i in range(len(counter_names)):
            if counter_names[i] in rest_counter_names:
                counter_names[i] = rest_counter_names[counter_names[i]]

        query = {
            'id': '|'.join(instance_uuids),
            'counters.name': '|'.join(counter_names),
            'fields': 'id,counter_table.name,counters.*',
        }

        response = self.send_request(
            f'/cluster/counter/tables/{object_name}/rows',
            'get', query=query)

        counter_data = []
        for record in response.get('records', []):
            for counter in record['counters']:

                counter_name = counter['name']

                # Reverts the name conversion
                if counter_name in zapi_counter_names:
                    counter_name = zapi_counter_names[counter_name]

                counter_value = ''
                if counter.get('value'):
                    counter_value = counter.get('value')
                elif counter.get('values'):
                    # NOTE(nahimsouza): Conversion made to keep compatibility
                    # with old ZAPI format
                    values = counter.get('values')
                    counter_value = ','.join([str(v) for v in values])

                counter_data.append({
                    'instance-name': record['counter_table']['name'],
                    'instance-uuid': record['id'],
                    'node-name': record['id'].split(':')[0],
                    'timestamp': int(time.time()),
                    counter_name: counter_value,
                })

        return counter_data

    @na_utils.trace
    def _list_vservers(self):
        """Get the names of vservers present"""
        query = {
            'fields': 'name',
        }
        response = self.send_request('/svm/svms', 'get', query=query,
                                     enable_tunneling=False)

        return [svm['name'] for svm in response.get('records', [])]

    @na_utils.trace
    def _get_ems_log_destination_vserver(self):
        """Returns the best vserver destination for EMS messages."""

        # NOTE(nahimsouza): Differently from ZAPI, only 'data' SVMs can be
        # managed by the SVM REST APIs - that's why the vserver type is not
        # specified.
        vservers = self._list_vservers()

        if vservers:
            return vservers[0]

        raise exception.NotFound("No Vserver found to receive EMS messages.")

    @na_utils.trace
    def send_ems_log_message(self, message_dict):
        """Sends a message to the Data ONTAP EMS log."""

        body = {
            'computer_name': message_dict['computer-name'],
            'event_source': message_dict['event-source'],
            'app_version': message_dict['app-version'],
            'category': message_dict['category'],
            'severity': 'notice',
            'autosupport_required': message_dict['auto-support'] == 'true',
            'event_id': message_dict['event-id'],
            'event_description': message_dict['event-description'],
        }

        bkp_connection = copy.copy(self.connection)
        bkp_timeout = self.connection.get_timeout()
        bkp_vserver = self.vserver

        self.connection.set_timeout(25)
        try:
            # TODO(nahimsouza): Vserver is being set to replicate the ZAPI
            # behavior, but need to check if this could be removed in REST API
            self.connection.set_vserver(
                self._get_ems_log_destination_vserver())
            self.send_request('/support/ems/application-logs',
                              'post', body=body)
            LOG.debug('EMS executed successfully.')
        except netapp_api.api.NaApiError as e:
            LOG.warning('Failed to invoke EMS. %s', e)
        finally:
            # Restores the data
            timeout = (
                bkp_timeout if bkp_timeout is not None else DEFAULT_TIMEOUT)
            self.connection = copy.copy(bkp_connection)
            self.connection.set_timeout(timeout)
            self.connection.set_vserver(bkp_vserver)

    @na_utils.trace
    def _get_deleted_nfs_export_policies(self):
        """Get soft deleted NFS export policies."""
        query = {
            'name': DELETED_PREFIX + '*',
            'fields': 'name,svm.name',
        }

        response = self.send_request('/protocols/nfs/export-policies',
                                     'get', query=query)

        policy_map = {}
        for record in response['records']:
            vserver = record['svm']['name']
            policies = policy_map.get(vserver, [])
            policies.append(record['name'])
            policy_map[vserver] = policies

        return policy_map

    @na_utils.trace
    def prune_deleted_nfs_export_policies(self):
        """Delete export policies that were marked for deletion."""
        deleted_policy_map = self._get_deleted_nfs_export_policies()
        for vserver in deleted_policy_map:
            client = copy.copy(self)
            client.connection = copy.copy(self.connection)
            client.connection.set_vserver(vserver)
            for policy in deleted_policy_map[vserver]:
                try:
                    client.delete_nfs_export_policy(policy)
                except netapp_api.api.NaApiError:
                    LOG.debug('Could not delete export policy %s.', policy)

    @na_utils.trace
    def get_nfs_config_default(self, desired_args=None):
        """Gets the default NFS config with the desired params"""

        query = {'fields': 'transport.*'}

        if self.vserver:
            query['svm.name'] = self.vserver

        response = self.send_request('/protocols/nfs/services/',
                                     'get', query=query)

        # NOTE(nahimsouza): Default values to replicate ZAPI behavior when
        # response is empty. Also, REST API does not have an equivalent to
        # 'udp-max-xfer-size', so the default is always returned.
        nfs_info = {
            'tcp-max-xfer-size': str(DEFAULT_TCP_MAX_XFER_SIZE),
            'udp-max-xfer-size': str(DEFAULT_UDP_MAX_XFER_SIZE),
        }
        records = response.get('records', [])
        if records:
            nfs_info['tcp-max-xfer-size'] = (
                str(records[0]['transport']['tcp_max_transfer_size']))

        return nfs_info

    @na_utils.trace
    def create_kerberos_realm(self, security_service):
        """Creates Kerberos realm on cluster."""

        body = {
            'comment': '',
            'kdc.ip': security_service['server'],
            'kdc.port': '88',
            'kdc.vendor': 'other',
            'name': security_service['domain'].upper(),
        }
        try:
            self.send_request('/protocols/nfs/kerberos/realms', 'post',
                              body=body)
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_DUPLICATE_ENTRY:
                LOG.debug('Kerberos realm config already exists.')
            else:
                msg = _('Failed to create Kerberos realm. %s')
                raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def configure_kerberos(self, security_service, vserver_name):
        """Configures Kerberos for NFS on Vserver."""

        self.configure_dns(security_service, vserver_name=vserver_name)
        spn = self._get_kerberos_service_principal_name(
            security_service, vserver_name)

        lifs = self.get_network_interfaces()

        if not lifs:
            msg = _("Cannot set up Kerberos. There are no LIFs configured.")
            raise exception.NetAppException(msg)

        for lif in lifs:
            body = {
                'password': security_service['password'],
                'user': security_service['user'],
                'interface.name': lif['interface-name'],
                'enabled': True,
                'spn': spn
            }

            interface_uuid = lif['uuid']

            self.send_request(
                f'/protocols/nfs/kerberos/interfaces/{interface_uuid}',
                'patch', body=body)

    @na_utils.trace
    def _get_kerberos_service_principal_name(self, security_service,
                                             vserver_name):
        """Build Kerberos service principal name."""
        return ('nfs/' + vserver_name.replace('_', '-') + '.' +
                security_service['domain'] + '@' +
                security_service['domain'].upper())

    @na_utils.trace
    def _get_cifs_server_name(self, vserver_name):
        """Build CIFS server name."""
        # 'cifs-server' is CIFS Server NetBIOS Name, max length is 15.
        # Should be unique within each domain (data['domain']).
        # Cut to 15 char with begin and end, attempt to make valid DNS hostname
        cifs_server = (vserver_name[0:8] +
                       '-' +
                       vserver_name[-6:]).replace('_', '-').upper()
        return cifs_server

    @na_utils.trace
    def configure_ldap(self, security_service, timeout=30, vserver_name=None):
        """Configures LDAP on Vserver."""
        self._create_ldap_client(security_service, vserver_name=vserver_name)

    @na_utils.trace
    def configure_active_directory(self, security_service, vserver_name):
        """Configures AD on Vserver."""
        self.configure_dns(security_service, vserver_name=vserver_name)
        self.set_preferred_dc(security_service, vserver_name)

        cifs_server = self._get_cifs_server_name(vserver_name)

        body = {
            'ad_domain.user': security_service['user'],
            'ad_domain.password': security_service['password'],
            'force': 'true',
            'name': cifs_server,
            'ad_domain.fqdn': security_service['domain'],
        }

        if security_service['ou'] is not None:
            body['ad_domain.organizational_unit'] = security_service['ou']

        try:
            LOG.debug("Trying to setup CIFS server with data: %s", body)
            self.send_request('/protocols/cifs/services', 'post', body=body)
        except netapp_api.api.NaApiError as e:
            msg = _("Failed to create CIFS server entry. %s")
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def _get_unique_svm_by_name(self, vserver_name=None):
        """Get the specified SVM UUID."""
        query = {
            'name': vserver_name if vserver_name else self.vserver,
            'fields': 'uuid'
        }
        response = self.send_request('/svm/svms', 'get', query=query)
        if not response.get('records'):
            msg = ('Vserver %s not found.') % self.vserver
            raise exception.NetAppException(msg)
        svm_uuid = response['records'][0]['uuid']
        return svm_uuid

    @na_utils.trace
    def get_dns_config(self, vserver_name=None):
        """Read DNS servers and domains currently configured in the vserver·"""
        svm_uuid = self._get_unique_svm_by_name(vserver_name)
        try:
            result = self.send_request(f'/name-services/dns/{svm_uuid}', 'get')
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_ENTRY_NOT_FOUND:
                return {}
            msg = ("Failed to retrieve DNS configuration. %s")
            raise exception.NetAppException(msg % e.message)

        dns_config = {}
        dns_info = result.get('dynamic_dns', {})

        dns_config['dns-state'] = dns_info.get('enabled', '')
        dns_config['domains'] = result.get('domains', [])
        dns_config['dns-ips'] = result.get('servers', [])

        return dns_config

    @na_utils.trace
    def configure_dns(self, security_service, vserver_name=None):
        """Configure DNS address and servers for a vserver."""
        body = {
            'domains': [],
            'servers': []
        }
        # NOTE(dviroel): Read the current dns configuration and merge with the
        # new one. This scenario is expected when 2 security services provide
        # a DNS configuration, like 'active_directory' and 'ldap'.
        current_dns_config = self.get_dns_config(vserver_name=vserver_name)
        domains = set(current_dns_config.get('domains', []))
        dns_ips = set(current_dns_config.get('dns-ips', []))

        svm_uuid = self._get_unique_svm_by_name(vserver_name)

        domains.add(security_service['domain'])
        for domain in domains:
            body['domains'].append(domain)

        for dns_ip in security_service['dns_ip'].split(','):
            dns_ips.add(dns_ip.strip())
        body['servers'] = []
        for dns_ip in sorted(dns_ips):
            body['servers'].append(dns_ip)

        try:
            if current_dns_config:
                self.send_request(f'/name-services/dns/{svm_uuid}',
                                  'patch', body=body)
            else:
                self.send_request('/name-services/dns', 'post', body=body)
        except netapp_api.api.NaApiError as e:
            msg = _("Failed to configure DNS. %s")
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def setup_security_services(self, security_services, vserver_client,
                                vserver_name, timeout=30):
        """Setup SVM security services."""
        body = {
            'nsswitch.namemap': ['ldap', 'files'],
            'nsswitch.group': ['ldap', 'files'],
            'nsswitch.netgroup': ['ldap', 'files'],
            'nsswitch.passwd': ['ldap', 'files'],
        }

        svm_uuid = self._get_unique_svm_by_name(vserver_name)

        self.send_request(f'/svm/svms/{svm_uuid}', 'patch', body=body)

        for security_service in security_services:
            if security_service['type'].lower() == 'ldap':
                vserver_client.configure_ldap(security_service,
                                              timeout=timeout,
                                              vserver_name=vserver_name)

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
    def _create_ldap_client(self, security_service, vserver_name=None):
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

        body = {
            'port': '389',
            'schema': ldap_schema,
            'bind_dn': bind_dn,
            'bind_password': security_service.get('password'),
            'svm.name': vserver_name
        }

        if security_service.get('ou'):
            body['base_dn'] = security_service['ou']
        if ad_domain:
            # Active Directory LDAP server
            body['ad_domain'] = ad_domain
        else:
            body['servers'] = []
            for server in ldap_servers.split(','):
                body['servers'].append(server.strip())

        self.send_request('/name-services/ldap', 'post',
                          body=body)

    @na_utils.trace
    def modify_ldap(self, new_security_service, current_security_service):
        """Modifies LDAP client on a Vserver."""
        ad_domain = new_security_service.get('domain')
        ldap_servers = new_security_service.get('server')
        bind_dn = new_security_service.get('user')
        ldap_schema = 'RFC-2307'
        svm_uuid = self._get_unique_svm_by_name(self.vserver)

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
            bind_dn = (new_security_service.get('user') + '@' + ad_domain)
        else:
            if not ldap_servers:
                msg = _("LDAP client cannot be configured without 'server' "
                        "or 'domain' parameters. Use 'server' for Linux/Unix "
                        "LDAP servers or 'domain' for Active Directory LDAP "
                        "server.")
                LOG.exception(msg)
                raise exception.NetAppException(msg)

        body = {
            'port': '389',
            'schema': ldap_schema,
            'bind_dn': bind_dn,
            'bind_password': new_security_service.get('password')
        }

        if new_security_service.get('ou'):
            body['base_dn'] = new_security_service['ou']
        if ad_domain:
            # Active Directory LDAP server
            body['ad_domain'] = ad_domain
        else:
            body['servers'] = []
            for server in ldap_servers.split(','):
                body['servers'].append(server.strip())

        self.send_request(f'/name-services/ldap/{svm_uuid}', 'patch',
                          body=body)

    @na_utils.trace
    def update_kerberos_realm(self, security_service):
        """Update Kerberos realm info. Only KDC IP can be changed."""
        realm_name = security_service['domain']
        svm_uuid = self._get_unique_svm_by_name(self.vserver)

        body = {
            'kdc-ip': security_service['server'],
        }

        try:
            self.send_request(
                f'/protocols/nfs/kerberos/realms/{svm_uuid}/{realm_name}',
                'patch', body=body)
        except netapp_api.api.NaApiError as e:
            msg = _('Failed to update Kerberos realm. %s')
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def update_dns_configuration(self, dns_ips, domains):
        """Overrides DNS configuration with the specified IPs and domains."""
        current_dns_config = self.get_dns_config(vserver_name=self.vserver)
        body = {
            'domains': [],
            'servers': [],
        }
        for domain in domains:
            body['domains'].append(domain)

        for dns_ip in dns_ips:
            body['servers'].append(dns_ip)

        empty_dns_config = (not body['domains'] and
                            not body['servers'])

        svm_uuid = self._get_unique_svm_by_name(self.vserver)

        if current_dns_config:
            endpoint, operation, body = (
                (f'/name-services/dns/{svm_uuid}',
                    'delete', {}) if empty_dns_config
                else (f'/name-services/dns/{svm_uuid}', 'patch', body))
        else:
            endpoint, operation, body = '/name-services/dns', 'post', body

        try:
            self.send_request(endpoint, operation, body)
        except netapp_api.api.NaApiError as e:
            msg = ("Failed to update DNS configuration. %s")
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def remove_preferred_dcs(self, security_service, svm_uuid):
        """Drops all preferred DCs at once."""

        query = {
            'fqdn': security_service['domain'],
        }

        records = self.send_request(f'/protocols/cifs/domains/{svm_uuid}/'
                                    f'preferred-domain-controllers/', 'get')

        fqdn = records.get('fqdn')
        server_ip = records.get('server_ip')

        try:
            self.send_request(
                f'/protocols/cifs/domains/{svm_uuid}/'
                f'preferred-domain-controllers/{fqdn}/{server_ip}',
                'delete', query=query)
        except netapp_api.api.NaApiError as e:
            msg = _("Failed to unset preferred DCs. %s")
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def modify_active_directory_security_service(
            self, vserver_name, differring_keys, new_security_service,
            current_security_service):
        """Modify Active Directory security service."""

        svm_uuid = self._get_unique_svm_by_name(vserver_name)
        new_username = new_security_service['user']

        records = self.send_request(
            f'/protocols/cifs/local-users/{svm_uuid}', 'get')
        sid = records.get('sid')
        if 'password' in differring_keys:
            query = {
                'password': new_security_service['password']
            }
            try:
                self.send_request(
                    f'/protocols/cifs/local-users/{svm_uuid}/{sid}',
                    'patch', query=query
                )
            except netapp_api.api.NaApiError as e:
                msg = _("Failed to modify existing CIFS server password. %s")
                raise exception.NetAppException(msg % e.message)

        if 'user' in differring_keys:
            query = {
                'name': new_username
            }
            try:
                self.send_request(
                    f'/protocols/cifs/local-users/{svm_uuid}/{sid}',
                    'patch', query=query
                )
            except netapp_api.api.NaApiError as e:
                msg = _("Failed to modify existing CIFS server user-name. %s")
                raise exception.NetAppException(msg % e.message)

        if 'server' in differring_keys:
            if current_security_service['server'] is not None:
                self.remove_preferred_dcs(current_security_service, svm_uuid)

            if new_security_service['server'] is not None:
                self.set_preferred_dc(new_security_service, svm_uuid)

    @na_utils.trace
    def set_preferred_dc(self, security_service, vserver_name):
        """Set preferred domain controller."""

        # server is optional
        if not security_service['server']:
            return

        query = {
            'server_ip': [],
            'fqdn': security_service['domain'],
            'skip_config_validation': 'false',
        }

        for dc_ip in security_service['server'].split(','):
            query['server_ip'].append(dc_ip.strip())

        svm_uuid = self._get_unique_svm_by_name(vserver_name)

        try:
            self.send_request(
                f'/protocols/cifs/domains/{svm_uuid}'
                '/preferred-domain-controllers',
                'post', query=query)
        except netapp_api.api.NaApiError as e:
            msg = _("Failed to set preferred DC. %s")
            raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def create_vserver_peer(self, vserver_name, peer_vserver_name,
                            peer_cluster_name=None):
        """Creates a Vserver peer relationship for SnapMirrors."""
        body = {
            'svm.name': vserver_name,
            'peer.svm.name': peer_vserver_name,
            'applications': ['snapmirror']
        }
        if peer_cluster_name:
            body['peer.cluster.name'] = peer_cluster_name

        self.send_request('/svm/peers', 'post', body=body,
                          enable_tunneling=False)

    @na_utils.trace
    def _get_svm_peer_uuid(self, vserver_name, peer_vserver_name):
        """Get UUID of SVM peer."""
        query = {
            'svm.name': vserver_name,
            'peer.svm.name': peer_vserver_name,
            'fields': 'uuid'
        }
        res = self.send_request('/svm/peers', 'get', query=query)
        if not res.get('records'):
            msg = ('Vserver peer not found.')
            raise exception.NetAppException(msg)
        peer_uuid = res.get('records')[0]['uuid']
        return peer_uuid

    @na_utils.trace
    def accept_vserver_peer(self, vserver_name, peer_vserver_name):
        """Accepts a pending Vserver peer relationship."""
        uuid = self._get_svm_peer_uuid(vserver_name, peer_vserver_name)
        body = {'state': 'peered'}
        self.send_request(f'/svm/peers/{uuid}', 'patch', body=body,
                          enable_tunneling=False)

    @na_utils.trace
    def get_vserver_peers(self, vserver_name=None, peer_vserver_name=None):
        """Gets one or more Vserver peer relationships."""

        query = {}
        if peer_vserver_name:
            query['name'] = peer_vserver_name
        if vserver_name:
            query['svm.name'] = vserver_name

        query['fields'] = 'uuid,svm.name,peer.svm.name,state,peer.cluster.name'

        result = self.send_request('/svm/peers', 'get', query=query)
        if not self._has_records(result):
            return []

        vserver_peers = []
        for vserver_peer in result['records']:
            vserver_peer_info = {
                'uuid': vserver_peer['uuid'],
                'vserver': vserver_peer['svm']['name'],
                'peer-vserver': vserver_peer['peer']['svm']['name'],
                'peer-state': vserver_peer['state'],
                'peer-cluster': vserver_peer['peer']['cluster']['name'],
            }
            vserver_peers.append(vserver_peer_info)

        return vserver_peers

    @na_utils.trace
    def delete_vserver_peer(self, vserver_name, peer_vserver_name):
        """Deletes a Vserver peer relationship."""

        vserver_peer = self.get_vserver_peers(vserver_name, peer_vserver_name)
        uuid = vserver_peer[0].get('uuid')
        self.send_request(f'/svm/peers/{uuid}', 'delete',
                          enable_tunneling=False)

    @na_utils.trace
    def create_vserver(self, vserver_name, root_volume_aggregate_name,
                       root_volume_name, aggregate_names, ipspace_name,
                       security_cert_expire_days):
        """Creates new vserver and assigns aggregates."""

        # NOTE(nahimsouza): root_volume_aggregate_name and root_volume_name
        # were kept due to compatibility issues, but they are not used in
        # the vserver creation by REST API
        self._create_vserver(
            vserver_name, aggregate_names, ipspace_name,
            name_server_switch=['files'])
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
                        name_server_switch=None, subtype=None):
        """Creates new vserver and assigns aggregates."""
        body = {
            'name': vserver_name,
        }

        if name_server_switch:
            body['nsswitch.namemap'] = name_server_switch

        if subtype:
            body['subtype'] = subtype

        if ipspace_name:
            body['ipspace.name'] = ipspace_name

        body['aggregates'] = []
        for aggr_name in aggregate_names:
            body['aggregates'].append({'name': aggr_name})

        self.send_request('/svm/svms', 'post', body=body)

    @na_utils.trace
    def _modify_security_cert(self, vserver_name, security_cert_expire_days):
        """Create new security certificate with given expire days."""

        # Do not modify security certificate if specified expire days are
        # equal to default security certificate expire days i.e. 365.
        if security_cert_expire_days == DEFAULT_SECURITY_CERT_EXPIRE_DAYS:
            return

        query = {
            'common-name': vserver_name,
            'ca': vserver_name,
            'type': 'server',
            'svm.name': vserver_name,
        }
        result = self.send_request('/security/certificates',
                                   'get', query=query)
        old_certificate_info_list = result.get('records', [])
        if not old_certificate_info_list:
            LOG.warning("Unable to retrieve certificate-info for vserver "
                        "%(server)s'. Cannot set the certificate expiry to "
                        "%s(conf)s. ", {'server': vserver_name,
                                        'conf': security_cert_expire_days})
            return

        body = {
            'common-name': vserver_name,
            'type': 'server',
            'svm.name': vserver_name,
            'expiry_time': f'P{security_cert_expire_days}DT',
        }
        query = {
            'return_records': 'true'
        }
        result = self.send_request('/security/certificates',
                                   'post', body=body, query=query)
        new_certificate_info_list = result.get('records', [])
        if not new_certificate_info_list:
            LOG.warning('Failed to create new security certificate for '
                        'vserver %(server)s.', {'server': vserver_name})
            return

        for certificate_info in new_certificate_info_list:
            cert_uuid = certificate_info.get('uuid', None)
            svm = certificate_info.get('svm', [])
            svm_uuid = svm.get('uuid', None)
            if not svm_uuid or not cert_uuid:
                continue

            try:
                body = {
                    'certificate': {
                        'uuid': cert_uuid,
                    },
                    'client_enabled': 'false',
                }
                self.send_request(f'/svm/svms/{svm_uuid}', 'patch',
                                  body=body)
            except netapp_api.api.NaApiError:
                LOG.debug('Failed to modify SSL for vserver '
                          '%(server)s.', {'server': vserver_name})

        # Delete all old security certificates
        for certificate_info in old_certificate_info_list:
            uuid = certificate_info.get('uuid', None)
            try:
                self.send_request(f'/security/certificates/{uuid}', 'delete')
            except netapp_api.api.NaApiError:
                LOG.error("Failed to delete security certificate for vserver "
                          "%s.", vserver_name)

    @na_utils.trace
    def list_node_data_ports(self, node):
        """List data ports from node."""
        ports = self.get_node_data_ports(node)
        return [port.get('port') for port in ports]

    @na_utils.trace
    def _sort_data_ports_by_speed(self, ports):
        """Sort ports by speed."""

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
    def get_node_data_ports(self, node):
        """Get applicable data ports on the node."""
        query = {
            'node.name': node,
            'state': 'up',
            'type': 'physical',
            'fields': 'node.name,speed,name'
        }

        result = self.send_request('/network/ethernet/ports', 'get',
                                   query=query)

        net_port_info_list = result.get('records', [])

        ports = []
        if net_port_info_list:

            # NOTE(nahimsouza): This query selects the ports that are
            # being used for node management
            query_interfaces = {
                'service_policy.name': 'default-management',
                'fields': 'location.port.name'
            }
            response = self.send_request('/network/ip/interfaces', 'get',
                                         query=query_interfaces,
                                         enable_tunneling=False)

            mgmt_ports = set(
                [record['location']['port']['name']
                    for record in response.get('records', [])]
            )

            for port_info in net_port_info_list:
                if port_info['name'] not in mgmt_ports:
                    port = {
                        'node': port_info['node']['name'],
                        'port': port_info['name'],
                        'speed': port_info['speed'],
                    }
                    ports.append(port)

            ports = self._sort_data_ports_by_speed(ports)

        return ports

    @na_utils.trace
    def get_ipspace_name_for_vlan_port(self, vlan_node, vlan_port, vlan_id):
        """Gets IPSpace name for specified VLAN"""

        port = vlan_port if not vlan_id else '%(port)s-%(id)s' % {
            'port': vlan_port,
            'id': vlan_id,
        }
        query = {
            'name': port,
            'node.name': vlan_node,
            'fields': 'broadcast_domain.ipspace.name'
        }
        result = self.send_request('/network/ethernet/ports/', 'get',
                                   query=query)

        records = result.get('records', [])
        if not records:
            return None
        ipspace_name = records[0]['broadcast_domain']['ipspace']['name']

        return ipspace_name

    @na_utils.trace
    def create_ipspace(self, ipspace_name):
        """Creates an IPspace."""
        body = {'name': ipspace_name}
        self.send_request('/network/ipspaces', 'post', body=body)

    @na_utils.trace
    def create_port_and_broadcast_domain(self, node, port, vlan, mtu, ipspace):
        """Create port and broadcast domain, if they don't exist."""
        home_port_name = port
        if vlan:
            self._create_vlan(node, port, vlan)
            home_port_name = '%(port)s-%(tag)s' % {'port': port, 'tag': vlan}

        self._ensure_broadcast_domain_for_port(
            node, home_port_name, mtu, ipspace=ipspace)

        return home_port_name

    @na_utils.trace
    def _create_vlan(self, node, port, vlan):
        """Create VLAN port if it does not exist."""
        try:
            body = {
                'vlan.base_port.name': port,
                'node.name': node,
                'vlan.tag': vlan,
                'type': 'vlan'
            }
            self.send_request('/network/ethernet/ports', 'post', body=body)
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_DUPLICATE_ENTRY:
                LOG.debug('VLAN %(vlan)s already exists on port %(port)s',
                          {'vlan': vlan, 'port': port})
            else:
                msg = _('Failed to create VLAN %(vlan)s on '
                        'port %(port)s. %(err_msg)s')
                msg_args = {'vlan': vlan, 'port': port, 'err_msg': e.message}
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
        query = {
            'node.name': node,
            'name': port,
            'fields': 'broadcast_domain.name,broadcast_domain.ipspace.name'
        }
        result = self.send_request(
            '/network/ethernet/ports', 'get', query=query)

        net_port_info_list = result.get('records', [])
        port_info = net_port_info_list[0]
        if not port_info:
            msg = _('Could not find port %(port)s on node %(node)s.')
            msg_args = {'port': port, 'node': node}
            raise exception.NetAppException(msg % msg_args)

        broadcast_domain = port_info.get('broadcast_domain', {})
        broadcast_domain_name = broadcast_domain.get('name')
        ipspace_name = broadcast_domain.get('ipspace', {}).get('name')
        port = {
            'broadcast-domain': broadcast_domain_name,
            'ipspace': ipspace_name
        }
        return port

    @na_utils.trace
    def _create_broadcast_domain(self, domain, ipspace, mtu):
        """Create a broadcast domain."""
        body = {
            'ipspace.name': ipspace,
            'name': domain,
            'mtu': mtu,
        }
        self.send_request(
            '/network/ethernet/broadcast-domains', 'post', body=body)

    @na_utils.trace
    def _modify_broadcast_domain(self, domain, ipspace, mtu):
        """Modify a broadcast domain."""
        query = {
            'name': domain
        }

        body = {
            'ipspace.name': ipspace,
            'mtu': mtu,
        }
        self.send_request(
            '/network/ethernet/broadcast-domains', 'patch', body=body,
            query=query)

    @na_utils.trace
    def _delete_port_by_ipspace_and_broadcast_domain(self, port,
                                                     domain, ipspace):
        query = {
            'broadcast_domain.ipspace.name': ipspace,
            'broadcast_domain.name': domain,
            'name': port
        }
        self.send_request('/network/ethernet/ports/', 'delete', query=query)

    @na_utils.trace
    def _broadcast_domain_exists(self, domain, ipspace):
        """Check if a broadcast domain exists."""
        query = {
            'ipspace.name': ipspace,
            'name': domain,
        }
        result = self.send_request(
            '/network/ethernet/broadcast-domains',
            'get', query=query)
        return self._has_records(result)

    @na_utils.trace
    def _add_port_to_broadcast_domain(self, node, port, domain, ipspace):
        """Set a broadcast domain for a given port."""
        try:
            query = {
                'name': port,
                'node.name': node,
            }
            body = {
                'broadcast_domain.ipspace.name': ipspace,
                'broadcast_domain.name': domain,
            }
            self.send_request('/network/ethernet/ports/', 'patch',
                              query=query, body=body)
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_FAIL_ADD_PORT_BROADCAST:
                LOG.debug('Port %(port)s already exists in broadcast domain '
                          '%(domain)s', {'port': port, 'domain': domain})
            else:
                msg = _('Failed to add port %(port)s to broadcast domain '
                        '%(domain)s. %(err_msg)s')
                msg_args = {
                    'port': port,
                    'domain': domain,
                    'err_msg': e.message,
                }
                raise exception.NetAppException(msg % msg_args)

    @na_utils.trace
    def enable_nfs(self, versions, nfs_config=None):
        """Enables NFS on Vserver."""
        svm_id = self._get_unique_svm_by_name()

        body = {
            'svm.uuid': svm_id,
            'enabled': 'true',
        }
        self.send_request('/protocols/nfs/services/', 'post',
                          body=body)

        self._enable_nfs_protocols(versions, svm_id)

        if nfs_config:
            self._configure_nfs(nfs_config, svm_id)

        self._create_default_nfs_export_rules()

    @na_utils.trace
    def _enable_nfs_protocols(self, versions, svm_id):
        """Set the enabled NFS protocol versions."""
        nfs3 = 'true' if 'nfs3' in versions else 'false'
        nfs40 = 'true' if 'nfs4.0' in versions else 'false'
        nfs41 = 'true' if 'nfs4.1' in versions else 'false'

        body = {
            'protocol.v3_enabled': nfs3,
            'protocol.v40_enabled': nfs40,
            'protocol.v41_enabled': nfs41,
            'showmount_enabled': 'true',
            'windows.v3_ms_dos_client_enabled': 'true',
            'protocol.v3_features.connection_drop': 'false',
            'protocol.v3_features.ejukebox_enabled': 'false',
        }
        self.send_request(f'/protocols/nfs/services/{svm_id}', 'patch',
                          body=body)

    @na_utils.trace
    def _create_default_nfs_export_rules(self):
        """Create the default export rule for the NFS service."""

        body = {
            'clients': [{'match': '0.0.0.0/0'}],
            'ro_rule': [
                'any',
            ],
            'rw_rule': [
                'never'
            ],
        }

        uuid = self.get_unique_export_policy_id('default')

        self.send_request(f'/protocols/nfs/export-policies/{uuid}/rules',
                          "post", body=body)
        body['clients'] = [{'match': '::/0'}]
        self.send_request(f'/protocols/nfs/export-policies/{uuid}/rules',
                          "post", body=body)

    @na_utils.trace
    def _configure_nfs(self, nfs_config, svm_id):
        """Sets the nfs configuraton"""

        if ('udp-max-xfer-size' in nfs_config and
                (nfs_config['udp-max-xfer-size']
                    != str(DEFAULT_UDP_MAX_XFER_SIZE))):

            msg = _('Failed to configure NFS. REST API does not support '
                    'setting udp-max-xfer-size default value %(default)s '
                    'is not equal to actual value %(actual)s')
            msg_args = {
                'default': DEFAULT_UDP_MAX_XFER_SIZE,
                'actual': nfs_config['udp-max-xfer-size'],
            }
            raise exception.NetAppException(msg % msg_args)

        nfs_config_value = int(nfs_config['tcp-max-xfer-size'])
        body = {
            'transport.tcp_max_transfer_size': nfs_config_value
        }
        self.send_request(f'/protocols/nfs/services/{svm_id}', 'patch',
                          body=body)

    @na_utils.trace
    def create_network_interface(self, ip, netmask, node, port,
                                 vserver_name, lif_name):
        """Creates LIF on VLAN port."""
        LOG.debug('Creating LIF %(lif)s for Vserver %(vserver)s '
                  'node/port %(node)s:%(port)s.',
                  {'lif': lif_name, 'vserver': vserver_name, 'node': node,
                   'port': port})

        query = {
            'name': 'default-data-files',
            'svm.name': vserver_name,
            'fields': 'uuid,name,services,svm.name'
        }

        result = self.send_request('/network/ip/service-policies/', 'get',
                                   query=query)

        if result.get('records'):
            policy = result['records'][0]

            # NOTE(nahimsouza): Workaround to add services in the policy
            # in the case ONTAP does not create it automatically
            if 'data_nfs' not in policy['services']:
                policy['services'].append('data_nfs')
            if 'data_cifs' not in policy['services']:
                policy['services'].append('data_cifs')

            uuid = policy['uuid']
            body = {'services': policy['services']}
            self.send_request(
                f'/network/ip/service-policies/{uuid}', 'patch',
                body=body)

        body = {
            'ip.address': ip,
            'ip.netmask': netmask,
            'enabled': 'true',
            'service_policy.name': 'default-data-files',
            'location.home_node.name': node,
            'location.home_port.name': port,
            'name': lif_name,
            'svm.name': vserver_name,
        }
        self.send_request('/network/ip/interfaces', 'post', body=body)

    @na_utils.trace
    def network_interface_exists(self, vserver_name, node, port, ip, netmask,
                                 vlan=None, home_port=None):
        """Checks if LIF exists."""
        if not home_port:
            home_port = port if not vlan else f'{port}-{vlan}'

        query = {
            'ip.address': ip,
            'location.home_node.name': node,
            'location.home_port.name': home_port,
            'ip.netmask': netmask,
            'svm.name': vserver_name,
            'fields': 'name',
        }
        result = self.send_request('/network/ip/interfaces',
                                   'get', query=query)
        return self._has_records(result)

    @na_utils.trace
    def create_route(self, gateway, destination=None):
        """Create a network route."""
        if not gateway:
            return

        address = None
        netmask = None
        if not destination:
            if ':' in gateway:
                destination = '::/0'
            else:
                destination = '0.0.0.0/0'

        if '/' in destination:
            address, netmask = destination.split('/')
        else:
            address = destination

        body = {
            'destination.address': address,
            'gateway': gateway,
        }

        if netmask:
            body['destination.netmask'] = netmask

        try:
            self.send_request('/network/ip/routes', 'post', body=body)
        except netapp_api.api.NaApiError as e:
            if (e.code == netapp_api.EREST_DUPLICATE_ROUTE):
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
    def rename_vserver(self, vserver_name, new_vserver_name):
        """Rename a vserver."""
        body = {
            'name': new_vserver_name
        }

        svm_uuid = self._get_unique_svm_by_name(vserver_name)
        self.send_request(f'/svm/svms/{svm_uuid}', 'patch', body=body)

    @na_utils.trace
    def get_vserver_info(self, vserver_name):
        """Retrieves Vserver info."""
        LOG.debug('Retrieving Vserver %s information.', vserver_name)

        query = {
            'name': vserver_name,
            'fields': 'state,subtype'
        }

        response = self.send_request('/svm/svms', 'get', query=query)
        if not response.get('records'):
            return

        vserver = response['records'][0]
        vserver_info = {
            'name': vserver_name,
            'subtype': vserver['subtype'],
            'operational_state': vserver['state'],
            'state': vserver['state'],
        }
        return vserver_info

    @na_utils.trace
    def get_nfs_config(self, desired_args, vserver):
        """Gets the NFS config of the given vserver with the desired params"""

        query = {'fields': 'transport.*'}
        query['svm.name'] = vserver

        nfs_info = {
            'tcp-max-xfer-size': str(DEFAULT_TCP_MAX_XFER_SIZE),
            'udp-max-xfer-size': str(DEFAULT_UDP_MAX_XFER_SIZE)
        }

        response = self.send_request('/protocols/nfs/services/',
                                     'get', query=query)
        records = response.get('records', [])

        if records:
            nfs_info['tcp-max-xfer-size'] = (
                str(records[0]['transport']['tcp_max_transfer_size']))

        return nfs_info

    @na_utils.trace
    def get_vserver_ipspace(self, vserver_name):
        """Get the IPspace of the vserver, or None if not supported."""
        query = {
            'name': vserver_name,
            'fields': 'ipspace.name'
        }

        try:
            response = self.send_request('/svm/svms', 'get', query=query)
        except netapp_api.api.NaApiError:
            msg = _('Could not determine IPspace for Vserver %s.')
            raise exception.NetAppException(msg % vserver_name)

        if self._has_records(response):
            return response['records'][0].get('ipspace', {}).get('name')

        return None

    @na_utils.trace
    def get_snapmirror_policies(self, vserver_name):
        """Get all SnapMirror policies associated to a vServer."""
        query = {
            'svm.name': vserver_name,
            'fields': 'name'
        }
        response = self.send_request(
            '/snapmirror/policies', 'get', query=query)
        records = response.get('records')

        policy_name = []
        for record in records:
            policy_name.append(record.get('name'))
        return policy_name

    @na_utils.trace
    def delete_snapmirror_policy(self, policy_name):
        """Deletes a SnapMirror policy."""

        query = {
            'name': policy_name,
            'fields': 'uuid,name'
        }
        response = self.send_request('/snapmirror/policies',
                                     'get', query=query)
        if self._has_records(response):
            uuid = response['records'][0]['uuid']
            try:
                self.send_request(f'/snapmirror/policies/{uuid}', 'delete')
            except netapp_api.api.NaApiError as e:
                if e.code != netapp_api.EREST_ENTRY_NOT_FOUND:
                    raise

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
        svm_uuid = self._get_unique_svm_by_name(vserver_name)

        is_dp_destination = vserver_info.get('subtype') == 'dp_destination'
        root_volume_name = self.get_vserver_root_volume_name(vserver_name)
        volumes_count = vserver_client.get_vserver_volume_count()

        # NOTE(dviroel): 'dp_destination' vservers don't allow to delete its
        # root volume. We can just call vserver-destroy directly.
        if volumes_count == 1 and not is_dp_destination:
            try:
                vserver_client.offline_volume(root_volume_name)
            except netapp_api.api.NaApiError as e:
                if e.code == netapp_api.EREST_ENTRY_NOT_FOUND:
                    LOG.error("Cannot delete Vserver %s. "
                              "Failed to put volumes offline. "
                              "Entry doesn't exist.", vserver_name)
                else:
                    raise
            vserver_client.delete_volume(root_volume_name)

        elif volumes_count > 1:
            msg = _("Cannot delete Vserver. Vserver %s has shares.")
            raise exception.NetAppException(msg % vserver_name)

        if security_services and not is_dp_destination:
            self._terminate_vserver_services(vserver_name, vserver_client,
                                             security_services)

        self.send_request(f'/svm/svms/{svm_uuid}', 'delete')

    @na_utils.trace
    def get_vserver_volume_count(self):
        """Get number of volumes in SVM."""
        query = {'return_records': 'false'}
        response = self.send_request('/storage/volumes', 'get', query=query)
        return response['num_records']

    @na_utils.trace
    def _terminate_vserver_services(self, vserver_name, vserver_client,
                                    security_services):
        """Terminate SVM security services."""
        svm_uuid = self._get_unique_svm_by_name(vserver_name)

        for service in security_services:
            if service['type'].lower() == 'active_directory':
                body = {
                    'ad_domain.password': service['password'],
                    'ad_domain.user': service['user'],
                }

                body_force = {
                    'ad_domain.password': service['password'],
                    'ad_domain.user': service['user'],
                    'force': True
                }

                try:
                    vserver_client.send_request(
                        f'/protocols/cifs/services/{svm_uuid}', 'delete',
                        body=body)
                except netapp_api.api.NaApiError as e:
                    if e.code == netapp_api.EREST_ENTRY_NOT_FOUND:
                        LOG.error('CIFS server does not exist for '
                                  'Vserver %s.', vserver_name)
                    else:
                        vserver_client.send_request(
                            f'/protocols/cifs/services/{svm_uuid}', 'delete',
                            body=body_force)
            elif service['type'].lower() == 'kerberos':
                vserver_client.disable_kerberos(service)

    @na_utils.trace
    def disable_kerberos(self, security_service):
        """Disable Kerberos in all Vserver LIFs."""

        lifs = self.get_network_interfaces()

        # NOTE(dviroel): If the Vserver has no LIFs, there are no Kerberos
        # to be disabled.
        for lif in lifs:
            body = {
                'password': security_service['password'],
                'user': security_service['user'],
                'interface.name': lif['interface-name'],
                'enabled': False
            }

            interface_uuid = lif['uuid']

            try:
                self.send_request(
                    f'/protocols/nfs/kerberos/interfaces/{interface_uuid}',
                    'patch', body=body)
            except netapp_api.api.NaApiError as e:
                disabled_msg = (
                    "Kerberos is already enabled/disabled on this LIF")
                if (e.code == netapp_api.EREST_KERBEROS_IS_ENABLED_DISABLED and
                        disabled_msg in e.message):
                    # NOTE(dviroel): do not raise an error for 'Kerberos is
                    # already disabled in this LIF'.
                    continue
                msg = ("Failed to disable Kerberos: %s.")
                raise exception.NetAppException(msg % e.message)

    @na_utils.trace
    def get_vserver_root_volume_name(self, vserver_name):
        """Get the root volume name of the vserver."""
        unique_volume = self._get_volume_by_args(vserver=vserver_name,
                                                 is_root=True)
        return unique_volume['name']

    @na_utils.trace
    def ipspace_has_data_vservers(self, ipspace_name):
        """Check whether an IPspace has any data Vservers assigned to it."""
        query = {'ipspace.name': ipspace_name}
        result = self.send_request('/svm/svms', 'get', query=query)
        return self._has_records(result)

    @na_utils.trace
    def delete_vlan(self, node, port, vlan):
        """Delete VLAN port if not in use."""
        query = {
            'vlan.base_port.name': port,
            'node.name': node,
            'vlan.tag': vlan,
        }

        try:
            self.send_request('/network/ethernet/ports/', 'delete',
                              query=query)
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_ENTRY_NOT_FOUND:
                LOG.debug('VLAN %(vlan)s on port %(port)s node %(node)s '
                          'was not found')
            elif (e.code == netapp_api.EREST_INTERFACE_BOUND or
                  e.code == netapp_api.EREST_PORT_IN_USE):
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
        body = {
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
            body["destination"].update(ipspace_data)

        return self.send_request('/svm/migrations', 'post', body=body,
                                 wait_on_accepted=False)

    @na_utils.trace
    def get_migration_check_job_state(self, job_id):
        """Get the job state of a share server migration.

        :param job_id: id of the job to be searched.
        """
        try:
            job = self.get_job(job_id)
            return job
        except netapp_api.api.NaApiError as e:
            if e.code == netapp_api.EREST_NFS_V4_0_ENABLED_MIGRATION_FAILURE:
                msg = _(
                    'NFS v4.0 is not supported while migrating vservers.')
                LOG.error(msg)
                raise exception.NetAppException(message=e.message)
            if e.code == netapp_api.EREST_VSERVER_MIGRATION_TO_NON_AFF_CLUSTER:
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
        body = {
            "action": "cutover"
        }

        return self.send_request(
            f'/svm/migrations/{migration_id}', 'patch', body=body,
            wait_on_accepted=False)

    @na_utils.trace
    def svm_migrate_cancel(self, migration_id):
        """Send a request to cancel the SVM migration.

        :param migration_id: the id of the migration provided by the storage.
        """
        return self.send_request(f'/svm/migrations/{migration_id}', 'delete',
                                 wait_on_accepted=False)

    @na_utils.trace
    def svm_migration_get(self, migration_id):
        """Send a request to get the progress of the SVM migration.

        :param migration_id: the id of the migration provided by the storage.
        """
        return self.send_request(f'/svm/migrations/{migration_id}', 'get')

    @na_utils.trace
    def svm_migrate_pause(self, migration_id):
        """Send a request to pause a migration.

        :param migration_id: the id of the migration provided by the storage.
        """
        body = {
            "action": "pause"
        }

        return self.send_request(
            f'/svm/migrations/{migration_id}', 'patch', body=body,
            wait_on_accepted=False)

    @na_utils.trace
    def delete_network_interface(self, vserver_name, interface_name):
        """Delete the LIF, disabling it before."""
        self.disable_network_interface(vserver_name, interface_name)

        query = {
            'svm.name': vserver_name,
            'name': interface_name
        }
        self.send_request('/network/ip/interfaces', 'delete', query=query)

    @na_utils.trace
    def disable_network_interface(self, vserver_name, interface_name):
        """Disable the LIF."""
        body = {
            'enabled': 'false'
        }
        query = {
            'svm.name': vserver_name,
            'name': interface_name
        }
        self.send_request('/network/ip/interfaces', 'patch', body=body,
                          query=query)

    @na_utils.trace
    def get_ipspaces(self, ipspace_name=None):
        """Gets one or more IPSpaces."""

        query = {
            'name': ipspace_name
        }
        result = self.send_request('/network/ipspaces', 'get',
                                   query=query)

        if not self._has_records(result):
            return []

        ipspace_info = result.get('records')[0]

        query = {
            'broadcast_domain.ipspace.name': ipspace_name
        }
        ports = self.send_request('/network/ethernet/ports',
                                  'get', query=query)

        query = {
            'ipspace.name': ipspace_name
        }
        vservers = self.send_request('/svm/svms',
                                     'get', query=query)

        br_domains = self.send_request('/network/ethernet/broadcast-domains',
                                       'get', query=query)

        ipspace = {
            'ports': [],
            'vservers': [],
            'broadcast-domains': [],
        }

        for port in ports.get('records'):
            ipspace['ports'].append(port.get('name'))

        for vserver in vservers.get('records'):
            ipspace['vservers'].append(vserver.get('name'))

        for broadcast in br_domains.get('records'):
            ipspace['broadcast-domains'].append(broadcast.get('name'))

        ipspace['ipspace'] = ipspace_info.get('name')

        ipspace['uuid'] = ipspace_info.get('uuid')

        return ipspace

    @na_utils.trace
    def _delete_port_and_broadcast_domain(self, domain, ipspace):
        """Delete a broadcast domain and its ports."""

        ipspace_name = ipspace['ipspace']
        ports = ipspace['ports']

        for port in ports:
            self._delete_port_by_ipspace_and_broadcast_domain(
                port,
                domain,
                ipspace_name)

        query = {
            'name': domain,
            'ipspace.name': ipspace_name
        }

        self.send_request('/network/ethernet/broadcast-domains', 'delete',
                          query=query)

    @na_utils.trace
    def _delete_port_and_broadcast_domains_for_ipspace(self, ipspace_name):
        """Deletes all broadcast domains in an IPspace."""
        ipspace = self.get_ipspaces(ipspace_name)
        if not ipspace:
            return

        for broadcast_domain_name in ipspace['broadcast-domains']:
            self._delete_port_and_broadcast_domain(broadcast_domain_name,
                                                   ipspace)

    @na_utils.trace
    def delete_ipspace(self, ipspace_name):
        """Deletes an IPspace and its ports/domains."""

        self._delete_port_and_broadcast_domains_for_ipspace(ipspace_name)

        query = {
            'name': ipspace_name
        }
        self.send_request('/network/ipspaces', 'delete', query=query)

    @na_utils.trace
    def get_svm_volumes_total_size(self, svm_name):
        """Gets volumes sizes sum (GB) from all volumes in SVM by svm_name"""

        query = {
            'svm.name': svm_name,
            'fields': 'size'
        }

        response = self.send_request('/storage/volumes/', 'get', query=query)

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
