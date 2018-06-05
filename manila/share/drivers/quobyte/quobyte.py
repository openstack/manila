# Copyright (c) 2015 Quobyte Inc.
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

"""
Quobyte driver.

Manila shares are directly mapped to Quobyte volumes. The access to the
shares is provided by the Quobyte NFS proxy (a Ganesha NFS server).
"""

import math

from oslo_config import cfg
from oslo_log import log
from oslo_utils import units
import six

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers.quobyte import jsonrpc

LOG = log.getLogger(__name__)

quobyte_manila_share_opts = [
    cfg.StrOpt('quobyte_api_url',
               help='URL of the Quobyte API server (http or https)'),
    cfg.StrOpt('quobyte_api_ca',
               help='The X.509 CA file to verify the server cert.'),
    cfg.BoolOpt('quobyte_delete_shares',
                default=False,
                help='Actually deletes shares (vs. unexport)'),
    cfg.StrOpt('quobyte_api_username',
               default='admin',
               help='Username for Quobyte API server.'),
    cfg.StrOpt('quobyte_api_password',
               default='quobyte',
               secret=True,
               help='Password for Quobyte API server'),
    cfg.StrOpt('quobyte_volume_configuration',
               default='BASE',
               help='Name of volume configuration used for new shares.'),
    cfg.StrOpt('quobyte_default_volume_user',
               default='root',
               help='Default owning user for new volumes.'),
    cfg.StrOpt('quobyte_default_volume_group',
               default='root',
               help='Default owning group for new volumes.'),
]

CONF = cfg.CONF
CONF.register_opts(quobyte_manila_share_opts)


class QuobyteShareDriver(driver.ExecuteMixin, driver.ShareDriver,):
    """Map share commands to Quobyte volumes.

    Version history:
        1.0     - Initial driver.
        1.0.1   - Adds ensure_share() implementation.
        1.1     - Adds extend_share() and shrink_share() implementation.
        1.2     - Adds update_access() implementation and related methods
        1.2.1   - Improved capacity calculation
        1.2.2   - Minor optimizations
        1.2.3   - Updated RPC layer for improved stability
        1.2.4   - Fixed handling updated QB API error codes
        1.2.5   - Fixed two quota handling bugs
        1.2.6   - Fixed volume resize and jsonrpc code style bugs
    """

    DRIVER_VERSION = '1.2.6'

    def __init__(self, *args, **kwargs):
        super(QuobyteShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(quobyte_manila_share_opts)
        self.backend_name = (self.configuration.safe_get('share_backend_name')
                             or CONF.share_backend_name or 'Quobyte')

    def _fetch_existing_access(self, context, share):
        volume_uuid = self._resolve_volume_name(share['name'],
                                                share['project_id'])
        result = self.rpc.call('getConfiguration', {})
        if result is None:
            raise exception.QBException(
                "Could not retrieve Quobyte configuration data!")
        tenant_configs = result['tenant_configuration']
        qb_access_list = []
        for tc in tenant_configs:
            for va in tc['volume_access']:
                if va['volume_uuid'] == volume_uuid:
                    a_level = constants.ACCESS_LEVEL_RW
                    if va['read_only']:
                        a_level = constants.ACCESS_LEVEL_RO
                    qb_access_list.append({
                        'access_to': va['restrict_to_network'],
                        'access_level': a_level,
                        'access_type': 'ip'
                    })
        return qb_access_list

    def do_setup(self, context):
        """Prepares the backend."""
        self.rpc = jsonrpc.JsonRpc(
            url=self.configuration.quobyte_api_url,
            ca_file=self.configuration.quobyte_api_ca,
            user_credentials=(
                self.configuration.quobyte_api_username,
                self.configuration.quobyte_api_password))

        try:
            self.rpc.call('getInformation', {})
        except Exception as exc:
            LOG.error("Could not connect to API: %s", exc)
            raise exception.QBException(
                _('Could not connect to API: %s') % exc)

    def _update_share_stats(self):
        total_gb, free_gb = self._get_capacities()

        data = dict(
            storage_protocol='NFS',
            vendor_name='Quobyte',
            share_backend_name=self.backend_name,
            driver_version=self.DRIVER_VERSION,
            total_capacity_gb=total_gb,
            free_capacity_gb=free_gb,
            reserved_percentage=self.configuration.reserved_share_percentage)
        super(QuobyteShareDriver, self)._update_share_stats(data)

    def _get_capacities(self):
        result = self.rpc.call('getSystemStatistics', {})

        total = float(result['total_physical_capacity'])
        used = float(result['total_physical_usage'])
        LOG.info('Read capacity of %(cap)s bytes and '
                 'usage of %(use)s bytes from backend. ',
                 {'cap': total, 'use': used})
        free = total - used
        if free < 0:
            free = 0  # no space available
        free_replicated = free / self._get_qb_replication_factor()
        # floor numbers to nine digits (bytes)
        total = math.floor((total / units.Gi) * units.G) / units.G
        free = math.floor((free_replicated / units.Gi) * units.G) / units.G

        return total, free

    def _get_qb_replication_factor(self):
        result = self.rpc.call('getEffectiveVolumeConfiguration',
                               {'configuration_name': self.
                                configuration.quobyte_volume_configuration})
        return int(result['configuration']['volume_metadata_configuration']
                   ['replication_factor'])

    def check_for_setup_error(self):
        pass

    def get_network_allocations_number(self):
        return 0

    def _get_project_name(self, context, project_id):
        """Retrieve the project name.

        TODO (kaisers): retrieve the project name in order
        to store and use in the backend for better usability.
        """
        return project_id

    def _resize_share(self, share, new_size):
        newsize_bytes = new_size * units.Gi
        self.rpc.call('setQuota', {"quotas": [
            {"consumer":
                [{"type": "VOLUME",
                  "identifier": self._resolve_volume_name(share["name"],
                                                          share['project_id']),
                  "tenant_id": share["project_id"]}],
             "limits": [{"type": "LOGICAL_DISK_SPACE",
                        "value": newsize_bytes}]}
        ]})

    def _resolve_volume_name(self, volume_name, tenant_domain):
        """Resolve a volume name to the global volume uuid."""
        result = self.rpc.call('resolveVolumeName', dict(
            volume_name=volume_name,
            tenant_domain=tenant_domain), [jsonrpc.ERROR_ENOENT,
                                           jsonrpc.ERROR_ENTITY_NOT_FOUND])
        if result:
            return result['volume_uuid']
        return None  # not found

    def _subtract_access_lists(self, list_a, list_b):
        """Returns a list of elements in list_a that are not in list_b

        :param list_a: Base list of access rules
        :param list_b:  List of access rules not to be returned
        :return: List of elements of list_a not present in
        list_b
        """
        sub_tuples_list = [{"to": s.get('access_to'),
                            "type": s.get('access_type'),
                            "level": s.get('access_level')}
                           for s in list_b]
        return [r for r in list_a if (
            {"to": r.get("access_to"),
             "type": r.get("access_type"),
             "level": r.get("access_level")} not in sub_tuples_list)]

    def create_share(self, context, share, share_server=None):
        """Create or export a volume that is usable as a Manila share."""
        if share['share_proto'] != 'NFS':
            raise exception.QBException(
                _('Quobyte driver only supports NFS shares'))

        volume_uuid = self._resolve_volume_name(share['name'],
                                                share['project_id'])

        if not volume_uuid:
            # create tenant, expect ERROR_GARBAGE_ARGS if it already exists
            self.rpc.call('setTenant',
                          dict(tenant=dict(tenant_id=share['project_id'])),
                          expected_errors=[jsonrpc.ERROR_GARBAGE_ARGS])
            result = self.rpc.call('createVolume', dict(
                name=share['name'],
                tenant_domain=share['project_id'],
                root_user_id=self.configuration.quobyte_default_volume_user,
                root_group_id=self.configuration.quobyte_default_volume_group,
                configuration_name=(self.configuration.
                                    quobyte_volume_configuration)))
            volume_uuid = result['volume_uuid']

        result = self.rpc.call('exportVolume', dict(
            volume_uuid=volume_uuid,
            protocol='NFS'))

        self._resize_share(share, share['size'])

        return '%(nfs_server_ip)s:%(nfs_export_path)s' % result

    def delete_share(self, context, share, share_server=None):
        """Delete the corresponding Quobyte volume."""
        volume_uuid = self._resolve_volume_name(share['name'],
                                                share['project_id'])
        if not volume_uuid:
            LOG.warning("No volume found for "
                        "share %(project_id)s/%(name)s",
                        {"project_id": share['project_id'],
                         "name": share['name']})
            return

        if self.configuration.quobyte_delete_shares:
            self.rpc.call('deleteVolume', {'volume_uuid': volume_uuid})
        else:
            self.rpc.call('exportVolume', {"volume_uuid": volume_uuid,
                                           "remove_export": True,
                                           })

    def ensure_share(self, context, share, share_server=None):
        """Invoked to ensure that share is exported.

        :param context: The `context.RequestContext` object for the request
        :param share: Share instance that will be checked.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        :returns: IP:<nfs_export_path> of share
        :raises:
            :ShareResourceNotFound: If the share instance cannot be found in
            the backend
        """

        volume_uuid = self._resolve_volume_name(share['name'],
                                                share['project_id'])

        LOG.debug("Ensuring Quobyte share %s", share['name'])

        if not volume_uuid:
            raise (exception.ShareResourceNotFound(
                share_id=share['id']))

        result = self.rpc.call('exportVolume', dict(
            volume_uuid=volume_uuid,
            protocol='NFS'))

        return '%(nfs_server_ip)s:%(nfs_export_path)s' % result

    def _allow_access(self, context, share, access, share_server=None):
        """Allow access to a share."""
        if access['access_type'] != 'ip':
            raise exception.InvalidShareAccess(
                _('Quobyte driver only supports ip access control'))

        volume_uuid = self._resolve_volume_name(share['name'],
                                                share['project_id'])
        ro = access['access_level'] == (constants.ACCESS_LEVEL_RO)
        call_params = {
            "volume_uuid": volume_uuid,
            "read_only": ro,
            "add_allow_ip": access['access_to']}
        self.rpc.call('exportVolume', call_params)

    def _deny_access(self, context, share, access, share_server=None):
        """Remove white-list ip from a share."""
        if access['access_type'] != 'ip':
            LOG.debug('Quobyte driver only supports ip access control. '
                      'Ignoring deny access call for %s , %s',
                      share['name'],
                      self._get_project_name(context, share['project_id']))
            return

        volume_uuid = self._resolve_volume_name(share['name'],
                                                share['project_id'])
        call_params = {
            "volume_uuid": volume_uuid,
            "remove_allow_ip": access['access_to']}
        self.rpc.call('exportVolume', call_params)

    def extend_share(self, ext_share, ext_size, share_server=None):
        """Uses _resize_share to extend a share.

        :param ext_share: Share model.
        :param ext_size: New size of share (new_size > share['size']).
        :param share_server: Currently not used.
        """
        self._resize_share(share=ext_share, new_size=ext_size)

    def shrink_share(self, shrink_share, shrink_size, share_server=None):
        """Uses _resize_share to shrink a share.

        Quobyte uses soft quotas. If a shares current size is bigger than
        the new shrunken size no data is lost. Data can be continuously read
        from the share but new writes receive out of disk space replies.

        :param shrink_share: Share model.
        :param shrink_size: New size of share (new_size < share['size']).
        :param share_server: Currently not used.
        """
        self._resize_share(share=shrink_share, new_size=shrink_size)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules for given share.

        Two different cases are supported in here:
        1. Recovery after error - 'access_rules' contains all access_rules,
        'add_rules' and 'delete_rules' are empty. Driver should apply all
        access rules for given share.

        2. Adding/Deleting of several access rules - 'access_rules' contains
        all access_rules, 'add_rules' and 'delete_rules' contain rules which
        should be added/deleted. Driver can ignore rules in 'access_rules' and
        apply only rules from 'add_rules' and 'delete_rules'.

        :param context: Current context
        :param share: Share model with share data.
        :param access_rules: All access rules for given share
        :param add_rules: Empty List or List of access rules which should be
               added. access_rules already contains these rules.
        :param delete_rules: Empty List or List of access rules which should be
               removed. access_rules doesn't contain these rules.
        :param share_server: None or Share server model
        :raises If all of the *_rules params are None the method raises an
        InvalidShareAccess exception
        """
        if (add_rules or delete_rules):
            # Handling access rule update
            for d_rule in delete_rules:
                self._deny_access(context, share, d_rule)
            for a_rule in add_rules:
                self._allow_access(context, share, a_rule)
        else:
            if not access_rules:
                LOG.warning("No access rules provided in update_access.")
            else:
                # Handling access rule recovery
                existing_rules = self._fetch_existing_access(context, share)

                missing_rules = self._subtract_access_lists(access_rules,
                                                            existing_rules)
                for a_rule in missing_rules:
                    LOG.debug("Adding rule %s in recovery.",
                              six.text_type(a_rule))
                    self._allow_access(context, share, a_rule)

                superfluous_rules = self._subtract_access_lists(existing_rules,
                                                                access_rules)
                for d_rule in superfluous_rules:
                    LOG.debug("Removing rule %s in recovery.",
                              six.text_type(d_rule))
                    self._deny_access(context, share, d_rule)
