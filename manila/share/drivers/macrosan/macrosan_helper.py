# Copyright (c) 2022 MacroSAN Technologies Co., Ltd.
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

import re

from oslo_config import cfg
from oslo_log import log
from oslo_utils import units

from manila import exception
from manila.i18n import _
from manila.share.drivers.macrosan import macrosan_constants as constants
from manila.share.drivers.macrosan import rest_helper
from manila.share import utils as share_utils

CONF = cfg.CONF

LOG = log.getLogger(__name__)


class MacrosanHelper(object):
    def __init__(self, configuration):
        self.configuration = configuration
        self.rest = rest_helper.RestHelper(self.configuration)
        self.snapshot_support = False
        self.replication_support = False
        self.pools = self.configuration.macrosan_share_pools

    def check_share_service(self):
        nfs_service = self.rest._get_nfs_service_status()
        if nfs_service['serviceStatus'] not in [constants.NFS_NON_CONFIG,
                                                constants.NFS_ENABLED,
                                                constants.NFS_DISABLED]:
            raise exception.MacrosanBackendExeption(
                reason=_("nfs service exception. Please check backend"))
        elif nfs_service['serviceStatus'] == constants.NFS_NON_CONFIG:
            self.rest._config_nfs_service()
            self.rest._start_nfs_service()
        elif nfs_service['serviceStatus'] == constants.NFS_DISABLED:
            if (nfs_service['nfs3Status'] == constants.NFS_NON_SUPPORTED and
                    nfs_service['nfs4Status'] == constants.NFS_NON_SUPPORTED):
                self.rest._config_nfs_service()
            self.rest._start_nfs_service()
        else:
            if (nfs_service['nfs3Status'] == constants.NFS_NON_SUPPORTED and
                    nfs_service['nfs4Status'] == constants.NFS_NON_SUPPORTED):
                self.rest._config_nfs_service()

        cifs_status = self.rest._get_cifs_service_status()
        if cifs_status == constants.CIFS_EXCEPTION:
            raise exception.MacrosanBackendExeption(
                reason=_("cifs service exception. Please check backend"))
        elif cifs_status == constants.CIFS_NON_CONFIG:
            """need config first, then start service"""
            self.rest._config_cifs_service()
            self.rest._start_cifs_service()
        elif cifs_status == constants.CIFS_DISABLED:
            self.rest._start_cifs_service()
            status = self.rest._get_cifs_service_status()
            if status == constants.CIFS_SHARE_MODE:
                self.rest._config_cifs_service()
        elif cifs_status == constants.CIFS_SHARE_MODE:
            self.rest._config_cifs_service()

    def do_setup(self):
        """get token"""
        self.rest.login()

    def create_share(self, share, share_server=None):
        """Create a share"""
        pool_name, share_name, proto = self._get_share_instance_pnp(share)
        share_size = ''.join((str(share['size']), 'GB'))

        # first create filesystem
        self.rest._create_filesystem(fs_name=share_name,
                                     pool_name=pool_name,
                                     filesystem_quota=share_size)

        share_path = self._generate_share_path(share_name)
        # second create filesystem dir
        self.rest._create_filesystem_dir(share_path)
        # third create nfs or cifs share
        if proto == 'NFS':
            self.rest._create_nfs_share(share_path=share_path)
        else:
            user_name = 'manilanobody'
            user_passwd = 'manilanobody'
            group_name = 'manilanobody'
            ret = self._ensure_user(user_name, user_passwd, group_name)
            if not ret:
                self.rest._delete_filesystem(share_name)
                raise exception.MacrosanBackendExeption(
                    reason=(_(
                        'Failed to create share %(share)s. Reason: '
                        'username %(user_name)s error.')
                        % {'share': share_name, 'user_name': user_name}))

            rw_list = [user_name]
            rw_list_type = ['0']
            self.rest._create_cifs_share(share_name=share_name,
                                         share_path=share_path,
                                         rw_list=rw_list,
                                         rw_list_type=rw_list_type)

        location = self._get_location_path(share_path, share_name, proto)
        return location

    def delete_share(self, share, share_server=None):
        """Delete a share."""
        pool, share_name, proto = self._get_share_instance_pnp(share)
        share_path = self._generate_share_path(share_name)

        backend_share = self._get_share(share_path, proto)
        if not backend_share:
            LOG.error(f'Share {share_name} not found.')
            filesystem = self.rest._get_filesystem(share_name)
            if filesystem:
                self.rest._delete_filesystem(share_name)
        else:
            if proto == 'NFS':
                self.rest._delete_nfs_share(share_path)
            else:
                self.rest._delete_cifs_share(share_name, share_path)
            self.rest._delete_filesystem(share_name)

    def extend_share(self, share, new_size, share_server=None):
        """Extend share"""
        pool, share_name, proto = self._get_share_instance_pnp(share)
        share_path = self._generate_share_path(share_name)
        backend_share = self._get_share(share_path, proto)
        if not backend_share:
            msg = f"Can't find the share by share name: {share_name}."
            msg = _(msg)
            LOG.error(msg)
            raise exception.ShareResourceNotFound(share_id=share['id'])

        # storage size logic already in manila/share/api.py extend func
        # size param need unit
        new_size = ''.join((str(new_size), 'GB'))
        self.rest._update_share_size(share_name, new_size)

    def shrink_share(self, share, new_size, share_server=None):
        """Shrink share"""
        pool, share_name, proto = self._get_share_instance_pnp(share)
        share_path = self._generate_share_path(share_name)
        backend_share = self._get_share(share_path, proto)
        if not backend_share:
            msg = f"Can't find the share by share name: {share_name}."
            msg = _(msg)
            LOG.error(msg)
            raise exception.ShareResourceNotFound(share_id=share['id'])

        filesystem_info = self.rest._get_filesystem(share_name)
        used_size = self._unit_convert_toGB(filesystem_info['usedCapacity'])
        if new_size <= used_size:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share['id'])
        # storage size logic already in manila/share/api.py shrink func
        new_size = ''.join((str(new_size), 'GB'))
        self.rest._update_share_size(share_name, new_size)

    def ensure_share(self, share, share_server=None):
        """Enusre that share is exported"""
        pool, share_name, proto = self._get_share_instance_pnp(share)
        share_path = self._generate_share_path(share_name)
        backend_share = self._get_share(share_path, proto)
        if not backend_share:
            raise exception.ShareResourceNotFound(share_id=share['id'])

        location = self._get_location_path(share_path, share_name, proto)
        return [location]

    def _allow_access(self, share, access, share_server=None):
        """Allow access to the share."""
        pool, share_name, proto = self._get_share_instance_pnp(share)
        share_path = self._generate_share_path(share_name)
        access_level = access['access_level']
        share_id = share['id']
        if access_level not in ('rw', 'ro'):
            raise exception.InvalidShareAccess(
                reason=(_('Unsupported access level: %s.') % access_level))
        if proto == 'NFS':
            self._allow_nfs_access(share_path, share_name, access, share_id)
        elif proto == 'CIFS':
            self._allow_cifs_access(share_path, share_name, access, share_id)

    def _allow_nfs_access(self, share_path, share_name, access, share_id):
        """Allow nfs access."""
        access_type = access['access_type']
        access_to = access['access_to']
        access_level = access['access_level']
        # Only use 'ip',
        # input "*" replace all, or ip 172.0.1.11 ,
        # or  ip network segment 172.0.1.11/255.255.0.0  172.0.1.11/16
        if access_type != 'ip':
            message = (_('NFS shares only allow IP access types. '
                         'access_type: %(access_type)s') %
                       {'access_type': access_type})
            raise exception.InvalidShareAccess(reason=message)
        backend_share = self.rest._get_nfs_share(share_path)
        if not backend_share:
            msg = (_("Can't find the share by share name: %s.")
                   % share_name)
            LOG.error(msg)
            raise exception.ShareResourceNotFound(share_id=share_id)

        if access_to == '0.0.0.0/0':
            access_to = '*'
        share_client = self.rest._get_access_from_nfs_share(share_path,
                                                            access_to)

        if share_client:
            if access_level != share_client['accessRight']:
                self.rest._change_nfs_access_rest(share_path,
                                                  access_to,
                                                  access_level)
        else:
            self.rest._allow_nfs_access_rest(share_path,
                                             access_to,
                                             access_level)

    def _allow_cifs_access(self, share_path, share_name, access, share_id):
        """Allow cifs access."""
        access_type = access['access_type']
        access_to = access['access_to']
        access_level = access['access_level']
        if access_type != 'user':
            message = _('Only user access type is '
                        'allowed for CIFS shares.')
            raise exception.InvalidShareAccess(reason=message)

        backend_share = self.rest._get_cifs_share(share_path)
        if not backend_share:
            msg = (_("Can't find the share by share name: %s.")
                   % share_name)
            LOG.error(msg)
            raise exception.ShareResourceNotFound(share_id=share_id)

        share_client = self.rest._get_access_from_cifs_share(share_path,
                                                             access_to)
        if share_client:
            if access_level != share_client['accessRight']:
                self.rest._change_cifs_access_rest(share_path,
                                                   access_to,
                                                   access_level,
                                                   share_client['ugType'])
        else:
            self.rest._allow_cifs_access_rest(share_path,
                                              access_to,
                                              access_level)

    def _deny_access(self, share, access, share_server=None):
        """Deny access to the share."""
        pool, share_name, proto = self._get_share_instance_pnp(share)
        share_path = self._generate_share_path(share_name)

        if proto == 'NFS':
            self._deny_nfs_access(share_path, share_name, access)
        else:
            self._deny_cifs_access(share_path, share_name, access)

    def _deny_nfs_access(self, share_path, share_name, access):
        """Deny nfs access."""
        access_type = access['access_type']
        access_to = access['access_to']
        if access_type != 'ip':
            LOG.error('Only IP access types are allowed '
                      'for NFS shares.')
            return
        if access_to == '0.0.0.0/0':
            access_to = '*'
        share_client = self.rest._get_access_from_nfs_share(share_path,
                                                            access_to)
        if not share_client:
            LOG.error(f'Could not list the share access for share '
                      f'{share_name}')
            return
        self.rest._delete_nfs_access_rest(share_path, access_to)

    def _deny_cifs_access(self, share_path, share_name, access):
        """Deny cifs access."""
        access_type = access['access_type']
        access_to = access['access_to']
        if access_type != 'user':
            LOG.error('Only USER access types are allowed '
                      'for CIFS shares.')
            return
        share_client = self.rest._get_access_from_cifs_share(share_path,
                                                             access_to)
        if not share_client:
            LOG.error(f'Could not list the share access for share '
                      f'{share_name}')
            return
        self.rest._delete_cifs_access_rest(share_path,
                                           share_client['ugName'],
                                           share_client['ugType'])

    def _clear_access(self, share, share_server=None):
        """Remove all access rules of the share"""
        pool, share_name, proto = self._get_share_instance_pnp(share)
        share_path = self._generate_share_path(share_name)
        access_list = self._get_all_access_from_share(share_path, proto)
        if not access_list:
            LOG.error(f'Could not list the share access for share '
                      f'{share_name}')
            return

        if proto == 'NFS':
            for share_access in access_list:
                # IPv4 Address Blocks Reserved for Documentation
                if share_access['access_to'] == '192.0.2.0':
                    continue
                self.rest._delete_nfs_access_rest(share_path,
                                                  share_access['access_to'])
        elif proto == 'CIFS':
            for share_access in access_list:
                if (share_access['access_to'] == 'manilanobody'
                        and share_access['ugType'] == '0'):
                    continue
                self.rest._delete_cifs_access_rest(share_path,
                                                   share_access['access_to'],
                                                   share_access['ugType'])

    def update_access(self, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules list."""
        access_updates = {}
        if not (add_rules or delete_rules):
            self._clear_access(share, share_server)
            for access_rule in access_rules:
                try:
                    self._allow_access(share, access_rule, share_server)
                except exception.InvalidShareAccess as e:
                    msg = f'Failed to allow {access_rule["access_level"]} ' \
                          f'access to {access_rule["access_to"]}, reason {e}'
                    msg = _(msg)
                    LOG.error(msg)
                    access_updates.update(
                        {access_rule['access_id']: {'state': 'error'}})
        else:
            for access_rule in delete_rules:
                self._deny_access(share, access_rule, share_server)
            for access_rule in add_rules:
                try:
                    self._allow_access(share, access_rule, share_server)
                except exception.InvalidShareAccess as e:
                    msg = f'Failed to allow {access_rule["access_level"]} ' \
                          f'access to {access_rule["access_to"]}, reason {e}'
                    msg = _(msg)
                    LOG.error(msg)
                    access_updates.update(
                        {access_rule['access_id']: {'state': 'error'}})
        return access_updates

    def _get_all_access_from_share(self, share_path, share_proto):
        access_list = []
        if share_proto == 'NFS':
            access_list = self.rest._get_all_nfs_access_rest(share_path)
        elif share_proto == 'CIFS':
            access_list = self.rest._get_all_cifs_access_rest(share_path)
        return access_list

    def _ensure_user(self, user_name, user_passwd, group_name):
        ret_user = self.rest._query_user(user_name)
        if ret_user == constants.USER_NOT_EXIST:
            ret_group = self.rest._query_group(group_name)
            if ret_group not in [constants.GROUP_NOT_EXIST,
                                 constants.GROUP_EXIST]:
                msg = f'Failed to use group {group_name}'
                msg = _(msg)
                raise exception.InvalidInput(reason=msg)
            elif ret_group == constants.GROUP_NOT_EXIST:
                self.rest._add_localgroup(group_name)
            self.rest._add_localuser(user_name, user_passwd, group_name)
            return True
        elif ret_user == constants.USER_EXIST:
            return True
        else:
            return False

    def update_share_stats(self, dict_data):
        """Update pools info"""
        result = self.rest._get_all_pool()
        dict_data["pools"] = []
        for pool_name in self.pools:
            pool_capacity = self._get_pool_capacity(pool_name, result)
            if pool_capacity:
                pool = {
                    'pool_name': pool_name,
                    'total_capacity_gb': pool_capacity['totalcapacity'],
                    'free_capacity_gb': pool_capacity['freecapacity'],
                    'allocated_capacity_gb':
                        pool_capacity['allocatedcapacity'],
                    'reserved_percentage':
                        self.configuration.reserved_share_percentage,
                    'reserved_snapshot_percentage':
                        self.configuration
                            .reserved_share_from_snapshot_percentage
                        or self.configuration.reserved_share_percentage,
                    'reserved_share_extend_percentage':
                        self.configuration.reserved_share_extend_percentage
                        or self.configuration.reserved_share_percentage,
                    'dedupe': False,
                    'compression': False,
                    'qos': False,
                    'thin_provisioning': False,
                    'snapshot_support': self.snapshot_support,
                    'create_share_from_snapshot_support':
                        self.snapshot_support,
                }

                dict_data["pools"].append(pool)

        if not dict_data['pools']:
            msg = _("StoragePool is None")
            LOG.error(msg)
            raise exception.InvalidInput(reason=msg)

    def _get_pool_capacity(self, pool_name, result):
        """Get total,allocated,free capacity of the pools"""
        pool_info = self._find_pool_info(pool_name, result)

        if pool_info:
            total_capacity = int(self._unit_convert_toGB(
                pool_info['totalcapacity']))
            free_capacity = int(self._unit_convert_toGB(
                pool_info['freecapacity']))
            allocated_capacity = int(self._unit_convert_toGB(
                pool_info['allocatedcapacity']))

            pool_info['totalcapacity'] = total_capacity
            pool_info['freecapacity'] = free_capacity
            pool_info['allocatedcapacity'] = allocated_capacity

        return pool_info

    def _unit_convert_toGB(self, capacity):
        """Convert unit to GB"""
        capacity = capacity.upper()

        try:
            # get unit char array and use join connect to string
            unit = re.findall(r'[A-Z]', capacity)
            unit = ''.join(unit)
        except BaseException:
            unit = ''
        # get capacity size,unit is GB
        capacity = capacity.replace(unit, '')
        capacity = float(capacity)
        if unit in ['B', '']:
            capacity = capacity / units.Gi
        elif unit in ['K', 'KB']:
            capacity = capacity / units.Mi
        elif unit in ['M', 'MB']:
            capacity = capacity / units.Ki
        elif unit in ['G', 'GB']:
            capacity = capacity
        elif unit in ['T', 'TB']:
            capacity = capacity * units.Ki
        elif unit in ['E', 'EB']:
            capacity = capacity * units.Mi

        capacity = '%.0f' % capacity

        return float(capacity)

    def _generate_share_name(self, share):
        share_name = 'manila_%s' % share['id']
        return self._format_name(share_name)

    def _format_name(self, name):
        """format name to meet the backend requirements"""
        name = name[0: 31]
        name = name.replace('-', '_')
        return name

    def _generate_share_path(self, share_name):
        """add '/' as path"""
        share_path = r'/%(path)s/%(dirName)s' % {
            'path': share_name.replace("-", "_"),
            'dirName': share_name.replace("-", "_")
        }
        return share_path

    def _get_location_path(self, share_path, share_name, share_proto, ip=None):
        location = None
        if ip is None:
            ip = self.configuration.macrosan_nas_ip
        share_proto = share_proto.upper()
        if share_proto == 'NFS':
            location = f'{ip}:{share_path}'
        elif share_proto == 'CIFS':
            location = f'\\\\{ip}\\{share_name}'
        return location

    def _get_share_instance_pnp(self, share_instance):

        proto = share_instance['share_proto'].upper()
        share_name = self._generate_share_name(share_instance)
        pool = share_utils.extract_host(share_instance['host'], level='pool')
        if not pool:
            msg = _("Pool doesn't exist in host field.")
            raise exception.InvalidHost(reason=msg)

        if proto != 'NFS' and proto != 'CIFS':
            msg = f'Share protocol {proto} is not supported.'
            msg = _(msg)
            raise exception.MacrosanBackendExeption(reason=msg)

        return pool, share_name, proto

    def _get_share(self, share_path, proto):
        return (self.rest._get_nfs_share(share_path)
                if proto == 'NFS'
                else self.rest._get_cifs_share(share_path))

    def _find_pool_info(self, pool_name, result):
        if pool_name is None:
            return
        pool_info = {}
        pool_name = pool_name.strip()

        for item in result.get('data', []):
            if pool_name == item['name']:
                pool_info['name'] = item['name']
                pool_info['totalcapacity'] = item['size']
                pool_info['allocatedcapacity'] = item['allocated']
                pool_info['freecapacity'] = item['free']
                pool_info['health'] = item['health']
                pool_info['rw'] = item['rwStatus']
                break

        return pool_info
