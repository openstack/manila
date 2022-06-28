# Copyright 2019 Inspur Corp.
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
Driver for Inspur InStorage
"""

import ipaddress
import itertools

from oslo_config import cfg
from oslo_log import log
from oslo_utils import units

from manila import coordination
from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share import utils as share_utils

from manila.share.drivers.inspur.instorage.cli_helper import InStorageSSH
from manila.share.drivers.inspur.instorage.cli_helper import SSHRunner

instorage_opts = [
    cfg.HostAddressOpt(
        'instorage_nas_ip',
        required=True,
        help='IP address for the InStorage.'
    ),
    cfg.PortOpt(
        'instorage_nas_port',
        default=22,
        help='Port number for the InStorage.'
    ),
    cfg.StrOpt(
        'instorage_nas_login',
        required=True,
        help='Username for the InStorage.'
    ),
    cfg.StrOpt(
        'instorage_nas_password',
        required=True,
        secret=True,
        help='Password for the InStorage.'
    ),
    cfg.ListOpt(
        'instorage_nas_pools',
        required=True,
        help='The Storage Pools Manila should use, a comma separated list.'
    )
]

CONF = cfg.CONF
CONF.register_opts(instorage_opts)
LOG = log.getLogger(__name__)


class InStorageShareDriver(driver.ShareDriver):
    """Inspur InStorage NAS driver. Allows for NFS and CIFS NAS.

    .. code::none
        Version history:
            1.0.0 - Initial driver.
                    Driver support:
                        share create/delete
                        extend size
                        update_access
                        protocol: NFS/CIFS
    """

    VENDOR = 'INSPUR'
    VERSION = '1.0.0'
    PROTOCOL = 'NFS_CIFS'

    def __init__(self, *args, **kwargs):
        super(InStorageShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(instorage_opts)

        self.backend_name = self.configuration.safe_get('share_backend_name')
        self.backend_pools = self.configuration.instorage_nas_pools

        self.ssh_runner = SSHRunner(**{
            'host': self.configuration.instorage_nas_ip,
            'port': 22,
            'login': self.configuration.instorage_nas_login,
            'password': self.configuration.instorage_nas_password
        })

        self.assistant = InStorageAssistant(self.ssh_runner)

    def check_for_setup_error(self):
        nodes = self.assistant.get_nodes_info()
        if len(nodes) == 0:
            msg = _('No valid node, be sure the NAS Port IP is configured')
            raise exception.ShareBackendException(msg=msg)

        pools = self.assistant.get_available_pools()
        not_exist = set(self.backend_pools).difference(set(pools))
        if not_exist:
            msg = _('Pool %s not exist on the storage system') % not_exist
            raise exception.InvalidParameterValue(msg)

    def _update_share_stats(self, **kwargs):
        """Retrieve share stats information."""

        try:
            stats = {
                'share_backend_name': self.backend_name,
                'vendor_name': self.VENDOR,
                'driver_version': self.VERSION,
                'storage_protocol': 'NFS_CIFS',
                'reserved_percentage':
                    self.configuration.reserved_share_percentage,
                'reserved_snapshot_percentage': (
                    self.configuration.reserved_share_from_snapshot_percentage
                    or self.configuration.reserved_share_percentage),
                'reserved_share_extend_percentage': (
                    self.configuration.reserved_share_extend_percentage
                    or self.configuration.reserved_share_percentage),
                'max_over_subscription_ratio':
                    self.configuration.max_over_subscription_ratio,
                'snapshot_support': False,
                'create_share_from_snapshot_support': False,
                'revert_to_snapshot_support': False,
                'qos': False,
                'total_capacity_gb': 0.0,
                'free_capacity_gb': 0.0,
                'pools': []
            }

            pools = self.assistant.get_pools_attr(self.backend_pools)
            total_capacity_gb = 0
            free_capacity_gb = 0
            for pool in pools.values():
                total_capacity_gb += pool['total_capacity_gb']
                free_capacity_gb += pool['free_capacity_gb']
                stats['pools'].append(pool)

            stats['total_capacity_gb'] = total_capacity_gb
            stats['free_capacity_gb'] = free_capacity_gb

            LOG.debug('share status %s', stats)

            super(InStorageShareDriver, self)._update_share_stats(stats)
        except Exception:
            msg = _('Unexpected error while trying to get the '
                    'usage stats from array.')
            LOG.exception(msg)
            raise

    @staticmethod
    def generate_share_name(share):
        # Generate a name with id of the share as base, and do follows:
        # 1. Remove the '-' in the id string.
        # 2. Transform all alpha to lower case.
        # 3. If the first char of the id is a num,
        #    transform it to an Upper case alpha start from 'A',
        #    such as '0' -> 'A', '1' -> 'B'.
        # e.g.
        # generate_share_name({
        #  'id': '46CF5E85-D618-4023-8727-6A1EA9292954',
        #  ...
        # })
        # returns 'E6cf5e85d618402387276a1ea9292954'

        name = share['id'].replace('-', '').lower()
        if name[0] in '0123456789':
            name = chr(ord('A') + ord(name[0]) - ord('0')) + name[1:]
        return name

    def get_network_allocations_number(self):
        """Get the number of network interfaces to be created."""

        return 0

    def create_share(self, context, share, share_server=None):
        """Create a new share instance."""
        share_name = self.generate_share_name(share)
        share_size = share['size']
        share_proto = share['share_proto']

        pool_name = share_utils.extract_host(share['host'], level='pool')

        self.assistant.create_share(
            share_name,
            pool_name,
            share_size,
            share_proto
        )

        return self.assistant.get_export_locations(share_name, share_proto)

    def delete_share(self, context, share, share_server=None):
        """Delete the given share instance."""
        share_name = self.generate_share_name(share)
        share_proto = share['share_proto']

        self.assistant.delete_share(share_name, share_proto)

    def extend_share(self, share, new_size, share_server=None):
        """Extend the share instance's size to new size."""
        share_name = self.generate_share_name(share)

        self.assistant.extend_share(share_name, new_size)

    def ensure_share(self, context, share, share_server=None):
        """Ensure that the share instance is exported."""
        share_name = self.generate_share_name(share)
        share_proto = share['share_proto']

        return self.assistant.get_export_locations(share_name, share_proto)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update the share instance's access rule."""
        share_name = self.generate_share_name(share)
        share_proto = share['share_proto']

        @coordination.synchronized('inspur-instorage-access-' + share_name)
        def _update_access(name, proto, rules, add_rules, delete_rules):
            self.assistant.update_access(
                name, proto, rules, add_rules, delete_rules
            )

        _update_access(
            share_name, share_proto, access_rules, add_rules, delete_rules
        )


class InStorageAssistant(object):

    NFS_CLIENT_SPEC_PATTERN = (
        '%(ip)s/%(mask)s:%(rights)s:%(all_squash)s:%(root_squash)s'
    )

    CIFS_CLIENT_RIGHT_PATTERN = (
        '%(type)s:%(name)s:%(rights)s'
    )

    def __init__(self, ssh_runner):
        self.ssh = InStorageSSH(ssh_runner)

    @staticmethod
    def handle_keyerror(cmd, out):
        msg = (_('Could not find key in output of command %(cmd)s: %(out)s.')
               % {'out': out, 'cmd': cmd})
        raise exception.ShareBackendException(msg=msg)

    def size_to_gb(self, size):
        new_size = 0

        if 'P' in size:
            new_size = int(float(size.rstrip('PB')) * units.Mi)
        elif 'T' in size:
            new_size = int(float(size.rstrip('TB')) * units.Ki)
        elif 'G' in size:
            new_size = int(float(size.rstrip('GB')) * 1)
        elif 'M' in size:
            mb_size = float(size.rstrip('MB'))
            new_size = int((mb_size + units.Ki - 1) / units.Ki)

        return new_size

    def get_available_pools(self):
        nas_pools = self.ssh.lsnaspool()
        return [pool['pool_name'] for pool in nas_pools]

    def get_pools_attr(self, backend_pools):
        pools = {}
        fs_attr = self.ssh.lsfs()
        nas_pools = self.ssh.lsnaspool()
        for pool_attr in nas_pools:
            pool_name = pool_attr['pool_name']
            if pool_name not in backend_pools:
                continue

            total_used_capacity = 0
            total_allocated_capacity = 0
            for fs in fs_attr:
                if fs['pool_name'] != pool_name:
                    continue
                allocated = self.size_to_gb(fs['total_capacity'])
                used = self.size_to_gb(fs['used_capacity'])

                total_allocated_capacity += allocated
                total_used_capacity += used

            available = self.size_to_gb(pool_attr['available_capacity'])

            pool = {
                'pool_name': pool_name,
                'total_capacity_gb': total_allocated_capacity + available,
                'free_capacity_gb': available,
                'allocated_capacity_gb': total_allocated_capacity,
                'reserved_percentage': 0,
                'reserved_snapshot_percentage': 0,
                'reserved_share_extend_percentage': 0,
                'qos': False,
                'dedupe': False,
                'compression': False,
                'thin_provisioning': False,
                'max_over_subscription_ratio': 0
            }

            pools[pool_name] = pool

        return pools

    def get_nodes_info(self):
        """Return a dictionary containing information of system's nodes."""
        nodes = {}
        resp = self.ssh.lsnasportip()
        for port in resp:
            try:
                # Port is invalid if it has no IP configured.
                if port['ip'] == '':
                    continue

                node_name = port['node_name']
                if node_name not in nodes:
                    nodes[node_name] = {}

                node = nodes[node_name]
                node[port['id']] = port
            except KeyError:
                self.handle_keyerror('lsnasportip', port)

        return nodes

    @staticmethod
    def get_fsname_by_name(name):
        return ('%(fsname)s' % {'fsname': name})[0:32]

    @staticmethod
    def get_dirname_by_name(name):
        return ('%(dirname)s' % {'dirname': name})[0:32]

    def get_dirpath_by_name(self, name):
        fsname = self.get_fsname_by_name(name)
        dirname = self.get_dirname_by_name(name)

        return '/fs/%(fsname)s/%(dirname)s' % {
            'fsname': fsname, 'dirname': dirname
        }

    def create_share(self, name, pool, size, proto):
        """Create a share with given info."""

        # use one available node as the primary node
        nodes = self.get_nodes_info()
        if len(nodes) == 0:
            msg = _('No valid node, be sure the NAS Port IP is configured')
            raise exception.ShareBackendException(msg=msg)

        node_name = [key for key in nodes.keys()][0]

        # first create the file system on which share will be created
        fsname = self.get_fsname_by_name(name)
        self.ssh.addfs(fsname, pool, size, node_name)

        # then create the directory used for the share
        dirpath = self.get_dirpath_by_name(name)
        self.ssh.addnasdir(dirpath)

        # For CIFS, we need to create a CIFS share.
        # For NAS, the share is automatically added when the first
        # 'access spec' is added on it.
        if proto == 'CIFS':
            self.ssh.addcifs(name, dirpath)

    def check_share_exist(self, name):
        """Check whether the specified share exist on backend."""

        fsname = self.get_fsname_by_name(name)
        for fs in self.ssh.lsfs():
            if fs['fs_name'] == fsname:
                return True
        return False

    def delete_share(self, name, proto):
        """Delete the given share."""

        if not self.check_share_exist(name):
            LOG.warning('Share %s does not exist on the backend.', name)
            return

        # For CIFS, we have to delete the share first.
        # For NAS, when the last client access spec is removed from
        # it, the share is automatically deleted.
        if proto == 'CIFS':
            self.ssh.rmcifs(name)

        # then delete the directory
        dirpath = self.get_dirpath_by_name(name)
        self.ssh.rmnasdir(dirpath)

        # at last delete the file system
        fsname = self.get_fsname_by_name(name)
        self.ssh.rmfs(fsname)

    def extend_share(self, name, new_size):
        """Extend a given share to a new size.

        :param name: the name of the share.
        :param new_size: the new size the share should be.
        :return:
        """
        # first get the original capacity
        old_size = None
        fsname = self.get_fsname_by_name(name)
        for fs in self.ssh.lsfs():
            if fs['fs_name'] == fsname:
                old_size = self.size_to_gb(fs['total_capacity'])
                break

        if old_size is None:
            msg = _('share %s is not available') % name
            raise exception.ShareBackendException(msg=msg)

        LOG.debug('Extend fs %s from %dGB to %dGB', fsname, old_size, new_size)
        self.ssh.expandfs(fsname, new_size - old_size)

    def get_export_locations(self, name, share_proto):
        """Get the export locations of a given share.

        :param name: the name of the share.
        :param share_proto: the protocol of the share.
        :return: a list of export locations.
        """

        if share_proto == 'NFS':
            dirpath = self.get_dirpath_by_name(name)
            pattern = '%(ip)s:' + dirpath
        elif share_proto == 'CIFS':
            pattern = '\\\\%(ip)s\\' + name
        else:
            msg = _('share protocol %s is not supported') % share_proto
            raise exception.ShareBackendException(msg=msg)

        # we need get the node so that we know which port ip we can use
        node_name = None
        fsname = self.get_fsname_by_name(name)
        for node in self.ssh.lsnode():
            for fs in self.ssh.lsfs(node['name']):
                if fs['fs_name'] == fsname:
                    node_name = node['name']
                    break
            if node_name:
                break

        if node_name is None:
            msg = _('share %s is not available') % name
            raise exception.ShareBackendException(msg=msg)

        locations = []
        ports = self.ssh.lsnasportip()
        for port in ports:
            if port['node_name'] == node_name and port['ip'] != '':
                location = pattern % {'ip': port['ip']}

                locations.append({
                    'path': location,
                    'is_admin_only': False,
                    'metadata': {}
                })

        return locations

    def classify_nfs_client_spec(self, client_spec, dirpath):
        nfslist = self.ssh.lsnfslist(dirpath)
        if len(nfslist):
            nfsinfo = self.ssh.lsnfsinfo(dirpath)
            spec_set = set([
                self.NFS_CLIENT_SPEC_PATTERN % i for i in nfsinfo
            ])
        else:
            spec_set = set()

        client_spec_set = set(client_spec)

        del_spec = spec_set.difference(client_spec_set)
        add_spec = client_spec_set.difference(spec_set)

        return list(add_spec), list(del_spec)

    def access_rule_to_client_spec(self, access_rule):
        if access_rule['access_type'] != 'ip':
            msg = _('only ip access type is supported when using NFS protocol')
            raise exception.ShareBackendException(msg=msg)

        network = ipaddress.ip_network(str(access_rule['access_to']))
        if network.version != 4:
            msg = _('only IPV4 is accepted when using NFS protocol')
            raise exception.ShareBackendException(msg=msg)

        client_spec = self.NFS_CLIENT_SPEC_PATTERN % {
            'ip': str(network.network_address),
            'mask': str(network.netmask),
            'rights': access_rule['access_level'],
            'all_squash': 'all_squash',
            'root_squash': 'root_squash'
        }

        return client_spec

    def update_nfs_access(self, share_name, access_rules, add_rules,
                          delete_rules):
        """Update a NFS share's access rule."""

        dirpath = self.get_dirpath_by_name(share_name)
        if add_rules or delete_rules:
            add_spec = [
                self.access_rule_to_client_spec(r) for r in add_rules
            ]
            del_spec = [
                self.access_rule_to_client_spec(r) for r in delete_rules
            ]

            _, can_del_spec = self.classify_nfs_client_spec(
                [], dirpath
            )
            to_del_set = set(del_spec)
            can_del_set = set(can_del_spec)
            will_del_set = to_del_set.intersection(can_del_set)
            del_spec = list(will_del_set)
        else:
            access_spec = [
                self.access_rule_to_client_spec(r) for r in access_rules
            ]

            add_spec, del_spec = self.classify_nfs_client_spec(
                access_spec, dirpath
            )

        for spec in del_spec:
            self.ssh.rmnfsclient(dirpath, spec)
        for spec in add_spec:
            self.ssh.addnfsclient(dirpath, spec)

    def classify_cifs_rights(self, access_rights, share_name):
        cifsinfo = self.ssh.lscifsinfo(share_name)
        rights_set = set([
            self.CIFS_CLIENT_RIGHT_PATTERN % i for i in cifsinfo
        ])
        access_rights_set = set(access_rights)

        del_rights = rights_set.difference(access_rights_set)
        add_rights = access_rights_set.difference(rights_set)

        return list(add_rights), list(del_rights)

    def access_rule_to_rights(self, access_rule):
        if access_rule['access_type'] != 'user':
            msg = _('only user access type is supported'
                    ' when using CIFS protocol')
            raise exception.ShareBackendException(msg=msg)

        rights = self.CIFS_CLIENT_RIGHT_PATTERN % {
            'type': 'LU',
            'name': access_rule['access_to'],
            'rights': access_rule['access_level']
        }

        return rights

    def update_cifs_access(self, share_name, access_rules, add_rules,
                           delete_rules):
        """Update a CIFS share's access rule."""

        if add_rules or delete_rules:
            add_rights = [
                self.access_rule_to_rights(r) for r in add_rules
            ]
            del_rights = [
                self.access_rule_to_rights(r) for r in delete_rules
            ]
        else:
            access_rights = [
                self.access_rule_to_rights(r) for r in access_rules
            ]

            add_rights, del_rights = self.classify_cifs_rights(
                access_rights, share_name
            )

        for rights in del_rights:
            self.ssh.rmcifsuser(share_name, rights)
        for rights in add_rights:
            self.ssh.addcifsuser(share_name, rights)

    @staticmethod
    def check_access_type(access_type, *rules):
        rule_chain = itertools.chain(*rules)
        if all([r['access_type'] == access_type for r in rule_chain]):
            return True
        else:
            return False

    def update_access(self, share_name, share_proto,
                      access_rules, add_rules, delete_rules):
        if share_proto == 'CIFS':
            if self.check_access_type('user', access_rules,
                                      add_rules, delete_rules):
                self.update_cifs_access(share_name, access_rules,
                                        add_rules, delete_rules)
            else:
                msg = _("Only %s access type allowed.") % "user"
                raise exception.InvalidShareAccess(reason=msg)
        elif share_proto == 'NFS':
            if self.check_access_type('ip', access_rules,
                                      add_rules, delete_rules):
                self.update_nfs_access(share_name, access_rules,
                                       add_rules, delete_rules)
            else:
                msg = _("Only %s access type allowed.") % "ip"
                raise exception.InvalidShareAccess(reason=msg)
        else:
            msg = _('share protocol %s is not supported') % share_proto
            raise exception.ShareBackendException(msg=msg)
