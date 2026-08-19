# Copyright 2026 Red Hat, Inc.
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
Share driver for Lustre parallel filesystem.

Uses sub-directories with project quotas on a pre-provisioned Lustre
filesystem. Access control is via Lustre nodemaps (requires Lustre >= 2.16).
"""

import hashlib
import ipaddress
import os
import re
import shlex

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log
from oslo_utils import units

from manila.common import constants
from manila import coordination
from manila import exception
from manila.i18n import _
from manila.privsep import lustre as privsep_lustre
from manila.privsep import os as privsep_os
from manila.share import driver
from manila import ssh_utils

LOG = log.getLogger(__name__)

LUSTRE_MIN_VERSION = (2, 16)

lustre_opts = [
    cfg.HostAddressOpt(
        'lustre_share_export_ip',
        required=True,
        help="IP or hostname of the Lustre client mount point that is "
             "accessible to tenants. Used in export locations."),
    cfg.HostAddressOpt(
        'lustre_mgs_ip',
        help="IP or hostname of the Lustre MGS for SSH nodemap operations. "
             "If not set, nodemap commands run locally via oslo.privsep."),
    cfg.HostAddressOpt(
        'lustre_mds_ip',
        help="IP or hostname of the Lustre MDS for SSH quota operations. "
             "If not set, quota commands run locally via oslo.privsep."),
    cfg.StrOpt(
        'lustre_mount_point',
        default='/mnt/lustre',
        required=True,
        help="Local mount point of the Lustre filesystem on the "
             "manila-share host."),
    cfg.StrOpt(
        'lustre_mds_mount_point',
        help="Mount point of the Lustre filesystem on the MDS host. "
             "Only needed when lustre_mds_ip is set and the MDS "
             "mount path differs from lustre_mount_point. "
             "Defaults to lustre_mount_point."),
    cfg.StrOpt(
        'lustre_fs_name',
        required=True,
        help="Name of the Lustre filesystem."),
    cfg.StrOpt(
        'lustre_share_path_prefix',
        default='manila_shares',
        help="Sub-directory under the mount point where Manila shares "
             "are created."),
    cfg.IntOpt(
        'lustre_project_id_start',
        default=10000,
        help="Starting Lustre project ID for quota allocation."),
    cfg.IntOpt(
        'lustre_project_id_end',
        default=60000,
        help="Maximum Lustre project ID for quota allocation."),
    cfg.StrOpt(
        'lustre_nid_type',
        default='tcp',
        help="Lustre NID type for client access (tcp, o2ib, etc)."),
    cfg.StrOpt(
        'lustre_ssh_username',
        default='root',
        help="SSH username for connecting to Lustre MGS/MDS."),
    cfg.StrOpt(
        'lustre_ssh_private_key_path',
        help="Path to SSH private key for MGS/MDS access."),
    cfg.BoolOpt(
        'lustre_reapply_access_on_startup',
        default=False,
        help="Reapply nodemap access rules for every share when the "
             "manila-share service starts. Nodemaps persist on the MGS, "
             "so this is not needed during normal operation. Enable "
             "temporarily to recover after a MGS rebuild or manual "
             "nodemap deletion."),
]

CONF = cfg.CONF


class LustreShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """Manila share driver for Lustre parallel filesystem.

    Creates shares as sub-directories on a pre-provisioned Lustre
    filesystem. Uses Lustre project quotas for capacity management
    and nodemaps for IP-based access control.

    Requires Lustre >= 2.16 for RBAC nodemaps and root project quota
    enforcement.
    """

    def __init__(self, *args, **kwargs):
        super(LustreShareDriver, self).__init__(
            [False], *args, **kwargs)
        self.configuration.append_config_values(lustre_opts)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'Lustre'
        self.private_storage = kwargs.get('private_storage')
        self.configuration.protocol_access_mapping = {
            'ip': ['lustre'],
        }
        self._mgs_ssh = None
        self._mds_ssh = None

    def do_setup(self, context):
        self.init_execute_mixin()
        mount_point = self.configuration.lustre_mount_point

        if not os.path.ismount(mount_point):
            raise exception.ShareBackendException(
                msg=_("Lustre filesystem is not mounted at %s.") %
                mount_point)

        self._check_lustre_version()
        self._setup_ssh_executors()

        share_root = os.path.join(
            mount_point,
            self.configuration.lustre_share_path_prefix)
        if not os.path.isdir(share_root):
            privsep_os.mkdir(share_root)
            privsep_os.chmod('0711', share_root)

    def _check_lustre_version(self):
        try:
            out, __ = self._exec_mds('lctl_get_param', 'version')
        except exception.ProcessExecutionError as e:
            raise exception.ShareBackendException(
                msg=_("Failed to retrieve Lustre version: %s") % e)
        version_str = out.strip()
        LOG.info("Lustre version: %s", version_str)

        match = re.search(r'(\d+)\.(\d+)', version_str)
        if not match:
            raise exception.ShareBackendException(
                msg=_("Could not parse Lustre version from: %s") %
                version_str)

        version = (int(match.group(1)), int(match.group(2)))
        if version < LUSTRE_MIN_VERSION:
            raise exception.ShareBackendException(
                msg=_("Lustre version %(found)s is below the minimum "
                      "required version %(min)s.") %
                {'found': version_str,
                 'min': '%d.%d' % LUSTRE_MIN_VERSION})

    def _setup_ssh_executors(self):
        mgs_ip = self.configuration.safe_get('lustre_mgs_ip')
        mds_ip = self.configuration.safe_get('lustre_mds_ip')
        ssh_timeout = self.configuration.safe_get('ssh_conn_timeout') or 60
        ssh_login = self.configuration.lustre_ssh_username
        ssh_key = self.configuration.safe_get('lustre_ssh_private_key_path')

        if mgs_ip:
            self._mgs_ssh = ssh_utils.SSHPool(
                ip=mgs_ip, port=22, conn_timeout=ssh_timeout,
                login=ssh_login, privatekey=ssh_key, max_size=10)
            LOG.info("Lustre MGS SSH pool configured for %s.", mgs_ip)

        if mds_ip:
            self._mds_ssh = ssh_utils.SSHPool(
                ip=mds_ip, port=22, conn_timeout=ssh_timeout,
                login=ssh_login, privatekey=ssh_key, max_size=10)
            LOG.info("Lustre MDS SSH pool configured for %s.", mds_ip)

    def _exec_mgs(self, cmd_name, *args):
        """Execute a command on the MGS (SSH if remote, privsep if local)."""
        if self._mgs_ssh:
            return self._ssh_cmd(self._mgs_ssh, cmd_name, *args)
        return self._privsep_cmd(cmd_name, *args)

    def _exec_mds(self, cmd_name, *args):
        """Execute a command on the MDS (SSH if remote, privsep if local)."""
        if self._mds_ssh:
            return self._ssh_cmd(self._mds_ssh, cmd_name, *args)
        return self._privsep_cmd(cmd_name, *args)

    _SSH_CMD_MAP = {
        'lfs_setquota': lambda args: (
            'lfs', 'setquota', '-p', str(args[0]), '-B', args[1], args[2]),
        'lfs_quota': lambda args: (
            'lfs', 'quota', '-p', str(args[0]), args[1]),
        'lfs_df': lambda args: ('lfs', 'df', args[0]),
        'lfs_project': lambda args: ('lfs', 'project', '-d', '-r', args[0]),
        'lfs_clear_quota': lambda args: (
            'lfs', 'setquota', '-p', str(args[0]),
            '-b', '0', '-B', '0', args[1]),
        'lctl_get_param': lambda args: (
            'lctl', 'get_param', '-n', args[0]),
        'lctl_nodemap_add': lambda args: ('lctl', 'nodemap_add', args[0]),
        'lctl_nodemap_del': lambda args: ('lctl', 'nodemap_del', args[0]),
        'lctl_nodemap_add_range': lambda args: (
            'lctl', 'nodemap_add_range',
            '--name', args[0], '--range', args[1]),
        'lctl_nodemap_del_range': lambda args: (
            'lctl', 'nodemap_del_range',
            '--name', args[0], '--range', args[1]),
        'lctl_nodemap_modify': lambda args: (
            'lctl', 'nodemap_modify',
            '--name', args[0], '--property', args[1], '--value', args[2]),
    }

    def _privsep_cmd(self, cmd_name, *args):
        func = getattr(privsep_lustre, cmd_name)
        return func(*args)

    def _ssh_cmd(self, pool, cmd_name, *args):
        cmd_builder = self._SSH_CMD_MAP[cmd_name]
        cmd_parts = cmd_builder(args)
        cmd = 'sudo ' + ' '.join(shlex.quote(str(a)) for a in cmd_parts)
        ssh = pool.get()
        try:
            return processutils.ssh_execute(ssh, cmd)
        finally:
            pool.put(ssh)

    def check_for_setup_error(self):
        mount_point = self.configuration.lustre_mount_point
        if not os.path.ismount(mount_point):
            raise exception.InvalidShare(
                reason=_("Lustre not mounted at %s") % mount_point)

    @property
    def _mds_mount_point(self):
        return (self.configuration.safe_get('lustre_mds_mount_point')
                or self.configuration.lustre_mount_point)

    def _share_path(self, share_id):
        return os.path.join(
            self.configuration.lustre_mount_point,
            self.configuration.lustre_share_path_prefix,
            share_id)

    @coordination.synchronized(
        'lustre-project-id-{self.configuration.lustre_fs_name}')
    def _assign_project_id(self, share_path):
        """Allocate a project ID and assign it to the directory.

        Synchronized to prevent concurrent creates from picking
        the same ID.
        """
        project_id = self._allocate_project_id()
        privsep_lustre.chattr_project(project_id, share_path)
        return project_id

    def _allocate_project_id(self):
        start = self.configuration.lustre_project_id_start
        end = self.configuration.lustre_project_id_end
        used_ids = self._get_used_project_ids()

        for candidate in range(start, end + 1):
            if candidate not in used_ids:
                return candidate

        raise exception.ShareBackendException(
            msg=_("No available Lustre project IDs in range "
                  "[%(start)d, %(end)d].") %
            {'start': start, 'end': end})

    def _get_used_project_ids(self):
        share_root = os.path.join(
            self.configuration.lustre_mount_point,
            self.configuration.lustre_share_path_prefix)
        used_ids = set()
        try:
            out, __ = self._privsep_cmd('lfs_project', share_root)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        used_ids.add(int(parts[0]))
                    except ValueError:
                        pass
        except exception.ProcessExecutionError:
            LOG.warning("Could not list Lustre project IDs; "
                        "assuming none in use.")
        return used_ids

    def _size_to_kb(self, size_gb):
        return int(size_gb * units.Mi)

    def _get_project_usage_kb(self, project_id):
        mount_point = self._mds_mount_point
        out, __ = self._exec_mds('lfs_quota', project_id, mount_point)
        for line in out.splitlines():
            if mount_point in line:
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1].rstrip('*'))
        raise exception.ShareBackendException(
            msg=_("Could not parse quota usage for project %s.") %
            project_id)

    def _get_project_limit_kb(self, project_id):
        mount_point = self._mds_mount_point
        out, __ = self._exec_mds('lfs_quota', project_id, mount_point)
        for line in out.splitlines():
            if mount_point in line:
                parts = line.split()
                if len(parts) >= 4:
                    return int(parts[3].rstrip('*'))
        raise exception.ShareBackendException(
            msg=_("Could not parse quota limit for project %s.") %
            project_id)

    def _get_directory_project_id(self, path):
        out, __ = privsep_lustre.lfs_project(path)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[0])
                except ValueError:
                    pass
        raise exception.ShareBackendException(
            msg=_("Could not read project ID from %s.") % path)

    def create_share(self, context, share, share_server=None):
        requested_proto = share['share_proto'].upper()
        if requested_proto != 'LUSTRE':
            raise exception.InvalidShare(
                reason=_("Unsupported protocol: %s") % requested_proto)

        share_id = share['id']
        share_path = self._share_path(share_id)

        LOG.debug("Creating Lustre share %(id)s at %(path)s, "
                  "size=%(size)s GB.",
                  {'id': share_id, 'path': share_path,
                   'size': share['size']})

        privsep_os.mkdir(share_path)
        privsep_os.chmod('0777', share_path)

        project_id = self._assign_project_id(share_path)

        size_kb = self._size_to_kb(share['size'])
        self._exec_mds(
            'lfs_setquota', project_id, '%dk' % size_kb,
            self._mds_mount_point)

        self.private_storage.update(share_id, {
            'project_id': str(project_id),
        })

        return self._get_export_locations(share_id)

    def delete_share(self, context, share, share_server=None):
        share_id = share['id']
        share_path = self._share_path(share_id)

        LOG.debug("Deleting Lustre share %(id)s at %(path)s.",
                  {'id': share_id, 'path': share_path})

        project_id = None
        if self.private_storage:
            project_id = self.private_storage.get(share_id, 'project_id')

        if not project_id and os.path.isdir(share_path):
            try:
                project_id = self._get_directory_project_id(share_path)
            except exception.ShareBackendException:
                LOG.warning("Could not read project ID for share %s.",
                            share_id)

        if project_id:
            try:
                self._exec_mds(
                    'lfs_clear_quota', project_id,
                    self._mds_mount_point)
            except exception.ProcessExecutionError:
                LOG.warning("Failed to clear quota for project %s.",
                            project_id)

            for level in (constants.ACCESS_LEVEL_RW,
                          constants.ACCESS_LEVEL_RO):
                nodemap_name = self._nodemap_name(share_id, level)
                try:
                    self._exec_mgs('lctl_nodemap_del', nodemap_name)
                except exception.ProcessExecutionError:
                    pass

        if os.path.isdir(share_path):
            privsep_os.recursive_forced_rm(share_path)

        if self.private_storage:
            self.private_storage.delete(share_id)

    def extend_share(self, share, new_size, share_server=None):
        share_id = share['id']
        project_id = self.private_storage.get(share_id, 'project_id')

        if not project_id:
            raise exception.ShareBackendException(
                msg=_("Cannot find project ID for share %s.") % share_id)

        size_kb = self._size_to_kb(new_size)
        self._exec_mds(
            'lfs_setquota', project_id, '%dk' % size_kb,
            self._mds_mount_point)

        LOG.debug("Extended share %(id)s to %(size)s GB.",
                  {'id': share_id, 'size': new_size})

    def shrink_share(self, share, new_size, share_server=None):
        share_id = share['id']
        project_id = self.private_storage.get(share_id, 'project_id')

        if not project_id:
            raise exception.ShareBackendException(
                msg=_("Cannot find project ID for share %s.") % share_id)

        usage_kb = self._get_project_usage_kb(project_id)
        new_size_kb = self._size_to_kb(new_size)

        if usage_kb >= new_size_kb:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share_id)

        self._exec_mds(
            'lfs_setquota', project_id, '%dk' % new_size_kb,
            self._mds_mount_point)

        LOG.debug("Shrunk share %(id)s to %(size)s GB.",
                  {'id': share_id, 'size': new_size})

    def manage_existing(self, share, driver_options):
        export_location = share['export_locations'][0]['path']
        share_path = self._export_to_local_path(export_location)

        if not os.path.isdir(share_path):
            raise exception.ManageInvalidShare(
                reason=_("No directory at %s.") % share_path)

        project_id = self._get_directory_project_id(share_path)

        limit_kb = self._get_project_limit_kb(project_id)
        if limit_kb <= 0:
            raise exception.ManageInvalidShare(
                reason=_("No project quota set on %s.") % share_path)
        size = int(limit_kb / units.Mi) or 1

        self.private_storage.update(share['id'], {
            'project_id': str(project_id),
        })

        share_id = os.path.basename(share_path)
        return {
            'size': size,
            'export_locations': self._get_export_locations(share_id),
        }

    def unmanage(self, share):
        self.private_storage.delete(share['id'])

    def _export_to_local_path(self, export_location):
        """Convert a Lustre export location to a local filesystem path.

        Export format: <ip>@<nid_type>:/<fsname>/<prefix>/<share_id>
        """
        if ':/' in export_location:
            remote_path = export_location.split(':/', 1)[1]
        else:
            remote_path = export_location

        parts = remote_path.strip('/').split('/')
        if len(parts) < 2:
            raise exception.ManageInvalidShare(
                reason=_("Cannot parse export location: %s") %
                export_location)

        # The local path is mount_point + everything after the fsname
        sub_path = '/'.join(parts[1:])
        return os.path.join(
            self.configuration.lustre_mount_point, sub_path)

    def _get_export_locations(self, share_id):
        export_ip = self.configuration.lustre_share_export_ip
        fs_name = self.configuration.lustre_fs_name
        nid_type = self.configuration.lustre_nid_type
        prefix = self.configuration.lustre_share_path_prefix

        path = "%s@%s:/%s/%s/%s" % (
            export_ip, nid_type, fs_name, prefix, share_id)

        return [{'path': path, 'is_admin_only': False, 'metadata': {}}]

    @staticmethod
    def _share_hash(share_id):
        """Derive a compact hash from a share UUID for use in nodemap names.

        Lustre nodemap names are limited to 15 characters. With a 'm'
        prefix and a 2-character access level suffix ('rw'/'ro'), only
        12 characters remain for identifying the share. This method
        hashes the UUID with SHA-256 and base36-encodes the first 8
        bytes, yielding 12 alphanumeric characters (~62 bits of
        entropy). Birthday collision probability stays below 1-in-56M
        even at 100k shares per filesystem.
        """
        digest = hashlib.sha256(
            share_id.encode(), usedforsecurity=False).digest()
        num = int.from_bytes(digest[:8], 'big')
        chars = '0123456789abcdefghijklmnopqrstuvwxyz'
        result = []
        for i in range(12):
            num, rem = divmod(num, 36)
            result.append(chars[rem])
        return ''.join(result)

    def _nodemap_name(self, share_id, access_level):
        return 'm%s%s' % (self._share_hash(share_id), access_level)

    @staticmethod
    def _ip_to_nid_range(access_to, nid_type):
        """Convert an IP address or CIDR to a Lustre NID range.

        Returns a string in the format 'startNID:endNID'.
        """
        if '/' in access_to:
            network = ipaddress.ip_network(access_to, strict=False)
            start = str(network.network_address)
            end = str(network.broadcast_address)
        else:
            start = access_to
            end = access_to

        start_nid = '%s@%s' % (start, nid_type)
        end_nid = '%s@%s' % (end, nid_type)
        return '%s:%s' % (start_nid, end_nid)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, update_rules, share_server=None):
        share_id = share['id']
        nid_type = self.configuration.lustre_nid_type

        access_updates = {}

        for rule in delete_rules:
            nodemap_name = self._nodemap_name(
                share_id, rule['access_level'])
            self._remove_access_rule(nodemap_name, rule, nid_type)

        for rule in add_rules:
            nodemap_name = self._nodemap_name(
                share_id, rule['access_level'])
            try:
                self._add_access_rule(
                    share_id, nodemap_name, rule, nid_type)
            except Exception:
                LOG.exception(
                    "Failed to add access rule %s.", rule['id'])
                access_updates[rule['access_id']] = {
                    'state': constants.ACCESS_STATE_ERROR}
                continue
            access_updates[rule['access_id']] = {
                'state': constants.ACCESS_STATE_ACTIVE}

        if access_rules and not add_rules and not delete_rules:
            self._reconcile_access(
                share_id, access_rules, nid_type,
                access_updates)

        return access_updates

    def _add_access_rule(self, share_id, nodemap_name, rule, nid_type):
        if rule['access_type'] != 'ip':
            raise exception.InvalidShareAccess(
                reason=_("Only 'ip' access type is supported."))

        access_to = rule['access_to']
        ip = ipaddress.ip_network(access_to, strict=False)
        if ip.version == 6:
            LOG.warning("Ignoring IPv6 access rule %s — Lustre NIDs "
                        "are IPv4-only.", access_to)
            return

        nid_range = self._ip_to_nid_range(access_to, nid_type)

        try:
            self._exec_mgs('lctl_nodemap_add', nodemap_name)
        except exception.ProcessExecutionError as e:
            if 'already exists' not in str(e).lower():
                raise

        try:
            self._exec_mgs('lctl_nodemap_add_range', nodemap_name, nid_range)
        except exception.ProcessExecutionError as e:
            if 'exists' not in str(e).lower():
                raise

        if rule['access_level'] == constants.ACCESS_LEVEL_RW:
            self._exec_mgs(
                'lctl_nodemap_modify', nodemap_name, 'trusted', '1')
            self._exec_mgs(
                'lctl_nodemap_modify', nodemap_name, 'admin', '1')
        else:
            self._exec_mgs(
                'lctl_nodemap_modify', nodemap_name,
                'readonly_mount', '1')

    def _remove_access_rule(self, nodemap_name, rule, nid_type):
        if rule['access_type'] != 'ip':
            return

        access_to = rule['access_to']
        ip = ipaddress.ip_network(access_to, strict=False)
        if ip.version == 6:
            return

        nid_range = self._ip_to_nid_range(access_to, nid_type)

        try:
            self._exec_mgs(
                'lctl_nodemap_del_range', nodemap_name, nid_range)
        except exception.ProcessExecutionError:
            LOG.warning("Failed to remove NID range %s from nodemap %s.",
                        nid_range, nodemap_name)

    def _reconcile_access(self, share_id, access_rules,
                          nid_type, access_updates):
        for level in (constants.ACCESS_LEVEL_RW,
                      constants.ACCESS_LEVEL_RO):
            nodemap_name = self._nodemap_name(share_id, level)
            try:
                self._exec_mgs('lctl_nodemap_del', nodemap_name)
            except exception.ProcessExecutionError:
                pass

        for rule in access_rules:
            nodemap_name = self._nodemap_name(
                share_id, rule['access_level'])
            try:
                self._add_access_rule(
                    share_id, nodemap_name, rule, nid_type)
            except Exception:
                LOG.exception(
                    "Failed to reconcile access rule %s.", rule['id'])
                access_updates[rule['access_id']] = {
                    'state': constants.ACCESS_STATE_ERROR}
                continue
            access_updates[rule['access_id']] = {
                'state': constants.ACCESS_STATE_ACTIVE}

    def _parse_lfs_df(self):
        mount_point = self.configuration.lustre_mount_point
        out, __ = self._privsep_cmd('lfs_df', mount_point)

        total_kb = 0
        free_kb = 0

        for line in out.splitlines():
            if 'OST' in line and '_UUID' in line:
                parts = line.split()
                if len(parts) >= 4:
                    total_kb += int(parts[1])
                    free_kb += int(parts[3])

        return total_kb, free_kb

    def _update_share_stats(self):
        try:
            total_kb, free_kb = self._parse_lfs_df()
            total_capacity_gb = round(total_kb / units.Mi, 2)
            free_capacity_gb = round(free_kb / units.Mi, 2)
            provisioned_gb = round((total_kb - free_kb) / units.Mi, 2)
        except Exception:
            LOG.exception("Failed to get Lustre capacity stats.")
            total_capacity_gb = 'unknown'
            free_capacity_gb = 'unknown'
            provisioned_gb = 0

        data = {
            'vendor_name': 'Lustre',
            'driver_version': '1.0',
            'share_backend_name': self.backend_name,
            'storage_protocol': 'LUSTRE',
            'pools': [
                {
                    'pool_name': self.configuration.lustre_fs_name,
                    'total_capacity_gb': total_capacity_gb,
                    'free_capacity_gb': free_capacity_gb,
                    'provisioned_capacity_gb': provisioned_gb,
                    'qos': False,
                    'reserved_percentage': self.configuration.safe_get(
                        'reserved_share_percentage'),
                    'reserved_snapshot_percentage':
                        self.configuration.safe_get(
                            'reserved_share_from_snapshot_percentage') or
                        self.configuration.safe_get(
                            'reserved_share_percentage'),
                    'reserved_share_extend_percentage':
                        self.configuration.safe_get(
                            'reserved_share_extend_percentage') or
                        self.configuration.safe_get(
                            'reserved_share_percentage'),
                    'dedupe': [False],
                    'compression': [False],
                    'thin_provisioning': [True],
                    'max_over_subscription_ratio':
                        self.configuration.safe_get(
                            'max_over_subscription_ratio'),
                }
            ],
            'total_capacity_gb': total_capacity_gb,
            'free_capacity_gb': free_capacity_gb,
        }
        super(LustreShareDriver, self)._update_share_stats(data)

    def get_backend_info(self, context):
        conf = self.configuration
        return {
            'lustre_fs_name': conf.lustre_fs_name,
            'lustre_mount_point': conf.lustre_mount_point,
            'lustre_share_export_ip': conf.lustre_share_export_ip,
        }

    def ensure_shares(self, context, shares):
        share_updates = {}
        for share in shares:
            share_id = share['id']
            share_path = self._share_path(share_id)

            if not os.path.isdir(share_path):
                LOG.warning("Share %(id)s directory missing at %(path)s.",
                            {'id': share_id, 'path': share_path})
                share_updates[share_id] = {
                    'status': constants.STATUS_ERROR,
                }
                continue

            reapply = self.configuration.lustre_reapply_access_on_startup
            share_updates[share_id] = {
                'export_locations': self._get_export_locations(share_id),
                'reapply_access_rules': reapply,
            }

        return share_updates

    def get_network_allocations_number(self):
        return 0
