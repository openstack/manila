# Copyright 2015 Mirantis Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os
import re

from oslo_log import log

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.i18n import _LW
from manila import utils

LOG = log.getLogger(__name__)


class NASHelperBase(object):
    """Interface to work with share."""

    def __init__(self, execute, ssh_execute, config_object):
        self.configuration = config_object
        self._execute = execute
        self._ssh_exec = ssh_execute

    def init_helper(self, server):
        pass

    def create_export(self, server, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        raise NotImplementedError()

    def remove_export(self, server, share_name):
        """Remove export."""
        raise NotImplementedError()

    def configure_access(self, server, share_name):
        """Configure server before allowing access."""
        pass

    def update_access(self, server, share_name, access_rules, add_rules,
                      delete_rules):
        """Update access rules for given share.

        This driver has two different behaviors according to parameters:
        1. Recovery after error - 'access_rules' contains all access_rules,
        'add_rules' and 'delete_rules' shall be empty. Previously existing
        access rules are cleared and then added back according
        to 'access_rules'.

        2. Adding/Deleting of several access rules - 'access_rules' contains
        all access_rules, 'add_rules' and 'delete_rules' contain rules which
        should be added/deleted. Rules in 'access_rules' are ignored and
        only rules from 'add_rules' and 'delete_rules' are applied.

        :param server: None or Share server's backend details
        :param share_name: Share's path according to id.
        :param access_rules: All access rules for given share
        :param add_rules: Empty List or List of access rules which should be
               added. access_rules already contains these rules.
        :param delete_rules: Empty List or List of access rules which should be
               removed. access_rules doesn't contain these rules.
        """
        raise NotImplementedError()

    @staticmethod
    def _verify_server_has_public_address(server):
        if 'public_address' not in server:
            raise exception.ManilaException(
                _("Can not get 'public_address' for generation of export."))

    def get_exports_for_share(self, server, old_export_location):
        """Returns list of exports based on server info."""
        raise NotImplementedError()

    def get_share_path_by_export_location(self, server, export_location):
        """Returns share path by its export location."""
        raise NotImplementedError()

    def disable_access_for_maintenance(self, server, share_name):
        """Disables access to share to perform maintenance operations."""

    def restore_access_after_maintenance(self, server, share_name):
        """Enables access to share after maintenance operations were done."""

    @staticmethod
    def validate_access_rules(access_rules, allowed_types, allowed_levels):
        """Validates access rules according to access_type and access_level.

        :param access_rules: List of access rules to be validated.
        :param allowed_types: tuple of allowed type values.
        :param allowed_levels: tuple of allowed level values.
        """
        for access in (access_rules or []):
            access_type = access['access_type']
            access_level = access['access_level']
            if access_type not in allowed_types:
                reason = _("Only %s access type allowed.") % (
                    ', '.join(tuple(["'%s'" % x for x in allowed_types])))
                raise exception.InvalidShareAccess(reason=reason)
            if access_level not in allowed_levels:
                raise exception.InvalidShareAccessLevel(level=access_level)

    def _get_maintenance_file_path(self, share_name):
        return os.path.join(self.configuration.share_mount_path,
                            "%s.maintenance" % share_name)


def nfs_synchronized(f):

    def wrapped_func(self, *args, **kwargs):
        key = "nfs-%s" % args[0].get("lock_name", args[0]["instance_id"])

        # NOTE(vponomaryov): 'external' lock is required for DHSS=False
        # mode of LVM and Generic drivers, that may have lots of
        # driver instances on single host.
        @utils.synchronized(key, external=True)
        def source_func(self, *args, **kwargs):
            return f(self, *args, **kwargs)

        return source_func(self, *args, **kwargs)

    return wrapped_func


class NFSHelper(NASHelperBase):
    """Interface to work with share."""

    def create_export(self, server, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        return ':'.join((server['public_address'],
                         os.path.join(
                             self.configuration.share_mount_path, share_name)))

    def init_helper(self, server):
        try:
            self._ssh_exec(server, ['sudo', 'exportfs'])
        except exception.ProcessExecutionError as e:
            if 'command not found' in e.stderr:
                raise exception.ManilaException(
                    _('NFS server is not installed on %s')
                    % server['instance_id'])
            LOG.error(e.stderr)

    def remove_export(self, server, share_name):
        """Remove export."""

    def _get_parsed_access_to(self, access_to):
        netmask = utils.cidr_to_netmask(access_to)
        if netmask == '255.255.255.255':
            return access_to.split('/')[0]
        return access_to.split('/')[0] + '/' + netmask

    @nfs_synchronized
    def update_access(self, server, share_name, access_rules, add_rules,
                      delete_rules):
        """Update access rules for given share.

        Please refer to base class for a more in-depth description.
        """
        local_path = os.path.join(self.configuration.share_mount_path,
                                  share_name)
        out, err = self._ssh_exec(server, ['sudo', 'exportfs'])
        # Recovery mode
        if not (add_rules or delete_rules):

            self.validate_access_rules(
                access_rules, ('ip',),
                (const.ACCESS_LEVEL_RO, const.ACCESS_LEVEL_RW))

            hosts = self._get_host_list(out, local_path)
            for host in hosts:
                self._ssh_exec(server, ['sudo', 'exportfs', '-u',
                                        ':'.join((host, local_path))])
            self._sync_nfs_temp_and_perm_files(server)
            for access in access_rules:
                rules_options = '%s,no_subtree_check'
                if access['access_level'] == const.ACCESS_LEVEL_RW:
                    rules_options = ','.join((rules_options, 'no_root_squash'))
                self._ssh_exec(
                    server,
                    ['sudo', 'exportfs', '-o',
                     rules_options % access['access_level'],
                     ':'.join((self._get_parsed_access_to(access['access_to']),
                               local_path))])
            self._sync_nfs_temp_and_perm_files(server)
        # Adding/Deleting specific rules
        else:

            self.validate_access_rules(
                add_rules, ('ip',),
                (const.ACCESS_LEVEL_RO, const.ACCESS_LEVEL_RW))

            for access in delete_rules:
                access['access_to'] = self._get_parsed_access_to(
                    access['access_to'])
                try:
                    self.validate_access_rules(
                        [access], ('ip',),
                        (const.ACCESS_LEVEL_RO, const.ACCESS_LEVEL_RW))
                except (exception.InvalidShareAccess,
                        exception.InvalidShareAccessLevel):
                    LOG.warning(_LW(
                        "Unsupported access level %(level)s or access type "
                        "%(type)s, skipping removal of access rule to "
                        "%(to)s.") % {'level': access['access_level'],
                                      'type': access['access_type'],
                                      'to': access['access_to']})
                    continue
                self._ssh_exec(server, ['sudo', 'exportfs', '-u',
                               ':'.join((access['access_to'], local_path))])
            if delete_rules:
                self._sync_nfs_temp_and_perm_files(server)
            for access in add_rules:
                access['access_to'] = self._get_parsed_access_to(
                    access['access_to'])
                found_item = re.search(
                    re.escape(local_path) + '[\s\n]*' + re.escape(
                        access['access_to']), out)
                if found_item is not None:
                    LOG.warning(_LW("Access rule %(type)s:%(to)s already "
                                    "exists for share %(name)s") % {
                        'to': access['access_to'],
                        'type': access['access_type'],
                        'name': share_name
                    })
                else:
                    rules_options = '%s,no_subtree_check'
                    if access['access_level'] == const.ACCESS_LEVEL_RW:
                        rules_options = ','.join((rules_options,
                                                 'no_root_squash'))
                    self._ssh_exec(
                        server,
                        ['sudo', 'exportfs', '-o',
                         rules_options % access['access_level'],
                         ':'.join((access['access_to'], local_path))])
            if add_rules:
                self._sync_nfs_temp_and_perm_files(server)

    def _get_host_list(self, output, local_path):
        entries = []
        output = output.replace('\n\t\t', ' ')
        lines = output.split('\n')
        for line in lines:
            items = line.split(' ')
            if local_path == items[0]:
                entries.append(items[1])
        return entries

    def _sync_nfs_temp_and_perm_files(self, server):
        """Sync changes of exports with permanent NFS config file.

        This is required to ensure, that after share server reboot, exports
        still exist.
        """
        sync_cmd = [
            'sudo', 'cp', const.NFS_EXPORTS_FILE_TEMP, const.NFS_EXPORTS_FILE
        ]
        self._ssh_exec(server, sync_cmd)
        self._ssh_exec(server, ['sudo', 'exportfs', '-a'])
        out, _ = self._ssh_exec(
            server, ['sudo', 'service', 'nfs-kernel-server', 'status'],
            check_exit_code=False)
        if "not" in out:
            self._ssh_exec(
                server, ['sudo', 'service', 'nfs-kernel-server', 'restart'])

    def get_exports_for_share(self, server, old_export_location):
        self._verify_server_has_public_address(server)
        path = old_export_location.split(':')[-1]
        return [':'.join((server['public_address'], path))]

    def get_share_path_by_export_location(self, server, export_location):
        return export_location.split(':')[-1]

    @nfs_synchronized
    def disable_access_for_maintenance(self, server, share_name):
        maintenance_file = self._get_maintenance_file_path(share_name)
        backup_exports = [
            'cat', const.NFS_EXPORTS_FILE,
            '| grep', share_name,
            '| sudo tee', maintenance_file
        ]
        self._ssh_exec(server, backup_exports)

        local_path = os.path.join(self.configuration.share_mount_path,
                                  share_name)
        self._ssh_exec(server, ['sudo', 'exportfs', '-u', local_path])
        self._sync_nfs_temp_and_perm_files(server)

    @nfs_synchronized
    def restore_access_after_maintenance(self, server, share_name):
        maintenance_file = self._get_maintenance_file_path(share_name)
        restore_exports = [
            'cat', maintenance_file,
            '| sudo tee -a', const.NFS_EXPORTS_FILE,
            '&& sudo exportfs -r',
            '&& sudo rm -f', maintenance_file
        ]
        self._ssh_exec(server, restore_exports)


class CIFSHelperIPAccess(NASHelperBase):
    """Manage shares in samba server by net conf tool.

    Class provides functionality to operate with CIFS shares.
    Samba server should be configured to use registry as configuration
    backend to allow dynamically share managements. This class allows
    to define access to shares by IPs with RW access level.
    """
    def __init__(self, *args):
        super(CIFSHelperIPAccess, self).__init__(*args)
        self.export_format = '\\\\%s\\%s'
        self.parameters = {
            'browseable': 'yes',
            '\"create mask\"': '0755',
            '\"hosts deny\"': '0.0.0.0/0',  # deny all by default
            '\"hosts allow\"': '127.0.0.1',
            '\"read only\"': 'no',
        }

    def init_helper(self, server):
        # This is smoke check that we have required dependency
        self._ssh_exec(server, ['sudo', 'net', 'conf', 'list'])

    def create_export(self, server, share_name, recreate=False):
        """Create share at samba server."""
        share_path = os.path.join(self.configuration.share_mount_path,
                                  share_name)
        create_cmd = [
            'sudo', 'net', 'conf', 'addshare', share_name, share_path,
            'writeable=y', 'guest_ok=y',
        ]
        try:
            self._ssh_exec(
                server, ['sudo', 'net', 'conf', 'showshare', share_name, ])
        except exception.ProcessExecutionError:
            # Share does not exist, create it
            try:
                self._ssh_exec(server, create_cmd)
            except Exception as child_e:
                msg = _("Could not create CIFS export %s.") % share_name
                LOG.exception(child_e)
                LOG.error(msg)
                raise exception.ManilaException(reason=msg)
        else:
            # Share exists
            if recreate:
                self._ssh_exec(
                    server, ['sudo', 'net', 'conf', 'delshare', share_name, ])
                try:
                    self._ssh_exec(server, create_cmd)
                except Exception as e:
                    msg = _("Could not create CIFS export %s.") % share_name
                    LOG.exception(e)
                    LOG.error(msg)
                    raise exception.ManilaException(reason=msg)
            else:
                msg = _('Share section %s already defined.') % share_name
                raise exception.ShareBackendException(msg=msg)

        for param, value in self.parameters.items():
            self._ssh_exec(server, ['sudo', 'net', 'conf', 'setparm',
                           share_name, param, value])

        return self.export_format % (server['public_address'], share_name)

    def remove_export(self, server, share_name):
        """Remove share definition from samba server."""
        try:
            self._ssh_exec(
                server, ['sudo', 'net', 'conf', 'delshare', share_name])
        except exception.ProcessExecutionError as e:
            LOG.warning(_LW("Caught error trying delete share: %(error)s, try"
                            "ing delete it forcibly."), {'error': e.stderr})
            self._ssh_exec(server, ['sudo', 'smbcontrol', 'all', 'close-share',
                                    share_name])

    def update_access(self, server, share_name, access_rules, add_rules,
                      delete_rules):
        """Update access rules for given share.

        Please refer to base class for a more in-depth description. For this
        specific implementation, add_rules and delete_rules parameters are not
        used.
        """
        hosts = []

        self.validate_access_rules(
            access_rules, ('ip',), (const.ACCESS_LEVEL_RW,))

        for access in access_rules:
            hosts.append(access['access_to'])
        self._set_allow_hosts(server, hosts, share_name)

    def _get_allow_hosts(self, server, share_name):
        (out, _) = self._ssh_exec(server, ['sudo', 'net', 'conf', 'getparm',
                                           share_name, '\"hosts allow\"'])
        return out.split()

    def _set_allow_hosts(self, server, hosts, share_name):
        value = "\"" + ' '.join(hosts) + "\""
        self._ssh_exec(server, ['sudo', 'net', 'conf', 'setparm', share_name,
                                '\"hosts allow\"', value])

    @staticmethod
    def _get_share_group_name_from_export_location(export_location):
        if '/' in export_location and '\\' in export_location:
            pass
        elif export_location.startswith('\\\\'):
            return export_location.split('\\')[-1]
        elif export_location.startswith('//'):
            return export_location.split('/')[-1]

        msg = _("Got incorrect CIFS export location '%s'.") % export_location
        raise exception.InvalidShare(reason=msg)

    def get_exports_for_share(self, server, old_export_location):
        self._verify_server_has_public_address(server)
        group_name = self._get_share_group_name_from_export_location(
            old_export_location)
        data = dict(ip=server['public_address'], share=group_name)
        return ['\\\\%(ip)s\\%(share)s' % data]

    def get_share_path_by_export_location(self, server, export_location):
        # Get name of group that contains share data on CIFS server
        group_name = self._get_share_group_name_from_export_location(
            export_location)

        # Get parameter 'path' from group that belongs to current share
        (out, __) = self._ssh_exec(
            server, ['sudo', 'net', 'conf', 'getparm', group_name, 'path'])

        # Remove special symbols from response and return path
        return out.strip()

    def disable_access_for_maintenance(self, server, share_name):
        maintenance_file = self._get_maintenance_file_path(share_name)
        allowed_hosts = " ".join(self._get_allow_hosts(server, share_name))

        backup_exports = [
            'echo', "'%s'" % allowed_hosts, '| sudo tee', maintenance_file
        ]
        self._ssh_exec(server, backup_exports)
        self._set_allow_hosts(server, [], share_name)

    def restore_access_after_maintenance(self, server, share_name):
        maintenance_file = self._get_maintenance_file_path(share_name)
        (exports, __) = self._ssh_exec(server, ['cat', maintenance_file])
        self._set_allow_hosts(server, exports.split(), share_name)
        self._ssh_exec(server, ['sudo rm -f', maintenance_file])


class CIFSHelperUserAccess(CIFSHelperIPAccess):
    """Manage shares in samba server by net conf tool.

    Class provides functionality to operate with CIFS shares.
    Samba server should be configured to use registry as configuration
    backend to allow dynamically share managements. This class allows
    to define access to shares by usernames with either RW or RO access levels.
    """
    def __init__(self, *args):
        super(CIFSHelperUserAccess, self).__init__(*args)
        self.export_format = '//%s/%s'
        self.parameters = {
            'browseable': 'yes',
            'create mask': '0755',
            'hosts allow': '0.0.0.0/0',
            'read only': 'no',
        }

    def update_access(self, server, share_name, access_rules, add_rules,
                      delete_rules):
        """Update access rules for given share.

        Please refer to base class for a more in-depth description. For this
        specific implementation, add_rules and delete_rules parameters are not
        used.
        """
        all_users_rw = []
        all_users_ro = []

        self.validate_access_rules(
            access_rules, ('user',),
            (const.ACCESS_LEVEL_RO, const.ACCESS_LEVEL_RW))

        for access in access_rules:
            if access['access_level'] == const.ACCESS_LEVEL_RW:
                all_users_rw.append(access['access_to'])
            else:
                all_users_ro.append(access['access_to'])
        self._set_valid_users(
            server, all_users_rw, share_name, const.ACCESS_LEVEL_RW)
        self._set_valid_users(
            server, all_users_ro, share_name, const.ACCESS_LEVEL_RO)

    def _get_conf_param(self, access_level):
        if access_level == const.ACCESS_LEVEL_RW:
            return 'valid users'
        else:
            return 'read list'

    def _set_valid_users(self, server, users, share_name, access_level):
        value = "\"" + ' '.join(users) + "\""
        param = self._get_conf_param(access_level)
        self._ssh_exec(server, ['sudo', 'net', 'conf', 'setparm', share_name,
                                param, value])
