# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 NetApp
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
LVM Driver for shares.

"""

import ConfigParser
import math
import os
import re

from manila import exception
from manila import flags
from manila.openstack.common import importutils
from manila.openstack.common import log as logging
from manila.share import driver
from manila import utils

from oslo.config import cfg


LOG = logging.getLogger(__name__)

share_opts = [
    cfg.StrOpt('share_export_root',
               default='$state_path/mnt',
               help='Base folder where exported shares are located'),
    cfg.StrOpt('share_export_ip',
               default=None,
               help='IP to be added to export string'),
    cfg.StrOpt('smb_config_path',
               default='$state_path/smb.conf',
               help="Path to smb config"),
    cfg.IntOpt('share_lvm_mirrors',
               default=0,
               help='If set, create lvms with multiple mirrors. Note that '
                    'this requires lvm_mirrors + 2 pvs with available space'),
    cfg.StrOpt('share_volume_group',
               default='manila-shares',
               help='Name for the VG that will contain exported shares'),
    cfg.ListOpt('share_lvm_helpers',
                default=[
                    'CIFS=manila.share.drivers.lvm.CIFSNetConfHelper',
                    'NFS=manila.share.drivers.lvm.NFSHelper',
                ],
                help='Specify list of share export helpers.'),
]

FLAGS = flags.FLAGS
FLAGS.register_opts(share_opts)


class LVMShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """Executes commands relating to Shares."""

    def __init__(self, db, *args, **kwargs):
        """Do initialization."""
        super(LVMShareDriver, self).__init__(*args, **kwargs)
        self.db = db
        self._helpers = None
        self.configuration.append_config_values(share_opts)

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""
        out, err = self._execute('vgs', '--noheadings', '-o', 'name',
                                 run_as_root=True)
        volume_groups = out.split()
        if self.configuration.share_volume_group not in volume_groups:
            msg = (_("share volume group %s doesn't exist")
                   % self.configuration.share_volume_group)
            raise exception.InvalidParameterValue(err=msg)
        if not self.configuration.share_export_ip:
            msg = (_("share_export_ip doesn't specified"))
            raise exception.InvalidParameterValue(err=msg)

    def do_setup(self, context):
        """Any initialization the volume driver does while starting."""
        super(LVMShareDriver, self).do_setup(context)
        self._setup_helpers()
        for helper in self._helpers.values():
            helper.init()

    def _setup_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        self._helpers = {}
        for helper_str in self.configuration.share_lvm_helpers:
            share_proto, _, import_str = helper_str.partition('=')
            helper = importutils.import_class(import_str)
            #TODO(rushiagr): better way to handle configuration
            #                   instead of just passing to the helper
            self._helpers[share_proto.upper()] = helper(self._execute,
                                                        self.configuration)

    def _local_path(self, share):
        # NOTE(vish): stops deprecation warning
        escaped_group = \
            self.configuration.share_volume_group.replace('-', '--')
        escaped_name = share['name'].replace('-', '--')
        return "/dev/mapper/%s-%s" % (escaped_group, escaped_name)

    def _allocate_container(self, share_name, sizestr):
        cmd = ['lvcreate', '-L', sizestr, '-n', share_name,
               self.configuration.share_volume_group]
        if self.configuration.share_lvm_mirrors:
            cmd += ['-m', self.configuration.share_lvm_mirrors, '--nosync']
            terras = int(sizestr[:-1]) / 1024.0
            if terras >= 1.5:
                rsize = int(2 ** math.ceil(math.log(terras) / math.log(2)))
                # NOTE(vish): Next power of two for region size. See:
                #             http://red.ht/U2BPOD
                cmd += ['-R', str(rsize)]

        self._try_execute(*cmd, run_as_root=True)

    def _deallocate_container(self, share_name):
        """Deletes a logical volume for share."""
        # zero out old volumes to prevent data leaking between users
        # TODO(ja): reclaiming space should be done lazy and low priority
        self._try_execute('lvremove', '-f', "%s/%s" %
                          (self.configuration.share_volume_group,
                           share_name),
                          run_as_root=True)

    def get_share_stats(self, refresh=False):
        """Get share status.

        If 'refresh' is True, run update the stats first."""
        if refresh:
            self._update_share_status()

        return self._stats

    def _update_share_status(self):
        """Retrieve status info from share volume group."""

        LOG.debug(_("Updating share status"))
        data = {}

        # Note(zhiteng): These information are driver/backend specific,
        # each driver may define these values in its own config options
        # or fetch from driver specific configuration file.
        data["share_backend_name"] = 'LVM'
        data["vendor_name"] = 'Open Source'
        data["driver_version"] = '1.0'
        #TODO(rushiagr): Pick storage_protocol from the helper used.
        data["storage_protocol"] = 'NFS_CIFS'

        data['total_capacity_gb'] = 0
        data['free_capacity_gb'] = 0
        data['reserved_percentage'] = \
            self.configuration.reserved_share_percentage
        data['QoS_support'] = False

        try:
            out, err = self._execute('vgs', '--noheadings', '--nosuffix',
                                     '--unit=G', '-o', 'name,size,free',
                                     self.configuration.share_volume_group,
                                     run_as_root=True)
        except exception.ProcessExecutionError as exc:
            LOG.error(_("Error retrieving volume status: %s") % exc.stderr)
            out = False

        if out:
            share = out.split()
            data['total_capacity_gb'] = float(share[1])
            data['free_capacity_gb'] = float(share[2])

        self._stats = data

    def deallocate_container(self, ctx, share):
        """Remove LVM volume that will be represented as share."""
        self._deallocate_container(share['name'])

    def allocate_container(self, ctx, share):
        """Create LVM volume that will be represented as share."""
        self._allocate_container(share['name'], '%sG' % share['size'])
        #create file system
        device_name = self._local_path(share)
        self._execute('mkfs.ext4', device_name, run_as_root=True)

    def allocate_container_from_snapshot(self, context, share, snapshot):
        """Is called to create share from snapshot."""
        self._allocate_container(share['name'], '%sG' % share['size'])
        self._copy_volume(self._local_path(snapshot), self._local_path(share),
                          snapshot['share_size'])

    def create_export(self, ctx, share):
        """Exports the volume. Can optionally return a Dictionary of changes
        to the share object to be persisted."""
        device_name = self._local_path(share)
        location = self._mount_device(share, device_name)
        #TODO(rushiagr): what is the provider_location? realy needed?
        return {'provider_location': location}

    def remove_export(self, ctx, share):
        """Removes an access rules for a share."""
        mount_path = self._get_mount_path(share)
        if os.path.exists(mount_path):
            #umount, may be busy
            try:
                self._execute('umount', '-f', mount_path, run_as_root=True)
            except exception.ProcessExecutionError, exc:
                if 'device is busy' in str(exc):
                    raise exception.ShareIsBusy(share_name=share['name'])
                else:
                    LOG.info('Unable to umount: %s', exc)
            #remove dir
            try:
                os.rmdir(mount_path)
            except OSError:
                LOG.info('Unable to delete %s', mount_path)

    def create_share(self, ctx, share):
        """Is called after allocate_space to create share on the volume."""
        location = self._get_mount_path(share)
        location = self._get_helper(share).create_export(location,
                                                         share['name'])
        return location

    def create_snapshot(self, context, snapshot):
        """Creates a snapshot."""
        orig_lv_name = "%s/%s" % (self.configuration.share_volume_group,
                                  snapshot['share_name'])
        self._try_execute('lvcreate', '-L', '%sG' % snapshot['share_size'],
                          '--name', snapshot['name'],
                          '--snapshot', orig_lv_name, run_as_root=True)

    def ensure_share(self, ctx, share):
        """Ensure that storage are mounted and exported."""
        device_name = self._local_path(share)
        location = self._mount_device(share, device_name)
        self._get_helper(share).create_export(location, share['name'],
                                              recreate=True)

    def delete_share(self, ctx, share):
        """Delete a share."""
        try:
            location = self._get_mount_path(share)
            self._get_helper(share).remove_export(location, share['name'])
        except exception.ProcessExecutionError:
            LOG.info("Can't remove share %r" % share['id'])
        except exception.InvalidShare, exc:
            LOG.info(exc.message)

    def delete_snapshot(self, context, snapshot):
        """Deletes a snapshot."""
        self._deallocate_container(snapshot['name'])

    def allow_access(self, ctx, share, access):
        """Allow access to the share."""
        location = self._get_mount_path(share)
        self._get_helper(share).allow_access(location, share['name'],
                                             access['access_type'],
                                             access['access_to'])

    def deny_access(self, ctx, share, access):
        """Allow access to the share."""
        location = self._get_mount_path(share)
        self._get_helper(share).deny_access(location, share['name'],
                                            access['access_type'],
                                            access['access_to'])

    def _get_helper(self, share):
        if share['share_proto'].startswith('NFS'):
            return self._helpers['NFS']
        elif share['share_proto'].startswith('CIFS'):
            return self._helpers['CIFS']
        else:
            raise exception.InvalidShare(reason='Wrong share type')

    def _mount_device(self, share, device_name):
        """Mount LVM share and ignore if already mounted."""
        mount_path = self._get_mount_path(share)
        self._execute('mkdir', '-p', mount_path)
        try:
            self._execute('mount', device_name, mount_path,
                          run_as_root=True, check_exit_code=True)
            self._execute('chmod', '777', mount_path,
                          run_as_root=True, check_exit_code=True)
        except exception.ProcessExecutionError as exc:
            if 'already mounted' in exc.stderr:
                LOG.warn(_("%s is already mounted"), device_name)
            else:
                raise
        return mount_path

    def _get_mount_path(self, share):
        """Returns path where share is mounted."""
        return os.path.join(self.configuration.share_export_root,
                            share['name'])

    def _copy_volume(self, srcstr, deststr, size_in_g):
        # Use O_DIRECT to avoid thrashing the system buffer cache
        extra_flags = ['iflag=direct', 'oflag=direct']

        # Check whether O_DIRECT is supported
        try:
            self._execute('dd', 'count=0', 'if=%s' % srcstr, 'of=%s' % deststr,
                          *extra_flags, run_as_root=True)
        except exception.ProcessExecutionError:
            extra_flags = []

        # Perform the copy
        self._execute('dd', 'if=%s' % srcstr, 'of=%s' % deststr,
                      'count=%d' % (size_in_g * 1024), 'bs=1M',
                      *extra_flags, run_as_root=True)


class NASHelperBase(object):
    """Interface to work with share."""

    def __init__(self, execute, config_object):
        self.configuration = config_object
        self._execute = execute

    def init(self):
        pass

    def create_export(self, local_path, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        raise NotImplementedError()

    def remove_export(self, local_path, share_name):
        """Remove export."""
        raise NotImplementedError()

    def allow_access(self, local_path, share_name, access_type, access):
        """Allow access to the host."""
        raise NotImplementedError()

    def deny_access(self, local_path, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        raise NotImplementedError()


class NFSHelper(NASHelperBase):
    """Interface to work with share."""

    def __init__(self, execute, config_object):
        super(NFSHelper, self).__init__(execute, config_object)
        try:
            self._execute('exportfs', check_exit_code=True,
                          run_as_root=True)
        except exception.ProcessExecutionError:
            raise exception.Error('NFS server not found')

    def create_export(self, local_path, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        return ':'.join([self.configuration.share_export_ip, local_path])

    def remove_export(self, local_path, share_name):
        """Remove export."""
        pass

    def allow_access(self, local_path, share_name, access_type, access):
        """Allow access to the host"""
        if access_type != 'ip':
            reason = 'only ip access type allowed'
            raise exception.InvalidShareAccess(reason)
        #check if presents in export
        out, _ = self._execute('exportfs', run_as_root=True)
        out = re.search(re.escape(local_path) + '[\s\n]*' + re.escape(access),
                        out)
        if out is not None:
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access)

        self._execute('exportfs', '-o', 'rw,no_subtree_check',
                      ':'.join([access, local_path]), run_as_root=True,
                      check_exit_code=True)

    def deny_access(self, local_path, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        self._execute('exportfs', '-u', ':'.join([access, local_path]),
                      run_as_root=True, check_exit_code=False)


class CIFSHelper(NASHelperBase):
    """Class provides functionality to operate with cifs shares"""

    def __init__(self, execute, config_object):
        """Store executor and configuration path."""
        super(CIFSHelper, self).__init__(execute, config_object)
        self.config = self.configuration.smb_config_path
        self.test_config = "%s_" % (self.config,)

    def init(self):
        """Initialize environment."""
        self._recreate_config()
        self._ensure_daemon_started()

    def create_export(self, local_path, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        parser = ConfigParser.ConfigParser()
        parser.read(self.config)
        #delete old one
        if parser.has_section(share_name):
            if recreate:
                parser.remove_section(share_name)
            else:
                raise exception.Error('Section exists')
        #Create new one
        parser.add_section(share_name)
        parser.set(share_name, 'path', local_path)
        parser.set(share_name, 'browseable', 'yes')
        parser.set(share_name, 'guest ok', 'yes')
        parser.set(share_name, 'read only', 'no')
        parser.set(share_name, 'writable', 'yes')
        parser.set(share_name, 'create mask', '0755')
        parser.set(share_name, 'hosts deny', '0.0.0.0/0')  # denying all ips
        parser.set(share_name, 'hosts allow', '127.0.0.1')
        #NOTE(rushiagr): ensure that local_path dir is existing
        if not os.path.exists(local_path):
            os.makedirs(local_path)
        self._execute('chown', 'nobody', '-R', local_path, run_as_root=True)
        self._update_config(parser)
        return '//%s/%s' % (self.configuration.share_export_ip, share_name)

    def remove_export(self, local_path, share_name):
        """Remove export."""
        parser = ConfigParser.ConfigParser()
        parser.read(self.config)
        #delete old one
        if parser.has_section(share_name):
            parser.remove_section(share_name)
        self._update_config(parser)
        self._execute('smbcontrol', 'all', 'close-share', share_name,
                      run_as_root=True)

    def allow_access(self, local_path, share_name, access_type, access):
        """Allow access to the host."""
        if access_type != 'ip':
            reason = 'only ip access type allowed'
            raise exception.InvalidShareAccess(reason)
        parser = ConfigParser.ConfigParser()
        parser.read(self.config)

        hosts = parser.get(share_name, 'hosts allow')
        if access in hosts.split():
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access)
        hosts += ' %s' % (access,)
        parser.set(share_name, 'hosts allow', hosts)
        self._update_config(parser)

    def deny_access(self, local_path, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        parser = ConfigParser.ConfigParser()
        try:
            parser.read(self.config)
            hosts = parser.get(share_name, 'hosts allow')
            hosts = hosts.replace(' %s' % (access,), '', 1)
            parser.set(share_name, 'hosts allow', hosts)
            self._update_config(parser)
        except ConfigParser.NoSectionError:
            if not force:
                raise

    def _ensure_daemon_started(self):
        """
        FYI: smbd starts at least two processes.
        """
        out, _ = self._execute(*'ps -C smbd -o args='.split(),
                               check_exit_code=False)
        processes = [process.strip() for process in out.split('\n')
                     if process.strip()]

        cmd = 'smbd -s %s -D' % (self.config,)

        running = False
        for process in processes:
            if not process.endswith(cmd):
                #alternatively exit
                raise exception.Error('smbd already started with wrong config')
            running = True

        if not running:
            self._execute(*cmd.split(), run_as_root=True)

    def _recreate_config(self):
        """create new SAMBA configuration file."""
        if os.path.exists(self.config):
            os.unlink(self.config)
        parser = ConfigParser.ConfigParser()
        parser.add_section('global')
        parser.set('global', 'security', 'user')
        parser.set('global', 'server string', '%h server (Samba, Openstack)')

        self._update_config(parser, restart=False)

    def _update_config(self, parser, restart=True):
        """Check if new configuration is correct and save it."""
        #Check that configuration is correct
        with open(self.test_config, 'w') as fp:
            parser.write(fp)
        self._execute('testparm', '-s', self.test_config,
                      check_exit_code=True)
        #save it
        with open(self.config, 'w') as fp:
            parser.write(fp)
        #restart daemon if necessary
        if restart:
            self._execute(*'pkill -HUP smbd'.split(), run_as_root=True)


class CIFSNetConfHelper(NASHelperBase):
    """Manage shares in samba server by net conf tool.

    Class provides functionality to operate with CIFS shares. Samba
    server should be configured to use registry as configuration
    backend to allow dynamically share managements. There are two ways
    to done that, one of them is to add specific parameter in the
    global configuration section at smb.conf:

        [global]
            include = registry

    For more inforation see smb.conf(5).
    """

    def create_export(self, local_path, share_name, recreate=False):
        """Create share at samba server."""
        create_cmd = ('net', 'conf', 'addshare', share_name, local_path,
                      'writeable=y', 'guest_ok=y')
        try:
            self._execute(*create_cmd, run_as_root=True)
        except exception.ProcessExecutionError as e:
            if 'already exists' in e.stderr:
                if recreate:
                    self._execute('net', 'conf', 'delshare', share_name,
                                  run_as_root=True)
                    self._execute(*create_cmd, run_as_root=True)
                else:
                    msg = _('Share section %r already defined.') % (share_name)
                    raise exception.ShareBackendException(msg=msg)
            else:
                raise
        parameters = {
            'browseable': 'yes',
            'create mask': '0755',
            'hosts deny': '0.0.0.0/0',  # deny all
            'hosts allow': '127.0.0.1',
        }
        for name, value in parameters.items():
            self._execute('net', 'conf', 'setparm', share_name, name, value,
                          run_as_root=True)
        return '//%s/%s' % (self.configuration.share_export_ip, share_name)

    def remove_export(self, local_path, share_name):
        """Remove share definition from samba server."""
        try:
            self._execute('net', 'conf', 'delshare', share_name,
                          run_as_root=True)
        except exception.ProcessExecutionError as e:
            if 'SBC_ERR_NO_SUCH_SERVICE' not in e.stderr:
                raise
        self._execute('smbcontrol', 'all', 'close-share', share_name,
                      run_as_root=True)

    def allow_access(self, local_path, share_name, access_type, access):
        """Add to allow hosts additional access rule."""
        if access_type != 'ip':
            reason = _('only ip access type allowed')
            raise exception.InvalidShareAccess(reason=reason)

        hosts = self._get_allow_hosts(share_name)
        if access in hosts:
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access)
        hosts.append(access)
        self._set_allow_hosts(hosts, share_name)

    def deny_access(self, local_path, share_name, access_type, access,
                    force=False):
        """Remove from allow hosts permit rule."""
        try:
            hosts = self._get_allow_hosts(share_name)
            hosts.remove(access)
            self._set_allow_hosts(hosts, share_name)
        except exception.ProcessExecutionError as e:
            if not ('does not exist' in e.stdout and force):
                raise

    def _get_allow_hosts(self, share_name):
        (out, _) = self._execute('net', 'conf', 'getparm', share_name,
                                 'hosts allow', run_as_root=True)
        return out.split()

    def _set_allow_hosts(self, hosts, share_name):
        value = ' '.join(hosts)
        self._execute('net', 'conf', 'setparm', share_name, 'hosts allow',
                      value, run_as_root=True)
