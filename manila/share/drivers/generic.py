# Copyright (c) 2014 NetApp, Inc.
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

"""Generic Driver for shares."""

import ConfigParser
import os
import re
import shutil
import time

from oslo.config import cfg

from manila import compute
from manila import context
from manila import exception
from manila.openstack.common import importutils
from manila.openstack.common import lockutils
from manila.openstack.common import log as logging
from manila.openstack.common import processutils
from manila.share import driver
from manila.share.drivers import service_instance
from manila import utils
from manila import volume


LOG = logging.getLogger(__name__)

share_opts = [
    cfg.StrOpt('smb_template_config_path',
               default='$state_path/smb.conf',
               help="Path to smb config."),
    cfg.StrOpt('volume_name_template',
               default='manila-share-%s',
               help="Volume name template."),
    cfg.StrOpt('volume_snapshot_name_template',
               default='manila-snapshot-%s',
               help="Volume snapshot name template."),
    cfg.StrOpt('share_mount_path',
               default='/shares',
               help="Parent path in service instance where shares "
               "will be mounted."),
    cfg.IntOpt('max_time_to_create_volume',
               default=180,
               help="Maximum time to wait for creating cinder volume."),
    cfg.IntOpt('max_time_to_attach',
               default=120,
               help="Maximum time to wait for attaching cinder volume."),
    cfg.StrOpt('service_instance_smb_config_path',
               default='$share_mount_path/smb.conf',
               help="Path to smb config in service instance."),
    cfg.ListOpt('share_helpers',
                default=[
                    'CIFS=manila.share.drivers.generic.CIFSHelper',
                    'NFS=manila.share.drivers.generic.NFSHelper',
                ],
                help='Specify list of share export helpers.'),
]

CONF = cfg.CONF
CONF.register_opts(share_opts)


def ensure_server(f):
    def wrap(self, *args, **kwargs):
        server = kwargs.get('share_server')
        context = args[0]
        if not server:
            # For now generic driver does not support flat networking.
            # When we implement flat networking in generic driver
            # we will not need share server to be passed and
            # will change this logic.
            raise exception.ManilaException(_('Share server not found.'))
        if not server.get('backend_details'):
            raise exception.ManilaException(_('Share server backend '
                                              'details missing.'))
        if not self.service_instance_manager.ensure_service_instance(
                context, server['backend_details']):
            raise exception.ServiceInstanceUnavailable()
        return f(self, *args, **kwargs)
    return wrap


class GenericShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """Executes commands relating to Shares."""

    def __init__(self, db, *args, **kwargs):
        """Do initialization."""
        super(GenericShareDriver, self).__init__(*args, **kwargs)
        self.admin_context = context.get_admin_context()
        self.db = db
        self.configuration.append_config_values(share_opts)
        self.configuration.append_config_values(service_instance.server_opts)
        self._helpers = {}
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or "Cinder_Volumes"
        self.ssh_connections = {}

    def _ssh_exec(self, server, command):
        connection = self.ssh_connections.get(server['instance_id'])
        if not connection:
            ssh_pool = utils.SSHPool(server['ip'],
                                     22,
                                     None,
                                     server['username'],
                                     server['password'],
                                     server['pk_path'],
                                     max_size=1)
            ssh = ssh_pool.create()
            self.ssh_connections[server['instance_id']] = (ssh_pool, ssh)
        else:
            ssh_pool, ssh = connection

        if not ssh.get_transport().is_active():
            ssh_pool.remove(server['ssh'])
            ssh = ssh_pool.create()
            self.ssh_connections[server['instance_id']] = (ssh_pool, ssh)
        return processutils.ssh_execute(ssh, ' '.join(command))

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""
        pass

    def do_setup(self, context):
        """Any initialization the generic driver does while starting."""
        super(GenericShareDriver, self).do_setup(context)
        self.compute_api = compute.API()
        self.volume_api = volume.API()
        self.service_instance_manager = service_instance.\
            ServiceInstanceManager(self.db, self._helpers,
                                   driver_config=self.configuration)
        self.share_networks_servers = self.service_instance_manager.\
                                                        share_networks_servers
        self._setup_helpers()

    def _setup_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        for helper_str in self.configuration.share_helpers:
            share_proto, __, import_str = helper_str.partition('=')
            helper = importutils.import_class(import_str)
            self._helpers[share_proto.upper()] = helper(
                self._execute,
                self._ssh_exec,
                self.configuration)

    @ensure_server
    def create_share(self, context, share, share_server=None):
        """Creates share."""
        server_details = share_server['backend_details']
        volume = self._allocate_container(self.admin_context, share)
        volume = self._attach_volume(
            self.admin_context,
            share,
            server_details['instance_id'],
            volume)
        self._format_device(server_details, volume)
        self._mount_device(context, share, server_details, volume)
        location = self._get_helper(share).create_export(
            server_details,
            share['name'])
        return location

    def _format_device(self, server_details, volume):
        """Formats device attached to the service vm."""
        command = ['sudo', 'mkfs.ext4', volume['mountpoint']]
        self._ssh_exec(server_details, command)

    def _mount_device(self, context, share, server_details, volume):
        """Mounts attached and formatted block device to the directory."""
        mount_path = self._get_mount_path(share)
        command = ['sudo', 'mkdir', '-p', mount_path, ';']
        command.extend(['sudo', 'mount', volume['mountpoint'], mount_path])
        try:
            self._ssh_exec(server_details, command)
        except exception.ProcessExecutionError as e:
            if 'already mounted' not in e.stderr:
                raise
            LOG.debug('Share %s is already mounted' % share['name'])
        command = ['sudo', 'chmod', '777', mount_path]
        self._ssh_exec(server_details, command)

    def _unmount_device(self, share, server_details):
        """Unmounts device from directory on service vm."""
        mount_path = self._get_mount_path(share)
        command = ['sudo', 'umount', mount_path, ';']
        command.extend(['sudo', 'rmdir', mount_path])
        try:
            self._ssh_exec(server_details, command)
        except exception.ProcessExecutionError as e:
            if 'not found' in e.stderr:
                LOG.debug('%s is not mounted' % share['name'])

    def _get_mount_path(self, share):
        """
        Returns the path, that will be used for mount device in service vm.
        """
        return os.path.join(self.configuration.share_mount_path, share['name'])

    def _attach_volume(self, context, share, instance_id, volume):
        """Attaches cinder volume to service vm."""
        @lockutils.synchronized(instance_id, external=True,
                                lock_path="attach_detach_locks")
        def do_attach(volume):
            if volume['status'] == 'in-use':
                attached_volumes = [vol.id for vol in
                                    self.compute_api.instance_volumes_list(
                                        self.admin_context, instance_id)]
                if volume['id'] in attached_volumes:
                    return volume
                else:
                    raise exception.ManilaException(
                        _('Volume %s is already attached to another instance')
                        % volume['id'])
            self.compute_api.instance_volume_attach(self.admin_context,
                                                    instance_id,
                                                    volume['id'],
                                                    )
            t = time.time()
            while time.time() - t < self.configuration.max_time_to_attach:
                volume = self.volume_api.get(context, volume['id'])
                if volume['status'] == 'in-use':
                    return volume
                elif volume['status'] != 'attaching':
                    raise exception.ManilaException(
                        _('Failed to attach volume %s') % volume['id'])
                time.sleep(1)
            else:
                raise exception.ManilaException(
                    _('Volume have not been attached in %ss. Giving up') %
                    self.configuration.max_time_to_attach)
        return do_attach(volume)

    def _get_volume(self, context, share_id):
        """Finds volume, associated to the specific share."""
        volume_name = self.configuration.volume_name_template % share_id
        search_opts = {'display_name': volume_name}
        if context.is_admin:
            search_opts['all_tenants'] = True
        volumes_list = self.volume_api.get_all(context, search_opts)
        volume = None
        if len(volumes_list) == 1:
            volume = volumes_list[0]
        elif len(volumes_list) > 1:
            raise exception.ManilaException(_('Error. Ambiguous volumes'))
        return volume

    def _get_volume_snapshot(self, context, snapshot_id):
        """Finds volume snaphots, associated to the specific share snaphots."""
        volume_snapshot_name = self.configuration.\
                volume_snapshot_name_template % snapshot_id
        volume_snapshot_list = self.volume_api.get_all_snapshots(context,
                                        {'display_name': volume_snapshot_name})
        volume_snapshot = None
        if len(volume_snapshot_list) == 1:
            volume_snapshot = volume_snapshot_list[0]
        elif len(volume_snapshot_list) > 1:
            raise exception.ManilaException(
                    _('Error. Ambiguous volume snaphots'))
        return volume_snapshot

    def _detach_volume(self, context, share, server_details):
        """Detaches cinder volume from service vm."""
        instance_id = server_details['instance_id']

        @lockutils.synchronized(instance_id, external=True,
                                lock_path="attach_detach_locks")
        def do_detach():
            attached_volumes = [vol.id for vol in
                                self.compute_api.instance_volumes_list(
                                    self.admin_context, instance_id)]
            volume = self._get_volume(context, share['id'])
            if volume and volume['id'] in attached_volumes:
                self.compute_api.instance_volume_detach(
                    self.admin_context,
                    instance_id,
                    volume['id']
                )
                t = time.time()
                while time.time() - t < self.configuration.max_time_to_attach:
                    volume = self.volume_api.get(context, volume['id'])
                    if volume['status'] in ('available', 'error'):
                        break
                    time.sleep(1)
                else:
                    raise exception.ManilaException(
                        _('Volume have not been detached in %ss. Giving up')
                        % self.configuration.max_time_to_attach)
        do_detach()

    def _allocate_container(self, context, share, snapshot=None):
        """Creates cinder volume, associated to share by name."""
        volume_snapshot = None
        if snapshot:
            volume_snapshot = self._get_volume_snapshot(context,
                                                        snapshot['id'])
        volume = self.volume_api.create(context, share['size'],
                     self.configuration.volume_name_template % share['id'], '',
                     snapshot=volume_snapshot)

        t = time.time()
        while time.time() - t < self.configuration.max_time_to_create_volume:
            if volume['status'] == 'available':
                break
            if volume['status'] == 'error':
                raise exception.ManilaException(_('Failed to create volume'))
            time.sleep(1)
            volume = self.volume_api.get(context, volume['id'])
        else:
            raise exception.ManilaException(_('Volume have not been created '
                                              'in %ss. Giving up') %
                                 self.configuration.max_time_to_create_volume)

        return volume

    def _deallocate_container(self, context, share):
        """Deletes cinder volume."""
        volume = self._get_volume(context, share['id'])
        if volume:
            self.volume_api.delete(context, volume['id'])
            t = time.time()
            while (time.time() - t <
                   self.configuration.max_time_to_create_volume):
                try:
                    volume = self.volume_api.get(context, volume['id'])
                except exception.VolumeNotFound:
                    LOG.debug('Volume was deleted succesfully')
                    break
                time.sleep(1)
            else:
                raise exception.ManilaException(_('Volume have not been '
                                                  'deleted in %ss. Giving up')
                               % self.configuration.max_time_to_create_volume)

    def get_share_stats(self, refresh=False):
        """Get share status.
        If 'refresh' is True, run update the stats first.
        """
        if refresh:
            self._update_share_status()

        return self._stats

    def _update_share_status(self):
        """Retrieve status info from share volume group."""

        LOG.debug("Updating share status")
        data = {}

        # Note(zhiteng): These information are driver/backend specific,
        # each driver may define these values in its own config options
        # or fetch from driver specific configuration file.
        data["share_backend_name"] = self.backend_name
        data["vendor_name"] = 'Open Source'
        data["driver_version"] = '1.0'
        data["storage_protocol"] = 'NFS_CIFS'

        data['total_capacity_gb'] = 'infinite'
        data['free_capacity_gb'] = 'infinite'
        data['reserved_percentage'] = (self.configuration.
                reserved_share_percentage)
        data['QoS_support'] = False

        self._stats = data

    @ensure_server
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        volume = self._allocate_container(self.admin_context, share, snapshot)
        volume = self._attach_volume(
            self.admin_context, share,
            share_server['backend_details']['instance_id'], volume)
        self._mount_device(context, share, share_server['backend_details'],
                           volume)
        location = self._get_helper(share).create_export(
            share_server['backend_details'],
            share['name'])
        return location

    @ensure_server
    def delete_share(self, context, share, share_server=None):
        """Deletes share."""
        self._get_helper(share).remove_export(share_server['backend_details'],
                                              share['name'])
        self._unmount_device(share, share_server['backend_details'])
        self._detach_volume(self.admin_context, share,
                            share_server['backend_details'])
        self._deallocate_container(self.admin_context, share)

    @ensure_server
    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot."""
        volume = self._get_volume(self.admin_context, snapshot['share_id'])
        volume_snapshot_name = (self.configuration.
                                volume_snapshot_name_template % snapshot['id'])
        volume_snapshot = self.volume_api.create_snapshot_force(
            self.admin_context, volume['id'], volume_snapshot_name, '')
        t = time.time()
        while time.time() - t < self.configuration.max_time_to_create_volume:
            if volume_snapshot['status'] == 'available':
                break
            if volume_snapshot['status'] == 'error':
                raise exception.ManilaException(_('Failed to create volume '
                                                  'snapshot'))
            time.sleep(1)
            volume_snapshot = self.volume_api.get_snapshot(self.admin_context,
                                                volume_snapshot['id'])
        else:
            raise exception.ManilaException(_('Volume snapshot have not been '
                                              'created in %ss. Giving up') %
                                  self.configuration.max_time_to_create_volume)

    @ensure_server
    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot."""
        volume_snapshot = self._get_volume_snapshot(self.admin_context,
                                                    snapshot['id'])
        if volume_snapshot is None:
            return
        self.volume_api.delete_snapshot(self.admin_context,
                                        volume_snapshot['id'])
        t = time.time()
        while time.time() - t < self.configuration.max_time_to_create_volume:
            try:
                snapshot = self.volume_api.get_snapshot(self.admin_context,
                                                        volume_snapshot['id'])
            except exception.VolumeSnapshotNotFound:
                LOG.debug('Volume snapshot was deleted succesfully')
                break
            time.sleep(1)
        else:
            raise exception.ManilaException(_('Volume snapshot have not been '
                                              'deleted in %ss. Giving up') %
                                  self.configuration.max_time_to_create_volume)

    @ensure_server
    def ensure_share(self, context, share, share_server=None):
        """Ensure that storage are mounted and exported."""
        volume = self._get_volume(context, share['id'])
        volume = self._attach_volume(
            context,
            share,
            share_server['backend_details']['instance_id'],
            volume)
        self._mount_device(context, share, share_server['backend_details'],
                           volume)
        self._get_helper(share).create_export(share_server['backend_details'],
                                              share['name'],
                                              recreate=True)

    @ensure_server
    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        self._get_helper(share).allow_access(share_server['backend_details'],
                                             share['name'],
                                             access['access_type'],
                                             access['access_to'])

    @ensure_server
    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        self._get_helper(share).deny_access(share_server['backend_details'],
                                            share['name'],
                                            access['access_type'],
                                            access['access_to'])

    def _get_helper(self, share):
        if share['share_proto'].startswith('NFS'):
            return self._helpers['NFS']
        elif share['share_proto'].startswith('CIFS'):
            return self._helpers['CIFS']
        else:
            raise exception.InvalidShare(reason='Wrong share type')

    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        # NOTE(vponomaryov): Generic driver does not need allocations, because
        # Nova will handle it. It is valid for all multitenant drivers, that
        # use service instance provided by Nova.
        return 0

    def setup_server(self, network_info, metadata=None):
        msg = "Creating share server '%s'."
        LOG.debug(msg % network_info['server_id'])
        server = self.service_instance_manager.set_up_service_instance(
            self.admin_context,
            network_info['server_id'],
            network_info['neutron_net_id'],
            network_info['neutron_subnet_id'],
        )
        for helper in self._helpers.values():
                helper.init_helper(server)
        return server

    def teardown_server(self, server_details, security_services=None):
        instance_id = server_details.get("instance_id")
        msg = "Removing share infrastructure for service instance '%s'."
        LOG.debug(msg % instance_id)
        try:
            self.service_instance_manager.delete_service_instance(
                self.admin_context,
                server_details['instance_id'],
                server_details['subnet_id'],
                server_details['router_id']
            )
        except Exception as e:
            LOG.warning(e)


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

    def allow_access(self, server, share_name, access_type, access):
        """Allow access to the host."""
        raise NotImplementedError()

    def deny_access(self, local_path, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        raise NotImplementedError()


class NFSHelper(NASHelperBase):
    """Interface to work with share."""

    def create_export(self, server, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        return ':'.join([server['ip'],
            os.path.join(self.configuration.share_mount_path, share_name)])

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
        pass

    def allow_access(self, server, share_name, access_type, access):
        """Allow access to the host"""
        local_path = os.path.join(self.configuration.share_mount_path,
                                  share_name)
        if access_type != 'ip':
            reason = 'only ip access type allowed'
            raise exception.InvalidShareAccess(reason)
        # check if presents in export
        out, _ = self._ssh_exec(server, ['sudo', 'exportfs'])
        out = re.search(re.escape(local_path) + '[\s\n]*' + re.escape(access),
                        out)
        if out is not None:
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access)
        self._ssh_exec(server,
                       ['sudo', 'exportfs', '-o', 'rw,no_subtree_check',
                        ':'.join([access, local_path])])

    def deny_access(self, server, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        local_path = os.path.join(self.configuration.share_mount_path,
                                  share_name)
        self._ssh_exec(server, ['sudo', 'exportfs', '-u',
                                ':'.join([access, local_path])])


def cifs_synchronized(f):

    def wrapped_func(self, *args, **kwargs):
        key = "cifs-%s" % args[0]["instance_id"]

        @lockutils.synchronized(key)
        def source_func(self, *args, **kwargs):
            return f(self, *args, **kwargs)

        return source_func(self, *args, **kwargs)

    return wrapped_func


class CIFSHelper(NASHelperBase):
    """Class provides functionality to operate with cifs shares"""

    def __init__(self, *args):
        """Store executor and configuration path."""
        super(CIFSHelper, self).__init__(*args)
        self.config_path = self.configuration.service_instance_smb_config_path
        self.smb_template_config = self.configuration.smb_template_config_path
        self.test_config = "%s_" % (self.smb_template_config,)
        self.local_configs = {}

    def _create_local_config(self, share_network_id):
        path, ext = os.path.splitext(self.smb_template_config)
        local_config = '%s-%s%s' % (path, share_network_id, ext)
        self.local_configs[share_network_id] = local_config
        shutil.copy(self.smb_template_config, local_config)
        return local_config

    def _get_local_config(self, share_network_id):
        local_config = self.local_configs.get(share_network_id, None)
        if local_config is None:
            local_config = self._create_local_config(share_network_id)
        return local_config

    @cifs_synchronized
    def init_helper(self, server):
        self._recreate_template_config()
        local_config = self._create_local_config(server['instance_id'])
        config_dir = os.path.dirname(self.config_path)
        try:
            self._ssh_exec(server, ['sudo', 'mkdir', config_dir])
        except exception.ProcessExecutionError as e:
            if 'File exists' not in e.stderr:
                raise
            LOG.debug('Directory %s already exists' % config_dir)
        self._ssh_exec(server, ['sudo', 'chown',
                                self.configuration.service_instance_user,
                                config_dir])
        self._ssh_exec(server, ['touch', self.config_path])
        try:
            self._ssh_exec(server, ['sudo', 'stop', 'smbd'])
        except exception.ProcessExecutionError as e:
            if 'Unknown instance' not in e.stderr:
                raise
            LOG.debug('Samba service is not running')
        self._write_remote_config(local_config, server)
        self._ssh_exec(server, ['sudo', 'smbd', '-s', self.config_path])
        self._restart_service(server)

    @cifs_synchronized
    def create_export(self, server, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        local_path = os.path.join(self.configuration.share_mount_path,
                                  share_name)
        config = self._get_local_config(server['instance_id'])
        parser = ConfigParser.ConfigParser()
        parser.read(config)
        # delete old one
        if parser.has_section(share_name):
            if recreate:
                parser.remove_section(share_name)
            else:
                raise exception.Error('Section exists')
        # Create new one
        parser.add_section(share_name)
        parser.set(share_name, 'path', local_path)
        parser.set(share_name, 'browseable', 'yes')
        parser.set(share_name, 'guest ok', 'yes')
        parser.set(share_name, 'read only', 'no')
        parser.set(share_name, 'writable', 'yes')
        parser.set(share_name, 'create mask', '0755')
        parser.set(share_name, 'hosts deny', '0.0.0.0/0')  # denying all ips
        parser.set(share_name, 'hosts allow', '127.0.0.1')
        self._update_config(parser, config)
        self._write_remote_config(config, server)
        self._restart_service(server)
        return '//%s/%s' % (server['ip'], share_name)

    @cifs_synchronized
    def remove_export(self, server, share_name):
        """Remove export."""
        config = self._get_local_config(server['instance_id'])
        parser = ConfigParser.ConfigParser()
        parser.read(config)
        # delete old one
        if parser.has_section(share_name):
            parser.remove_section(share_name)
        self._update_config(parser, config)
        self._write_remote_config(config, server)
        self._ssh_exec(server, ['sudo', 'smbcontrol', 'all', 'close-share',
                                share_name])

    def _write_remote_config(self, config, server):
        with open(config, 'r') as f:
            cfg = "'%s'" % f.read()
        self._ssh_exec(server, ['echo %s > %s' % (cfg, self.config_path)])

    @cifs_synchronized
    def allow_access(self, server, share_name, access_type, access):
        """Allow access to the host."""
        if access_type != 'ip':
            reason = 'only ip access type allowed'
            raise exception.InvalidShareAccess(reason)
        config = self._get_local_config(server['instance_id'])
        parser = ConfigParser.ConfigParser()
        parser.read(config)

        hosts = parser.get(share_name, 'hosts allow')

        if access in hosts.split():
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access)
        hosts += ' %s' % (access,)
        parser.set(share_name, 'hosts allow', hosts)
        self._update_config(parser, config)
        self._write_remote_config(config, server)
        self._restart_service(server)

    @cifs_synchronized
    def deny_access(self, server, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        config = self._get_local_config(server['instance_id'])
        parser = ConfigParser.ConfigParser()
        try:
            parser.read(config)
            hosts = parser.get(share_name, 'hosts allow')
            hosts = hosts.replace(' %s' % (access,), '', 1)
            parser.set(share_name, 'hosts allow', hosts)
            self._update_config(parser, config)
        except ConfigParser.NoSectionError:
            if not force:
                raise
        self._write_remote_config(config, server)
        self._restart_service(server)

    def _recreate_template_config(self):
        """Create new SAMBA configuration file."""
        if os.path.exists(self.smb_template_config):
            os.unlink(self.smb_template_config)
        parser = ConfigParser.ConfigParser()
        parser.add_section('global')
        parser.set('global', 'security', 'user')
        parser.set('global', 'server string', '%h server (Samba, Openstack)')
        self._update_config(parser, self.smb_template_config)

    def _restart_service(self, server):
        self._ssh_exec(server, 'sudo pkill -HUP smbd'.split())

    def _update_config(self, parser, config):
        """Check if new configuration is correct and save it."""
        # Check that configuration is correct
        with open(self.test_config, 'w') as fp:
            parser.write(fp)
        self._execute('testparm', '-s', self.test_config, check_exit_code=True)
        # save it
        with open(config, 'w') as fp:
            parser.write(fp)
