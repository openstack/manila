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

import os
import time

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
from oslo_utils import units
import retrying
import six

from manila.common import constants as const
from manila import compute
from manila import context
from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LI
from manila.i18n import _LW
from manila.share import driver
from manila.share.drivers import service_instance
from manila import utils
from manila import volume

LOG = log.getLogger(__name__)

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
    cfg.IntOpt('max_time_to_extend_volume',
               default=180,
               help="Maximum time to wait for extending cinder volume."),
    cfg.IntOpt('max_time_to_attach',
               default=120,
               help="Maximum time to wait for attaching cinder volume."),
    cfg.StrOpt('service_instance_smb_config_path',
               default='$share_mount_path/smb.conf',
               help="Path to SMB config in service instance."),
    cfg.ListOpt('share_helpers',
                default=[
                    'CIFS=manila.share.drivers.helpers.CIFSHelperIPAccess',
                    'NFS=manila.share.drivers.helpers.NFSHelper',
                ],
                help='Specify list of share export helpers.'),
    cfg.StrOpt('share_volume_fstype',
               default='ext4',
               choices=['ext4', 'ext3'],
               help='Filesystem type of the share volume.'),
    cfg.StrOpt('cinder_volume_type',
               help='Name or id of cinder volume type which will be used '
                    'for all volumes created by driver.'),
]

CONF = cfg.CONF
CONF.register_opts(share_opts)

# NOTE(u_glide): These constants refer to the column number in the "df" output
BLOCK_DEVICE_SIZE_INDEX = 1
USED_SPACE_INDEX = 2


def ensure_server(f):

    def wrap(self, context, *args, **kwargs):
        server = kwargs.get('share_server')

        if not self.driver_handles_share_servers:
            if not server:
                server = self.service_instance_manager.get_common_server()
                kwargs['share_server'] = server
            else:
                raise exception.ManilaException(
                    _("Share server handling is not available. "
                      "But 'share_server' was provided. '%s'. "
                      "Share network should not be used.") % server.get('id'))
        elif not server:
            raise exception.ManilaException(
                _("Share server handling is enabled. But 'share_server' "
                  "is not provided. Make sure you used 'share_network'."))

        if not server.get('backend_details'):
            raise exception.ManilaException(
                _("Share server '%s' does not have backend details.") %
                server['id'])
        if not self.service_instance_manager.ensure_service_instance(
                context, server['backend_details']):
            raise exception.ServiceInstanceUnavailable()

        return f(self, context, *args, **kwargs)

    return wrap


class GenericShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """Executes commands relating to Shares."""

    def __init__(self, *args, **kwargs):
        """Do initialization."""
        super(GenericShareDriver, self).__init__(
            [False, True], *args, **kwargs)
        self.admin_context = context.get_admin_context()
        self.configuration.append_config_values(share_opts)
        self._helpers = {}
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or "Cinder_Volumes"
        self.ssh_connections = {}
        self._setup_service_instance_manager()
        self.private_storage = kwargs.get('private_storage')

    def _setup_service_instance_manager(self):
        self.service_instance_manager = (
            service_instance.ServiceInstanceManager(
                driver_config=self.configuration))

    def _ssh_exec(self, server, command):
        connection = self.ssh_connections.get(server['instance_id'])
        ssh_conn_timeout = self.configuration.ssh_conn_timeout
        if not connection:
            ssh_pool = utils.SSHPool(server['ip'],
                                     22,
                                     ssh_conn_timeout,
                                     server['username'],
                                     server.get('password'),
                                     server.get('pk_path'),
                                     max_size=1)
            ssh = ssh_pool.create()
            self.ssh_connections[server['instance_id']] = (ssh_pool, ssh)
        else:
            ssh_pool, ssh = connection

        if not ssh.get_transport().is_active():
            ssh_pool.remove(ssh)
            ssh = ssh_pool.create()
            self.ssh_connections[server['instance_id']] = (ssh_pool, ssh)
        return processutils.ssh_execute(ssh, ' '.join(command))

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""

    def do_setup(self, context):
        """Any initialization the generic driver does while starting."""
        super(GenericShareDriver, self).do_setup(context)
        self.compute_api = compute.API()
        self.volume_api = volume.API()
        self._setup_helpers()

        common_sv_available = False
        share_server = None
        sv_fetch_retry_interval = 5
        while not (common_sv_available or self.driver_handles_share_servers):
            try:
                # Verify availability of common server
                share_server = (
                    self.service_instance_manager.get_common_server())
                common_sv_available = self._is_share_server_active(
                    context, share_server)
            except Exception as ex:
                LOG.error(ex)

            if not common_sv_available:
                time.sleep(sv_fetch_retry_interval)
                LOG.warning(_LW("Waiting for the common service VM to become "
                                "available. "
                                "Driver is currently uninitialized. "
                                "Share server: %(share_server)s "
                                "Retry interval: %(retry_interval)s"),
                            dict(share_server=share_server,
                                 retry_interval=sv_fetch_retry_interval))

    def _setup_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        helpers = self.configuration.share_helpers
        if helpers:
            for helper_str in helpers:
                share_proto, __, import_str = helper_str.partition('=')
                helper = importutils.import_class(import_str)
                self._helpers[share_proto.upper()] = helper(
                    self._execute,
                    self._ssh_exec,
                    self.configuration)
        else:
            raise exception.ManilaException(
                "No protocol helpers selected for Generic Driver. "
                "Please specify using config option 'share_helpers'.")

    def _get_access_rule_for_data_copy(self, context, share, share_server):
        if not self.driver_handles_share_servers:
            service_ip = self.configuration.safe_get(
                'migration_data_copy_node_ip')
        else:
            service_ip = share_server['backend_details']['service_ip']
        return {'access_type': 'ip',
                'access_level': 'rw',
                'access_to': service_ip}

    @ensure_server
    def create_share(self, context, share, share_server=None):
        """Creates share."""
        helper = self._get_helper(share)
        server_details = share_server['backend_details']
        volume = self._allocate_container(self.admin_context, share)
        volume = self._attach_volume(
            self.admin_context,
            share,
            server_details['instance_id'],
            volume)
        self._format_device(server_details, volume)
        self._mount_device(share, server_details, volume)
        location = helper.create_export(
            server_details,
            share['name'])
        return {
            "path": location,
            "is_admin_only": False,
            "metadata": {
                # TODO(vponomaryov): remove this fake metadata when proper
                # appears.
                "export_location_metadata_example": "example",
            },
        }

    def _format_device(self, server_details, volume):
        """Formats device attached to the service vm."""
        command = ['sudo', 'mkfs.%s' % self.configuration.share_volume_fstype,
                   volume['mountpoint']]
        self._ssh_exec(server_details, command)

    def _is_device_mounted(self, mount_path, server_details, volume=None):
        """Checks whether volume already mounted or not."""
        log_data = {
            'mount_path': mount_path,
            'server_id': server_details['instance_id'],
        }
        if volume and volume.get('mountpoint', ''):
            log_data['volume_id'] = volume['id']
            log_data['dev_mount_path'] = volume['mountpoint']
            msg = ("Checking whether volume '%(volume_id)s' with mountpoint "
                   "'%(dev_mount_path)s' is mounted on mount path '%(mount_p"
                   "ath)s' on server '%(server_id)s' or not." % log_data)
        else:
            msg = ("Checking whether mount path '%(mount_path)s' exists on "
                   "server '%(server_id)s' or not." % log_data)
        LOG.debug(msg)
        mounts_list_cmd = ['sudo', 'mount']
        output, __ = self._ssh_exec(server_details, mounts_list_cmd)
        mounts = output.split('\n')
        for mount in mounts:
            mount_elements = mount.split(' ')
            if (len(mount_elements) > 2 and mount_path == mount_elements[2]):
                if volume:
                    # Mount goes with device path and mount path
                    if (volume.get('mountpoint', '') == mount_elements[0]):
                        return True
                else:
                    # Unmount goes only by mount path
                    return True
        return False

    def _sync_mount_temp_and_perm_files(self, server_details):
        """Sync temporary and permanent files for mounted filesystems."""
        try:
            self._ssh_exec(
                server_details,
                ['sudo', 'cp', const.MOUNT_FILE_TEMP, const.MOUNT_FILE],
            )
        except exception.ProcessExecutionError as e:
            LOG.error(_LE("Failed to sync mount files on server '%s'."),
                      server_details['instance_id'])
            raise exception.ShareBackendException(msg=six.text_type(e))
        try:
            # Remount it to avoid postponed point of failure
            self._ssh_exec(server_details, ['sudo', 'mount', '-a'])
        except exception.ProcessExecutionError as e:
            LOG.error(_LE("Failed to mount all shares on server '%s'."),
                      server_details['instance_id'])
            raise exception.ShareBackendException(msg=six.text_type(e))

    def _mount_device(self, share, server_details, volume):
        """Mounts block device to the directory on service vm.

        Mounts attached and formatted block device to the directory if not
        mounted yet.
        """

        @utils.synchronized('generic_driver_mounts_'
                            '%s' % server_details['instance_id'])
        def _mount_device_with_lock():
            mount_path = self._get_mount_path(share)
            log_data = {
                'dev': volume['mountpoint'],
                'path': mount_path,
                'server': server_details['instance_id'],
            }
            try:
                if not self._is_device_mounted(mount_path, server_details,
                                               volume):
                    LOG.debug("Mounting '%(dev)s' to path '%(path)s' on "
                              "server '%(server)s'.", log_data)
                    mount_cmd = ['sudo mkdir -p', mount_path, '&&']
                    mount_cmd.extend(['sudo mount', volume['mountpoint'],
                                      mount_path])
                    mount_cmd.extend(['&& sudo chmod 777', mount_path])
                    self._ssh_exec(server_details, mount_cmd)

                    # Add mount permanently
                    self._sync_mount_temp_and_perm_files(server_details)
                else:
                    LOG.warning(_LW("Mount point '%(path)s' already exists on "
                                    "server '%(server)s'."), log_data)
            except exception.ProcessExecutionError as e:
                raise exception.ShareBackendException(msg=six.text_type(e))
        return _mount_device_with_lock()

    @utils.retry(exception.ProcessExecutionError)
    def _unmount_device(self, share, server_details):
        """Unmounts block device from directory on service vm."""

        @utils.synchronized('generic_driver_mounts_'
                            '%s' % server_details['instance_id'])
        def _unmount_device_with_lock():
            mount_path = self._get_mount_path(share)
            log_data = {
                'path': mount_path,
                'server': server_details['instance_id'],
            }
            if self._is_device_mounted(mount_path, server_details):
                LOG.debug("Unmounting path '%(path)s' on server "
                          "'%(server)s'.", log_data)
                unmount_cmd = ['sudo umount', mount_path, '&& sudo rmdir',
                               mount_path]
                self._ssh_exec(server_details, unmount_cmd)
                # Remove mount permanently
                self._sync_mount_temp_and_perm_files(server_details)
            else:
                LOG.warning(_LW("Mount point '%(path)s' does not exist on "
                                "server '%(server)s'."), log_data)
        return _unmount_device_with_lock()

    def _get_mount_path(self, share):
        """Returns the path to use for mount device in service vm."""
        return os.path.join(self.configuration.share_mount_path, share['name'])

    def _attach_volume(self, context, share, instance_id, volume):
        """Attaches cinder volume to service vm."""
        @utils.synchronized(
            "generic_driver_attach_detach_%s" % instance_id, external=True)
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

            @retrying.retry(stop_max_attempt_number=3,
                            wait_fixed=2000,
                            retry_on_exception=lambda exc: True)
            def attach_volume():
                self.compute_api.instance_volume_attach(
                    self.admin_context, instance_id, volume['id'])

            attach_volume()

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

    def _get_volume_name(self, share_id):
        return self.configuration.volume_name_template % share_id

    def _get_volume(self, context, share_id):
        """Finds volume, associated to the specific share."""
        volume_id = self.private_storage.get(share_id, 'volume_id')

        if volume_id is not None:
            return self.volume_api.get(context, volume_id)
        else:  # Fallback to legacy method
            return self._get_volume_legacy(context, share_id)

    def _get_volume_legacy(self, context, share_id):
        # NOTE(u_glide): this method is deprecated and will be removed in
        # future versions
        volume_name = self._get_volume_name(share_id)
        search_opts = {'name': volume_name}
        if context.is_admin:
            search_opts['all_tenants'] = True
        volumes_list = self.volume_api.get_all(context, search_opts)
        if len(volumes_list) == 1:
            return volumes_list[0]
        elif len(volumes_list) > 1:
            LOG.error(
                _LE("Expected only one volume in volume list with name "
                    "'%(name)s', but got more than one in a result - "
                    "'%(result)s'."), {
                        'name': volume_name, 'result': volumes_list})
            raise exception.ManilaException(
                _("Error. Ambiguous volumes for name '%s'") % volume_name)
        return None

    def _get_volume_snapshot(self, context, snapshot_id):
        """Find volume snapshot associated to the specific share snapshot."""
        volume_snapshot_id = self.private_storage.get(
            snapshot_id, 'volume_snapshot_id')

        if volume_snapshot_id is not None:
            return self.volume_api.get_snapshot(context, volume_snapshot_id)
        else:  # Fallback to legacy method
            return self._get_volume_snapshot_legacy(context, snapshot_id)

    def _get_volume_snapshot_legacy(self, context, snapshot_id):
        # NOTE(u_glide): this method is deprecated and will be removed in
        # future versions
        volume_snapshot_name = (
            self.configuration.volume_snapshot_name_template % snapshot_id)
        volume_snapshot_list = self.volume_api.get_all_snapshots(
            context, {'name': volume_snapshot_name})
        volume_snapshot = None
        if len(volume_snapshot_list) == 1:
            volume_snapshot = volume_snapshot_list[0]
        elif len(volume_snapshot_list) > 1:
            LOG.error(
                _LE("Expected only one volume snapshot in list with name "
                    "'%(name)s', but got more than one in a result - "
                    "'%(result)s'."), {
                        'name': volume_snapshot_name,
                        'result': volume_snapshot_list})
            raise exception.ManilaException(
                _('Error. Ambiguous volume snaphots'))
        return volume_snapshot

    def _detach_volume(self, context, share, server_details):
        """Detaches cinder volume from service vm."""
        instance_id = server_details['instance_id']

        @utils.synchronized(
            "generic_driver_attach_detach_%s" % instance_id, external=True)
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
                    if volume['status'] in (const.STATUS_AVAILABLE,
                                            const.STATUS_ERROR):
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

        volume = self.volume_api.create(
            context,
            share['size'],
            self.configuration.volume_name_template % share['id'], '',
            snapshot=volume_snapshot,
            volume_type=self.configuration.cinder_volume_type,
            availability_zone=share['availability_zone'])

        self.private_storage.update(
            share['id'], {'volume_id': volume['id']})

        msg_error = _('Failed to create volume')
        msg_timeout = (
            _('Volume has not been created in %ss. Giving up') %
            self.configuration.max_time_to_create_volume
        )

        return self._wait_for_available_volume(
            volume, self.configuration.max_time_to_create_volume,
            msg_error=msg_error, msg_timeout=msg_timeout
        )

    def _wait_for_available_volume(self, volume, timeout,
                                   msg_error, msg_timeout,
                                   expected_size=None):
        t = time.time()
        while time.time() - t < timeout:
            if volume['status'] == const.STATUS_AVAILABLE:
                if expected_size and volume['size'] != expected_size:
                    LOG.debug("The volume %(vol_id)s is available but the "
                              "volume size does not match the expected size. "
                              "A volume resize operation may be pending. "
                              "Expected size: %(expected_size)s, "
                              "Actual size: %(volume_size)s.",
                              dict(vol_id=volume['id'],
                                   expected_size=expected_size,
                                   volume_size=volume['size']))
                else:
                    break
            elif 'error' in volume['status'].lower():
                raise exception.ManilaException(msg_error)
            time.sleep(1)
            volume = self.volume_api.get(self.admin_context, volume['id'])
        else:
            raise exception.ManilaException(msg_timeout)

        return volume

    def _deallocate_container(self, context, share):
        """Deletes cinder volume."""
        try:
            volume = self._get_volume(context, share['id'])
        except exception.VolumeNotFound:
            LOG.info(_LI("Volume not found. Already deleted?"))
            volume = None
        if volume:
            if volume['status'] == 'in-use':
                raise exception.ManilaException(
                    _('Volume is still in use and '
                      'cannot be deleted now.'))
            self.volume_api.delete(context, volume['id'])
            t = time.time()
            while (time.time() - t <
                   self.configuration.max_time_to_create_volume):
                try:
                    volume = self.volume_api.get(context, volume['id'])
                except exception.VolumeNotFound:
                    LOG.debug('Volume was deleted successfully')
                    break
                time.sleep(1)
            else:
                raise exception.ManilaException(
                    _('Volume have not been '
                      'deleted in %ss. Giving up')
                    % self.configuration.max_time_to_create_volume)

    def _update_share_stats(self):
        """Retrieve stats info from share volume group."""
        data = dict(
            share_backend_name=self.backend_name,
            storage_protocol='NFS_CIFS',
            reserved_percentage=self.configuration.reserved_share_percentage,
            consistency_group_support='pool',
        )
        super(GenericShareDriver, self)._update_share_stats(data)

    @ensure_server
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        helper = self._get_helper(share)
        volume = self._allocate_container(self.admin_context, share, snapshot)
        volume = self._attach_volume(
            self.admin_context, share,
            share_server['backend_details']['instance_id'], volume)
        self._mount_device(share, share_server['backend_details'], volume)
        location = helper.create_export(share_server['backend_details'],
                                        share['name'])
        return location

    @ensure_server
    def extend_share(self, share, new_size, share_server=None):
        server_details = share_server['backend_details']

        helper = self._get_helper(share)
        helper.disable_access_for_maintenance(server_details, share['name'])
        self._unmount_device(share, server_details)
        self._detach_volume(self.admin_context, share, server_details)

        volume = self._get_volume(self.admin_context, share['id'])
        volume = self._extend_volume(self.admin_context, volume, new_size)

        volume = self._attach_volume(
            self.admin_context,
            share,
            server_details['instance_id'],
            volume)
        self._resize_filesystem(server_details, volume)
        self._mount_device(share, server_details, volume)
        helper.restore_access_after_maintenance(server_details,
                                                share['name'])

    def _extend_volume(self, context, volume, new_size):
        self.volume_api.extend(context, volume['id'], new_size)

        msg_error = _('Failed to extend volume %s') % volume['id']
        msg_timeout = (
            _('Volume has not been extended in %ss. Giving up') %
            self.configuration.max_time_to_extend_volume
        )
        return self._wait_for_available_volume(
            volume, self.configuration.max_time_to_extend_volume,
            msg_error=msg_error, msg_timeout=msg_timeout,
            expected_size=new_size
        )

    @ensure_server
    def shrink_share(self, share, new_size, share_server=None):
        server_details = share_server['backend_details']

        helper = self._get_helper(share)
        export_location = share['export_locations'][0]['path']
        mount_path = helper.get_share_path_by_export_location(
            server_details, export_location)

        consumed_space = self._get_consumed_space(mount_path, server_details)

        LOG.debug("Consumed space on share: %s", consumed_space)

        if consumed_space >= new_size:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share['id'])

        volume = self._get_volume(self.admin_context, share['id'])

        helper.disable_access_for_maintenance(server_details, share['name'])
        self._unmount_device(share, server_details)

        try:
            self._resize_filesystem(server_details, volume, new_size=new_size)
        except exception.Invalid:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share['id'])
        except Exception as e:
            msg = _("Cannot shrink share: %s") % six.text_type(e)
            raise exception.Invalid(msg)
        finally:
            self._mount_device(share, server_details, volume)
            helper.restore_access_after_maintenance(server_details,
                                                    share['name'])

    def _resize_filesystem(self, server_details, volume, new_size=None):
        """Resize filesystem of provided volume."""
        check_command = ['sudo', 'fsck', '-pf', volume['mountpoint']]
        self._ssh_exec(server_details, check_command)
        command = ['sudo', 'resize2fs', volume['mountpoint']]

        if new_size:
            command.append("%sG" % six.text_type(new_size))

        try:
            self._ssh_exec(server_details, command)
        except processutils.ProcessExecutionError as e:
            if e.stderr.find('New size smaller than minimum') != -1:
                msg = (_("Invalid 'new_size' provided: %s")
                       % six.text_type(new_size))
                raise exception.Invalid(msg)
            else:
                msg = _("Cannot resize file-system: %s") % six.text_type(e)
                raise exception.ManilaException(msg)

    def _is_share_server_active(self, context, share_server):
        """Check if the share server is active."""
        has_active_share_server = (
            share_server and share_server.get('backend_details') and
            self.service_instance_manager.ensure_service_instance(
                context, share_server['backend_details']))
        return has_active_share_server

    def delete_share(self, context, share, share_server=None):
        """Deletes share."""
        helper = self._get_helper(share)
        if not self.driver_handles_share_servers:
            share_server = self.service_instance_manager.get_common_server()
        if self._is_share_server_active(context, share_server):
            helper.remove_export(
                share_server['backend_details'], share['name'])
            self._unmount_device(share, share_server['backend_details'])
            self._detach_volume(self.admin_context, share,
                                share_server['backend_details'])

        # Note(jun): It is an intended breakage to deal with the cases
        # with any reason that caused absence of Nova instances.
        self._deallocate_container(self.admin_context, share)

        self.private_storage.delete(share['id'])

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot."""
        volume = self._get_volume(self.admin_context, snapshot['share_id'])
        volume_snapshot_name = (self.configuration.
                                volume_snapshot_name_template % snapshot['id'])
        volume_snapshot = self.volume_api.create_snapshot_force(
            self.admin_context, volume['id'], volume_snapshot_name, '')
        t = time.time()
        while time.time() - t < self.configuration.max_time_to_create_volume:
            if volume_snapshot['status'] == const.STATUS_AVAILABLE:
                break
            if volume_snapshot['status'] == const.STATUS_ERROR:
                raise exception.ManilaException(_('Failed to create volume '
                                                  'snapshot'))
            time.sleep(1)
            volume_snapshot = self.volume_api.get_snapshot(
                self.admin_context,
                volume_snapshot['id'])

            self.private_storage.update(
                snapshot['id'], {'volume_snapshot_id': volume_snapshot['id']})
        else:
            raise exception.ManilaException(
                _('Volume snapshot have not been '
                  'created in %ss. Giving up') %
                self.configuration.max_time_to_create_volume)

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
                LOG.debug('Volume snapshot was deleted successfully')
                self.private_storage.delete(snapshot['id'])
                break
            time.sleep(1)
        else:
            raise exception.ManilaException(
                _('Volume snapshot have not been '
                  'deleted in %ss. Giving up') %
                self.configuration.max_time_to_create_volume)

    @ensure_server
    def ensure_share(self, context, share, share_server=None):
        """Ensure that storage are mounted and exported."""
        helper = self._get_helper(share)
        volume = self._get_volume(context, share['id'])

        # NOTE(vponomaryov): volume can be None for managed shares
        if volume:
            volume = self._attach_volume(
                context,
                share,
                share_server['backend_details']['instance_id'],
                volume)
            self._mount_device(share, share_server['backend_details'], volume)
            helper.create_export(
                share_server['backend_details'], share['name'], recreate=True)

    @ensure_server
    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""

        # NOTE(vponomaryov): use direct verification for case some additional
        # level is added.
        access_level = access['access_level']
        if access_level not in (const.ACCESS_LEVEL_RW, const.ACCESS_LEVEL_RO):
            raise exception.InvalidShareAccessLevel(level=access_level)
        self._get_helper(share).allow_access(
            share_server['backend_details'], share['name'],
            access['access_type'], access['access_level'], access['access_to'])

    @ensure_server
    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        self._get_helper(share).deny_access(
            share_server['backend_details'], share['name'], access)

    def _get_helper(self, share):
        helper = self._helpers.get(share['share_proto'])
        if helper:
            return helper
        else:
            raise exception.InvalidShare(
                reason="Wrong, unsupported or disabled protocol")

    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        # NOTE(vponomaryov): Generic driver does not need allocations, because
        # Nova will handle it. It is valid for all multitenant drivers, that
        # use service instance provided by Nova.
        return 0

    def _setup_server(self, network_info, metadata=None):
        msg = "Creating share server '%s'."
        LOG.debug(msg % network_info['server_id'])
        server = self.service_instance_manager.set_up_service_instance(
            self.admin_context, network_info)
        for helper in self._helpers.values():
            helper.init_helper(server)
        return server

    def _teardown_server(self, server_details, security_services=None):
        instance_id = server_details.get("instance_id")
        LOG.debug("Removing share infrastructure for service instance '%s'.",
                  instance_id)
        self.service_instance_manager.delete_service_instance(
            self.admin_context, server_details)

    def manage_existing(self, share, driver_options):
        """Manage existing share to manila.

        Generic driver accepts only one driver_option 'volume_id'.
        If an administrator provides this option, then appropriate Cinder
        volume will be managed by Manila as well.

        :param share: share data
        :param driver_options: Empty dict or dict with 'volume_id' option.
        :return: dict with share size, example: {'size': 1}
        """
        helper = self._get_helper(share)
        share_server = self.service_instance_manager.get_common_server()
        server_details = share_server['backend_details']

        old_export_location = share['export_locations'][0]['path']
        mount_path = helper.get_share_path_by_export_location(
            share_server['backend_details'], old_export_location)
        LOG.debug("Manage: mount path = %s", mount_path)

        mounted = self._is_device_mounted(mount_path, server_details)
        LOG.debug("Manage: is share mounted = %s", mounted)

        if not mounted:
            msg = _("Provided share %s is not mounted.") % share['id']
            raise exception.ManageInvalidShare(reason=msg)

        def get_volume():
            if 'volume_id' in driver_options:
                try:
                    return self.volume_api.get(
                        self.admin_context, driver_options['volume_id'])
                except exception.VolumeNotFound as e:
                    raise exception.ManageInvalidShare(reason=six.text_type(e))

            # NOTE(vponomaryov): Manila can only combine volume name by itself,
            # nowhere to get volume ID from. Return None since Cinder volume
            # names are not unique or fixed, hence, they can not be used for
            # sure.
            return None

        share_volume = get_volume()

        if share_volume:
            instance_volumes = self.compute_api.instance_volumes_list(
                self.admin_context, server_details['instance_id'])

            attached_volumes = [vol.id for vol in instance_volumes]
            LOG.debug('Manage: attached volumes = %s',
                      six.text_type(attached_volumes))

            if share_volume['id'] not in attached_volumes:
                msg = _("Provided volume %s is not attached "
                        "to service instance.") % share_volume['id']
                raise exception.ManageInvalidShare(reason=msg)

            linked_volume_name = self._get_volume_name(share['id'])
            if share_volume['name'] != linked_volume_name:
                LOG.debug('Manage: volume_id = %s' % share_volume['id'])
                self.volume_api.update(self.admin_context, share_volume['id'],
                                       {'name': linked_volume_name})

            self.private_storage.update(
                share['id'], {'volume_id': share_volume['id']})

            share_size = share_volume['size']
        else:
            share_size = self._get_mounted_share_size(
                mount_path, share_server['backend_details'])

        export_locations = helper.get_exports_for_share(
            server_details, old_export_location)
        return {'size': share_size, 'export_locations': export_locations}

    def _get_mount_stats_by_index(self, mount_path, server_details, index,
                                  block_size='G'):
        """Get mount stats using df shell command.

        :param mount_path: Share path on share server
        :param server_details: Share server connection details
        :param index: Data index in df command output:
            BLOCK_DEVICE_SIZE_INDEX - Size of block device
            USED_SPACE_INDEX - Used space
        :param block_size: size of block (example: G, M, Mib, etc)
        :returns: value of provided index
        """
        share_size_cmd = ['df', '-PB%s' % block_size, mount_path]
        output, __ = self._ssh_exec(server_details, share_size_cmd)
        lines = output.split('\n')
        return int(lines[1].split()[index][:-1])

    def _get_mounted_share_size(self, mount_path, server_details):
        try:
            size = self._get_mount_stats_by_index(
                mount_path, server_details, BLOCK_DEVICE_SIZE_INDEX)
        except Exception as e:
            msg = _("Cannot calculate size of share %(path)s : %(error)s") % {
                'path': mount_path,
                'error': six.text_type(e)
            }
            raise exception.ManageInvalidShare(reason=msg)

        return size

    def _get_consumed_space(self, mount_path, server_details):
        try:
            size = self._get_mount_stats_by_index(
                mount_path, server_details, USED_SPACE_INDEX, block_size='M')
            size /= float(units.Ki)
        except Exception as e:
            msg = _("Cannot calculate consumed space on share "
                    "%(path)s : %(error)s") % {
                'path': mount_path,
                'error': six.text_type(e)
            }
            raise exception.InvalidShare(reason=msg)

        return size

    @ensure_server
    def create_consistency_group(self, context, cg_dict, share_server=None):
        """Creates a consistency group.

        Since we are faking the CG object, apart from verifying if the
        share_server is valid, we do nothing else here.
        """

        LOG.debug('Created a Consistency Group with ID: %s.', cg_dict['id'])

        msg = _LW('The Generic driver has no means to guarantee consistency '
                  'group snapshots are actually consistent. This '
                  'implementation is for reference and testing purposes only.')
        LOG.warning(msg)

    def delete_consistency_group(self, context, cg_dict, share_server=None):
        """Deletes a consistency group.

        Since we are faking the CG object we do nothing here.
        """

        LOG.debug('Deleted the consistency group with ID %s.', cg_dict['id'])

    def _cleanup_cg_share_snapshot(self, context, share_snapshot,
                                   share_server):
        """Deletes the snapshot of a share belonging to a consistency group."""

        try:
            self.delete_snapshot(context, share_snapshot, share_server)
        except exception.ManilaException:
            msg = _LE('Could not delete CG Snapshot %(snap)s '
                      'for share %(share)s.')
            LOG.error(msg % {
                'snap': share_snapshot['id'],
                'share': share_snapshot['share_id'],
            })
            raise

    @ensure_server
    def create_cgsnapshot(self, context, snap_dict, share_server=None):
        """Creates a consistency group snapshot one or more shares."""

        LOG.debug('Attempting to create a CG snapshot %s.' % snap_dict['id'])

        msg = _LW('The Consistency Group Snapshot being created is '
                  'not expected to be consistent. This implementation is '
                  'for reference and testing purposes only.')
        LOG.warning(msg)

        cg_members = snap_dict.get('cgsnapshot_members', [])
        if not cg_members:
            LOG.warning(_LW('No shares in Consistency Group to Create CG '
                            'snapshot.'))
        else:
            share_snapshots = []
            for member in cg_members:
                share_snapshot = {
                    'share_id': member['share_id'],
                    'id': member['id'],
                }
                try:
                    self.create_snapshot(context, share_snapshot, share_server)
                    share_snapshots.append(share_snapshot)
                except exception.ManilaException as e:
                    msg = _LE('Could not create CG Snapshot. Failed '
                              'to create share snapshot %(snap)s for '
                              'share %(share)s.')
                    LOG.exception(msg % {
                        'snap': share_snapshot['id'],
                        'share': share_snapshot['share_id']
                    })

                    # clean up any share snapshots previously created
                    LOG.debug('Attempting to clean up snapshots due to '
                              'failure...')
                    for share_snapshot in share_snapshots:
                        self._cleanup_cg_share_snapshot(context,
                                                        share_snapshot,
                                                        share_server)
                    raise e

            LOG.debug('Successfully created CG snapshot %s.' % snap_dict['id'])

        return None, None

    @ensure_server
    def delete_cgsnapshot(self, context, snap_dict, share_server=None):
        """Deletes a consistency group snapshot."""

        cg_members = snap_dict.get('cgsnapshot_members', [])

        LOG.debug('Deleting CG snapshot %s.' % snap_dict['id'])

        for member in cg_members:
            share_snapshot = {
                'share_id': member['share_id'],
                'id': member['id'],
            }

            self._cleanup_cg_share_snapshot(context,
                                            share_snapshot,
                                            share_server)

        LOG.debug('Deleted CG snapshot %s.' % snap_dict['id'])

        return None, None

    @ensure_server
    def create_consistency_group_from_cgsnapshot(self, context, cg_dict,
                                                 cgsnapshot_dict,
                                                 share_server=None):
        """Creates a consistency group from an existing CG snapshot."""

        # Ensure that the consistency group snapshot has members
        if not cgsnapshot_dict['cgsnapshot_members']:
            return None, None

        clone_list = self._collate_cg_snapshot_info(cg_dict, cgsnapshot_dict)
        share_update_list = list()

        LOG.debug('Creating consistency group from CG snapshot %s.',
                  cgsnapshot_dict['id'])

        for clone in clone_list:

            kwargs = {}
            if self.driver_handles_share_servers:
                kwargs['share_server'] = share_server
            export_location = (
                self.create_share_from_snapshot(
                    context,
                    clone['share'],
                    clone['snapshot'],
                    **kwargs))

            share_update_list.append({
                'id': clone['share']['id'],
                'export_locations': export_location,
            })

        return None, share_update_list

    def _collate_cg_snapshot_info(self, cg_dict, cgsnapshot_dict):
        """Collate the data for a clone of the CG snapshot.

        Given two data structures, a CG snapshot (cgsnapshot_dict) and a new
        CG to be cloned from the snapshot (cg_dict), match up both
        structures into a list of dicts (share & snapshot) suitable for use
        by existing method that clones individual share snapshots.
        """

        clone_list = list()

        for share in cg_dict['shares']:

            clone_info = {'share': share}

            for cgsnapshot_member in cgsnapshot_dict['cgsnapshot_members']:
                if (share['source_cgsnapshot_member_id'] ==
                        cgsnapshot_member['id']):
                    clone_info['snapshot'] = {
                        'id': cgsnapshot_member['id'],
                    }
                    break

            if len(clone_info) != 2:
                msg = _("Invalid data supplied for creating consistency "
                        "group from CG snapshot %s.") % cgsnapshot_dict['id']
                raise exception.InvalidConsistencyGroup(reason=msg)

            clone_list.append(clone_info)

        return clone_list
