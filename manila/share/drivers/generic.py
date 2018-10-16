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

    def _ssh_exec(self, server, command, check_exit_code=True):
        LOG.debug("_ssh_exec - server: %s, command: %s, check_exit_code: %s",
                  server, command, check_exit_code)
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

        # (aovchinnikov): ssh_execute does not behave well when passed
        # parameters with spaces.
        wrap = lambda token: "\"" + token + "\""
        command = [wrap(tkn) if tkn.count(' ') else tkn for tkn in command]
        return processutils.ssh_execute(ssh, ' '.join(command),
                                        check_exit_code=check_exit_code)

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
                LOG.warning("Waiting for the common service VM to become "
                            "available. "
                            "Driver is currently uninitialized. "
                            "Share server: %(share_server)s "
                            "Retry interval: %(retry_interval)s",
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

    @ensure_server
    def create_share(self, context, share, share_server=None):
        """Creates share."""
        return self._create_share(
            context, share,
            snapshot=None,
            share_server=share_server,
        )

    def _create_share(self, context, share, snapshot, share_server=None):
        helper = self._get_helper(share)
        server_details = share_server['backend_details']
        volume = self._allocate_container(
            self.admin_context, share, snapshot=snapshot)
        volume = self._attach_volume(
            self.admin_context, share, server_details['instance_id'], volume)
        if not snapshot:
            self._format_device(server_details, volume)

        self._mount_device(share, server_details, volume)
        export_locations = helper.create_exports(
            server_details, share['name'])
        return export_locations

    @utils.retry(exception.ProcessExecutionError, backoff_rate=1)
    def _is_device_file_available(self, server_details, volume):
        """Checks whether the device file is available"""
        command = ['sudo', 'test', '-b', volume['mountpoint']]
        self._ssh_exec(server_details, command)

    def _format_device(self, server_details, volume):
        """Formats device attached to the service vm."""
        self._is_device_file_available(server_details, volume)
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

    def _add_mount_permanently(self, share_id, server_details):
        """Add mount permanently for mounted filesystems."""
        try:
            self._ssh_exec(
                server_details,
                ['grep', share_id, const.MOUNT_FILE_TEMP,
                 '|', 'sudo', 'tee', '-a', const.MOUNT_FILE],
            )
        except exception.ProcessExecutionError as e:
            LOG.error("Failed to add 'Share-%(share_id)s' mount "
                      "permanently on server '%(instance_id)s'.",
                      {"share_id": share_id,
                       "instance_id": server_details['instance_id']})
            raise exception.ShareBackendException(msg=six.text_type(e))
        try:
            # Remount it to avoid postponed point of failure
            self._ssh_exec(server_details, ['sudo', 'mount', '-a'])
        except exception.ProcessExecutionError as e:
            LOG.error("Failed to mount all shares on server '%s'.",
                      server_details['instance_id'])

    def _remove_mount_permanently(self, share_id, server_details):
        """Remove mount permanently from mounted filesystems."""
        try:
            self._ssh_exec(
                server_details,
                ['sudo', 'sed', '-i', '\'/%s/d\'' % share_id,
                 const.MOUNT_FILE],
            )
        except exception.ProcessExecutionError as e:
            LOG.error("Failed to remove 'Share-%(share_id)s' mount "
                      "permanently on server '%(instance_id)s'.",
                      {"share_id": share_id,
                       "instance_id": server_details['instance_id']})
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
            device_path = volume['mountpoint']
            log_data = {
                'dev': device_path,
                'path': mount_path,
                'server': server_details['instance_id'],
            }
            try:
                if not self._is_device_mounted(mount_path, server_details,
                                               volume):
                    LOG.debug("Mounting '%(dev)s' to path '%(path)s' on "
                              "server '%(server)s'.", log_data)
                    mount_cmd = (
                        'sudo', 'mkdir', '-p', mount_path,
                        '&&', 'sudo', 'mount', device_path, mount_path,
                        '&&', 'sudo', 'chmod', '777', mount_path,
                        '&&', 'sudo', 'umount', mount_path,
                        # NOTE(vponomaryov): 'tune2fs' is required to make
                        # filesystem of share created from snapshot have
                        # unique ID, in case of LVM volumes, by default,
                        # it will have the same UUID as source volume one.
                        # 'tune2fs' command can be executed only when device
                        # is not mounted and also, in current case, it takes
                        # effect only after it was mounted. Closes #1645751
                        # NOTE(gouthamr): Executing tune2fs -U only works on
                        # a recently checked filesystem. See debian bug 857336
                        '&&', 'sudo', 'e2fsck', '-y', '-f', device_path,
                        '&&', 'sudo', 'tune2fs', '-U', 'random', device_path,
                        '&&', 'sudo', 'mount', device_path, mount_path,
                    )
                    self._ssh_exec(server_details, mount_cmd)
                    self._add_mount_permanently(share.id, server_details)
                else:
                    LOG.warning("Mount point '%(path)s' already exists on "
                                "server '%(server)s'.", log_data)
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
                unmount_cmd = ['sudo', 'umount', mount_path, '&&', 'sudo',
                               'rmdir', mount_path]
                self._ssh_exec(server_details, unmount_cmd)
                self._remove_mount_permanently(share.id, server_details)
            else:
                LOG.warning("Mount point '%(path)s' does not exist on "
                            "server '%(server)s'.", log_data)
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
                elif volume['status'] not in ('attaching', 'reserved'):
                    raise exception.ManilaException(
                        _('Failed to attach volume %s') % volume['id'])
                time.sleep(1)
            else:
                err_msg = {
                    'volume_id': volume['id'],
                    'max_time': self.configuration.max_time_to_attach
                }
                raise exception.ManilaException(
                    _('Volume %(volume_id)s has not been attached in '
                      '%(max_time)ss. Giving up.') % err_msg)
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
                "Expected only one volume in volume list with name "
                "'%(name)s', but got more than one in a result - "
                "'%(result)s'.", {
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
                "Expected only one volume snapshot in list with name"
                "'%(name)s', but got more than one in a result - "
                "'%(result)s'.", {
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
            try:
                volume = self._get_volume(context, share['id'])
            except exception.VolumeNotFound:
                LOG.warning("Volume not found for share %s. "
                            "Possibly already deleted.", share['id'])
                volume = None
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
                    err_msg = {
                        'volume_id': volume['id'],
                        'max_time': self.configuration.max_time_to_attach
                    }
                    raise exception.ManilaException(
                        _('Volume %(volume_id)s has not been detached in '
                          '%(max_time)ss. Giving up.') % err_msg)
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
            LOG.info("Volume not found. Already deleted?")
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
        )
        super(GenericShareDriver, self)._update_share_stats(data)

    @ensure_server
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        return self._create_share(
            context, share,
            snapshot=snapshot,
            share_server=share_server,
        )

    @ensure_server
    def extend_share(self, share, new_size, share_server=None):
        server_details = share_server['backend_details']

        helper = self._get_helper(share)
        helper.disable_access_for_maintenance(server_details, share['name'])
        self._unmount_device(share, server_details)
        volume = self._get_volume(self.admin_context, share['id'])

        if int(new_size) > volume['size']:
            self._detach_volume(self.admin_context, share, server_details)
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
            helper.remove_exports(
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
        model_update = {}
        volume = self._get_volume(
            self.admin_context, snapshot['share_instance_id'])
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

            # NOTE(xyang): We should look at whether we still need to save
            # volume_snapshot_id in private_storage later, now that is saved
            # in provider_location.
            self.private_storage.update(
                snapshot['id'], {'volume_snapshot_id': volume_snapshot['id']})
            # NOTE(xyang): Need to update provider_location in the db so
            # that it can be used in manage/unmanage snapshot tempest tests.
            model_update['provider_location'] = volume_snapshot['id']
        else:
            raise exception.ManilaException(
                _('Volume snapshot have not been '
                  'created in %ss. Giving up') %
                self.configuration.max_time_to_create_volume)

        return model_update

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
            helper.create_exports(
                share_server['backend_details'], share['name'], recreate=True)

    @ensure_server
    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
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

        :param context: Current context
        :param share: Share model with share data.
        :param access_rules: All access rules for given share
        :param add_rules: Empty List or List of access rules which should be
               added. access_rules already contains these rules.
        :param delete_rules: Empty List or List of access rules which should be
               removed. access_rules doesn't contain these rules.
        :param share_server: None or Share server model
        """
        self._get_helper(share).update_access(share_server['backend_details'],
                                              share['name'], access_rules,
                                              add_rules=add_rules,
                                              delete_rules=delete_rules)

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
        LOG.debug(msg, network_info['server_id'])
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
                LOG.debug('Manage: volume_id = %s', share_volume['id'])
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

    def manage_existing_snapshot(self, snapshot, driver_options):
        """Manage existing share snapshot with manila.

        :param snapshot: Snapshot data
        :param driver_options: Not used by the Generic driver currently
        :return: dict with share snapshot size, example: {'size': 1}
        """
        model_update = {}
        volume_snapshot = None
        snapshot_size = snapshot.get('share_size', 0)
        provider_location = snapshot.get('provider_location')
        try:
            volume_snapshot = self.volume_api.get_snapshot(
                self.admin_context,
                provider_location)
        except exception.VolumeSnapshotNotFound as e:
            raise exception.ManageInvalidShareSnapshot(
                reason=six.text_type(e))

        if volume_snapshot:
            snapshot_size = volume_snapshot['size']
            # NOTE(xyang): volume_snapshot_id is saved in private_storage
            # in create_snapshot, so saving it here too for consistency.
            # We should look at whether we still need to save it in
            # private_storage later.
            self.private_storage.update(
                snapshot['id'], {'volume_snapshot_id': volume_snapshot['id']})
            # NOTE(xyang): provider_location is used to map a Manila snapshot
            # to its name on the storage backend and prevent managing of the
            # same snapshot twice.
            model_update['provider_location'] = volume_snapshot['id']

        model_update['size'] = snapshot_size
        return model_update

    def unmanage_snapshot(self, snapshot):
        """Unmanage share snapshot with manila."""

        self.private_storage.delete(snapshot['id'])

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
