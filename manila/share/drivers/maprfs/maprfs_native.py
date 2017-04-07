# Copyright (c) 2016, MapR Technologies
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
Share driver for MapR-FS distributed file system.
"""
import math
import os

from oslo_config import cfg
from oslo_log import log
from oslo_utils import strutils
from oslo_utils import units

from manila import context
from manila import exception
from manila.i18n import _
from manila.share import api
from manila.share import driver

from manila.share.drivers.maprfs import driver_util as mapru

LOG = log.getLogger(__name__)

maprfs_native_share_opts = [
    cfg.ListOpt('maprfs_clinode_ip',
                help='The list of IPs or hostnames of nodes where mapr-core '
                     'is installed.'),
    cfg.PortOpt('maprfs_ssh_port',
                default=22,
                help='CLDB node SSH port.'),
    cfg.StrOpt('maprfs_ssh_name',
               default="mapr",
               help='Cluster admin user ssh login name.'),
    cfg.StrOpt('maprfs_ssh_pw',
               help='Cluster node SSH login password, '
                    'This parameter is not necessary, if '
                    '\'maprfs_ssh_private_key\' is configured.'),
    cfg.StrOpt('maprfs_ssh_private_key',
               help='Path to SSH private '
                    'key for login.'),
    cfg.StrOpt('maprfs_base_volume_dir',
               default='/',
               help='Path in MapRFS where share volumes must be created.'),
    cfg.ListOpt('maprfs_zookeeper_ip',
                help='The list of IPs or hostnames of ZooKeeper nodes.'),
    cfg.ListOpt('maprfs_cldb_ip',
                help='The list of IPs or hostnames of CLDB nodes.'),
    cfg.BoolOpt('maprfs_rename_managed_volume',
                default=True,
                help='Specify whether existing volume should be renamed when'
                     ' start managing.'),
]

CONF = cfg.CONF
CONF.register_opts(maprfs_native_share_opts)


class MapRFSNativeShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """MapR-FS Share Driver.

    Executes commands relating to shares.
    driver_handles_share_servers must be False because this driver does not
    support creating or managing virtual storage servers (share servers)
    API version history:

        1.0 - Initial Version
    """

    def __init__(self, *args, **kwargs):
        super(MapRFSNativeShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(maprfs_native_share_opts)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'MapR-FS-Native'
        self._base_volume_dir = self.configuration.safe_get(
            'maprfs_base_volume_dir') or '/'
        self._maprfs_util = None
        self._maprfs_base_path = "maprfs://"
        self.cldb_ip = self.configuration.maprfs_cldb_ip or []
        self.zookeeper_ip = self.configuration.maprfs_zookeeper_ip or []
        self.rename_volume = self.configuration.maprfs_rename_managed_volume
        self.api = api.API()

    def do_setup(self, context):
        """Do initialization while the share driver starts."""
        super(MapRFSNativeShareDriver, self).do_setup(context)
        self._maprfs_util = mapru.get_version_handler(self.configuration)

    def _share_dir(self, share_name):
        return os.path.join(self._base_volume_dir, share_name)

    def _volume_name(self, share_name):
        return share_name

    def _get_share_path(self, share):
        return share['export_location']

    def _get_snapshot_path(self, snapshot):
        share_dir = snapshot['share_instance']['export_location'].split(
            ' ')[0][len(self._maprfs_base_path):]
        return os.path.join(share_dir, '.snapshot',
                            snapshot['provider_location'] or snapshot['name'])

    def _get_volume_name(self, context, share):
        metadata = self.api.get_share_metadata(context,
                                               {'id': share['share_id']})
        return metadata.get('_name', self._volume_name(share['name']))

    def _get_share_export_locations(self, share, path=None):
        """Return share path on storage provider."""
        cluster_name = self._maprfs_util.get_cluster_name()
        path = '%(path)s -C %(cldb)s -Z %(zookeeper)s -N %(name)s' % {
            'path': self._maprfs_base_path + (
                path or self._share_dir(share['name'])),
            'cldb': ' '.join(self.cldb_ip),
            'zookeeper': ' '.join(self.zookeeper_ip),
            'name': cluster_name
        }
        export_list = [{
            "path": path,
            "is_admin_only": False,
            "metadata": {
                "cldb": ','.join(self.cldb_ip),
                "zookeeper": ','.join(self.zookeeper_ip),
                "cluster-name": cluster_name,
            },
        }]

        return export_list

    def _create_share(self, share, metadata, context):
        """Creates a share."""
        if share['share_proto'].lower() != 'maprfs':
            msg = _('Only MapRFS protocol supported!')
            LOG.error(msg)
            raise exception.MapRFSException(msg=msg)
        options = {k[1:]: v for k, v in metadata.items() if k[0] == '_'}
        share_dir = options.pop('path', self._share_dir(share['name']))
        volume_name = options.pop('name', self._volume_name(share['name']))
        try:
            self._maprfs_util.create_volume(volume_name, share_dir,
                                            share['size'],
                                            **options)
            # posix permissions should be 777, ACEs are used as a restriction
            self._maprfs_util.maprfs_chmod(share_dir, '777')
        except exception.ProcessExecutionError:
            self.api.update_share_metadata(context,
                                           {'id': share['share_id']},
                                           {'_name': 'error'})
            msg = (_('Failed to create volume in MapR-FS for the '
                     'share %(share_name)s.') % {'share_name': share['name']})
            LOG.exception(msg)
            raise exception.MapRFSException(msg=msg)

    def _set_share_size(self, share, size):
        volume_name = self._get_volume_name(context.get_admin_context(), share)
        try:
            if share['size'] > size:
                info = self._maprfs_util.get_volume_info(volume_name)
                used = info['totalused']
                if int(used) >= int(size) * units.Ki:
                    raise exception.ShareShrinkingPossibleDataLoss(
                        share_id=share['id'])
            self._maprfs_util.set_volume_size(volume_name, size)
        except exception.ProcessExecutionError:
            msg = (_('Failed to set space quota for the share %(share_name)s.')
                   % {'share_name': share['name']})
            LOG.exception(msg)
            raise exception.MapRFSException(msg=msg)

    def get_network_allocations_number(self):
        return 0

    def create_share(self, context, share, share_server=None):
        """Create a MapRFS volume which acts as a share."""
        metadata = self.api.get_share_metadata(context,
                                               {'id': share['share_id']})
        self._create_share(share, metadata, context)
        return self._get_share_export_locations(share,
                                                path=metadata.get('_path'))

    def ensure_share(self, context, share, share_server=None):
        """Updates export location if it is changes."""
        volume_name = self._get_volume_name(context, share)
        if self._maprfs_util.volume_exists(volume_name):
            info = self._maprfs_util.get_volume_info(volume_name)
            path = info['mountdir']
            old_location = share['export_locations'][0]
            new_location = self._get_share_export_locations(
                share, path=path)
            if new_location[0]['path'] != old_location['path']:
                return new_location
        else:
            raise exception.ShareResourceNotFound(share_id=share['share_id'])

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Creates a share from snapshot."""
        metadata = self.api.get_share_metadata(context,
                                               {'id': share['share_id']})
        sn_share_tenant = self.api.get_share_metadata(context, {
            'id': snapshot['share_instance']['share_id']}).get('_tenantuser')
        if sn_share_tenant and sn_share_tenant != metadata.get('_tenantuser'):
            msg = (
                _('Cannot create share from snapshot %(snapshot_name)s '
                  'with name %(share_name)s. Error: Tenant user should not '
                  'differ from tenant of the source snapshot.') %
                {'snapshot_name': snapshot['name'],
                 'share_name': share['name']})
            LOG.error(msg)
            raise exception.MapRFSException(msg=msg)
        share_dir = metadata.get('_path', self._share_dir(share['name']))
        snapshot_path = self._get_snapshot_path(snapshot)
        self._create_share(share, metadata, context)

        try:
            if self._maprfs_util.dir_not_empty(snapshot_path):
                self._maprfs_util.maprfs_cp(snapshot_path + '/*', share_dir)
        except exception.ProcessExecutionError:
            msg = (
                _('Failed to create share from snapshot %(snapshot_name)s '
                  'with name %(share_name)s.') % {
                    'snapshot_name': snapshot['name'],
                    'share_name': share['name']})
            LOG.exception(msg)
            raise exception.MapRFSException(msg=msg)
        return self._get_share_export_locations(share,
                                                path=metadata.get('_path'))

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot."""
        volume_name = self._get_volume_name(context, snapshot['share'])
        snapshot_name = snapshot['name']
        try:
            self._maprfs_util.create_snapshot(snapshot_name, volume_name)
            return {'provider_location': snapshot_name}
        except exception.ProcessExecutionError:
            msg = (
                _('Failed to create snapshot %(snapshot_name)s for the share '
                  '%(share_name)s.') % {'snapshot_name': snapshot_name,
                                        'share_name': snapshot['share_name']})
            LOG.exception(msg)
            raise exception.MapRFSException(msg=msg)

    def delete_share(self, context, share, share_server=None):
        """Deletes share storage."""
        volume_name = self._get_volume_name(context, share)
        if volume_name == "error":
            LOG.info("Skipping deleting share with name %s, as it does not"
                     " exist on the backend", share['name'])
            return
        try:
            self._maprfs_util.delete_volume(volume_name)
        except exception.ProcessExecutionError:
            msg = (_('Failed to delete share %(share_name)s.') %
                   {'share_name': share['name']})
            LOG.exception(msg)
            raise exception.MapRFSException(msg=msg)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot."""
        snapshot_name = snapshot['provider_location'] or snapshot['name']
        volume_name = self._get_volume_name(context, snapshot['share'])
        try:
            self._maprfs_util.delete_snapshot(snapshot_name, volume_name)
        except exception.ProcessExecutionError:
            msg = (_('Failed to delete snapshot %(snapshot_name)s.') %
                   {'snapshot_name': snapshot['name']})
            LOG.exception(msg)
            raise exception.MapRFSException(msg=msg)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules for given share."""
        for access in access_rules:
            if access['access_type'].lower() != 'user':
                msg = _("Only 'user' access type allowed!")
                LOG.error(msg)
                raise exception.InvalidShareAccess(reason=msg)
        volume_name = self._get_volume_name(context, share)
        try:
            # 'update_access' is called before share is removed, so this
            #  method shouldn`t raise exception if share does
            #  not exist actually
            if not self._maprfs_util.volume_exists(volume_name):
                LOG.warning('Can not get share %s.', share['name'])
                return
            # check update
            if add_rules or delete_rules:
                self._maprfs_util.remove_volume_ace_rules(volume_name,
                                                          delete_rules)
                self._maprfs_util.add_volume_ace_rules(volume_name, add_rules)
            else:
                self._maprfs_util.set_volume_ace(volume_name, access_rules)
        except exception.ProcessExecutionError:
            msg = (_('Failed to update access for share %(name)s.') %
                   {'name': share['name']})
            LOG.exception(msg)
            raise exception.MapRFSException(msg=msg)

    def extend_share(self, share, new_size, share_server=None):
        """Extend share storage."""
        self._set_share_size(share, new_size)

    def shrink_share(self, share, new_size, share_server=None):
        """Shrink share storage."""
        self._set_share_size(share, new_size)

    def _check_maprfs_state(self):
        try:
            return self._maprfs_util.check_state()
        except exception.ProcessExecutionError:
            msg = _('Failed to check MapRFS state.')
            LOG.exception(msg)
            raise exception.MapRFSException(msg=msg)

    def check_for_setup_error(self):
        """Return an error if the prerequisites are not met."""
        if not self.configuration.maprfs_clinode_ip:
            msg = _(
                'MapR cluster has not been specified in the configuration. '
                'Add the ip or list of ip of nodes with mapr-core installed '
                'in the "maprfs_clinode_ip" configuration parameter.')
            LOG.error(msg)
            raise exception.MapRFSException(msg=msg)

        if not self.configuration.maprfs_cldb_ip:
            LOG.warning('CLDB nodes are not specified!')

        if not self.configuration.maprfs_zookeeper_ip:
            LOG.warning('Zookeeper nodes are not specified!')

        if not self._check_maprfs_state():
            msg = _('MapR-FS is not in healthy state.')
            LOG.error(msg)
            raise exception.MapRFSException(msg=msg)
        try:
            self._maprfs_util.maprfs_ls(
                os.path.join(self._base_volume_dir, ''))
        except exception.ProcessExecutionError:
            msg = _('Invalid "maprfs_base_volume_name". No such directory.')
            LOG.exception(msg)
            raise exception.MapRFSException(msg=msg)

    def manage_existing(self, share, driver_options):
        try:
            # retrieve share path from export location, maprfs:// prefix and
            # metadata (-C -Z -N) should be casted away
            share_path = share['export_location'].split(
            )[0][len(self._maprfs_base_path):]
            info = self._maprfs_util.get_volume_info_by_path(
                share_path, check_if_exists=True)
            if not info:
                msg = _("Share %s not found") % share[
                    'export_location']
                LOG.error(msg)
                raise exception.ManageInvalidShare(reason=msg)
            size = math.ceil(float(info['quota']) / units.Ki)
            used = math.ceil(float(info['totalused']) / units.Ki)
            volume_name = info['volumename']
            should_rename = self.rename_volume
            rename_option = driver_options.get('rename')
            if rename_option:
                should_rename = strutils.bool_from_string(rename_option)
            if should_rename:
                self._maprfs_util.rename_volume(volume_name, share['name'])
            else:
                self.api.update_share_metadata(context.get_admin_context(),
                                               {'id': share['share_id']},
                                               {'_name': volume_name})
            location = self._get_share_export_locations(share, path=share_path)
            if size == 0:
                size = used
                msg = (
                    'Share %s has no size quota. Total used value will be'
                    ' used as share size')
                LOG.warning(msg, share['name'])
            return {'size': size, 'export_locations': location}
        except (ValueError, KeyError, exception.ProcessExecutionError):
            msg = _('Failed to manage share.')
            LOG.exception(msg)
            raise exception.MapRFSException(msg=msg)

    def manage_existing_snapshot(self, snapshot, driver_options):
        volume_name = self._get_volume_name(context.get_admin_context(),
                                            snapshot['share'])
        snapshot_path = self._get_snapshot_path(snapshot)
        try:
            snapshot_list = self._maprfs_util.get_snapshot_list(
                volume_name=volume_name)
            snapshot_name = snapshot['provider_location']
            if snapshot_name not in snapshot_list:
                msg = _("Snapshot %s not found") % snapshot_name
                LOG.error(msg)
                raise exception.ManageInvalidShareSnapshot(reason=msg)
            size = math.ceil(float(self._maprfs_util.maprfs_du(
                snapshot_path)) / units.Gi)
            return {'size': size}
        except exception.ProcessExecutionError:
            msg = _("Manage existing share snapshot failed.")
            LOG.exception(msg)
            raise exception.MapRFSException(msg=msg)

    def _update_share_stats(self):
        """Retrieves stats info of share directories group."""
        try:
            total, free = self._maprfs_util.fs_capacity()
        except exception.ProcessExecutionError:
            msg = _('Failed to check MapRFS capacity info.')
            LOG.exception(msg)
            raise exception.MapRFSException(msg=msg)
        total_capacity_gb = int(math.ceil(float(total) / units.Gi))
        free_capacity_gb = int(math.floor(float(free) / units.Gi))
        data = {
            'share_backend_name': self.backend_name,
            'storage_protocol': 'MAPRFS',
            'driver_handles_share_servers': self.driver_handles_share_servers,
            'vendor_name': 'MapR Technologies',
            'driver_version': '1.0',
            'total_capacity_gb': total_capacity_gb,
            'free_capacity_gb': free_capacity_gb,
            'snapshot_support': True,
            'create_share_from_snapshot_support': True,
        }

        super(MapRFSNativeShareDriver, self)._update_share_stats(data)
