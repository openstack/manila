# Copyright 2016 Nexenta Systems, Inc.
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

from oslo_log import log
from oslo_utils import excutils

from manila.common import constants as common
from manila import exception
from manila.i18n import _
from manila.share.drivers.nexenta.ns4 import jsonrpc
from manila.share.drivers.nexenta import utils

LOG = log.getLogger(__name__)
NOT_EXIST = 'does not exist'
DEP_CLONES = 'has dependent clones'


class NFSHelper(object):

    def __init__(self, configuration):
        self.configuration = configuration
        self.nfs_mount_point_base = (
            self.configuration.nexenta_mount_point_base)
        self.dataset_compression = (
            self.configuration.nexenta_dataset_compression)
        self.dataset_dedupe = self.configuration.nexenta_dataset_dedupe
        self.nms = None
        self.nms_protocol = self.configuration.nexenta_rest_protocol
        self.nms_host = self.configuration.nexenta_host
        self.volume = self.configuration.nexenta_volume
        self.share = self.configuration.nexenta_nfs_share
        self.nms_port = self.configuration.nexenta_rest_port
        self.nms_user = self.configuration.nexenta_user
        self.nfs = self.configuration.nexenta_nfs
        self.nms_password = self.configuration.nexenta_password
        self.storage_protocol = 'NFS'

    def do_setup(self):
        if self.nms_protocol == 'auto':
            protocol, auto = 'http', True
        else:
            protocol, auto = self.nms_protocol, False
        path = '/rest/nms/'
        self.nms = jsonrpc.NexentaJSONProxy(
            protocol, self.nms_host, self.nms_port, path, self.nms_user,
            self.nms_password, auto=auto)

    def check_for_setup_error(self):
        if not self.nms.volume.object_exists(self.volume):
            raise exception.NexentaException(reason=_(
                "Volume %s does not exist in NexentaStor appliance.") %
                self.volume)
        folder = '%s/%s' % (self.volume, self.share)
        create_folder_props = {
            'recordsize': '4K',
            'quota': 'none',
            'compression': self.dataset_compression,
        }
        if not self.nms.folder.object_exists(folder):
            self.nms.folder.create_with_props(
                self.volume, self.share, create_folder_props)

    def create_filesystem(self, share):
        """Create file system."""
        create_folder_props = {
            'recordsize': '4K',
            'quota': '%sG' % share['size'],
            'compression': self.dataset_compression,
        }
        if not self.configuration.nexenta_thin_provisioning:
            create_folder_props['reservation'] = '%sG' % share['size']

        parent_path = '%s/%s' % (self.volume, self.share)
        self.nms.folder.create_with_props(
            parent_path, share['name'], create_folder_props)

        path = self._get_share_path(share['name'])
        return [self._get_location_path(path, share['share_proto'])]

    def set_quota(self, share_name, new_size):
        if self.configuration.nexenta_thin_provisioning:
            quota = '%sG' % new_size
            self.nms.folder.set_child_prop(
                self._get_share_path(share_name), 'quota', quota)

    def _get_location_path(self, path, protocol):
        location = None
        if protocol == 'NFS':
            location = {'path': '%s:/volumes/%s' % (self.nms_host, path)}
        else:
            raise exception.InvalidShare(
                reason=(_('Only NFS protocol is currently supported.')))
        return location

    def delete_share(self, share_name):
        """Delete share."""
        folder = self._get_share_path(share_name)
        try:
            self.nms.folder.destroy(folder.strip(), '-r')
        except exception.NexentaException as e:
            with excutils.save_and_reraise_exception() as exc:
                if NOT_EXIST in e.args[0]:
                    LOG.info('Folder %s does not exist, it was '
                             'already deleted.', folder)
                    exc.reraise = False

    def _get_share_path(self, share_name):
        return '%s/%s/%s' % (self.volume, self.share, share_name)

    def _get_snapshot_name(self, snapshot_name):
        return 'snapshot-%s' % snapshot_name

    def create_snapshot(self, share_name, snapshot_name):
        """Create a snapshot."""
        folder = self._get_share_path(share_name)
        self.nms.folder.create_snapshot(folder, snapshot_name, '-r')
        model_update = {'provider_location': '%s@%s' % (folder, snapshot_name)}
        return model_update

    def delete_snapshot(self, share_name, snapshot_name):
        """Deletes snapshot."""
        try:
            self.nms.snapshot.destroy('%s@%s' % (
                self._get_share_path(share_name), snapshot_name), '')
        except exception.NexentaException as e:
            with excutils.save_and_reraise_exception() as exc:
                if NOT_EXIST in e.args[0]:
                    LOG.info('Snapshot %(folder)s@%(snapshot)s does not '
                             'exist, it was already deleted.',
                             {
                                 'folder': share_name,
                                 'snapshot': snapshot_name,
                             })
                    exc.reraise = False
                elif DEP_CLONES in e.args[0]:
                    LOG.info(
                        'Snapshot %(folder)s@%(snapshot)s has dependent '
                        'clones, it will be deleted later.', {
                            'folder': share_name,
                            'snapshot': snapshot_name
                            })
                    exc.reraise = False

    def create_share_from_snapshot(self, share, snapshot):
        snapshot_name = '%s/%s/%s@%s' % (
            self.volume, self.share, snapshot['share_name'], snapshot['name'])
        self.nms.folder.clone(
            snapshot_name,
            '%s/%s/%s' % (self.volume, self.share, share['name']))
        path = self._get_share_path(share['name'])
        return [self._get_location_path(path, share['share_proto'])]

    def update_access(self, share_name, access_rules):
        """Update access to the share."""
        rw_list = []
        ro_list = []
        for rule in access_rules:
            if rule['access_type'].lower() != 'ip':
                msg = _('Only IP access type is supported.')
                raise exception.InvalidShareAccess(reason=msg)
            else:
                if rule['access_level'] == common.ACCESS_LEVEL_RW:
                    rw_list.append(rule['access_to'])
                else:
                    ro_list.append(rule['access_to'])

        share_opts = {
            'auth_type': 'none',
            'read_write': ':'.join(rw_list),
            'read_only': ':'.join(ro_list),
            'recursive': 'true',
            'anonymous_rw': 'true',
            'anonymous': 'true',
            'extra_options': 'anon=0',
        }
        self.nms.netstorsvc.share_folder(
            'svc:/network/nfs/server:default',
            self._get_share_path(share_name), share_opts)

    def _get_capacity_info(self):
        """Calculate available space on the NFS share."""
        folder_props = self.nms.folder.get_child_props(
            '%s/%s' % (self.volume, self.share), 'used|available')
        free = utils.str2gib_size(folder_props['available'])
        allocated = utils.str2gib_size(folder_props['used'])
        return free + allocated, free, allocated

    def update_share_stats(self):
        """Update driver capabilities.

        No way of tracking provisioned capacity on this appliance,
        not returning any to let the scheduler estimate it.
        """
        total, free, allocated = self._get_capacity_info()
        compression = not self.dataset_compression == 'off'
        dedupe = not self.dataset_dedupe == 'off'
        return {
            'vendor_name': 'Nexenta',
            'storage_protocol': self.storage_protocol,
            'nfs_mount_point_base': self.nfs_mount_point_base,
            'pools': [{
                'pool_name': self.volume,
                'total_capacity_gb': total,
                'free_capacity_gb': free,
                'reserved_percentage':
                    self.configuration.reserved_share_percentage,
                'compression': compression,
                'dedupe': dedupe,
                'max_over_subscription_ratio': (
                    self.configuration.safe_get(
                        'max_over_subscription_ratio')),
                'thin_provisioning':
                    self.configuration.nexenta_thin_provisioning,
            }],
        }
