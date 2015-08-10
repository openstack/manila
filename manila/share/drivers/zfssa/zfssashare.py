# Copyright (c) 2014, Oracle and/or its affiliates. All rights reserved.
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
ZFS Storage Appliance Manila Share Driver
"""

import base64

from oslo_config import cfg
from oslo_log import log
from oslo_utils import units
import six

from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.share import driver
from manila.share.drivers.zfssa import zfssarest


ZFSSA_OPTS = [
    cfg.StrOpt('zfssa_host',
               help='ZFSSA management IP address.'),
    cfg.StrOpt('zfssa_data_ip',
               help='IP address for data.'),
    cfg.StrOpt('zfssa_auth_user',
               help='ZFSSA management authorized username.'),
    cfg.StrOpt('zfssa_auth_password',
               help='ZFSSA management authorized userpassword.'),
    cfg.StrOpt('zfssa_pool',
               help='ZFSSA storage pool name.'),
    cfg.StrOpt('zfssa_project',
               help='ZFSSA project name.'),
    cfg.StrOpt('zfssa_nas_checksum', default='fletcher4',
               help='Controls checksum used for data blocks.'),
    cfg.StrOpt('zfssa_nas_compression', default='off',
               help='Data compression-off, lzjb, gzip-2, gzip, gzip-9.'),
    cfg.StrOpt('zfssa_nas_logbias', default='latency',
               help='Controls behavior when servicing synchronous writes.'),
    cfg.StrOpt('zfssa_nas_mountpoint', default='',
               help='Location of project in ZFS/SA.'),
    cfg.StrOpt('zfssa_nas_quota_snap', default='true',
               help='Controls whether a share quota includes snapshot.'),
    cfg.StrOpt('zfssa_nas_rstchown', default='true',
               help='Controls whether file ownership can be changed.'),
    cfg.StrOpt('zfssa_nas_vscan', default='false',
               help='Controls whether the share is scanned for viruses.'),
    cfg.StrOpt('zfssa_rest_timeout',
               help='REST connection timeout (in seconds).')
]

cfg.CONF.register_opts(ZFSSA_OPTS)

LOG = log.getLogger(__name__)


def factory_zfssa():
    return zfssarest.ZFSSAApi()


class ZFSSAShareDriver(driver.ShareDriver):
    """ZFSSA share driver: Supports NFS and CIFS protocols.

    Uses ZFSSA RESTful API to create shares and snapshots on backend.
    API version history:

        1.0 - Initial version.
    """

    VERSION = '1.0.0'
    PROTOCOL = 'NFS_CIFS'

    def __init__(self, *args, **kwargs):
        super(ZFSSAShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(ZFSSA_OPTS)
        self.zfssa = None
        self._stats = None
        self.mountpoint = '/export/'
        lcfg = self.configuration

        required = [
            'zfssa_host',
            'zfssa_data_ip',
            'zfssa_auth_user',
            'zfssa_auth_password',
            'zfssa_pool',
            'zfssa_project'
        ]

        for prop in required:
            if not getattr(lcfg, prop, None):
                exception_msg = _('%s is required in manila.conf') % prop
                LOG.error(exception_msg)
                raise exception.InvalidParameterValue(exception_msg)

        self.default_args = {
            'compression': lcfg.zfssa_nas_compression,
            'logbias': lcfg.zfssa_nas_logbias,
            'checksum': lcfg.zfssa_nas_checksum,
            'vscan': lcfg.zfssa_nas_vscan,
            'rstchown': lcfg.zfssa_nas_rstchown,
        }
        self.share_args = {
            'sharedav': 'off',
            'shareftp': 'off',
            'sharesftp': 'off',
            'sharetftp': 'off',
            'root_permissions': '777',
            'sharenfs': 'sec=sys',
            'sharesmb': 'off',
            'quota_snap': self.configuration.zfssa_nas_quota_snap,
            'reservation_snap': self.configuration.zfssa_nas_quota_snap,
        }

    def do_setup(self, context):
        """Login, create project, no sharing option enabled."""
        lcfg = self.configuration
        LOG.debug("Connecting to host: %s.", lcfg.zfssa_host)
        self.zfssa = factory_zfssa()
        self.zfssa.set_host(lcfg.zfssa_host, timeout=lcfg.zfssa_rest_timeout)
        creds = '%s:%s' % (lcfg.zfssa_auth_user, lcfg.zfssa_auth_password)
        auth_str = base64.encodestring(six.b(creds))[:-1]
        self.zfssa.login(auth_str)
        if lcfg.zfssa_nas_mountpoint == '':
            self.mountpoint += lcfg.zfssa_project
        else:
            self.mountpoint += lcfg.zfssa_nas_mountpoint
        arg = {
            'name': lcfg.zfssa_project,
            'sharesmb': 'off',
            'sharenfs': 'off',
            'mountpoint': self.mountpoint,
        }
        arg.update(self.default_args)
        self.zfssa.create_project(lcfg.zfssa_pool, lcfg.zfssa_project, arg)
        self.zfssa.enable_service('nfs')
        self.zfssa.enable_service('smb')

    def check_for_setup_error(self):
        """Check for properly configured pool, project."""
        lcfg = self.configuration
        LOG.debug("Verifying pool %s.", lcfg.zfssa_pool)
        self.zfssa.verify_pool(lcfg.zfssa_pool)
        LOG.debug("Verifying project %s.", lcfg.zfssa_project)
        self.zfssa.verify_project(lcfg.zfssa_pool, lcfg.zfssa_project)

    def _export_location(self, share):
        """Export share's location based on protocol used."""
        lcfg = self.configuration
        arg = {
            'host': lcfg.zfssa_data_ip,
            'mountpoint': self.mountpoint,
            'name': share['id'],
        }
        location = ''
        proto = share['share_proto']
        if proto == 'NFS':
            location = ("%(host)s:%(mountpoint)s/%(name)s" % arg)
        elif proto == 'CIFS':
            location = ("\\\\%(host)s\\%(name)s" % arg)
        else:
            exception_msg = _('Protocol %s is not supported.') % proto
            LOG.error(exception_msg)
            raise exception.InvalidParameterValue(exception_msg)
        LOG.debug("Export location: %s.", location)
        return location

    def create_arg(self, size):
        size = units.Gi * int(size)
        arg = {
            'quota': size,
            'reservation': size,
        }
        arg.update(self.share_args)
        return arg

    def create_share(self, context, share, share_server=None):
        """Create a share and export it based on protocol used.

        The created share inherits properties from its project.
        """
        lcfg = self.configuration
        arg = self.create_arg(share['size'])
        arg.update(self.default_args)
        arg.update({'name': share['id']})

        if share['share_proto'] == 'CIFS':
            arg.update({'sharesmb': 'on'})
        LOG.debug("ZFSSAShareDriver.create_share: id=%(name)s, size=%(quota)s",
                  {'name': arg['name'],
                   'quota': arg['quota']})
        self.zfssa.create_share(lcfg.zfssa_pool, lcfg.zfssa_project, arg)
        return self._export_location(share)

    def delete_share(self, context, share, share_server=None):
        """Delete a share.

        Shares with existing snapshots can't be deleted.
        """
        LOG.debug("ZFSSAShareDriver.delete_share: id=%s", share['id'])
        lcfg = self.configuration
        self.zfssa.delete_share(lcfg.zfssa_pool,
                                lcfg.zfssa_project,
                                share['id'])

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot of the snapshot['share_id']."""
        LOG.debug("ZFSSAShareDriver.create_snapshot: "
                  "id=%(snap)s share=%(share)s",
                  {'snap': snapshot['id'],
                   'share': snapshot['share_id']})
        lcfg = self.configuration
        self.zfssa.create_snapshot(lcfg.zfssa_pool,
                                   lcfg.zfssa_project,
                                   snapshot['share_id'],
                                   snapshot['id'])

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Create a share from a snapshot - clone a snapshot."""
        lcfg = self.configuration
        LOG.debug("ZFSSAShareDriver.create_share_from_snapshot: clone=%s",
                  share['id'])
        LOG.debug("ZFSSAShareDriver.create_share_from_snapshot: snapshot=%s",
                  snapshot['id'])
        arg = self.create_arg(share['size'])
        details = {
            'share': share['id'],
            'project': lcfg.zfssa_project,
        }
        arg.update(details)

        if share['share_proto'] == 'CIFS':
            arg.update({'sharesmb': 'on'})
        self.zfssa.clone_snapshot(lcfg.zfssa_pool,
                                  lcfg.zfssa_project,
                                  snapshot,
                                  share,
                                  arg)
        return self._export_location(share)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot.

        Snapshots with existing clones cannot be deleted.
        """
        LOG.debug("ZFSSAShareDriver.delete_snapshot: id=%s", snapshot['id'])
        lcfg = self.configuration
        has_clones = self.zfssa.has_clones(lcfg.zfssa_pool,
                                           lcfg.zfssa_project,
                                           snapshot['share_id'],
                                           snapshot['id'])
        if has_clones:
            LOG.error(_LE("snapshot %s: has clones"), snapshot['id'])
            raise exception.ShareSnapshotIsBusy(snapshot_name=snapshot['id'])
        self.zfssa.delete_snapshot(lcfg.zfssa_pool,
                                   lcfg.zfssa_project,
                                   snapshot['share_id'],
                                   snapshot['id'])

    def ensure_share(self, context, share, share_server=None):
        lcfg = self.configuration
        details = self.zfssa.get_share(lcfg.zfssa_pool,
                                       lcfg.zfssa_project,
                                       share['id'])
        if not details:
            msg = (_("Share %s doesn't exists.") % share['id'])
            raise exception.ManilaException(msg)

    def allow_access(self, context, share, access, share_server=None):
        """Allows access to an NFS share for the specified IP."""
        LOG.debug("ZFSSAShareDriver.allow_access: share=%s", share['id'])
        lcfg = self.configuration
        if share['share_proto'] == 'NFS':
            self.zfssa.allow_access_nfs(lcfg.zfssa_pool,
                                        lcfg.zfssa_project,
                                        share['id'],
                                        access)

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to an NFS share for the specified IP."""
        LOG.debug("ZFSSAShareDriver.deny_access: share=%s", share['id'])
        lcfg = self.configuration
        if share['share_proto'] == 'NFS':
            self.zfssa.deny_access_nfs(lcfg.zfssa_pool,
                                       lcfg.zfssa_project,
                                       share['id'],
                                       access)
        elif share['share_proto'] == 'CIFS':
            return

    def _update_share_stats(self):
        """Retrieve stats info from a share."""
        backend_name = self.configuration.safe_get('share_backend_name')
        data = dict(
            share_backend_name=backend_name or self.__class__.__name__,
            vendor_name='Oracle',
            driver_version=self.VERSION,
            storage_protocol=self.PROTOCOL)

        lcfg = self.configuration
        (avail, used) = self.zfssa.get_pool_stats(lcfg.zfssa_pool)
        if avail:
            data['free_capacity_gb'] = int(avail) / units.Gi
            if used:
                total = int(avail) + int(used)
                data['total_capacity_gb'] = total / units.Gi
            else:
                data['total_capacity_gb'] = 0
        else:
            data['free_capacity_gb'] = 0
            data['total_capacity_gb'] = 0

        super(ZFSSAShareDriver, self)._update_share_stats(data)

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""
        return 0
