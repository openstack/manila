# Copyright (c) 2014 Red Hat, Inc.
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

""" GlusterFS native protocol (glusterfs) driver for shares.

Manila share is a GlusterFS volume. Unlike the generic driver, this
does not use service VM approach. Instances directly talk with the
GlusterFS backend storage pool. Instance use the 'glusterfs' protocol
to mount the GlusterFS share. Access to the share is allowed via
SSL Certificates. Only the instance which has the SSL trust established
with the GlusterFS backend can mount and hence use the share.

Supports working with multiple glusterfs volumes.
"""

import re

from oslo_log import log

from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LW
from manila.share import driver
from manila.share.drivers.glusterfs import common
from manila.share.drivers.glusterfs import layout
from manila import utils

LOG = log.getLogger(__name__)


ACCESS_TYPE_CERT = 'cert'
AUTH_SSL_ALLOW = 'auth.ssl-allow'
CLIENT_SSL = 'client.ssl'
NFS_EXPORT_VOL = 'nfs.export-volumes'
SERVER_SSL = 'server.ssl'
DYNAMIC_AUTH = 'server.dynamic-auth'


class GlusterfsNativeShareDriver(driver.ExecuteMixin,
                                 layout.GlusterfsShareDriverBase):
    """GlusterFS native protocol (glusterfs) share driver.

    Executes commands relating to Shares.
    Supports working with multiple glusterfs volumes.

    API version history:

        1.0 - Initial version.
        1.1 - Support for working with multiple gluster volumes.
    """

    GLUSTERFS_VERSION_MIN = (3, 6)

    supported_layouts = ('layout_volume.GlusterfsVolumeMappedLayout',)
    supported_protocols = ('GLUSTERFS',)

    def __init__(self, *args, **kwargs):
        super(GlusterfsNativeShareDriver, self).__init__(
            False, *args, **kwargs)
        self._helpers = None
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'GlusterFS-Native'

    def _setup_via_manager(self, share_mgr, share_mgr_parent=None):
        # Enable gluster volumes for SSL access only.

        gluster_mgr = share_mgr['manager']
        gluster_mgr_parent = (share_mgr_parent or {}).get('manager', None)

        ssl_allow_opt = (gluster_mgr_parent if gluster_mgr_parent else
                         gluster_mgr).get_gluster_vol_option(
            AUTH_SSL_ALLOW)
        if not ssl_allow_opt:
            # Not having AUTH_SSL_ALLOW set is a problematic edge case.
            # - In GlusterFS 3.6, it implies that access is allowed to
            #   noone, including intra-service access, which causes
            #   problems internally in GlusterFS
            # - In GlusterFS 3.7, it implies that access control is
            #   disabled, which defeats the purpose of this driver --
            # so to avoid these possiblitiies, we throw an error in this case.
            msg = (_("Option %(option)s is not defined on gluster volume. "
                     "Volume: %(volname)s") %
                   {'volname': gluster_mgr.volume,
                    'option': AUTH_SSL_ALLOW})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        gluster_actions = []
        if gluster_mgr_parent:
            # The clone of the snapshot, a new volume, retains the authorized
            # access list of the snapshotted volume/share, which includes TLS
            # identities of the backend servers, Manila hosts and clients.
            # Retain the identities of the GlusterFS servers and Manila host,
            # and exclude those of the clients in the authorized access list of
            # the new volume. The TLS identities of GlusterFS servers are
            # determined as those that are prefixed by 'glusterfs-server'.
            # And the TLS identity of the Manila host is identified as the
            # one that has 'manila-host' as the prefix.
            # Wrt. GlusterFS' parsing of auth.ssl-allow, please see code from
            # https://github.com/gluster/glusterfs/blob/v3.6.2/
            # xlators/protocol/auth/login/src/login.c#L80
            # until end of gf_auth() function
            old_access_list = re.split('[ ,]', ssl_allow_opt)
            glusterfs_server_CN_pattern = '\Aglusterfs-server'
            manila_host_CN_pattern = '\Amanila-host'
            regex = re.compile(
                '%(pattern1)s|%(pattern2)s' % {
                    'pattern1': glusterfs_server_CN_pattern,
                    'pattern2': manila_host_CN_pattern})
            access_to = ','.join(filter(regex.match, old_access_list))
            gluster_actions.append((AUTH_SSL_ALLOW, access_to))

        for option, value in (
            (NFS_EXPORT_VOL, 'off'), (CLIENT_SSL, 'on'), (SERVER_SSL, 'on')
        ):
            gluster_actions.append((option, value))

        for action in gluster_actions:
            gluster_mgr.gluster_call(
                'volume', 'set', gluster_mgr.volume, *action,
                log=_LE('Setting up GlusterFS volume'))

        try:
            gluster_mgr.gluster_call(
                'volume', 'set', gluster_mgr.volume, DYNAMIC_AUTH, 'on',
                raw_error=True)
        except exception.ProcessExecutionError as exc:
            if exc.exit_code == 1:
                # 'dynamic-auth' is not supported by gluster backend,
                # that's OK
                pass
            else:
                msg = (_("Error in gluster volume set during volume "
                         "setup. volume: %(volname)s, option: %(option)s, "
                         "value: %(value)s, error: %(error)s") %
                       {'volname': gluster_mgr.volume,
                        'option': option, 'value': value,
                        'error': exc.stderr})
                LOG.error(msg)
                raise exception.GlusterfsException(msg)

        # SSL enablement requires a fresh volume start
        # to take effect
        if gluster_mgr_parent:
            # in this case the volume is not started
            # yet (will only be started after this func
            # returns), so we have nothing to do here
            pass
        else:
            common._restart_gluster_vol(gluster_mgr)

        return gluster_mgr.export

    @utils.synchronized("glusterfs_native_access", external=False)
    def _allow_access_via_manager(self, gluster_mgr, context, share, access,
                                  share_server=None):
        """Allow access to a share using certs.

        Add the SSL CN (Common Name) that's allowed to access the server.
        """

        if access['access_type'] != ACCESS_TYPE_CERT:
            raise exception.InvalidShareAccess(_("Only 'cert' access type "
                                                 "allowed"))

        ssl_allow_opt = gluster_mgr.get_gluster_vol_option(AUTH_SSL_ALLOW)
        # wrt. GlusterFS' parsing of auth.ssl-allow, please see code from
        # https://github.com/gluster/glusterfs/blob/v3.6.2/
        # xlators/protocol/auth/login/src/login.c#L80
        # until end of gf_auth() function
        ssl_allow = re.split('[ ,]', ssl_allow_opt)
        access_to = access['access_to']
        if access_to in ssl_allow:
            LOG.warning(_LW("Access to %(share)s at %(export)s is already "
                            "granted for %(access_to)s. GlusterFS volume "
                            "options might have been changed externally."),
                        {'share': share['id'], 'export': gluster_mgr.qualified,
                         'access_to': access_to})
            return

        ssl_allow.append(access_to)
        ssl_allow_opt = ','.join(ssl_allow)
        gluster_mgr.gluster_call(
            'volume', 'set', gluster_mgr.volume,
            AUTH_SSL_ALLOW, ssl_allow_opt,
            log=_LE("Tuning GlusterFS volume in allow-access"))

    @utils.synchronized("glusterfs_native_access", external=False)
    def _deny_access_via_manager(self, gluster_mgr, context, share, access,
                                 share_server=None):
        """Deny access to a share that's using cert based auth.

        Remove the SSL CN (Common Name) that's allowed to access the server.
        """

        if access['access_type'] != ACCESS_TYPE_CERT:
            raise exception.InvalidShareAccess(_("Only 'cert' access type "
                                                 "allowed for access "
                                                 "removal."))

        ssl_allow_opt = gluster_mgr.get_gluster_vol_option(AUTH_SSL_ALLOW)
        ssl_allow = re.split('[ ,]', ssl_allow_opt)
        access_to = access['access_to']
        if access_to not in ssl_allow:
            LOG.warning(_LW("Access to %(share)s at %(export)s is already "
                            "denied for %(access_to)s. GlusterFS volume "
                            "options might have been changed externally."),
                        {'share': share['id'], 'export': gluster_mgr.qualified,
                         'access_to': access_to})
            return

        ssl_allow.remove(access_to)
        ssl_allow_opt = ','.join(ssl_allow)
        gluster_mgr.gluster_call(
            'volume', 'set', gluster_mgr.volume,
            AUTH_SSL_ALLOW, ssl_allow_opt,
            log=_LE("Tuning GlusterFS volume in deny-access"))

        dynauth = gluster_mgr.get_gluster_vol_option(DYNAMIC_AUTH) or 'off'
        # TODO(csaba): boolean option processing shoud be done in common
        if dynauth.lower() not in ('on', '1', 'true', 'yes', 'enable'):
            common._restart_gluster_vol(gluster_mgr)

    def _update_share_stats(self):
        """Send stats info for the GlusterFS volume."""

        data = dict(
            share_backend_name=self.backend_name,
            vendor_name='Red Hat',
            driver_version='1.1',
            storage_protocol='glusterfs',
            reserved_percentage=self.configuration.reserved_share_percentage)

        # We don't use a service mount to get stats data.
        # Instead we use glusterfs quota feature and use that to limit
        # the share to its expected share['size'].

        # TODO(deepakcs): Change below once glusterfs supports volume
        # specific stats via the gluster cli.
        data['total_capacity_gb'] = 'unknown'
        data['free_capacity_gb'] = 'unknown'

        super(GlusterfsNativeShareDriver, self)._update_share_stats(data)

    def get_network_allocations_number(self):
        return 0
