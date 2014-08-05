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
SSL Certificates. Only the share which has the SSL trust established
with the GlusterFS backend can mount and hence use the share.
"""


from manila import exception
from manila.openstack.common import log as logging
from manila.share.drivers import glusterfs


LOG = logging.getLogger(__name__)

CLIENT_SSL = 'client.ssl'
SERVER_SSL = 'server.ssl'
AUTH_SSL_ALLOW = 'auth.ssl-allow'
ACCESS_TYPE_CERT = 'cert'


class GlusterfsNativeShareDriver(glusterfs.GlusterfsShareDriver):

    def _setup_gluster_vol(self):
        super(GlusterfsNativeShareDriver, self)._setup_gluster_vol()

        # Enable gluster volume for SSL access.
        # This applies for both service mount and instance mount(s).

        # TODO(deepakcs): Once gluster support dual-access, we can limit
        # service mount to non-ssl access.
        gargs, gkw = self.gluster_address.make_gluster_args(
            'volume', 'set', self.gluster_address.volume,
            CLIENT_SSL, 'on')
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            LOG.error(_("Error in gluster volume set during volume setup."
                        "Volume: %(volname)s, Option: %(option)s, "
                        "Error: %(error)s"),
                      {'volname': self.gluster_address.volume,
                       'option': CLIENT_SSL, 'error': exc.stderr})
            raise
        gargs, gkw = self.gluster_address.make_gluster_args(
            'volume', 'set', self.gluster_address.volume,
            SERVER_SSL, 'on')
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            LOG.error(_("Error in gluster volume set during volume setup."
                        "Volume: %(volname)s, Option: %(option)s, "
                        "Error: %(error)s"),
                      {'volname': self.gluster_address.volume,
                       'option': SERVER_SSL, 'error': exc.stderr})
            raise

    def create_share(self, ctx, share, share_server=None):
        """Create a share using GlusterFS volume.

        1 Manila share = 1 GlusterFS volume. Ensure that the
        GlusterFS volume is properly setup to be consumed as
        a share.
        """

        # Handle the case where create is called after delete share
        try:
            self._setup_gluster_vol()
        except exception.ProcessExecutionError:
            LOG.error(_("Unable to create share %s"), (share['name'],))
            raise

        # TODO(deepakcs): Add validation for gluster mount being present
        # (decorator maybe)

        # For native protocol, the export_location should be of the form:
        # server:/volname
        export_location = self.gluster_address.export

        LOG.info(_("export_location sent back from create_share: %s"),
                  (export_location,))
        return export_location

    def delete_share(self, context, share, share_server=None):
        """Delete a share on the GlusterFS volume.

        1 Manila share = 1 GlusterFS volume. Ensure that the
        GlusterFS volume is reset back to its original state.
        """
        # Get the gluster volume back to its original state

        gargs, gkw = self.gluster_address.make_gluster_args(
            'volume', 'reset', self.gluster_address.volume)
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            LOG.error(_("Error in gluster volume reset during delete share."
                        "Volume: %(volname)s, Error: %(error)s"),
                      {'volname': self.gluster_address.volume,
                       'error': exc.stderr})
            raise

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to a share using certs.

        Add the SSL CN (Common Name) that's allowed to access the server.
        """

        if access['access_type'] != ACCESS_TYPE_CERT:
            raise exception.InvalidShareAccess(_("Only 'cert' access type "
                                                 "allowed"))

        gargs, gkw = self.gluster_address.make_gluster_args(
            'volume', 'set', self.gluster_address.volume,
            AUTH_SSL_ALLOW, access['access_to'])
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            LOG.error(_("Error in gluster volume set during allow access."
                        "Volume: %(volname)s, Option: %(option)s, "
                        "access_to: %(access_to)s, Error: %(error)s"),
                      {'volname': self.gluster_address.volume,
                       'option': AUTH_SSL_ALLOW,
                       'access_to': access['access_to'], 'error': exc.stderr})
            raise

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to a share that's using cert based auth.

        Remove the SSL CN (Common Name) that's allowed to access the server.
        """

        if access['access_type'] != ACCESS_TYPE_CERT:
            raise exception.InvalidShareAccess(_("Only 'cert' access type "
                                                 "allowed for access "
                                                 "removal."))

        gargs, gkw = self.gluster_address.make_gluster_args(
            'volume', 'reset', self.gluster_address.volume,
            AUTH_SSL_ALLOW)
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            LOG.error(_("Error in gluster volume reset during deny access."
                        "Volume: %(volname)s, Option: %(option)s, "
                        "Error: %(error)s"),
                      {'volname': self.gluster_address.volume,
                       'option': AUTH_SSL_ALLOW, 'error': exc.stderr})
            raise
