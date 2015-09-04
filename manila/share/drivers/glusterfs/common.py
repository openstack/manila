# Copyright (c) 2015 Red Hat, Inc.
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

"""Common GlussterFS routines."""


import re
import xml.etree.cElementTree as etree

from oslo_log import log
import six

from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LW
from manila.share.drivers.ganesha import utils as ganesha_utils

LOG = log.getLogger(__name__)


class GlusterManager(object):
    """Interface with a GlusterFS volume."""

    scheme = re.compile('\A(?:(?P<user>[^:@/]+)@)?'
                        '(?P<host>[^:@/]+)'
                        '(?::/(?P<vol>.+))?')

    def __init__(self, address, execf, path_to_private_key=None,
                 remote_server_password=None, has_volume=True):
        """Initialize a GlusterManager instance.

        :param address: the Gluster URI (in [<user>@]<host>:/<vol> format).
        :param execf: executor function for management commands.
        :param path_to_private_key: path to private ssh key of remote server.
        :param remote_server_password: ssh password for remote server.
        :param has_volume: instruction to uri parser regarding how to deal
                           with the optional volume part (True: require its
                           presence, False: require its absence, None: don't
                           require anything about volume).
        """
        m = self.scheme.search(address)
        if m:
            self.volume = m.group('vol')
            if (has_volume is True and not self.volume) or (
               has_volume is False and self.volume):
                m = None
        if not m:
            raise exception.GlusterfsException(
                _('Invalid gluster address %s.') % address)
        self.remote_user = m.group('user')
        self.host = m.group('host')
        self.management_address = '@'.join(
            filter(None, (self.remote_user, self.host)))
        self.qualified = address
        if self.volume:
            self.export = ':/'.join([self.host, self.volume])
        else:
            self.export = None
        self.path_to_private_key = path_to_private_key
        self.remote_server_password = remote_server_password
        self.gluster_call = self.make_gluster_call(execf)

    def make_gluster_call(self, execf):
        """Execute a Gluster command locally or remotely."""
        if self.remote_user:
            gluster_execf = ganesha_utils.SSHExecutor(
                self.host, 22, None, self.remote_user,
                password=self.remote_server_password,
                privatekey=self.path_to_private_key)
        else:
            gluster_execf = ganesha_utils.RootExecutor(execf)
        return lambda *args, **kwargs: gluster_execf(*(('gluster',) + args),
                                                     **kwargs)

    def get_gluster_vol_option(self, option):
        """Get the value of an option set on a GlusterFS volume."""
        args = ('--xml', 'volume', 'info', self.volume)
        try:
            out, err = self.gluster_call(*args)
        except exception.ProcessExecutionError as exc:
            LOG.error(_LE("Error retrieving volume info: %s"), exc.stderr)
            raise exception.GlusterfsException("gluster %s failed" %
                                               ' '.join(args))

        if not out:
            raise exception.GlusterfsException(
                'gluster volume info %s: no data received' %
                self.volume
            )

        vix = etree.fromstring(out)
        if int(vix.find('./volInfo/volumes/count').text) != 1:
            raise exception.InvalidShare('Volume name ambiguity')
        for e in vix.findall(".//option"):
            o, v = (e.find(a).text for a in ('name', 'value'))
            if o == option:
                return v

    def get_gluster_version(self):
        """Retrieve GlusterFS version.

        :returns: version (as tuple of strings, example: ('3', '6', '0beta2'))
        """
        try:
            out, err = self.gluster_call('--version')
        except exception.ProcessExecutionError as exc:
            raise exception.GlusterfsException(
                _("'gluster version' failed on server "
                  "%(server)s: %(message)s") %
                {'server': self.host, 'message': six.text_type(exc)})
        try:
            owords = out.split()
            if owords[0] != 'glusterfs':
                raise RuntimeError
            vers = owords[1].split('.')
            # provoke an exception if vers does not start with two numerals
            int(vers[0])
            int(vers[1])
        except Exception:
            raise exception.GlusterfsException(
                _("Cannot parse version info obtained from server "
                  "%(server)s, version info: %(info)s") %
                {'server': self.host, 'info': out})
        return vers

    def check_gluster_version(self, minvers):
        """Retrieve and check GlusterFS version.

        :param minvers: minimum version to require
                        (given as tuple of integers, example: (3, 6))
        """
        vers = self.get_gluster_version()
        if self.numreduct(vers) < minvers:
            raise exception.GlusterfsException(_(
                "Unsupported GlusterFS version %(version)s on server "
                "%(server)s, minimum requirement: %(minvers)s") % {
                'server': self.host,
                'version': '.'.join(vers),
                'minvers': '.'.join(six.text_type(c) for c in minvers)})

    @staticmethod
    def numreduct(vers):
        """The numeric reduct of a tuple of strings.

        That is, applying an integer conversion map on the longest
        initial segment of vers which consists of numerals.
        """
        numvers = []
        for c in vers:
            try:
                numvers.append(int(c))
            except ValueError:
                break
        return tuple(numvers)


def _mount_gluster_vol(execute, gluster_export, mount_path, ensure=False):
    """Mount a GlusterFS volume at the specified mount path.

    :param execute: command exectution function
    :param gluster_export: GlusterFS export to mount
    :param mount_path: path to mount at
    :param ensure: boolean to allow remounting a volume with a warning
    """
    execute('mkdir', '-p', mount_path)
    command = ['mount', '-t', 'glusterfs', gluster_export, mount_path]
    try:
        execute(*command, run_as_root=True)
    except exception.ProcessExecutionError as exc:
        if ensure and 'already mounted' in exc.stderr:
            LOG.warn(_LW("%s is already mounted"), gluster_export)
        else:
            raise exception.GlusterfsException(
                'Unable to mount Gluster volume'
            )


def _umount_gluster_vol(execute, mount_path):
    """Unmount a GlusterFS volume at the specified mount path.

    :param execute: command exectution function
    :param mount_path: path where volume is mounted
    """

    try:
        execute('umount', mount_path, run_as_root=True)
    except exception.ProcessExecutionError as exc:
        msg = (_("Unable to unmount gluster volume. "
                 "mount_dir: %(mount_path)s, Error: %(error)s") %
               {'mount_path': mount_path, 'error': exc.stderr})
        LOG.error(msg)
        raise exception.GlusterfsException(msg)


def _restart_gluster_vol(gluster_mgr):
    """Restart a GlusterFS volume through its manager.

    :param gluster_mgr: GlusterManager instance
    """

    try:
        # TODO(csaba): '--mode=script' ensures that the Gluster CLI runs in
        # script mode. This seems unnecessary as the Gluster CLI is
        # expected to run in non-interactive mode when the stdin is not
        # a terminal, as is the case below. But on testing, found the
        # behaviour of Gluster-CLI to be the contrary. Need to investigate
        # this odd-behaviour of Gluster-CLI.
        gluster_mgr.gluster_call(
            'volume', 'stop', gluster_mgr.volume, '--mode=script')
    except exception.ProcessExecutionError as exc:
        msg = (_("Error stopping gluster volume. "
                 "Volume: %(volname)s, Error: %(error)s") %
               {'volname': gluster_mgr.volume, 'error': exc.stderr})
        LOG.error(msg)
        raise exception.GlusterfsException(msg)

    try:
        gluster_mgr.gluster_call(
            'volume', 'start', gluster_mgr.volume)
    except exception.ProcessExecutionError as exc:
        msg = (_("Error starting gluster volume. "
                 "Volume: %(volname)s, Error: %(error)s") %
               {'volname': gluster_mgr.volume, 'error': exc.stderr})
        LOG.error(msg)
        raise exception.GlusterfsException(msg)
