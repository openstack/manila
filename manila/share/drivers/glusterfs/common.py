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

from oslo_config import cfg
from oslo_log import log
import six

from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LW
from manila.share.drivers.ganesha import utils as ganesha_utils

LOG = log.getLogger(__name__)


glusterfs_common_opts = [
    cfg.StrOpt('glusterfs_server_password',
               secret=True,
               deprecated_name='glusterfs_native_server_password',
               help='Remote GlusterFS server node\'s login password. '
                    'This is not required if '
                    '\'glusterfs_path_to_private_key\' is '
                    'configured.'),
    cfg.StrOpt('glusterfs_path_to_private_key',
               deprecated_name='glusterfs_native_path_to_private_key',
               help='Path of Manila host\'s private SSH key file.'),
]


CONF = cfg.CONF
CONF.register_opts(glusterfs_common_opts)


def _check_volume_presence(f):

    def wrapper(self, *args, **kwargs):
        if not self.components.get('volume'):
            raise exception.GlusterfsException(
                _("Gluster address does not have a volume component."))
        return f(self, *args, **kwargs)

    return wrapper


def volxml_get(xmlout, path, *default):
    """Extract a value by a path from XML."""
    value = xmlout.find(path)
    if value is None:
        if default:
            return default[0]
        raise exception.InvalidShare(
            _('Xpath %s not found in volume query response XML') % path)
    return value.text


class GlusterManager(object):
    """Interface with a GlusterFS volume."""

    scheme = re.compile('\A(?:(?P<user>[^:@/]+)@)?'
                        '(?P<host>[^:@/]+)'
                        '(?::/(?P<volume>[^/]+)(?P<path>/.*)?)?\Z')

    # See this about GlusterFS' convention for Boolean interpretation
    # of strings:
    # https://github.com/gluster/glusterfs/blob/v3.7.8/
    #         libglusterfs/src/common-utils.c#L1680-L1708
    GLUSTERFS_TRUE_VALUES = ('ON', 'YES', 'TRUE', 'ENABLE', '1')
    GLUSTERFS_FALSE_VALUES = ('OFF', 'NO', 'FALSE', 'DISABLE', '0')

    @classmethod
    def parse(cls, address):
        """Parse address string into component dict."""
        m = cls.scheme.search(address)
        if not m:
            raise exception.GlusterfsException(
                _('Invalid gluster address %s.') % address)
        return m.groupdict()

    def __getattr__(self, attr):
        if attr in self.components:
            return self.components[attr]
        raise AttributeError("'%(typ)s' object has no attribute '%(attr)s'" %
                             {'typ': type(self).__name__, 'attr': attr})

    def __init__(self, address, execf=None, path_to_private_key=None,
                 remote_server_password=None, requires={}):
        """Initialize a GlusterManager instance.

        :param address: the Gluster URI (either string of
                        [<user>@]<host>[:/<volume>[/<path>]] format or
                        component dict with "user", "host", "volume",
                        "path" keys).
        :param execf: executor function for management commands.
        :param path_to_private_key: path to private ssh key of remote server.
        :param remote_server_password: ssh password for remote server.
        :param requires: a dict mapping some of the component names to
                         either True or False; having it specified,
                         respectively, the presence or absence of the
                         given component in the uri will be enforced.
        """

        if isinstance(address, dict):
            tmp_addr = ""
            if address.get('user') is not None:
                tmp_addr = address.get('user') + '@'
            if address.get('host') is not None:
                tmp_addr += address.get('host')
            if address.get('volume') is not None:
                tmp_addr += ':/' + address.get('volume')
            if address.get('path') is not None:
                tmp_addr += address.get('path')
            self.components = self.parse(tmp_addr)
            # Verify that the original dictionary matches the parsed
            # dictionary. This will flag typos such as {'volume': 'vol/err'}
            # in the original dictionary as errors.  Additionally,
            # extra keys will need to be flagged as an error.
            sanitized_address = {key: None for key in self.scheme.groupindex}
            sanitized_address.update(address)
            if sanitized_address != self.components:
                raise exception.GlusterfsException(
                    _('Invalid gluster address %s.') % address)
        else:
            self.components = self.parse(address)

        for k, v in requires.items():
            if v is None:
                continue
            if (self.components.get(k) is not None) != v:
                raise exception.GlusterfsException(
                    _('Invalid gluster address %s.') % address)

        self.path_to_private_key = path_to_private_key
        self.remote_server_password = remote_server_password
        if execf:
            self.gluster_call = self.make_gluster_call(execf)

    @property
    def host_access(self):
        return '@'.join(filter(None, (self.user, self.host)))

    def _build_uri(self, base):
        u = base
        for sep, comp in ((':/', 'volume'), ('', 'path')):
            if self.components[comp] is None:
                break
            u = sep.join((u, self.components[comp]))
        return u

    @property
    def qualified(self):
        return self._build_uri(self.host_access)

    @property
    def export(self):
        if self.volume:
            return self._build_uri(self.host)

    def make_gluster_call(self, execf):
        """Execute a Gluster command locally or remotely."""
        if self.user:
            gluster_execf = ganesha_utils.SSHExecutor(
                self.host, 22, None, self.user,
                password=self.remote_server_password,
                privatekey=self.path_to_private_key)
        else:
            gluster_execf = ganesha_utils.RootExecutor(execf)

        def _gluster_call(*args, **kwargs):
            logmsg = kwargs.pop('log', None)
            error_policy = kwargs.pop('error_policy', 'coerce')
            if (error_policy not in ('raw', 'coerce', 'suppress') and
               not isinstance(error_policy[0], int)):
                raise TypeError(_("undefined error_policy %s") %
                                repr(error_policy))

            try:
                return gluster_execf(*(('gluster',) + args), **kwargs)
            except exception.ProcessExecutionError as exc:
                if error_policy == 'raw':
                    raise
                elif error_policy == 'coerce':
                    pass
                elif (error_policy == 'suppress' or
                      exc.exit_code in error_policy):
                    return
                if logmsg:
                    LOG.error(_LE("%s: GlusterFS instrumentation failed.") %
                              logmsg)
                raise exception.GlusterfsException(
                    _("GlusterFS management command '%(cmd)s' failed "
                      "with details as follows:\n%(details)s.") % {
                        'cmd': ' '.join(args),
                        'details': exc})

        return _gluster_call

    def xml_response_check(self, xmlout, command, countpath=None):
        """Sanity check for GlusterFS XML response."""
        commandstr = ' '.join(command)
        ret = {}
        for e in 'opRet', 'opErrno':
            ret[e] = int(volxml_get(xmlout, e))
        if ret == {'opRet': -1, 'opErrno': 0}:
            raise exception.GlusterfsException(_(
                'GlusterFS command %(command)s on volume %(volume)s failed'
            ) % {'volume': self.volume, 'command': command})
        if list(six.itervalues(ret)) != [0, 0]:
            errdct = {'volume': self.volume, 'command': commandstr,
                      'opErrstr': volxml_get(xmlout, 'opErrstr', None)}
            errdct.update(ret)
            raise exception.InvalidShare(_(
                'GlusterFS command %(command)s on volume %(volume)s got '
                'unexpected response: '
                'opRet=%(opRet)s, opErrno=%(opErrno)s, opErrstr=%(opErrstr)s'
            ) % errdct)
        if not countpath:
            return
        count = volxml_get(xmlout, countpath)
        if count != '1':
            raise exception.InvalidShare(
                _('GlusterFS command %(command)s on volume %(volume)s got '
                  'ambiguous response: '
                  '%(count)s records') % {
                    'volume': self.volume, 'command': commandstr,
                    'count': count})

    def _get_vol_option_via_info(self, option):
        """Get the value of an option set on a GlusterFS volume via volinfo."""
        args = ('--xml', 'volume', 'info', self.volume)
        out, err = self.gluster_call(*args, log=_LE("retrieving volume info"))

        if not out:
            raise exception.GlusterfsException(
                'gluster volume info %s: no data received' %
                self.volume
            )

        volxml = etree.fromstring(out)
        self.xml_response_check(volxml, args[1:], './volInfo/volumes/count')
        for e in volxml.findall(".//option"):
            o, v = (volxml_get(e, a) for a in ('name', 'value'))
            if o == option:
                return v

    @_check_volume_presence
    def _get_vol_user_option(self, useropt):
        """Get the value of an user option set on a GlusterFS volume."""
        option = '.'.join(('user', useropt))
        return self._get_vol_option_via_info(option)

    @_check_volume_presence
    def _get_vol_regular_option(self, option):
        """Get the value of a regular option set on a GlusterFS volume."""
        args = ('--xml', 'volume', 'get', self.volume, option)

        out, err = self.gluster_call(*args, check_exit_code=False)

        if not out:
            # all input is valid, but the option has not been set
            # (nb. some options do come by a null value, but some
            # don't even have that, see eg. cluster.nufa)
            return

        try:
            optxml = etree.fromstring(out)
        except Exception:
            # non-xml output indicates that GlusterFS backend does not support
            # 'vol get', we fall back to 'vol info' based retrieval (glusterfs
            # < 3.7).
            return self._get_vol_option_via_info(option)

        self.xml_response_check(optxml, args[1:], './volGetopts/count')
        return volxml_get(optxml, './volGetopts/Value')

    def get_vol_option(self, option, boolean=False):
        """Get the value of an option set on a GlusterFS volume."""
        useropt = re.sub('\Auser\.', '', option)
        if option == useropt:
            value = self._get_vol_regular_option(option)
        else:
            value = self._get_vol_user_option(useropt)
        if not boolean or value is None:
            return value
        if value.upper() in self.GLUSTERFS_TRUE_VALUES:
            return True
        if value.upper() in self.GLUSTERFS_FALSE_VALUES:
            return False
        raise exception.GlusterfsException(_(
            "GlusterFS volume option on volume %(volume)s: "
            "%(option)s=%(value)s cannot be interpreted as Boolean") % {
                'volume': self.volume, 'option': option, 'value': value})

    @_check_volume_presence
    def set_vol_option(self, option, value, ignore_failure=False):
        value = {True: self.GLUSTERFS_TRUE_VALUES[0],
                 False: self.GLUSTERFS_FALSE_VALUES[0]}.get(value, value)
        if value is None:
            args = ('reset', (option,))
        else:
            args = ('set', (option, value))
        policy = (1,) if ignore_failure else 'coerce'
        self.gluster_call(
            'volume', args[0], self.volume, *args[1], error_policy=policy)

    def get_gluster_version(self):
        """Retrieve GlusterFS version.

        :returns: version (as tuple of strings, example: ('3', '6', '0beta2'))
        """
        out, err = self.gluster_call('--version',
                                     log=_LE("GlusterFS version query"))
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
        if numreduct(vers) < minvers:
            raise exception.GlusterfsException(_(
                "Unsupported GlusterFS version %(version)s on server "
                "%(server)s, minimum requirement: %(minvers)s") % {
                'server': self.host,
                'version': '.'.join(vers),
                'minvers': '.'.join(six.text_type(c) for c in minvers)})


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
            LOG.warning(_LW("%s is already mounted."), gluster_export)
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

    # TODO(csaba): '--mode=script' ensures that the Gluster CLI runs in
    # script mode. This seems unnecessary as the Gluster CLI is
    # expected to run in non-interactive mode when the stdin is not
    # a terminal, as is the case below. But on testing, found the
    # behaviour of Gluster-CLI to be the contrary. Need to investigate
    # this odd-behaviour of Gluster-CLI.
    gluster_mgr.gluster_call(
        'volume', 'stop', gluster_mgr.volume, '--mode=script',
        log=_LE("stopping GlusterFS volume %s") % gluster_mgr.volume)

    gluster_mgr.gluster_call(
        'volume', 'start', gluster_mgr.volume,
        log=_LE("starting GlusterFS volume %s") % gluster_mgr.volume)
