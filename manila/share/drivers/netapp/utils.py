# Copyright (c) 2015 Bob Callaway.  All rights reserved.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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
"""Utilities for NetApp drivers."""

import copy
import platform
import socket

from oslo_concurrency import processutils as putils
from oslo_log import log
from oslo_utils import timeutils

from manila import exception
from manila.i18n import _, _LI, _LW
from manila.share.drivers.netapp import api as na_api
from manila import version

LOG = log.getLogger(__name__)


VALID_TRACE_FLAGS = ['method', 'api']
TRACE_METHOD = False
TRACE_API = False


def setup_tracing(trace_flags_string):
    global TRACE_METHOD
    global TRACE_API
    TRACE_METHOD = False
    TRACE_API = False
    if trace_flags_string:
        flags = trace_flags_string.split(',')
        flags = [flag.strip() for flag in flags]
        for invalid_flag in list(set(flags) - set(VALID_TRACE_FLAGS)):
            LOG.warning(_LW('Invalid trace flag: %s') % invalid_flag)
        TRACE_METHOD = 'method' in flags
        TRACE_API = 'api' in flags


def trace(f):
    def trace_wrapper(self, *args, **kwargs):
        if TRACE_METHOD:
            LOG.debug('Entering method %s' % f.__name__)
        result = f(self, *args, **kwargs)
        if TRACE_METHOD:
            LOG.debug('Leaving method %s' % f.__name__)
        return result
    return trace_wrapper


def check_flags(required_flags, configuration):
    """Ensure that the flags we care about are set."""
    for flag in required_flags:
        if not getattr(configuration, flag, None):
            msg = _('Configuration value %s is not set.') % flag
            raise exception.InvalidInput(reason=msg)


def provide_ems(requester, server, netapp_backend, app_version,
                server_type="cluster"):
    """Provide ems with volume stats for the requester.

    """
    # TODO(tbarron): rework provide_ems to not store timestamp in the caller.
    # This requires upcoming Manila NetApp refactoring work.

    def _create_ems(netapp_backend, app_version, server_type):
        """Create ems api request."""
        ems_log = na_api.NaElement('ems-autosupport-log')
        host = socket.getfqdn() or 'Manila_node'
        if server_type == "cluster":
            dest = "cluster node"
        else:
            dest = "7 mode controller"
        ems_log.add_new_child('computer-name', host)
        ems_log.add_new_child('event-id', '0')
        ems_log.add_new_child('event-source',
                              'Manila driver %s' % netapp_backend)
        ems_log.add_new_child('app-version', app_version)
        ems_log.add_new_child('category', 'provisioning')
        ems_log.add_new_child('event-description',
                              'OpenStack Manila connected to %s' % dest)
        ems_log.add_new_child('log-level', '6')
        ems_log.add_new_child('auto-support', 'false')
        return ems_log

    def _create_vs_get():
        """Create vs_get api request."""
        vs_get = na_api.NaElement('vserver-get-iter')
        vs_get.add_new_child('max-records', '1')
        query = na_api.NaElement('query')
        query.add_node_with_children('vserver-info',
                                     **{'vserver-type': 'node'})
        vs_get.add_child_elem(query)
        desired = na_api.NaElement('desired-attributes')
        desired.add_node_with_children(
            'vserver-info', **{'vserver-name': '', 'vserver-type': ''})
        vs_get.add_child_elem(desired)
        return vs_get

    def _get_cluster_node(na_server):
        """Get the cluster node for ems."""
        na_server.set_vserver(None)
        vs_get = _create_vs_get()
        res = na_server.invoke_successfully(vs_get)
        if (res.get_child_content('num-records') and
           int(res.get_child_content('num-records')) > 0):
            attr_list = res.get_child_by_name('attributes-list')
            vs_info = attr_list.get_child_by_name('vserver-info')
            vs_name = vs_info.get_child_content('vserver-name')
            return vs_name
        return None

    do_ems = True
    if hasattr(requester, 'last_ems'):
        sec_limit = 3559
        if not (timeutils.is_older_than(requester.last_ems, sec_limit)):
            do_ems = False
    if do_ems:
        na_server = copy.copy(server)
        na_server.set_timeout(25)
        ems = _create_ems(netapp_backend, app_version, server_type)
        try:
            if server_type == "cluster":
                api_version = na_server.get_api_version()
                if api_version:
                    major, minor = api_version
                else:
                    raise na_api.NaApiError(code='Not found',
                                            message='No api version found')
                if major == 1 and minor > 15:
                    node = getattr(requester, 'vserver', None)
                else:
                    node = _get_cluster_node(na_server)
                if node is None:
                    raise na_api.NaApiError(code='Not found',
                                            message='No vserver found')
                na_server.set_vserver(node)
            else:
                na_server.set_vfiler(None)
            na_server.invoke_successfully(ems, True)
            LOG.debug("ems executed successfully.")
        except na_api.NaApiError as e:
            LOG.warn(_LW("Failed to invoke ems. Message : %s") % e)
        finally:
            requester.last_ems = timeutils.utcnow()


class OpenStackInfo(object):
    """OS/distribution, release, and version.

    NetApp uses these fields as content for EMS log entry.
    """

    PACKAGE_NAME = 'python-manila'

    def __init__(self):
        self._version = 'unknown version'
        self._release = 'unknown release'
        self._vendor = 'unknown vendor'
        self._platform = 'unknown platform'

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        self._version = value

    @property
    def release(self):
        return self._release

    @release.setter
    def release(self, value):
        self._release = value

    @property
    def vendor(self):
        return self._vendor

    @vendor.setter
    def vendor(self, value):
        self._vendor = value

    @property
    def platform(self):
        return self._platform

    @platform.setter
    def platform(self, value):
        self._platform = value

    # Because of the variety of platforms and OpenStack distributions that we
    # may run against, it is by no means a sure thing that these update methods
    # will work.  We collect what information we can and deliberately ignore
    # exceptions of any kind in order to avoid fillling the manila share log
    # with noise.
    def _update_version_from_version_string(self):
        try:
            self.version = version.version_info.version_string()
        except Exception:
            pass

    def _update_release_from_release_string(self):
        try:
            self.release = version.version_info.release_string()
        except Exception:
            pass

    def _update_platform(self):
        try:
            self.platform = platform.platform()
        except Exception:
            pass

    @staticmethod
    def _get_version_info_version():
        return version.version_info.version

    @staticmethod
    def _get_version_info_release():
        return version.version_info.release

    def _update_info_from_version_info(self):
        try:
            ver = self._get_version_info_version()
            if ver:
                self.version = ver
        except Exception:
            pass
        try:
            rel = self._get_version_info_release()
            if rel:
                self.release = rel
        except Exception:
            pass

    # RDO, RHEL-OSP, Mirantis on Redhat, SUSE
    def _update_info_from_rpm(self):
        LOG.debug('Trying rpm command.')
        try:
            out, err = putils.execute("rpm", "-q", "--queryformat",
                                      "'%{version}\t%{release}\t%{vendor}'",
                                      self.PACKAGE_NAME)
            if not out:
                LOG.info(_LI('No rpm info found for %(pkg)s package.') % {
                    'pkg': self.PACKAGE_NAME})
                return False
            parts = out.split()
            self.version = parts[0]
            self.release = parts[1]
            self.vendor = ' '.join(parts[2::])
            return True
        except Exception as e:
            LOG.info(_LI('Could not run rpm command: %(msg)s.') % {
                'msg': e})
            return False

    # ubuntu, mirantis on ubuntu
    def _update_info_from_dpkg(self):
        LOG.debug('Trying dpkg-query command.')
        try:
            _vendor = None
            out, err = putils.execute("dpkg-query", "-W", "-f='${Version}'",
                                      self.PACKAGE_NAME)
            if not out:
                LOG.info(_LI(
                    'No dpkg-query info found for %(pkg)s package.') % {
                    'pkg': self.PACKAGE_NAME})
                return False
            # debian format: [epoch:]upstream_version[-debian_revision]
            deb_version = out
            # in case epoch or revision is missing, copy entire string
            _release = deb_version
            if ':' in deb_version:
                deb_epoch, upstream_version = deb_version.split(':')
                _release = upstream_version
            if '-' in deb_version:
                deb_revision = deb_version.split('-')[1]
                _vendor = deb_revision
            self.release = _release
            if _vendor:
                self.vendor = _vendor
            return True
        except Exception as e:
            LOG.info(_LI('Could not run dpkg-query command: %(msg)s.') % {
                'msg': e})
            return False

    def _update_openstack_info(self):
        self._update_version_from_version_string()
        self._update_release_from_release_string()
        self._update_platform()
        # some distributions override with more meaningful information
        self._update_info_from_version_info()
        # see if we have still more targeted info from rpm or apt
        found_package = self._update_info_from_rpm()
        if not found_package:
            self._update_info_from_dpkg()

    def info(self):
        self._update_openstack_info()
        return '%(version)s|%(release)s|%(vendor)s|%(platform)s' % {
            'version': self.version, 'release': self.release,
            'vendor': self.vendor, 'platform': self.platform}
