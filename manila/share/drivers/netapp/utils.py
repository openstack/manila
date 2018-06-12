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

import collections
import decimal
import platform
import re

from oslo_concurrency import processutils as putils
from oslo_log import log
import six

from manila import exception
from manila.i18n import _
from manila import version


LOG = log.getLogger(__name__)

VALID_TRACE_FLAGS = ['method', 'api']
TRACE_METHOD = False
TRACE_API = False
API_TRACE_PATTERN = '(.*)'


def validate_driver_instantiation(**kwargs):
    """Checks if a driver is instantiated other than by the unified driver.

    Helps check direct instantiation of netapp drivers.
    Call this function in every netapp block driver constructor.
    """
    if kwargs and kwargs.get('netapp_mode') == 'proxy':
        return
    LOG.warning('Please use NetAppDriver in the configuration file '
                'to load the driver instead of directly specifying '
                'the driver module name.')


def check_flags(required_flags, configuration):
    """Ensure that the flags we care about are set."""
    for flag in required_flags:
        if getattr(configuration, flag, None) is None:
            msg = _('Configuration value %s is not set.') % flag
            raise exception.InvalidInput(reason=msg)


def round_down(value, precision='0.00'):
    """Round a number downward using a specified level of precision.

    Example: round_down(float(total_space_in_bytes) / units.Gi, '0.01')
    """
    return float(decimal.Decimal(six.text_type(value)).quantize(
        decimal.Decimal(precision), rounding=decimal.ROUND_DOWN))


def setup_tracing(trace_flags_string, api_trace_pattern=API_TRACE_PATTERN):
    global TRACE_METHOD
    global TRACE_API
    global API_TRACE_PATTERN
    TRACE_METHOD = False
    TRACE_API = False
    API_TRACE_PATTERN = api_trace_pattern
    if trace_flags_string:
        flags = trace_flags_string.split(',')
        flags = [flag.strip() for flag in flags]
        for invalid_flag in list(set(flags) - set(VALID_TRACE_FLAGS)):
            LOG.warning('Invalid trace flag: %s', invalid_flag)
        try:
            re.compile(api_trace_pattern)
        except re.error:
            msg = _('Cannot parse the API trace pattern. %s is not a '
                    'valid python regular expression.') % api_trace_pattern
            raise exception.BadConfigurationException(reason=msg)
        TRACE_METHOD = 'method' in flags
        TRACE_API = 'api' in flags


def trace(f):
    def trace_wrapper(self, *args, **kwargs):
        if TRACE_METHOD:
            LOG.debug('Entering method %s', f.__name__)
        result = f(self, *args, **kwargs)
        if TRACE_METHOD:
            LOG.debug('Leaving method %s', f.__name__)
        return result
    return trace_wrapper


def convert_to_list(value):

    if value is None:
        return []
    elif isinstance(value, six.string_types):
        return [value]
    elif isinstance(value, collections.Iterable):
        return list(value)
    else:
        return [value]


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

    def _update_version_from_version_string(self):
        try:
            self._version = version.version_info.version_string()
        except Exception:
            pass

    def _update_release_from_release_string(self):
        try:
            self._release = version.version_info.release_string()
        except Exception:
            pass

    def _update_platform(self):
        try:
            self._platform = platform.platform()
        except Exception:
            pass

    @staticmethod
    def _get_version_info_version():
        return version.version_info.version

    @staticmethod
    def _get_version_info_release():
        return version.version_info.release_string()

    def _update_info_from_version_info(self):
        try:
            ver = self._get_version_info_version()
            if ver:
                self._version = ver
        except Exception:
            pass
        try:
            rel = self._get_version_info_release()
            if rel:
                self._release = rel
        except Exception:
            pass

    # RDO, RHEL-OSP, Mirantis on Redhat, SUSE.
    def _update_info_from_rpm(self):
        LOG.debug('Trying rpm command.')
        try:
            out, err = putils.execute("rpm", "-q", "--queryformat",
                                      "'%{version}\t%{release}\t%{vendor}'",
                                      self.PACKAGE_NAME)
            if not out:
                LOG.info('No rpm info found for %(pkg)s package.', {
                    'pkg': self.PACKAGE_NAME})
                return False
            parts = out.split()
            self._version = parts[0]
            self._release = parts[1]
            self._vendor = ' '.join(parts[2::])
            return True
        except Exception as e:
            LOG.info('Could not run rpm command: %(msg)s.', {
                'msg': e})
            return False

    # Ubuntu, Mirantis on Ubuntu.
    def _update_info_from_dpkg(self):
        LOG.debug('Trying dpkg-query command.')
        try:
            _vendor = None
            out, err = putils.execute("dpkg-query", "-W", "-f='${Version}'",
                                      self.PACKAGE_NAME)
            if not out:
                LOG.info(
                    'No dpkg-query info found for %(pkg)s package.', {
                        'pkg': self.PACKAGE_NAME})
                return False
            # Debian format: [epoch:]upstream_version[-debian_revision]
            deb_version = out
            # In case epoch or revision is missing, copy entire string.
            _release = deb_version
            if ':' in deb_version:
                deb_epoch, upstream_version = deb_version.split(':')
                _release = upstream_version
            if '-' in deb_version:
                deb_revision = deb_version.split('-')[1]
                _vendor = deb_revision
            self._release = _release
            if _vendor:
                self._vendor = _vendor
            return True
        except Exception as e:
            LOG.info('Could not run dpkg-query command: %(msg)s.', {
                'msg': e})
            return False

    def _update_openstack_info(self):
        self._update_version_from_version_string()
        self._update_release_from_release_string()
        self._update_platform()
        # Some distributions override with more meaningful information.
        self._update_info_from_version_info()
        # See if we have still more targeted info from rpm or apt.
        found_package = self._update_info_from_rpm()
        if not found_package:
            self._update_info_from_dpkg()

    def info(self):
        self._update_openstack_info()
        return '%(version)s|%(release)s|%(vendor)s|%(platform)s' % {
            'version': self._version, 'release': self._release,
            'vendor': self._vendor, 'platform': self._platform}
