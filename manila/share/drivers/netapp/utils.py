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

from collections import abc
import decimal
import platform
import re

from oslo_concurrency import processutils as putils
from oslo_log import log
from oslo_utils import timeutils

from manila import exception
from manila.i18n import _
from manila import version


LOG = log.getLogger(__name__)

VALID_TRACE_FLAGS = ['method', 'api']
TRACE_METHOD = False
TRACE_API = False
API_TRACE_PATTERN = '(.*)'
SVM_MIGRATE_POLICY_TYPE_NAME = 'migrate'
MIGRATION_OPERATION_ID_KEY = 'migration_operation_id'
MIGRATION_STATE_READY_FOR_CUTOVER = 'ready_for_cutover'
MIGRATION_STATE_READY_FOR_SOURCE_CLEANUP = 'ready_for_source_cleanup'
MIGRATION_STATE_MIGRATE_COMPLETE = 'migrate_complete'
MIGRATION_STATE_MIGRATE_PAUSED = 'migrate_paused'

EXTENDED_DATA_PROTECTION_TYPE = 'extended_data_protection'
MIRROR_ALL_SNAP_POLICY = 'MirrorAllSnapshots'
DATA_PROTECTION_TYPE = 'data_protection'

FLEXGROUP_STYLE_EXTENDED = 'flexgroup'
FLEXVOL_STYLE_EXTENDED = 'flexvol'

FLEXGROUP_DEFAULT_POOL_NAME = 'flexgroup_auto'


class NetAppDriverException(exception.ShareBackendException):
    message = _("NetApp Manila Driver exception.")


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
    return float(decimal.Decimal(str(value)).quantize(
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
    elif isinstance(value, str):
        return [value]
    elif isinstance(value, abc.Iterable):
        return list(value)
    else:
        return [value]


def convert_string_to_list(string, separator=','):
    return [elem.strip() for elem in string.split(separator)]


def get_relationship_type(is_flexgroup):
    """Returns the snapmirror relationship type."""
    return (EXTENDED_DATA_PROTECTION_TYPE if is_flexgroup
            else DATA_PROTECTION_TYPE)


def is_style_extended_flexgroup(style_extended):
    """Returns whether the style is extended type or not."""
    return style_extended == FLEXGROUP_STYLE_EXTENDED


def parse_flexgroup_pool_config(config, cluster_aggr_set={}, check=False):
    """Returns the dict with the FlexGroup pools and if it is auto provisioned.

    :param config: the configuration flexgroup list of dict.
    :param cluster_aggr_set: the set of aggregates in the cluster.
    :param check: should check the config is correct.
    """

    flexgroup_pools_map = {}
    aggr_list_used = []
    for pool_dic in config:
        for pool_name, aggr_str in pool_dic.items():
            aggr_name_list = aggr_str.split()

            if not check:
                aggr_name_list.sort()
                flexgroup_pools_map[pool_name] = aggr_name_list
                continue

            if pool_name in cluster_aggr_set:
                msg = _('The %s FlexGroup pool name is not valid, because '
                        'it is a cluster aggregate name. Ensure that the '
                        'configuration option netapp_flexgroup_pools is '
                        'set correctly.')
                raise exception.NetAppException(msg % pool_name)

            aggr_name_set = set(aggr_name_list)
            if len(aggr_name_set) != len(aggr_name_list):
                msg = _('There is a repeated aggregate name in the '
                        'FlexGroup pool %s definition. Ensure that the '
                        'configuration option netapp_flexgroup_pools is '
                        'set correctly.')
                raise exception.NetAppException(msg % pool_name)

            not_found_aggr = aggr_name_set - cluster_aggr_set
            if not_found_aggr:
                not_found_list = [str(s) for s in not_found_aggr]
                not_found_str = ", ".join(not_found_list)
                msg = _('There is an aggregate name in the FlexGroup pool '
                        '%(pool)s that is not in the cluster: %(aggr)s. '
                        'Ensure that the configuration option '
                        'netapp_flexgroup_pools is set correctly.')
                msg_args = {'pool': pool_name, 'aggr': not_found_str}
                raise exception.NetAppException(msg % msg_args)

            aggr_name_list.sort()
            aggr_name_list_str = "".join(aggr_name_list)
            if aggr_name_list_str in aggr_list_used:
                msg = _('The FlexGroup pool %s is duplicated. Ensure that '
                        'the configuration option netapp_flexgroup_pools '
                        'is set correctly.')
                raise exception.NetAppException(msg % pool_name)

            aggr_list_used.append(aggr_name_list_str)
            flexgroup_pools_map[pool_name] = aggr_name_list

    return flexgroup_pools_map


class OpenStackInfo(object):
    """OS/distribution, release, and version.

    NetApp uses these fields as content for EMS log entry.
    """

    PACKAGE_NAME = 'python3-manila'

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


class DataCache(object):
    """DataCache class for caching NetApp information.

    The cache validity is measured by a stop watch that is
    not thread-safe.
    """

    def __init__(self, duration):
        self._stop_watch = timeutils.StopWatch(duration)
        self._cached_data = None

    def is_expired(self):
        return not self._stop_watch.has_started() or self._stop_watch.expired()

    def get_data(self):
        return self._cached_data

    def update_data(self, cached_data):
        if not self._stop_watch.has_started():
            self._stop_watch.start()
        else:
            self._stop_watch.restart()

        self._cached_data = cached_data
