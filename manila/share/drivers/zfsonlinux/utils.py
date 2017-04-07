# Copyright 2016 Mirantis Inc.
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
Module for storing ZFSonLinux driver utility stuff such as:
 - Common ZFS code
 - Share helpers
"""

# TODO(vponomaryov): add support of SaMBa

import abc

from oslo_log import log
import six

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers.ganesha import utils as ganesha_utils
from manila import utils

LOG = log.getLogger(__name__)


def zfs_dataset_synchronized(f):

    def wrapped_func(self, *args, **kwargs):
        key = "zfs-dataset-%s" % args[0]

        @utils.synchronized(key, external=True)
        def source_func(self, *args, **kwargs):
            return f(self, *args, **kwargs)

        return source_func(self, *args, **kwargs)

    return wrapped_func


def get_remote_shell_executor(
        ip, port, conn_timeout, login=None, password=None, privatekey=None,
        max_size=10):
    return ganesha_utils.SSHExecutor(
        ip=ip,
        port=port,
        conn_timeout=conn_timeout,
        login=login,
        password=password,
        privatekey=privatekey,
        max_size=max_size,
    )


class ExecuteMixin(driver.ExecuteMixin):

    def init_execute_mixin(self, *args, **kwargs):
        """Init method for mixin called in the end of driver's __init__()."""
        super(ExecuteMixin, self).init_execute_mixin(*args, **kwargs)
        if self.configuration.zfs_use_ssh:
            self.ssh_executor = get_remote_shell_executor(
                ip=self.configuration.zfs_service_ip,
                port=22,
                conn_timeout=self.configuration.ssh_conn_timeout,
                login=self.configuration.zfs_ssh_username,
                password=self.configuration.zfs_ssh_user_password,
                privatekey=self.configuration.zfs_ssh_private_key_path,
                max_size=10,
            )
        else:
            self.ssh_executor = None

    def execute(self, *cmd, **kwargs):
        """Common interface for running shell commands."""
        if kwargs.get('executor'):
            executor = kwargs.get('executor')
        elif self.ssh_executor:
            executor = self.ssh_executor
        else:
            executor = self._execute
        kwargs.pop('executor', None)
        if cmd[0] == 'sudo':
            kwargs['run_as_root'] = True
            cmd = cmd[1:]
        return executor(*cmd, **kwargs)

    @utils.retry(exception.ProcessExecutionError,
                 interval=5, retries=36, backoff_rate=1)
    def execute_with_retry(self, *cmd, **kwargs):
        """Retry wrapper over common shell interface."""
        try:
            return self.execute(*cmd, **kwargs)
        except exception.ProcessExecutionError as e:
            LOG.warning("Failed to run command, got error: %s", e)
            raise

    def _get_option(self, resource_name, option_name, pool_level=False,
                    **kwargs):
        """Returns value of requested zpool or zfs dataset option."""
        app = 'zpool' if pool_level else 'zfs'

        out, err = self.execute(
            'sudo', app, 'get', option_name, resource_name, **kwargs)

        data = self.parse_zfs_answer(out)
        option = data[0]['VALUE']
        return option

    def parse_zfs_answer(self, string):
        """Returns list of dicts with data returned by ZFS shell commands."""
        lines = string.split('\n')
        if len(lines) < 2:
            return []
        keys = list(filter(None, lines[0].split(' ')))
        data = []
        for line in lines[1:]:
            values = list(filter(None, line.split(' ')))
            if not values:
                continue
            data.append(dict(zip(keys, values)))
        return data

    def get_zpool_option(self, zpool_name, option_name, **kwargs):
        """Returns value of requested zpool option."""
        return self._get_option(zpool_name, option_name, True, **kwargs)

    def get_zfs_option(self, dataset_name, option_name, **kwargs):
        """Returns value of requested zfs dataset option."""
        return self._get_option(dataset_name, option_name, False, **kwargs)

    def zfs(self, *cmd, **kwargs):
        """ZFS shell commands executor."""
        return self.execute('sudo', 'zfs', *cmd, **kwargs)

    def zfs_with_retry(self, *cmd, **kwargs):
        """ZFS shell commands executor."""
        return self.execute_with_retry('sudo', 'zfs', *cmd, **kwargs)


@six.add_metaclass(abc.ABCMeta)
class NASHelperBase(object):
    """Base class for share helpers of 'ZFS on Linux' driver."""

    def __init__(self, configuration):
        """Init share helper.

        :param configuration: share driver 'configuration' instance
        :return: share helper instance.
        """
        self.configuration = configuration
        self.init_execute_mixin()  # pylint: disable=E1101
        self.verify_setup()

    @abc.abstractmethod
    def verify_setup(self):
        """Performs checks for required stuff."""

    @abc.abstractmethod
    def create_exports(self, dataset_name, executor):
        """Creates share exports."""

    @abc.abstractmethod
    def get_exports(self, dataset_name, service, executor):
        """Gets/reads share exports."""

    @abc.abstractmethod
    def remove_exports(self, dataset_name, executor):
        """Removes share exports."""

    @abc.abstractmethod
    def update_access(self, dataset_name, access_rules, add_rules,
                      delete_rules, executor):
        """Update access rules for specified ZFS dataset."""


class NFSviaZFSHelper(ExecuteMixin, NASHelperBase):
    """Helper class for handling ZFS datasets as NFS shares.

    Kernel and Fuse versions of ZFS have different syntax for setting up access
    rules, and this Helper designed to satisfy both making autodetection.
    """

    @property
    def is_kernel_version(self):
        """Says whether Kernel version of ZFS is used or not."""
        if not hasattr(self, '_is_kernel_version'):
            try:
                self.execute('modinfo', 'zfs')
                self._is_kernel_version = True
            except exception.ProcessExecutionError as e:
                LOG.info(
                    "Looks like ZFS kernel module is absent. "
                    "Assuming FUSE version is installed. Error: %s", e)
                self._is_kernel_version = False
        return self._is_kernel_version

    def verify_setup(self):
        """Performs checks for required stuff."""
        out, err = self.execute('which', 'exportfs')
        if not out:
            raise exception.ZFSonLinuxException(
                msg=_("Utility 'exportfs' is not installed."))
        try:
            self.execute('sudo', 'exportfs')
        except exception.ProcessExecutionError:
            LOG.exception("Call of 'exportfs' utility returned error.")
            raise

        # Init that class instance attribute on start of manila-share service
        self.is_kernel_version

    def create_exports(self, dataset_name, executor=None):
        """Creates NFS share exports for given ZFS dataset."""
        return self.get_exports(dataset_name, executor=executor)

    def get_exports(self, dataset_name, executor=None):
        """Gets/reads NFS share export for given ZFS dataset."""
        mountpoint = self.get_zfs_option(
            dataset_name, 'mountpoint', executor=executor)
        return [
            {
                "path": "%(ip)s:%(mp)s" % {"ip": ip, "mp": mountpoint},
                "metadata": {
                },
                "is_admin_only": is_admin_only,
            } for ip, is_admin_only in (
                (self.configuration.zfs_share_export_ip, False),
                (self.configuration.zfs_service_ip, True))
        ]

    @zfs_dataset_synchronized
    def remove_exports(self, dataset_name, executor=None):
        """Removes NFS share exports for given ZFS dataset."""
        sharenfs = self.get_zfs_option(
            dataset_name, 'sharenfs', executor=executor)
        if sharenfs == 'off':
            return
        self.zfs("set", "sharenfs=off", dataset_name, executor=executor)

    def _get_parsed_access_to(self, access_to):
        netmask = utils.cidr_to_netmask(access_to)
        if netmask == '255.255.255.255':
            return access_to.split('/')[0]
        return access_to.split('/')[0] + '/' + netmask

    @zfs_dataset_synchronized
    def update_access(self, dataset_name, access_rules, add_rules,
                      delete_rules, make_all_ro=False, executor=None):
        """Update access rules for given ZFS dataset exported as NFS share."""
        rw_rules = []
        ro_rules = []
        for rule in access_rules:
            if rule['access_type'].lower() != 'ip':
                msg = _("Only IP access type allowed for NFS protocol.")
                raise exception.InvalidShareAccess(reason=msg)
            if (rule['access_level'] == constants.ACCESS_LEVEL_RW and
                    not make_all_ro):
                rw_rules.append(self._get_parsed_access_to(rule['access_to']))
            elif (rule['access_level'] in (constants.ACCESS_LEVEL_RW,
                                           constants.ACCESS_LEVEL_RO)):
                ro_rules.append(self._get_parsed_access_to(rule['access_to']))
            else:
                msg = _("Unsupported access level provided - "
                        "%s.") % rule['access_level']
                raise exception.InvalidShareAccess(reason=msg)

        rules = []
        if self.is_kernel_version:
            if rw_rules:
                rules.append(
                    "rw=%s,no_root_squash" % ":".join(rw_rules))
            if ro_rules:
                rules.append("ro=%s,no_root_squash" % ":".join(ro_rules))
            rules_str = "sharenfs=" + (','.join(rules) or 'off')
        else:
            for rule in rw_rules:
                rules.append("%s:rw,no_root_squash" % rule)
            for rule in ro_rules:
                rules.append("%s:ro,no_root_squash" % rule)
            rules_str = "sharenfs=" + (' '.join(rules) or 'off')

        out, err = self.zfs(
            'list', '-r', dataset_name.split('/')[0], executor=executor)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if datum['NAME'] == dataset_name:
                self.zfs("set", rules_str, dataset_name)
                break
        else:
            LOG.warning(
                "Dataset with '%(name)s' NAME is absent on backend. "
                "Access rules were not applied.", {'name': dataset_name})

        # NOTE(vponomaryov): Setting of ZFS share options does not remove rules
        # that were added and then removed. So, remove them explicitly.
        if delete_rules and access_rules:
            mountpoint = self.get_zfs_option(dataset_name, 'mountpoint')
            for rule in delete_rules:
                if rule['access_type'].lower() != 'ip':
                    continue
                access_to = self._get_parsed_access_to(rule['access_to'])
                export_location = access_to + ':' + mountpoint
                self.execute(
                    'sudo', 'exportfs', '-u', export_location,
                    executor=executor,
                )
