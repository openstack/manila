# Copyright 2012 NetApp
# Copyright 2015 Mirantis inc.
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
Drivers for shares.

"""

import time

from oslo_config import cfg
from oslo_log import log

from manila import exception
from manila.i18n import _LE
from manila import network
from manila import utils

LOG = log.getLogger(__name__)

share_opts = [
    # NOTE(rushiagr): Reasonable to define this option at only one place.
    cfg.IntOpt(
        'num_shell_tries',
        default=3,
        help='Number of times to attempt to run flakey shell commands.'),
    cfg.IntOpt(
        'reserved_share_percentage',
        default=0,
        help='The percentage of backend capacity reserved.'),
    cfg.StrOpt(
        'share_backend_name',
        default=None,
        help='The backend name for a given driver implementation.'),
    cfg.StrOpt(
        'network_config_group',
        default=None,
        help="Name of the configuration group in the Manila conf file "
             "to look for network config options."
             "If not set, the share backend's config group will be used."
             "If an option is not found within provided group, then"
             "'DEFAULT' group will be used for search of option."),
    cfg.BoolOpt(
        'driver_handles_share_servers',
        help="There are two possible approaches for share drivers in Manila. "
             "First is when share driver is able to handle share-servers and "
             "second when not. Drivers can support either both or only one "
             "of these approaches. So, set this opt to True if share driver "
             "is able to handle share servers and it is desired mode else set "
             "False. It is set to None by default to make this choice "
             "intentional."),
]

ssh_opts = [
    cfg.IntOpt(
        'ssh_conn_timeout',
        default=60,
        help='Backend server SSH connection timeout.'),
    cfg.IntOpt(
        'ssh_min_pool_conn',
        default=1,
        help='Minimum number of connections in the SSH pool.'),
    cfg.IntOpt(
        'ssh_max_pool_conn',
        default=10,
        help='Maximum number of connections in the SSH pool.'),
]

ganesha_opts = [
    cfg.StrOpt('ganesha_config_dir',
               default='/etc/ganesha',
               help='Directory where Ganesha config files are stored.'),
    cfg.StrOpt('ganesha_config_path',
               default='$ganesha_config_dir/ganesha.conf',
               help='Path to main Ganesha config file.'),
    cfg.StrOpt('ganesha_nfs_export_options',
               default='maxread = 65536, prefread = 65536',
               help='Options to use when exporting a share using ganesha '
                    'NFS server. Note that these defaults can be overridden '
                    'when a share is created by passing metadata with key '
                    'name export_options.  Also note the complete set of '
                    'default ganesha export options is specified in '
                    'ganesha_utils. (GPFS only.)'),
    cfg.StrOpt('ganesha_service_name',
               default='ganesha.nfsd',
               help='Name of the ganesha nfs service.'),
    cfg.StrOpt('ganesha_db_path',
               default='$state_path/manila-ganesha.db',
               help='Location of Ganesha database file. '
                    '(Ganesha module only.)'),
    cfg.StrOpt('ganesha_export_dir',
               default='$ganesha_config_dir/export.d',
               help='Path to directory containing Ganesha export '
                    'configuration. (Ganesha module only.)'),
    cfg.StrOpt('ganesha_export_template_dir',
               default='/etc/manila/ganesha-export-templ.d',
               help='Path to directory containing Ganesha export '
                    'block templates. (Ganesha module only.)'),
]

CONF = cfg.CONF
CONF.register_opts(share_opts)
CONF.register_opts(ssh_opts)
CONF.register_opts(ganesha_opts)


class ExecuteMixin(object):
    """Provides an executable functionality to a driver class."""

    def init_execute_mixin(self, *args, **kwargs):
        if self.configuration:
            self.configuration.append_config_values(ssh_opts)
        self.set_execute(kwargs.pop('execute', utils.execute))

    def set_execute(self, execute):
        self._execute = execute

    def _try_execute(self, *command, **kwargs):
        # NOTE(vish): Volume commands can partially fail due to timing, but
        #             running them a second time on failure will usually
        #             recover nicely.
        tries = 0
        while True:
            try:
                self._execute(*command, **kwargs)
                return True
            except exception.ProcessExecutionError:
                tries += 1
                if tries >= self.configuration.num_shell_tries:
                    raise
                LOG.exception(_LE("Recovering from a failed execute. "
                                  "Try number %s"), tries)
                time.sleep(tries ** 2)


class GaneshaMixin(object):
    """Augment derived classes with Ganesha configuration."""

    def init_ganesha_mixin(self, *args, **kwargs):
        if self.configuration:
            self.configuration.append_config_values(ganesha_opts)


class ShareDriver(object):
    """Class defines interface of NAS driver."""

    def __init__(self, driver_handles_share_servers, *args, **kwargs):
        """Implements base functionality for share drivers.

        :param driver_handles_share_servers: expected boolean value or
            tuple/list/set of boolean values.
            There are two possible approaches for share drivers in Manila.
            First is when share driver is able to handle share-servers and
            second when not.
            Drivers can support either both or only one of these approaches.
            So, it is allowed to be 'True' when share driver does support
            handling of share servers and allowed to be 'False' when does
            support usage of unhandled share-servers that are not tracked by
            Manila.
            Share drivers are allowed to work only in one of two possible
            driver modes, that is why only one should be chosen.
        """
        super(ShareDriver, self).__init__()
        self.configuration = kwargs.get('configuration', None)
        self._stats = {}

        self.pools = {}
        if self.configuration:
            self.configuration.append_config_values(share_opts)
            network_config_group = (self.configuration.network_config_group or
                                    self.configuration.config_group)
        else:
            network_config_group = None

        self._verify_share_server_handling(driver_handles_share_servers)
        if self.driver_handles_share_servers:
            self.network_api = network.API(
                config_group_name=network_config_group)

        if hasattr(self, 'init_execute_mixin'):
            # Instance with 'ExecuteMixin'
            self.init_execute_mixin(*args, **kwargs)  # pylint: disable=E1101
        if hasattr(self, 'init_ganesha_mixin'):
            # Instance with 'GaneshaMixin'
            self.init_ganesha_mixin(*args, **kwargs)  # pylint: disable=E1101

    @property
    def driver_handles_share_servers(self):
        if self.configuration:
            return self.configuration.safe_get('driver_handles_share_servers')
        return CONF.driver_handles_share_servers

    def _verify_share_server_handling(self, driver_handles_share_servers):
        if not isinstance(self.driver_handles_share_servers, bool):
            raise exception.ManilaException(
                "Config opt 'driver_handles_share_servers' has improper "
                "value - '%s'. Please define it as boolean." %
                self.driver_handles_share_servers)
        elif isinstance(driver_handles_share_servers, bool):
            driver_handles_share_servers = [driver_handles_share_servers]
        elif not isinstance(driver_handles_share_servers, (tuple, list, set)):
            raise exception.ManilaException(
                "Improper data provided for 'driver_handles_share_servers' - "
                "%s" % driver_handles_share_servers)

        if any(not isinstance(v, bool) for v in driver_handles_share_servers):
            raise exception.ManilaException(
                "Provided wrong data: %s" % driver_handles_share_servers)

        if (self.driver_handles_share_servers not in
                driver_handles_share_servers):
            raise exception.ManilaException(
                "Driver does not support mode 'driver_handles_share_servers="
                "%(actual)s'. It can be used only with value '%(allowed)s'." %
                {'actual': self.driver_handles_share_servers,
                 'allowed': driver_handles_share_servers})

    def create_share(self, context, share, share_server=None):
        """Is called to create share."""
        raise NotImplementedError()

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        raise NotImplementedError()

    def create_snapshot(self, context, snapshot, share_server=None):
        """Is called to create snapshot.

        :param context: Current context
        :param snapshot: Snapshot model. Share model could be
            retrieved through snapshot['share'].
        :param share_server: Share server model or None.
        """
        raise NotImplementedError()

    def delete_share(self, context, share, share_server=None):
        """Is called to remove share."""
        raise NotImplementedError()

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Is called to remove snapshot.

        :param context: Current context
        :param snapshot: Snapshot model. Share model could be
            retrieved through snapshot['share'].
        :param share_server: Share server model or None.
        """
        raise NotImplementedError()

    def get_pool(self, share):
        """Return pool name where the share resides on.

        :param share: The share hosted by the driver.
        """

    def ensure_share(self, context, share, share_server=None):
        """Invoked to ensure that share is exported.

        Driver can use this method to update the list of export locations of
        the share if it changes. To do that, you should return list with
        export locations.

        :return None or list with export locations
        """
        raise NotImplementedError()

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        raise NotImplementedError()

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        raise NotImplementedError()

    def check_for_setup_error(self):
        """Check for setup error."""

    def do_setup(self, context):
        """Any initialization the share driver does while starting."""

    def get_share_stats(self, refresh=False):
        """Get share status.

        If 'refresh' is True, run update the stats first.
        """
        if refresh:
            self._update_share_stats()

        return self._stats

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs.

        Drivers that use Nova for share servers should return zero (0) here
        same as Generic driver does.
        Because Nova will handle network resources allocation.
        Drivers that handle networking itself should calculate it according
        to their own requirements. It can have 1+ network interfaces.
        """
        raise NotImplementedError()

    def allocate_network(self, context, share_server, share_network,
                         count=None, **kwargs):
        """Allocate network resources using given network information."""
        if count is None:
            count = self.get_network_allocations_number()
        if count:
            kwargs.update(count=count)
            self.network_api.allocate_network(
                context, share_server, share_network, **kwargs)

    def deallocate_network(self, context, share_server_id):
        """Deallocate network resources for the given share server."""
        if self.get_network_allocations_number():
            self.network_api.deallocate_network(context, share_server_id)

    def setup_server(self, *args, **kwargs):
        if self.driver_handles_share_servers:
            return self._setup_server(*args, **kwargs)
        else:
            LOG.debug(
                "Skipping step 'setup share server', because driver is "
                "enabled with mode when Manila does not handle share servers.")

    def _setup_server(self, network_info, metadata=None):
        """Sets up and configures share server with given network parameters.

        Redefine it within share driver when it is going to handle share
        servers.
        """
        raise NotImplementedError()

    def manage_existing(self, share, driver_options):
        """Brings an existing share under Manila management.

        If provided share is not valid, then raise a
        ManageInvalidShare exception, specifying a reason for the failure.

        The share has a share_type, and the driver can inspect that and
        compare against the properties of the referenced backend share.
        If they are incompatible, raise a
        ManageExistingShareTypeMismatch, specifying a reason for the failure.

        :param share: Share model
        :param driver_options: Driver-specific options provided by admin.
        :return: share_update dictionary with required key 'size',
                 which should contain size of the share.
        """
        raise NotImplementedError()

    def unmanage(self, share):
        """Removes the specified share from Manila management.

        Does not delete the underlying backend share.

        For most drivers, this will not need to do anything.  However, some
        drivers might use this call as an opportunity to clean up any
        Manila-specific configuration that they have associated with the
        backend share.

        If provided share cannot be unmanaged, then raise an
        UnmanageInvalidShare exception, specifying a reason for the failure.
        """

    def extend_share(self, share, new_size, share_server=None):
        """Extends size of existing share.

        :param share: Share model
        :param new_size: New size of share (new_size > share['size'])
        :param share_server: Optional -- Share server model
        """
        raise NotImplementedError()

    def teardown_server(self, *args, **kwargs):
        if self.driver_handles_share_servers:
            return self._teardown_server(*args, **kwargs)
        else:
            LOG.debug(
                "Skipping step 'teardown share server', because driver is "
                "enabled with mode when Manila does not handle share servers.")

    def _teardown_server(self, server_details, security_services=None):
        """Tears down share server.

        Redefine it within share driver when it is going to handle share
        servers.
        """
        raise NotImplementedError()

    def _update_share_stats(self, data=None):
        """Retrieve stats info from share group.

        :param data: dict -- dict with key-value pairs to redefine common ones.
        """

        LOG.debug("Updating share stats.")
        backend_name = (self.configuration.safe_get('share_backend_name') or
                        CONF.share_backend_name)

        # Note(zhiteng): These information are driver/backend specific,
        # each driver may define these values in its own config options
        # or fetch from driver specific configuration file.
        common = dict(
            share_backend_name=backend_name or 'Generic_NFS',
            driver_handles_share_servers=self.driver_handles_share_servers,
            vendor_name='Open Source',
            driver_version='1.0',
            storage_protocol=None,
            total_capacity_gb='infinite',
            free_capacity_gb='infinite',
            reserved_percentage=0,
            QoS_support=False)
        if isinstance(data, dict):
            common.update(data)
        self._stats = common
