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
from manila.i18n import _, _LE
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
        help='The backend name for a given driver implementation.'),
    cfg.StrOpt(
        'network_config_group',
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
    cfg.FloatOpt(
        'max_over_subscription_ratio',
        default=20.0,
        help='Float representation of the over subscription ratio '
             'when thin provisioning is involved. Default ratio is '
             '20.0, meaning provisioned capacity can be 20 times '
             'the total physical capacity. If the ratio is 10.5, it '
             'means provisioned capacity can be 10.5 times the '
             'total physical capacity. A ratio of 1.0 means '
             'provisioned capacity cannot exceed the total physical '
             'capacity. A ratio lower than 1.0 is invalid.'),
    cfg.ListOpt(
        'migration_ignore_files',
        default=['lost+found'],
        help="List of files and folders to be ignored when migrating shares. "
             "Items should be names (not including any path)."),
    cfg.StrOpt(
        'share_mount_template',
        default='mount -vt %(proto)s %(export)s %(path)s',
        help="The template for mounting shares for this backend. Must specify "
             "the executable with all necessary parameters for the protocol "
             "supported. 'proto' template element may not be required if "
             "included in the command. 'export' and 'path' template elements "
             "are required. It is advisable to separate different commands "
             "per backend."),
    cfg.StrOpt(
        'share_unmount_template',
        default='umount -v %(path)s',
        help="The template for unmounting shares for this backend. Must "
             "specify the executable with all necessary parameters for the "
             "protocol supported. 'path' template element is required. It is "
             "advisable to separate different commands per backend."),
    cfg.BoolOpt(
        'migration_readonly_rules_support',
        default=True,
        deprecated_name='migration_readonly_support',
        help="Specify whether read only access rule mode is supported in this "
             "backend."),
    cfg.StrOpt(
        "admin_network_config_group",
        help="If share driver requires to setup admin network for share, then "
             "define network plugin config options in some separate config "
             "group and set its name here. Used only with another "
             "option 'driver_handles_share_servers' set to 'True'."),
    # Replication option/s
    cfg.StrOpt(
        "replication_domain",
        default=None,
        help="A string specifying the replication domain that the backend "
             "belongs to. This option needs to be specified the same in the "
             "configuration sections of all backends that support "
             "replication between each other. If this option is not "
             "specified in the group, it means that replication is not "
             "enabled on the backend."),
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
            Drivers can support either both (indicated by a tuple/set/list with
            (True, False)) or only one of these approaches. So, it is allowed
            to be 'True' when share driver does support handling of share
            servers and allowed to be 'False' when it does support usage of
            unhandled share-servers that are not tracked by Manila.
            Share drivers are allowed to work only in one of two possible
            driver modes, that is why only one should be chosen.
        :param config_opts: tuple, list or set of config option lists
            that should be registered in driver's configuration right after
            this attribute is created. Useful for usage with mixin classes.
        """
        super(ShareDriver, self).__init__()
        self.configuration = kwargs.get('configuration', None)
        self.initialized = False
        self._stats = {}

        self.pools = []
        if self.configuration:
            self.configuration.append_config_values(share_opts)
            network_config_group = (self.configuration.network_config_group or
                                    self.configuration.config_group)
            admin_network_config_group = (
                self.configuration.admin_network_config_group)
        else:
            network_config_group = None
            admin_network_config_group = (
                CONF.admin_network_config_group)

        self._verify_share_server_handling(driver_handles_share_servers)
        if self.driver_handles_share_servers:
            # Enable common network
            self.network_api = network.API(
                config_group_name=network_config_group)

            # Enable admin network
            if admin_network_config_group:
                self._admin_network_api = network.API(
                    config_group_name=admin_network_config_group,
                    label='admin')

        for config_opt_set in kwargs.get('config_opts', []):
            self.configuration.append_config_values(config_opt_set)

        if hasattr(self, 'init_execute_mixin'):
            # Instance with 'ExecuteMixin'
            self.init_execute_mixin(*args, **kwargs)  # pylint: disable=E1101
        if hasattr(self, 'init_ganesha_mixin'):
            # Instance with 'GaneshaMixin'
            self.init_ganesha_mixin(*args, **kwargs)  # pylint: disable=E1101

    @property
    def admin_network_api(self):
        if hasattr(self, '_admin_network_api'):
            return self._admin_network_api

    @property
    def driver_handles_share_servers(self):
        if self.configuration:
            return self.configuration.safe_get('driver_handles_share_servers')
        return CONF.driver_handles_share_servers

    @property
    def replication_domain(self):
        if self.configuration:
            return self.configuration.safe_get('replication_domain')
        return CONF.replication_domain

    def _verify_share_server_handling(self, driver_handles_share_servers):
        """Verifies driver_handles_share_servers and given configuration."""
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

    def migration_start(self, context, share_ref, share_server, host,
                        dest_driver_migration_info, notify):
        """Is called to perform 1st phase of driver migration of a given share.

        Driver should implement this method if willing to perform migration
        in an optimized way, useful for when driver understands destination
        backend.
        :param context: The 'context.RequestContext' object for the request.
        :param share_ref: Reference to the share being migrated.
        :param share_server: Share server model or None.
        :param host: Destination host and its capabilities.
        :param dest_driver_migration_info: Migration information provided by
        destination host.
        :param notify: whether the migration should complete or wait for
        2nd phase call. Driver may throw exception when validating this
        parameter, exception if does not support 1-phase or 2-phase approach.
        :returns: Boolean value indicating if driver migration succeeded.
        :returns: Dictionary containing a model update.
        """
        return None, None

    def migration_complete(self, context, share_ref, share_server,
                           dest_driver_migration_info):
        """Is called to perform 2nd phase of driver migration of a given share.

        If driver is implementing 2-phase migration, this method should
        perform tasks related to the 2nd phase of migration, thus completing
        it.
        :param context: The 'context.RequestContext' object for the request.
        :param share_ref: Reference to the share being migrated.
        :param share_server: Share server model or None.
        :param dest_driver_migration_info: Migration information provided by
        destination host.
        :returns: Dictionary containing a model update.
        """
        return None

    def migration_cancel(self, context, share_ref, share_server,
                         dest_driver_migration_info):
        """Is called to cancel driver migration.

        If possible, driver can implement a way to cancel an in-progress
        migration.
        :param context: The 'context.RequestContext' object for the request.
        :param share_ref: Reference to the share being migrated.
        :param share_server: Share server model or None.
        :param dest_driver_migration_info: Migration information provided by
        destination host.
        """
        raise NotImplementedError()

    def migration_get_progress(self, context, share_ref, share_server,
                               dest_driver_migration_info):
        """Is called to get migration progress.

        If possible, driver can implement a way to return migration progress
        information.
        :param context: The 'context.RequestContext' object for the request.
        :param share_ref: Reference to the share being migrated.
        :param share_server: Share server model or None.
        :param dest_driver_migration_info: Migration information provided by
        destination host.
        :return: A dictionary with 'total_progress' field containing the
        percentage value.
        """
        raise NotImplementedError()

    def migration_get_driver_info(self, context, share, share_server):
        """Is called to provide necessary driver migration logic.

        :param context: The 'context.RequestContext' object for the request.
        :param share: Reference to the share being migrated.
        :param share_server: Share server model or None.
        :return: A dictionary with migration information.
        """
        return None

    def migration_get_info(self, context, share, share_server):
        """Is called to provide necessary generic migration logic.

        :param context: The 'context.RequestContext' object for the request.
        :param share: Reference to the share being migrated.
        :param share_server: Share server model or None.
        :return: A dictionary with migration information.
        """
        mount_template = self._get_mount_command(context, share, share_server)

        unmount_template = self._get_unmount_command(context, share,
                                                     share_server)

        return {'mount': mount_template,
                'unmount': unmount_template}

    def _get_mount_command(self, context, share_instance, share_server):
        """Is called to delegate mounting share logic."""

        mount_template = self.configuration.safe_get('share_mount_template')

        mount_export = self._get_mount_export(share_instance, share_server)

        format_template = {'proto': share_instance['share_proto'].lower(),
                           'export': mount_export,
                           'path': '%(path)s'}

        return mount_template % format_template

    def _get_mount_export(self, share_instance, share_server):
        # NOTE(ganso): If drivers want to override the export_location IP,
        # they can do so using this configuration. This method can also be
        # overridden if necessary.
        path = next((x['path'] for x in share_instance['export_locations']
                    if x['is_admin_only']), None)
        if not path:
            path = share_instance['export_locations'][0]['path']
        return path

    def _get_unmount_command(self, context, share_instance, share_server):
        return self.configuration.safe_get('share_unmount_template')

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

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules for given share.

        Drivers should support 2 different cases in this method:
        1. Recovery after error - 'access_rules' contains all access_rules,
        'add_rules' and 'delete_rules' shall be empty. Driver should clear any
        existent access rules and apply all access rules for given share.
        This recovery is made at driver start up.

        2. Adding/Deleting of several access rules - 'access_rules' contains
        all access_rules, 'add_rules' and 'delete_rules' contain rules which
        should be added/deleted. Driver can ignore rules in 'access_rules' and
        apply only rules from 'add_rules' and 'delete_rules'.

        Drivers must be mindful of this call for share replicas. When
        'update_access' is called on one of the replicas, the call is likely
        propagated to all replicas belonging to the share, especially when
        individual rules are added or removed. If a particular access rule
        does not make sense to the driver in the context of a given replica,
        the driver should be careful to report a correct behavior, and take
        meaningful action. For example, if R/W access is requested on a
        replica that is part of a "readable" type replication; R/O access
        may be added by the driver instead of R/W. Note that raising an
        exception *will* result in the access_rules_status on the replica,
        and the share itself being "out_of_sync". Drivers can sync on the
        valid access rules that are provided on the create_replica and
        promote_replica calls.

        :param context: Current context
        :param share: Share model with share data.
        :param access_rules: All access rules for given share
        :param add_rules: Empty List or List of access rules which should be
               added. access_rules already contains these rules.
        :param delete_rules: Empty List or List of access rules which should be
               removed. access_rules doesn't contain these rules.
        :param share_server: None or Share server model
        """
        raise NotImplementedError()

    def check_for_setup_error(self):
        """Check for setup error."""
        max_ratio = self.configuration.safe_get('max_over_subscription_ratio')
        if not max_ratio or float(max_ratio) < 1.0:
            msg = (_("Invalid max_over_subscription_ratio '%s'. "
                     "Valid value should be >= 1.0.") % max_ratio)
            raise exception.InvalidParameterValue(err=msg)

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

    def get_admin_network_allocations_number(self):
        return 0

    def allocate_network(self, context, share_server, share_network,
                         count=None, **kwargs):
        """Allocate network resources using given network information."""
        if count is None:
            count = self.get_network_allocations_number()
        if count:
            kwargs.update(count=count)
            self.network_api.allocate_network(
                context, share_server, share_network, **kwargs)

    def allocate_admin_network(self, context, share_server, count=None,
                               **kwargs):
        """Allocate admin network resources using given network information."""
        if count is None:
            count = self.get_admin_network_allocations_number()
        if count and not self.admin_network_api:
            msg = _("Admin network plugin is not set up.")
            raise exception.NetworkBadConfigurationException(reason=msg)
        elif count:
            kwargs.update(count=count)
            self.admin_network_api.allocate_network(
                context, share_server, **kwargs)

    def deallocate_network(self, context, share_server_id):
        """Deallocate network resources for the given share server."""
        if self.get_network_allocations_number():
            self.network_api.deallocate_network(context, share_server_id)

    def choose_share_server_compatible_with_share(self, context, share_servers,
                                                  share, snapshot=None,
                                                  consistency_group=None):
        """Method that allows driver to choose share server for provided share.

        If compatible share-server is not found, method should return None.

        :param context: Current context
        :param share_servers: list with share-server models
        :param share:  share model
        :param snapshot: snapshot model
        :param consistency_group: ConsistencyGroup model with shares
        :returns: share-server or None
        """
        # If creating in a consistency group, use its share server
        if consistency_group:
            for share_server in share_servers:
                if (consistency_group.get('share_server_id') ==
                        share_server['id']):
                    return share_server
            return None

        return share_servers[0] if share_servers else None

    def choose_share_server_compatible_with_cg(self, context, share_servers,
                                               cg_ref, cgsnapshot=None):

        return share_servers[0] if share_servers else None

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

    def manage_existing_snapshot(self, snapshot, driver_options):
        """Brings an existing snapshot under Manila management.

        If provided snapshot is not valid, then raise a
        ManageInvalidShareSnapshot exception, specifying a reason for
        the failure.

        :param snapshot: ShareSnapshotInstance model with ShareSnapshot data.
                         Example:
                         {'id': <instance id>, 'snapshot_id': < snapshot id>,
                          'provider_location': <location>, ......}
        :param driver_options: Optional driver-specific options provided
                               by admin. Example:
                               {'key': 'value', ......}
        :return: model_update dictionary with required key 'size',
                 which should contain size of the share snapshot.
        """
        raise NotImplementedError()

    def unmanage_snapshot(self, snapshot):
        """Removes the specified snapshot from Manila management.

        Does not delete the underlying backend share snapshot.

        For most drivers, this will not need to do anything.  However, some
        drivers might use this call as an opportunity to clean up any
        Manila-specific configuration that they have associated with the
        backend share snapshot.

        If provided share snapshot cannot be unmanaged, then raise an
        UnmanageInvalidShareSnapshot exception, specifying a reason for
        the failure.
        """

    def extend_share(self, share, new_size, share_server=None):
        """Extends size of existing share.

        :param share: Share model
        :param new_size: New size of share (new_size > share['size'])
        :param share_server: Optional -- Share server model
        """
        raise NotImplementedError()

    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share.

        If consumed space on share larger than new_size driver should raise
        ShareShrinkingPossibleDataLoss exception:
        raise ShareShrinkingPossibleDataLoss(share_id=share['id'])

        :param share: Share model
        :param new_size: New size of share (new_size < share['size'])
        :param share_server: Optional -- Share server model

        :raises ShareShrinkingPossibleDataLoss, NotImplementedError
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

    def _has_redefined_driver_methods(self, methods):
        """Returns boolean as a result of methods presence and redefinition."""
        if not isinstance(methods, (set, list, tuple)):
            methods = (methods, )
        for method_name in methods:
            method = getattr(type(self), method_name, None)
            if (not method or method == getattr(ShareDriver, method_name)):
                return False
        return True

    @property
    def snapshots_are_supported(self):
        if not hasattr(self, '_snapshots_are_supported'):
            methods = (
                "create_snapshot",
                "delete_snapshot",
                "create_share_from_snapshot")
            # NOTE(vponomaryov): calculate default value for
            # stat 'snapshot_support' based on implementation of
            # appropriate methods of this base driver class.
            self._snapshots_are_supported = self._has_redefined_driver_methods(
                methods)
        return self._snapshots_are_supported

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
            total_capacity_gb='unknown',
            free_capacity_gb='unknown',
            reserved_percentage=0,
            qos=False,
            pools=self.pools or None,
            snapshot_support=self.snapshots_are_supported,
            replication_domain=self.replication_domain,
        )
        if isinstance(data, dict):
            common.update(data)
        self._stats = common

    def get_share_server_pools(self, share_server):
        """Return list of pools related to a particular share server.

        :param share_server: ShareServer class instance.
        """
        return []

    def create_consistency_group(self, context, cg_dict, share_server=None):
        """Create a consistency group.

        :param context:
        :param cg_dict: The consistency group details
            EXAMPLE:
            {
            'status': 'creating',
            'project_id': '13c0be6290934bd98596cfa004650049',
            'user_id': 'a0314a441ca842019b0952224aa39192',
            'description': None,
            'deleted': 'False',
            'created_at': datetime.datetime(2015, 8, 10, 15, 14, 6),
            'updated_at': None,
            'source_cgsnapshot_id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
            'host': 'openstack2@cmodeSSVMNFS',
            'deleted_at': None,
            'share_types': [<models.ConsistencyGroupShareTypeMapping>],
            'id': 'eda52174-0442-476d-9694-a58327466c14',
            'name': None
            }
        :returns: (cg_model_update, share_update_list)
            cg_model_update - a dict containing any values to be updated
            for the CG in the database. This value may be None.

        """
        raise NotImplementedError()

    def create_consistency_group_from_cgsnapshot(self, context, cg_dict,
                                                 cgsnapshot_dict,
                                                 share_server=None):
        """Create a consistency group from a cgsnapshot.

        :param context:
        :param cg_dict: The consistency group details
            EXAMPLE:
            .. code::

                {
                'status': 'creating',
                'project_id': '13c0be6290934bd98596cfa004650049',
                'user_id': 'a0314a441ca842019b0952224aa39192',
                'description': None,
                'deleted': 'False',
                'created_at': datetime.datetime(2015, 8, 10, 15, 14, 6),
                'updated_at': None,
                'source_cgsnapshot_id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
                'host': 'openstack2@cmodeSSVMNFS',
                'deleted_at': None,
                'shares': [<models.Share>], # The new shares being created
                'share_types': [<models.ConsistencyGroupShareTypeMapping>],
                'id': 'eda52174-0442-476d-9694-a58327466c14',
                'name': None
                }
        :param cgsnapshot_dict: The cgsnapshot details
            EXAMPLE:
            .. code::

                {
                'status': 'available',
                'project_id': '13c0be6290934bd98596cfa004650049',
                'user_id': 'a0314a441ca842019b0952224aa39192',
                'description': None,
                'deleted': '0',
                'created_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                'updated_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                'consistency_group_id': '4b04fdc3-00b9-4909-ba1a-06e9b3f88b67',
                'cgsnapshot_members': [
                    {
                     'status': 'available',
                     'share_type_id': '1a9ed31e-ee70-483d-93ba-89690e028d7f',
                     'user_id': 'a0314a441ca842019b0952224aa39192',
                     'deleted': 'False',
                     'created_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                     'share': <models.Share>,
                     'updated_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                     'share_proto': 'NFS',
                     'project_id': '13c0be6290934bd98596cfa004650049',
                     'cgsnapshot_id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
                     'deleted_at': None,
                     'id': '6813e06b-a8f5-4784-b17d-f3e91afa370e',
                     'size': 1
                    }
                ],
                'deleted_at': None,
                'id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
                'name': None
                }
        :return: (cg_model_update, share_update_list)
            cg_model_update - a dict containing any values to be updated
            for the CG in the database. This value may be None.

            share_update_list - a list of dictionaries containing dicts for
            every share created in the CG. Any share dicts should at a minimum
            contain the 'id' key and 'export_locations'. Export locations
            should be in the same format as returned by a share_create. This
            list may be empty or None.
            EXAMPLE:
            .. code::

                [{'id': 'uuid', 'export_locations': ['export_path']}]
        """
        raise NotImplementedError()

    def delete_consistency_group(self, context, cg_dict, share_server=None):
        """Delete a consistency group

        :param context: The request context
        :param cg_dict: The consistency group details
            EXAMPLE:
            .. code::

                {
                'status': 'creating',
                'project_id': '13c0be6290934bd98596cfa004650049',
                'user_id': 'a0314a441ca842019b0952224aa39192',
                'description': None,
                'deleted': 'False',
                'created_at': datetime.datetime(2015, 8, 10, 15, 14, 6),
                'updated_at': None,
                'source_cgsnapshot_id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
                'host': 'openstack2@cmodeSSVMNFS',
                'deleted_at': None,
                'shares': [<models.Share>], # The new shares being created
                'share_types': [<models.ConsistencyGroupShareTypeMapping>],
                'id': 'eda52174-0442-476d-9694-a58327466c14',
                'name': None
                }
        :return: cg_model_update
            cg_model_update - a dict containing any values to be updated
            for the CG in the database. This value may be None.
        """
        raise NotImplementedError()

    def create_cgsnapshot(self, context, snap_dict, share_server=None):
        """Create a consistency group snapshot.

        :param context:
        :param snap_dict: The cgsnapshot details
            EXAMPLE:
            .. code::

                {
                'status': 'available',
                'project_id': '13c0be6290934bd98596cfa004650049',
                'user_id': 'a0314a441ca842019b0952224aa39192',
                'description': None,
                'deleted': '0',
                'created_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                'updated_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                'consistency_group_id': '4b04fdc3-00b9-4909-ba1a-06e9b3f88b67',
                'cgsnapshot_members': [
                    {
                     'status': 'available',
                     'share_type_id': '1a9ed31e-ee70-483d-93ba-89690e028d7f',
                     'user_id': 'a0314a441ca842019b0952224aa39192',
                     'deleted': 'False',
                     'created_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                     'share': <models.Share>,
                     'updated_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                     'share_proto': 'NFS',
                     'project_id': '13c0be6290934bd98596cfa004650049',
                     'cgsnapshot_id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
                     'deleted_at': None,
                     'id': '6813e06b-a8f5-4784-b17d-f3e91afa370e',
                     'size': 1
                    }
                ],
                'deleted_at': None,
                'id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
                'name': None
                }
        :return: (cgsnapshot_update, member_update_list)
            cgsnapshot_update - a dict containing any values to be updated
            for the CGSnapshot in the database. This value may be None.

            member_update_list -  a list of dictionaries containing for every
            member of the cgsnapshot. Each dict should contains values to be
            updated for teh CGSnapshotMember in the database. This list may be
            empty or None.
        """
        raise NotImplementedError()

    def delete_cgsnapshot(self, context, snap_dict, share_server=None):
        """Delete a consistency group snapshot

        :param context:
        :param snap_dict: The cgsnapshot details
            EXAMPLE:
            .. code::

                {
                'status': 'available',
                'project_id': '13c0be6290934bd98596cfa004650049',
                'user_id': 'a0314a441ca842019b0952224aa39192',
                'description': None,
                'deleted': '0',
                'created_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                'updated_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                'consistency_group_id': '4b04fdc3-00b9-4909-ba1a-06e9b3f88b67',
                'cgsnapshot_members': [
                    {
                     'status': 'available',
                     'share_type_id': '1a9ed31e-ee70-483d-93ba-89690e028d7f',
                     'share_id': 'e14b5174-e534-4f35-bc4f-fe81c1575d6f',
                     'user_id': 'a0314a441ca842019b0952224aa39192',
                     'deleted': 'False',
                     'created_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                     'share': <models.Share>,
                     'updated_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                     'share_proto': 'NFS',
                     'project_id': '13c0be6290934bd98596cfa004650049',
                     'cgsnapshot_id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
                     'deleted_at': None,
                     'id': '6813e06b-a8f5-4784-b17d-f3e91afa370e',
                     'size': 1
                    }
                ],
                'deleted_at': None,
                'id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
                'name': None
                }
        :return: (cgsnapshot_update, member_update_list)
            cgsnapshot_update - a dict containing any values to be updated
            for the CGSnapshot in the database. This value may be None.
        """
        raise NotImplementedError()

    def get_periodic_hook_data(self, context, share_instances):
        """Dedicated for update/extend of data for existing share instances.

        Redefine this method in share driver to be able to update/change/extend
        share instances data that will be used by periodic hook action.
        One of possible updates is add-on of "automount" CLI commands for each
        share instance for case of notification is enabled using 'hook'
        approach.

        :param context: Current context
        :param share_instances: share instances list provided by share manager
        :return: list of share instances.
        """
        return share_instances

    def create_replica(self, context, replica_list, new_replica,
                       access_rules, replica_snapshots, share_server=None):
        """Replicate the active replica to a new replica on this backend.

        NOTE: This call is made on the host that the new replica is
        being created upon.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share.
        This list also contains the replica to be created. The 'active'
        replica will have its 'replica_state' attr set to 'active'.
            EXAMPLE:
             .. code::

            [
                {
                'id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'in_sync',
                    ...
                'share_server_id': '4ce78e7b-0ef6-4730-ac2a-fd2defefbd05',
                'share_server': <models.ShareServer> or None,
                },
                {
                'id': '10e49c3e-aca9-483b-8c2d-1c337b38d6af',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'active',
                    ...
                'share_server_id': 'f63629b3-e126-4448-bec2-03f788f76094',
                'share_server': <models.ShareServer> or None,
                },
                {
                'id': 'e82ff8b6-65f0-11e5-9d70-feff819cdc9f',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'in_sync',
                    ...
                'share_server_id': '07574742-67ea-4dfd-9844-9fbd8ada3d87',
                'share_server': <models.ShareServer> or None,
                },
                ...
            ]
        :param new_replica: The share replica dictionary.
            EXAMPLE:
             .. code::

            {
            'id': 'e82ff8b6-65f0-11e5-9d70-feff819cdc9f',
            'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
            'deleted': False,
            'host': 'openstack2@cmodeSSVMNFS2',
            'status': 'creating',
            'scheduled_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
            'launched_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
            'terminated_at': None,
            'replica_state': 'out_of_sync',
            'availability_zone_id': 'f6e146d0-65f0-11e5-9d70-feff819cdc9f',
            'export_locations': [
                models.ShareInstanceExportLocations,
            ],
            'access_rules_status': 'out_of_sync',
            'share_network_id': '4ccd5318-65f1-11e5-9d70-feff819cdc9f',
            'share_server_id': 'e6155221-ea00-49ef-abf9-9f89b7dd900a',
            'share_server': <models.ShareServer> or None,
            }
        :param access_rules: A list of access rules that other instances of
        the share already obey. Drivers are expected to apply access rules
        to the new replica or disregard access rules that don't apply.
            EXAMPLE:
             .. code::
             [ {
             'id': 'f0875f6f-766b-4865-8b41-cccb4cdf1676',
             'deleted' = False,
             'share_id' = 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
             'access_type' = 'ip',
             'access_to' = '172.16.20.1',
             'access_level' = 'rw',
             }]
        :param replica_snapshots: List of dictionaries of snapshot instances
        for each snapshot of the share whose 'aggregate_status' property was
        reported to be 'available' when the share manager initiated this
        request. Each list member will have two sub dictionaries:
        'active_replica_snapshot' and 'share_replica_snapshot'. The 'active'
        replica snapshot corresponds to the instance of the snapshot on any
        of the 'active' replicas of the share while share_replica_snapshot
        corresponds to the snapshot instance for the specific replica that
        will need to exist on the new share replica that is being created.
        The driver needs to ensure that this snapshot instance is truly
        available before transitioning the replica from 'out_of_sync' to
        'in_sync'. Snapshots instances for snapshots that have an
        'aggregate_status' of 'creating' or 'deleting' will be polled for in
        the update_replicated_snapshot method.
            EXAMPLE:
             .. code::
             [ {
             'active_replica_snapshot': {
                'id': '8bda791c-7bb6-4e7b-9b64-fefff85ff13e',
                'share_instance_id': '10e49c3e-aca9-483b-8c2d-1c337b38d6af',
                'status': 'available',
                'provider_location': '/newton/share-snapshot-10e49c3e-aca9',
                ...
                },
             'share_replica_snapshot': {
                'id': '',
                'share_instance_id': 'e82ff8b6-65f0-11e5-9d70-feff819cdc9f',
                'status': 'available',
                'provider_location': None,
                    ...
                },
             }]
        :param share_server: <models.ShareServer> or None,
        Share server of the replica being created.
        :return: None or a dictionary containing export_locations,
        replica_state and access_rules_status. export_locations is a list of
        paths and replica_state is one of active, in_sync, out_of_sync or
        error. A backend supporting 'writable' type replication should return
        'active' as the replica_state. Export locations should be in the
        same format as returned during the create_share call.
            EXAMPLE:
            .. code::
            {
                'export_locations': [
                    {
                        'path': '172.16.20.22/sample/export/path',
                         'is_admin_only': False,
                         'metadata': {'some_key': 'some_value'},
                    },
                ],
                 'replica_state': 'in_sync',
                 'access_rules_status': 'in_sync',
            }
        """
        raise NotImplementedError()

    def delete_replica(self, context, replica_list, replica_snapshots,
                       replica, share_server=None):
        """Delete a replica.

        NOTE: This call is made on the host that hosts the replica being
        deleted.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share.
        This list also contains the replica to be deleted. The 'active'
        replica will have its 'replica_state' attr set to 'active'.
            EXAMPLE:
             .. code::

            [
                {
                'id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'in_sync',
                    ...
                'share_server_id': '4ce78e7b-0ef6-4730-ac2a-fd2defefbd05',
                'share_server': <models.ShareServer> or None,
                },
                {
                'id': '10e49c3e-aca9-483b-8c2d-1c337b38d6af',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'active',
                    ...
                'share_server_id': 'f63629b3-e126-4448-bec2-03f788f76094',
                'share_server': <models.ShareServer> or None,
                },
                {
                'id': 'e82ff8b6-65f0-11e5-9d70-feff819cdc9f',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'in_sync',
                    ...
                'share_server_id': '07574742-67ea-4dfd-9844-9fbd8ada3d87',
                'share_server': <models.ShareServer> or None,
                },
                ...
            ]
        :param replica: Dictionary of the share replica being deleted.
            EXAMPLE:
             .. code::

            {
            'id': 'e82ff8b6-65f0-11e5-9d70-feff819cdc9f',
            'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
            'deleted': False,
            'host': 'openstack2@cmodeSSVMNFS2',
            'status': 'available',
            'scheduled_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
            'launched_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
            'terminated_at': None,
            'replica_state': 'in_sync',
            'availability_zone_id': 'f6e146d0-65f0-11e5-9d70-feff819cdc9f',
            'export_locations': [
                models.ShareInstanceExportLocations
            ],
            'access_rules_status': 'out_of_sync',
            'share_network_id': '4ccd5318-65f1-11e5-9d70-feff819cdc9f',
            'share_server_id': '53099868-65f1-11e5-9d70-feff819cdc9f',
            'share_server': <models.ShareServer> or None,
            }
        :param replica_snapshots: A list of dictionaries containing snapshot
        instances that are associated with the share replica being deleted.
        No model updates are possible in this method. The driver should
        return when the cleanup is completed on the backend for both,
        the snapshots and the replica itself. Drivers must handle situations
        where the snapshot may not yet have finished 'creating' on this
        replica.
            EXAMPLE:
                 .. code::

                [
                    {
                    'id': '89dafd00-0999-4d23-8614-13eaa6b02a3b',
                    'snapshot_id': '3ce1caf7-0945-45fd-a320-714973e949d3',
                    'status: 'available',
                    'share_instance_id': 'e82ff8b6-65f0-11e5-9d70-feff819cdc9f'
                        ...
                    },
                    {
                    'id': '8bda791c-7bb6-4e7b-9b64-fefff85ff13e',
                    'snapshot_id': '13ee5cb5-fc53-4539-9431-d983b56c5c40',
                    'status: 'creating',
                    'share_instance_id': 'e82ff8b6-65f0-11e5-9d70-feff819cdc9f'
                        ...
                    },
                    ...
                ]
        :param share_server: <models.ShareServer> or None,
        Share server of the replica to be deleted.
        :return: None.
        :raises Exception. Any exception raised will set the share replica's
        'status' and 'replica_state' to 'error_deleting'. It will not affect
        snapshots belonging to this replica.
        """
        raise NotImplementedError()

    def promote_replica(self, context, replica_list, replica, access_rules,
                        share_server=None):
        """Promote a replica to 'active' replica state.

        NOTE: This call is made on the host that hosts the replica being
        promoted.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share.
        This list also contains the replica to be promoted. The 'active'
        replica will have its 'replica_state' attr set to 'active'.
            EXAMPLE:
             .. code::

            [
                {
                'id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'in_sync',
                    ...
                'share_server_id': '4ce78e7b-0ef6-4730-ac2a-fd2defefbd05',
                'share_server': <models.ShareServer> or None,
                },
                {
                'id': '10e49c3e-aca9-483b-8c2d-1c337b38d6af',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'active',
                    ...
                'share_server_id': 'f63629b3-e126-4448-bec2-03f788f76094',
                'share_server': <models.ShareServer> or None,
                },
                {
                'id': 'e82ff8b6-65f0-11e5-9d70-feff819cdc9f',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'in_sync',
                    ...
                'share_server_id': '07574742-67ea-4dfd-9844-9fbd8ada3d87',
                'share_server': <models.ShareServer> or None,
                },
                ...
            ]

        :param replica: Dictionary of the replica to be promoted.
            EXAMPLE:
             .. code::

            {
            'id': 'e82ff8b6-65f0-11e5-9d70-feff819cdc9f',
            'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
            'deleted': False,
            'host': 'openstack2@cmodeSSVMNFS2',
            'status': 'available',
            'scheduled_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
            'launched_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
            'terminated_at': None,
            'replica_state': 'in_sync',
            'availability_zone_id': 'f6e146d0-65f0-11e5-9d70-feff819cdc9f',
            'export_locations': [
                models.ShareInstanceExportLocations
            ],
            'access_rules_status': 'in_sync',
            'share_network_id': '4ccd5318-65f1-11e5-9d70-feff819cdc9f',
            'share_server_id': '07574742-67ea-4dfd-9844-9fbd8ada3d87',
            'share_server': <models.ShareServer> or None,
            }
        :param access_rules: A list of access rules that other instances of
        the share already obey.
        EXAMPLE:
             .. code::
             [ {
             'id': 'f0875f6f-766b-4865-8b41-cccb4cdf1676',
             'deleted' = False,
             'share_id' = 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
             'access_type' = 'ip',
             'access_to' = '172.16.20.1',
             'access_level' = 'rw',
             }]
        :param share_server: <models.ShareServer> or None,
        Share server of the replica to be promoted.
        :return: updated_replica_list or None
            The driver can return the updated list as in the request
            parameter. Changes that will be updated to the Database are:
            'export_locations', 'access_rules_status' and 'replica_state'.
        :raises Exception
            This can be any exception derived from BaseException. This is
            re-raised by the manager after some necessary cleanup. If the
            driver raises an exception during promotion, it is assumed
            that all of the replicas of the share are in an inconsistent
            state. Recovery is only possible through the periodic update
            call and/or administrator intervention to correct the 'status'
            of the affected replicas if they become healthy again.
        """
        raise NotImplementedError()

    def update_replica_state(self, context, replica_list, replica,
                             access_rules, replica_snapshots,
                             share_server=None):
        """Update the replica_state of a replica.

        NOTE: This call is made on the host which hosts the replica being
        updated.

        Drivers should fix replication relationships that were broken if
        possible inside this method.

        This method is called periodically by the share manager; and
        whenever requested by the administrator through the 'resync' API.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share.
        This list also contains the replica to be updated. The 'active'
        replica will have its 'replica_state' attr set to 'active'.
            EXAMPLE:
             .. code::

            [
                {
                'id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'in_sync',
                    ...
                'share_server_id': '4ce78e7b-0ef6-4730-ac2a-fd2defefbd05',
                'share_server': <models.ShareServer> or None,
                },
                {
                'id': '10e49c3e-aca9-483b-8c2d-1c337b38d6af',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'active',
                    ...
                'share_server_id': 'f63629b3-e126-4448-bec2-03f788f76094',
                'share_server': <models.ShareServer> or None,
                },
                {
                'id': 'e82ff8b6-65f0-11e5-9d70-feff819cdc9f',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'in_sync',
                    ...
                'share_server_id': '07574742-67ea-4dfd-9844-9fbd8ada3d87',
                'share_server': <models.ShareServer> or None,
                },
                ...
            ]
        :param replica: Dictionary of the replica being updated.
        Replica state will always be 'in_sync', 'out_of_sync', or 'error'.
        Replicas in 'active' state will not be passed via this parameter.
            EXAMPLE:
             .. code::

            {
            'id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
            'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
            'deleted': False,
            'host': 'openstack2@cmodeSSVMNFS1',
            'status': 'available',
            'scheduled_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
            'launched_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
            'terminated_at': None,
            'replica_state': 'in_sync',
            'availability_zone_id': 'e2c2db5c-cb2f-4697-9966-c06fb200cb80',
            'export_locations': [
                models.ShareInstanceExportLocations,
            ],
            'access_rules_status': 'in_sync',
            'share_network_id': '4ccd5318-65f1-11e5-9d70-feff819cdc9f',
            'share_server_id': '4ce78e7b-0ef6-4730-ac2a-fd2defefbd05',
            }
        :param access_rules: A list of access rules that other replicas of
        the share already obey. The driver could attempt to sync on any
        un-applied access_rules.
        EXAMPLE:
             .. code::
             [ {
             'id': 'f0875f6f-766b-4865-8b41-cccb4cdf1676',
             'deleted' = False,
             'share_id' = 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
             'access_type' = 'ip',
             'access_to' = '172.16.20.1',
             'access_level' = 'rw',
             }]
        :param replica_snapshots: List of dictionaries of snapshot instances
        for each snapshot of the share whose 'aggregate_status' property was
        reported to be 'available' when the share manager initiated this
        request. Each list member will have two sub dictionaries:
        'active_replica_snapshot' and 'share_replica_snapshot'. The 'active'
        replica snapshot corresponds to the instance of the snapshot on any
        of the 'active' replicas of the share while share_replica_snapshot
        corresponds to the snapshot instance for the specific replica being
        updated. The driver needs to ensure that this snapshot instance is
        truly available before transitioning from 'out_of_sync' to
        'in_sync'. Snapshots instances for snapshots that have an
        'aggregate_status' of 'creating' or 'deleting' will be polled for in
        the update_replicated_snapshot method.
         EXAMPLE:
             .. code::
             [ {
             'active_replica_snapshot': {
                'id': '8bda791c-7bb6-4e7b-9b64-fefff85ff13e',
                'share_instance_id': '10e49c3e-aca9-483b-8c2d-1c337b38d6af',
                'status': 'available',
                'provider_location': '/newton/share-snapshot-10e49c3e-aca9',
                ...
                },
             'share_replica_snapshot': {
             'id': ,
                'share_instance_id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
                'status': 'creating',
                'provider_location': None,
                    ...
                },
             }]
        :param share_server: <models.ShareServer> or None
        :return: replica_state
            replica_state - a str value denoting the replica_state that the
            replica can have. Valid values are 'in_sync' and 'out_of_sync'
            or None (to leave the current replica_state unchanged).
        """
        raise NotImplementedError()

    def create_replicated_snapshot(self, context, replica_list,
                                   replica_snapshots,
                                   share_server=None):
        """Create a snapshot on active instance and update across the replicas.

        NOTE: This call is made on the 'active' replica's host. Drivers
        are expected to transfer the snapshot created to the respective
        replicas.

        The driver is expected to return model updates to the share manager.
        If it was able to confirm the creation of any number of the snapshot
        instances passed in this interface, it can set their status to
        'available' as a cue for the share manager to set the progress attr
        to '100%'.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share.
        The 'active' replica will have its 'replica_state' attr set to
        'active'.
            EXAMPLE:
             .. code::

            [
                {
                'id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'in_sync',
                    ...
                'share_server_id': '4ce78e7b-0ef6-4730-ac2a-fd2defefbd05',
                'share_server': <models.ShareServer> or None,
                },
                {
                'id': '10e49c3e-aca9-483b-8c2d-1c337b38d6af',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'active',
                    ...
                'share_server_id': 'f63629b3-e126-4448-bec2-03f788f76094',
                'share_server': <models.ShareServer> or None,
                },
                ...
            ]
        :param replica_snapshots: List of all snapshot instances that track
         the snapshot across the replicas. All the instances will have their
         status attribute set to 'creating'.
            EXAMPLE:
             .. code::
             [
                {
                'id': 'd3931a93-3984-421e-a9e7-d9f71895450a',
                'snapshot_id': '13ee5cb5-fc53-4539-9431-d983b56c5c40',
                'status: 'creating',
                'progress': '0%',
                    ...
                },
                {
                'id': '8bda791c-7bb6-4e7b-9b64-fefff85ff13e',
                'snapshot_id': '13ee5cb5-fc53-4539-9431-d983b56c5c40',
                'status: 'creating',
                'progress': '0%',
                    ...
                },
                ...
            ]
        :param share_server: <models.ShareServer> or None
        :return: List of replica_snapshots, a list of dictionaries containing
        values that need to be updated on the database for the snapshot
        instances being created.
        :raises: Exception. Any exception in this method will set all
        instances to 'error'.
        """
        raise NotImplementedError()

    def delete_replicated_snapshot(self, context, replica_list,
                                   replica_snapshots, share_server=None):
        """Delete a snapshot by deleting its instances across the replicas.

        NOTE: This call is made on the 'active' replica's host, since
        drivers may not be able to delete the snapshot from an individual
        replica.

        The driver is expected to return model updates to the share manager.
        If it was able to confirm the removal of any number of the snapshot
        instances passed in this interface, it can set their status to
        'deleted' as a cue for the share manager to clean up that instance
        from the database.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share.
        The 'active' replica will have its 'replica_state' attr set to
        'active'.
            EXAMPLE:
             .. code::

            [
                {
                'id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'in_sync',
                    ...
                'share_server_id': '4ce78e7b-0ef6-4730-ac2a-fd2defefbd05',
                'share_server': <models.ShareServer> or None,
                },
                {
                'id': '10e49c3e-aca9-483b-8c2d-1c337b38d6af',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'active',
                    ...
                'share_server_id': 'f63629b3-e126-4448-bec2-03f788f76094',
                'share_server': <models.ShareServer> or None,
                },
                ...
            ]
        :param replica_snapshots: List of all snapshot instances that track
         the snapshot across the replicas. All the instances will have their
         status attribute set to 'deleting'.
         EXAMPLE:
             .. code::
             [
                {
                'id': 'd3931a93-3984-421e-a9e7-d9f71895450a',
                'snapshot_id': '13ee5cb5-fc53-4539-9431-d983b56c5c40',
                'status': 'deleting',
                'progress': '100%',
                    ...
                },
                {
                'id': '8bda791c-7bb6-4e7b-9b64-fefff85ff13e',
                'snapshot_id': '13ee5cb5-fc53-4539-9431-d983b56c5c40',
                'status: 'deleting',
                'progress': '100%',
                    ...
                },
                ...
            ]
        :param share_server: <models.ShareServer> or None
        :return: List of replica_snapshots, a list of dictionaries containing
        values that need to be updated on the database for the snapshot
        instances being deleted. To confirm the deletion of the snapshot
        instance, set the 'status' attribute of the instance to
        'deleted'(constants.STATUS_DELETED).
        :raises: Exception. Any exception in this method will set all
        instances to 'error_deleting'.
        """
        raise NotImplementedError()

    def update_replicated_snapshot(self, context, replica_list,
                                   share_replica, replica_snapshots,
                                   replica_snapshot, share_server=None):
        """Update the status of a snapshot instance that lives on a replica.

        NOTE: For DR and Readable styles of replication, this call is made on
        the replica's host and not the 'active' replica's host.

        This method is called periodically by the share manager. It will
        query for snapshot instances that track the parent snapshot across
        non-'active' replicas. Drivers can expect the status of the instance to
        be 'creating' or 'deleting'. If the driver sees that a snapshot
        instance has been removed from the replica's backend and the
        instance status was set to 'deleting', it is expected to raise a
        SnapshotResourceNotFound exception. All other exceptions will set the
        snapshot instance status to 'error'. If the instance was not in
        'deleting' state, raising a SnapshotResourceNotFound will set the
        instance status to 'error'.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share.
        The 'active' replica will have its 'replica_state' attr set to
        'active'.
            EXAMPLE:
             .. code::

            [
                {
                'id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'in_sync',
                    ...
                'share_server_id': '4ce78e7b-0ef6-4730-ac2a-fd2defefbd05',
                'share_server': <models.ShareServer> or None,
                },
                {
                'id': '10e49c3e-aca9-483b-8c2d-1c337b38d6af',
                'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                'replica_state': 'active',
                    ...
                'share_server_id': 'f63629b3-e126-4448-bec2-03f788f76094',
                'share_server': <models.ShareServer> or None,
                },
                ...
            ]
        :param share_replica: Dictionary of the replica the snapshot instance
        is meant to be associated with. Replicas in 'active' replica_state
        will not be passed via this parameter.
            EXAMPLE:
             .. code::

            {
            'id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
            'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
            'deleted': False,
            'host': 'openstack2@cmodeSSVMNFS1',
            'status': 'available',
            'scheduled_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
            'launched_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
            'terminated_at': None,
            'replica_state': 'in_sync',
            'availability_zone_id': 'e2c2db5c-cb2f-4697-9966-c06fb200cb80',
            'export_locations': [
                models.ShareInstanceExportLocations,
            ],
            'access_rules_status': 'in_sync',
            'share_network_id': '4ccd5318-65f1-11e5-9d70-feff819cdc9f',
            'share_server_id': '4ce78e7b-0ef6-4730-ac2a-fd2defefbd05',
            }
        :param replica_snapshots: List of all snapshot instances that track
         the snapshot across the replicas. This will include the instance
         being updated as well.
         EXAMPLE:
             .. code::
             [
                {
                'id': 'd3931a93-3984-421e-a9e7-d9f71895450a',
                'snapshot_id': '13ee5cb5-fc53-4539-9431-d983b56c5c40',
                    ...
                },
                {
                'id': '8bda791c-7bb6-4e7b-9b64-fefff85ff13e',
                'snapshot_id': '13ee5cb5-fc53-4539-9431-d983b56c5c40',
                    ...
                },
                ...
            ]
        :param replica_snapshot: Dictionary of the snapshot instance to be
        updated. replica_snapshot will be in 'creating' or 'deleting'
        states when sent via this parameter.
            EXAMPLE:
             .. code::

            {
            'name': 'share-snapshot-18825630-574f-4912-93bb-af4611ef35a2',
            'share_id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
            'share_name': 'share-d487b88d-e428-4230-a465-a800c2cce5f8',
            'status': 'creating',
            'id': '18825630-574f-4912-93bb-af4611ef35a2',
            'deleted': False,
            'created_at': datetime.datetime(2016, 8, 3, 0, 5, 58),
            'share': <models.ShareInstance>,
            'updated_at': datetime.datetime(2016, 8, 3, 0, 5, 58),
            'share_instance_id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
            'snapshot_id': '13ee5cb5-fc53-4539-9431-d983b56c5c40',
            'progress': '0%',
            'deleted_at': None,
            'provider_location': None,
            }
        :param share_server: <models.ShareServer> or None
        :return: replica_snapshot_model_update, a dictionary containing
        values that need to be updated on the database for the snapshot
        instance that represents the snapshot on the replica.
        :raises: exception.SnapshotResourceNotFound for
        snapshots that are not found on the backend and their status was
        'deleting'.
        """
        raise NotImplementedError()
