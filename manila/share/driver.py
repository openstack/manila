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

import six
import time

from oslo_config import cfg
from oslo_log import log

from manila import exception
from manila.i18n import _
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
        default='mount -vt %(proto)s %(options)s %(export)s %(path)s',
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
    cfg.DictOpt(
        'protocol_access_mapping',
        default={
            'ip': ['nfs'],
            'user': ['cifs'],
        },
        help="Protocol access mapping for this backend. Should be a "
             "dictionary comprised of "
             "{'access_type1': ['share_proto1', 'share_proto2'],"
             " 'access_type2': ['share_proto2', 'share_proto3']}."),
    cfg.BoolOpt(
        'migration_readonly_rules_support',
        default=True,
        deprecated_for_removal=True,
        deprecated_reason="All drivers are now required to support read-only "
                          "access rules.",
        deprecated_name='migration_readonly_support',
        help="Specify whether read only access rule mode is supported in this "
             "backend. Obsolete."),
    cfg.StrOpt(
        "admin_network_config_group",
        help="If share driver requires to setup admin network for share, then "
             "define network plugin config options in some separate config "
             "group and set its name here. Used only with another "
             "option 'driver_handles_share_servers' set to 'True'."),
    # Replication option/s
    cfg.StrOpt(
        "replication_domain",
        help="A string specifying the replication domain that the backend "
             "belongs to. This option needs to be specified the same in the "
             "configuration sections of all backends that support "
             "replication between each other. If this option is not "
             "specified in the group, it means that replication is not "
             "enabled on the backend."),
    cfg.StrOpt('filter_function',
               help='String representation for an equation that will be '
                    'used to filter hosts.'),
    cfg.StrOpt('goodness_function',
               help='String representation for an equation that will be '
                    'used to determine the goodness of a host.'),
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
    cfg.BoolOpt('ganesha_rados_store_enable',
                default=False,
                help='Persist Ganesha exports and export counter '
                     'in Ceph RADOS objects, highly available storage.'),
    cfg.StrOpt('ganesha_rados_store_pool_name',
               help='Name of the Ceph RADOS pool to store Ganesha exports '
                    'and export counter.'),
    cfg.StrOpt('ganesha_rados_export_counter',
               default='ganesha-export-counter',
               help='Name of the Ceph RADOS object used as the Ganesha '
                    'export counter.'),
    cfg.StrOpt('ganesha_rados_export_index',
               default='ganesha-export-index',
               help='Name of the Ceph RADOS object used to store a list '
                    'of the export RADOS object URLS.'),
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
                LOG.exception("Recovering from a failed execute. "
                              "Try number %s", tries)
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
        self.ip_versions = None
        self.ipv6_implemented = False

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

    def migration_check_compatibility(
            self, context, source_share, destination_share,
            share_server=None, destination_share_server=None):
        """Checks destination compatibility for migration of a given share.

        .. note::
            Is called to test compatibility with destination backend.

        Driver should check if it is compatible with destination backend so
        driver-assisted migration can proceed.

        :param context: The 'context.RequestContext' object for the request.
        :param source_share: Reference to the share to be migrated.
        :param destination_share: Reference to the share model to be used by
            migrated share.
        :param share_server: Share server model or None.
        :param destination_share_server: Destination Share server model or
            None.
        :return: A dictionary containing values indicating if destination
            backend is compatible, if share can remain writable during
            migration, if it can preserve all file metadata and if it can
            perform migration of given share non-disruptively.

            Example::

                {
                    'compatible': True,
                    'writable': True,
                    'preserve_metadata': True,
                    'nondisruptive': True,
                    'preserve_snapshots': True,
                }

        """
        return {
            'compatible': False,
            'writable': False,
            'preserve_metadata': False,
            'nondisruptive': False,
            'preserve_snapshots': False,
        }

    def migration_start(
            self, context, source_share, destination_share,
            source_snapshots, snapshot_mappings, share_server=None,
            destination_share_server=None):
        """Starts migration of a given share to another host.

        .. note::
           Is called in source share's backend to start migration.

        Driver should implement this method if willing to perform migration
        in a driver-assisted way, useful for when source share's backend driver
        is compatible with destination backend driver. This method should
        start the migration procedure in the backend and end. Following steps
        should be done in 'migration_continue'.

        :param context: The 'context.RequestContext' object for the request.
        :param source_share: Reference to the original share model.
        :param destination_share: Reference to the share model to be used by
            migrated share.
        :param source_snapshots: List of snapshots owned by the source share.
        :param snapshot_mappings: Mapping of source snapshot IDs to
            destination snapshot models.
        :param share_server: Share server model or None.
        :param destination_share_server: Destination Share server model or
            None.
        """
        raise NotImplementedError()

    def migration_continue(
            self, context, source_share, destination_share, source_snapshots,
            snapshot_mappings, share_server=None,
            destination_share_server=None):
        """Continues migration of a given share to another host.

        .. note::
            Is called in source share's backend to continue migration.

        Driver should implement this method to continue monitor the migration
        progress in storage and perform following steps until 1st phase is
        completed.

        :param context: The 'context.RequestContext' object for the request.
        :param source_share: Reference to the original share model.
        :param destination_share: Reference to the share model to be used by
            migrated share.
        :param source_snapshots: List of snapshots owned by the source share.
        :param snapshot_mappings: Mapping of source snapshot IDs to
            destination snapshot models.
        :param share_server: Share server model or None.
        :param destination_share_server: Destination Share server model or
            None.
        :return: Boolean value to indicate if 1st phase is finished.
        """
        raise NotImplementedError()

    def migration_complete(
            self, context, source_share, destination_share, source_snapshots,
            snapshot_mappings, share_server=None,
            destination_share_server=None):
        """Completes migration of a given share to another host.

        .. note::
            Is called in source share's backend to complete migration.

        If driver is implementing 2-phase migration, this method should
        perform the disruptive tasks related to the 2nd phase of migration,
        thus completing it. Driver should also delete all original share data
        from source backend.

        :param context: The 'context.RequestContext' object for the request.
        :param source_share: Reference to the original share model.
        :param destination_share: Reference to the share model to be used by
            migrated share.
        :param source_snapshots: List of snapshots owned by the source share.
        :param snapshot_mappings: Mapping of source snapshot IDs to
            destination snapshot models.
        :param share_server: Share server model or None.
        :param destination_share_server: Destination Share server model or
            None.
        :return: If the migration changes the share export locations, snapshot
            provider locations or snapshot export locations, this method should
            return a dictionary with the relevant info. In such case, a
            dictionary containing a list of export locations and a list of
            model updates for each snapshot indexed by their IDs.

            Example::

                {
                    'export_locations':
                    [
                        {
                        'path': '1.2.3.4:/foo',
                        'metadata': {},
                        'is_admin_only': False
                        },
                        {
                        'path': '5.6.7.8:/foo',
                        'metadata': {},
                        'is_admin_only': True
                        },
                    ],
                    'snapshot_updates':
                    {
                        'bc4e3b28-0832-4168-b688-67fdc3e9d408':
                        {
                        'provider_location': '/snapshots/foo/bar_1',
                        'export_locations':
                        [
                            {
                            'path': '1.2.3.4:/snapshots/foo/bar_1',
                            'is_admin_only': False,
                            },
                            {
                            'path': '5.6.7.8:/snapshots/foo/bar_1',
                            'is_admin_only': True,
                            },
                        ],
                        },
                        '2e62b7ea-4e30-445f-bc05-fd523ca62941':
                        {
                        'provider_location': '/snapshots/foo/bar_2',
                        'export_locations':
                        [
                            {
                            'path': '1.2.3.4:/snapshots/foo/bar_2',
                            'is_admin_only': False,
                            },
                            {
                            'path': '5.6.7.8:/snapshots/foo/bar_2',
                            'is_admin_only': True,
                            },
                        ],
                        },
                    },
                }

        """
        raise NotImplementedError()

    def migration_cancel(
            self, context, source_share, destination_share, source_snapshots,
            snapshot_mappings, share_server=None,
            destination_share_server=None):
        """Cancels migration of a given share to another host.

        .. note::
           Is called in source share's backend to cancel migration.

        If possible, driver can implement a way to cancel an in-progress
        migration.

        :param context: The 'context.RequestContext' object for the request.
        :param source_share: Reference to the original share model.
        :param destination_share: Reference to the share model to be used by
            migrated share.
        :param source_snapshots: List of snapshots owned by the source share.
        :param snapshot_mappings: Mapping of source snapshot IDs to
            destination snapshot models.
        :param share_server: Share server model or None.
        :param destination_share_server: Destination Share server model or
            None.
        """
        raise NotImplementedError()

    def migration_get_progress(
            self, context, source_share, destination_share, source_snapshots,
            snapshot_mappings, share_server=None,
            destination_share_server=None):
        """Obtains progress of migration of a given share to another host.

        .. note::
            Is called in source share's backend to obtain migration progress.

        If possible, driver can implement a way to return migration progress
        information.

        :param context: The 'context.RequestContext' object for the request.
        :param source_share: Reference to the original share model.
        :param destination_share: Reference to the share model to be used by
            migrated share.
        :param source_snapshots: List of snapshots owned by the source share.
        :param snapshot_mappings: Mapping of source snapshot IDs to
            destination snapshot models.
        :param share_server: Share server model or None.
        :param destination_share_server: Destination Share server model or
            None.
        :return: A dictionary with at least 'total_progress' field containing
            the percentage value.
        """
        raise NotImplementedError()

    def connection_get_info(self, context, share, share_server=None):
        """Is called to provide necessary generic migration logic.

        :param context: The 'context.RequestContext' object for the request.
        :param share: Reference to the share being migrated.
        :param share_server: Share server model or None.
        :return: A dictionary with migration information.
        """
        mount_template = self._get_mount_command(context, share, share_server)

        unmount_template = self._get_unmount_command(context, share,
                                                     share_server)

        access_mapping = self._get_access_mapping(context, share, share_server)

        info = {
            'mount': mount_template,
            'unmount': unmount_template,
            'access_mapping': access_mapping,
        }

        LOG.debug("Migration info obtained for share %(share_id)s: %(info)s.",
                  {'share_id': share['id'], 'info': six.text_type(info)})

        return info

    def _get_access_mapping(self, context, share, share_server):

        mapping = self.configuration.safe_get('protocol_access_mapping') or {}
        result = {}
        share_proto = share['share_proto'].lower()
        for access_type, protocols in mapping.items():
            if share_proto in [y.lower() for y in protocols]:
                result[access_type] = result.get(access_type, [])
                result[access_type].append(share_proto)
        return result

    def _get_mount_command(self, context, share_instance, share_server=None):
        """Is called to delegate mounting share logic."""

        mount_template = self.configuration.safe_get('share_mount_template')

        mount_export = self._get_mount_export(share_instance, share_server)

        format_template = {
            'proto': share_instance['share_proto'].lower(),
            'export': mount_export,
            'path': '%(path)s',
            'options': '%(options)s',
        }

        return mount_template % format_template

    def _get_mount_export(self, share_instance, share_server=None):
        # NOTE(ganso): If drivers want to override the export_location IP,
        # they can do so using this configuration. This method can also be
        # overridden if necessary.
        path = next((x['path'] for x in share_instance['export_locations']
                    if x['is_admin_only']), None)
        if not path:
            path = share_instance['export_locations'][0]['path']
        return path

    def _get_unmount_command(self, context, share_instance,
                             share_server=None):
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
        :return: None or a dictionary with key 'export_locations' containing
            a list of export locations, if snapshots can be mounted.
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

        :return: None or list with export locations
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

        ``access_rules`` contains all access_rules that need to be on the
        share. If the driver can make bulk access rule updates, it can
        safely ignore the ``add_rules`` and ``delete_rules`` parameters.

        If the driver cannot make bulk access rule changes, it can rely on
        new rules to be present in ``add_rules`` and rules that need to be
        removed to be present in ``delete_rules``.

        When a rule in ``delete_rules`` was never applied, drivers must not
        raise an exception, or attempt to set the rule to ``error`` state.

        ``add_rules`` and ``delete_rules`` can be empty lists, in this
        situation, drivers should ensure that the rules present in
        ``access_rules`` are the same as those on the back end. One scenario
        where this situation is forced is when the access_level is changed for
        all existing rules (share migration and for readable replicas).

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
        valid access rules that are provided on the ``create_replica`` and
        ``promote_replica`` calls.

        :param context: Current context
        :param share: Share model with share data.
        :param access_rules: A list of access rules for given share
        :param add_rules: Empty List or List of access rules which should be
               added. access_rules already contains these rules.
        :param delete_rules: Empty List or List of access rules which should be
               removed. access_rules doesn't contain these rules.
        :param share_server: None or Share server model
        :returns: None, or a dictionary of updates in the format::

            {

                '09960614-8574-4e03-89cf-7cf267b0bd08': {

                    'access_key': 'alice31493e5441b8171d2310d80e37e',
                    'state': 'error',

                },

                '28f6eabb-4342-486a-a7f4-45688f0c0295': {

                    'access_key': 'bob0078aa042d5a7325480fd13228b',
                    'state': 'active',

                },

            }

        The top level keys are 'access_id' fields of the access rules that
        need to be updated. ``access_key``s are credentials (str) of the
        entities granted access. Any rule in the ``access_rules`` parameter
        can be updated.

        .. important::

            Raising an exception in this method will force *all* rules in
            'applying' and 'denying' states to 'error'.

            An access rule can be set to 'error' state, either explicitly
            via this return parameter or because of an exception raised in
            this method. Such an access rule will no longer be sent to the
            driver on subsequent access rule updates. When users deny that
            rule however, the driver will be asked to deny access to the
            client/s represented by the rule. We expect that a
            rule that was error-ed at the driver should never exist on the
            back end. So, do not fail the deletion request.

            Also, it is possible that the driver may receive a request to
            add a rule that is already present on the back end.
            This can happen if the share manager service goes down
            while the driver is committing access rule changes. Since we
            cannot determine if the rule was applied successfully by the driver
            before the disruption, we will treat all 'applying' transitional
            rules as new rules and repeat the request.
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

    def update_network_allocation(self, context, share_server):
        """Update network allocation after share server creation."""
        self.network_api.update_network_allocation(context, share_server)

    def update_admin_network_allocation(self, context, share_server):
        """Update admin network allocation after share server creation."""
        if (self.get_admin_network_allocations_number() and
                self.admin_network_api):
            self.admin_network_api.update_network_allocation(context,
                                                             share_server)

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
                                                  share_group=None):
        """Method that allows driver to choose share server for provided share.

        If compatible share-server is not found, method should return None.

        :param context: Current context
        :param share_servers: list with share-server models
        :param share:  share model
        :param snapshot: snapshot model
        :param share_group: ShareGroup model with shares
        :returns: share-server or None
        """
        # If creating in a share group, use its share server
        if share_group:
            for share_server in share_servers:
                if (share_group.get('share_server_id') ==
                        share_server['id']):
                    return share_server
            return None

        return share_servers[0] if share_servers else None

    def choose_share_server_compatible_with_share_group(
            self, context, share_servers, share_group_ref,
            share_group_snapshot=None):

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

        :param metadata: a dictionary, for now containing a key 'request_host'
        """
        raise NotImplementedError()

    def manage_existing(self, share, driver_options):
        """Brings an existing share under Manila management.

        If the provided share is not valid, then raise a
        ManageInvalidShare exception, specifying a reason for the failure.

        If the provided share is not in a state that can be managed, such as
        being replicated on the backend, the driver *MUST* raise
        ManageInvalidShare exception with an appropriate message.

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

        Example::
            {
            'id': <instance id>,
            'snapshot_id': < snapshot id>,
            'provider_location': <location>,
            ...
            }

        :param driver_options: Optional driver-specific options provided
            by admin.

        Example::

            {
            'key': 'value',
            ...
            }

        :return: model_update dictionary with required key 'size',
            which should contain size of the share snapshot, and key
            'export_locations' containing a list of export locations, if
            snapshots can be mounted.
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

    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, share_server=None):
        """Reverts a share (in place) to the specified snapshot.

        Does not delete the share snapshot.  The share and snapshot must both
        be 'available' for the restore to be attempted.  The snapshot must be
        the most recent one taken by Manila; the API layer performs this check
        so the driver doesn't have to.

        The share must be reverted in place to the contents of the snapshot.
        Application admins should quiesce or otherwise prepare the application
        for the shared file system contents to change suddenly.

        :param context: Current context
        :param snapshot: The snapshot to be restored
        :param share_access_rules: List of all access rules for the affected
            share
        :param snapshot_access_rules: List of all access rules for the affected
            snapshot
        :param share_server: Optional -- Share server model or None
        """
        raise NotImplementedError()

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
            methods = ('create_snapshot', 'delete_snapshot')
            # NOTE(vponomaryov): calculate default value for
            # stat 'snapshot_support' based on implementation of
            # appropriate methods of this base driver class.
            self._snapshots_are_supported = self._has_redefined_driver_methods(
                methods)
        return self._snapshots_are_supported

    @property
    def creating_shares_from_snapshots_is_supported(self):
        """Calculate default value for create_share_from_snapshot_support."""

        if not hasattr(self, '_creating_shares_from_snapshots_is_supported'):
            methods = ('create_share_from_snapshot', )
            self._creating_shares_from_snapshots_is_supported = (
                self._has_redefined_driver_methods(methods))

        return (
            self._creating_shares_from_snapshots_is_supported and
            self.snapshots_are_supported
        )

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
            create_share_from_snapshot_support=(
                self.creating_shares_from_snapshots_is_supported),
            revert_to_snapshot_support=False,
            mount_snapshot_support=False,
            replication_domain=self.replication_domain,
            filter_function=self.get_filter_function(),
            goodness_function=self.get_goodness_function(),
        )
        if isinstance(data, dict):
            common.update(data)

        sg_stats = data.get('share_group_stats', {}) if data else {}
        common['share_group_stats'] = {
            'consistent_snapshot_support': sg_stats.get(
                'consistent_snapshot_support'),
        }

        self.add_ip_version_capability(common)
        self._stats = common

    def get_share_server_pools(self, share_server):
        """Return list of pools related to a particular share server.

        :param share_server: ShareServer class instance.
        """
        return []

    def create_share_group(self, context, share_group_dict, share_server=None):
        """Create a share group.

        :param context:
        :param share_group_dict: The share group details
            EXAMPLE:
            {
            'status': 'creating',
            'project_id': '13c0be6290934bd98596cfa004650049',
            'user_id': 'a0314a441ca842019b0952224aa39192',
            'description': None,
            'deleted': 'False',
            'created_at': datetime.datetime(2015, 8, 10, 15, 14, 6),
            'updated_at': None,
            'source_share_group_snapshot_id': 'some_fake_uuid',
            'share_group_type_id': 'some_fake_uuid',
            'host': 'hostname@backend_name',
            'share_network_id': None,
            'share_server_id': None,
            'deleted_at': None,
            'share_types': [<models.ShareGroupShareTypeMapping>],
            'id': 'some_fake_uuid',
            'name': None
            }
        :returns: (share_group_model_update, share_update_list)
            share_group_model_update - a dict containing any values to be
            updated for the SG in the database. This value may be None.

        """
        LOG.debug('Created a Share Group with ID: %s.', share_group_dict['id'])

    def create_share_group_from_share_group_snapshot(
            self, context, share_group_dict, share_group_snapshot_dict,
            share_server=None):
        """Create a share group from a share group snapshot.

        :param context:
        :param share_group_dict: The share group details
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
                'source_share_group_snapshot_id':
                    'f6aa3b59-57eb-421e-965c-4e182538e36a',
                'host': 'hostname@backend_name',
                'deleted_at': None,
                'shares': [<models.Share>], # The new shares being created
                'share_types': [<models.ShareGroupShareTypeMapping>],
                'id': 'some_fake_uuid',
                'name': None
                }
        :param share_group_snapshot_dict: The share group snapshot details
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
                'share_group_id': 'some_fake_uuid',
                'share_share_group_snapshot_members': [
                    {
                     'status': 'available',
                     'user_id': 'a0314a441ca842019b0952224aa39192',
                     'deleted': 'False',
                     'created_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                     'share': <models.Share>,
                     'updated_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                     'share_proto': 'NFS',
                     'project_id': '13c0be6290934bd98596cfa004650049',
                     'share_group_snapshot_id': 'some_fake_uuid',
                     'deleted_at': None,
                     'id': 'some_fake_uuid',
                     'size': 1
                    }
                ],
                'deleted_at': None,
                'id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
                'name': None
                }
        :return: (share_group_model_update, share_update_list)
            share_group_model_update - a dict containing any values to be
            updated for the share group in the database. This value may be None

            share_update_list - a list of dictionaries containing dicts for
            every share created in the share group. Any share dicts should at a
            minimum contain the 'id' key and 'export_locations'.
            Export locations should be in the same format as returned by
            a share_create. This list may be empty or None. EXAMPLE:
            .. code::

                [{'id': 'uuid', 'export_locations': [{...}, {...}]}]
        """
        # Ensure that the share group snapshot has members
        if not share_group_snapshot_dict['share_group_snapshot_members']:
            return None, None

        clone_list = self._collate_share_group_snapshot_info(
            share_group_dict, share_group_snapshot_dict)
        share_update_list = []

        LOG.debug('Creating share group from group snapshot %s.',
                  share_group_snapshot_dict['id'])

        for clone in clone_list:
            kwargs = {}
            if self.driver_handles_share_servers:
                kwargs['share_server'] = share_server
            export_locations = (
                self.create_share_from_snapshot(
                    context, clone['share'], clone['snapshot'], **kwargs))
            share_update_list.append({
                'id': clone['share']['id'],
                'export_locations': export_locations,
            })
        return None, share_update_list

    def delete_share_group(self, context, share_group_dict, share_server=None):
        """Delete a share group

        :param context: The request context
        :param share_group_dict: The share group details
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
                'source_share_group_snapshot_id': 'some_fake_uuid',
                'share_share_group_type_id': 'some_fake_uuid',
                'host': 'hostname@backend_name',
                'deleted_at': None,
                'shares': [<models.Share>], # The new shares being created
                'share_types': [<models.ShareGroupShareTypeMapping>],
                'id': 'some_fake_uuid',
                'name': None
                }
        :return: share_group_model_update
            share_group_model_update - a dict containing any values to be
            updated for the group in the database. This value may be None.
        """

    def _cleanup_group_share_snapshot(self, context, share_snapshot,
                                      share_server):
        """Deletes the snapshot of a share belonging to a group."""

        try:
            self.delete_snapshot(
                context, share_snapshot, share_server=share_server)
        except exception.ManilaException:
            msg = ('Could not delete share group snapshot member %(snap)s '
                   'for share %(share)s.')
            LOG.error(msg, {
                'snap': share_snapshot['id'],
                'share': share_snapshot['share_id'],
            })
            raise

    def create_share_group_snapshot(self, context, snap_dict,
                                    share_server=None):
        """Create a share group snapshot.

        :param context:
        :param snap_dict: The share group snapshot details
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
                'share_group_id': 'some_fake_uuid',
                'share_group_snapshot_members': [
                    {
                     'status': 'available',
                     'share_type_id': 'some_fake_uuid',
                     'user_id': 'a0314a441ca842019b0952224aa39192',
                     'deleted': 'False',
                     'created_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                     'share': <models.Share>,
                     'updated_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                     'share_proto': 'NFS',
                     'project_id': '13c0be6290934bd98596cfa004650049',
                     'share_group_snapshot_id': 'some_fake_uuid',
                     'deleted_at': None,
                     'share_id': 'some_fake_uuid',
                     'id': 'some_fake_uuid',
                     'size': 1,
                     'provider_location': None,
                    }
                ],
                'deleted_at': None,
                'id': 'some_fake_uuid',
                'name': None
                }
        :return: (share_group_snapshot_update, member_update_list)
            share_group_snapshot_update - a dict containing any values to be
            updated for the CGSnapshot in the database. This value may be None.

            member_update_list -  a list of dictionaries containing for every
            member of the share group snapshot. Each dict should contains
            values to be updated for the ShareGroupSnapshotMember in
            the database. This list may be empty or None.
        """
        LOG.debug('Attempting to create a share group snapshot %s.',
                  snap_dict['id'])

        snapshot_members = snap_dict.get('share_group_snapshot_members', [])
        if not self._stats.get('snapshot_support'):
            raise exception.ShareGroupSnapshotNotSupported(
                share_group=snap_dict['share_group_id'])
        elif not snapshot_members:
            LOG.warning('No shares in share group to create snapshot.')
            return None, None
        else:
            share_snapshots = []
            snapshot_members_updates = []
            for member in snapshot_members:
                share_snapshot = {
                    'snapshot_id': member['share_group_snapshot_id'],
                    'share_id': member['share_id'],
                    'share_instance_id': member['share']['id'],
                    'id': member['id'],
                    'share': member['share'],
                    'size': member['share']['size'],
                    'share_size': member['share']['size'],
                    'share_proto': member['share']['share_proto'],
                    'provider_location': None,
                }
                try:
                    member_update = self.create_snapshot(
                        context, share_snapshot, share_server=share_server)
                    if member_update:
                        member_update['id'] = member['id']
                        snapshot_members_updates.append(member_update)
                    share_snapshots.append(share_snapshot)
                except exception.ManilaException as e:
                    msg = ('Could not create share group snapshot. Failed '
                           'to create share snapshot %(snap)s for '
                           'share %(share)s.')
                    LOG.exception(msg, {
                        'snap': share_snapshot['id'],
                        'share': share_snapshot['share_id']
                    })

                    # clean up any share snapshots previously created
                    LOG.debug(
                        'Attempting to clean up snapshots due to failure.')
                    for share_snapshot in share_snapshots:
                        self._cleanup_group_share_snapshot(
                            context, share_snapshot, share_server)
                    raise e

            LOG.debug('Successfully created share group snapshot %s.',
                      snap_dict['id'])
            return None, snapshot_members_updates

    def delete_share_group_snapshot(self, context, snap_dict,
                                    share_server=None):
        """Delete a share group snapshot

        :param context:
        :param snap_dict: The share group snapshot details
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
                'share_group_id': 'some_fake_uuid',
                'share_group_snapshot_members': [
                    {
                     'status': 'available',
                     'share_type_id': 'some_fake_uuid',
                     'share_id': 'some_fake_uuid',
                     'user_id': 'a0314a441ca842019b0952224aa39192',
                     'deleted': 'False',
                     'created_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                     'share': <models.Share>,
                     'updated_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
                     'share_proto': 'NFS',
                     'project_id': '13c0be6290934bd98596cfa004650049',
                     'share_group_snapshot_id': 'some_fake_uuid',
                     'deleted_at': None,
                     'id': 'some_fake_uuid',
                     'size': 1,
                     'provider_location': 'fake_provider_location_value',
                    }
                ],
                'deleted_at': None,
                'id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
                'name': None
                }
        :return: (share_group_snapshot_update, member_update_list)
            share_group_snapshot_update - a dict containing any values
            to be updated for the ShareGroupSnapshot in the database.
            This value may be None.
        """
        snapshot_members = snap_dict.get('share_group_snapshot_members', [])
        LOG.debug('Deleting share group snapshot %s.', snap_dict['id'])
        for member in snapshot_members:
            share_snapshot = {
                'snapshot_id': member['share_group_snapshot_id'],
                'share_id': member['share_id'],
                'share_instance_id': member['share']['id'],
                'id': member['id'],
                'share': member['share'],
                'size': member['share']['size'],
                'share_size': member['share']['size'],
                'share_proto': member['share']['share_proto'],
                'provider_location': member['provider_location'],
            }
            self.delete_snapshot(
                context, share_snapshot, share_server=share_server)

        LOG.debug('Deleted share group snapshot %s.', snap_dict['id'])
        return None, None

    def _collate_share_group_snapshot_info(self, share_group_dict,
                                           share_group_snapshot_dict):
        """Collate the data for a clone of the SG snapshot.

        Given two data structures, a share group snapshot (
        share_group_snapshot_dict) and a new share to be cloned from
        the snapshot (share_group_dict), match up both structures into a list
        of dicts (share & snapshot) suitable for use by existing method
        that clones individual share snapshots.
        """
        clone_list = []
        for share in share_group_dict['shares']:
            clone_info = {'share': share}
            for share_group_snapshot_member in share_group_snapshot_dict[
                    'share_group_snapshot_members']:
                if (share['source_share_group_snapshot_member_id'] ==
                        share_group_snapshot_member['id']):
                    clone_info['snapshot'] = share_group_snapshot_member
                    break

            if len(clone_info) != 2:
                msg = _(
                    "Invalid data supplied for creating share group from "
                    "share group snapshot "
                    "%s.") % share_group_snapshot_dict['id']
                raise exception.InvalidShareGroup(reason=msg)

            clone_list.append(clone_info)

        return clone_list

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

        .. note::
            This call is made on the host that the new replica is being created
            upon.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share.
            This list also contains the replica to be created. The 'active'
            replica will have its 'replica_state' attr set to 'active'.

        Example::

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

        Example::

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

        :param access_rules: A list of access rules.
            These are rules that other instances of the share already obey.
            Drivers are expected to apply access rules to the new replica or
            disregard access rules that don't apply.

        Example::

             [
              {
                 'id': 'f0875f6f-766b-4865-8b41-cccb4cdf1676',
                 'deleted' = False,
                 'share_id' = 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                 'access_type' = 'ip',
                 'access_to' = '172.16.20.1',
                 'access_level' = 'rw',
              }
             ]

        :param replica_snapshots: List of dictionaries of snapshot instances.
            This includes snapshot instances of every snapshot of the share
            whose 'aggregate_status' property was reported to be 'available'
            when the share manager initiated this request. Each list member
            will have two sub dictionaries: 'active_replica_snapshot' and
            'share_replica_snapshot'. The 'active' replica snapshot corresponds
            to the instance of the snapshot on any of the 'active' replicas of
            the share while share_replica_snapshot corresponds to the snapshot
            instance for the specific replica that will need to exist on the
            new share replica that is being created. The driver needs to ensure
            that this snapshot instance is truly available before transitioning
            the replica from 'out_of_sync' to 'in_sync'. Snapshots instances
            for snapshots that have an 'aggregate_status' of 'creating' or
            'deleting' will be polled for in the ``update_replicated_snapshot``
            method.

        Example::

            [
             {
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
             }
            ]

        :param share_server: <models.ShareServer> or None
            Share server of the replica being created.
        :return: None or a dictionary.
            The dictionary can contain export_locations replica_state and
            access_rules_status. export_locations is a list of paths and
            replica_state is one of 'active', 'in_sync', 'out_of_sync' or
            'error'.

        .. important::

            A backend supporting 'writable' type replication should return
            'active' as the replica_state.

        Export locations should be in the same format as returned during the
        ``create_share`` call.

        Example::

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

        .. note::
            This call is made on the host that hosts the replica being
            deleted.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share
            This list also contains the replica to be deleted. The 'active'
            replica will have its 'replica_state' attr set to 'active'.

        Example::

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

        Example::

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

        :param replica_snapshots: List of dictionaries of snapshot instances.
            The dict contains snapshot instances that are associated with the
            share replica being deleted.
            No model updates to snapshot instances are possible in this method.
            The driver should return when the cleanup is completed on the
            backend for both, the snapshots and the replica itself. Drivers
            must handle situations where the snapshot may not yet have
            finished 'creating' on this replica.

        Example::

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

        :param share_server: <models.ShareServer> or None
            Share server of the replica to be deleted.
        :return: None.
        :raises: Exception.
            Any exception raised will set the share replica's 'status' and
            'replica_state' attributes to 'error_deleting'. It will not affect
            snapshots belonging to this replica.
        """
        raise NotImplementedError()

    def promote_replica(self, context, replica_list, replica, access_rules,
                        share_server=None):
        """Promote a replica to 'active' replica state.

        .. note::
            This call is made on the host that hosts the replica being
            promoted.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share
            This list also contains the replica to be promoted. The 'active'
            replica will have its 'replica_state' attr set to 'active'.

        Example::

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

        Example::

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

        :param access_rules: A list of access rules
            These access rules are obeyed by other instances of the share

        Example::

             [
              {
                 'id': 'f0875f6f-766b-4865-8b41-cccb4cdf1676',
                 'deleted' = False,
                 'share_id' = 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                 'access_type' = 'ip',
                 'access_to' = '172.16.20.1',
                 'access_level' = 'rw',
              }
             ]

        :param share_server: <models.ShareServer> or None
            Share server of the replica to be promoted.
        :return: updated_replica_list or None.
            The driver can return the updated list as in the request
            parameter. Changes that will be updated to the Database are:
            'export_locations', 'access_rules_status' and 'replica_state'.
        :raises: Exception.
            This can be any exception derived from BaseException. This is
            re-raised by the manager after some necessary cleanup. If the
            driver raises an exception during promotion, it is assumed that
            all of the replicas of the share are in an inconsistent state.
            Recovery is only possible through the periodic update call and/or
            administrator intervention to correct the 'status' of the affected
            replicas if they become healthy again.
        """
        raise NotImplementedError()

    def update_replica_state(self, context, replica_list, replica,
                             access_rules, replica_snapshots,
                             share_server=None):
        """Update the replica_state of a replica.

        .. note::
            This call is made on the host which hosts the replica being
            updated.

        Drivers should fix replication relationships that were broken if
        possible inside this method.

        This method is called periodically by the share manager; and
        whenever requested by the administrator through the 'resync' API.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share
            This list also contains the replica to be updated. The 'active'
            replica will have its 'replica_state' attr set to 'active'.

        Example::

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

        :param replica: Dictionary of the replica being updated
            Replica state will always be 'in_sync', 'out_of_sync', or 'error'.
            Replicas in 'active' state will not be passed via this parameter.

        Example::

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

        :param access_rules: A list of access rules
            These access rules are obeyed by other instances of the share. The
            driver could attempt to sync on any un-applied access_rules.

        Example::

             [
              {
                 'id': 'f0875f6f-766b-4865-8b41-cccb4cdf1676',
                 'deleted' = False,
                 'share_id' = 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
                 'access_type' = 'ip',
                 'access_to' = '172.16.20.1',
                 'access_level' = 'rw',
              }
             ]

        :param replica_snapshots: List of dictionaries of snapshot instances.
            This includes snapshot instances of every snapshot of the share
            whose 'aggregate_status' property was reported to be 'available'
            when the share manager initiated this request. Each list member
            will have two sub dictionaries: 'active_replica_snapshot' and
            'share_replica_snapshot'. The 'active' replica snapshot corresponds
            to the instance of the snapshot on any of the 'active' replicas of
            the share while share_replica_snapshot corresponds to the snapshot
            instance for the specific replica being updated. The driver needs
            to ensure that this snapshot instance is truly available before
            transitioning from 'out_of_sync' to 'in_sync'. Snapshots instances
            for snapshots that have an 'aggregate_status' of 'creating' or
            'deleting' will be polled for in the update_replicated_snapshot
            method.

        Example::

             [
              {
            'active_replica_snapshot': {
                 'id': '8bda791c-7bb6-4e7b-9b64-fefff85ff13e',
                 'share_instance_id': '10e49c3e-aca9-483b-8c2d-1c337b38d6af',
                 'status': 'available',
                 'provider_location': '/newton/share-snapshot-10e49c3e-aca9',
                 ...
                },
             'share_replica_snapshot': {
                 'id': '10e49c3e-aca9-483b-8c2d-1c337b38d6af',
                 'share_instance_id': 'd487b88d-e428-4230-a465-a800c2cce5f8',
                 'status': 'creating',
                 'provider_location': None,
                    ...
                },
              }
             ]

        :param share_server: <models.ShareServer> or None
        :return: replica_state: a str value denoting the replica_state.
            Valid values are 'in_sync' and 'out_of_sync' or None (to leave the
            current replica_state unchanged).
        """
        raise NotImplementedError()

    def create_replicated_snapshot(self, context, replica_list,
                                   replica_snapshots,
                                   share_server=None):
        """Create a snapshot on active instance and update across the replicas.

        .. note::
            This call is made on the 'active' replica's host. Drivers are
            expected to transfer the snapshot created to the respective
            replicas.

        The driver is expected to return model updates to the share manager.
        If it was able to confirm the creation of any number of the snapshot
        instances passed in this interface, it can set their status to
        'available' as a cue for the share manager to set the progress attr
        to '100%'.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share
            The 'active' replica will have its 'replica_state' attr set to
            'active'.

        Example::

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

        :param replica_snapshots: List of dictionaries of snapshot instances.
            These snapshot instances track the snapshot across the replicas.
            All the instances will have their status attribute set to
            'creating'.

        Example::

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
        :return: List of dictionaries of snapshot instances.
            The dictionaries can contain values that need to be updated on the
            database for the snapshot instances being created.
        :raises: Exception.
            Any exception in this method will set all instances to 'error'.
        """
        raise NotImplementedError()

    def revert_to_replicated_snapshot(self, context, active_replica,
                                      replica_list, active_replica_snapshot,
                                      replica_snapshots, share_access_rules,
                                      snapshot_access_rules,
                                      share_server=None):
        """Reverts a replicated share (in place) to the specified snapshot.

        .. note::
            This call is made on the 'active' replica's host, since drivers may
            not be able to revert snapshots on individual replicas.

        Does not delete the share snapshot.  The share and snapshot must both
        be 'available' for the restore to be attempted.  The snapshot must be
        the most recent one taken by Manila; the API layer performs this check
        so the driver doesn't have to.

        The share must be reverted in place to the contents of the snapshot.
        Application admins should quiesce or otherwise prepare the application
        for the shared file system contents to change suddenly.

        :param context: Current context
        :param active_replica: The current active replica
        :param replica_list: List of all replicas for a particular share
            The 'active' replica will have its 'replica_state' attr set to
            'active' and its 'status' set to 'reverting'.
        :param active_replica_snapshot: snapshot to be restored
        :param replica_snapshots: List of dictionaries of snapshot instances.
            These snapshot instances track the snapshot across the replicas.
            The snapshot of the active replica to be restored with have its
            status attribute set to 'restoring'.
        :param share_access_rules: List of access rules for the affected share.
        :param snapshot_access_rules: List of access rules for the affected
            snapshot.
        :param share_server: Optional -- Share server model
        """
        raise NotImplementedError()

    def delete_replicated_snapshot(self, context, replica_list,
                                   replica_snapshots, share_server=None):
        """Delete a snapshot by deleting its instances across the replicas.

        .. note::
            This call is made on the 'active' replica's host, since
            drivers may not be able to delete the snapshot from an individual
            replica.

        The driver is expected to return model updates to the share manager.
        If it was able to confirm the removal of any number of the snapshot
        instances passed in this interface, it can set their status to
        'deleted' as a cue for the share manager to clean up that instance
        from the database.

        :param context: Current context
        :param replica_list: List of all replicas for a particular share
            The 'active' replica will have its 'replica_state' attr set to
            'active'.

        Example::

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

        :param replica_snapshots: List of dictionaries of snapshot instances.
            These snapshot instances track the snapshot across the replicas.
            All the instances will have their status attribute set to
            'deleting'.

        Example::

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
        :return: List of dictionaries of snapshot instances.
            The dictionaries can contain values that need to be updated on the
            database for the snapshot instances being deleted. To confirm the
            deletion of the snapshot instance, set the 'status' attribute of
            the instance to 'deleted' (constants.STATUS_DELETED)
        :raises: Exception.
            Any exception in this method will set the status attribute of all
            snapshot instances to 'error_deleting'.
        """
        raise NotImplementedError()

    def update_replicated_snapshot(self, context, replica_list,
                                   share_replica, replica_snapshots,
                                   replica_snapshot, share_server=None):
        """Update the status of a snapshot instance that lives on a replica.

        .. note::
            For DR and Readable styles of replication, this call is made on
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
        :param replica_list: List of all replicas for a particular share
            The 'active' replica will have its 'replica_state' attr set to
            'active'.

        Example::

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

        :param share_replica: Share replica dictionary.
            This replica is associated with the snapshot instance whose
            status is being updated. Replicas in 'active' replica_state will
            not be passed via this parameter.

        Example::

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

        :param replica_snapshots: List of dictionaries of snapshot instances.
            These snapshot instances track the snapshot across the replicas.
            This will include the snapshot instance being updated as well.

        Example::

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

        :param replica_snapshot: Dictionary of the snapshot instance.
            This is the instance to be updated. It will be in 'creating' or
            'deleting' state when sent via this parameter.

        Example::

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
        :return: replica_snapshot_model_update: a dictionary.
            The dictionary must contain values that need to be updated on the
            database for the snapshot instance that represents the snapshot on
            the replica.
        :raises: exception.SnapshotResourceNotFound
            Raise this exception for snapshots that are not found on the
            backend and their status was 'deleting'.
        """
        raise NotImplementedError()

    def get_filter_function(self):
        """Get filter_function string.

        Returns either the string from the driver instance or global section
        in manila.conf. If nothing is specified in manila.conf, then try to
        find the default filter_function. When None is returned the scheduler
        will always pass the driver instance.

        :return: a filter_function string or None
        """
        ret_function = self.configuration.filter_function
        if not ret_function:
            ret_function = CONF.filter_function
        if not ret_function:
            ret_function = self.get_default_filter_function()
        return ret_function

    def get_goodness_function(self):
        """Get good_function string.

        Returns either the string from the driver instance or global section
        in manila.conf. If nothing is specified in manila.conf, then try to
        find the default goodness_function. When None is returned the scheduler
        will give the lowest score to the driver instance.

        :return: a goodness_function string or None
        """
        ret_function = self.configuration.goodness_function
        if not ret_function:
            ret_function = CONF.goodness_function
        if not ret_function:
            ret_function = self.get_default_goodness_function()
        return ret_function

    def get_default_filter_function(self):
        """Get the default filter_function string.

        Each driver could overwrite the method to return a well-known
        default string if it is available.

        :return: None
        """
        return None

    def get_default_goodness_function(self):
        """Get the default goodness_function string.

        Each driver could overwrite the method to return a well-known
        default string if it is available.

        :return: None
        """
        return None

    def snapshot_update_access(self, context, snapshot, access_rules,
                               add_rules, delete_rules, share_server=None):
        """Update access rules for given snapshot.

        ``access_rules`` contains all access_rules that need to be on the
        share. If the driver can make bulk access rule updates, it can
        safely ignore the ``add_rules`` and ``delete_rules`` parameters.

        If the driver cannot make bulk access rule changes, it can rely on
        new rules to be present in ``add_rules`` and rules that need to be
        removed to be present in ``delete_rules``.

        When a rule in ``add_rules`` already exists in the back end, drivers
        must not raise an exception. When a rule in ``delete_rules`` was never
        applied, drivers must not raise an exception, or attempt to set the
        rule to ``error`` state.

        ``add_rules`` and ``delete_rules`` can be empty lists, in this
        situation, drivers should ensure that the rules present in
        ``access_rules`` are the same as those on the back end.

        :param context: Current context
        :param snapshot: Snapshot model with snapshot data.
        :param access_rules: All access rules for given snapshot
        :param add_rules: Empty List or List of access rules which should be
               added. access_rules already contains these rules.
        :param delete_rules: Empty List or List of access rules which should be
               removed. access_rules doesn't contain these rules.
        :param share_server: None or Share server model
        """
        raise NotImplementedError()

    def update_share_usage_size(self, context, shares):
        """Invoked to get the usage size of given shares.

        Driver can use this method to update the share usage size of
        the shares. To do that, a dictionary of shares should be
        returned.
        :param shares: None or a list of all shares for updates.
        :returns: An empty list or a list of dictionary of updates in the
        following format. The value of "used_size" can be specified in GiB
        units, as a floating point number::

            [
                {
                    'id': '09960614-8574-4e03-89cf-7cf267b0bd08',
                    'used_size': '200',
                    'gathered_at': datetime.datetime(2017, 8, 10, 15, 14, 6),
                },
            ]

        """
        LOG.debug("This backend does not support gathering 'used_size' of "
                  "shares created on it.")
        return []

    def get_configured_ip_versions(self):
        """"Get allowed IP versions.

        The supported versions are returned with list, possible
        values are: [4], [6], or [4, 6]

        Drivers that assert ipv6_implemented = True must override
        this method. If the returned list includes 4, then shares
        created by this driver must have an IPv4 export location.
        If the list includes 6, then shares created by the driver
        must have an IPv6 export location.

        Drivers should check that their storage controller actually
        has IPv4/IPv6 enabled and configured properly.
        """

        # For drivers that haven't implemented IPv6, assume legacy behavior
        if not self.ipv6_implemented:
            return [4]

        raise NotImplementedError()

    def add_ip_version_capability(self, data):
        """Add IP version support capabilities.

        When DHSS is true, the capabilities are determined by driver
        and configured network plugin.
        When DHSS is false, the capabilities are determined by driver
        only.
        :param data: the capability dictionary
        :returns: capability data
        """
        self.ip_versions = self.get_configured_ip_versions()
        if isinstance(self.ip_versions, list):
            self.ip_versions = set(self.ip_versions)
        else:
            self.ip_versions = set(list(self.ip_versions))

        if not self.ip_versions:
            LOG.error("Backend %s supports neither IPv4 nor IPv6.",
                      data['share_backend_name'])

        if self.driver_handles_share_servers:
            network_versions = self.network_api.enabled_ip_versions
            self.ip_versions = self.ip_versions & network_versions
            if not self.ip_versions:
                LOG.error("The enabled IP version of the network plugin is "
                          "not compatible with the version supported by "
                          "backend %s.", data['share_backend_name'])

        data['ipv4_support'] = (4 in self.ip_versions)
        data['ipv6_support'] = (6 in self.ip_versions)
        return data

    def get_backend_info(self, context):
        """Get driver and array configuration parameters.

        Driver can use this method to get the special configuration info and
        return for assessment.

        :returns: A dictionary containing driver-specific info.

            Example::

                 {
                      'version': '2.23'
                      'port': '80',
                      'logicalportip': '1.1.1.1',
                       ...
                 }

        """
        raise NotImplementedError()

    def ensure_shares(self, context, shares):
        """Invoked to ensure that shares are exported.

        Driver can use this method to update the list of export locations of
        the shares if it changes. To do that, a dictionary of shares should
        be returned.
        :shares: None or a list of all shares for updates.
        :returns: None or a dictionary of updates in the format.

            Example::

                {
                    '09960614-8574-4e03-89cf-7cf267b0bd08': {
                        'export_locations': [{...}, {...}],
                        'status': 'error',
                    },

                    '28f6eabb-4342-486a-a7f4-45688f0c0295': {
                        'export_locations': [{...}, {...}],
                        'status': 'available',
                    },

                }

        """
        raise NotImplementedError()
