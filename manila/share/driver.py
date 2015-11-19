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

import re
import time

from oslo_config import cfg
from oslo_log import log
import six

from manila import exception
from manila.i18n import _, _LE
from manila import network
from manila.share import utils as share_utils
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
    cfg.StrOpt(
        'migration_tmp_location',
        default='/tmp/',
        help="Temporary path to create and mount shares during migration."),
    cfg.ListOpt(
        'migration_ignore_files',
        default=['lost+found'],
        help="List of files and folders to be ignored when migrating shares. "
             "Items should be names (not including any path)."),
    cfg.IntOpt(
        'migration_wait_access_rules_timeout',
        default=90,
        help="Time to wait for access rules to be allowed/denied on backends "
             "when migrating shares using generic approach (seconds)."),
    cfg.IntOpt(
        'migration_create_delete_share_timeout',
        default=300,
        help='Timeout for creating and deleting share instances '
             'when performing share migration (seconds).'),
    cfg.StrOpt(
        'migration_mounting_backend_ip',
        help="Backend IP in admin network to use for mounting "
             "shares during migration."),
    cfg.StrOpt(
        'migration_data_copy_node_ip',
        help="The IP of the node responsible for copying data during "
             "migration, such as the data copy service node, reachable by "
             "the backend."),
    cfg.StrOpt(
        'migration_protocol_mount_command',
        help="The command for mounting shares for this backend. Must specify"
             "the executable and all necessary parameters for the protocol "
             "supported. It is advisable to separate protocols per backend."),
    cfg.BoolOpt(
        'migration_readonly_support',
        default=True,
        help="Specify whether read only access mode is supported in this"
             "backend."),
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

    def migrate_share(self, context, share_ref, host,
                      dest_driver_migration_info):
        """Is called to perform driver migration.

        Driver should implement this method if willing to perform migration
        in an optimized way, useful for when driver understands destination
        backend.
        :param context: The 'context.RequestContext' object for the request.
        :param share_ref: Reference to the share being migrated.
        :param host: Destination host and its capabilities.
        :param dest_driver_migration_info: Migration information provided by
        destination host.
        :returns: Boolean value indicating if driver migration succeeded.
        :returns: Dictionary containing a model update.
        """
        return None, None

    def get_driver_migration_info(self, context, share_instance, share_server):
        """Is called to provide necessary driver migration logic."""
        return None

    def get_migration_info(self, context, share_instance, share_server):
        """Is called to provide necessary generic migration logic."""

        mount_cmd = self._get_mount_command(context, share_instance,
                                            share_server)

        umount_cmd = self._get_unmount_command(context, share_instance,
                                               share_server)

        access = self._get_access_rule_for_data_copy(
            context, share_instance, share_server)
        return {'mount': mount_cmd,
                'umount': umount_cmd,
                'access': access}

    def _get_mount_command(self, context, share_instance, share_server):
        """Is called to delegate mounting share logic."""
        mount_cmd = self._get_mount_command_protocol(share_instance,
                                                     share_server)

        mount_ip = self._get_mount_ip(share_instance, share_server)
        mount_cmd.append(mount_ip)

        mount_path = self.configuration.safe_get(
            'migration_tmp_location') + share_instance['id']
        mount_cmd.append(mount_path)

        return mount_cmd

    def _get_mount_command_protocol(self, share_instance, share_server):
        mount_cmd = self.configuration.safe_get(
            'migration_protocol_mount_command')
        if mount_cmd:
            return mount_cmd.split()
        else:
            return ['mount', '-t', share_instance['share_proto'].lower()]

    def _get_mount_ip(self, share_instance, share_server):
        # Note(ganso): DHSS = true drivers may need to override this method
        # and use information saved in share_server structure.
        mount_ip = self.configuration.safe_get('migration_mounting_backend_ip')
        old_ip = share_instance['export_locations'][0]['path']
        if mount_ip:
            # NOTE(ganso): Does not currently work with hostnames and ipv6.
            p = re.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")
            new_ip = p.sub(mount_ip, old_ip)
            return new_ip
        else:
            return old_ip

    def _get_unmount_command(self, context, share_instance, share_server):
        return ['umount',
                self.configuration.safe_get('migration_tmp_location')
                + share_instance['id']]

    def _get_access_rule_for_data_copy(
            self, context, share_instance, share_server):
        """Is called to obtain access rule so data copy node can mount."""
        # Note(ganso): The current method implementation is intended to work
        # with Data Copy Service approach. If Manila Node is used for copying,
        # then DHSS = true drivers may need to override this method.
        service_ip = self.configuration.safe_get('migration_data_copy_node_ip')
        return {'access_type': 'ip',
                'access_level': 'rw',
                'access_to': service_ip}

    def copy_share_data(self, context, helper, share, share_instance,
                        share_server, new_share_instance, new_share_server,
                        migration_info_src, migration_info_dest):
        """Copies share data of a given share to a new share.

        :param context: The 'context.RequestContext' object for the request.
        :param helper: instance of a share migration helper.
        :param share: the share to copy.
        :param share_instance: current instance holding the share.
        :param share_server: current share_server hosting the share.
        :param new_share_instance: share instance to copy data to.
        :param new_share_server: share server that hosts destination share.
        :param migration_info_src: migration information (source).
        :param migration_info_dest: migration information (destination).
        """

        # NOTE(ganso): This method is here because it is debatable if it can
        # be overridden by a driver or not. Personally I think it should not,
        # else it would be possible to lose compatibility with generic
        # migration between backends, but allows the driver to use it on its
        # own implementation if it wants to.

        migrated = False

        mount_path = self.configuration.safe_get('migration_tmp_location')

        src_access = migration_info_src['access']
        dest_access = migration_info_dest['access']

        if None in (src_access['access_to'], dest_access['access_to']):
            msg = _("Access rules not appropriate for mounting share instances"
                    " for migration of share %(share_id)s,"
                    " source share access: %(src_ip)s, destination share"
                    " access: %(dest_ip)s. Aborting.") % {
                'src_ip': src_access['access_to'],
                'dest_ip': dest_access['access_to'],
                'share_id': share['id']}
            raise exception.ShareMigrationFailed(reason=msg)

        # NOTE(ganso): Removing any previously conflicting access rules, which
        # would cause the following access_allow to fail for one instance.
        helper.deny_migration_access(None, src_access, False)
        helper.deny_migration_access(None, dest_access, False)

        # NOTE(ganso): I would rather allow access to instances separately,
        # but I require an access_id since it is a new access rule and
        # destination manager must receive an access_id. I can either move
        # this code to manager code so I can create the rule in DB manually,
        # or ignore duplicate access rule errors for some specific scenarios.

        try:
            src_access_ref = helper.allow_migration_access(src_access)
        except Exception as e:
            LOG.error(_LE("Share migration failed attempting to allow "
                          "access of %(access_to)s to share "
                          "instance %(instance_id)s.") % {
                'access_to': src_access['access_to'],
                'instance_id': share_instance['id']})
            msg = six.text_type(e)
            LOG.exception(msg)
            raise exception.ShareMigrationFailed(reason=msg)

        try:
            dest_access_ref = helper.allow_migration_access(dest_access)
        except Exception as e:
            LOG.error(_LE("Share migration failed attempting to allow "
                          "access of %(access_to)s to share "
                          "instance %(instance_id)s.") % {
                'access_to': dest_access['access_to'],
                'instance_id': new_share_instance['id']})
            msg = six.text_type(e)
            LOG.exception(msg)
            helper.cleanup_migration_access(src_access_ref, src_access)
            raise exception.ShareMigrationFailed(reason=msg)

        # NOTE(ganso): From here we have the possibility of not cleaning
        # anything when facing an error. At this moment, we have the
        # destination instance in "inactive" state, while we are performing
        # operations on the source instance. I think it is best to not clean
        # the instance, leave it in "inactive" state, but try to clean
        # temporary access rules, mounts, folders, etc, since no additional
        # harm is done.

        def _mount_for_migration(migration_info):

            try:
                utils.execute(*migration_info['mount'], run_as_root=True)
            except Exception:
                LOG.error(_LE("Failed to mount temporary folder for "
                              "migration of share instance "
                              "%(share_instance_id)s "
                              "to %(new_share_instance_id)s") % {
                    'share_instance_id': share_instance['id'],
                    'new_share_instance_id': new_share_instance['id']})
                helper.cleanup_migration_access(
                    src_access_ref, src_access)
                helper.cleanup_migration_access(
                    dest_access_ref, dest_access)
                raise

        utils.execute('mkdir', '-p',
                      ''.join((mount_path, share_instance['id'])))

        utils.execute('mkdir', '-p',
                      ''.join((mount_path, new_share_instance['id'])))

        # NOTE(ganso): mkdir command sometimes returns faster than it
        # actually runs, so we better sleep for 1 second.

        time.sleep(1)

        try:
            _mount_for_migration(migration_info_src)
        except Exception as e:
            LOG.error(_LE("Share migration failed attempting to mount "
                          "share instance %s.") % share_instance['id'])
            msg = six.text_type(e)
            LOG.exception(msg)
            helper.cleanup_temp_folder(share_instance, mount_path)
            helper.cleanup_temp_folder(new_share_instance, mount_path)
            raise exception.ShareMigrationFailed(reason=msg)

        try:
            _mount_for_migration(migration_info_dest)
        except Exception as e:
            LOG.error(_LE("Share migration failed attempting to mount "
                          "share instance %s.") % new_share_instance['id'])
            msg = six.text_type(e)
            LOG.exception(msg)
            helper.cleanup_unmount_temp_folder(share_instance,
                                               migration_info_src)
            helper.cleanup_temp_folder(share_instance, mount_path)
            helper.cleanup_temp_folder(new_share_instance, mount_path)
            raise exception.ShareMigrationFailed(reason=msg)

        try:
            ignore_list = self.configuration.safe_get('migration_ignore_files')
            copy = share_utils.Copy(mount_path + share_instance['id'],
                                    mount_path + new_share_instance['id'],
                                    ignore_list)
            copy.run()
            if copy.get_progress()['total_progress'] == 100:
                migrated = True

        except Exception as e:
            LOG.exception(six.text_type(e))
            LOG.error(_LE("Failed to copy files for "
                          "migration of share instance %(share_instance_id)s "
                          "to %(new_share_instance_id)s") % {
                'share_instance_id': share_instance['id'],
                'new_share_instance_id': new_share_instance['id']})

        # NOTE(ganso): For some reason I frequently get AMQP errors after
        # copying finishes, which seems like is the service taking too long to
        # copy while not replying heartbeat messages, so AMQP closes the
        # socket. There is no impact, it just shows a big trace and AMQP
        # reconnects after, although I would like to prevent this situation
        # without the use of additional threads. Suggestions welcome.

        utils.execute(*migration_info_src['umount'], run_as_root=True)
        utils.execute(*migration_info_dest['umount'], run_as_root=True)

        utils.execute('rmdir', ''.join((mount_path, share_instance['id'])),
                      check_exit_code=False)
        utils.execute('rmdir', ''.join((mount_path, new_share_instance['id'])),
                      check_exit_code=False)

        helper.deny_migration_access(src_access_ref, src_access)
        helper.deny_migration_access(dest_access_ref, dest_access)

        if not migrated:
            msg = ("Copying from share instance %(instance_id)s "
                   "to %(new_instance_id)s did not succeed." % {
                       'instance_id': share_instance['id'],
                       'new_instance_id': new_share_instance['id']})
            raise exception.ShareMigrationFailed(reason=msg)

        LOG.debug("Copying completed in migration for share %s." % share['id'])

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
