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
Module with ZFSonLinux share driver that utilizes ZFS filesystem resources
and exports them as shares.
"""

import time

from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
from oslo_utils import strutils
from oslo_utils import timeutils

from manila.common import constants
from manila import exception
from manila.i18n import _, _LI, _LW
from manila.share import driver
from manila.share.drivers.zfsonlinux import utils as zfs_utils
from manila.share import share_types
from manila.share import utils as share_utils
from manila import utils


zfsonlinux_opts = [
    cfg.StrOpt(
        "zfs_share_export_ip",
        required=True,
        help="IP to be added to user-facing export location. Required."),
    cfg.StrOpt(
        "zfs_service_ip",
        required=True,
        help="IP to be added to admin-facing export location. Required."),
    cfg.ListOpt(
        "zfs_zpool_list",
        required=True,
        help="Specify list of zpools that are allowed to be used by backend. "
             "Can contain nested datasets. Examples: "
             "Without nested dataset: 'zpool_name'. "
             "With nested dataset: 'zpool_name/nested_dataset_name'. "
             "Required."),
    cfg.ListOpt(
        "zfs_dataset_creation_options",
        help="Define here list of options that should be applied "
             "for each dataset creation if needed. Example: "
             "compression=gzip,dedup=off. "
             "Note that, for secondary replicas option 'readonly' will be set "
             "to 'on' and for active replicas to 'off' in any way. "
             "Also, 'quota' will be equal to share size. Optional."),
    cfg.StrOpt(
        "zfs_dataset_name_prefix",
        default='manila_share_',
        help="Prefix to be used in each dataset name. Optional."),
    cfg.StrOpt(
        "zfs_dataset_snapshot_name_prefix",
        default='manila_share_snapshot_',
        help="Prefix to be used in each dataset snapshot name. Optional."),
    cfg.BoolOpt(
        "zfs_use_ssh",
        default=False,
        help="Remote ZFS storage hostname that should be used for SSH'ing. "
             "Optional."),
    cfg.StrOpt(
        "zfs_ssh_username",
        help="SSH user that will be used in 2 cases: "
             "1) By manila-share service in case it is located on different "
             "host than its ZFS storage. "
             "2) By manila-share services with other ZFS backends that "
             "perform replication. "
             "It is expected that SSH'ing will be key-based, passwordless. "
             "This user should be passwordless sudoer. Optional."),
    cfg.StrOpt(
        "zfs_ssh_user_password",
        secret=True,
        help="Password for user that is used for SSH'ing ZFS storage host. "
             "Not used for replication operations. They require "
             "passwordless SSH access. Optional."),
    cfg.StrOpt(
        "zfs_ssh_private_key_path",
        help="Path to SSH private key that should be used for SSH'ing ZFS "
             "storage host. Not used for replication operations. Optional."),
    cfg.ListOpt(
        "zfs_share_helpers",
        required=True,
        default=[
            "NFS=manila.share.drivers.zfsonlinux.utils.NFSviaZFSHelper",
        ],
        help="Specify list of share export helpers for ZFS storage. "
             "It should look like following: "
             "'FOO_protocol=foo.FooClass,BAR_protocol=bar.BarClass'. "
             "Required."),
    cfg.StrOpt(
        "zfs_replica_snapshot_prefix",
        required=True,
        default="tmp_snapshot_for_replication_",
        help="Set snapshot prefix for usage in ZFS replication. Required."),
]

CONF = cfg.CONF
CONF.register_opts(zfsonlinux_opts)
LOG = log.getLogger(__name__)


def ensure_share_server_not_provided(f):

    def wrap(self, context, *args, **kwargs):
        server = kwargs.get('share_server')
        if server:
            raise exception.InvalidInput(
                reason=_("Share server handling is not available. "
                         "But 'share_server' was provided. '%s'. "
                         "Share network should not be used.") % server.get(
                             "id", server))
        return f(self, context, *args, **kwargs)

    return wrap


class ZFSonLinuxShareDriver(zfs_utils.ExecuteMixin, driver.ShareDriver):

    def __init__(self, *args, **kwargs):
        super(self.__class__, self).__init__(
            [False], *args, config_opts=[zfsonlinux_opts], **kwargs)
        self.replica_snapshot_prefix = (
            self.configuration.zfs_replica_snapshot_prefix)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'ZFSonLinux'
        self.zpool_list = self._get_zpool_list()
        self.dataset_creation_options = (
            self.configuration.zfs_dataset_creation_options)
        self.share_export_ip = self.configuration.zfs_share_export_ip
        self.service_ip = self.configuration.zfs_service_ip
        self.private_storage = kwargs.get('private_storage')
        self._helpers = {}

        # Set config based capabilities
        self._init_common_capabilities()

    def _init_common_capabilities(self):
        self.common_capabilities = {}
        if 'dedup=on' in self.dataset_creation_options:
            self.common_capabilities['dedupe'] = [True]
        elif 'dedup=off' in self.dataset_creation_options:
            self.common_capabilities['dedupe'] = [False]
        else:
            self.common_capabilities['dedupe'] = [True, False]

        if 'compression=off' in self.dataset_creation_options:
            self.common_capabilities['compression'] = [False]
        elif any('compression=' in option
                 for option in self.dataset_creation_options):
            self.common_capabilities['compression'] = [True]
        else:
            self.common_capabilities['compression'] = [True, False]

        # NOTE(vponomaryov): Driver uses 'quota' approach for
        # ZFS dataset. So, we can consider it as
        # 'always thin provisioned' because this driver never reserves
        # space for dataset.
        self.common_capabilities['thin_provisioning'] = [True]
        self.common_capabilities['max_over_subscription_ratio'] = (
            self.configuration.max_over_subscription_ratio)
        self.common_capabilities['qos'] = [False]

    def _get_zpool_list(self):
        zpools = []
        for zpool in self.configuration.zfs_zpool_list:
            zpool_name = zpool.split('/')[0]
            if zpool_name in zpools:
                raise exception.BadConfigurationException(
                    reason=_("Using the same zpool twice is prohibited. "
                             "Duplicate is '%(zpool)s'. List of zpools: "
                             "%(zpool_list)s.") % {
                                 'zpool': zpool,
                                 'zpool_list': ', '.join(
                                     self.configuration.zfs_zpool_list)})
            zpools.append(zpool_name)
        return zpools

    @zfs_utils.zfs_dataset_synchronized
    def _delete_dataset_or_snapshot_with_retry(self, name):
        """Attempts to destroy some dataset or snapshot with retries."""
        # NOTE(vponomaryov): it is possible to see 'dataset is busy' error
        # under the load. So, we are ok to perform retry in this case.
        mountpoint = self.get_zfs_option(name, 'mountpoint')
        if '@' not in name:
            # NOTE(vponomaryov): check that dataset has no open files.
            start_point = time.time()
            while time.time() - start_point < 60:
                try:
                    out, err = self.execute('lsof', '-w', mountpoint)
                except exception.ProcessExecutionError:
                    # NOTE(vponomaryov): lsof returns code 1 if search
                    # didn't give results.
                    break
                LOG.debug("Cannot destroy dataset '%(name)s', it has "
                          "opened files. Will wait 2 more seconds. "
                          "Out: \n%(out)s", {
                              'name': name, 'out': out})
                time.sleep(2)
            else:
                raise exception.ZFSonLinuxException(
                    msg=_("Could not destroy '%s' dataset, "
                          "because it had opened files.") % name)

        # NOTE(vponomaryov): Now, when no file usages and mounts of dataset
        # exist, destroy dataset.
        try:
            self.zfs('destroy', '-f', name)
            return
        except exception.ProcessExecutionError:
            LOG.info(_LI("Failed to destroy ZFS dataset, retrying one time"))

        # NOTE(bswartz): There appears to be a bug in ZFS when creating and
        # destroying datasets concurrently where the filesystem remains mounted
        # even though ZFS thinks it's unmounted. The most reliable workaround
        # I've found is to force the unmount, then retry the destroy, with
        # short pauses around the unmount.
        time.sleep(1)
        try:
            self.execute('sudo', 'umount', mountpoint)
        except exception.ProcessExecutionError:
            # Ignore failed umount, it's normal
            pass
        time.sleep(1)

        # This time the destroy is expected to succeed.
        self.zfs('destroy', '-f', name)

    def _setup_helpers(self):
        """Setups share helper for ZFS backend."""
        self._helpers = {}
        helpers = self.configuration.zfs_share_helpers
        if helpers:
            for helper_str in helpers:
                share_proto, __, import_str = helper_str.partition('=')
                helper = importutils.import_class(import_str)
                self._helpers[share_proto.upper()] = helper(
                    self.configuration)
        else:
            raise exception.BadConfigurationException(
                reason=_(
                    "No share helpers selected for ZFSonLinux Driver. "
                    "Please specify using config option 'zfs_share_helpers'."))

    def _get_share_helper(self, share_proto):
        """Returns share helper specific for used share protocol."""
        helper = self._helpers.get(share_proto)
        if helper:
            return helper
        else:
            raise exception.InvalidShare(
                reason=_("Wrong, unsupported or disabled protocol - "
                         "'%s'.") % share_proto)

    def do_setup(self, context):
        """Perform basic setup and checks."""
        super(self.__class__, self).do_setup(context)
        self._setup_helpers()
        for ip in (self.share_export_ip, self.service_ip):
            if not utils.is_valid_ip_address(ip, 4):
                raise exception.BadConfigurationException(
                    reason=_("Wrong IP address provided: "
                             "%s") % self.share_export_ip)

        if not self.zpool_list:
            raise exception.BadConfigurationException(
                reason=_("No zpools specified for usage: "
                         "%s") % self.zpool_list)

        # Make pool mounts shared so that cloned namespaces receive unmounts
        # and don't prevent us from unmounting datasets
        for zpool in self.configuration.zfs_zpool_list:
            self.execute('sudo', 'mount', '--make-rshared', ('/%s' % zpool))

        if self.configuration.zfs_use_ssh:
            # Check workability of SSH executor
            self.ssh_executor('whoami')

    def _get_pools_info(self):
        """Returns info about all pools used by backend."""
        pools = []
        for zpool in self.zpool_list:
            free_size = self.get_zpool_option(zpool, 'free')
            free_size = utils.translate_string_size_to_float(free_size)
            total_size = self.get_zpool_option(zpool, 'size')
            total_size = utils.translate_string_size_to_float(total_size)
            pool = {
                'pool_name': zpool,
                'total_capacity_gb': float(total_size),
                'free_capacity_gb': float(free_size),
                'reserved_percentage':
                    self.configuration.reserved_share_percentage,
            }
            pool.update(self.common_capabilities)
            if self.configuration.replication_domain:
                pool['replication_type'] = 'readable'
            pools.append(pool)
        return pools

    def _update_share_stats(self):
        """Retrieves share stats info."""
        data = {
            'share_backend_name': self.backend_name,
            'storage_protocol': 'NFS',
            'reserved_percentage':
                self.configuration.reserved_share_percentage,
            'consistency_group_support': None,
            'snapshot_support': True,
            'driver_name': 'ZFS',
            'pools': self._get_pools_info(),
        }
        if self.configuration.replication_domain:
            data['replication_type'] = 'readable'
        super(self.__class__, self)._update_share_stats(data)

    def _get_share_name(self, share_id):
        """Returns name of dataset used for given share."""
        prefix = self.configuration.zfs_dataset_name_prefix or ''
        return prefix + share_id.replace('-', '_')

    def _get_snapshot_name(self, snapshot_id):
        """Returns name of dataset snapshot used for given share snapshot."""
        prefix = self.configuration.zfs_dataset_snapshot_name_prefix or ''
        return prefix + snapshot_id.replace('-', '_')

    def _get_dataset_creation_options(self, share, is_readonly=False):
        """Returns list of options to be used for dataset creation."""
        options = ['quota=%sG' % share['size']]
        extra_specs = share_types.get_extra_specs_from_share(share)

        dedupe_set = False
        dedupe = extra_specs.get('dedupe')
        if dedupe:
            dedupe = strutils.bool_from_string(
                dedupe.lower().split(' ')[-1], default=dedupe)
            if (dedupe in self.common_capabilities['dedupe']):
                options.append('dedup=%s' % ('on' if dedupe else 'off'))
                dedupe_set = True
            else:
                raise exception.ZFSonLinuxException(msg=_(
                    "Cannot use requested '%(requested)s' value of 'dedupe' "
                    "extra spec. It does not fit allowed value '%(allowed)s' "
                    "that is configured for backend.") % {
                        'requested': dedupe,
                        'allowed': self.common_capabilities['dedupe']})

        compression_set = False
        compression_type = extra_specs.get('zfsonlinux:compression')
        if compression_type:
            if (compression_type == 'off' and
                    False in self.common_capabilities['compression']):
                options.append('compression=off')
                compression_set = True
            elif (compression_type != 'off' and
                    True in self.common_capabilities['compression']):
                options.append('compression=%s' % compression_type)
                compression_set = True
            else:
                raise exception.ZFSonLinuxException(msg=_(
                    "Cannot use value '%s' of extra spec "
                    "'zfsonlinux:compression' because compression is disabled "
                    "for this backend. Set extra spec 'compression=True' to "
                    "make scheduler pick up appropriate backend."
                ) % compression_type)

        for option in self.dataset_creation_options or []:
            if any(v in option for v in (
                    'readonly', 'sharenfs', 'sharesmb', 'quota')):
                continue
            if 'dedup' in option and dedupe_set is True:
                continue
            if 'compression' in option and compression_set is True:
                continue
            options.append(option)
        if is_readonly:
            options.append('readonly=on')
        else:
            options.append('readonly=off')
        return options

    def _get_dataset_name(self, share):
        """Returns name of dataset used for given share."""
        pool_name = share_utils.extract_host(share['host'], level='pool')

        # Pick pool with nested dataset name if set up
        for pool in self.configuration.zfs_zpool_list:
            pool_data = pool.split('/')
            if (pool_name == pool_data[0] and len(pool_data) > 1):
                pool_name = pool
                if pool_name[-1] == '/':
                    pool_name = pool_name[0:-1]
                break

        dataset_name = self._get_share_name(share['id'])
        full_dataset_name = '%(pool)s/%(dataset)s' % {
            'pool': pool_name, 'dataset': dataset_name}

        return full_dataset_name

    @ensure_share_server_not_provided
    def create_share(self, context, share, share_server=None):
        """Is called to create a share."""
        options = self._get_dataset_creation_options(share, is_readonly=False)
        cmd = ['create']
        for option in options:
            cmd.extend(['-o', option])
        dataset_name = self._get_dataset_name(share)
        cmd.append(dataset_name)

        ssh_cmd = '%(username)s@%(host)s' % {
            'username': self.configuration.zfs_ssh_username,
            'host': self.service_ip,
        }
        pool_name = share_utils.extract_host(share['host'], level='pool')
        self.private_storage.update(
            share['id'], {
                'entity_type': 'share',
                'dataset_name': dataset_name,
                'ssh_cmd': ssh_cmd,  # used in replication
                'pool_name': pool_name,  # used in replication
                'used_options': ' '.join(options),
            }
        )

        self.zfs(*cmd)

        return self._get_share_helper(
            share['share_proto']).create_exports(dataset_name)

    @ensure_share_server_not_provided
    def delete_share(self, context, share, share_server=None):
        """Is called to remove a share."""
        pool_name = self.private_storage.get(share['id'], 'pool_name')
        dataset_name = self.private_storage.get(share['id'], 'dataset_name')
        if not dataset_name:
            dataset_name = self._get_dataset_name(share)

        out, err = self.zfs('list', '-r', pool_name)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if datum['NAME'] != dataset_name:
                continue

            # Delete dataset's snapshots first
            out, err = self.zfs('list', '-r', '-t', 'snapshot', pool_name)
            snapshots = self.parse_zfs_answer(out)
            full_snapshot_prefix = (
                dataset_name + '@' + self.replica_snapshot_prefix)
            for snap in snapshots:
                if full_snapshot_prefix in snap['NAME']:
                    self._delete_dataset_or_snapshot_with_retry(snap['NAME'])

            self._get_share_helper(
                share['share_proto']).remove_exports(dataset_name)
            self._delete_dataset_or_snapshot_with_retry(dataset_name)
            break
        else:
            LOG.warning(
                _LW("Share with '%(id)s' ID and '%(name)s' NAME is "
                    "absent on backend. Nothing has been deleted."),
                {'id': share['id'], 'name': dataset_name})
        self.private_storage.delete(share['id'])

    @ensure_share_server_not_provided
    def create_snapshot(self, context, snapshot, share_server=None):
        """Is called to create a snapshot."""
        dataset_name = self.private_storage.get(
            snapshot['share_instance_id'], 'dataset_name')
        snapshot_tag = self._get_snapshot_name(snapshot['id'])
        snapshot_name = dataset_name + '@' + snapshot_tag
        self.private_storage.update(
            snapshot['snapshot_id'], {
                'entity_type': 'snapshot',
                'snapshot_tag': snapshot_tag,
            }
        )
        self.zfs('snapshot', snapshot_name)

    @ensure_share_server_not_provided
    def delete_snapshot(self, context, snapshot, share_server=None):
        """Is called to remove a snapshot."""
        return self._delete_snapshot(context, snapshot)

    def _get_saved_snapshot_name(self, snapshot_instance):
        snapshot_tag = self.private_storage.get(
            snapshot_instance['snapshot_id'], 'snapshot_tag')
        dataset_name = self.private_storage.get(
            snapshot_instance['share_instance_id'], 'dataset_name')
        snapshot_name = dataset_name + '@' + snapshot_tag
        return snapshot_name

    def _delete_snapshot(self, context, snapshot):
        snapshot_name = self._get_saved_snapshot_name(snapshot)
        out, err = self.zfs('list', '-r', '-t', 'snapshot', snapshot_name)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if datum['NAME'] == snapshot_name:
                self._delete_dataset_or_snapshot_with_retry(snapshot_name)
                break
        else:
            LOG.warning(
                _LW("Snapshot with '%(id)s' ID and '%(name)s' NAME is "
                    "absent on backend. Nothing has been deleted."),
                {'id': snapshot['id'], 'name': snapshot_name})
        self.private_storage.delete(snapshot['id'])

    @ensure_share_server_not_provided
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create a share from snapshot."""
        dataset_name = self._get_dataset_name(share)
        ssh_cmd = '%(username)s@%(host)s' % {
            'username': self.configuration.zfs_ssh_username,
            'host': self.service_ip,
        }
        pool_name = share_utils.extract_host(share['host'], level='pool')
        options = self._get_dataset_creation_options(share, is_readonly=False)
        self.private_storage.update(
            share['id'], {
                'entity_type': 'share',
                'dataset_name': dataset_name,
                'ssh_cmd': ssh_cmd,  # used in replication
                'pool_name': pool_name,  # used in replication
                'used_options': options,
            }
        )
        snapshot_name = self._get_saved_snapshot_name(snapshot)

        self.execute(
            # NOTE(vponomaryov): SSH is used as workaround for 'execute'
            # implementation restriction that does not support usage of '|'.
            'ssh', ssh_cmd,
            'sudo', 'zfs', 'send', '-vDp', snapshot_name, '|',
            'sudo', 'zfs', 'receive', '-v', dataset_name,
        )
        # Apply options based on used share type that may differ from
        # one used for original share.
        for option in options:
            self.zfs('set', option, dataset_name)

        # Delete with retry as right after creation it may be temporary busy.
        self.execute_with_retry(
            'sudo', 'zfs', 'destroy',
            dataset_name + '@' + snapshot_name.split('@')[-1])

        return self._get_share_helper(
            share['share_proto']).create_exports(dataset_name)

    def get_pool(self, share):
        """Return pool name where the share resides on.

        :param share: The share hosted by the driver.
        """
        pool_name = share_utils.extract_host(share['host'], level='pool')
        return pool_name

    @ensure_share_server_not_provided
    def ensure_share(self, context, share, share_server=None):
        """Invoked to ensure that given share is exported."""
        dataset_name = self.private_storage.get(share['id'], 'dataset_name')
        if not dataset_name:
            dataset_name = self._get_dataset_name(share)

        pool_name = share_utils.extract_host(share['host'], level='pool')
        out, err = self.zfs('list', '-r', pool_name)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if datum['NAME'] == dataset_name:
                ssh_cmd = '%(username)s@%(host)s' % {
                    'username': self.configuration.zfs_ssh_username,
                    'host': self.service_ip,
                }
                self.private_storage.update(
                    share['id'], {'ssh_cmd': ssh_cmd})
                sharenfs = self.get_zfs_option(dataset_name, 'sharenfs')
                if sharenfs != 'off':
                    self.zfs('share', dataset_name)
                export_locations = self._get_share_helper(
                    share['share_proto']).get_exports(dataset_name)
                return export_locations
        else:
            raise exception.ShareResourceNotFound(share_id=share['id'])

    def get_network_allocations_number(self):
        """ZFS does not handle networking. Return 0."""
        return 0

    @ensure_share_server_not_provided
    def extend_share(self, share, new_size, share_server=None):
        """Extends size of existing share."""
        dataset_name = self._get_dataset_name(share)
        self.zfs('set', 'quota=%sG' % new_size, dataset_name)

    @ensure_share_server_not_provided
    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share."""
        dataset_name = self._get_dataset_name(share)
        consumed_space = self.get_zfs_option(dataset_name, 'used')
        consumed_space = utils.translate_string_size_to_float(consumed_space)
        if consumed_space >= new_size:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share['id'])
        self.zfs('set', 'quota=%sG' % new_size, dataset_name)

    @ensure_share_server_not_provided
    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Updates access rules for given share."""
        dataset_name = self._get_dataset_name(share)
        return self._get_share_helper(share['share_proto']).update_access(
            dataset_name, access_rules, add_rules, delete_rules)

    def unmanage(self, share):
        """Removes the specified share from Manila management."""
        self.private_storage.delete(share['id'])

    def _get_replication_snapshot_prefix(self, replica):
        """Returns replica-based snapshot prefix."""
        replication_snapshot_prefix = "%s_%s" % (
            self.replica_snapshot_prefix, replica['id'].replace('-', '_'))
        return replication_snapshot_prefix

    def _get_replication_snapshot_tag(self, replica):
        """Returns replica- and time-based snapshot tag."""
        current_time = timeutils.utcnow().isoformat()
        snapshot_tag = "%s_time_%s" % (
            self._get_replication_snapshot_prefix(replica), current_time)
        return snapshot_tag

    def _get_active_replica(self, replica_list):
        for replica in replica_list:
            if replica['replica_state'] == constants.REPLICA_STATE_ACTIVE:
                return replica
        msg = _("Active replica not found.")
        raise exception.ReplicationException(reason=msg)

    @ensure_share_server_not_provided
    def create_replica(self, context, replica_list, new_replica,
                       access_rules, replica_snapshots, share_server=None):
        """Replicates the active replica to a new replica on this backend."""
        active_replica = self._get_active_replica(replica_list)
        src_dataset_name = self.private_storage.get(
            active_replica['id'], 'dataset_name')
        ssh_to_src_cmd = self.private_storage.get(
            active_replica['id'], 'ssh_cmd')
        dst_dataset_name = self._get_dataset_name(new_replica)

        ssh_cmd = '%(username)s@%(host)s' % {
            'username': self.configuration.zfs_ssh_username,
            'host': self.service_ip,
        }

        snapshot_tag = self._get_replication_snapshot_tag(new_replica)
        src_snapshot_name = (
            '%(dataset_name)s@%(snapshot_tag)s' % {
                'snapshot_tag': snapshot_tag,
                'dataset_name': src_dataset_name,
            }
        )
        # Save valuable data to DB
        self.private_storage.update(active_replica['id'], {
            'repl_snapshot_tag': snapshot_tag,
        })
        self.private_storage.update(new_replica['id'], {
            'entity_type': 'replica',
            'replica_type': 'readable',
            'dataset_name': dst_dataset_name,
            'ssh_cmd': ssh_cmd,
            'pool_name': share_utils.extract_host(
                new_replica['host'], level='pool'),
            'repl_snapshot_tag': snapshot_tag,
        })

        # Create temporary snapshot. It will exist until following replica sync
        # After it - new one will appear and so in loop.
        self.execute(
            'ssh', ssh_to_src_cmd,
            'sudo', 'zfs', 'snapshot', src_snapshot_name,
        )

        # Send/receive temporary snapshot
        out, err = self.execute(
            'ssh', ssh_to_src_cmd,
            'sudo', 'zfs', 'send', '-vDR', src_snapshot_name, '|',
            'ssh', ssh_cmd,
            'sudo', 'zfs', 'receive', '-v', dst_dataset_name,
        )
        msg = ("Info about replica '%(replica_id)s' creation is following: "
               "\n%(out)s")
        LOG.debug(msg, {'replica_id': new_replica['id'], 'out': out})

        # Make replica readonly
        self.zfs('set', 'readonly=on', dst_dataset_name)

        # Set original share size as quota to new replica
        self.zfs('set', 'quota=%sG' % active_replica['size'], dst_dataset_name)

        # Apply access rules from original share
        self._get_share_helper(new_replica['share_proto']).update_access(
            dst_dataset_name, access_rules, add_rules=[], delete_rules=[],
            make_all_ro=True)

        return {
            'export_locations': self._get_share_helper(
                new_replica['share_proto']).create_exports(dst_dataset_name),
            'replica_state': constants.REPLICA_STATE_IN_SYNC,
            'access_rules_status': constants.STATUS_ACTIVE,
        }

    @ensure_share_server_not_provided
    def delete_replica(self, context, replica_list, replica_snapshots, replica,
                       share_server=None):
        """Deletes a replica. This is called on the destination backend."""
        pool_name = self.private_storage.get(replica['id'], 'pool_name')
        dataset_name = self.private_storage.get(replica['id'], 'dataset_name')
        if not dataset_name:
            dataset_name = self._get_dataset_name(replica)

        # Delete dataset's snapshots first
        out, err = self.zfs('list', '-r', '-t', 'snapshot', pool_name)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if dataset_name in datum['NAME']:
                self._delete_dataset_or_snapshot_with_retry(datum['NAME'])

        # Now we delete dataset itself
        out, err = self.zfs('list', '-r', pool_name)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if datum['NAME'] == dataset_name:
                self._get_share_helper(
                    replica['share_proto']).remove_exports(dataset_name)
                self._delete_dataset_or_snapshot_with_retry(dataset_name)
                break
        else:
            LOG.warning(
                _LW("Share replica with '%(id)s' ID and '%(name)s' NAME is "
                    "absent on backend. Nothing has been deleted."),
                {'id': replica['id'], 'name': dataset_name})
        self.private_storage.delete(replica['id'])

    @ensure_share_server_not_provided
    def update_replica_state(self, context, replica_list, replica,
                             access_rules, replica_snapshots,
                             share_server=None):
        """Syncs replica and updates its 'replica_state'."""
        return self._update_replica_state(
            context, replica_list, replica, replica_snapshots, access_rules)

    def _update_replica_state(self, context, replica_list, replica,
                              replica_snapshots=None, access_rules=None):
        active_replica = self._get_active_replica(replica_list)
        src_dataset_name = self.private_storage.get(
            active_replica['id'], 'dataset_name')
        ssh_to_src_cmd = self.private_storage.get(
            active_replica['id'], 'ssh_cmd')
        ssh_to_dst_cmd = self.private_storage.get(
            replica['id'], 'ssh_cmd')
        dst_dataset_name = self.private_storage.get(
            replica['id'], 'dataset_name')

        # Create temporary snapshot
        previous_snapshot_tag = self.private_storage.get(
            replica['id'], 'repl_snapshot_tag')
        snapshot_tag = self._get_replication_snapshot_tag(replica)
        src_snapshot_name = src_dataset_name + '@' + snapshot_tag
        self.execute(
            'ssh', ssh_to_src_cmd,
            'sudo', 'zfs', 'snapshot', src_snapshot_name,
        )

        # Make sure it is readonly
        self.zfs('set', 'readonly=on', dst_dataset_name)

        # Send/receive diff between previous snapshot and last one
        out, err = self.execute(
            'ssh', ssh_to_src_cmd,
            'sudo', 'zfs', 'send', '-vDRI',
            previous_snapshot_tag, src_snapshot_name, '|',
            'ssh', ssh_to_dst_cmd,
            'sudo', 'zfs', 'receive', '-vF', dst_dataset_name,
        )
        msg = ("Info about last replica '%(replica_id)s' sync is following: "
               "\n%(out)s")
        LOG.debug(msg, {'replica_id': replica['id'], 'out': out})

        # Update DB data that will be used on following replica sync
        self.private_storage.update(active_replica['id'], {
            'repl_snapshot_tag': snapshot_tag,
        })
        self.private_storage.update(
            replica['id'], {'repl_snapshot_tag': snapshot_tag})

        # Destroy all snapshots on dst filesystem except referenced ones.
        snap_references = set()
        for repl in replica_list:
            snap_references.add(
                self.private_storage.get(repl['id'], 'repl_snapshot_tag'))

        dst_pool_name = dst_dataset_name.split('/')[0]
        out, err = self.zfs('list', '-r', '-t', 'snapshot', dst_pool_name)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if (dst_dataset_name in datum['NAME'] and
                    '@' + self.replica_snapshot_prefix in datum['NAME'] and
                    datum['NAME'].split('@')[-1] not in snap_references):
                self._delete_dataset_or_snapshot_with_retry(datum['NAME'])

        # Destroy all snapshots on src filesystem except referenced ones.
        src_pool_name = src_snapshot_name.split('/')[0]
        out, err = self.execute(
            'ssh', ssh_to_src_cmd,
            'sudo', 'zfs', 'list', '-r', '-t', 'snapshot', src_pool_name,
        )
        data = self.parse_zfs_answer(out)
        full_src_snapshot_prefix = (
            src_dataset_name + '@' +
            self._get_replication_snapshot_prefix(replica))
        for datum in data:
            if (full_src_snapshot_prefix in datum['NAME'] and
                    datum['NAME'].split('@')[-1] not in snap_references):
                self.execute_with_retry(
                    'ssh', ssh_to_src_cmd,
                    'sudo', 'zfs', 'destroy', '-f', datum['NAME'],
                )

        if access_rules:
            # Apply access rules from original share
            # TODO(vponomaryov): we should remove somehow rules that were
            # deleted on active replica after creation of secondary replica.
            # For the moment there will be difference and it can be considered
            # as a bug.
            self._get_share_helper(replica['share_proto']).update_access(
                dst_dataset_name, access_rules, add_rules=[], delete_rules=[],
                make_all_ro=True)

        # Return results
        return constants.REPLICA_STATE_IN_SYNC

    @ensure_share_server_not_provided
    def promote_replica(self, context, replica_list, replica, access_rules,
                        share_server=None):
        """Promotes secondary replica to active and active to secondary."""
        active_replica = self._get_active_replica(replica_list)
        src_dataset_name = self.private_storage.get(
            active_replica['id'], 'dataset_name')
        ssh_to_src_cmd = self.private_storage.get(
            active_replica['id'], 'ssh_cmd')
        dst_dataset_name = self.private_storage.get(
            replica['id'], 'dataset_name')
        replica_dict = {
            r['id']: {
                'id': r['id'],
                # NOTE(vponomaryov): access rules will be updated in next
                # 'sync' operation.
                'access_rules_status': constants.STATUS_OUT_OF_SYNC,
            }
            for r in replica_list
        }
        try:
            # Mark currently active replica as readonly
            self.execute(
                'ssh', ssh_to_src_cmd,
                'set', 'readonly=on', src_dataset_name,
            )

            # Create temporary snapshot of currently active replica
            snapshot_tag = self._get_replication_snapshot_tag(active_replica)
            src_snapshot_name = src_dataset_name + '@' + snapshot_tag
            self.execute(
                'ssh', ssh_to_src_cmd,
                'sudo', 'zfs', 'snapshot', src_snapshot_name,
            )

            # Apply temporary snapshot to all replicas
            for repl in replica_list:
                if repl['replica_state'] == constants.REPLICA_STATE_ACTIVE:
                    continue
                previous_snapshot_tag = self.private_storage.get(
                    repl['id'], 'repl_snapshot_tag')
                dataset_name = self.private_storage.get(
                    repl['id'], 'dataset_name')
                ssh_to_dst_cmd = self.private_storage.get(
                    repl['id'], 'ssh_cmd')

                try:
                    # Send/receive diff between previous snapshot and last one
                    out, err = self.execute(
                        'ssh', ssh_to_src_cmd,
                        'sudo', 'zfs', 'send', '-vDRI',
                        previous_snapshot_tag, src_snapshot_name, '|',
                        'ssh', ssh_to_dst_cmd,
                        'sudo', 'zfs', 'receive', '-vF', dataset_name,
                    )
                except exception.ProcessExecutionError as e:
                    LOG.warning(_LW("Failed to sync replica %(id)s. %(e)s"),
                                {'id': repl['id'], 'e': e})
                    replica_dict[repl['id']]['replica_state'] = (
                        constants.REPLICA_STATE_OUT_OF_SYNC)
                    continue

                msg = ("Info about last replica '%(replica_id)s' "
                       "sync is following: \n%(out)s")
                LOG.debug(msg, {'replica_id': repl['id'], 'out': out})

                # Update latest replication snapshot for replica
                self.private_storage.update(
                    repl['id'], {'repl_snapshot_tag': snapshot_tag})

            # Update latest replication snapshot for currently active replica
            self.private_storage.update(
                active_replica['id'], {'repl_snapshot_tag': snapshot_tag})

            replica_dict[active_replica['id']]['replica_state'] = (
                constants.REPLICA_STATE_IN_SYNC)
        except Exception as e:
            LOG.warning(
                _LW("Failed to update currently active replica. \n%s"), e)

            replica_dict[active_replica['id']]['replica_state'] = (
                constants.REPLICA_STATE_OUT_OF_SYNC)

            # Create temporary snapshot of new replica and sync it with other
            # secondary replicas.
            snapshot_tag = self._get_replication_snapshot_tag(replica)
            src_snapshot_name = dst_dataset_name + '@' + snapshot_tag
            ssh_to_src_cmd = self.private_storage.get(replica['id'], 'ssh_cmd')
            self.zfs('snapshot', src_snapshot_name)
            for repl in replica_list:
                if (repl['replica_state'] == constants.REPLICA_STATE_ACTIVE or
                        repl['id'] == replica['id']):
                    continue
                previous_snapshot_tag = self.private_storage.get(
                    repl['id'], 'repl_snapshot_tag')
                dataset_name = self.private_storage.get(
                    repl['id'], 'dataset_name')
                ssh_to_dst_cmd = self.private_storage.get(
                    repl['id'], 'ssh_cmd')

                try:
                    # Send/receive diff between previous snapshot and last one
                    out, err = self.execute(
                        'ssh', ssh_to_src_cmd,
                        'sudo', 'zfs', 'send', '-vDRI',
                        previous_snapshot_tag, src_snapshot_name, '|',
                        'ssh', ssh_to_dst_cmd,
                        'sudo', 'zfs', 'receive', '-vF', dataset_name,
                    )
                except exception.ProcessExecutionError as e:
                    LOG.warning(_LW("Failed to sync replica %(id)s. %(e)s"),
                                {'id': repl['id'], 'e': e})
                    replica_dict[repl['id']]['replica_state'] = (
                        constants.REPLICA_STATE_OUT_OF_SYNC)
                    continue

                msg = ("Info about last replica '%(replica_id)s' "
                       "sync is following: \n%(out)s")
                LOG.debug(msg, {'replica_id': repl['id'], 'out': out})

                # Update latest replication snapshot for replica
                self.private_storage.update(
                    repl['id'], {'repl_snapshot_tag': snapshot_tag})

            # Update latest replication snapshot for new active replica
            self.private_storage.update(
                replica['id'], {'repl_snapshot_tag': snapshot_tag})

        replica_dict[replica['id']]['replica_state'] = (
            constants.REPLICA_STATE_ACTIVE)

        self._get_share_helper(replica['share_proto']).update_access(
            dst_dataset_name, access_rules, add_rules=[], delete_rules=[])

        replica_dict[replica['id']]['access_rules_status'] = (
            constants.STATUS_ACTIVE)

        self.zfs('set', 'readonly=off', dst_dataset_name)

        return list(replica_dict.values())

    @ensure_share_server_not_provided
    def create_replicated_snapshot(self, context, replica_list,
                                   replica_snapshots, share_server=None):
        """Create a snapshot and update across the replicas."""
        active_replica = self._get_active_replica(replica_list)
        src_dataset_name = self.private_storage.get(
            active_replica['id'], 'dataset_name')
        ssh_to_src_cmd = self.private_storage.get(
            active_replica['id'], 'ssh_cmd')
        replica_snapshots_dict = {
            si['id']: {'id': si['id']} for si in replica_snapshots}

        active_snapshot_instance_id = [
            si['id'] for si in replica_snapshots
            if si['share_instance_id'] == active_replica['id']][0]
        snapshot_tag = self._get_snapshot_name(active_snapshot_instance_id)
        # Replication should not be dependent on manually created snapshots
        # so, create additional one, newer, that will be used for replication
        # synchronizations.
        repl_snapshot_tag = self._get_replication_snapshot_tag(active_replica)
        src_snapshot_name = src_dataset_name + '@' + repl_snapshot_tag

        self.private_storage.update(
            replica_snapshots[0]['snapshot_id'], {
                'entity_type': 'snapshot',
                'snapshot_tag': snapshot_tag,
            }
        )
        for tag in (snapshot_tag, repl_snapshot_tag):
            self.execute(
                'ssh', ssh_to_src_cmd,
                'sudo', 'zfs', 'snapshot', src_dataset_name + '@' + tag,
            )

        # Populate snapshot to all replicas
        for replica_snapshot in replica_snapshots:
            replica_id = replica_snapshot['share_instance_id']
            if replica_id == active_replica['id']:
                replica_snapshots_dict[replica_snapshot['id']]['status'] = (
                    constants.STATUS_AVAILABLE)
                continue
            previous_snapshot_tag = self.private_storage.get(
                replica_id, 'repl_snapshot_tag')
            dst_dataset_name = self.private_storage.get(
                replica_id, 'dataset_name')
            ssh_to_dst_cmd = self.private_storage.get(replica_id, 'ssh_cmd')

            try:
                # Send/receive diff between previous snapshot and last one
                out, err = self.execute(
                    'ssh', ssh_to_src_cmd,
                    'sudo', 'zfs', 'send', '-vDRI',
                    previous_snapshot_tag, src_snapshot_name, '|',
                    'ssh', ssh_to_dst_cmd,
                    'sudo', 'zfs', 'receive', '-vF', dst_dataset_name,
                )
            except exception.ProcessExecutionError as e:
                LOG.warning(
                    _LW("Failed to sync snapshot instance %(id)s. %(e)s"),
                    {'id': replica_snapshot['id'], 'e': e})
                replica_snapshots_dict[replica_snapshot['id']]['status'] = (
                    constants.STATUS_ERROR)
                continue

            replica_snapshots_dict[replica_snapshot['id']]['status'] = (
                constants.STATUS_AVAILABLE)

            msg = ("Info about last replica '%(replica_id)s' "
                   "sync is following: \n%(out)s")
            LOG.debug(msg, {'replica_id': replica_id, 'out': out})

            # Update latest replication snapshot for replica
            self.private_storage.update(
                replica_id, {'repl_snapshot_tag': repl_snapshot_tag})

        # Update latest replication snapshot for currently active replica
        self.private_storage.update(
            active_replica['id'], {'repl_snapshot_tag': repl_snapshot_tag})

        return list(replica_snapshots_dict.values())

    @ensure_share_server_not_provided
    def delete_replicated_snapshot(self, context, replica_list,
                                   replica_snapshots, share_server=None):
        """Delete a snapshot by deleting its instances across the replicas."""
        active_replica = self._get_active_replica(replica_list)
        replica_snapshots_dict = {
            si['id']: {'id': si['id']} for si in replica_snapshots}

        for replica_snapshot in replica_snapshots:
            replica_id = replica_snapshot['share_instance_id']
            snapshot_name = self._get_saved_snapshot_name(replica_snapshot)
            if active_replica['id'] == replica_id:
                self._delete_snapshot(context, replica_snapshot)
                replica_snapshots_dict[replica_snapshot['id']]['status'] = (
                    constants.STATUS_DELETED)
                continue
            ssh_cmd = self.private_storage.get(replica_id, 'ssh_cmd')
            out, err = self.execute(
                'ssh', ssh_cmd,
                'sudo', 'zfs', 'list', '-r', '-t', 'snapshot', snapshot_name,
            )
            data = self.parse_zfs_answer(out)
            for datum in data:
                if datum['NAME'] != snapshot_name:
                    continue
                self.execute_with_retry(
                    'ssh', ssh_cmd,
                    'sudo', 'zfs', 'destroy', '-f', datum['NAME'],
                )

            self.private_storage.delete(replica_snapshot['id'])
            replica_snapshots_dict[replica_snapshot['id']]['status'] = (
                constants.STATUS_DELETED)

        return list(replica_snapshots_dict.values())

    @ensure_share_server_not_provided
    def update_replicated_snapshot(self, context, replica_list,
                                   share_replica, replica_snapshots,
                                   replica_snapshot, share_server=None):
        """Update the status of a snapshot instance that lives on a replica."""

        self._update_replica_state(context, replica_list, share_replica)

        snapshot_name = self._get_saved_snapshot_name(replica_snapshot)

        out, err = self.zfs('list', '-r', '-t', 'snapshot', snapshot_name)
        data = self.parse_zfs_answer(out)
        snapshot_found = False
        for datum in data:
            if datum['NAME'] == snapshot_name:
                snapshot_found = True
                break
        return_dict = {'id': replica_snapshot['id']}
        if snapshot_found:
            return_dict.update({'status': constants.STATUS_AVAILABLE})
        else:
            return_dict.update({'status': constants.STATUS_ERROR})

        return return_dict
