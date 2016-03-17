# Copyright (c) 2015 Hitachi Data Systems, Inc.
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

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
import six

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.i18n import _LI
from manila.i18n import _LW
from manila.share import driver

LOG = log.getLogger(__name__)

hds_hnas_opts = [
    cfg.StrOpt('hds_hnas_ip',
               help="HNAS management interface IP for communication "
                    "between Manila controller and HNAS."),
    cfg.StrOpt('hds_hnas_user',
               help="HNAS username Base64 String in order to perform tasks "
                    "such as create file-systems and network interfaces."),
    cfg.StrOpt('hds_hnas_password',
               secret=True,
               help="HNAS user password. Required only if private key is not "
                    "provided."),
    cfg.IntOpt('hds_hnas_evs_id',
               help="Specify which EVS this backend is assigned to."),
    cfg.StrOpt('hds_hnas_evs_ip',
               help="Specify IP for mounting shares."),
    cfg.StrOpt('hds_hnas_file_system_name',
               help="Specify file-system name for creating shares."),
    cfg.StrOpt('hds_hnas_ssh_private_key',
               secret=True,
               help="RSA/DSA private key value used to connect into HNAS. "
                    "Required only if password is not provided."),
    cfg.StrOpt('hds_hnas_cluster_admin_ip0',
               help="The IP of the clusters admin node. Only set in HNAS "
                    "multinode clusters."),
    cfg.IntOpt('hds_hnas_stalled_job_timeout',
               default=30,
               help="The time (in seconds) to wait for stalled HNAS jobs "
                    "before aborting."),
    cfg.StrOpt('hds_hnas_driver_helper',
               default='manila.share.drivers.hitachi.ssh.HNASSSHBackend',
               help="Python class to be used for driver helper."),
]

CONF = cfg.CONF
CONF.register_opts(hds_hnas_opts)


class HDSHNASDriver(driver.ShareDriver):
    """Manila HNAS Driver implementation.

    1.0.0 - Initial Version.
    2.0.0 - Refactoring, bugfixes, implemented Share Shrink and Update Access.
    """

    def __init__(self, *args, **kwargs):
        """Do initialization."""

        LOG.debug("Invoking base constructor for Manila HDS HNAS Driver.")
        super(HDSHNASDriver, self).__init__(False, *args, **kwargs)

        LOG.debug("Setting up attributes for Manila HDS HNAS Driver.")
        self.configuration.append_config_values(hds_hnas_opts)

        LOG.debug("Reading config parameters for Manila HDS HNAS Driver.")
        self.backend_name = self.configuration.safe_get('share_backend_name')
        hnas_helper = self.configuration.safe_get('hds_hnas_driver_helper')
        hnas_ip = self.configuration.safe_get('hds_hnas_ip')
        hnas_username = self.configuration.safe_get('hds_hnas_user')
        hnas_password = self.configuration.safe_get('hds_hnas_password')
        hnas_evs_id = self.configuration.safe_get('hds_hnas_evs_id')
        self.hnas_evs_ip = self.configuration.safe_get('hds_hnas_evs_ip')
        self.fs_name = self.configuration.safe_get('hds_hnas_file_system_name')
        ssh_private_key = self.configuration.safe_get(
            'hds_hnas_ssh_private_key')
        cluster_admin_ip0 = self.configuration.safe_get(
            'hds_hnas_cluster_admin_ip0')
        self.private_storage = kwargs.get('private_storage')
        job_timeout = self.configuration.safe_get(
            'hds_hnas_stalled_job_timeout')

        if hnas_helper is None:
            msg = _("The config parameter hds_hnas_driver_helper is not set.")
            raise exception.InvalidParameterValue(err=msg)

        if hnas_evs_id is None:
            msg = _("The config parameter hds_hnas_evs_id is not set.")
            raise exception.InvalidParameterValue(err=msg)

        if self.hnas_evs_ip is None:
            msg = _("The config parameter hds_hnas_evs_ip is not set.")
            raise exception.InvalidParameterValue(err=msg)

        if hnas_ip is None:
            msg = _("The config parameter hds_hnas_ip is not set.")
            raise exception.InvalidParameterValue(err=msg)

        if hnas_username is None:
            msg = _("The config parameter hds_hnas_user is not set.")
            raise exception.InvalidParameterValue(err=msg)

        if hnas_password is None and ssh_private_key is None:
            msg = _("Credentials configuration parameters missing: "
                    "you need to set hds_hnas_password or "
                    "hds_hnas_ssh_private_key.")
            raise exception.InvalidParameterValue(err=msg)

        LOG.debug("Initializing HNAS Layer.")

        helper = importutils.import_class(hnas_helper)

        self.hnas = helper(hnas_ip, hnas_username, hnas_password,
                           ssh_private_key, cluster_admin_ip0,
                           hnas_evs_id, self.hnas_evs_ip, self.fs_name,
                           job_timeout)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules for given share.

        :param context: The `context.RequestContext` object for the request
        :param share: Share that will have its access rules updated.
        :param access_rules: All access rules for given share. This list
        is enough to update the access rules for given share.
        :param add_rules: Empty List or List of access rules which should be
        added. access_rules already contains these rules. Not used by this
        driver.
        :param delete_rules: Empty List or List of access rules which should be
        removed. access_rules doesn't contain these rules. Not used by
        this driver.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        """

        try:
            self._ensure_share(share['id'])
        except exception.HNASItemNotFoundException:
            raise exception.ShareResourceNotFound(share_id=share['id'])

        host_list = []
        share_id = self._get_hnas_share_id(share['id'])

        for rule in access_rules:
            if rule['access_type'].lower() != 'ip':
                msg = _("Only IP access type currently supported.")
                raise exception.InvalidShareAccess(reason=msg)

            if rule['access_level'] == constants.ACCESS_LEVEL_RW:
                host_list.append(rule['access_to'] + '(' +
                                 rule['access_level'] +
                                 ',norootsquash)')
            else:
                host_list.append(rule['access_to'] + '(' +
                                 rule['access_level'] + ')')

        self.hnas.update_access_rule(share_id, host_list)

        if host_list:
            LOG.debug("Share %(share)s has the rules: %(rules)s",
                      {'share': share_id, 'rules': ', '.join(host_list)})
        else:
            LOG.debug("Share %(share)s has no rules.", {'share': share_id})

    def create_share(self, context, share, share_server=None):
        """Creates share.

        :param context: The `context.RequestContext` object for the request
        :param share: Share that will be created.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        :returns: Returns a path of EVS IP concatenate with the path
        of share in the filesystem (e.g. ['172.24.44.10:/shares/id']).
        """
        LOG.debug("Creating share in HNAS: %(shr)s.",
                  {'shr': share['id']})

        if share['share_proto'].lower() != 'nfs':
            msg = _("Only NFS protocol is currently supported.")
            raise exception.ShareBackendException(msg=msg)

        path = self._create_share(share['id'], share['size'])
        uri = self.hnas_evs_ip + ":" + path

        LOG.debug("Share created successfully on path: %(uri)s.",
                  {'uri': uri})
        return uri

    def delete_share(self, context, share, share_server=None):
        """Deletes share.

        :param context: The `context.RequestContext` object for the request
        :param share: Share that will be deleted.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        """
        share_id = self._get_hnas_share_id(share['id'])

        LOG.debug("Deleting share in HNAS: %(shr)s.",
                  {'shr': share['id']})

        self._delete_share(share_id)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates snapshot.

        :param context: The `context.RequestContext` object for the request
        :param snapshot: Snapshot that will be created.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        """
        share_id = self._get_hnas_share_id(snapshot['share_id'])

        LOG.debug("The snapshot of share %(ss_sid)s will be created with "
                  "id %(ss_id)s.", {'ss_sid': snapshot['share_id'],
                                    'ss_id': snapshot['id']})

        self._create_snapshot(share_id, snapshot['id'])
        LOG.info(_LI("Snapshot %(id)s successfully created."),
                 {'id': snapshot['id']})

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes snapshot.

        :param context: The `context.RequestContext` object for the request
        :param snapshot: Snapshot that will be deleted.
        :param share_server:Data structure with share server information.
        Not used by this driver.
        """
        share_id = self._get_hnas_share_id(snapshot['share_id'])

        LOG.debug("The snapshot %(ss_sid)s will be deleted. The related "
                  "share ID is %(ss_id)s.",
                  {'ss_sid': snapshot['share_id'], 'ss_id': snapshot['id']})

        self._delete_snapshot(share_id, snapshot['id'])
        LOG.info(_LI("Snapshot %(id)s successfully deleted."),
                 {'id': snapshot['id']})

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Creates a new share from snapshot.

        :param context: The `context.RequestContext` object for the request
        :param share: Information about the new share.
        :param snapshot: Information about the snapshot that will be copied
        to new share.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        :returns: Returns a path of EVS IP concatenate with the path
        of new share in the filesystem (e.g. ['172.24.44.10:/shares/id']).
        """
        LOG.debug("Creating a new share from snapshot: %(ss_id)s.",
                  {'ss_id': snapshot['id']})

        path = self._create_share_from_snapshot(share, snapshot)
        uri = self.hnas_evs_ip + ":" + path

        LOG.debug("Share created successfully on path: %(uri)s.",
                  {'uri': uri})
        return uri

    def ensure_share(self, context, share, share_server=None):
        """Ensure that share is exported.

        :param context: The `context.RequestContext` object for the request
        :param share: Share that will be checked.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        :returns: Returns a list of EVS IP concatenated with the path
        of share in the filesystem (e.g. ['172.24.44.10:/shares/id']).
        """
        LOG.debug("Ensuring share in HNAS: %(shr)s.",
                  {'shr': share['id']})

        share_id = self._get_hnas_share_id(share['id'])

        path = self._ensure_share(share_id)

        export = self.hnas_evs_ip + ":" + path
        export_list = [export]

        LOG.debug("Share ensured in HNAS: %(shr)s.",
                  {'shr': share['id']})
        return export_list

    def extend_share(self, share, new_size, share_server=None):
        """Extends a share to new size.

        :param share: Share that will be extended.
        :param new_size: New size of share.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        """
        share_id = self._get_hnas_share_id(share['id'])

        LOG.debug("Expanding share in HNAS: %(shr_id)s.",
                  {'shr_id': share['id']})

        self._extend_share(share_id, share['size'], new_size)
        LOG.info(_LI("Share %(shr_id)s successfully extended to "
                     "%(shr_size)s."),
                 {'shr_id': share['id'],
                  'shr_size': six.text_type(new_size)})

    # TODO(alyson): Implement in DHSS = true mode
    def get_network_allocations_number(self):
        """Track allocations_number in DHSS = true.

        When using the setting driver_handles_share_server = false
        does not require to track allocations_number because we do not handle
        network stuff.
        """
        return 0

    def _update_share_stats(self, data=None):
        """Updates the Capability of Backend."""
        LOG.debug("Updating Backend Capability Information - HDS HNAS.")

        self._check_fs_mounted()

        total_space, free_space = self.hnas.get_stats()

        reserved = self.configuration.safe_get('reserved_share_percentage')

        data = {
            'share_backend_name': self.backend_name,
            'driver_handles_share_servers': self.driver_handles_share_servers,
            'vendor_name': 'HDS',
            'driver_version': '2.0.0',
            'storage_protocol': 'NFS',
            'total_capacity_gb': total_space,
            'free_capacity_gb': free_space,
            'reserved_percentage': reserved,
            'qos': False,
            'thin_provisioning': True,
        }

        LOG.info(_LI("HNAS Capabilities: %(data)s."),
                 {'data': six.text_type(data)})

        super(HDSHNASDriver, self)._update_share_stats(data)

    def manage_existing(self, share, driver_options):
        """Manages a share that exists on backend.

        :param share: Share that will be managed.
        :param driver_options: Empty dict or dict with 'volume_id' option.
        :returns: Returns a dict with size of share managed
        and its location (your path in file-system).
        """
        share_id = self._get_hnas_share_id(share['id'])

        if share_id != share['id']:
            msg = _("Share ID %s already exists, cannot manage.") % share_id
            raise exception.HNASBackendException(msg=msg)

        LOG.info(_LI("Share %(shr_path)s will be managed with ID %(shr_id)s."),
                 {'shr_path': share['export_locations'][0]['path'],
                  'shr_id': share['id']})

        old_path_info = share['export_locations'][0]['path'].split(':')
        old_path = old_path_info[1].split('/')

        if len(old_path) == 3:
            evs_ip = old_path_info[0]
            share_id = old_path[2]
        else:
            msg = _("Incorrect path. It should have the following format: "
                    "IP:/shares/share_id.")
            raise exception.ShareBackendException(msg=msg)

        if evs_ip != self.hnas_evs_ip:
            msg = _("The EVS IP %(evs)s is not "
                    "configured.") % {'evs': evs_ip}
            raise exception.ShareBackendException(msg=msg)

        if self.backend_name not in share['host']:
            msg = _("The backend passed in the host parameter (%(shr)s) is "
                    "not configured.") % {'shr': share['host']}
            raise exception.ShareBackendException(msg=msg)

        output = self._manage_existing(share_id)
        self.private_storage.update(
            share['id'], {'hnas_id': share_id})

        return output

    def unmanage(self, share):
        """Unmanages a share.

        :param share: Share that will be unmanaged.
        """
        self.private_storage.delete(share['id'])

        if len(share['export_locations']) == 0:
            LOG.info(_LI("The share with ID %(shr_id)s is no longer being "
                         "managed."), {'shr_id': share['id']})
        else:
            LOG.info(_LI("The share with current path %(shr_path)s and ID "
                         "%(shr_id)s is no longer being managed."),
                     {'shr_path': share['export_locations'][0]['path'],
                         'shr_id': share['id']})

    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks a share to new size.

        :param share: Share that will be shrunk.
        :param new_size: New size of share.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        """
        share_id = self._get_hnas_share_id(share['id'])

        LOG.debug("Shrinking share in HNAS: %(shr_id)s.",
                  {'shr_id': share['id']})

        self._shrink_share(share_id, share['size'], new_size)
        LOG.info(_LI("Share %(shr_id)s successfully shrunk to "
                     "%(shr_size)sG."),
                 {'shr_id': share['id'],
                  'shr_size': six.text_type(new_size)})

    def _get_hnas_share_id(self, share_id):
        hnas_id = self.private_storage.get(share_id, 'hnas_id')

        if hnas_id is None:
            hnas_id = share_id
        return hnas_id

    def _create_share(self, share_id, share_size):
        """Creates share.

        Creates a virtual-volume, adds a quota limit and exports it.
        :param share_id: ID of share that will be created.
        :param share_size: Size limit of share.
        :returns: Returns a path of /shares/share_id if the export was
        created successfully.
        """
        path = '/shares/' + share_id

        self._check_fs_mounted()

        self.hnas.vvol_create(share_id)

        self.hnas.quota_add(share_id, share_size)

        LOG.debug("Share created with id %(shr)s, size %(size)sG.",
                  {'shr': share_id, 'size': share_size})

        try:
            # Create NFS export
            self.hnas.nfs_export_add(share_id)
            LOG.debug("NFS Export created to %(shr)s.",
                      {'shr': share_id})
            return path
        except exception.HNASBackendException as e:
            with excutils.save_and_reraise_exception():
                self.hnas.vvol_delete(share_id)
                msg = six.text_type(e)
                LOG.exception(msg)

    def _check_fs_mounted(self):
        if not self.hnas.check_fs_mounted():
            LOG.debug("Filesystem %(fs)s is unmounted. Mounting...",
                      {'fs': self.fs_name})
            self.hnas.mount()

    def _ensure_share(self, share_id):
        """Ensure that share is exported.

        :param share_id: ID of share that will be checked.
        :returns: Returns a path of /shares/share_id if the export is ok.
        """
        path = '/shares/' + share_id

        self._check_fs_mounted()

        self.hnas.check_vvol(share_id)
        self.hnas.check_quota(share_id)
        self.hnas.check_export(share_id)
        return path

    def _shrink_share(self, share_id, old_size, new_size):
        """Shrinks a share to new size.

        :param share_id: ID of share that will be shrunk.
        :param old_size: Current size of share that will be shrunk.
        :param new_size: New size of share after shrink operation.
        """
        self._ensure_share(share_id)

        usage = self.hnas.get_share_usage(share_id)

        LOG.debug("Usage space in share %(share)s: %(usage)sG",
                  {'share': share_id, 'usage': usage})

        if new_size > usage:
            self.hnas.modify_quota(share_id, new_size)
        else:
            raise exception.ShareShrinkingPossibleDataLoss(share_id=share_id)

    def _extend_share(self, share_id, old_size, new_size):
        """Extends a share to new size.

        :param share_id: ID of share that will be extended.
        :param old_size: Current size of share that will be extended.
        :param new_size: New size of share after extend operation.
        """
        self._ensure_share(share_id)

        total, available_space = self.hnas.get_stats()

        LOG.debug("Available space in filesystem: %(space)sG.",
                  {'space': available_space})

        if (new_size - old_size) < available_space:
            self.hnas.modify_quota(share_id, new_size)
        else:
            msg = (_("Share %s cannot be extended due to insufficient space.")
                   % share_id)
            raise exception.HNASBackendException(msg=msg)

    def _delete_share(self, share_id):
        """Deletes share.

        It uses tree-delete-job-submit to format and delete virtual-volumes.
        Quota is deleted with virtual-volume.
        :param share_id: ID of share that will be deleted.
        """
        self._check_fs_mounted()

        self.hnas.nfs_export_del(share_id)
        self.hnas.vvol_delete(share_id)

        LOG.debug("Export and share successfully deleted: %(shr)s on Manila.",
                  {'shr': share_id})

    def _manage_existing(self, share_id):
        """Manages a share that exists on backend.

        :param share_id: ID of share that will be managed.
        :returns: Returns a dict with size of share managed
        and its location (your path in file-system).
        """
        self._ensure_share(share_id)

        share_size = self.hnas.get_share_quota(share_id)
        if share_size is None:
            msg = (_("The share %s trying to be managed does not have a "
                     "quota limit, please set it before manage.") % share_id)
            raise exception.ManageInvalidShare(msg)

        path = self.hnas_evs_ip + ':/shares/' + share_id

        return {'size': share_size, 'export_locations': [path]}

    def _create_snapshot(self, share_id, snapshot_id):
        """Creates a snapshot of share.

        It copies the directory and all files to a new directory inside
        /snapshots/share_id/.
        :param share_id: ID of share for snapshot.
        :param snapshot_id: ID of new snapshot.
        """
        self._ensure_share(share_id)

        saved_list = self.hnas.get_host_list(share_id)
        new_list = []
        for access in saved_list:
            new_list.append(access.replace('(rw)', '(ro)'))
        self.hnas.update_access_rule(share_id, new_list)

        src_path = '/shares/' + share_id
        dest_path = '/snapshots/' + share_id + '/' + snapshot_id
        try:
            self.hnas.tree_clone(src_path, dest_path)
        except exception.HNASNothingToCloneException:
            LOG.warning(_LW("Source directory is empty, creating an empty "
                            "directory."))
            self.hnas.create_directory(dest_path)
        finally:
            self.hnas.update_access_rule(share_id, saved_list)

    def _delete_snapshot(self, share_id, snapshot_id):
        """Deletes snapshot.

        It receives the share_id only to mount the path for snapshot.
        :param share_id: ID of share that snapshot was created.
        :param snapshot_id: ID of snapshot.
        """
        path = '/snapshots/' + share_id + '/' + snapshot_id
        self.hnas.tree_delete(path)
        path = '/snapshots/' + share_id
        self.hnas.delete_directory(path)

    def _create_share_from_snapshot(self, share, snapshot):
        """Creates a new share from snapshot.

        It copies everything from snapshot directory to a new vvol,
        set a quota limit for it and export.
        :param share: a dict from new share.
        :param snapshot: a dict from snapshot that will be copied to
        new share.
        :returns: Returns the path for new share.
        """
        dest_path = '/shares/' + share['id']
        src_path = '/snapshots/' + snapshot['share_id'] + '/' + snapshot['id']

        # Before copying everything to new vvol, we need to create it,
        # because we only can transform an empty directory into a vvol.

        self._check_fs_mounted()

        self.hnas.vvol_create(share['id'])

        self.hnas.quota_add(share['id'], share['size'])

        try:
            self.hnas.tree_clone(src_path, dest_path)
        except exception.HNASNothingToCloneException:
            LOG.warning(_LW("Source directory is empty, exporting "
                            "directory."))
        self.hnas.nfs_export_add(share['id'])
        return dest_path
