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

import os

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
import six

from manila.common import constants
from manila import exception
from manila.i18n import _, _LE, _LI, _LW
from manila.share import driver

LOG = log.getLogger(__name__)

hitachi_hnas_opts = [
    cfg.StrOpt('hitachi_hnas_ip',
               deprecated_name='hds_hnas_ip',
               help="HNAS management interface IP for communication "
                    "between Manila controller and HNAS."),
    cfg.StrOpt('hitachi_hnas_user',
               deprecated_name='hds_hnas_user',
               help="HNAS username Base64 String in order to perform tasks "
                    "such as create file-systems and network interfaces."),
    cfg.StrOpt('hitachi_hnas_password',
               deprecated_name='hds_hnas_password',
               secret=True,
               help="HNAS user password. Required only if private key is not "
                    "provided."),
    cfg.IntOpt('hitachi_hnas_evs_id',
               deprecated_name='hds_hnas_evs_id',
               help="Specify which EVS this backend is assigned to."),
    cfg.StrOpt('hitachi_hnas_evs_ip',
               deprecated_name='hds_hnas_evs_ip',
               help="Specify IP for mounting shares."),
    cfg.StrOpt('hitachi_hnas_file_system_name',
               deprecated_name='hds_hnas_file_system_name',
               help="Specify file-system name for creating shares."),
    cfg.StrOpt('hitachi_hnas_ssh_private_key',
               deprecated_name='hds_hnas_ssh_private_key',
               secret=True,
               help="RSA/DSA private key value used to connect into HNAS. "
                    "Required only if password is not provided."),
    cfg.StrOpt('hitachi_hnas_cluster_admin_ip0',
               deprecated_name='hds_hnas_cluster_admin_ip0',
               help="The IP of the clusters admin node. Only set in HNAS "
                    "multinode clusters."),
    cfg.IntOpt('hitachi_hnas_stalled_job_timeout',
               deprecated_name='hds_hnas_stalled_job_timeout',
               default=30,
               help="The time (in seconds) to wait for stalled HNAS jobs "
                    "before aborting."),
    cfg.StrOpt('hitachi_hnas_driver_helper',
               deprecated_name='hds_hnas_driver_helper',
               default='manila.share.drivers.hitachi.hnas.ssh.HNASSSHBackend',
               help="Python class to be used for driver helper."),
    cfg.BoolOpt('hitachi_hnas_allow_cifs_snapshot_while_mounted',
                deprecated_name='hds_hnas_allow_cifs_snapshot_while_mounted',
                default=False,
                help="By default, CIFS snapshots are not allowed to be taken "
                     "when the share has clients connected because consistent "
                     "point-in-time replica cannot be guaranteed for all "
                     "files. Enabling this might cause inconsistent snapshots "
                     "on CIFS shares."),
]

CONF = cfg.CONF
CONF.register_opts(hitachi_hnas_opts)


class HitachiHNASDriver(driver.ShareDriver):
    """Manila HNAS Driver implementation.

    1.0.0 - Initial Version.
    2.0.0 - Refactoring, bugfixes, implemented Share Shrink and Update Access.
    3.0.0 - New driver location, implemented support for CIFS protocol.
    """

    def __init__(self, *args, **kwargs):
        """Do initialization."""

        LOG.debug("Invoking base constructor for Manila Hitachi HNAS Driver.")
        super(HitachiHNASDriver, self).__init__(False, *args, **kwargs)

        LOG.debug("Setting up attributes for Manila Hitachi HNAS Driver.")
        self.configuration.append_config_values(hitachi_hnas_opts)

        LOG.debug("Reading config parameters for Manila Hitachi HNAS Driver.")
        self.backend_name = self.configuration.safe_get('share_backend_name')
        hnas_helper = self.configuration.safe_get('hitachi_hnas_driver_helper')
        hnas_ip = self.configuration.safe_get('hitachi_hnas_ip')
        hnas_username = self.configuration.safe_get('hitachi_hnas_user')
        hnas_password = self.configuration.safe_get('hitachi_hnas_password')
        hnas_evs_id = self.configuration.safe_get('hitachi_hnas_evs_id')
        self.hnas_evs_ip = self.configuration.safe_get('hitachi_hnas_evs_ip')
        self.fs_name = self.configuration.safe_get(
            'hitachi_hnas_file_system_name')
        self.cifs_snapshot = self.configuration.safe_get(
            'hitachi_hnas_allow_cifs_snapshot_while_mounted')
        ssh_private_key = self.configuration.safe_get(
            'hitachi_hnas_ssh_private_key')
        cluster_admin_ip0 = self.configuration.safe_get(
            'hitachi_hnas_cluster_admin_ip0')
        self.private_storage = kwargs.get('private_storage')
        job_timeout = self.configuration.safe_get(
            'hitachi_hnas_stalled_job_timeout')

        if hnas_helper is None:
            msg = _("The config parameter hitachi_hnas_driver_helper is not "
                    "set.")
            raise exception.InvalidParameterValue(err=msg)

        if hnas_evs_id is None:
            msg = _("The config parameter hitachi_hnas_evs_id is not set.")
            raise exception.InvalidParameterValue(err=msg)

        if self.hnas_evs_ip is None:
            msg = _("The config parameter hitachi_hnas_evs_ip is not set.")
            raise exception.InvalidParameterValue(err=msg)

        if hnas_ip is None:
            msg = _("The config parameter hitachi_hnas_ip is not set.")
            raise exception.InvalidParameterValue(err=msg)

        if hnas_username is None:
            msg = _("The config parameter hitachi_hnas_user is not set.")
            raise exception.InvalidParameterValue(err=msg)

        if hnas_password is None and ssh_private_key is None:
            msg = _("Credentials configuration parameters missing: "
                    "you need to set hitachi_hnas_password or "
                    "hitachi_hnas_ssh_private_key.")
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
        :param access_rules: All access rules for given share.
        :param add_rules: Empty List or List of access rules which should be
            added. access_rules already contains these rules.
        :param delete_rules: Empty List or List of access rules which should be
            removed. access_rules doesn't contain these rules.
        :param share_server: Data structure with share server information.
            Not used by this driver.
        """

        hnas_share_id = self._get_hnas_share_id(share['id'])

        try:
            self._ensure_share(share, hnas_share_id)
        except exception.HNASItemNotFoundException:
            raise exception.ShareResourceNotFound(share_id=share['id'])

        self._check_protocol(share['id'], share['share_proto'])

        if share['share_proto'].lower() == 'nfs':
            self._nfs_update_access(share, hnas_share_id, access_rules)
        else:
            if not (add_rules or delete_rules):
                # recovery mode
                self._clean_cifs_access_list(hnas_share_id)
                self._cifs_allow_access(share, hnas_share_id, access_rules)
            else:
                self._cifs_deny_access(share, hnas_share_id, delete_rules)
                self._cifs_allow_access(share, hnas_share_id, add_rules)

    def _nfs_update_access(self, share, hnas_share_id, access_rules):
        host_list = []

        for rule in access_rules:
            if rule['access_type'].lower() != 'ip':
                msg = _("Only IP access type currently supported for NFS. "
                        "Share provided %(share)s with rule type "
                        "%(type)s.") % {'share': share['id'],
                                        'type': rule['access_type']}
                raise exception.InvalidShareAccess(reason=msg)

            if rule['access_level'] == constants.ACCESS_LEVEL_RW:
                host_list.append(rule['access_to'] + '(' +
                                 rule['access_level'] +
                                 ',norootsquash)')
            else:
                host_list.append(rule['access_to'] + '(' +
                                 rule['access_level'] + ')')

        self.hnas.update_nfs_access_rule(hnas_share_id, host_list)

        if host_list:
            LOG.debug("Share %(share)s has the rules: %(rules)s",
                      {'share': share['id'], 'rules': ', '.join(host_list)})
        else:
            LOG.debug("Share %(share)s has no rules.", {'share': share['id']})

    def _cifs_allow_access(self, share, hnas_share_id, add_rules):
        for rule in add_rules:
            if rule['access_type'].lower() != 'user':
                msg = _("Only USER access type currently supported for CIFS. "
                        "Share provided %(share)s with rule %(r_id)s type "
                        "%(type)s allowing permission to %(to)s.") % {
                    'share': share['id'], 'type': rule['access_type'],
                    'r_id': rule['id'], 'to': rule['access_to']}
                raise exception.InvalidShareAccess(reason=msg)

            if rule['access_level'] == constants.ACCESS_LEVEL_RW:
                # Adding permission acr = Allow Change&Read
                permission = 'acr'
            else:
                # Adding permission ar = Allow Read
                permission = 'ar'

            formatted_user = rule['access_to'].replace('\\', '\\\\')

            self.hnas.cifs_allow_access(hnas_share_id, formatted_user,
                                        permission)

            LOG.debug("Added %(rule)s rule for user/group %(user)s to share "
                      "%(share)s.", {'rule': rule['access_level'],
                                     'user': rule['access_to'],
                                     'share': share['id']})

    def _cifs_deny_access(self, share, hnas_share_id, delete_rules):
        for rule in delete_rules:
            if rule['access_type'].lower() != 'user':
                LOG.warning(_LW('Only USER access type is allowed for '
                                'CIFS shares. Share provided %(share)s with '
                                'protocol %(proto)s.'),
                            {'share': share['id'],
                             'proto': share['share_proto']})
                continue

            formatted_user = rule['access_to'].replace('\\', '\\\\')

            self.hnas.cifs_deny_access(hnas_share_id, formatted_user)

            LOG.debug("Access denied for user/group %(user)s to share "
                      "%(share)s.", {'user': rule['access_to'],
                                     'share': share['id']})

    def _clean_cifs_access_list(self, hnas_share_id):
        permission_list = self.hnas.list_cifs_permissions(hnas_share_id)

        for permission in permission_list:
            formatted_user = r'"\{1}{0}\{1}"'.format(permission[0], '"')
            self.hnas.cifs_deny_access(hnas_share_id, formatted_user)

    def create_share(self, context, share, share_server=None):
        """Creates share.

        :param context: The `context.RequestContext` object for the request
        :param share: Share that will be created.
        :param share_server: Data structure with share server information.
            Not used by this driver.
        :returns: Returns a path of EVS IP concatenate with the path
            of share in the filesystem (e.g. ['172.24.44.10:/shares/id'] for
            NFS and ['\\172.24.44.10\id'] for CIFS).
        """
        LOG.debug("Creating share in HNAS: %(shr)s.",
                  {'shr': share['id']})

        self._check_protocol(share['id'], share['share_proto'])

        uri = self._create_share(share['id'], share['size'],
                                 share['share_proto'])

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
        hnas_share_id = self._get_hnas_share_id(share['id'])

        LOG.debug("Deleting share in HNAS: %(shr)s.",
                  {'shr': share['id']})

        self._delete_share(hnas_share_id, share['share_proto'])

        LOG.debug("Export and share successfully deleted: %(shr)s.",
                  {'shr': share['id']})

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates snapshot.

        :param context: The `context.RequestContext` object for the request
        :param snapshot: Snapshot that will be created.
        :param share_server: Data structure with share server information.
            Not used by this driver.
        """
        hnas_share_id = self._get_hnas_share_id(snapshot['share_id'])

        LOG.debug("The snapshot of share %(ss_sid)s will be created with "
                  "id %(ss_id)s.", {'ss_sid': snapshot['share_id'],
                                    'ss_id': snapshot['id']})

        self._create_snapshot(hnas_share_id, snapshot)
        LOG.info(_LI("Snapshot %(id)s successfully created."),
                 {'id': snapshot['id']})

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes snapshot.

        :param context: The `context.RequestContext` object for the request
        :param snapshot: Snapshot that will be deleted.
        :param share_server: Data structure with share server information.
            Not used by this driver.
        """
        hnas_share_id = self._get_hnas_share_id(snapshot['share_id'])

        LOG.debug("The snapshot %(ss_sid)s will be deleted. The related "
                  "share ID is %(ss_id)s.",
                  {'ss_sid': snapshot['share_id'], 'ss_id': snapshot['id']})

        self._delete_snapshot(hnas_share_id, snapshot['id'])
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

        hnas_src_share_id = self._get_hnas_share_id(snapshot['share_id'])

        uri = self._create_share_from_snapshot(share, hnas_src_share_id,
                                               snapshot)

        LOG.debug("Share %(share)s created successfully on path: %(uri)s.",
                  {'uri': uri,
                   'share': share['id']})
        return uri

    def ensure_share(self, context, share, share_server=None):
        """Ensure that share is exported.

        :param context: The `context.RequestContext` object for the request
        :param share: Share that will be checked.
        :param share_server: Data structure with share server information.
            Not used by this driver.
        :returns: Returns a list of EVS IP concatenated with the path
            of share in the filesystem (e.g. ['172.24.44.10:/shares/id'] for
            NFS and ['\\172.24.44.10\id'] for CIFS).
        """
        LOG.debug("Ensuring share in HNAS: %(shr)s.", {'shr': share['id']})

        hnas_share_id = self._get_hnas_share_id(share['id'])

        export = self._ensure_share(share, hnas_share_id)

        export_list = [export]

        LOG.debug("Share ensured in HNAS: %(shr)s, protocol %(proto)s.",
                  {'shr': share['id'], 'proto': share['share_proto']})
        return export_list

    def extend_share(self, share, new_size, share_server=None):
        """Extends a share to new size.

        :param share: Share that will be extended.
        :param new_size: New size of share.
        :param share_server: Data structure with share server information.
            Not used by this driver.
        """
        hnas_share_id = self._get_hnas_share_id(share['id'])

        LOG.debug("Expanding share in HNAS: %(shr_id)s.",
                  {'shr_id': share['id']})

        self._extend_share(hnas_share_id, share, new_size)
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
        LOG.debug("Updating Backend Capability Information - Hitachi HNAS.")

        self._check_fs_mounted()

        total_space, free_space, dedupe = self.hnas.get_stats()

        reserved = self.configuration.safe_get('reserved_share_percentage')

        data = {
            'share_backend_name': self.backend_name,
            'driver_handles_share_servers': self.driver_handles_share_servers,
            'vendor_name': 'Hitachi',
            'driver_version': '3.0.0',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': total_space,
            'free_capacity_gb': free_space,
            'reserved_percentage': reserved,
            'qos': False,
            'thin_provisioning': True,
            'dedupe': dedupe,
        }

        LOG.info(_LI("HNAS Capabilities: %(data)s."),
                 {'data': six.text_type(data)})

        super(HitachiHNASDriver, self)._update_share_stats(data)

    def manage_existing(self, share, driver_options):
        """Manages a share that exists on backend.

        :param share: Share that will be managed.
        :param driver_options: Empty dict or dict with 'volume_id' option.
        :returns: Returns a dict with size of share managed
            and its export location.
        """
        hnas_share_id = self._get_hnas_share_id(share['id'])

        # Make sure returned value is the same as provided,
        # confirming it does not exist.
        if hnas_share_id != share['id']:
            msg = _("Share ID %s already exists, cannot manage.") % share['id']
            raise exception.HNASBackendException(msg=msg)

        self._check_protocol(share['id'], share['share_proto'])

        if share['share_proto'].lower() == 'nfs':
            # 10.0.0.1:/shares/example
            LOG.info(_LI("Share %(shr_path)s will be managed with ID "
                         "%(shr_id)s."),
                     {'shr_path': share['export_locations'][0]['path'],
                      'shr_id': share['id']})

            old_path_info = share['export_locations'][0]['path'].split(
                ':/shares/')

            if len(old_path_info) == 2:
                evs_ip = old_path_info[0]
                hnas_share_id = old_path_info[1]
            else:
                msg = _("Incorrect path. It should have the following format: "
                        "IP:/shares/share_id.")
                raise exception.ShareBackendException(msg=msg)
        else:  # then its CIFS
            # \\10.0.0.1\example
            old_path = share['export_locations'][0]['path'].split('\\')

            if len(old_path) == 4:
                evs_ip = old_path[2]
                hnas_share_id = old_path[3]
            else:
                msg = _("Incorrect path. It should have the following format: "
                        "\\\\IP\\share_id.")
                raise exception.ShareBackendException(msg=msg)

        if evs_ip != self.hnas_evs_ip:
            msg = _("The EVS IP %(evs)s is not "
                    "configured.") % {'evs': evs_ip}
            raise exception.ShareBackendException(msg=msg)

        if self.backend_name not in share['host']:
            msg = _("The backend passed in the host parameter (%(shr)s) is "
                    "not configured.") % {'shr': share['host']}
            raise exception.ShareBackendException(msg=msg)

        output = self._manage_existing(share, hnas_share_id)
        self.private_storage.update(
            share['id'], {'hnas_id': hnas_share_id})

        LOG.debug("HNAS ID %(hnas_id)s has been saved to private storage for "
                  "Share ID %(share_id)s", {'hnas_id': hnas_share_id,
                                            'share_id': share['id']})

        LOG.info(_LI("Share %(shr_path)s was successfully managed with ID "
                     "%(shr_id)s."),
                 {'shr_path': share['export_locations'][0]['path'],
                  'shr_id': share['id']})

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
        hnas_share_id = self._get_hnas_share_id(share['id'])

        LOG.debug("Shrinking share in HNAS: %(shr_id)s.",
                  {'shr_id': share['id']})

        self._shrink_share(hnas_share_id, share, new_size)
        LOG.info(_LI("Share %(shr_id)s successfully shrunk to "
                     "%(shr_size)sG."),
                 {'shr_id': share['id'],
                  'shr_size': six.text_type(new_size)})

    def _get_hnas_share_id(self, share_id):
        hnas_id = self.private_storage.get(share_id, 'hnas_id')

        if hnas_id is None:
            hnas_id = share_id

        LOG.debug("Share ID is %(shr_id)s and respective HNAS ID "
                  "is %(hnas_id)s.", {'shr_id': share_id,
                                      'hnas_id': hnas_id})

        return hnas_id

    def _create_share(self, share_id, share_size, share_proto):
        """Creates share.

        Creates a virtual-volume, adds a quota limit and exports it.
        :param share_id: manila's database ID of share that will be created.
        :param share_size: Size limit of share.
        :param share_proto: Protocol of share that will be created
            (NFS or CIFS)
        :returns: Returns a path IP:/shares/share_id for NFS or \\IP\share_id
            for CIFS if the export was created successfully.
        """
        self._check_fs_mounted()

        self.hnas.vvol_create(share_id)

        self.hnas.quota_add(share_id, share_size)

        LOG.debug("Share created with id %(shr)s, size %(size)sG.",
                  {'shr': share_id, 'size': share_size})

        try:
            if share_proto.lower() == 'nfs':
                # Create NFS export
                self.hnas.nfs_export_add(share_id)
                LOG.debug("NFS Export created to %(shr)s.",
                          {'shr': share_id})
                uri = self.hnas_evs_ip + ":/shares/" + share_id
            else:
                # Create CIFS share with vvol path
                self.hnas.cifs_share_add(share_id)
                LOG.debug("CIFS share created to %(shr)s.",
                          {'shr': share_id})
                uri = r'\\%s\%s' % (self.hnas_evs_ip, share_id)
            return uri
        except exception.HNASBackendException as e:
            with excutils.save_and_reraise_exception():
                self.hnas.vvol_delete(share_id)
                msg = six.text_type(e)
                LOG.exception(msg)

    def _check_fs_mounted(self):
        mounted = self.hnas.check_fs_mounted()
        if not mounted:
            msg = _("Filesystem %s is not mounted.") % self.fs_name
            raise exception.HNASBackendException(msg=msg)

    def _ensure_share(self, share, hnas_share_id):
        """Ensure that share is exported.

        :param share: Share that will be checked.
        :param hnas_share_id: HNAS ID of share that will be checked.
        :returns: Returns a path IP:/shares/share_id for NFS or \\IP\share_id
            for CIFS if the export is ok.
        """
        self._check_protocol(share['id'], share['share_proto'])

        path = os.path.join('/shares', hnas_share_id)

        self._check_fs_mounted()

        self.hnas.check_vvol(hnas_share_id)
        self.hnas.check_quota(hnas_share_id)
        if share['share_proto'].lower() == 'nfs':
            self.hnas.check_export(hnas_share_id)
            export = self.hnas_evs_ip + ":" + path
        else:
            self.hnas.check_cifs(hnas_share_id)
            export = r'\\%s\%s' % (self.hnas_evs_ip, hnas_share_id)
        return export

    def _shrink_share(self, hnas_share_id, share, new_size):
        """Shrinks a share to new size.

        :param hnas_share_id: HNAS ID of share that will be shrunk.
        :param share: model of share that will be shrunk.
        :param new_size: New size of share after shrink operation.
        """
        self._ensure_share(share, hnas_share_id)

        usage = self.hnas.get_share_usage(hnas_share_id)

        LOG.debug("Usage space in share %(share)s: %(usage)sG",
                  {'share': share['id'], 'usage': usage})

        if new_size > usage:
            self.hnas.modify_quota(hnas_share_id, new_size)
        else:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share['id'])

    def _extend_share(self, hnas_share_id, share, new_size):
        """Extends a share to new size.

        :param hnas_share_id: HNAS ID of share that will be extended.
        :param share: model of share that will be extended.
        :param new_size: New size of share after extend operation.
        """
        self._ensure_share(share, hnas_share_id)

        old_size = share['size']
        available_space = self.hnas.get_stats()[1]

        LOG.debug("Available space in filesystem: %(space)sG.",
                  {'space': available_space})

        if (new_size - old_size) < available_space:
            self.hnas.modify_quota(hnas_share_id, new_size)
        else:
            msg = (_("Share %s cannot be extended due to insufficient space.")
                   % share['id'])
            raise exception.HNASBackendException(msg=msg)

    def _delete_share(self, hnas_share_id, share_proto):
        """Deletes share.

        It uses tree-delete-job-submit to format and delete virtual-volumes.
        Quota is deleted with virtual-volume.
        :param hnas_share_id: HNAS ID of share that will be deleted.
        :param share_proto: Protocol of share that will be deleted.
        """
        self._check_fs_mounted()

        if share_proto.lower() == 'nfs':
            self.hnas.nfs_export_del(hnas_share_id)
        elif share_proto.lower() == 'cifs':
            self.hnas.cifs_share_del(hnas_share_id)
        self.hnas.vvol_delete(hnas_share_id)

    def _manage_existing(self, share, hnas_share_id):
        """Manages a share that exists on backend.

        :param share: share that will be managed.
        :param hnas_share_id: HNAS ID of share that will be managed.
        :returns: Returns a dict with size of share managed
            and its export location.
        """
        self._ensure_share(share, hnas_share_id)

        share_size = self.hnas.get_share_quota(hnas_share_id)
        if share_size is None:
            msg = (_("The share %s trying to be managed does not have a "
                     "quota limit, please set it before manage.")
                   % share['id'])
            raise exception.ManageInvalidShare(reason=msg)

        if share['share_proto'].lower() == 'nfs':
            path = self.hnas_evs_ip + os.path.join(':/shares', hnas_share_id)
        else:
            path = r'\\%s\%s' % (self.hnas_evs_ip, hnas_share_id)

        return {'size': share_size, 'export_locations': [path]}

    def _create_snapshot(self, hnas_share_id, snapshot):
        """Creates a snapshot of share.

        It copies the directory and all files to a new directory inside
        /snapshots/share_id/.
        :param hnas_share_id: HNAS ID of share for snapshot.
        :param snapshot: Snapshot that will be created.
        """
        self._ensure_share(snapshot['share'], hnas_share_id)
        saved_list = []

        self._check_protocol(snapshot['share_id'],
                             snapshot['share']['share_proto'])

        if snapshot['share']['share_proto'].lower() == 'nfs':
            saved_list = self.hnas.get_nfs_host_list(hnas_share_id)
            new_list = []
            for access in saved_list:
                new_list.append(access.replace('(rw)', '(ro)'))
            self.hnas.update_nfs_access_rule(hnas_share_id, new_list)
        else:  # CIFS
            if (self.hnas.is_cifs_in_use(hnas_share_id) and
                    not self.cifs_snapshot):
                msg = _("CIFS snapshot when share is mounted is disabled. "
                        "Set hitachi_hnas_allow_cifs_snapshot_while_mounted to"
                        " True or unmount the share to take a snapshot.")
                raise exception.ShareBackendException(msg=msg)

        src_path = os.path.join('/shares', hnas_share_id)
        dest_path = os.path.join('/snapshots', hnas_share_id, snapshot['id'])
        try:
            self.hnas.tree_clone(src_path, dest_path)
        except exception.HNASNothingToCloneException:
            LOG.warning(_LW("Source directory is empty, creating an empty "
                            "directory."))
            self.hnas.create_directory(dest_path)
        finally:
            if snapshot['share']['share_proto'].lower() == 'nfs':
                self.hnas.update_nfs_access_rule(hnas_share_id, saved_list)

    def _delete_snapshot(self, hnas_share_id, snapshot_id):
        """Deletes snapshot.

        It receives the hnas_share_id only to join the path for snapshot.
        :param hnas_share_id: HNAS ID of share from which snapshot was taken.
        :param snapshot_id: ID of snapshot.
        """
        self._check_fs_mounted()

        path = os.path.join('/snapshots', hnas_share_id, snapshot_id)
        self.hnas.tree_delete(path)
        path = os.path.join('/snapshots', hnas_share_id)
        self.hnas.delete_directory(path)

    def _create_share_from_snapshot(self, share, src_hnas_share_id, snapshot):
        """Creates a new share from snapshot.

        It copies everything from snapshot directory to a new vvol,
        set a quota limit for it and export.
        :param share: a dict from new share.
        :param src_hnas_share_id: HNAS ID of share from which snapshot was
            taken.
        :param snapshot: a dict from snapshot that will be copied to
            new share.
        :returns: Returns the path for new share.
        """
        dest_path = os.path.join('/shares', share['id'])
        src_path = os.path.join('/snapshots', src_hnas_share_id,
                                snapshot['id'])

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

        self._check_protocol(share['id'], share['share_proto'])

        try:
            if share['share_proto'].lower() == 'nfs':
                self.hnas.nfs_export_add(share['id'])
                uri = self.hnas_evs_ip + ":" + dest_path
            else:
                self.hnas.cifs_share_add(share['id'])
                uri = r'\\%s\%s' % (self.hnas_evs_ip, share['id'])
            return uri
        except exception.HNASBackendException:
            with excutils.save_and_reraise_exception():
                msg = _LE('Failed to create share %(share_id)s from snapshot '
                          '%(snap)s.')
                LOG.exception(msg, {'share_id': share['id'],
                                    'snap': snapshot['id']})
                self.hnas.vvol_delete(share['id'])

    def _check_protocol(self, share_id, protocol):
        if protocol.lower() not in ('nfs', 'cifs'):
            msg = _("Only NFS or CIFS protocol are currently supported. "
                    "Share provided %(share)s with protocol "
                    "%(proto)s.") % {'share': share_id,
                                     'proto': protocol}
            raise exception.ShareBackendException(msg=msg)
