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
import six

from manila import exception
from manila.i18n import _
from manila.i18n import _LI
from manila.share import driver
from manila.share.drivers.hitachi import ssh

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
    cfg.StrOpt('hds_hnas_evs_id',
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
]

CONF = cfg.CONF
CONF.register_opts(hds_hnas_opts)


class HDSHNASDriver(driver.ShareDriver):
    """Manila HNAS Driver implementation.

    1.0 - Initial Version
    """

    def __init__(self, *args, **kwargs):
        """Do initialization."""

        LOG.debug("Invoking base constructor for Manila HDS HNAS Driver.")
        super(HDSHNASDriver, self).__init__(False, *args, **kwargs)

        LOG.debug("Setting up attributes for Manila HDS HNAS Driver.")
        self.configuration.append_config_values(hds_hnas_opts)

        LOG.debug("Reading config parameters for Manila HDS HNAS Driver.")
        self.backend_name = self.configuration.safe_get('share_backend_name')
        hnas_ip = self.configuration.safe_get('hds_hnas_ip')
        hnas_username = self.configuration.safe_get('hds_hnas_user')
        hnas_password = self.configuration.safe_get('hds_hnas_password')
        hnas_evs_id = self.configuration.safe_get('hds_hnas_evs_id')
        self.hnas_evs_ip = self.configuration.safe_get('hds_hnas_evs_ip')
        fs_name = self.configuration.safe_get('hds_hnas_file_system_name')
        ssh_private_key = self.configuration.safe_get(
            'hds_hnas_ssh_private_key')
        cluster_admin_ip0 = self.configuration.safe_get(
            'hds_hnas_cluster_admin_ip0')
        self.private_storage = kwargs.get('private_storage')
        job_timeout = self.configuration.safe_get(
            'hds_hnas_stalled_job_timeout')

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

        self.hnas = ssh.HNASSSHBackend(hnas_ip, hnas_username, hnas_password,
                                       ssh_private_key, cluster_admin_ip0,
                                       hnas_evs_id, self.hnas_evs_ip, fs_name,
                                       job_timeout)

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to a share.

        :param context: The `context.RequestContext` object for the request
        :param share: Share to which access will be allowed.
        :param access: Information about the access that will be allowed, e.g.
        host allowed, type of access granted.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        """
        if ('nfs', 'ip') != (share['share_proto'].lower(),
                             access['access_type'].lower()):
            msg = _("Only NFS protocol and IP access type currently "
                    "supported.")
            raise exception.InvalidShareAccess(reason=msg)

        LOG.debug("Sending HNAS Request to allow access to share: "
                  "%(shr)s.", {'shr': (share['id'])})

        share_id = self._get_hnas_share_id(share['id'])

        self.hnas.allow_access(share_id, access['access_to'],
                               share['share_proto'],
                               access['access_level'])

        LOG.info(_LI("Access allowed successfully to share: %(shr)s."),
                 {'shr': six.text_type(share['id'])})

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to a share.

        :param context: The `context.RequestContext` object for the request
        :param share: Share to which access will be denied.
        :param access: Information about the access that will be denied, e.g.
        host and type of access denied.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        """
        if ('nfs', 'ip') != (share['share_proto'].lower(),
                             access['access_type'].lower()):
            msg = _("Only NFS protocol and IP access type currently "
                    "supported.")
            raise exception.InvalidShareAccess(reason=msg)

        LOG.debug("Sending HNAS request to deny access to share:"
                  " %(shr_id)s.",
                  {'shr_id': six.text_type(share['id'])})

        share_id = self._get_hnas_share_id(share['id'])

        self.hnas.deny_access(share_id, access['access_to'],
                              share['share_proto'], access['access_level'])

        LOG.info(_LI("Access denied successfully to share: %(shr)s."),
                 {'shr': six.text_type(share['id'])})

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
                  {'shr': six.text_type(share['id'])})

        if share['share_proto'].lower() != 'nfs':
            msg = _("Only NFS protocol is currently supported.")
            raise exception.ShareBackendException(msg=msg)

        ip = self.hnas_evs_ip

        path = self.hnas.create_share(share['id'], share['size'],
                                      share['share_proto'])

        LOG.debug("Share created successfully on path: %(ip)s:%(path)s.",
                  {'ip': ip, 'path': path})
        return ip + ":" + path

    def delete_share(self, context, share, share_server=None):
        """Deletes share.

        :param context: The `context.RequestContext` object for the request
        :param share: Share that will be deleted.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        """
        share_id = self._get_hnas_share_id(share['id'])

        LOG.debug("Deleting share in HNAS: %(shr)s.",
                  {'shr': six.text_type(share['id'])})

        self.hnas.delete_share(share_id, share['share_proto'])

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

        self.hnas.create_snapshot(share_id, snapshot['id'])
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

        self.hnas.delete_snapshot(share_id, snapshot['id'])
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
                  {'ss_id': six.text_type(snapshot['id'])})

        ip = self.hnas_evs_ip
        path = self.hnas.create_share_from_snapshot(share, snapshot)

        LOG.debug("Share created successfully on path: %(ip)s:%(path)s.",
                  {'ip': ip, 'path': path})
        return ip + ":" + path

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
                  {'shr': six.text_type(share['id'])})

        if share['share_proto'].lower() != 'nfs':
            msg = _("Only NFS protocol is currently supported.")
            raise exception.ShareBackendException(msg=msg)

        path = self.hnas.ensure_share(share['id'], share['share_proto'])

        export = self.hnas_evs_ip + ":" + path
        export_list = [export]

        LOG.debug("Share ensured in HNAS: %(shr)s.",
                  {'shr': six.text_type(share['id'])})
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
                  {'shr_id': six.text_type(share['id'])})

        if share['share_proto'].lower() != 'nfs':
            msg = _("Only NFS protocol is currently supported.")
            raise exception.ShareBackendException(msg=msg)

        self.hnas.extend_share(share_id, new_size, share['share_proto'])
        LOG.info(_LI("Share %(shr_id)s successfully extended to "
                     "%(shr_size)s."),
                 {'shr_id': six.text_type(share['id']),
                  'shr_size': six.text_type(new_size)})

    # TODO(alyson): Implement in DHSS = true mode
    def get_network_allocations_number(self):
        """Track allocations_number in DHSS = true.

        When using the setting driver_handles_share_server = false
        does not require to track allocations_number because we do not handle
        network stuff.
        """
        return 0

    def _update_share_stats(self):
        """Updates the Capability of Backend."""
        LOG.debug("Updating Backend Capability Information - HDS HNAS.")

        total_space, free_space = self.hnas.get_stats()

        reserved = self.configuration.safe_get('reserved_share_percentage')

        data = {
            'share_backend_name': self.backend_name,
            'driver_handles_share_servers': self.driver_handles_share_servers,
            'vendor_name': 'HDS',
            'driver_version': '1.0',
            'storage_protocol': 'NFS',
            'total_capacity_gb': total_space,
            'free_capacity_gb': free_space,
            'reserved_percentage': reserved,
            'qos': False,
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

        LOG.info(_LI("Share %(shr_path)s will be managed with ID %(shr_id)s."),
                 {'shr_path': six.text_type(
                     share['export_locations'][0]['path']),
                  'shr_id': six.text_type(share_id)})

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
                    "configured.") % {'evs': six.text_type(evs_ip)}
            raise exception.ShareBackendException(msg=msg)

        if six.text_type(self.backend_name) not in share['host']:
            msg = _("The backend passed in the host parameter (%(shr)s) is "
                    "not configured.") % {'shr': share['host']}
            raise exception.ShareBackendException(msg=msg)

        output = self.hnas.manage_existing(share, share_id)
        self.private_storage.update(
            share['id'], {'hnas_id': share_id})

        return output

    def unmanage(self, share):
        """Unmanages a share.

        :param share: Share that will be unmanaged.
        """
        self.private_storage.delete(share['id'])

        LOG.info(_LI("The share with current path %(shr_path)s and ID "
                     "%(shr_id)s is no longer being managed."),
                 {'shr_path': six.text_type(
                     share['export_locations'][0]['path']),
                  'shr_id': six.text_type(share['id'])})

    def _get_hnas_share_id(self, share_id):
        hnas_id = self.private_storage.get(share_id, 'hnas_id')

        if hnas_id is None:
            hnas_id = share_id
        return hnas_id
