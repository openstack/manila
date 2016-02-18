# Copyright 2015 EMC Corporation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Isilon specific NAS backend plugin.
"""
import os
from oslo_config import cfg
from oslo_log import log
from oslo_utils import units
import six

from manila.common import constants as const
from manila import exception
from manila.i18n import _, _LW
from manila.share.drivers.emc.plugins import base
from manila.share.drivers.emc.plugins.isilon import isilon_api

CONF = cfg.CONF
VERSION = "0.1.0"

LOG = log.getLogger(__name__)


class IsilonStorageConnection(base.StorageConnection):
    """Implements Isilon specific functionality for EMC Manila driver."""

    def __init__(self, *args, **kwargs):
        super(IsilonStorageConnection, self).__init__(*args, **kwargs)
        self._server = None
        self._port = None
        self._username = None
        self._password = None
        self._server_url = None
        self._connect_resp = None
        self._root_dir = None
        self._verify_ssl_cert = None
        self._containers = {}
        self._shares = {}
        self._snapshots = {}

        self._isilon_api = None
        self._isilon_api_class = isilon_api.IsilonApi
        self.driver_handles_share_servers = False

    def _get_container_path(self, share):
        """Return path to a container."""
        return os.path.join(self._root_dir, share['name'])

    def create_share(self, context, share, share_server):
        """Is called to create share."""
        if share['share_proto'] == 'NFS':
            location = self._create_nfs_share(share)
        elif share['share_proto'] == 'CIFS':
            location = self._create_cifs_share(share)
        else:
            message = (_('Unsupported share protocol: %(proto)s.') %
                       {'proto': share['share_proto']})
            LOG.error(message)
            raise exception.InvalidShare(reason=message)

        # apply directory quota based on share size
        max_share_size = share['size'] * units.Gi
        self._isilon_api.quota_create(
            self._get_container_path(share), 'directory', max_share_size)

        return location

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server):
        """Creates a share from the snapshot."""

        # Create share at new location
        location = self.create_share(context, share, share_server)

        # Clone snapshot to new location
        fq_target_dir = self._get_container_path(share)
        self._isilon_api.clone_snapshot(snapshot['name'], fq_target_dir)

        return location

    def _create_nfs_share(self, share):
        """Is called to create nfs share."""
        container_path = self._get_container_path(share)
        self._isilon_api.create_directory(container_path)

        share_created = self._isilon_api.create_nfs_export(container_path)
        if not share_created:
            message = (
                _('The requested NFS share "%(share)s" was not created.') %
                {'share': share['name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        location = '{0}:{1}'.format(self._server, container_path)
        return location

    def _create_cifs_share(self, share):
        """Is called to create cifs share."""

        # Create the directory
        container_path = self._get_container_path(share)
        self._isilon_api.create_directory(container_path)
        self._isilon_api.create_smb_share(share['name'], container_path)
        share_path = '\\\\{0}\\{1}'.format(self._server, share['name'])
        return share_path

    def create_snapshot(self, context, snapshot, share_server):
        """Is called to create snapshot."""
        snapshot_path = os.path.join(self._root_dir, snapshot['share_name'])
        self._isilon_api.create_snapshot(snapshot['name'], snapshot_path)

    def delete_share(self, context, share, share_server):
        """Is called to remove share."""
        if share['share_proto'] == 'NFS':
            self._delete_nfs_share(share)
        elif share['share_proto'] == 'CIFS':
            self._delete_cifs_share(share)
        else:
            message = (_('Unsupported share type: %(type)s.') %
                       {'type': share['share_proto']})
            LOG.error(message)
            raise exception.InvalidShare(reason=message)

    def _delete_nfs_share(self, share):
        """Is called to remove nfs share."""
        share_id = self._isilon_api.lookup_nfs_export(
            self._root_dir + '/' + share['name'])

        if share_id is None:
            lw = _LW('Attempted to delete NFS Share "%s", but the share does '
                     'not appear to exist.')
            LOG.warning(lw, share['name'])
        else:
            # attempt to delete the share
            export_deleted = self._isilon_api.delete_nfs_share(share_id)
            if not export_deleted:
                message = _('Error deleting NFS share: %s') % share['name']
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)

    def _delete_cifs_share(self, share):
        """Is called to remove CIFS share."""
        smb_share = self._isilon_api.lookup_smb_share(share['name'])
        if smb_share is None:
            lw = _LW('Attempted to delete CIFS Share "%s", but the share does '
                     'not appear to exist.')
            LOG.warning(lw, share['name'])
        else:
            share_deleted = self._isilon_api.delete_smb_share(share['name'])
            if not share_deleted:
                message = _('Error deleting CIFS share: %s') % share['name']
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)

    def delete_snapshot(self, context, snapshot, share_server):
        """Is called to remove snapshot."""
        self._isilon_api.delete_snapshot(snapshot['name'])

    def ensure_share(self, context, share, share_server):
        """Invoked to ensure that share is exported."""

    def extend_share(self, share, new_size, share_server=None):
        """Extends a share."""
        new_quota_size = new_size * units.Gi
        self._isilon_api.quota_set(
            self._get_container_path(share), 'directory', new_quota_size)

    def allow_access(self, context, share, access, share_server):
        """Allow access to the share."""

        if share['share_proto'] == 'NFS':
            self._nfs_allow_access(share, access)
        elif share['share_proto'] == 'CIFS':
            self._cifs_allow_access(share, access)
        else:
            message = _(
                'Unsupported share protocol: %s. Only "NFS" and '
                '"CIFS" are currently supported share protocols.') % share[
                'share_proto']
            LOG.error(message)
            raise exception.InvalidShare(reason=message)

    def _nfs_allow_access(self, share, access):
        """Allow access to nfs share."""
        access_type = access['access_type']
        if access_type != 'ip':
            message = _('Only "ip" access type allowed for the NFS'
                        'protocol.')
            LOG.error(message)
            raise exception.InvalidShareAccess(reason=message)

        export_path = self._get_container_path(share)
        access_ip = access['access_to']
        access_level = access['access_level']
        share_id = self._isilon_api.lookup_nfs_export(export_path)

        share_access_group = 'clients'
        if access_level == const.ACCESS_LEVEL_RO:
            share_access_group = 'read_only_clients'

        # Get current allowed clients
        export = self._get_existing_nfs_export(share_id)
        current_clients = export[share_access_group]

        # Format of ips could be '10.0.0.2', or '10.0.0.2, 10.0.0.0/24'
        ips = list()
        ips.append(access_ip)
        ips.extend(current_clients)
        export_params = {share_access_group: ips}
        url = '{0}/platform/1/protocols/nfs/exports/{1}'.format(
            self._server_url, share_id)
        resp = self._isilon_api.request('PUT', url, data=export_params)
        resp.raise_for_status()

    def _cifs_allow_access(self, share, access):
        access_type = access['access_type']
        access_to = access['access_to']
        access_level = access['access_level']
        if access_type == 'ip':
            access_ip = access['access_to']
            self._cifs_allow_access_ip(access_ip, share, access_level)
        elif access_type == 'user':
            self._cifs_allow_access_user(access_to, share, access_level)
        else:
            message = _('Only "ip" and "user" access types allowed for '
                        'CIFS protocol.')
            LOG.error(message)
            raise exception.InvalidShareAccess(reason=message)

    def _cifs_allow_access_ip(self, ip, share, access_level):
        if access_level == const.ACCESS_LEVEL_RO:
            message = _('Only RW Access allowed for CIFS Protocol when using '
                        'the "ip" access type.')
            LOG.error(message)
            raise exception.InvalidShareAccess(reason=message)

        allowed_ip = 'allow:' + ip
        smb_share = self._isilon_api.lookup_smb_share(share['name'])
        host_acl = smb_share['host_acl']
        if allowed_ip not in host_acl:
            host_acl.append(allowed_ip)
            data = {'host_acl': host_acl}
            url = ('{0}/platform/1/protocols/smb/shares/{1}'
                   .format(self._server_url, smb_share['name']))
            r = self._isilon_api.request('PUT', url, data=data)
            r.raise_for_status()

    def _cifs_allow_access_user(self, user, share, access_level):
        if access_level == const.ACCESS_LEVEL_RW:
            smb_permission = isilon_api.SmbPermission.rw
        elif access_level == const.ACCESS_LEVEL_RO:
            smb_permission = isilon_api.SmbPermission.ro
        else:
            message = _('Only "RW" and "RO" access levels are supported.')
            LOG.error(message)
            raise exception.InvalidShareAccess(reason=message)

        self._isilon_api.smb_permissions_add(share['name'], user,
                                             smb_permission)

    def deny_access(self, context, share, access, share_server):
        """Deny access to the share."""

        if share['share_proto'] == 'NFS':
            self._nfs_deny_access(share, access)
        elif share['share_proto'] == 'CIFS':
            self._cifs_deny_access(share, access)

    def _nfs_deny_access(self, share, access):
        """Deny access to nfs share."""
        if access['access_type'] != 'ip':
            return

        denied_ip = access['access_to']
        access_level = access['access_level']
        share_access_group = 'clients'
        if access_level == const.ACCESS_LEVEL_RO:
            share_access_group = 'read_only_clients'

        # Get list of currently allowed client ips
        export_id = self._isilon_api.lookup_nfs_export(
            self._get_container_path(share))
        if export_id is None:
            message = _('Share %s should have been created, but was not '
                        'found.') % share['name']
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        export = self._get_existing_nfs_export(export_id)
        try:
            clients = export[share_access_group]
        except KeyError:
            message = (_('Export %(export_name)s should have contained the '
                         'JSON key %(json_key)s, but this key was not found.')
                       % {'export_name': share['name'],
                          'json_key': share_access_group})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        allowed_ips = set(clients)

        if allowed_ips.__contains__(denied_ip):
            allowed_ips.remove(denied_ip)
            data = {share_access_group: list(allowed_ips)}
            url = ('{0}/platform/1/protocols/nfs/exports/{1}'
                   .format(self._server_url, six.text_type(export_id)))
            r = self._isilon_api.request('PUT', url, data=data)
            r.raise_for_status()

    def _get_existing_nfs_export(self, export_id):
        export = self._isilon_api.get_nfs_export(export_id)
        if export is None:
            message = _('NFS share with export id %d should have been '
                        'created, but was not found.') % export_id
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

        return export

    def _cifs_deny_access(self, share, access):
        access_type = access['access_type']
        if access_type == 'ip':
            self._cifs_deny_access_ip(access['access_to'], share)
        elif access_type == 'user':
            self._cifs_deny_access_user(share, access)
        else:
            message = _('Access type for CIFS deny access request was '
                        '"%(access_type)s". Only "user" and "ip" access types '
                        'are supported for CIFS protocol access.') % {
                'access_type': access_type}
            LOG.warning(message)

    def _cifs_deny_access_ip(self, denied_ip, share):
        """Deny access to cifs share."""

        share_json = self._isilon_api.lookup_smb_share(share['name'])
        host_acl_list = share_json['host_acl']
        allow_ip = 'allow:' + denied_ip
        if allow_ip in host_acl_list:
            host_acl_list.remove(allow_ip)
            share_params = {"host_acl": host_acl_list}
            url = ('{0}/platform/1/protocols/smb/shares/{1}'
                   .format(self._server_url, share['name']))
            resp = self._isilon_api.request('PUT', url, data=share_params)
            resp.raise_for_status()

    def _cifs_deny_access_user(self, share, access):
        self._isilon_api.smb_permissions_remove(share['name'], access[
            'access_to'])

    def check_for_setup_error(self):
        """Check for setup error."""

    def connect(self, emc_share_driver, context):
        """Connect to an Isilon cluster."""
        self._server = emc_share_driver.configuration.safe_get(
            "emc_nas_server")
        self._port = (
            int(emc_share_driver.configuration.safe_get("emc_nas_server_port"))
        )
        self._server_url = ('https://' + self._server + ':' +
                            six.text_type(self._port))
        self._username = emc_share_driver.configuration.safe_get(
            "emc_nas_login")
        self._password = emc_share_driver.configuration.safe_get(
            "emc_nas_password")
        self._root_dir = emc_share_driver.configuration.safe_get(
            "emc_nas_root_dir")
        # TODO(Shaun Edwards): make verify ssl a config variable?
        self._verify_ssl_cert = False
        self._isilon_api = self._isilon_api_class(self._server_url, auth=(
            self._username, self._password),
            verify_ssl_cert=self._verify_ssl_cert)
        if not self._isilon_api.is_path_existent(self._root_dir):
            self._isilon_api.create_directory(self._root_dir, recursive=True)

    def update_share_stats(self, stats_dict):
        """TODO."""
        # TODO(Shaun Edwards): query capacity, set storage_protocol,
        # QoS support?
        stats_dict['driver_version'] = VERSION

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""
        # TODO(Shaun Edwards)
        return 0

    def setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""
        # TODO(Shaun Edwards): Look into supporting share servers

    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
        # TODO(Shaun Edwards): Look into supporting share servers
