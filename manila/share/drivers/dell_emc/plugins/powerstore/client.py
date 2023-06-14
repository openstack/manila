# Copyright (c) 2023 Dell Inc. or its subsidiaries.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""REST client for Dell EMC PowerStore Manila Driver."""

import functools
import json

from oslo_log import log as logging
from oslo_utils import strutils
import requests

LOG = logging.getLogger(__name__)


class PowerStoreClient(object):
    def __init__(self,
                 rest_ip,
                 rest_username,
                 rest_password,
                 verify_certificate=False,
                 certificate_path=None):
        self.rest_ip = rest_ip
        self.rest_username = rest_username
        self.rest_password = rest_password
        self.verify_certificate = verify_certificate
        self.certificate_path = certificate_path
        self.base_url = "https://%s/api/rest" % self.rest_ip
        self.ok_codes = [
            requests.codes.ok,
            requests.codes.created,
            requests.codes.accepted,
            requests.codes.no_content,
            requests.codes.partial_content
        ]

    @property
    def _verify_cert(self):
        verify_cert = self.verify_certificate
        if self.verify_certificate and self.certificate_path:
            verify_cert = self.certificate_path
        return verify_cert

    def _send_request(self,
                      method,
                      url,
                      payload=None,
                      params=None,
                      log_response_data=True):
        if not params:
            params = {}
        request_params = {
            "auth": (self.rest_username, self.rest_password),
            "verify": self._verify_cert,
            "params": params
        }
        if payload and method != "GET":
            request_params["data"] = json.dumps(payload)
        request_url = self.base_url + url
        r = requests.request(method, request_url, **request_params)

        log_level = logging.DEBUG
        if r.status_code not in self.ok_codes:
            log_level = logging.ERROR
        LOG.log(log_level,
                "REST Request: %s %s with body %s",
                r.request.method,
                r.request.url,
                strutils.mask_password(r.request.body))
        if log_response_data or log_level == logging.ERROR:
            msg = "REST Response: %s with data %s" % (r.status_code, r.text)
        else:
            msg = "REST Response: %s" % r.status_code
        LOG.log(log_level, msg)

        try:
            response = r.json()
        except ValueError:
            response = None
        return r, response

    _send_get_request = functools.partialmethod(_send_request, "GET")
    _send_post_request = functools.partialmethod(_send_request, "POST")
    _send_patch_request = functools.partialmethod(_send_request, "PATCH")
    _send_delete_request = functools.partialmethod(_send_request, "DELETE")

    def get_nas_server_id(self, nas_server_name):
        """Retrieves the NAS server ID.

        :param nas_server_name: NAS server name
        :return: ID of the NAS server if success
        """
        url = '/nas_server?name=eq.' + nas_server_name
        res, response = self._send_get_request(url)
        if res.status_code == requests.codes.ok:
            return response[0]['id']

    def get_nas_server_interfaces(self, nas_server_id):
        """Retrieves the NAS server ID.

        :param nas_server_id: NAS server ID
        :return: File interfaces of the NAS server if success
        """
        url = '/nas_server/' + nas_server_id + \
            '?select=current_preferred_IPv4_interface_id,' \
            'current_preferred_IPv6_interface_id,' \
            'file_interfaces(id,ip_address)'
        res, response = self._send_get_request(url)
        if res.status_code == requests.codes.ok:
            preferred_IP = [response['current_preferred_IPv4_interface_id'],
                            response['current_preferred_IPv6_interface_id']]
            file_interfaces = []
            for i in response['file_interfaces']:
                file_interfaces.append({
                    'ip': i['ip_address'],
                    'preferred': i['id'] in preferred_IP
                })
            return file_interfaces

    def create_filesystem(self, nas_server_id, name, size):
        """Creates a filesystem.

        :param nas_server_id: ID of the nas_server
        :param name: name of the filesystem
        :param size: size in Byte
        :return: ID of the filesystem if created successfully
        """
        payload = {
            "name": name,
            "size_total": size,
            "nas_server_id": nas_server_id
            }
        url = '/file_system'
        res, response = self._send_post_request(url, payload)
        if res.status_code == requests.codes.created:
            return response["id"]

    def create_nfs_export(self, filesystem_id, name):
        """Creates an NFS export.

        :param filesystem_id: ID of the filesystem on which
                              the export will be created
        :param name: name of the NFS export
        :return: ID of the export if created successfully
        """
        payload = {
            "file_system_id": filesystem_id,
            "path": "/" + str(name),
            "name": name
            }
        url = '/nfs_export'
        res, response = self._send_post_request(url, payload)
        if res.status_code == requests.codes.created:
            return response["id"]

    def delete_filesystem(self, filesystem_id):
        """Deletes a filesystem and all associated export.

        :param filesystem_id: ID of the filesystem to delete
        :return: True if deleted successfully
        """
        url = '/file_system/' + filesystem_id
        res, _ = self._send_delete_request(url)
        return res.status_code == requests.codes.no_content

    def get_nfs_export_name(self, export_id):
        """Retrieves NFS Export name.

        :param export_id: ID of the NFS export
        :return: path of the NFS export if success
        """
        url = '/nfs_export/' + export_id + '?select=name'
        res, response = self._send_get_request(url)
        if res.status_code == requests.codes.ok:
            return response["name"]

    def get_nfs_export_id(self, name):
        """Retrieves NFS Export ID.

        :param name: name of the NFS export
        :return: id of the NFS export if success
        """
        url = '/nfs_export?select=id&name=eq.' + name
        res, response = self._send_get_request(url)
        if res.status_code == requests.codes.ok:
            return response[0]['id']

    def get_filesystem_id(self, name):
        """Retrieves an ID for a filesystem.

        :param name: name of the filesystem
        :return: ID of the filesystem if success
        """
        url = '/file_system?name=eq.' + name
        res, response = self._send_get_request(url)
        if res.status_code == requests.codes.ok:
            return response[0]['id']

    def set_export_access(self, export_id, rw_hosts, ro_hosts):
        """Sets the access hosts on the export.

        :param export_id: NFS export ID
        :param rw_hosts: a set of RW hosts
        :param ro_hosts: a set of RO hosts
        :return: True if operation succeeded
        """
        payload = {
            "read_only_hosts": list(ro_hosts),
            "read_write_root_hosts": list(rw_hosts)
            }
        url = '/nfs_export/' + export_id
        res, _ = self._send_patch_request(url, payload)
        return res.status_code == requests.codes.no_content

    def resize_filesystem(self, filesystem_id, new_size):
        """Extends the size of a share to a new size.

        :param export_id: ID of the NFS export
        :param new_size: new size to allocate in bytes
        :return: True if extended successfully
        """
        payload = {
            "size_total": new_size
            }
        url = '/file_system/' + filesystem_id
        res, response = self._send_patch_request(url, payload)
        if res.status_code == requests.codes.unprocessable and \
                response['messages'][0]['code'] == '0xE08010080449':
            return False, response['messages'][0]['message_l10n']
        return res.status_code == requests.codes.no_content, None

    def get_fsid_from_export_name(self, name):
        """Retieves the Filesystem ID used by an export.

        :param name: name of the export
        :return: ID of the Filesystem which owns the export
        """
        url = '/nfs_export?select=file_system_id&name=eq.' + name
        res, response = self._send_get_request(url)
        if res.status_code == requests.codes.ok:
            return response[0]['file_system_id']

    def create_snapshot(self, filesystem_id, name):
        """Creates a snapshot of a filesystem.

        :param filesystem_id: ID of the filesystem
        :param name: name of the snapshot
        :return: ID of the snapshot if created successfully
        """
        payload = {
            "name": name
            }
        url = '/file_system/' + filesystem_id + '/snapshot'
        res, response = self._send_post_request(url, payload)
        if res.status_code == requests.codes.created:
            return response["id"]

    def restore_snapshot(self, snapshot_id):
        """Restore a snapshot of a filesystem.

        :param snapshot_id: ID of the snapshot
        :return: True if operation succeeded
        """
        url = '/file_system/' + snapshot_id + '/restore'
        res, _ = self._send_post_request(url)
        return res.status_code == requests.codes.no_content

    def clone_snapshot(self, snapshot_id, name):
        """Clone a snapshot of a filesystem.

        :param snapshot_id: ID of the snapshot
        :param name: name the snapshot
        :return: ID of the clone if created successfully
        """
        payload = {
            "name": name
            }
        url = '/file_system/' + snapshot_id + '/clone'
        res, response = self._send_post_request(url, payload)
        if res.status_code == requests.codes.created:
            return response["id"]

    def get_cluster_id(self):
        """Get cluster id.

        :return: ID of the cluster
        """
        url = '/cluster'
        res, response = self._send_get_request(url)
        if res.status_code == requests.codes.ok:
            return response[0]["id"]

    def retreive_cluster_capacity_metrics(self, cluster_id):
        """Retreive cluster capacity metrics.

        :param cluster_id: ID of the cluster
        :return: total and used capacity in Byte
        """
        payload = {
            "entity": "space_metrics_by_cluster",
            "entity_id": cluster_id
            }
        url = '/metrics/generate?order=timestamp'
        # disable logging of the response
        res, response = self._send_post_request(url, payload,
                                                log_response_data=False)
        if res.status_code == requests.codes.ok:
            # latest cluster capacity metrics
            latestMetrics = response[len(response) - 1]
            LOG.debug(f"Latest cluster capacity: {latestMetrics}")
            return (latestMetrics["physical_total"],
                    latestMetrics["physical_used"])
        return None, None

    def create_smb_share(self, filesystem_id, name):
        """Creates a SMB share.

        :param filesystem_id: ID of the filesystem on which
                              the export will be created
        :param name: name of the SMB share
        :return: ID of the share if created successfully
        """
        payload = {
            "file_system_id": filesystem_id,
            "path": "/" + str(name),
            "name": name
            }
        url = '/smb_share'
        res, response = self._send_post_request(url, payload)
        if res.status_code == requests.codes.created:
            return response["id"]

    def get_fsid_from_share_name(self, name):
        """Retieves the Filesystem ID used by a SMB share.

        :param name: name of the SMB share
        :return: ID of the Filesystem which owns the share
        """
        url = '/smb_share?select=file_system_id&name=eq.' + name
        res, response = self._send_get_request(url)
        if res.status_code == requests.codes.ok:
            return response[0]['file_system_id']

    def get_smb_share_id(self, name):
        """Retrieves SMB share ID.

        :param name: name of the SMB share
        :return: id of the SMB share if success
        """
        url = '/smb_share?select=id&name=eq.' + name
        res, response = self._send_get_request(url)
        if res.status_code == requests.codes.ok:
            return response[0]['id']

    def get_nas_server_smb_netbios(self, nas_server_name):
        """Retrieves the domain name or netbios name.

        :param nas_server_name: NAS server name
        :return: Netbios name of SMB server if success
        """
        url = '/nas_server?select=smb_servers(is_standalone,netbios_name)' \
            '&name=eq.' + nas_server_name
        res, response = self._send_get_request(url)
        if res.status_code == requests.codes.ok:
            smb_server = response[0]['smb_servers'][0]
            if smb_server["is_standalone"]:
                return smb_server["netbios_name"]

    def set_acl(self, smb_share_id, cifs_rw_users, cifs_ro_users):
        """Set ACL for a SMB share.

        :param smb_share_id: ID of the SMB share
        :param name: name of the SMB share
        :return: ID of the share if created successfully
        """
        aces = list()
        for rw_user in cifs_rw_users:
            ace = {
                "trustee_type": "User",
                "trustee_name": rw_user,
                "access_level": "Change",
                "access_type": "Allow"
            }
            aces.append(ace)

        for ro_user in cifs_ro_users:
            ace = {
                "trustee_type": "User",
                "trustee_name": ro_user,
                "access_level": "Read",
                "access_type": "Allow"
            }
            aces.append(ace)

        payload = {
            "aces": aces
            }
        url = '/smb_share/' + smb_share_id + '/set_acl'
        res, _ = self._send_post_request(url, payload)
        return res.status_code == requests.codes.no_content
