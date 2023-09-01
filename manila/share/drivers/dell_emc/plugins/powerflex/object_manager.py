# Copyright (c) 2023 Dell Inc. or its subsidiaries.
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

from http import client as http_client
import json

from oslo_log import log as logging
import requests

from manila import exception

LOG = logging.getLogger(__name__)


class StorageObjectManager(object):

    def __init__(self,
                 host_url,
                 username,
                 password,
                 export_path,
                 certificate_path=None,
                 verify_ssl_cert=False):
        self.host_url = host_url
        self.base_url = host_url + '/rest'
        self.rest_username = username
        self.rest_password = password
        self.rest_token = None
        self.got_token = False
        self.export_path = export_path
        self.verify_certificate = verify_ssl_cert
        self.certificate_path = certificate_path

    def _get_headers(self):
        if self.got_token:
            return {"Content-type": "application/json",
                    "Accept": "application/json",
                    "Authorization": "Bearer " + self.rest_token}
        else:
            return {"Content-type": "application/json",
                    "Accept": "application/json"}

    def execute_powerflex_get_request(self, url, **url_params):
        request = url % url_params
        res = requests.get(request,
                           headers=self._get_headers(),
                           verify=self._get_verify_cert())
        res = self._check_response(res, request, "GET")
        response = res.json()

        return res, response

    def execute_powerflex_post_request(self, url, params=None, **url_params):
        if not params:
            params = {}
        request = url % url_params
        res = requests.post(request,
                            data=json.dumps(params),
                            headers=self._get_headers(),
                            verify=self._get_verify_cert())
        res = self._check_response(res, request, "POST", params)
        response = None
        try:
            response = res.json()
        except ValueError:
            # Particular case for get_storage_pool_id which is not
            # a json object but a string
            response = res
        return res, response

    def execute_powerflex_delete_request(self, url, **url_params):
        request = url % url_params
        res = requests.delete(request,
                              headers=self._get_headers(),
                              verify=self._get_verify_cert())
        res = self._check_response(res, request, "DELETE")
        return res

    def execute_powerflex_patch_request(self, url, params=None, **url_params):
        if not params:
            params = {}
        request = url % url_params
        res = requests.patch(request,
                             data=json.dumps(params),
                             headers=self._get_headers(),
                             verify=self._get_verify_cert())
        res = self._check_response(res, request, "PATCH")
        return res

    def _check_response(self,
                        response,
                        request,
                        request_type,
                        params=None):
        login_url = "/auth/login"

        if (response.status_code == http_client.UNAUTHORIZED or
                response.status_code == http_client.FORBIDDEN):
            LOG.info("Dell PowerFlex token is invalid, going to re-login "
                     "and get a new one.")
            login_request = self.base_url + login_url
            verify_cert = self._get_verify_cert()
            self.got_token = False
            payload = json.dumps({"username": self.rest_username,
                                  "password": self.rest_password})
            res = requests.post(login_request,
                                headers=self._get_headers(),
                                data=payload,
                                verify=verify_cert)
            if (res.status_code == http_client.UNAUTHORIZED or
                    res.status_code == http_client.FORBIDDEN):
                message = ("PowerFlex REST API access is still forbidden or "
                           "unauthorized, there might be an issue with your "
                           "credentials.")
                LOG.error(message)
                raise exception.NotAuthorized()
            else:
                token = res.json()["access_token"]
                self.rest_token = token
                self.got_token = True
                LOG.info("Going to perform request again %s with valid token.",
                         request)
                if (request_type == "GET"):
                    response = requests.get(request,
                                            headers=self._get_headers(),
                                            verify=verify_cert)
                elif (request_type == "POST"):
                    response = requests.post(request,
                                             headers=self._get_headers(),
                                             data=json.dumps(params),
                                             verify=verify_cert)
                elif (request_type == "DELETE"):
                    response = requests.delete(request,
                                               headers=self._get_headers(),
                                               verify=verify_cert)
                elif (request_type == "PATCH"):
                    response = requests.patch(request,
                                              headers=self._get_headers(),
                                              data=json.dumps(params),
                                              verify=verify_cert)
                level = logging.DEBUG
                if response.status_code != http_client.OK:
                    level = logging.ERROR
                LOG.log(level,
                        "REST REQUEST: %s with params %s",
                        request,
                        json.dumps(params))
                LOG.log(level,
                        "REST RESPONSE: %s with params %s",
                        response.status_code,
                        response.text)
        return response

    def _get_verify_cert(self):
        verify_cert = False
        if self.verify_certificate:
            verify_cert = self.certificate_path
        return verify_cert

    def create_filesystem(self, storage_pool_id, nas_server, name, size):
        """Creates a filesystem.

        :param nas_server: name of the nas_server
        :param name: name of the filesystem
        :param size: size in GiB
        :return: ID of the filesystem if created successfully
        """
        nas_server_id = self.get_nas_server_id(nas_server)
        params = {
            "name": name,
            "size_total": size,
            "storage_pool_id": storage_pool_id,
            "nas_server_id": nas_server_id
            }
        url = f'{self.base_url}/v1/file-systems'
        res, response = self.execute_powerflex_post_request(url, params)
        if res.status_code == 201:
            return response["id"]

    def create_nfs_export(self, filesystem_id, name):
        """Creates an NFS export.

        :param filesystem_id: ID of the filesystem on which
                              the export will be created
        :param name: name of the NFS export
        :return: ID of the export if created successfully
        """
        params = {
            "file_system_id": filesystem_id,
            "path": "/" + str(name),
            "name": name
            }
        url = f'{self.base_url}/v1/nfs-exports'
        res, response = self.execute_powerflex_post_request(url, params)
        if res.status_code == 201:
            return response["id"]

    def delete_filesystem(self, filesystem_id):
        """Deletes a filesystem and all associated export.

        :param filesystem_id: ID of the filesystem to delete
        :return: True if deleted successfully
        """
        url = f'{self.base_url}/v1/file-systems/{filesystem_id}'
        res = self.execute_powerflex_delete_request(url)
        return res.status_code == 204

    def create_snapshot(self, name, filesystem_id):
        """Creates a snapshot of a filesystem.

        :param name: name of the snapshot
        :param filesystem_id: ID of the filesystem
        :return: ID of the snapshot if created successfully
        """
        params = {
            "name": name
            }
        url = f'{self.base_url}/v1/file-systems/{filesystem_id}/snapshot'
        res, response = self.execute_powerflex_post_request(url, params)
        return res.status_code == 201

    def get_nas_server_id(self, nas_server):
        """Retrieves the NAS server ID.

        :param nas_server: NAS server name
        :return: ID of the NAS server if success
        """
        url = f'{self.base_url}/v1/nas-servers?select=id&name=eq.{nas_server}'
        res, response = self.execute_powerflex_get_request(url)
        if res.status_code == 200:
            return response[0]['id']

    def get_nfs_export_name(self, export_id):
        """Retrieves NFS Export name.

        :param export_id: ID of the NFS export
        :return: path of the NFS export if success
        """
        url = f'{self.base_url}/v1/nfs-exports/{export_id}?select=*'
        res, response = self.execute_powerflex_get_request(url)
        if res.status_code == 200:
            return response["name"]

    def get_filesystem_id(self, name):
        """Retrieves an ID for a filesystem.

        :param name: name of the filesystem
        :return: ID of the filesystem if success
        """
        url = f'{self.base_url}/v1/file-systems?select=id&name=eq.{name}'
        res, response = self.execute_powerflex_get_request(url)
        if res.status_code == 200:
            return response[0]['id']

    def get_nfs_export_id(self, name):
        """Retrieves NFS Export ID.

        :param name: name of the NFS export
        :return: id of the NFS export if success
        """
        url = f'{self.base_url}/v1/nfs-exports?select=id&name=eq.{name}'
        res, response = self.execute_powerflex_get_request(url)
        if res.status_code == 200:
            return response[0]['id']

    def get_storage_pool_id(self, protection_domain, storage_pool):
        """Retrieves the Storage Pool ID.

        :param protection_domain: protection domain name
        :param storage_pool: storage pool name
        :return: ID of the storage pool if success
        """
        params = {
            "protectionDomainName": protection_domain,
            "name": storage_pool
            }
        url = (f'{self.host_url}/api/types/StoragePool/instances/'
               'action/queryIdByKey')
        res, response = self.execute_powerflex_post_request(url, params)
        if res.status_code == 200:
            return response

    def set_export_access(self, export_id, rw_hosts, ro_hosts):
        """Sets the authorization access on the export.

        :param export_id: NFS export ID
        :param rw_hosts: a set of RW hosts
        :param ro_hosts: a set of RO hosts
        :return: True if operation succeeded
        """
        params = {
            "read_only_hosts": list(ro_hosts),
            "read_write_root_hosts": list(rw_hosts)
            }
        url = f'{self.base_url}/v1/nfs-exports/{export_id}'
        res = self.execute_powerflex_patch_request(url, params)
        return res.status_code == 204

    def extend_export(self, export_id, new_size):
        """Extends the size of a share to a new size.

        :param export_id: ID of the NFS export
        :param new_size: new size to allocate in bytes
        :return: True if extended successfully
        """
        params = {
            "size_total": new_size
            }
        url = f'{self.base_url}/v1/file-systems/{export_id}'
        res = self.execute_powerflex_patch_request(url, params)
        return res.status_code == 204

    def get_fsid_from_export_name(self, name):
        """Retieves the Filesystem ID used by an export.

        :param name: name of the export
        :return: ID of the Filesystem which owns the export
        """
        url = (f'{self.base_url}/v1/nfs-exports'
               f'?select=file_system_id&name=eq.{name}')
        res, response = self.execute_powerflex_get_request(url)
        if res.status_code == 200:
            return response[0]['file_system_id']

    def get_fsid_from_snapshot_name(self, snapshot_name):
        """Retrieves the Filesystem ID used by a snapshot.

        :param snapshot_name: Name of the snapshot
        :return: ID of the parent filesystem of the snapshot
        """
        url = (f'{self.base_url}/v1/file-systems'
               f'?select=id&name=eq.{snapshot_name}')
        res, response = self.execute_powerflex_get_request(url)
        if res.status_code == 200:
            return response[0]['id']

    def get_storage_pool_spare_percentage(self, storage_pool_id):
        """Retrieves the spare capacity percentage of the storage pool.

        :param storage_pool_id: ID of the storage pool
        :return: Spare capacity percentage of the storage pool
        """
        url = f'{self.host_url}/api/instances/StoragePool::{storage_pool_id}'
        res, response = self.execute_powerflex_get_request(url)
        if res.status_code == 200:
            return response['sparePercentage']

    def get_storage_pool_statistic(self, storage_pool_id):
        """Retrieves the spare capacity percentage of the storage pool.

        :param storage_pool_id: ID of the storage pool
        :return: Statistics of the storage pool
        """
        url = (f'{self.host_url}/api/instances/StoragePool::{storage_pool_id}'
               '/relationships/Statistics')
        res, response = self.execute_powerflex_get_request(url)
        if res.status_code == 200:
            statistics = {
                "maxCapacityInKb": response['maxCapacityInKb'],
                "capacityInUseInKb": response['capacityInUseInKb'],
                "netUnusedCapacityInKb": response['netUnusedCapacityInKb'],
                "primaryVacInKb": response['primaryVacInKb'],
            }
        return statistics

    def get_nas_server_interfaces(self, nas_server_id):
        """Retrieves the file interfaces for a given na_server.

        :param nas_server_id: ID of the NAS server
        :return: file interfaces of the NAS server
        """
        url = (f'{self.base_url}/v1/file-interfaces'
               f'?select=ip_address&nas_server_id=eq.{nas_server_id}')
        res, response = self.execute_powerflex_get_request(url)
        if res.status_code == 200:
            return [i['ip_address'] for i in response]
