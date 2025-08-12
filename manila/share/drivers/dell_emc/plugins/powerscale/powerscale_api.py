# Copyright (c) 2015 EMC Corporation.
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

import enum
import functools

from oslo_log import log
from oslo_serialization import jsonutils
import requests

from manila import exception
from manila.i18n import _


LOG = log.getLogger(__name__)


class PowerScaleApi(object):

    def __init__(self, api_url, username, password,
                 verify_ssl_cert=False,
                 ssl_cert_path=None,
                 dir_permission=None,
                 threshold_limit=0):
        self.host_url = api_url
        self.session = requests.session()
        self.username = username
        self.password = password
        self.verify_ssl_cert = verify_ssl_cert
        self.certificate_path = ssl_cert_path
        self.dir_permission = dir_permission
        self.threshold_limit = threshold_limit

        # Create session
        self.session_token = None
        self.csrf_token = None
        LOG.debug("Login to PowerScale OneFS during initialization.")
        login = self.create_session(username, password)
        if not login:
            message = _("Failed to login to PowerScale OneFS.")
            raise exception.BadConfigurationException(reason=message)

    @property
    def _verify_cert(self):
        verify_cert = self.verify_ssl_cert
        if self.verify_ssl_cert and self.certificate_path:
            verify_cert = self.certificate_path
        return verify_cert

    def create_session(self, username, password):
        """Create a session. Update session token and csrf token."""

        headers = {"Content-type": "application/json"}
        url = self.host_url + '/session/1/session'
        data = {
            "username": username,
            "password": password,
            "services": ["platform", "namespace"]
        }
        r = self.session.request(
            'POST', url, headers=headers, data=jsonutils.dumps(data),
            verify=self._verify_cert)
        if r.status_code == requests.codes.created:
            self.session_token = r.cookies['isisessid']
            self.csrf_token = r.cookies['isicsrf']
            return True

        message = (_('Failed to create session. '
                     'Status_code="%(code)s", body="%(body)s".') %
                   {'code': r.status_code, 'body': r.text})
        LOG.error(message)
        return False

    def create_directory(self, container_path, recursive=False):
        """Create a directory."""

        headers = {"x-isi-ifs-target-type": "container"}
        if self.dir_permission:
            headers.update({"x-isi-ifs-access-control": self.dir_permission})
        url = (self.host_url + "/namespace" + container_path + '?recursive='
               + str(recursive))
        r = self.send_put_request(url, headers=headers)
        return r.status_code == 200

    def clone_snapshot(self, snapshot_name, fq_target_dir):
        self.create_directory(fq_target_dir)
        snapshot = self.get_snapshot(snapshot_name)
        snapshot_path = snapshot['path']
        # remove /ifs from start of path
        relative_snapshot_path = snapshot_path[4:]
        fq_snapshot_path = ('/ifs/.snapshot/' + snapshot_name +
                            relative_snapshot_path)
        self._clone_directory_contents(fq_snapshot_path, fq_target_dir,
                                       snapshot_name, relative_snapshot_path)

    def _clone_directory_contents(self, fq_source_dir, fq_target_dir,
                                  snapshot_name, relative_path):
        dir_listing = self.get_directory_listing(fq_source_dir)
        for item in dir_listing['children']:
            name = item['name']
            source_item_path = fq_source_dir + '/' + name
            new_relative_path = relative_path + '/' + name
            dest_item_path = fq_target_dir + '/' + name
            if item['type'] == 'container':
                # create the container name in the target dir & clone dir
                self.create_directory(dest_item_path)
                self._clone_directory_contents(source_item_path,
                                               dest_item_path,
                                               snapshot_name,
                                               new_relative_path)
            elif item['type'] == 'object':
                self.clone_file_from_snapshot('/ifs' + new_relative_path,
                                              dest_item_path, snapshot_name)

    def clone_file_from_snapshot(self, fq_file_path, fq_dest_path,
                                 snapshot_name):
        headers = {'x-isi-ifs-copy-source': '/namespace' + fq_file_path}
        snapshot_suffix = '&snapshot=' + snapshot_name
        url = (self.host_url + '/namespace' + fq_dest_path + '?clone=true' +
               snapshot_suffix)
        self.send_put_request(url, headers=headers)

    def get_directory_listing(self, fq_dir_path):
        url = self.host_url + '/namespace' + fq_dir_path + '?detail=default'
        r = self.send_get_request(url)

        r.raise_for_status()
        return r.json()

    def is_path_existent(self, resource_path):
        url = self.host_url + '/namespace' + resource_path
        r = self.send_head_request(url)
        if r.status_code == 200:
            return True
        elif r.status_code == 404:
            return False
        else:
            r.raise_for_status()

    def get_snapshot(self, snapshot_name):
        r = self.send_get_request(
            self.host_url + '/platform/1/snapshot/snapshots/' +
            snapshot_name)
        snapshot_json = r.json()
        if r.status_code == 200:
            return snapshot_json['snapshots'][0]
        elif r.status_code == 404:
            return None
        else:
            r.raise_for_status()

    def get_snapshots(self):
        r = self.send_get_request(
            self.host_url + '/platform/1/snapshot/snapshots')
        if r.status_code == 200:
            return r.json()
        else:
            r.raise_for_status()

    def lookup_nfs_export(self, share_path):
        '''Retrieve NFS export by directory path.'''
        r = self.send_get_request(
            self.host_url + '/platform/12/protocols/nfs/exports',
            params={'path': share_path})
        if r.status_code == 200 and r.json()['total'] > 0:
            return r.json()['exports'][0]['id']
        return None

    def get_nfs_export(self, export_id):
        response = self.send_get_request(
            self.host_url + '/platform/1/protocols/nfs/exports/' +
            str(export_id))
        if response.status_code == 200:
            return response.json()['exports'][0]
        else:
            return None

    def lookup_smb_share(self, share_name):
        response = self.send_get_request(
            self.host_url + '/platform/1/protocols/smb/shares/' + share_name)
        if response.status_code == 200:
            return response.json()['shares'][0]
        else:
            return None

    def create_nfs_export(self, export_path):
        """Creates an NFS export using the Platform API.

        :param export_path: a string specifying the desired export path
        :return: "True" if created successfully; "False" otherwise
        """

        data = {'paths': [export_path]}
        url = self.host_url + '/platform/1/protocols/nfs/exports'
        response = self.send_post_request(url, data=data)
        return response.status_code == 201

    def modify_nfs_export_access(self, share_id, ro_ips=None, rw_ips=None):
        """Modify access on an existing NFS export.

        :param share_id: the ID of the NFS export
        :param ro_ips: a list of IP addresses that should have read-only
                       access
        :param rw_ips: a list of IP addresses that should have read-write
                       access
        :return: a boolean indicating whether the modification was successful
        """
        export_params = {}
        if ro_ips is not None:
            export_params['read_only_clients'] = ro_ips
        if rw_ips is not None:
            export_params['clients'] = rw_ips

        url = '{0}/platform/1/protocols/nfs/exports/{1}'.format(
            self.host_url, share_id)

        resp = self.send_put_request(url, data=export_params)
        return resp.status_code == 204

    def create_smb_share(self, share_name, share_path):
        """Creates an SMB/CIFS share.

        :param share_name: the name of the CIFS share
        :param share_path: the path associated with the CIFS share
        :return: "True" if the share created successfully; returns "False"
        otherwise
        """

        data = {'permissions': []}
        data['name'] = share_name
        data['path'] = share_path
        url = self.host_url + '/platform/1/protocols/smb/shares'
        response = self.send_post_request(url, data=data)
        return response.status_code == 201

    def create_snapshot(self, snapshot_name, snapshot_path):
        """Creates a snapshot."""

        data = {'name': snapshot_name, 'path': snapshot_path}
        r = self.send_post_request(
            self.host_url + '/platform/1/snapshot/snapshots',
            data=data)
        return r.status_code == 201

    def delete_path(self, fq_resource_path, recursive=False):
        """Deletes a file or folder."""

        r = self.send_delete_request(
            self.host_url + '/namespace' + fq_resource_path +
            '?recursive=' + str(recursive))
        return r.status_code == 204

    def delete_nfs_share(self, share_number):
        response = self.send_delete_request(
            self.host_url + '/platform/1/protocols/nfs/exports' + '/' +
            str(share_number))
        return response.status_code == 204

    def delete_smb_share(self, share_name):
        url = self.host_url + '/platform/1/protocols/smb/shares/' + share_name
        response = self.send_delete_request(url)
        return response.status_code == 204

    def delete_snapshot(self, snapshot_name):
        response = self.send_delete_request(
            '{0}/platform/1/snapshot/snapshots/{1}'
            .format(self.host_url, snapshot_name))
        return response.status_code == 204

    def quota_create(self, path, quota_type, size):
        thresholds = {'hard': size}
        if self.threshold_limit > 0:
            advisory_size = round((size * self.threshold_limit) / 100)
            thresholds['advisory'] = int(advisory_size)
        data = {
            'path': path,
            'type': quota_type,
            'include_snapshots': False,
            'thresholds_include_overhead': False,
            'enforced': True,
            'thresholds': thresholds,
        }
        response = self.send_post_request(
            '{0}/platform/1/quota/quotas'.format(self.host_url),
            data=data)
        response.raise_for_status()

    def quota_get(self, path, quota_type):
        response = self.send_get_request(
            '{0}/platform/1/quota/quotas?path={1}'.format(self.host_url, path),
        )
        if response.status_code == 404:
            return None
        elif response.status_code != 200:
            response.raise_for_status()

        json = response.json()
        len_returned_quotas = len(json['quotas'])
        if len_returned_quotas == 0:
            return None
        elif len_returned_quotas == 1:
            return json['quotas'][0]
        else:
            message = (_('Greater than one quota returned when querying '
                         'quotas associated with share path: %(path)s .') %
                       {'path': path})
            raise exception.ShareBackendException(msg=message)

    def quota_modify_size(self, quota_id, new_size):
        data = {'thresholds': {'hard': new_size}}
        if self.threshold_limit > 0:
            advisory_size = round((new_size * self.threshold_limit) / 100)
            data.get('thresholds')['advisory'] = int(advisory_size)
        response = self.send_put_request(
            '{0}/platform/1/quota/quotas/{1}'.format(self.host_url, quota_id),
            data=data
        )
        response.raise_for_status()

    def quota_set(self, path, quota_type, size):
        """Sets a quota of the given type and size on the given path."""
        quota_json = self.quota_get(path, quota_type)
        if quota_json is None:
            self.quota_create(path, quota_type, size)
        else:
            # quota already exists, modify it's size
            quota_id = quota_json['id']
            self.quota_modify_size(quota_id, size)

    def delete_quota(self, quota_id):
        response = self.send_delete_request(
            '{0}/platform/1/quota/quotas/{1}'.format(self.host_url, quota_id))
        return response.status_code == 204

    def modify_smb_share_access(self, share_name,
                                host_acl=None, permissions=None):
        """Modifies SMB share access

        :param share_name: the name of the SMB share
        :param host_acl: host access control list
        :param permissions: SMB permissions
        :return: "True" if access updated successfully; otherwise "False"
        """
        data = {}
        if host_acl is not None:
            data['host_acl'] = host_acl
        if permissions is not None:
            data['permissions'] = permissions
        url = ('{0}/platform/1/protocols/smb/shares/{1}'
               .format(self.host_url, share_name))
        r = self.send_put_request(url, data=data)
        return r.status_code == 204

    def get_user_sid(self, user):
        user_json = self.auth_lookup_user(user)
        if user_json:
            auth_mappings = user_json['mapping']
            if len(auth_mappings) > 1:
                message = (_('More than one mapping found for user "%(user)s".'
                             ) % {'user': user})
                LOG.error(message)
                return None
            user_sid = auth_mappings[0]['user']['sid']
            return user_sid

    def auth_lookup_user(self, user_string):
        url = '{0}/platform/1/auth/mapping/users/lookup'.format(self.host_url)
        r = self.send_get_request(url, params={"user": user_string})
        if r.status_code == 200:
            return r.json()
        LOG.error(f'Failed to lookup user {user_string}.')

    def get_space_stats(self):
        url = '{0}/platform/1/statistics/current'.format(self.host_url)
        params = {'keys': 'ifs.bytes.free,ifs.bytes.total,ifs.bytes.used'}
        r = self.send_get_request(url, params=params)
        if r.status_code != 200:
            raise exception.ShareBackendException(
                msg=_('Failed to get statistics from PowerScale.')
            )
        stats = r.json()['stats']
        spaces = {}
        for stat in stats:
            if stat['key'] == 'ifs.bytes.total':
                spaces['total'] = stat['value']
            elif stat['key'] == 'ifs.bytes.free':
                spaces['free'] = stat['value']
            elif stat['key'] == 'ifs.bytes.used':
                spaces['used'] = stat['value']
        return spaces

    def get_allocated_space(self):
        url = '{0}/platform/1/quota/quotas'.format(self.host_url)
        r = self.send_get_request(url)
        allocated_capacity = 0
        if r.status_code != 200:
            raise exception.ShareBackendException(
                msg=_('Failed to get share quotas from PowerScale.')
            )
        quotas = r.json()['quotas']
        for quota in quotas:
            if quota['thresholds']['hard'] is not None:
                allocated_capacity += quota['thresholds']['hard']
        if allocated_capacity > 0:
            return round(allocated_capacity / (1024 ** 3), 2)
        return allocated_capacity

    def get_cluster_version(self):
        url = '{0}/platform/12/cluster/version'.format(self.host_url)
        r = self.send_get_request(url)
        if r.status_code != 200:
            raise exception.ShareBackendException(
                msg=_('Failed to get cluster version from PowerScale.')
            )
        return r.json()['nodes'][0]['release']

    def request(self, method, url, headers=None, data=None, params=None):
        if data is not None:
            data = jsonutils.dumps(data)
        cookies = {'isisessid': self.session_token}
        csrf_headers = {'X-CSRF-Token': self.csrf_token,
                        'referer': self.host_url}
        if headers:
            headers.update(csrf_headers)
        else:
            headers = csrf_headers

        self._log_request(method, url, data, params)
        r = self.session.request(
            method, url, cookies=cookies, headers=headers, data=data,
            verify=self._verify_cert, params=params)
        self._log_response(r)

        # Unauthorized, login again
        if r.status_code == 401:
            login = self.create_session(self.username, self.password)
            # Resend the request once login is successful
            if login:
                self._log_request(method, url, data, params)
                r = self.session.request(
                    method, url, cookies=cookies, headers=headers, data=data,
                    verify=self._verify_cert, params=params)
                self._log_response(r)

        return r

    def _log_request(self, method, url, data=None, params=None):
        req_dict = {}
        if data:
            req_dict['data'] = data
        if params:
            req_dict['params'] = params
        if req_dict:
            LOG.debug(f'Request: {method} {url} {req_dict}')
        else:
            LOG.debug(f'Request: {method} {url}')

    def _log_response(self, r):
        try:
            body = r.json()
        except requests.exceptions.JSONDecodeError:
            body = r.text
        LOG.debug(f'Response: status_code={r.status_code} body={body}')

    send_get_request = functools.partialmethod(request, "GET")
    send_post_request = functools.partialmethod(request, "POST")
    send_put_request = functools.partialmethod(request, "PUT")
    send_delete_request = functools.partialmethod(request, "DELETE")
    send_head_request = functools.partialmethod(request, "HEAD")


class SmbPermission(enum.Enum):
    full = 'full'
    rw = 'change'
    ro = 'read'
