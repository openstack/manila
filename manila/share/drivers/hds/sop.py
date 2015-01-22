# Copyright (c) 2015 Hitachi Data Systems.
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
Hitachi Data Systems Scale-out-Platform Manila Driver.
"""

import base64
import socket
import time

import httplib2
from oslo_config import cfg
from oslo_serialization import jsonutils as json
from oslo_utils import units
import six

from manila import exception
from manila.i18n import _LW
from manila.openstack.common import log as logging
from manila.share import driver


LOG = logging.getLogger(__name__)

hdssop_share_opts = [
    cfg.StrOpt('hdssop_target',
               help='Specifies the SOPAPI cluster VIP. '
               'It is of the form https://<SOPAPI cluster VIP>.'),
    cfg.StrOpt('hdssop_adminuser',
               help='Specifies the sop admin user'),
    cfg.StrOpt('hdssop_adminpassword',
               help='Specifies the sop admin user password',
               secret=True)
]

CONF = cfg.CONF
CONF.register_opts(hdssop_share_opts)


class SopShareDriver(driver.ShareDriver):
    """Execute commands relating to Shares."""

    def __init__(self, db, *args, **kwargs):
        super(SopShareDriver, self).__init__(False, *args, **kwargs)
        self.db = db
        self.configuration.append_config_values(hdssop_share_opts)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'HDS_SOP'
        self.sop_target = self.configuration.safe_get('hdssop_target')
        self.sopuser = self.configuration.safe_get('hdssop_adminuser')
        self.soppassword = self.configuration.safe_get('hdssop_adminpassword')

    def get_sop_auth_header(self):
        return 'Basic ' + base64.b64encode(
            self.sopuser + ':' +
            self.soppassword).encode('utf-8').decode('ascii')

    def _wait_for_job_completion(self, httpclient, job_uri):
        """Wait for job identified by job_uri to complete."""
        count = 0
        headers = dict(Authorization=self.get_sop_auth_header())

        # NOTE(jasonsb): timeout logic here needs be revisited after
        # load testing results are in.
        while True:
            if count > 300:
                raise exception.SopAPIError(err=_('job timed out'))

            resp_headers, resp_content = httpclient.request(job_uri, 'GET',
                                                            body='',
                                                            headers=headers)
            if int(resp_headers['status']) != 200:
                raise exception.SopAPIError(err=_('error getting job status'))

            job = json.loads(resp_content)
            if job['properties']['completion-status'] == 'ERROR':
                raise exception.SopAPIError(err=_('job errored out'))
            if job['properties']['completion-status'] == 'COMPLETE':
                return job
            time.sleep(1)
            count += 1

    def _add_file_system_sopapi(self, httpclient, payload):
        """Add a new filesystem via SOPAPI."""
        sopuri = '/file-systems/'
        headers = dict(Authorization=self.get_sop_auth_header())
        uri = self.sop_target + '/sopapi' + sopuri
        payload_json = json.dumps(payload)
        resp_headers, resp_content = httpclient.request(uri, 'POST',
                                                        body=payload_json,
                                                        headers=headers)
        resp_code = int(resp_headers['status'])
        if resp_code == 202:
            job_loc = resp_headers['location']
            self._wait_for_job_completion(httpclient, job_loc)
        else:
            raise exception.SopAPIError(
                err=(_('received error: %s') %
                     resp_content['messages'][0]['message']))

    def _add_share_sopapi(self, httpclient, payload):
        """Add a new filesystem via SOPAPI."""
        sopuri = '/shares/'
        headers = dict(Authorization=self.get_sop_auth_header())
        payload_json = json.dumps(payload)
        uri = self.sop_target + '/sopapi' + sopuri
        resp_headers, resp_content = httpclient.request(uri, 'POST',
                                                        body=payload_json,
                                                        headers=headers)
        resp_code = int(resp_headers['status'])
        if resp_code == 202:
            job_loc = resp_headers['location']
            job = self._wait_for_job_completion(httpclient, job_loc)
            if job['properties']['completion-status'] == 'COMPLETE':
                return job['properties']['resource-name']
        else:
            raise exception.SopAPIError(err=_('received error: %s') %
                                        resp_headers['status'])

    def _get_file_system_id_by_name(self, httpclient, fsname):

        sopuri = '/file-systems/list?name=' + fsname
        headers = dict(Authorization=self.get_sop_auth_header())
        uri = self.sop_target + '/sopapi' + sopuri
        resp_headers, resp_content = httpclient.request(uri, 'GET',
                                                        body='',
                                                        headers=headers)

        response = json.loads(resp_content)
        num_of_resources = 0
        if int(resp_headers['status']) != 200 and 'messages' in response:
            raise exception.SopAPIError(
                err=(_('received error: %s') %
                     response['messages'][0]['message']))
        resource_list = []
        resource_list = response['list']
        num_of_resources = len(resource_list)
        if num_of_resources <= 0:
            return ''
        return resource_list[0]['id']

    def _get_share_id_by_name(self, httpclient, share_name):
        """Look up share given the share name."""
        sopuri = '/shares/list?name=' + share_name
        headers = dict(Authorization=self.get_sop_auth_header())
        uri = self.sop_target + '/sopapi' + sopuri
        resp_headers, resp_content = httpclient.request(uri, 'GET',
                                                        body='',
                                                        headers=headers)
        response = json.loads(resp_content)
        num_of_resources = 0
        if int(resp_headers['status']) != 200 and 'messages' in response:
            raise exception.SopAPIError(
                err=(_('received error: %s') %
                     response['messages'][0]['message']))
        resource_list = response['list']
        num_of_resources = len(resource_list)
        if num_of_resources == 0:
            return ''
        return resource_list[0]['id']

    def create_share(self, ctx, share, share_server=None):
        """Create new share on HDS Scale-out Platform."""
        sharesize = int(six.text_type(share['size']))

        httpclient = httplib2.Http(disable_ssl_certificate_validation=True,
                                   timeout=None)

        if share['share_proto'] != 'NFS':
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.') %
                        share['share_proto']))

        payload = {
            'quota': sharesize * units.Gi,
            'enabled': True,
            'description': '',
            'record-access-time': True,
            'tags': '',
            'space-hwm': 90,
            'space-lwm': 70,
            'name': share['id'],
        }
        self._add_file_system_sopapi(httpclient, payload)
        payload = {
            'description': '',
            'type': 'NFS',
            'enabled': True,
            'tags': '',
            'name': share['id'],
            'file-system-id': self._get_file_system_id_by_name(
                httpclient, share['id']),
        }
        return self.sop_target + ':/' + self._add_share_sopapi(
            httpclient, payload)

    def _delete_file_system_sopapi(self, httpclient, fs_id):
        """Delete filesystem on SOP."""
        sopuri = '/file-systems/' + fs_id
        headers = dict(Authorization=self.get_sop_auth_header())
        uri = self.sop_target + '/sopapi' + sopuri
        resp_headers, resp_content = httpclient.request(uri, 'DELETE',
                                                        body='',
                                                        headers=headers)
        resp_code = int(resp_headers['status'])
        if resp_code == 202:
            job_loc = resp_headers['location']
            self._wait_for_job_completion(httpclient, job_loc)
        else:
            raise exception.SopAPIError(err=_('received error: %s') %
                                        resp_headers['status'])

    def _delete_share_sopapi(self, httpclient, share_id):
        """Delete share on SOP."""
        sopuri = '/shares/' + share_id
        headers = dict(Authorization=self.get_sop_auth_header())
        uri = self.sop_target + '/sopapi' + sopuri
        resp_headers, resp_content = httpclient.request(uri, 'DELETE',
                                                        body='',
                                                        headers=headers)
        resp_code = int(resp_headers['status'])
        if resp_code == 202:
            job_loc = resp_headers['location']
            self._wait_for_job_completion(httpclient, job_loc)
        else:
            raise exception.SopAPIError(err=_('received error: %s') %
                                        resp_headers['status'])

    def delete_share(self, context, share, share_server=None):
        """Remove a share from Sop volume."""

        httpclient = httplib2.Http(disable_ssl_certificate_validation=True,
                                   timeout=None)
        self._delete_share_sopapi(
            httpclient,
            self._get_share_id_by_name(httpclient, share['id']))
        self._delete_file_system_sopapi(
            httpclient,
            self._get_file_system_id_by_name(httpclient, share['id']))

    def create_snapshot(self, context, snapshot, share_server=None):
        """Not currently supported on HDS Scale-out Platform."""
        raise NotImplementedError()

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Not currently supported on HDS Scale-out Platform."""
        raise NotImplementedError()

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Not currently supported on HDS Scale-out Platform."""
        raise NotImplementedError()

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to a share.

        Currently only IP based access control is supported.
        """

        if access['access_type'] != 'ip':
            raise exception.InvalidShareAccess(
                reason=_('only IP access type allowed'))

        httpclient = httplib2.Http(disable_ssl_certificate_validation=True,
                                   timeout=None)
        sop_share_id = self._get_share_id_by_name(httpclient, share['id'])

        if access['access_level'] == 'rw':
            access_level = True
        elif access['access_level'] == 'ro':
            access_level = False
        else:
            raise exception.InvalidShareAccess(
                reason=(_('Unsupported level of access was provided - %s') %
                        access['access_level']))
        payload = {
            'action': 'add-access-rule',
            'all-squash': True,
            'anongid': 65534,
            'anonuid': 65534,
            'host-specification': access['access_to'],
            'description': '',
            'read-write': access_level,
            'root-squash': False,
            'tags': 'nfs',
            'name': '%s-%s' % (share['id'], access['access_to']),
        }
        sopuri = '/shares/'
        headers = dict(Authorization=self.get_sop_auth_header())
        uri = self.sop_target + '/sopapi' + sopuri + sop_share_id
        resp_headers, resp_content = httpclient.request(
            uri, 'POST',
            body=json.dumps(payload),
            headers=headers)
        resp_code = int(resp_headers['status'])
        if resp_code == 202:
            job_loc = resp_headers['location']
            self._wait_for_job_completion(httpclient, job_loc)
        else:
            raise exception.SopAPIError(err=_('received error: %s') %
                                        resp_headers['status'])

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to a share.

        Currently only IP based access control is supported.
        """
        if access['access_type'] != 'ip':
            LOG.warn(_LW('Only ip access type allowed.'))
            return

        httpclient = httplib2.Http(disable_ssl_certificate_validation=True,
                                   timeout=None)
        sop_share_id = self._get_share_id_by_name(httpclient, share['id'])
        payload = {
            'action': 'delete-access-rule',
            'name': '%s-%s' % (share['id'], access['access_to']),
        }

        sopuri = '/shares/' + sop_share_id
        headers = dict(Authorization=self.get_sop_auth_header())
        uri = self.sop_target + '/sopapi' + sopuri
        resp_headers, resp_content = httpclient.request(
            uri, 'POST',
            body=json.dumps(payload),
            headers=headers)
        resp_code = int(resp_headers['status'])
        if resp_code == 202:
            job_loc = resp_headers['location']
            self._wait_for_job_completion(httpclient, job_loc)
        else:
            raise exception.SopAPIError(err=_('received error: %s') %
                                        resp_headers['status'])

    def check_for_setup_error(self):
        """Check for setup error.

        Socket timeout set for 5 seconds to verify SOPAPI rest
        interface is reachable and the credentials will allow us
        to login.
        """
        headers = dict(Authorization=self.get_sop_auth_header())
        uri = self.sop_target + '/sopapi/clusters'
        try:
            httpclient = httplib2.Http(disable_ssl_certificate_validation=True,
                                       timeout=5)
            resp_headers, resp_content = httpclient.request(uri, 'GET',
                                                            body='',
                                                            headers=headers)
            response = json.loads(resp_content)
            if 'messages' in response:
                soperror = _('received error: %(code)s: %(msg)s') % {
                    'code': response['messages'][0]['code'],
                    'msg': response['messages'][0]['message'],
                }
                raise exception.SopAPIError(err=soperror)
        except socket.timeout:
            raise exception.SopAPIError(
                err=_('connection to SOPAPI timed out'))

    def _get_sop_filesystem_stats(self):
        """Calculate cluster storage capacity and return in GiB."""
        headers = dict(Authorization=self.get_sop_auth_header())
        uri = self.sop_target + '/sopapi/clusters'
        httpclient = httplib2.Http(disable_ssl_certificate_validation=True,
                                   timeout=None)
        resp_headers, resp_content = httpclient.request(uri, 'GET',
                                                        body='',
                                                        headers=headers)
        response = json.loads(resp_content)
        if resp_content is not None:
            for cluster in response['element-links']:
                (resp_headers, resp_content) = httpclient.request(
                    cluster,
                    'GET',
                    body='',
                    headers=headers)
                response = json.loads(resp_content)
                totalspace = int(response['properties']
                                 ['total-storage-capacity']) / units.Gi
                spaceavail = int(response['properties']
                                 ['total-storage-available']) / units.Gi
                return (totalspace, spaceavail)

    def _update_share_stats(self):
        """Retrieve stats info from SOPAPI."""
        totalspace, spaceavail = self._get_sop_filesystem_stats()
        data = dict(
            share_backend_name=self.backend_name,
            vendor_name='Hitach Data Systems',
            storage_protocol='NFS',
            total_capacity_gb=totalspace,
            free_capacity_gb=spaceavail)
        super(SopShareDriver, self)._update_share_stats(data)
