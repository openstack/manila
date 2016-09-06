# Copyright (c) 2016 Hitachi Data Systems, Inc.
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

import json
import requests

from manila import exception
from manila.i18n import _
from manila import utils


# Suppress the Insecure request warnings
requests.packages.urllib3.disable_warnings()


class HSPRestBackend(object):
    def __init__(self, hsp_host, hsp_username, hsp_password):
        self.host = hsp_host
        self.username = hsp_username
        self.password = hsp_password

    def _send_post(self, url, payload=None):
        resp = requests.post(url, auth=(self.username, self.password),
                             data=payload, verify=False)

        if resp.status_code == 202:
            self._wait_job_status(resp.headers['location'], 'COMPLETE')
        else:
            msg = (_("HSP API post failed: %s.") %
                   resp.json()['messages'][0]['message'])
            raise exception.HSPBackendException(msg=msg)

    def _send_get(self, url, payload=None):
        resp = requests.get(url, auth=(self.username, self.password),
                            data=payload, verify=False)

        if resp.status_code == 200:
            if resp.content == 'null':
                return None
            else:
                return resp.json()
        else:
            msg = (_("HSP API get failed: %s.") %
                   resp.json()['messages'][0]['message'])
            raise exception.HSPBackendException(msg=msg)

    def _send_delete(self, url, payload=None):
        resp = requests.delete(url, auth=(self.username, self.password),
                               data=payload, verify=False)

        if resp.status_code == 202:
            self._wait_job_status(resp.headers['location'], 'COMPLETE')
        else:
            msg = (_("HSP API delete failed: %s.") %
                   resp.json()['messages'][0]['message'])
            raise exception.HSPBackendException(msg=msg)

    def add_file_system(self, name, quota):
        url = "https://%s/hspapi/file-systems/" % self.host
        payload = {
            'quota': quota,
            'auto-access': False,
            'enabled': True,
            'description': '',
            'record-access-time': True,
            'tags': '',
            # Usage percentage in which a warning will be shown
            'space-hwm': 90,
            # Usage percentage in which the warning will be cleared
            'space-lwm': 70,
            'name': name,
        }
        self._send_post(url, payload=json.dumps(payload))

    def get_file_system(self, name):
        url = ("https://%s/hspapi/file-systems/list?name=%s" %
               (self.host, name))

        filesystems = self._send_get(url)

        try:
            return filesystems['list'][0]
        except (TypeError, KeyError, IndexError):
            msg = _("Filesystem does not exist or is not available.")
            raise exception.HSPItemNotFoundException(msg=msg)

    def delete_file_system(self, filesystem_id):
        url = "https://%s/hspapi/file-systems/%s" % (self.host, filesystem_id)
        self._send_delete(url)

    def resize_file_system(self, filesystem_id, new_size):
        url = "https://%s/hspapi/file-systems/%s" % (self.host, filesystem_id)
        payload = {'quota': new_size}

        self._send_post(url, payload=json.dumps(payload))

    def rename_file_system(self, filesystem_id, new_name):
        url = "https://%s/hspapi/file-systems/%s" % (self.host, filesystem_id)
        payload = {'name': new_name}

        self._send_post(url, payload=json.dumps(payload))

    def add_share(self, name, filesystem_id):
        url = "https://%s/hspapi/shares/" % self.host
        payload = {
            'description': '',
            'type': 'NFS',
            'enabled': True,
            'tags': '',
            'name': name,
            'file-system-id': filesystem_id,
        }

        self._send_post(url, payload=json.dumps(payload))

    def get_share(self, fs_id=None, name=None):
        if fs_id is not None:
            url = ('https://%s/hspapi/shares/list?file-system-id=%s' %
                   (self.host, fs_id))
        elif name is not None:
            url = ('https://%s/hspapi/shares/list?name=%s' %
                   (self.host, name))
        share = self._send_get(url)

        try:
            return share['list'][0]
        except (TypeError, KeyError, IndexError):
            msg = _("Share %s does not exist or is not available.")

            if fs_id is not None:
                args = "for filesystem %s" % fs_id
            else:
                args = name

            raise exception.HSPItemNotFoundException(msg=msg % args)

    def delete_share(self, share_id):
        url = "https://%s/hspapi/shares/%s" % (self.host, share_id)
        self._send_delete(url)

    def add_access_rule(self, share_id, host_to, read_write):
        url = "https://%s/hspapi/shares/%s/" % (self.host, share_id)
        payload = {
            "action": "add-access-rule",
            "name": share_id + host_to,
            "host-specification": host_to,
            "read-write": read_write,
        }

        self._send_post(url, payload=json.dumps(payload))

    def delete_access_rule(self, share_id, rule_name):
        url = "https://%s/hspapi/shares/%s/" % (self.host, share_id)
        payload = {
            "action": "delete-access-rule",
            "name": rule_name,
        }

        self._send_post(url, payload=json.dumps(payload))

    def get_access_rules(self, share_id):
        url = ("https://%s/hspapi/shares/%s/access-rules" %
               (self.host, share_id))
        rules = self._send_get(url)

        try:
            rules = rules['list']
        except (TypeError, KeyError, IndexError):
            rules = []
        return rules

    def get_cluster(self):
        url = "https://%s/hspapi/clusters/list" % self.host
        clusters = self._send_get(url)

        try:
            return clusters['list'][0]
        except (TypeError, KeyError, IndexError):
            msg = _("No cluster was found on HSP.")
            raise exception.HSPBackendException(msg=msg)

    @utils.retry(exception.HSPTimeoutException, retries=10, wait_random=True)
    def _wait_job_status(self, job_url, target_status):
        resp_json = self._send_get(job_url)

        status = resp_json['properties']['completion-status']

        if status == 'ERROR':
            msg = _("HSP job %(id)s failed. %(reason)s")
            job_id = resp_json['id']
            reason = resp_json['properties']['completion-details']
            raise exception.HSPBackendException(msg=msg % {'id': job_id,
                                                           'reason': reason})
        elif status != target_status:
            msg = _("Timeout while waiting for job %s to complete.")
            args = resp_json['id']
            raise exception.HSPTimeoutException(msg=msg % args)
