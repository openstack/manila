# vim: tabstop=4 shiftwidth=4 softtabstop=4
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

from tempest.common import rest_client
from tempest.common.utils.data_utils import rand_name
from tempest import exceptions
from tempest import exceptions_shares

import time
import urllib


class SharesClientJSON(rest_client.RestClient):

    """
    Tempest REST client for Manila.
    It handles shares and access to it in openstack.
    """

    def __init__(self, config, username, password, auth_url, tenant_name=None):
        super(SharesClientJSON, self).__init__(config, username, password,
                                               auth_url, tenant_name)
        self.service = self.config.shares.catalog_type  # share
        self.share_protocol = self.config.shares.share_protocol
        self.build_interval = self.config.shares.build_interval
        self.build_timeout = self.config.shares.build_timeout

        self.tenant_name = tenant_name
        self.username = username

    def _parse_resp(self, body):
        if len(body) > 0:
            body = json.loads(body)
            if len(body) is 1 and isinstance(body.items()[0][1], (dict, list)):
                return body[body.items()[0][0]]
        return body

    def create_share(self, share_protocol=None, size=1,
                     name=None, snapshot_id=None,
                     description="tempest created share",
                     metadata={}):
        if name is None:
            name = rand_name("tempest-created-share-")
        if share_protocol is None:
            share_protocol = self.share_protocol
        post_body = {
            "share": {
                "share_proto": share_protocol,
                "description": description,
                "snapshot_id": snapshot_id,
                "name": name,
                "size": size,
                "metadata": metadata
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post("shares", body, self.headers)
        return resp, self._parse_resp(body)

    def delete_share(self, share_id):
        resp, body = self.delete("shares/%s" % share_id, self.headers)
        return resp, self._parse_resp(body)

    def list_shares(self):
        resp, body = self.get("shares", self.headers)
        return resp, self._parse_resp(body)

    def list_shares_with_detail(self, params=None):
        """List the details of all shares."""
        url = 'shares/detail'
        if params:
                url += '?%s' % urllib.urlencode(params)
        resp, body = self.get(url, self.headers)
        return resp, self._parse_resp(body)

    def get_share(self, share_id):
        uri = "shares/%s" % share_id
        resp, body = self.get(uri, self.headers)
        return resp, self._parse_resp(body)

    def create_access_rule(self, share_id,
                           access_type="ip", access_to="0.0.0.0"):
        post_body = {
            "os-allow_access": {
                "access_type": access_type,
                "access_to": access_to
            }
        }
        body = json.dumps(post_body)
        uri = "shares/%s/action" % share_id
        resp, body = self.post(uri, body, self.headers)
        return resp, self._parse_resp(body)

    def list_access_rules(self, share_id):
        uri = "shares/%s/action" % share_id
        body = {"os-access_list": None}
        resp, body = self.post(uri, json.dumps(body), self.headers)
        return resp, self._parse_resp(body)

    def delete_access_rule(self, share_id, rule_id):
        post_body = {
            "os-deny_access": {
                "access_id": rule_id
            }
        }
        body = json.dumps(post_body)
        uri = "shares/%s/action" % share_id
        return self.post(uri, body, self.headers)

    def create_snapshot(self, share_id, name=None,
                        description="tempest created share-ss",
                        force=False):
        if name is None:
            name = rand_name("tempest-created-share-snap-")
        post_body = {
            "snapshot": {
                "name": name,
                "force": force,
                "description": description,
                "share_id": share_id
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post("snapshots", body, self.headers)
        return resp, self._parse_resp(body)

    def get_snapshot(self, snapshot_id):
        uri = "snapshots/%s" % snapshot_id
        resp, body = self.get(uri, self.headers)
        return resp, self._parse_resp(body)

    def list_snapshots(self):
        resp, body = self.get("snapshots", self.headers)
        return resp, self._parse_resp(body)

    def list_snapshots_with_detail(self, params=None):
        """List the details of all shares."""
        url = 'snapshots/detail'
        if params:
                url += '?%s' % urllib.urlencode(params)
        resp, body = self.get(url, self.headers)
        return resp, self._parse_resp(body)

    def delete_snapshot(self, snap_id):
        uri = "snapshots/%s" % snap_id
        resp, body = self.delete(uri, self.headers)
        return resp, self._parse_resp(body)

    def wait_for_share_status(self, share_id, status):
        """Waits for a Share to reach a given status."""
        resp, body = self.get_share(share_id)
        share_name = body['name']
        share_status = body['status']
        start = int(time.time())

        while share_status != status:
            time.sleep(self.build_interval)
            resp, body = self.get_share(share_id)
            share_status = body['status']
            if 'error' in share_status:
                raise exceptions_shares.\
                    ShareBuildErrorException(share_id=share_id)

            if int(time.time()) - start >= self.build_timeout:
                message = ('Share %s failed to reach %s status within '
                           'the required time (%s s).' %
                           (share_name, status, self.build_timeout))
                raise exceptions.TimeoutException(message)

    def wait_for_snapshot_status(self, snapshot_id, status):
        """Waits for a Share to reach a given status."""
        resp, body = self.get_snapshot(snapshot_id)
        snapshot_name = body['name']
        snapshot_status = body['status']
        start = int(time.time())

        while snapshot_status != status:
            time.sleep(self.build_interval)
            resp, body = self.get_snapshot(snapshot_id)
            snapshot_status = body['status']
            if 'error' in snapshot_status:
                raise exceptions.\
                    SnapshotBuildErrorException(snapshot_id=snapshot_id)

            if int(time.time()) - start >= self.build_timeout:
                message = ('Share Snapshot %s failed to reach %s status '
                           'within the required time (%s s).' %
                           (snapshot_name, status, self.build_timeout))
                raise exceptions.TimeoutException(message)

    def wait_for_access_rule_status(self, share_id, rule_id, status):
        """Waits for a Share to reach a given status."""
        rule_status = "new"
        start = int(time.time())
        while rule_status != status:
            time.sleep(self.build_interval)
            resp, rules = self.list_access_rules(share_id)
            for rule in rules:
                if rule["id"] in rule_id:
                    rule_status = rule['state']
                    break
            if 'error' in rule_status:
                raise exceptions_shares.\
                    AccessRuleBuildErrorException(rule_id=rule_id)

            if int(time.time()) - start >= self.build_timeout:
                message = ('Share Access Rule %s failed to reach %s status '
                           'within the required time (%s s).' %
                           (rule_id, status, self.build_timeout))
                raise exceptions.TimeoutException(message)

    def default_quotas(self, tenant_id):
        uri = "os-quota-sets/%s/defaults" % tenant_id
        resp, body = self.get(uri, self.headers)
        return resp, self._parse_resp(body)

    def show_quotas(self, tenant_id, user_id=None):
        uri = "os-quota-sets/%s" % tenant_id
        if user_id is not None:
            uri += "?user_id=%s" % (user_id)
        resp, body = self.get(uri, self.headers)
        return resp, self._parse_resp(body)

    def reset_quotas(self, tenant_id, user_id=None):
        uri = "os-quota-sets/%s" % tenant_id
        if user_id is not None:
            uri += "?user_id=%s" % user_id
        resp, body = self.delete(uri, self.headers)
        return resp, self._parse_resp(body)

    def update_quotas(self, tenant_id, user_id=None,
                      shares=None, snapshots=None,
                      gigabytes=None, force=True):
        put_body = {"quota_set": {}}
        put_body["quota_set"]["tenant_id"] = tenant_id
        if force:
            put_body["quota_set"]["force"] = "true"
        if shares is not None:
            put_body["quota_set"]["shares"] = shares
        if snapshots is not None:
            put_body["quota_set"]["snapshots"] = snapshots
        if gigabytes is not None:
            put_body["quota_set"]["gigabytes"] = gigabytes
        put_body = json.dumps(put_body)
        uri = "os-quota-sets/%s" % tenant_id
        if user_id is not None:
            uri += "?user_id=%s" % user_id
        resp, body = self.put(uri, put_body, self.headers)
        return resp, self._parse_resp(body)

    def get_limits(self):
        resp, body = self.get("limits", self.headers)
        return resp, self._parse_resp(body)

    def is_resource_deleted(self, s_id, rule_id=None):
        if rule_id is None:
            try:
                self.get_snapshot(s_id)
            except exceptions.NotFound:
                try:
                    self.get_share(s_id)
                except exceptions.NotFound:
                    return True
            return False
        else:
            _, rules = self.list_share_access_rules(s_id)
            for rule in rules:
                if rule["id"] in rule_id:
                    return False
            return True

    def list_extensions(self):
        resp, extensions = self.get("extensions", self.headers)
        return resp, self._parse_resp(extensions)

    def rename(self, share_id, name, desc=None):
        uri = "shares/%s" % share_id
        body = {"share": {"display_name": name}}
        if desc is not None:
            body["share"].update({"display_description": desc})
        body = json.dumps(body)
        resp, body = self.put(uri, body, self.headers)
        return resp, self._parse_resp(body)

    def rename_snapshot(self, snapshot_id, name, desc=None):
        uri = "snapshots/%s" % snapshot_id
        body = {"snapshot": {"display_name": name}}
        if desc is not None:
            body["snapshot"].update({"display_description": desc})
        body = json.dumps(body)
        resp, body = self.put(uri, body, self.headers)
        return resp, self._parse_resp(body)

    def reset_state(self, s_id, status="error", s_type="shares"):
        """
        Resets the state of a share or a snapshot
        status: available, error, creating, deleting, error_deleting
        s_type: shares, snapshots
        """
        uri = "%s/%s/action" % (s_type, s_id)
        body = {"os-reset_status": {"status": status}}
        body = json.dumps(body)
        resp, body = self.post(uri, body, self.headers)
        return resp, self._parse_resp(body)

###############

    def _update_metadata(self, share_id, metadata={}, method="post"):
        uri = "shares/%s/metadata" % share_id
        post_body = {"metadata": metadata}
        body = json.dumps(post_body)
        if method is "post":
            resp, metadata = self.post(uri, body, self.headers)
        if method is "put":
            resp, metadata = self.put(uri, body, self.headers)
        return resp, self._parse_resp(metadata)

    def set_metadata(self, share_id, metadata={}):
        return self._update_metadata(share_id, metadata)

    def update_all_metadata(self, share_id, metadata={}):
        return self._update_metadata(share_id, metadata, method="put")

    def delete_metadata(self, share_id, key):
        uri = "shares/%s/metadata/%s" % (share_id, key)
        resp, body = self.delete(uri, self.headers)
        return resp, self._parse_resp(body)

    def get_metadata(self, share_id):
        uri = "shares/%s/metadata" % share_id
        resp, body = self.get(uri, self.headers)
        return resp, self._parse_resp(body)
