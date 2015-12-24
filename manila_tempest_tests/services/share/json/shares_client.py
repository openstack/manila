# Copyright 2014 Mirantis Inc.
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
import time

import six
from six.moves.urllib import parse as urlparse

from tempest import config  # noqa
from tempest_lib.common import rest_client
from tempest_lib.common.utils import data_utils
from tempest_lib import exceptions

from manila_tempest_tests import share_exceptions

CONF = config.CONF


class SharesClient(rest_client.RestClient):
    """Tempest REST client for Manila.

    It handles shares and access to it in OpenStack.
    """

    def __init__(self, auth_provider):
        super(SharesClient, self).__init__(
            auth_provider,
            CONF.share.catalog_type,
            CONF.share.region or CONF.identity.region,
            endpoint_type=CONF.share.endpoint_type)
        self.share_protocol = None
        if CONF.share.enable_protocols:
            self.share_protocol = CONF.share.enable_protocols[0]
        self.share_network_id = CONF.share.share_network_id
        self.build_interval = CONF.share.build_interval
        self.build_timeout = CONF.share.build_timeout

    def create_share(self, share_protocol=None, size=1,
                     name=None, snapshot_id=None, description=None,
                     metadata=None, share_network_id=None,
                     share_type_id=None, is_public=False):
        metadata = metadata or {}
        if name is None:
            name = data_utils.rand_name("tempest-created-share")
        if description is None:
            description = data_utils.rand_name("tempest-created-share-desc")
        if share_protocol is None:
            share_protocol = self.share_protocol
        if share_protocol is None:
            raise share_exceptions.ShareProtocolNotSpecified()
        post_body = {
            "share": {
                "share_proto": share_protocol,
                "description": description,
                "snapshot_id": snapshot_id,
                "name": name,
                "size": size,
                "metadata": metadata,
                "is_public": is_public,
            }
        }
        if share_network_id:
            post_body["share"]["share_network_id"] = share_network_id
        if share_type_id:
            post_body["share"]["share_type"] = share_type_id
        body = json.dumps(post_body)
        resp, body = self.post("shares", body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def delete_share(self, share_id):
        resp, body = self.delete("shares/%s" % share_id)
        self.expected_success(202, resp.status)
        return body

    def manage_share(self, service_host, protocol, export_path,
                     share_type_id, name=None, description=None):
        post_body = {
            "share": {
                "export_path": export_path,
                "service_host": service_host,
                "protocol": protocol,
                "share_type": share_type_id,
                "name": name,
                "description": description,
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post("os-share-manage", body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def unmanage_share(self, share_id):
        resp, body = self.post(
            "os-share-unmanage/%s/unmanage" % share_id, None)
        self.expected_success(202, resp.status)
        return body

    def list_shares(self, detailed=False, params=None):
        """Get list of shares w/o filters."""
        uri = 'shares/detail' if detailed else 'shares'
        uri += '?%s' % urlparse.urlencode(params) if params else ''
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_shares_with_detail(self, params=None):
        """Get detailed list of shares w/o filters."""
        return self.list_shares(detailed=True, params=params)

    def get_share(self, share_id):
        resp, body = self.get("shares/%s" % share_id)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def create_access_rule(self, share_id, access_type="ip",
                           access_to="0.0.0.0", access_level=None):
        post_body = {
            "os-allow_access": {
                "access_type": access_type,
                "access_to": access_to,
                "access_level": access_level,
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post("shares/%s/action" % share_id, body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_access_rules(self, share_id):
        body = {"os-access_list": None}
        resp, body = self.post("shares/%s/action" % share_id, json.dumps(body))
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def delete_access_rule(self, share_id, rule_id):
        post_body = {
            "os-deny_access": {
                "access_id": rule_id,
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post("shares/%s/action" % share_id, body)
        self.expected_success(202, resp.status)
        return body

    def extend_share(self, share_id, new_size):
        post_body = {
            "os-extend": {
                "new_size": new_size,
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post("shares/%s/action" % share_id, body)
        self.expected_success(202, resp.status)
        return body

    def shrink_share(self, share_id, new_size):
        post_body = {
            "os-shrink": {
                "new_size": new_size,
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post("shares/%s/action" % share_id, body)
        self.expected_success(202, resp.status)
        return body

    def create_snapshot(self, share_id, name=None, description=None,
                        force=False):
        if name is None:
            name = data_utils.rand_name("tempest-created-share-snap")
        if description is None:
            description = data_utils.rand_name(
                "tempest-created-share-snap-desc")
        post_body = {
            "snapshot": {
                "name": name,
                "force": force,
                "description": description,
                "share_id": share_id,
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post("snapshots", body)
        self.expected_success(202, resp.status)
        return self._parse_resp(body)

    def get_snapshot(self, snapshot_id):
        resp, body = self.get("snapshots/%s" % snapshot_id)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_snapshots(self, detailed=False, params=None):
        """Get list of share snapshots w/o filters."""
        uri = 'snapshots/detail' if detailed else 'snapshots'
        uri += '?%s' % urlparse.urlencode(params) if params else ''
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_snapshots_with_detail(self, params=None):
        """Get detailed list of share snapshots w/o filters."""
        return self.list_snapshots(detailed=True, params=params)

    def delete_snapshot(self, snap_id):
        resp, body = self.delete("snapshots/%s" % snap_id)
        self.expected_success(202, resp.status)
        return body

    def wait_for_share_status(self, share_id, status):
        """Waits for a share to reach a given status."""
        body = self.get_share(share_id)
        share_name = body['name']
        share_status = body['status']
        start = int(time.time())

        while share_status != status:
            time.sleep(self.build_interval)
            body = self.get_share(share_id)
            share_status = body['status']
            if share_status == status:
                return
            elif 'error' in share_status.lower():
                raise share_exceptions.\
                    ShareBuildErrorException(share_id=share_id)

            if int(time.time()) - start >= self.build_timeout:
                message = ('Share %s failed to reach %s status within '
                           'the required time (%s s).' %
                           (share_name, status, self.build_timeout))
                raise exceptions.TimeoutException(message)

    def wait_for_snapshot_status(self, snapshot_id, status):
        """Waits for a snapshot to reach a given status."""
        body = self.get_snapshot(snapshot_id)
        snapshot_name = body['name']
        snapshot_status = body['status']
        start = int(time.time())

        while snapshot_status != status:
            time.sleep(self.build_interval)
            body = self.get_snapshot(snapshot_id)
            snapshot_status = body['status']
            if 'error' in snapshot_status:
                raise share_exceptions.\
                    SnapshotBuildErrorException(snapshot_id=snapshot_id)

            if int(time.time()) - start >= self.build_timeout:
                message = ('Share Snapshot %s failed to reach %s status '
                           'within the required time (%s s).' %
                           (snapshot_name, status, self.build_timeout))
                raise exceptions.TimeoutException(message)

    def wait_for_access_rule_status(self, share_id, rule_id, status):
        """Waits for an access rule to reach a given status."""
        rule_status = "new"
        start = int(time.time())
        while rule_status != status:
            time.sleep(self.build_interval)
            rules = self.list_access_rules(share_id)
            for rule in rules:
                if rule["id"] in rule_id:
                    rule_status = rule['state']
                    break
            if 'error' in rule_status:
                raise share_exceptions.\
                    AccessRuleBuildErrorException(rule_id=rule_id)

            if int(time.time()) - start >= self.build_timeout:
                message = ('Share Access Rule %s failed to reach %s status '
                           'within the required time (%s s).' %
                           (rule_id, status, self.build_timeout))
                raise exceptions.TimeoutException(message)

    def default_quotas(self, tenant_id):
        resp, body = self.get("os-quota-sets/%s/defaults" % tenant_id)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def show_quotas(self, tenant_id, user_id=None):
        uri = "os-quota-sets/%s" % tenant_id
        if user_id is not None:
            uri += "?user_id=%s" % user_id
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def reset_quotas(self, tenant_id, user_id=None):
        uri = "os-quota-sets/%s" % tenant_id
        if user_id is not None:
            uri += "?user_id=%s" % user_id
        resp, body = self.delete(uri)
        self.expected_success(202, resp.status)
        return body

    def update_quotas(self, tenant_id, user_id=None, shares=None,
                      snapshots=None, gigabytes=None, snapshot_gigabytes=None,
                      share_networks=None, force=True):
        uri = "os-quota-sets/%s" % tenant_id
        if user_id is not None:
            uri += "?user_id=%s" % user_id

        put_body = {"tenant_id": tenant_id}
        if force:
            put_body["force"] = "true"
        if shares is not None:
            put_body["shares"] = shares
        if snapshots is not None:
            put_body["snapshots"] = snapshots
        if gigabytes is not None:
            put_body["gigabytes"] = gigabytes
        if snapshot_gigabytes is not None:
            put_body["snapshot_gigabytes"] = snapshot_gigabytes
        if share_networks is not None:
            put_body["share_networks"] = share_networks
        put_body = json.dumps({"quota_set": put_body})

        resp, body = self.put(uri, put_body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def get_limits(self):
        resp, body = self.get("limits")
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def is_resource_deleted(self, *args, **kwargs):
        """Verifies whether provided resource deleted or not.

        :param kwargs: dict with expected keys 'share_id', 'snapshot_id',
        :param kwargs: 'sn_id', 'ss_id', 'vt_id' and 'server_id'
        :raises share_exceptions.InvalidResource
        """
        if "share_id" in kwargs:
            if "rule_id" in kwargs:
                rule_id = kwargs.get("rule_id")
                share_id = kwargs.get("share_id")
                rules = self.list_access_rules(share_id)
                for rule in rules:
                    if rule["id"] == rule_id:
                        return False
                return True
            else:
                return self._is_resource_deleted(
                    self.get_share, kwargs.get("share_id"))
        elif "snapshot_id" in kwargs:
            return self._is_resource_deleted(
                self.get_snapshot, kwargs.get("snapshot_id"))
        elif "sn_id" in kwargs:
            return self._is_resource_deleted(
                self.get_share_network, kwargs.get("sn_id"))
        elif "ss_id" in kwargs:
            return self._is_resource_deleted(
                self.get_security_service, kwargs.get("ss_id"))
        elif "vt_id" in kwargs:
            return self._is_resource_deleted(
                self.get_volume_type, kwargs.get("vt_id"))
        elif "st_id" in kwargs:
            return self._is_resource_deleted(
                self.get_share_type, kwargs.get("st_id"))
        elif "server_id" in kwargs:
            return self._is_resource_deleted(
                self.show_share_server, kwargs.get("server_id"))
        else:
            raise share_exceptions.InvalidResource(
                message=six.text_type(kwargs))

    def _is_resource_deleted(self, func, res_id):
        try:
            res = func(res_id)
        except exceptions.NotFound:
            return True
        if res.get('status') in ['error_deleting', 'error']:
            # Resource has "error_deleting" status and can not be deleted.
            resource_type = func.__name__.split('_', 1)[-1]
            raise share_exceptions.ResourceReleaseFailed(
                res_type=resource_type, res_id=res_id)
        return False

    def wait_for_resource_deletion(self, *args, **kwargs):
        """Waits for a resource to be deleted."""
        start_time = int(time.time())
        while True:
            if self.is_resource_deleted(*args, **kwargs):
                return
            if int(time.time()) - start_time >= self.build_timeout:
                raise exceptions.TimeoutException
            time.sleep(self.build_interval)

    def list_extensions(self):
        resp, extensions = self.get("extensions")
        self.expected_success(200, resp.status)
        return self._parse_resp(extensions)

    def update_share(self, share_id, name=None, desc=None, is_public=None):
        body = {"share": {}}
        if name is not None:
            body["share"].update({"display_name": name})
        if desc is not None:
            body["share"].update({"display_description": desc})
        if is_public is not None:
            body["share"].update({"is_public": is_public})
        body = json.dumps(body)
        resp, body = self.put("shares/%s" % share_id, body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def rename_snapshot(self, snapshot_id, name, desc=None):
        body = {"snapshot": {"display_name": name}}
        if desc is not None:
            body["snapshot"].update({"display_description": desc})
        body = json.dumps(body)
        resp, body = self.put("snapshots/%s" % snapshot_id, body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def reset_state(self, s_id, status="error", s_type="shares"):
        """Resets the state of a share or a snapshot.

        status: available, error, creating, deleting, error_deleting
        s_type: shares, snapshots
        """
        body = {"os-reset_status": {"status": status}}
        body = json.dumps(body)
        resp, body = self.post("%s/%s/action" % (s_type, s_id), body)
        self.expected_success(202, resp.status)
        return body

    def force_delete(self, s_id, s_type="shares"):
        """Force delete share or snapshot.

        s_type: shares, snapshots
        """
        body = {"os-force_delete": None}
        body = json.dumps(body)
        resp, body = self.post("%s/%s/action" % (s_type, s_id), body)
        self.expected_success(202, resp.status)
        return body

###############

    def list_services(self, params=None):
        """List services."""
        uri = 'os-services'
        if params:
            uri += '?%s' % urlparse.urlencode(params)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

###############

    def _update_metadata(self, share_id, metadata=None, method="post"):
        uri = "shares/%s/metadata" % share_id
        if metadata is None:
            metadata = {}
        post_body = {"metadata": metadata}
        body = json.dumps(post_body)
        if method is "post":
            resp, metadata = self.post(uri, body)
        if method is "put":
            resp, metadata = self.put(uri, body)
        self.expected_success(200, resp.status)
        return self._parse_resp(metadata)

    def set_metadata(self, share_id, metadata=None):
        return self._update_metadata(share_id, metadata)

    def update_all_metadata(self, share_id, metadata=None):
        return self._update_metadata(share_id, metadata, method="put")

    def delete_metadata(self, share_id, key):
        resp, body = self.delete("shares/%s/metadata/%s" % (share_id, key))
        self.expected_success(200, resp.status)
        return body

    def get_metadata(self, share_id):
        resp, body = self.get("shares/%s/metadata" % share_id)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

###############

    def create_security_service(self, ss_type="ldap", **kwargs):
        # ss_type: ldap, kerberos, active_directory
        # kwargs: name, description, dns_ip, server, domain, user, password
        post_body = {"type": ss_type}
        post_body.update(kwargs)
        body = json.dumps({"security_service": post_body})
        resp, body = self.post("security-services", body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def update_security_service(self, ss_id, **kwargs):
        # ss_id - id of security-service entity
        # kwargs: dns_ip, server, domain, user, password, name, description
        # for 'active' status can be changed
        # only 'name' and 'description' fields
        body = json.dumps({"security_service": kwargs})
        resp, body = self.put("security-services/%s" % ss_id, body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def get_security_service(self, ss_id):
        resp, body = self.get("security-services/%s" % ss_id)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_security_services(self, detailed=False, params=None):
        uri = "security-services"
        if detailed:
            uri += '/detail'
        if params:
            uri += "?%s" % urlparse.urlencode(params)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def delete_security_service(self, ss_id):
        resp, body = self.delete("security-services/%s" % ss_id)
        self.expected_success(202, resp.status)
        return body

###############

    def create_share_network(self, **kwargs):
        # kwargs: name, description
        # + for neutron: neutron_net_id, neutron_subnet_id
        body = json.dumps({"share_network": kwargs})
        resp, body = self.post("share-networks", body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def update_share_network(self, sn_id, **kwargs):
        # kwargs: name, description
        # + for neutron: neutron_net_id, neutron_subnet_id
        body = json.dumps({"share_network": kwargs})
        resp, body = self.put("share-networks/%s" % sn_id, body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def get_share_network(self, sn_id):
        resp, body = self.get("share-networks/%s" % sn_id)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_share_networks(self):
        resp, body = self.get("share-networks")
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_share_networks_with_detail(self, params=None):
        """List the details of all shares."""
        uri = "share-networks/detail"
        if params:
            uri += "?%s" % urlparse.urlencode(params)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def delete_share_network(self, sn_id):
        resp, body = self.delete("share-networks/%s" % sn_id)
        self.expected_success(202, resp.status)
        return body

###############

    def _map_security_service_and_share_network(self, sn_id, ss_id,
                                                action="add"):
        # sn_id: id of share_network_entity
        # ss_id: id of security service entity
        # action: add, remove
        data = {
            "%s_security_service" % action: {
                "security_service_id": ss_id,
            }
        }
        body = json.dumps(data)
        resp, body = self.post("share-networks/%s/action" % sn_id, body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def add_sec_service_to_share_network(self, sn_id, ss_id):
        body = self._map_security_service_and_share_network(sn_id, ss_id)
        return body

    def remove_sec_service_from_share_network(self, sn_id, ss_id):
        body = self._map_security_service_and_share_network(
            sn_id, ss_id, "remove")
        return body

    def list_sec_services_for_share_network(self, sn_id):
        resp, body = self.get("security-services?share_network_id=%s" % sn_id)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

###############

    def list_share_types(self, params=None):
        uri = 'types'
        if params is not None:
            uri += '?%s' % urlparse.urlencode(params)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def create_share_type(self, name, is_public=True, **kwargs):
        post_body = {
            'name': name,
            'extra_specs': kwargs.get('extra_specs'),
            'os-share-type-access:is_public': is_public,
        }
        post_body = json.dumps({'share_type': post_body})
        resp, body = self.post('types', post_body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def delete_share_type(self, share_type_id):
        resp, body = self.delete("types/%s" % share_type_id)
        self.expected_success(202, resp.status)
        return body

    def get_share_type(self, share_type_id):
        resp, body = self.get("types/%s" % share_type_id)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def add_access_to_share_type(self, share_type_id, project_id):
        uri = 'types/%s/action' % share_type_id
        post_body = {'project': project_id}
        post_body = json.dumps({'addProjectAccess': post_body})
        resp, body = self.post(uri, post_body)
        self.expected_success(202, resp.status)
        return body

    def remove_access_from_share_type(self, share_type_id, project_id):
        uri = 'types/%s/action' % share_type_id
        post_body = {'project': project_id}
        post_body = json.dumps({'removeProjectAccess': post_body})
        resp, body = self.post(uri, post_body)
        self.expected_success(202, resp.status)
        return body

    def list_access_to_share_type(self, share_type_id):
        uri = 'types/%s/os-share-type-access' % share_type_id
        resp, body = self.get(uri)
        # [{"share_type_id": "%st_id%", "project_id": "%project_id%"}, ]
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

###############

    def create_share_type_extra_specs(self, share_type_id, extra_specs):
        url = "types/%s/extra_specs" % share_type_id
        post_body = json.dumps({'extra_specs': extra_specs})
        resp, body = self.post(url, post_body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def get_share_type_extra_spec(self, share_type_id, extra_spec_name):
        uri = "types/%s/extra_specs/%s" % (share_type_id, extra_spec_name)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def get_share_type_extra_specs(self, share_type_id, params=None):
        uri = "types/%s/extra_specs" % share_type_id
        if params is not None:
            uri += '?%s' % urlparse.urlencode(params)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def update_share_type_extra_spec(self, share_type_id, spec_name,
                                     spec_value):
        uri = "types/%s/extra_specs/%s" % (share_type_id, spec_name)
        extra_spec = {spec_name: spec_value}
        post_body = json.dumps(extra_spec)
        resp, body = self.put(uri, post_body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def update_share_type_extra_specs(self, share_type_id, extra_specs):
        uri = "types/%s/extra_specs" % share_type_id
        extra_specs = {"extra_specs": extra_specs}
        post_body = json.dumps(extra_specs)
        resp, body = self.post(uri, post_body)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def delete_share_type_extra_spec(self, share_type_id, extra_spec_name):
        uri = "types/%s/extra_specs/%s" % (share_type_id, extra_spec_name)
        resp, body = self.delete(uri)
        self.expected_success(202, resp.status)
        return body

###############

    def list_share_servers(self, search_opts=None):
        """Get list of share servers."""
        uri = "share-servers"
        if search_opts:
            uri += "?%s" % urlparse.urlencode(search_opts)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def delete_share_server(self, share_server_id):
        """Delete share server by its ID."""
        uri = "share-servers/%s" % share_server_id
        resp, body = self.delete(uri)
        self.expected_success(202, resp.status)
        return body

    def show_share_server(self, share_server_id):
        """Get share server info."""
        uri = "share-servers/%s" % share_server_id
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def show_share_server_details(self, share_server_id):
        """Get share server details only."""
        uri = "share-servers/%s/details" % share_server_id
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

###############

    def list_pools(self, detail=False, search_opts=None):
        """Get list of scheduler pools."""
        uri = 'scheduler-stats/pools'
        if detail:
            uri += '/detail'
        if search_opts:
            uri += "?%s" % urlparse.urlencode(search_opts)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return json.loads(body)

###############

    def list_availability_zones(self):
        """Get list of availability zones."""
        uri = 'os-availability-zone'
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)
