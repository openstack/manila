# Copyright 2015 Andrew Kerr
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

from six.moves.urllib import parse as urlparse
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from manila_tempest_tests.common import constants
from manila_tempest_tests.services.share.json import shares_client
from manila_tempest_tests import share_exceptions
from manila_tempest_tests import utils

CONF = config.CONF
LATEST_MICROVERSION = CONF.share.max_api_microversion
EXPERIMENTAL = {'X-OpenStack-Manila-API-Experimental': 'True'}


class SharesV2Client(shares_client.SharesClient):
    """Tempest REST client for Manila.

    It handles shares and access to it in OpenStack.
    """
    api_version = 'v2'

    def __init__(self, auth_provider):
        super(SharesV2Client, self).__init__(auth_provider)
        self.API_MICROVERSIONS_HEADER = 'x-openstack-manila-api-version'

    def inject_microversion_header(self, headers, version,
                                   extra_headers=False):
        """Inject the required manila microversion header."""
        new_headers = self.get_headers()
        new_headers[self.API_MICROVERSIONS_HEADER] = version
        if extra_headers and headers:
            new_headers.update(headers)
        elif headers:
            new_headers = headers
        return new_headers

    # Overwrite all http verb calls to inject the micro version header
    def post(self, url, body, headers=None, extra_headers=False,
             version=LATEST_MICROVERSION):
        headers = self.inject_microversion_header(headers, version,
                                                  extra_headers=extra_headers)
        return super(SharesV2Client, self).post(url, body, headers=headers)

    def get(self, url, headers=None, extra_headers=False,
            version=LATEST_MICROVERSION):
        headers = self.inject_microversion_header(headers, version,
                                                  extra_headers=extra_headers)
        return super(SharesV2Client, self).get(url, headers=headers)

    def delete(self, url, headers=None, body=None, extra_headers=False,
               version=LATEST_MICROVERSION):
        headers = self.inject_microversion_header(headers, version,
                                                  extra_headers=extra_headers)
        return super(SharesV2Client, self).delete(url, headers=headers,
                                                  body=body)

    def patch(self, url, body, headers=None, extra_headers=False,
              version=LATEST_MICROVERSION):
        headers = self.inject_microversion_header(headers, version,
                                                  extra_headers=extra_headers)
        return super(SharesV2Client, self).patch(url, body, headers=headers)

    def put(self, url, body, headers=None, extra_headers=False,
            version=LATEST_MICROVERSION):
        headers = self.inject_microversion_header(headers, version,
                                                  extra_headers=extra_headers)
        return super(SharesV2Client, self).put(url, body, headers=headers)

    def head(self, url, headers=None, extra_headers=False,
             version=LATEST_MICROVERSION):
        headers = self.inject_microversion_header(headers, version,
                                                  extra_headers=extra_headers)
        return super(SharesV2Client, self).head(url, headers=headers)

    def copy(self, url, headers=None, extra_headers=False,
             version=LATEST_MICROVERSION):
        headers = self.inject_microversion_header(headers, version,
                                                  extra_headers=extra_headers)
        return super(SharesV2Client, self).copy(url, headers=headers)

    def reset_state(self, s_id, status="error", s_type="shares",
                    headers=None, version=LATEST_MICROVERSION,
                    action_name=None):
        """Resets the state of a share, snapshot, cg, or a cgsnapshot.

        status: available, error, creating, deleting, error_deleting
        s_type: shares, share_instances, snapshots, consistency-groups,
            cgsnapshots.
        """
        if action_name is None:
            if utils.is_microversion_gt(version, "2.6"):
                action_name = 'reset_status'
            else:
                action_name = 'os-reset_status'
        body = {action_name: {"status": status}}
        body = json.dumps(body)
        resp, body = self.post("%s/%s/action" % (s_type, s_id), body,
                               headers=headers, extra_headers=True,
                               version=version)
        self.expected_success(202, resp.status)
        return body

    def force_delete(self, s_id, s_type="shares", headers=None,
                     version=LATEST_MICROVERSION, action_name=None):
        """Force delete share or snapshot.

        s_type: shares, snapshots
        """
        if action_name is None:
            if utils.is_microversion_gt(version, "2.6"):
                action_name = 'force_delete'
            else:
                action_name = 'os-force_delete'
        body = {action_name: None}
        body = json.dumps(body)
        resp, body = self.post("%s/%s/action" % (s_type, s_id), body,
                               headers=headers, extra_headers=True,
                               version=version)
        self.expected_success(202, resp.status)
        return body

    def send_microversion_request(self, version=None, script_name=None):
        """Prepare and send the HTTP GET Request to the base URL.

        Extracts the base URL from the shares_client endpoint and makes a GET
        request with the microversions request header.
        :param version: The string to send for the value of the microversion
                        header, or None to omit the header.
        :param script_name: The first part of the URL (v1 or v2), or None to
                            omit it.
        """

        headers = self.get_headers()
        url, headers, body = self.auth_provider.auth_request(
            'GET', 'shares', headers, None, self.filters)
        url = '/'.join(url.split('/')[:3]) + '/'
        if script_name:
            url += script_name + '/'
        if version:
            headers[self.API_MICROVERSIONS_HEADER] = version
        resp, resp_body = self.raw_request(url, 'GET', headers=headers)
        self.response_checker('GET', resp, resp_body)
        resp_body = json.loads(resp_body)
        return resp, resp_body

    def is_resource_deleted(self, *args, **kwargs):
        """Verifies whether provided resource deleted or not.

        :param kwargs: dict with expected keys 'share_id', 'snapshot_id',
        :param kwargs: 'sn_id', 'ss_id', 'vt_id' and 'server_id'
        :raises share_exceptions.InvalidResource
        """
        if "share_instance_id" in kwargs:
            return self._is_resource_deleted(
                self.get_share_instance, kwargs.get("share_instance_id"))
        elif "cg_id" in kwargs:
            return self._is_resource_deleted(
                self.get_consistency_group, kwargs.get("cg_id"))
        elif "cgsnapshot_id" in kwargs:
            return self._is_resource_deleted(
                self.get_cgsnapshot, kwargs.get("cgsnapshot_id"))
        elif "replica_id" in kwargs:
            return self._is_resource_deleted(
                self.get_share_replica, kwargs.get("replica_id"))
        else:
            return super(SharesV2Client, self).is_resource_deleted(
                *args, **kwargs)

###############

    def create_share(self, share_protocol=None, size=1,
                     name=None, snapshot_id=None, description=None,
                     metadata=None, share_network_id=None,
                     share_type_id=None, is_public=False,
                     consistency_group_id=None, availability_zone=None,
                     version=LATEST_MICROVERSION):
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
        if availability_zone:
            post_body["share"]["availability_zone"] = availability_zone
        if share_network_id:
            post_body["share"]["share_network_id"] = share_network_id
        if share_type_id:
            post_body["share"]["share_type"] = share_type_id
        if consistency_group_id:
            post_body["share"]["consistency_group_id"] = consistency_group_id
        body = json.dumps(post_body)
        resp, body = self.post("shares", body, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_shares(self, detailed=False, params=None,
                    version=LATEST_MICROVERSION):
        """Get list of shares w/o filters."""
        uri = 'shares/detail' if detailed else 'shares'
        uri += '?%s' % urlparse.urlencode(params) if params else ''
        resp, body = self.get(uri, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_shares_with_detail(self, params=None,
                                version=LATEST_MICROVERSION):
        """Get detailed list of shares w/o filters."""
        return self.list_shares(detailed=True, params=params, version=version)

    def get_share(self, share_id, version=LATEST_MICROVERSION):
        resp, body = self.get("shares/%s" % share_id, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def get_share_export_location(
            self, share_id, export_location_uuid, version=LATEST_MICROVERSION):
        resp, body = self.get(
            "shares/%(share_id)s/export_locations/%(el_uuid)s" % {
                "share_id": share_id, "el_uuid": export_location_uuid},
            version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_share_export_locations(
            self, share_id, version=LATEST_MICROVERSION):
        resp, body = self.get(
            "shares/%(share_id)s/export_locations" % {"share_id": share_id},
            version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def delete_share(self, share_id, params=None,
                     version=LATEST_MICROVERSION):
        uri = "shares/%s" % share_id
        uri += '?%s' % (urlparse.urlencode(params) if params else '')
        resp, body = self.delete(uri, version=version)
        self.expected_success(202, resp.status)
        return body

###############

    def get_instances_of_share(self, share_id, version=LATEST_MICROVERSION):
        resp, body = self.get("shares/%s/instances" % share_id,
                              version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_share_instances(self, version=LATEST_MICROVERSION):
        resp, body = self.get("share_instances", version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def get_share_instance(self, instance_id, version=LATEST_MICROVERSION):
        resp, body = self.get("share_instances/%s" % instance_id,
                              version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def get_share_instance_export_location(
            self, instance_id, export_location_uuid,
            version=LATEST_MICROVERSION):
        resp, body = self.get(
            "share_instances/%(instance_id)s/export_locations/%(el_uuid)s" % {
                "instance_id": instance_id, "el_uuid": export_location_uuid},
            version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_share_instance_export_locations(
            self, instance_id, version=LATEST_MICROVERSION):
        resp, body = self.get(
            "share_instances/%s/export_locations" % instance_id,
            version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def wait_for_share_instance_status(self, instance_id, status,
                                       version=LATEST_MICROVERSION):
        """Waits for a share to reach a given status."""
        body = self.get_share_instance(instance_id, version=version)
        instance_status = body['status']
        start = int(time.time())

        while instance_status != status:
            time.sleep(self.build_interval)
            body = self.get_share(instance_id)
            instance_status = body['status']
            if instance_status == status:
                return
            elif 'error' in instance_status.lower():
                raise share_exceptions. \
                    ShareInstanceBuildErrorException(id=instance_id)

            if int(time.time()) - start >= self.build_timeout:
                message = ('Share instance %s failed to reach %s status within'
                           ' the required time (%s s).' %
                           (instance_id, status, self.build_timeout))
                raise exceptions.TimeoutException(message)

    def wait_for_share_status(self, share_id, status, status_attr='status',
                              version=LATEST_MICROVERSION):
        """Waits for a share to reach a given status."""
        body = self.get_share(share_id, version=version)
        share_status = body[status_attr]
        start = int(time.time())

        while share_status != status:
            time.sleep(self.build_interval)
            body = self.get_share(share_id, version=version)
            share_status = body[status_attr]
            if share_status == status:
                return
            elif 'error' in share_status.lower():
                raise share_exceptions.ShareBuildErrorException(
                    share_id=share_id)

            if int(time.time()) - start >= self.build_timeout:
                message = ("Share's %(status_attr)s failed to transition to "
                           "%(status)s within the required time %(seconds)s." %
                           {"status_attr": status_attr, "status": status,
                            "seconds": self.build_timeout})
                raise exceptions.TimeoutException(message)

###############

    def extend_share(self, share_id, new_size, version=LATEST_MICROVERSION,
                     action_name=None):
        if action_name is None:
            if utils.is_microversion_gt(version, "2.6"):
                action_name = 'extend'
            else:
                action_name = 'os-extend'
        post_body = {
            action_name: {
                "new_size": new_size,
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post(
            "shares/%s/action" % share_id, body, version=version)
        self.expected_success(202, resp.status)
        return body

    def shrink_share(self, share_id, new_size, version=LATEST_MICROVERSION,
                     action_name=None):
        if action_name is None:
            if utils.is_microversion_gt(version, "2.6"):
                action_name = 'shrink'
            else:
                action_name = 'os-shrink'
        post_body = {
            action_name: {
                "new_size": new_size,
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post(
            "shares/%s/action" % share_id, body, version=version)
        self.expected_success(202, resp.status)
        return body

###############

    def manage_share(self, service_host, protocol, export_path,
                     share_type_id, name=None, description=None,
                     is_public=False, version=LATEST_MICROVERSION,
                     url=None):
        post_body = {
            "share": {
                "export_path": export_path,
                "service_host": service_host,
                "protocol": protocol,
                "share_type": share_type_id,
                "name": name,
                "description": description,
                "is_public": is_public,
            }
        }
        if url is None:
            if utils.is_microversion_gt(version, "2.6"):
                url = 'shares/manage'
            else:
                url = 'os-share-manage'
        body = json.dumps(post_body)
        resp, body = self.post(url, body, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def unmanage_share(self, share_id, version=LATEST_MICROVERSION, url=None,
                       action_name=None, body=None):
        if url is None:
            if utils.is_microversion_gt(version, "2.6"):
                url = 'shares'
            else:
                url = 'os-share-unmanage'
        if action_name is None:
            if utils.is_microversion_gt(version, "2.6"):
                action_name = 'action'
            else:
                action_name = 'unmanage'
        if body is None and utils.is_microversion_gt(version, "2.6"):
            body = json.dumps({'unmanage': {}})
        resp, body = self.post(
            "%(url)s/%(share_id)s/%(action_name)s" % {
                'url': url, 'share_id': share_id, 'action_name': action_name},
            body,
            version=version)
        self.expected_success(202, resp.status)
        return body

###############

    def create_snapshot(self, share_id, name=None, description=None,
                        force=False, version=LATEST_MICROVERSION):
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
        resp, body = self.post("snapshots", body, version=version)
        self.expected_success(202, resp.status)
        return self._parse_resp(body)

    def get_snapshot(self, snapshot_id, version=LATEST_MICROVERSION):
        resp, body = self.get("snapshots/%s" % snapshot_id, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_snapshots(self, detailed=False, params=None,
                       version=LATEST_MICROVERSION):
        """Get list of share snapshots w/o filters."""
        uri = 'snapshots/detail' if detailed else 'snapshots'
        uri += '?%s' % urlparse.urlencode(params) if params else ''
        resp, body = self.get(uri, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_snapshots_with_detail(self, params=None,
                                   version=LATEST_MICROVERSION):
        """Get detailed list of share snapshots w/o filters."""
        return self.list_snapshots(detailed=True, params=params,
                                   version=version)

    def delete_snapshot(self, snap_id, version=LATEST_MICROVERSION):
        resp, body = self.delete("snapshots/%s" % snap_id, version=version)
        self.expected_success(202, resp.status)
        return body

    def wait_for_snapshot_status(self, snapshot_id, status,
                                 version=LATEST_MICROVERSION):
        """Waits for a snapshot to reach a given status."""
        body = self.get_snapshot(snapshot_id, version=version)
        snapshot_name = body['name']
        snapshot_status = body['status']
        start = int(time.time())

        while snapshot_status != status:
            time.sleep(self.build_interval)
            body = self.get_snapshot(snapshot_id, version=version)
            snapshot_status = body['status']
            if 'error' in snapshot_status:
                raise (share_exceptions.
                       SnapshotBuildErrorException(snapshot_id=snapshot_id))

            if int(time.time()) - start >= self.build_timeout:
                message = ('Share Snapshot %s failed to reach %s status '
                           'within the required time (%s s).' %
                           (snapshot_name, status, self.build_timeout))
                raise exceptions.TimeoutException(message)

    def manage_snapshot(self, share_id, provider_location,
                        name=None, description=None,
                        version=LATEST_MICROVERSION,
                        driver_options=None):
        if name is None:
            name = data_utils.rand_name("tempest-manage-snapshot")
        if description is None:
            description = data_utils.rand_name("tempest-manage-snapshot-desc")
        post_body = {
            "snapshot": {
                "share_id": share_id,
                "provider_location": provider_location,
                "name": name,
                "description": description,
                "driver_options": driver_options if driver_options else {},
            }
        }
        url = 'snapshots/manage'
        body = json.dumps(post_body)
        resp, body = self.post(url, body, version=version)
        self.expected_success(202, resp.status)
        return self._parse_resp(body)

    def unmanage_snapshot(self, snapshot_id, version=LATEST_MICROVERSION,
                          body=None):
        url = 'snapshots'
        action_name = 'action'
        if body is None:
            body = json.dumps({'unmanage': {}})
        resp, body = self.post(
            "%(url)s/%(snapshot_id)s/%(action_name)s" % {
                'url': url, 'snapshot_id': snapshot_id,
                'action_name': action_name},
            body,
            version=version)
        self.expected_success(202, resp.status)
        return body

###############

    def _get_access_action_name(self, version, action):
        if utils.is_microversion_gt(version, "2.6"):
            return action.split('os-')[-1]
        return action

    def create_access_rule(self, share_id, access_type="ip",
                           access_to="0.0.0.0", access_level=None,
                           version=LATEST_MICROVERSION, action_name=None):
        post_body = {
            self._get_access_action_name(version, 'os-allow_access'): {
                "access_type": access_type,
                "access_to": access_to,
                "access_level": access_level,
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post(
            "shares/%s/action" % share_id, body, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_access_rules(self, share_id, version=LATEST_MICROVERSION,
                          action_name=None):
        body = {self._get_access_action_name(version, 'os-access_list'): None}
        resp, body = self.post(
            "shares/%s/action" % share_id, json.dumps(body), version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def delete_access_rule(self, share_id, rule_id,
                           version=LATEST_MICROVERSION, action_name=None):
        post_body = {
            self._get_access_action_name(version, 'os-deny_access'): {
                "access_id": rule_id,
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post(
            "shares/%s/action" % share_id, body, version=version)
        self.expected_success(202, resp.status)
        return body

###############

    def list_availability_zones(self, url='availability-zones',
                                version=LATEST_MICROVERSION):
        """Get list of availability zones."""
        if url is None:
            if utils.is_microversion_gt(version, "2.6"):
                url = 'availability-zones'
            else:
                url = 'os-availability-zone'
        resp, body = self.get(url, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

###############

    def list_services(self, params=None, url=None,
                      version=LATEST_MICROVERSION):
        """List services."""
        if url is None:
            if utils.is_microversion_gt(version, "2.6"):
                url = 'services'
            else:
                url = 'os-services'
        if params:
            url += '?%s' % urlparse.urlencode(params)
        resp, body = self.get(url, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

###############

    def list_share_types(self, params=None, version=LATEST_MICROVERSION):
        uri = 'types'
        if params is not None:
            uri += '?%s' % urlparse.urlencode(params)
        resp, body = self.get(uri, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def create_share_type(self, name, is_public=True,
                          version=LATEST_MICROVERSION, **kwargs):
        if utils.is_microversion_gt(version, "2.6"):
            is_public_keyname = 'share_type_access:is_public'
        else:
            is_public_keyname = 'os-share-type-access:is_public'
        post_body = {
            'name': name,
            'extra_specs': kwargs.get('extra_specs'),
            is_public_keyname: is_public,
        }
        post_body = json.dumps({'share_type': post_body})
        resp, body = self.post('types', post_body, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def delete_share_type(self, share_type_id, version=LATEST_MICROVERSION):
        resp, body = self.delete("types/%s" % share_type_id, version=version)
        self.expected_success(202, resp.status)
        return body

    def get_share_type(self, share_type_id, version=LATEST_MICROVERSION):
        resp, body = self.get("types/%s" % share_type_id, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_access_to_share_type(self, share_type_id,
                                  version=LATEST_MICROVERSION,
                                  action_name=None):
        if action_name is None:
            if utils.is_microversion_gt(version, "2.6"):
                action_name = 'share_type_access'
            else:
                action_name = 'os-share-type-access'
        url = 'types/%(st_id)s/%(action_name)s' % {
            'st_id': share_type_id, 'action_name': action_name}
        resp, body = self.get(url, version=version)
        # [{"share_type_id": "%st_id%", "project_id": "%project_id%"}, ]
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

###############

    def _get_quotas_url(self, version):
        if utils.is_microversion_gt(version, "2.6"):
            return 'quota-sets'
        return 'os-quota-sets'

    def default_quotas(self, tenant_id, url=None, version=LATEST_MICROVERSION):
        if url is None:
            url = self._get_quotas_url(version)
        url += '/%s' % tenant_id
        resp, body = self.get("%s/defaults" % url, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def show_quotas(self, tenant_id, user_id=None, url=None,
                    version=LATEST_MICROVERSION):
        if url is None:
            url = self._get_quotas_url(version)
        url += '/%s' % tenant_id
        if user_id is not None:
            url += "?user_id=%s" % user_id
        resp, body = self.get(url, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def reset_quotas(self, tenant_id, user_id=None, url=None,
                     version=LATEST_MICROVERSION):
        if url is None:
            url = self._get_quotas_url(version)
        url += '/%s' % tenant_id
        if user_id is not None:
            url += "?user_id=%s" % user_id
        resp, body = self.delete(url, version=version)
        self.expected_success(202, resp.status)
        return body

    def update_quotas(self, tenant_id, user_id=None, shares=None,
                      snapshots=None, gigabytes=None, snapshot_gigabytes=None,
                      share_networks=None, force=True, url=None,
                      version=LATEST_MICROVERSION):
        if url is None:
            url = self._get_quotas_url(version)
        url += '/%s' % tenant_id
        if user_id is not None:
            url += "?user_id=%s" % user_id

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

        resp, body = self.put(url, put_body, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

###############

    def create_consistency_group(self, name=None, description=None,
                                 share_type_ids=(), share_network_id=None,
                                 source_cgsnapshot_id=None,
                                 version=LATEST_MICROVERSION):
        """Create a new consistency group."""
        uri = 'consistency-groups'
        post_body = {}
        if name:
            post_body['name'] = name
        if description:
            post_body['description'] = description
        if share_type_ids:
            post_body['share_types'] = share_type_ids
        if source_cgsnapshot_id:
            post_body['source_cgsnapshot_id'] = source_cgsnapshot_id
        if share_network_id:
            post_body['share_network_id'] = share_network_id
        body = json.dumps({'consistency_group': post_body})
        resp, body = self.post(uri, body, headers=EXPERIMENTAL,
                               extra_headers=True, version=version)
        self.expected_success(202, resp.status)
        return self._parse_resp(body)

    def delete_consistency_group(self, consistency_group_id,
                                 version=LATEST_MICROVERSION):
        """Delete a consistency group."""
        uri = 'consistency-groups/%s' % consistency_group_id
        resp, body = self.delete(uri, headers=EXPERIMENTAL,
                                 extra_headers=True, version=version)
        self.expected_success(202, resp.status)
        return body

    def list_consistency_groups(self, detailed=False, params=None,
                                version=LATEST_MICROVERSION):
        """Get list of consistency groups w/o filters."""
        uri = 'consistency-groups%s' % ('/detail' if detailed else '')
        uri += '?%s' % (urlparse.urlencode(params) if params else '')
        resp, body = self.get(uri, headers=EXPERIMENTAL, extra_headers=True,
                              version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def get_consistency_group(self, consistency_group_id,
                              version=LATEST_MICROVERSION):
        """Get consistency group info."""
        uri = 'consistency-groups/%s' % consistency_group_id
        resp, body = self.get(uri, headers=EXPERIMENTAL, extra_headers=True,
                              version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def update_consistency_group(self, consistency_group_id, name=None,
                                 description=None,
                                 version=LATEST_MICROVERSION, **kwargs):
        """Update an existing consistency group."""
        uri = 'consistency-groups/%s' % consistency_group_id
        post_body = {}
        if name:
            post_body['name'] = name
        if description:
            post_body['description'] = description
        if kwargs:
            post_body.update(kwargs)
        body = json.dumps({'consistency_group': post_body})
        resp, body = self.put(uri, body, headers=EXPERIMENTAL,
                              extra_headers=True, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def consistency_group_reset_state(self, id, status,
                                      version=LATEST_MICROVERSION):
        self.reset_state(id, status=status,
                         s_type='consistency-groups', headers=EXPERIMENTAL,
                         version=version)

    def consistency_group_force_delete(self, id, version=LATEST_MICROVERSION):
        self.force_delete(id, s_type='consistency-groups',
                          headers=EXPERIMENTAL, version=version)

    def wait_for_consistency_group_status(self, consistency_group_id, status):
        """Waits for a consistency group to reach a given status."""
        body = self.get_consistency_group(consistency_group_id)
        consistency_group_name = body['name']
        consistency_group_status = body['status']
        start = int(time.time())

        while consistency_group_status != status:
            time.sleep(self.build_interval)
            body = self.get_consistency_group(consistency_group_id)
            consistency_group_status = body['status']
            if 'error' in consistency_group_status and status != 'error':
                raise share_exceptions.ConsistencyGroupBuildErrorException(
                    consistency_group_id=consistency_group_id)

            if int(time.time()) - start >= self.build_timeout:
                consistency_group_name = (
                    consistency_group_name if consistency_group_name else
                    consistency_group_id
                )
                message = ('Consistency Group %s failed to reach %s status '
                           'within the required time (%s s). '
                           'Current status: %s' %
                           (consistency_group_name, status,
                            self.build_timeout, consistency_group_status))
                raise exceptions.TimeoutException(message)

###############

    def create_cgsnapshot(self, consistency_group_id,
                          name=None, description=None,
                          version=LATEST_MICROVERSION):
        """Create a new cgsnapshot of an existing consistency group."""
        uri = 'cgsnapshots'
        post_body = {'consistency_group_id': consistency_group_id}
        if name:
            post_body['name'] = name
        if description:
            post_body['description'] = description
        body = json.dumps({'cgsnapshot': post_body})
        resp, body = self.post(uri, body, headers=EXPERIMENTAL,
                               extra_headers=True, version=version)
        self.expected_success(202, resp.status)
        return self._parse_resp(body)

    def delete_cgsnapshot(self, cgsnapshot_id,
                          version=LATEST_MICROVERSION):
        """Delete an existing cgsnapshot."""
        uri = 'cgsnapshots/%s' % cgsnapshot_id
        resp, body = self.delete(uri, headers=EXPERIMENTAL,
                                 extra_headers=True, version=version)
        self.expected_success(202, resp.status)
        return body

    def list_cgsnapshots(self, detailed=False, params=None,
                         version=LATEST_MICROVERSION):
        """Get list of cgsnapshots w/o filters."""
        uri = 'cgsnapshots/detail' if detailed else 'cgsnapshots'
        uri += '?%s' % (urlparse.urlencode(params) if params else '')
        resp, body = self.get(uri, headers=EXPERIMENTAL, extra_headers=True,
                              version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_cgsnapshot_members(self, cgsnapshot_id,
                                version=LATEST_MICROVERSION):
        """Get list of members of a cgsnapshots."""
        uri = 'cgsnapshots/%s/members' % cgsnapshot_id
        resp, body = self.get(uri, headers=EXPERIMENTAL, extra_headers=True,
                              version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def get_cgsnapshot(self, cgsnapshot_id, version=LATEST_MICROVERSION):
        """Get cgsnapshot info."""
        uri = 'cgsnapshots/%s' % cgsnapshot_id
        resp, body = self.get(uri, headers=EXPERIMENTAL, extra_headers=True,
                              version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def update_cgsnapshot(self, cgsnapshot_id, name=None, description=None,
                          version=LATEST_MICROVERSION):
        """Update an existing cgsnapshot."""
        uri = 'cgsnapshots/%s' % cgsnapshot_id
        post_body = {}
        if name:
            post_body['name'] = name
        if description:
            post_body['description'] = description
        body = json.dumps({'cgsnapshot': post_body})
        resp, body = self.put(uri, body, headers=EXPERIMENTAL,
                              extra_headers=True, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def cgsnapshot_reset_state(self, id, status,
                               version=LATEST_MICROVERSION):
        self.reset_state(id, status=status,
                         s_type='cgsnapshots', headers=EXPERIMENTAL,
                         version=version)

    def cgsnapshot_force_delete(self, id, version=LATEST_MICROVERSION):
        self.force_delete(id, s_type='cgsnapshots', headers=EXPERIMENTAL,
                          version=version)

    def wait_for_cgsnapshot_status(self, cgsnapshot_id, status):
        """Waits for a cgsnapshot to reach a given status."""
        body = self.get_cgsnapshot(cgsnapshot_id)
        cgsnapshot_name = body['name']
        cgsnapshot_status = body['status']
        start = int(time.time())

        while cgsnapshot_status != status:
            time.sleep(self.build_interval)
            body = self.get_cgsnapshot(cgsnapshot_id)
            cgsnapshot_status = body['status']
            if 'error' in cgsnapshot_status and status != 'error':
                raise share_exceptions.CGSnapshotBuildErrorException(
                    cgsnapshot_id=cgsnapshot_id)

            if int(time.time()) - start >= self.build_timeout:
                message = ('CGSnapshot %s failed to reach %s status '
                           'within the required time (%s s).' %
                           (cgsnapshot_name, status, self.build_timeout))
                raise exceptions.TimeoutException(message)

###############

    def migrate_share(self, share_id, host, notify,
                      version=LATEST_MICROVERSION, action_name=None):
        if action_name is None:
            if utils.is_microversion_lt(version, "2.7"):
                action_name = 'os-migrate_share'
            elif utils.is_microversion_lt(version, "2.15"):
                action_name = 'migrate_share'
            else:
                action_name = 'migration_start'
        post_body = {
            action_name: {
                'host': host,
                'notify': notify,
            }
        }
        body = json.dumps(post_body)
        return self.post('shares/%s/action' % share_id, body,
                         headers=EXPERIMENTAL, extra_headers=True,
                         version=version)

    def migration_complete(self, share_id, version=LATEST_MICROVERSION,
                           action_name='migration_complete'):
        post_body = {
            action_name: None,
        }
        body = json.dumps(post_body)
        return self.post('shares/%s/action' % share_id, body,
                         headers=EXPERIMENTAL, extra_headers=True,
                         version=version)

    def migration_cancel(self, share_id, version=LATEST_MICROVERSION,
                         action_name='migration_cancel'):
        post_body = {
            action_name: None,
        }
        body = json.dumps(post_body)
        return self.post('shares/%s/action' % share_id, body,
                         headers=EXPERIMENTAL, extra_headers=True,
                         version=version)

    def migration_get_progress(self, share_id, version=LATEST_MICROVERSION,
                               action_name='migration_get_progress'):
        post_body = {
            action_name: None,
        }
        body = json.dumps(post_body)
        return self.post('shares/%s/action' % share_id, body,
                         headers=EXPERIMENTAL, extra_headers=True,
                         version=version)

    def reset_task_state(
            self, share_id, task_state, version=LATEST_MICROVERSION,
            action_name='reset_task_state'):
        post_body = {
            action_name: {
                'task_state': task_state,
            }
        }
        body = json.dumps(post_body)
        return self.post('shares/%s/action' % share_id, body,
                         headers=EXPERIMENTAL, extra_headers=True,
                         version=version)

    def wait_for_migration_status(self, share_id, dest_host, status,
                                  version=LATEST_MICROVERSION):
        """Waits for a share to migrate to a certain host."""
        share = self.get_share(share_id, version=version)
        migration_timeout = CONF.share.migration_timeout
        start = int(time.time())
        while share['task_state'] != status:
            time.sleep(self.build_interval)
            share = self.get_share(share_id, version=version)
            if share['task_state'] == status:
                return share
            elif share['task_state'] == 'migration_error':
                raise share_exceptions.ShareMigrationException(
                    share_id=share['id'], src=share['host'], dest=dest_host)
            elif int(time.time()) - start >= migration_timeout:
                message = ('Share %(share_id)s failed to reach status '
                           '%(status)s when migrating from host %(src)s to '
                           'host %(dest)s within the required time '
                           '%(timeout)s.' % {
                               'src': share['host'],
                               'dest': dest_host,
                               'share_id': share['id'],
                               'timeout': self.build_timeout,
                               'status': status,
                           })
                raise exceptions.TimeoutException(message)

################

    def create_share_replica(self, share_id, availability_zone=None,
                             version=LATEST_MICROVERSION):
        """Add a share replica of an existing share."""
        uri = "share-replicas"
        post_body = {
            'share_id': share_id,
            'availability_zone': availability_zone,
        }

        body = json.dumps({'share_replica': post_body})
        resp, body = self.post(uri, body,
                               headers=EXPERIMENTAL,
                               extra_headers=True,
                               version=version)
        self.expected_success(202, resp.status)
        return self._parse_resp(body)

    def get_share_replica(self, replica_id, version=LATEST_MICROVERSION):
        """Get the details of share_replica."""
        resp, body = self.get("share-replicas/%s" % replica_id,
                              headers=EXPERIMENTAL,
                              extra_headers=True,
                              version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_share_replicas(self, share_id=None, version=LATEST_MICROVERSION):
        """Get list of replicas."""
        uri = "share-replicas/detail"
        uri += ("?share_id=%s" % share_id) if share_id is not None else ''
        resp, body = self.get(uri, headers=EXPERIMENTAL,
                              extra_headers=True, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def list_share_replicas_summary(self, share_id=None,
                                    version=LATEST_MICROVERSION):
        """Get summary list of replicas."""
        uri = "share-replicas"
        uri += ("?share_id=%s" % share_id) if share_id is not None else ''
        resp, body = self.get(uri, headers=EXPERIMENTAL,
                              extra_headers=True, version=version)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def delete_share_replica(self, replica_id, version=LATEST_MICROVERSION):
        """Delete share_replica."""
        uri = "share-replicas/%s" % replica_id
        resp, body = self.delete(uri,
                                 headers=EXPERIMENTAL,
                                 extra_headers=True,
                                 version=version)
        self.expected_success(202, resp.status)
        return body

    def promote_share_replica(self, replica_id, expected_status=202,
                              version=LATEST_MICROVERSION):
        """Promote a share replica to active state."""
        uri = "share-replicas/%s/action" % replica_id
        post_body = {
            'promote': None,
        }
        body = json.dumps(post_body)
        resp, body = self.post(uri, body,
                               headers=EXPERIMENTAL,
                               extra_headers=True,
                               version=version)
        self.expected_success(expected_status, resp.status)
        return self._parse_resp(body)

    def wait_for_share_replica_status(self, replica_id, expected_status,
                                      status_attr='status'):
        """Waits for a replica's status_attr to reach a given status."""
        body = self.get_share_replica(replica_id)
        replica_status = body[status_attr]
        start = int(time.time())

        while replica_status != expected_status:
            time.sleep(self.build_interval)
            body = self.get_share_replica(replica_id)
            replica_status = body[status_attr]
            if replica_status == expected_status:
                return
            if ('error' in replica_status
                    and expected_status != constants.STATUS_ERROR):
                raise share_exceptions.ShareInstanceBuildErrorException(
                    id=replica_id)

            if int(time.time()) - start >= self.build_timeout:
                message = ('The %(status_attr)s of Replica %(id)s failed to '
                           'reach %(expected_status)s status within the '
                           'required time (%(time)ss). Current '
                           '%(status_attr)s: %(current_status)s.' %
                           {
                               'status_attr': status_attr,
                               'expected_status': expected_status,
                               'time': self.build_timeout,
                               'id': replica_id,
                               'current_status': replica_status,
                           })
                raise exceptions.TimeoutException(message)

    def reset_share_replica_status(self, replica_id,
                                   status=constants.STATUS_AVAILABLE,
                                   version=LATEST_MICROVERSION):
        """Reset the status."""
        uri = 'share-replicas/%s/action' % replica_id
        post_body = {
            'reset_status': {
                'status': status
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post(uri, body,
                               headers=EXPERIMENTAL,
                               extra_headers=True,
                               version=version)
        self.expected_success(202, resp.status)
        return self._parse_resp(body)

    def reset_share_replica_state(self, replica_id,
                                  state=constants.REPLICATION_STATE_ACTIVE,
                                  version=LATEST_MICROVERSION):
        """Reset the replication state of a replica."""
        uri = 'share-replicas/%s/action' % replica_id
        post_body = {
            'reset_replica_state': {
                'replica_state': state
            }
        }
        body = json.dumps(post_body)
        resp, body = self.post(uri, body,
                               headers=EXPERIMENTAL,
                               extra_headers=True,
                               version=version)
        self.expected_success(202, resp.status)
        return self._parse_resp(body)

    def resync_share_replica(self, replica_id, expected_result=202,
                             version=LATEST_MICROVERSION):
        """Force an immediate resync of the replica."""
        uri = 'share-replicas/%s/action' % replica_id
        post_body = {
            'resync': None
        }
        body = json.dumps(post_body)
        resp, body = self.post(uri, body,
                               headers=EXPERIMENTAL,
                               extra_headers=True,
                               version=version)
        self.expected_success(expected_result, resp.status)
        return self._parse_resp(body)

    def force_delete_share_replica(self, replica_id,
                                   version=LATEST_MICROVERSION):
        """Force delete a replica."""
        uri = 'share-replicas/%s/action' % replica_id
        post_body = {
            'force_delete': None
        }
        body = json.dumps(post_body)
        resp, body = self.post(uri, body,
                               headers=EXPERIMENTAL,
                               extra_headers=True,
                               version=version)
        self.expected_success(202, resp.status)
        return self._parse_resp(body)
