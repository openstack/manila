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
import urllib

from tempest_lib.common.utils import data_utils
from tempest_lib import exceptions

from manila_tempest_tests.services.share.json import shares_client  # noqa
from manila_tempest_tests import share_exceptions
from tempest import config  # noqa

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
                    headers=None, version=LATEST_MICROVERSION):
        """Resets the state of a share, snapshot, cg, or a cgsnapshot.

        status: available, error, creating, deleting, error_deleting
        s_type: shares, snapshots, consistency-groups, cgsnapshots
        """
        body = {"os-reset_status": {"status": status}}
        body = json.dumps(body)
        resp, body = self.post("%s/%s/action" % (s_type, s_id), body,
                               headers=headers, extra_headers=True,
                               version=version)
        self.expected_success(202, resp.status)
        return body

    def force_delete(self, s_id, s_type="shares", headers=None,
                     version=LATEST_MICROVERSION):
        """Force delete share or snapshot.

        s_type: shares, snapshots
        """
        body = {"os-force_delete": None}
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
        else:
            return super(SharesV2Client, self).is_resource_deleted(
                *args, **kwargs)

###############

    def create_share(self, share_protocol=None, size=1,
                     name=None, snapshot_id=None, description=None,
                     metadata=None, share_network_id=None,
                     share_type_id=None, is_public=False,
                     consistency_group_id=None, version=LATEST_MICROVERSION):
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
        uri += '?%s' % urllib.urlencode(params) if params else ''
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

    def delete_share(self, share_id, params=None,
                     version=LATEST_MICROVERSION):
        uri = "shares/%s" % share_id
        uri += '?%s' % (urllib.urlencode(params) if params else '')
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
        uri += '?%s' % (urllib.urlencode(params) if params else '')
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
                message = ('Consistency Group %s failed to reach %s status '
                           'within the required time (%s s).' %
                           (consistency_group_name, status,
                            self.build_timeout))
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
        uri += '?%s' % (urllib.urlencode(params) if params else '')
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

    def migrate_share(self, share_id, host, version=LATEST_MICROVERSION):
        post_body = {
            'os-migrate_share': {
                'host': host,
            }
        }
        body = json.dumps(post_body)
        return self.post('shares/%s/action' % share_id, body,
                         headers=EXPERIMENTAL, extra_headers=True,
                         version=version)

    def wait_for_migration_completed(self, share_id, dest_host,
                                     version=LATEST_MICROVERSION):
        """Waits for a share to migrate to a certain host."""
        share = self.get_share(share_id, version=version)
        migration_timeout = CONF.share.migration_timeout
        start = int(time.time())
        while share['task_state'] != 'migration_success':
            time.sleep(self.build_interval)
            share = self.get_share(share_id, version=version)
            if share['task_state'] == 'migration_success':
                return share
            elif share['task_state'] == 'migration_error':
                raise share_exceptions.ShareMigrationException(
                    share_id=share['id'], src=share['host'], dest=dest_host)
            elif int(time.time()) - start >= migration_timeout:
                message = ('Share %(share_id)s failed to migrate from '
                           'host %(src)s to host %(dest)s within the required '
                           'time %(timeout)s.' % {
                               'src': share['host'],
                               'dest': dest_host,
                               'share_id': share['id'],
                               'timeout': self.build_timeout
                           })
                raise exceptions.TimeoutException(message)
