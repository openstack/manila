# Copyright 2015 Goutham Pacha Ravi
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

from unittest import mock

import copy
import ddt
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import strutils
from webob import exc

from manila.api import common
from manila.api.openstack import api_version_request as api_version
from manila.api.v2 import share_replicas
from manila.common import constants
from manila import context
from manila import exception
from manila import policy
from manila import share
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils
from manila.tests import fake_share

CONF = cfg.CONF
CAST_RULES_READONLY_VERSION = '2.30'
PRE_GRADUATION_VERSION = '2.55'
GRADUATION_VERSION = '2.56'
PROMOTE_QUIESCE_WAIT_VERSION = '2.75'


@ddt.ddt
class ShareReplicasApiTest(test.TestCase):
    """Share Replicas API Test Cases."""
    def setUp(self):
        super(ShareReplicasApiTest, self).setUp()
        self.controller = share_replicas.ShareReplicationController()
        self.resource_name = self.controller.resource_name
        self.api_version = share_replicas.MIN_SUPPORTED_API_VERSION
        self.replicas_req = fakes.HTTPRequest.blank(
            '/share-replicas', version=self.api_version,
            experimental=True)
        self.member_context = context.RequestContext('fake', 'fake')
        self.replicas_req.environ['manila.context'] = self.member_context
        self.replicas_req_admin = fakes.HTTPRequest.blank(
            '/share-replicas', version=self.api_version,
            experimental=True, use_admin_context=True)
        self.admin_context = self.replicas_req_admin.environ['manila.context']
        self.mock_policy_check = self.mock_object(policy, 'check_policy')
        self.fake_share_network = {
            'id': 'fake network id',
            'project_id': 'fake project',
            'updated_at': None,
            'name': 'fake name',
            'description': 'fake description',
            'security_services': [],
            'share_network_subnets': [],
            'security_service_update_support': True,
            'status': 'active'
        }

    def _get_context(self, role):
        return getattr(self, '%s_context' % role)

    def _create_replica_get_req(self, **kwargs):
        if 'status' not in kwargs:
            kwargs['status'] = constants.STATUS_AVAILABLE
        if 'replica_state' not in kwargs:
            kwargs['replica_state'] = constants.REPLICA_STATE_IN_SYNC
        replica = db_utils.create_share_replica(**kwargs)
        path = '/v2/fake/share-replicas/%s/action' % replica['id']
        microversion = kwargs.get('microversion', self.api_version)
        experimental = True
        if (api_version.APIVersionRequest(microversion) >=
                api_version.APIVersionRequest(GRADUATION_VERSION)):
            experimental = False
        req = fakes.HTTPRequest.blank(path, script_name=path,
                                      version=microversion,
                                      experimental=experimental)
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.headers['X-Openstack-Manila-Api-Version'] = microversion
        req.headers['X-Openstack-Manila-Api-Experimental'] = True

        return replica, req

    def _get_fake_replica(
            self, summary=False, admin=False,
            microversion=share_replicas.MIN_SUPPORTED_API_VERSION, **values):
        replica = fake_share.fake_replica(**values)
        replica['updated_at'] = '2016-02-11T19:57:56.506805'
        expected_keys = {'id', 'share_id', 'status', 'replica_state'}
        expected_replica = {key: replica[key] for key in replica if key
                            in expected_keys}

        if not summary:
            expected_replica.update({
                'availability_zone': None,
                'created_at': None,
                'share_network_id': replica['share_network_id'],
                'updated_at': replica['updated_at'],
            })

        if admin:
            expected_replica['share_server_id'] = replica['share_server_id']
            expected_replica['host'] = replica['host']

        if (api_version.APIVersionRequest(microversion) >=
                api_version.APIVersionRequest(CAST_RULES_READONLY_VERSION)
                and admin):
            expected_replica['cast_rules_to_readonly'] = False

        return replica, expected_replica

    def _get_request(self, microversion, is_admin=False):
        experimental = (api_version.APIVersionRequest(microversion) <=
                        api_version.APIVersionRequest(GRADUATION_VERSION))
        req = fakes.HTTPRequest.blank(
            '/share-replicas', version=microversion,
            experimental=experimental, use_admin_context=is_admin)

        return req

    @ddt.data((False, PRE_GRADUATION_VERSION), (False, GRADUATION_VERSION))
    @ddt.unpack
    def test_list_replicas_summary(self, is_admin, microversion):
        fake_replica, expected_replica = self._get_fake_replica(
            summary=True, admin=is_admin, microversion=microversion)
        self.mock_object(share_replicas.db, 'share_replicas_get_all',
                         mock.Mock(return_value=[fake_replica]))

        req = self._get_request(is_admin=is_admin, microversion=microversion)
        context = req.environ['manila.context']
        res_dict = self.controller.index(req)

        self.assertEqual([expected_replica], res_dict['share_replicas'])
        self.mock_policy_check.assert_called_once_with(
            context, self.resource_name, 'get_all')

    def test_list_share_replicas_summary(self):
        fake_replica, expected_replica = self._get_fake_replica(summary=True)
        self.mock_object(share_replicas.db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[fake_replica]))
        req = fakes.HTTPRequest.blank(
            '/share-replicas?share_id=FAKE_SHARE_ID',
            version=self.api_version, experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req)

        self.assertEqual([expected_replica], res_dict['share_replicas'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    @ddt.data((True, PRE_GRADUATION_VERSION), (False, GRADUATION_VERSION))
    @ddt.unpack
    def test_list_replicas_detail(self, is_admin, microversion):
        fake_replica, expected_replica = self._get_fake_replica(
            admin=is_admin, microversion=microversion)
        self.mock_object(share_replicas.db, 'share_replicas_get_all',
                         mock.Mock(return_value=[fake_replica]))

        req = self._get_request(is_admin=is_admin, microversion=microversion)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual([expected_replica], res_dict['share_replicas'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_replicas_detail_with_limit(self):
        fake_replica_1, expected_replica_1 = self._get_fake_replica()
        fake_replica_2, expected_replica_2 = self._get_fake_replica(
            id="fake_id2")
        self.mock_object(
            share_replicas.db, 'share_replicas_get_all',
            mock.Mock(return_value=[fake_replica_1, fake_replica_2]))
        req = fakes.HTTPRequest.blank('/share-replicas?limit=1',
                                      version=self.api_version,
                                      experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['share_replicas']))
        self.assertEqual([expected_replica_1], res_dict['share_replicas'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_replicas_detail_with_limit_and_offset(self):
        fake_replica_1, expected_replica_1 = self._get_fake_replica()
        fake_replica_2, expected_replica_2 = self._get_fake_replica(
            id="fake_id2")
        self.mock_object(
            share_replicas.db, 'share_replicas_get_all',
            mock.Mock(return_value=[fake_replica_1, fake_replica_2]))
        req = fakes.HTTPRequest.blank(
            '/share-replicas/detail?limit=1&offset=1',
            version=self.api_version, experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['share_replicas']))
        self.assertEqual([expected_replica_2], res_dict['share_replicas'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_share_replicas_detail_invalid_share(self):
        self.mock_object(share_replicas.db, 'share_replicas_get_all_by_share',
                         mock.Mock(side_effect=exception.NotFound))
        mock__view_builder_call = self.mock_object(
            share_replicas.replication_view.ReplicationViewBuilder,
            'detail_list')
        req = self.replicas_req
        req.GET['share_id'] = 'FAKE_SHARE_ID'

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.detail, req)
        self.assertFalse(mock__view_builder_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'get_all')

    @ddt.data(True, False)
    def test_list_share_replicas_detail(self, is_admin):
        fake_replica, expected_replica = self._get_fake_replica(admin=is_admin)
        self.mock_object(share_replicas.db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[fake_replica]))
        req = fakes.HTTPRequest.blank(
            '/share-replicas?share_id=FAKE_SHARE_ID',
            version=self.api_version, experimental=True)
        req.environ['manila.context'] = (
            self.member_context if not is_admin else self.admin_context)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual([expected_replica], res_dict['share_replicas'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_share_replicas_with_limit(self):
        fake_replica_1, expected_replica_1 = self._get_fake_replica()
        fake_replica_2, expected_replica_2 = self._get_fake_replica(
            id="fake_id2")
        self.mock_object(
            share_replicas.db, 'share_replicas_get_all_by_share',
            mock.Mock(return_value=[fake_replica_1, fake_replica_2]))
        req = fakes.HTTPRequest.blank(
            '/share-replicas?share_id=FAKE_SHARE_ID&limit=1',
            version=self.api_version, experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['share_replicas']))
        self.assertEqual([expected_replica_1], res_dict['share_replicas'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_share_replicas_with_limit_and_offset(self):
        fake_replica_1, expected_replica_1 = self._get_fake_replica()
        fake_replica_2, expected_replica_2 = self._get_fake_replica(
            id="fake_id2")
        self.mock_object(
            share_replicas.db, 'share_replicas_get_all_by_share',
            mock.Mock(return_value=[fake_replica_1, fake_replica_2]))
        req = fakes.HTTPRequest.blank(
            '/share-replicas?share_id=FAKE_SHARE_ID&limit=1&offset=1',
            version=self.api_version, experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['share_replicas']))
        self.assertEqual([expected_replica_2], res_dict['share_replicas'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    @ddt.data((True, PRE_GRADUATION_VERSION),
              (False, GRADUATION_VERSION))
    @ddt.unpack
    def test_show(self, is_admin, microversion):
        fake_replica, expected_replica = self._get_fake_replica(
            admin=is_admin, microversion=microversion)
        self.mock_object(
            share_replicas.db, 'share_replica_get',
            mock.Mock(return_value=fake_replica))

        req = self._get_request(microversion, is_admin)
        req_context = req.environ['manila.context']

        res_dict = self.controller.show(req, fake_replica.get('id'))

        self.assertEqual(expected_replica, res_dict['share_replica'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'show')

    def test_show_no_replica(self):
        mock__view_builder_call = self.mock_object(
            share_replicas.replication_view.ReplicationViewBuilder, 'detail')
        fake_exception = exception.ShareReplicaNotFound(
            replica_id='FAKE_REPLICA_ID')
        self.mock_object(share_replicas.db, 'share_replica_get', mock.Mock(
            side_effect=fake_exception))

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.show,
                          self.replicas_req,
                          'FAKE_REPLICA_ID')
        self.assertFalse(mock__view_builder_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'show')

    def test_create_invalid_body(self):
        body = {}
        mock__view_builder_call = self.mock_object(
            share_replicas.replication_view.ReplicationViewBuilder,
            'detail_list')

        self.assertRaises(exc.HTTPUnprocessableEntity,
                          self.controller.create,
                          self.replicas_req, body)
        self.assertEqual(0, mock__view_builder_call.call_count)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'create')

    def test_create_no_share_id(self):
        body = {
            'share_replica': {
                'share_id': None,
                'availability_zone': None,
            }
        }
        mock__view_builder_call = self.mock_object(
            share_replicas.replication_view.ReplicationViewBuilder,
            'detail_list')

        self.assertRaises(exc.HTTPBadRequest,
                          self.controller.create,
                          self.replicas_req, body)
        self.assertFalse(mock__view_builder_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'create')

    def test_create_invalid_share_id(self):
        body = {
            'share_replica': {
                'share_id': 'FAKE_SHAREID',
                'availability_zone': 'FAKE_AZ'
            }
        }
        mock__view_builder_call = self.mock_object(
            share_replicas.replication_view.ReplicationViewBuilder,
            'detail_list')
        self.mock_object(share_replicas.db, 'share_get',
                         mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.create,
                          self.replicas_req, body)
        self.assertFalse(mock__view_builder_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'create')

    def test_create_has_been_soft_deleted(self):
        share_ref = fake_share.fake_share(is_soft_deleted=True)
        body = {
            'share_replica': {
                'share_id': 'FAKE_SHAREID',
                'availability_zone': 'FAKE_AZ'
            }
        }
        mock__view_builder_call = self.mock_object(
            share_replicas.replication_view.ReplicationViewBuilder,
            'detail_list')
        self.mock_object(share_replicas.db, 'share_get',
                         mock.Mock(return_value=share_ref))

        self.assertRaises(exc.HTTPForbidden,
                          self.controller.create,
                          self.replicas_req, body)
        self.assertFalse(mock__view_builder_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'create')

    def test_create_invalid_network_id(self):
        fake_replica, _ = self._get_fake_replica(
            replication_type='writable')
        req = self._get_request("2.72", False)
        req_context = req.environ['manila.context']

        body = {
            'share_replica': {
                'share_id': 'FAKE_SHAREID',
                'availability_zone': 'FAKE_AZ',
                'share_network_id': 'FAKE_NETID'
            }
        }
        mock__view_builder_call = self.mock_object(
            share_replicas.replication_view.ReplicationViewBuilder,
            'detail_list')
        self.mock_object(share_replicas.db, 'share_get',
                         mock.Mock(return_value=fake_replica))
        self.mock_object(share_replicas.db, 'share_network_get',
                         mock.Mock(side_effect=exception.ShareNetworkNotFound(
                                   share_network_id='FAKE_NETID')))

        self.assertRaises(exc.HTTPBadRequest,
                          self.controller.create,
                          req, body)
        self.assertFalse(mock__view_builder_call.called)
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')

    @ddt.data(exception.AvailabilityZoneNotFound,
              exception.ReplicationException, exception.ShareBusyException)
    def test_create_exception_path(self, exception_type):
        fake_replica, _ = self._get_fake_replica(
            replication_type='writable')
        mock__view_builder_call = self.mock_object(
            share_replicas.replication_view.ReplicationViewBuilder,
            'detail_list')
        share_network = db_utils.create_share_network()
        body = {
            'share_replica': {
                'share_id': 'FAKE_SHAREID',
                'availability_zone': 'FAKE_AZ'
            }
        }
        exc_args = {'id': 'xyz', 'reason': 'abc'}
        self.mock_object(share_replicas.db, 'share_get',
                         mock.Mock(return_value=fake_replica))
        self.mock_object(share.API, 'create_share_replica',
                         mock.Mock(side_effect=exception_type(**exc_args)))
        self.mock_object(share_replicas.db, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(common, 'check_share_network_is_active',
                         mock.Mock(return_value=True))

        self.assertRaises(exc.HTTPBadRequest,
                          self.controller.create,
                          self.replicas_req, body)
        self.assertFalse(mock__view_builder_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'create')
        share_replicas.db.share_network_get.assert_called_once_with(
            self.member_context, fake_replica['share_network_id'])
        common.check_share_network_is_active.assert_called_once_with(
            share_network)

    @ddt.data((True, PRE_GRADUATION_VERSION), (False, GRADUATION_VERSION),
              (False, "2.72"))
    @ddt.unpack
    def test_create(self, is_admin, microversion):
        fake_replica, expected_replica = self._get_fake_replica(
            replication_type='writable', admin=is_admin,
            microversion=microversion)
        body = {
            'share_replica': {
                'share_id': 'FAKE_SHAREID',
                'availability_zone': 'FAKE_AZ'
            }
        }
        if self.is_microversion_ge(microversion, '2.72'):
            body["share_replica"].update({"share_network_id": 'FAKE_NETID'})
            share_network = {'id': 'FAKE_NETID'}
        else:
            share_network = db_utils.create_share_network()

        self.mock_object(share_replicas.db, 'share_get',
                         mock.Mock(return_value=fake_replica))
        self.mock_object(share.API, 'create_share_replica',
                         mock.Mock(return_value=fake_replica))
        self.mock_object(share_replicas.db,
                         'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=[{'id': 'active1'}]))
        self.mock_object(share_replicas.db, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(common, 'check_share_network_is_active',
                         mock.Mock(return_value=True))

        req = self._get_request(microversion, is_admin)
        req_context = req.environ['manila.context']

        res_dict = self.controller.create(req, body)

        self.assertEqual(expected_replica, res_dict['share_replica'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')
        if self.is_microversion_ge(microversion, '2.72'):
            share_replicas.db.share_network_get.assert_called_once_with(
                req_context, 'FAKE_NETID')
        else:
            share_replicas.db.share_network_get.assert_called_once_with(
                req_context, fake_replica['share_network_id'])
        common.check_share_network_is_active.assert_called_once_with(
            share_network)

    def test_delete_invalid_replica(self):
        fake_exception = exception.ShareReplicaNotFound(
            replica_id='FAKE_REPLICA_ID')
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(side_effect=fake_exception))
        mock_delete_replica_call = self.mock_object(
            share.API, 'delete_share_replica')

        self.assertRaises(
            exc.HTTPNotFound, self.controller.delete,
            self.replicas_req, 'FAKE_REPLICA_ID')
        self.assertFalse(mock_delete_replica_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'delete')

    def test_delete_exception(self):
        fake_replica_1 = self._get_fake_replica(
            share_id='FAKE_SHARE_ID',
            replica_state=constants.REPLICA_STATE_ACTIVE)[0]
        fake_replica_2 = self._get_fake_replica(
            share_id='FAKE_SHARE_ID',
            replica_state=constants.REPLICA_STATE_ACTIVE)[0]
        exception_type = exception.ReplicationException(reason='xyz')
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=fake_replica_1))
        self.mock_object(
            share_replicas.db, 'share_replicas_get_all_by_share',
            mock.Mock(return_value=[fake_replica_1, fake_replica_2]))
        self.mock_object(share.API, 'delete_share_replica',
                         mock.Mock(side_effect=exception_type))

        self.assertRaises(exc.HTTPBadRequest, self.controller.delete,
                          self.replicas_req, 'FAKE_REPLICA_ID')
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'delete')

    @ddt.data(PRE_GRADUATION_VERSION, GRADUATION_VERSION)
    def test_delete(self, microversion):
        fake_replica = self._get_fake_replica(
            share_id='FAKE_SHARE_ID',
            replica_state=constants.REPLICA_STATE_ACTIVE)[0]
        req = self._get_request(microversion=microversion)
        context = req.environ['manila.context']
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=fake_replica))
        self.mock_object(share.API, 'delete_share_replica')

        resp = self.controller.delete(
            req, 'FAKE_REPLICA_ID')

        self.assertEqual(202, resp.status_code)
        self.mock_policy_check.assert_called_once_with(
            context, self.resource_name, 'delete')

    def test_promote_invalid_replica_id(self):
        body = {'promote': None}
        fake_exception = exception.ShareReplicaNotFound(
            replica_id='FAKE_REPLICA_ID')
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(side_effect=fake_exception))

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.promote,
                          self.replicas_req,
                          'FAKE_REPLICA_ID', body)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'promote')

    def test_promote_already_active(self):
        body = {'promote': None}
        replica, expected_replica = self._get_fake_replica(
            replica_state=constants.REPLICA_STATE_ACTIVE)
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(share_replicas.db, 'share_network_get',
                         mock.Mock(return_value=self.fake_share_network))
        mock_api_promote_replica_call = self.mock_object(
            share.API, 'promote_share_replica')

        resp = self.controller.promote(self.replicas_req, replica['id'], body)

        self.assertEqual(200, resp.status_code)
        self.assertFalse(mock_api_promote_replica_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'promote')

    def test_promote_replication_exception(self):
        body = {'promote': None}
        replica, expected_replica = self._get_fake_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC)
        exception_type = exception.ReplicationException(reason='xyz')
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(share_replicas.db, 'share_network_get',
                         mock.Mock(return_value=self.fake_share_network))
        mock_api_promote_replica_call = self.mock_object(
            share.API, 'promote_share_replica',
            mock.Mock(side_effect=exception_type))

        self.assertRaises(exc.HTTPBadRequest,
                          self.controller.promote,
                          self.replicas_req,
                          replica['id'],
                          body)
        self.assertTrue(mock_api_promote_replica_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'promote')

    def test_promote_share_network_not_active(self):
        body = {'promote': None}
        replica, expected_replica = self._get_fake_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC)
        fake_share_network = copy.deepcopy(self.fake_share_network)
        fake_share_network['status'] = constants.STATUS_NETWORK_CHANGE
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(share_replicas.db, 'share_network_get',
                         mock.Mock(return_value=fake_share_network))

        self.assertRaises(exc.HTTPBadRequest,
                          self.controller.promote,
                          self.replicas_req,
                          replica['id'],
                          body)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'promote')

    def test_promote_admin_required_exception(self):
        body = {'promote': None}
        replica, expected_replica = self._get_fake_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC)
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(share_replicas.db, 'share_network_get',
                         mock.Mock(return_value=self.fake_share_network))
        mock_api_promote_replica_call = self.mock_object(
            share.API, 'promote_share_replica',
            mock.Mock(side_effect=exception.AdminRequired))

        self.assertRaises(exc.HTTPForbidden,
                          self.controller.promote,
                          self.replicas_req,
                          replica['id'],
                          body)
        self.assertTrue(mock_api_promote_replica_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'promote')

    @ddt.data(PRE_GRADUATION_VERSION, GRADUATION_VERSION)
    def test_promote(self, microversion):
        body = {'promote': None}
        replica, expected_replica = self._get_fake_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC,
            microversion=microversion)
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(share_replicas.db, 'share_network_get',
                         mock.Mock(return_value=self.fake_share_network))
        mock_api_promote_replica_call = self.mock_object(
            share.API, 'promote_share_replica',
            mock.Mock(return_value=replica))
        req = self._get_request(microversion=microversion)
        context = req.environ['manila.context']
        resp = self.controller.promote(req, replica['id'], body)

        self.assertEqual(expected_replica, resp['share_replica'])
        self.assertTrue(mock_api_promote_replica_call.called)
        self.mock_policy_check.assert_called_once_with(
            context, self.resource_name, 'promote')

    @ddt.data(('2.74', None),
              (PROMOTE_QUIESCE_WAIT_VERSION, None),
              (PROMOTE_QUIESCE_WAIT_VERSION, 10),
              (PROMOTE_QUIESCE_WAIT_VERSION, 'foobar'),
              )
    @ddt.unpack
    def test_promote_quiesce_wait_time(self, microversion, time):
        body = {'promote': {'quiesce_wait_time': time}}
        replica, expected_replica = self._get_fake_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC,
            microversion=microversion)
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(share_replicas.db, 'share_network_get',
                         mock.Mock(return_value=self.fake_share_network))

        req = self._get_request(microversion=microversion)
        allow_quiesce_wait_time = False
        if (api_version.APIVersionRequest(microversion) >=
                api_version.APIVersionRequest(PROMOTE_QUIESCE_WAIT_VERSION)):
            allow_quiesce_wait_time = True
        if time and allow_quiesce_wait_time:
            if strutils.is_int_like(time):
                mock_api_promote_replica_call = self.mock_object(
                    share.API, 'promote_share_replica',
                    mock.Mock(return_value=replica))
                resp = self.controller.promote(req, replica['id'], body)
                self.assertEqual(expected_replica, resp['share_replica'])
                self.assertTrue(mock_api_promote_replica_call.called)
            else:
                self.assertRaises(exc.HTTPBadRequest,
                                  self.controller.promote,
                                  req,
                                  replica['id'],
                                  body)

    @ddt.data('index', 'detail', '_show', '_create', '_delete_share_replica',
              '_promote', 'reset_replica_state', 'reset_status', '_resync')
    def test_policy_not_authorized(self, method_name):

        method = getattr(self.controller, method_name)
        arguments = {
            'id': 'FAKE_REPLICA_ID',
            'body': {'FAKE_KEY': 'FAKE_VAL'},
        }
        if method_name in ('index', 'detail'):
            arguments.clear()

        noauthexc = exception.PolicyNotAuthorized(action=method_name)

        with mock.patch.object(
                policy, 'check_policy', mock.Mock(side_effect=noauthexc)):

            self.assertRaises(
                exc.HTTPForbidden, method, self.replicas_req, **arguments)

    @ddt.data('index', 'detail', 'show', 'create', 'delete', 'promote',
              'reset_replica_state', 'reset_status', 'resync')
    def test_upsupported_microversion(self, method_name):

        unsupported_microversions = ('1.0', '2.2', '2.10')
        method = getattr(self.controller, method_name)
        arguments = {
            'id': 'FAKE_REPLICA_ID',
            'body': {'FAKE_KEY': 'FAKE_VAL'},
        }
        if method_name in ('index', 'detail'):
            arguments.clear()

        for microversion in unsupported_microversions:
            req = fakes.HTTPRequest.blank(
                '/share-replicas', version=microversion,
                experimental=True)
            self.assertRaises(exception.VersionNotFoundForAPIMethod,
                              method, req, **arguments)

    def _reset_status(self, context, replica, req,
                      valid_code=202, status_attr='status',
                      valid_status=None, body=None):

        if status_attr == 'status':
            action_name = 'reset_status'
            body = body or {action_name: {'status': constants.STATUS_ERROR}}
        else:
            action_name = 'reset_replica_state'
            body = body or {
                action_name: {'replica_state': constants.STATUS_ERROR},
            }

        req.body = jsonutils.dumps(body).encode("utf-8")
        req.environ['manila.context'] = context

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        # validate response code and model status
        self.assertEqual(valid_code, resp.status_int)

        actual_replica = share_replicas.db.share_replica_get(
            context, replica['id'])
        self.assertEqual(valid_status, actual_replica[status_attr])

    @ddt.data(*fakes.fixture_reset_replica_status_with_different_roles)
    @ddt.unpack
    def test_reset_status_with_different_roles(self, role, valid_code,
                                               valid_status, microversion):
        context = self._get_context(role)
        replica, action_req = self._create_replica_get_req(
            microversion=microversion)

        self._reset_status(context, replica, action_req,
                           valid_code=valid_code, status_attr='status',
                           valid_status=valid_status)

    @ddt.data(
        {'os-reset_status': {'x-status': 'bad'}},
        {'os-reset_status': {'status': constants.STATUS_AVAILABLE}},
        {'reset_status': {'x-status': 'bad'}},
        {'reset_status': {'status': 'invalid'}},
    )
    def test_reset_status_invalid_body(self, body):
        replica, action_req = self._create_replica_get_req()

        self._reset_status(self.admin_context, replica, action_req,
                           valid_code=400, status_attr='status',
                           valid_status=constants.STATUS_AVAILABLE, body=body)

    @ddt.data(*fakes.fixture_reset_replica_state_with_different_roles)
    @ddt.unpack
    def test_reset_replica_state_with_different_roles(
            self, role, valid_code, valid_status, microversion):
        context = self._get_context(role)
        replica, action_req = self._create_replica_get_req(
            microversion=microversion)
        body = {'reset_replica_state': {'replica_state': valid_status}}

        self._reset_status(context, replica, action_req,
                           valid_code=valid_code, status_attr='replica_state',
                           valid_status=valid_status, body=body)

    @ddt.data(
        {'os-reset_replica_state': {'x-replica_state': 'bad'}},
        {'os-reset_replica_state': {'replica_state': constants.STATUS_ERROR}},
        {'reset_replica_state': {'x-replica_state': 'bad'}},
        {'reset_replica_state': {'replica_state': constants.STATUS_AVAILABLE}},
    )
    def test_reset_replica_state_invalid_body(self, body):
        replica, action_req = self._create_replica_get_req()

        self._reset_status(self.admin_context, replica, action_req,
                           valid_code=400, status_attr='status',
                           valid_status=constants.STATUS_AVAILABLE, body=body)

    def _force_delete(self, context, req, valid_code=202):
        body = {'force_delete': {}}
        req.environ['manila.context'] = context
        req.body = jsonutils.dumps(body).encode("utf-8")

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        # validate response
        self.assertEqual(valid_code, resp.status_int)

    @ddt.data(*fakes.fixture_force_delete_with_different_roles)
    @ddt.unpack
    def test_force_delete_replica_with_different_roles(self, role, resp_code,
                                                       version):
        replica, req = self._create_replica_get_req()
        context = self._get_context(role)

        self._force_delete(context, req, valid_code=resp_code)

    @ddt.data((PRE_GRADUATION_VERSION, 202),
              (GRADUATION_VERSION, 202))
    @ddt.unpack
    def test_force_delete_replica(self, microversion, resp_code):
        replica, req = self._create_replica_get_req(microversion=microversion)
        context = self.admin_context

        self._force_delete(context, req, valid_code=resp_code)

    def test_force_delete_missing_replica(self):
        replica, req = self._create_replica_get_req()
        share_replicas.db.share_replica_delete(
            self.admin_context, replica['id'], need_to_update_usages=False)

        self._force_delete(self.admin_context, req, valid_code=404)

    def test_resync_replica_not_found(self):

        replica, req = self._create_replica_get_req()
        share_replicas.db.share_replica_delete(
            self.admin_context, replica['id'], need_to_update_usages=False)
        share_api_call = self.mock_object(self.controller.share_api,
                                          'update_share_replica')
        body = {'resync': {}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        req.environ['manila.context'] = self.admin_context

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        self.assertEqual(404, resp.status_int)
        self.assertFalse(share_api_call.called)

    def test_resync_API_exception(self):

        replica, req = self._create_replica_get_req(
            replica_state=constants.REPLICA_STATE_OUT_OF_SYNC)
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        share_api_call = self.mock_object(
            share.API, 'update_share_replica', mock.Mock(
                side_effect=exception.InvalidHost(reason='')))

        body = {'resync': None}
        req.body = jsonutils.dumps(body).encode("utf-8")
        req.environ['manila.context'] = self.admin_context

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        self.assertEqual(400, resp.status_int)
        share_api_call.assert_called_once_with(self.admin_context, replica)

    @ddt.data((constants.REPLICA_STATE_ACTIVE, PRE_GRADUATION_VERSION),
              (constants.REPLICA_STATE_IN_SYNC, PRE_GRADUATION_VERSION),
              (constants.REPLICA_STATE_OUT_OF_SYNC, GRADUATION_VERSION),
              (constants.STATUS_ERROR, GRADUATION_VERSION))
    @ddt.unpack
    def test_resync(self, replica_state, microversion):

        replica, req = self._create_replica_get_req(
            replica_state=replica_state, host='skywalker@jedi#temple',
            microversion=microversion)
        share_api_call = self.mock_object(
            share.API, 'update_share_replica', mock.Mock(return_value=None))
        body = {'resync': {}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        req.environ['manila.context'] = self.admin_context

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        if replica_state == constants.REPLICA_STATE_ACTIVE:
            self.assertEqual(200, resp.status_int)
            self.assertFalse(share_api_call.called)
        else:
            self.assertEqual(202, resp.status_int)
            self.assertTrue(share_api_call.called)
