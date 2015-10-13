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

import ddt
import mock
from oslo_config import cfg
import six
from webob import exc

from manila.api.v2 import share_replicas
from manila.common import constants
from manila import context
from manila import exception
from manila import policy
from manila import share
from manila import test
from manila.tests.api import fakes
from manila.tests import fake_share

CONF = cfg.CONF


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
        self.context = context.RequestContext('user', 'fake', False)
        self.replicas_req.environ['manila.context'] = self.context
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.mock_policy_check = self.mock_object(policy, 'check_policy')

    def _get_fake_replica(self, summary=False, **values):
        replica = fake_share.fake_replica(**values)
        expected_keys = {'id', 'share_id', 'status', 'replica_state'}
        expected_replica = {key: replica[key] for key in replica if key
                            in expected_keys}

        if not summary:
            expected_replica.update({
                'host': replica['host'],
                'availability_zone': None,
                'created_at': None,
                'share_server_id': replica['share_server_id'],
                'share_network_id': replica['share_network_id'],
            })

        return replica, expected_replica

    def test_list_replicas_summary(self):
        fake_replica, expected_replica = self._get_fake_replica(summary=True)
        self.mock_object(share_replicas.db, 'share_replicas_get_all',
                         mock.Mock(return_value=[fake_replica]))

        res_dict = self.controller.index(self.replicas_req)

        self.assertEqual([expected_replica], res_dict['share_replicas'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

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

    def test_list_replicas_detail(self):
        fake_replica, expected_replica = self._get_fake_replica()
        self.mock_object(share_replicas.db, 'share_replicas_get_all',
                         mock.Mock(return_value=[fake_replica]))

        res_dict = self.controller.detail(self.replicas_req)

        self.assertEqual([expected_replica], res_dict['share_replicas'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

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
            self.context, self.resource_name, 'get_all')

    def test_list_share_replicas_detail(self):
        fake_replica, expected_replica = self._get_fake_replica()
        self.mock_object(share_replicas.db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[fake_replica]))
        req = fakes.HTTPRequest.blank(
            '/share-replicas?share_id=FAKE_SHARE_ID',
            version=self.api_version, experimental=True)
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

    def test_show(self):
        fake_replica, expected_replica = self._get_fake_replica()
        self.mock_object(
            share_replicas.db, 'share_replica_get',
            mock.Mock(return_value=fake_replica))

        res_dict = self.controller.show(
            self.replicas_req, fake_replica.get('id'))

        self.assertEqual(expected_replica, res_dict['share_replica'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'show')

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
            self.context, self.resource_name, 'show')

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
            self.context, self.resource_name, 'create')

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
            self.context, self.resource_name, 'create')

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
            self.context, self.resource_name, 'create')

    @ddt.data(exception.AvailabilityZoneNotFound,
              exception.ReplicationException, exception.ShareBusyException)
    def test_create_exception_path(self, exception_type):
        fake_replica, _ = self._get_fake_replica(
            replication_type='writable')
        mock__view_builder_call = self.mock_object(
            share_replicas.replication_view.ReplicationViewBuilder,
            'detail_list')
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

        self.assertRaises(exc.HTTPBadRequest,
                          self.controller.create,
                          self.replicas_req, body)
        self.assertFalse(mock__view_builder_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create(self):
        fake_replica, expected_replica = self._get_fake_replica(
            replication_type='writable')
        body = {
            'share_replica': {
                'share_id': 'FAKE_SHAREID',
                'availability_zone': 'FAKE_AZ'
            }
        }
        self.mock_object(share_replicas.db, 'share_get',
                         mock.Mock(return_value=fake_replica))
        self.mock_object(share.API, 'create_share_replica',
                         mock.Mock(return_value=fake_replica))
        self.mock_object(share_replicas.db,
                         'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=[{'id': 'active1'}]))

        res_dict = self.controller.create(self.replicas_req, body)

        self.assertEqual(expected_replica, res_dict['share_replica'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

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
            self.context, self.resource_name, 'delete')

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
            self.context, self.resource_name, 'delete')

    def test_delete(self):
        fake_replica = self._get_fake_replica(
            share_id='FAKE_SHARE_ID',
            replica_state=constants.REPLICA_STATE_ACTIVE)[0]
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=fake_replica))
        self.mock_object(share.API, 'delete_share_replica')

        resp = self.controller.delete(
            self.replicas_req, 'FAKE_REPLICA_ID')

        self.assertEqual(202, resp.status_code)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'delete')

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
            self.context, self.resource_name, 'promote')

    def test_promote_already_active(self):
        body = {'promote': None}
        replica, expected_replica = self._get_fake_replica(
            replica_state=constants.REPLICA_STATE_ACTIVE)
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        mock_api_promote_replica_call = self.mock_object(
            share.API, 'promote_share_replica')

        resp = self.controller.promote(self.replicas_req, replica['id'], body)

        self.assertEqual(200, resp.status_code)
        self.assertFalse(mock_api_promote_replica_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'promote')

    def test_promote_replication_exception(self):
        body = {'promote': None}
        replica, expected_replica = self._get_fake_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC)
        exception_type = exception.ReplicationException(reason='xyz')
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
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
            self.context, self.resource_name, 'promote')

    def test_promote_admin_required_exception(self):
        body = {'promote': None}
        replica, expected_replica = self._get_fake_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC)
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
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
            self.context, self.resource_name, 'promote')

    def test_promote(self):
        body = {'promote': None}
        replica, expected_replica = self._get_fake_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC)
        self.mock_object(share_replicas.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        mock_api_promote_replica_call = self.mock_object(
            share.API, 'promote_share_replica',
            mock.Mock(return_value=replica))

        resp = self.controller.promote(self.replicas_req, replica['id'], body)

        self.assertEqual(expected_replica, resp['share_replica'])
        self.assertTrue(mock_api_promote_replica_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'promote')

    @ddt.data('index', 'detail', 'show', 'create', 'delete', 'promote')
    def test_policy_not_authorized(self, method_name):

        method = getattr(self.controller, method_name)
        arguments = {
            'id': 'FAKE_REPLICA_ID',
            'body': {'FAKE_KEY': 'FAKE_VAL'},
        }
        if method_name in ('index', 'detail'):
            arguments.clear()

        noauthexc = exception.PolicyNotAuthorized(action=six.text_type(method))

        with mock.patch.object(
                policy, 'check_policy', mock.Mock(side_effect=noauthexc)):

            self.assertRaises(
                exc.HTTPForbidden, method, self.replicas_req, **arguments)

    @ddt.data('index', 'detail', 'show', 'create', 'delete', 'promote')
    def test_upsupported_microversion(self, method_name):

        unsupported_microversions = ('1.0', '2.2', '2.8')
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
