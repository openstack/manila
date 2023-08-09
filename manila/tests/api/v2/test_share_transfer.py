# Copyright (c) 2022 China Telecom Digital Intelligence.
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

import http.client as http_client
from unittest import mock

import ddt
from oslo_serialization import jsonutils
import webob

from manila.api.v2 import share_transfer
from manila import context
from manila import db
from manila import exception
from manila import quota
from manila.share import api as share_api
from manila.share import rpcapi as share_rpcapi
from manila.share import share_types
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils
from manila.transfer import api as transfer_api

SHARE_TRANSFER_VERSION = "2.77"


@ddt.ddt
class ShareTransferAPITestCase(test.TestCase):
    """Test Case for transfers V3 API."""

    microversion = SHARE_TRANSFER_VERSION

    def setUp(self):
        super(ShareTransferAPITestCase, self).setUp()
        self.share_transfer_api = transfer_api.API()
        self.v2_controller = share_transfer.ShareTransferController()
        self.ctxt = context.RequestContext(
            'fake_user_id', 'fake_project_id', auth_token=True, is_admin=True)

    def _create_transfer(self, share_id='fake_share_id',
                         display_name='test_transfer'):
        transfer = self.share_transfer_api.create(context.get_admin_context(),
                                                  share_id, display_name)
        return transfer

    def _create_share(self, display_name='test_share',
                      display_description='this is a test share',
                      status='available',
                      size=1,
                      project_id='fake_project_id',
                      user_id='fake_user_id',
                      share_network_id=None):
        """Create a share object."""
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(display_name=display_name,
                                      display_description=display_description,
                                      status=status, size=size,
                                      project_id=project_id,
                                      user_id=user_id,
                                      share_type_id=share_type['id'],
                                      share_network_id=share_network_id
                                      )
        share_id = share['id']
        return share_id

    def test_show_transfer(self):
        share_id = self._create_share(size=5)
        transfer = self._create_transfer(share_id)
        path = '/v2/fake_project_id/share-transfers/%s' % transfer['id']
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'GET'
        req.headers['Content-Type'] = 'application/json'
        res_dict = self.v2_controller.show(req, transfer['id'])

        self.assertEqual('test_transfer', res_dict['transfer']['name'])
        self.assertEqual(transfer['id'], res_dict['transfer']['id'])
        self.assertEqual(share_id, res_dict['transfer']['resource_id'])

    def test_list_transfers(self):
        share_id_1 = self._create_share(size=5)
        share_id_2 = self._create_share(size=5)
        transfer1 = self._create_transfer(share_id_1)
        transfer2 = self._create_transfer(share_id_2)

        path = '/v2/fake_project_id/share-transfers'
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'GET'
        req.headers['Content-Type'] = 'application/json'
        res_dict = self.v2_controller.index(req)

        self.assertEqual(transfer1['id'], res_dict['transfers'][1]['id'])
        self.assertEqual('test_transfer', res_dict['transfers'][1]['name'])
        self.assertEqual(transfer2['id'], res_dict['transfers'][0]['id'])
        self.assertEqual('test_transfer', res_dict['transfers'][0]['name'])

    def test_list_transfers_with_all_tenants(self):
        share_id_1 = self._create_share(size=5)
        share_id_2 = self._create_share(size=5, project_id='fake_project_id2',
                                        user_id='fake_user_id2')
        self._create_transfer(share_id_1)
        self._create_transfer(share_id_2)

        path = '/v2/fake_project_id/share-transfers?all_tenants=true'
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = context.get_admin_context()
        req.method = 'GET'
        req.headers['Content-Type'] = 'application/json'
        res_dict = self.v2_controller.index(req)

        self.assertEqual(2, len(res_dict['transfers']))

    def test_list_transfers_with_limit(self):
        share_id_1 = self._create_share(size=5)
        share_id_2 = self._create_share(size=5)
        self._create_transfer(share_id_1)
        self._create_transfer(share_id_2)
        path = '/v2/fake_project_id/share-transfers?limit=1'
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'GET'
        req.headers['Content-Type'] = 'application/json'
        res_dict = self.v2_controller.index(req)

        self.assertEqual(1, len(res_dict['transfers']))

    @ddt.data("desc", "asc")
    def test_list_transfers_with_sort(self, sort_dir):
        share_id_1 = self._create_share(size=5)
        share_id_2 = self._create_share(size=5)
        transfer1 = self._create_transfer(share_id_1)
        transfer2 = self._create_transfer(share_id_2)
        path = \
            '/v2/fake_project_id/share-transfers?sort_key=id&sort_dir=%s' % (
                sort_dir)
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'GET'
        req.headers['Content-Type'] = 'application/json'
        res_dict = self.v2_controller.index(req)

        self.assertEqual(2, len(res_dict['transfers']))
        order_ids = sorted([transfer1['id'],
                            transfer2['id']])
        expect_result = order_ids[1] if sort_dir == "desc" else order_ids[0]
        self.assertEqual(expect_result,
                         res_dict['transfers'][0]['id'])

    def test_list_transfers_detail(self):
        share_id_1 = self._create_share(size=5)
        share_id_2 = self._create_share(size=5)
        transfer1 = self._create_transfer(share_id_1)
        transfer2 = self._create_transfer(share_id_2)

        path = '/v2/fake_project_id/share-transfers/detail'
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'GET'
        req.headers['Content-Type'] = 'application/json'
        req.headers['Accept'] = 'application/json'
        res_dict = self.v2_controller.detail(req)

        self.assertEqual('test_transfer',
                         res_dict['transfers'][1]['name'])
        self.assertEqual(transfer1['id'], res_dict['transfers'][1]['id'])
        self.assertEqual(share_id_1, res_dict['transfers'][1]['resource_id'])

        self.assertEqual('test_transfer',
                         res_dict['transfers'][0]['name'])
        self.assertEqual(transfer2['id'], res_dict['transfers'][0]['id'])
        self.assertEqual(share_id_2, res_dict['transfers'][0]['resource_id'])

    def test_create_transfer(self):
        share_id = self._create_share(status='available', size=5)
        body = {"transfer": {"name": "transfer1",
                             "share_id": share_id}}

        path = '/v2/fake_project_id/share-transfers'
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'POST'
        req.headers['Content-Type'] = 'application/json'
        req.body = jsonutils.dumps(body).encode("utf-8")
        res_dict = self.v2_controller.create(req, body)

        self.assertIn('id', res_dict['transfer'])
        self.assertIn('auth_key', res_dict['transfer'])
        self.assertIn('created_at', res_dict['transfer'])
        self.assertIn('name', res_dict['transfer'])
        self.assertIn('resource_id', res_dict['transfer'])

    @ddt.data({},
              {"transfer": {"name": "transfer1"}},
              {"transfer": {"name": "transfer1",
                            "share_id": "invalid_share_id"}})
    def test_create_transfer_with_invalid_body(self, body):
        path = '/v2/fake_project_id/share-transfers'
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'POST'
        req.headers['Content-Type'] = 'application/json'
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.v2_controller.create, req, body)

    def test_create_transfer_with_invalid_share_status(self):
        share_id = self._create_share()
        body = {"transfer": {"name": "transfer1",
                             "share_id": share_id}}
        db.share_update(context.get_admin_context(),
                        share_id, {'status': 'error'})

        path = '/v2/fake_project_id/share-transfers'
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'POST'
        req.headers['Content-Type'] = 'application/json'
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.v2_controller.create, req, body)

    def test_create_transfer_share_with_network_id(self):
        share_id = self._create_share(share_network_id='fake_id')
        body = {"transfer": {"name": "transfer1",
                             "share_id": share_id}}

        path = '/v2/fake_project_id/share-transfers'
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'POST'
        req.headers['Content-Type'] = 'application/json'
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.v2_controller.create, req, body)

    def test_create_transfer_share_with_invalid_snapshot(self):
        share_id = self._create_share(share_network_id='fake_id')
        db_utils.create_snapshot(share_id=share_id)
        body = {"transfer": {"name": "transfer1",
                             "share_id": share_id}}

        path = '/v2/fake_project_id/share-transfers'
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'POST'
        req.headers['Content-Type'] = 'application/json'
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.v2_controller.create, req, body)

    def test_delete_transfer_awaiting_transfer(self):
        share_id = self._create_share()
        transfer = self.share_transfer_api.create(context.get_admin_context(),
                                                  share_id, 'test_transfer')
        path = '/v2/fake_project_id/share-transfers/%s' % transfer['id']
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'DELETE'
        req.headers['Content-Type'] = 'application/json'
        self.v2_controller.delete(req, transfer['id'])

        # verify transfer has been deleted
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'GET'
        req.headers['Content-Type'] = 'application/json'
        res = req.get_response(fakes.app())

        self.assertEqual(http_client.NOT_FOUND, res.status_int)
        self.assertEqual(db.share_get(context.get_admin_context(),
                         share_id)['status'], 'available')

    def test_delete_transfer_not_awaiting_transfer(self):
        share_id = self._create_share()
        transfer = self.share_transfer_api.create(context.get_admin_context(),
                                                  share_id, 'test_transfer')
        db.share_update(context.get_admin_context(),
                        share_id, {'status': 'available'})

        path = '/v2/fake_project_id/share-transfers/%s' % transfer['id']
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'DELETE'
        req.headers['Content-Type'] = 'application/json'
        self.assertRaises(exception.InvalidShare,
                          self.v2_controller.delete, req,
                          transfer['id'])

    def test_transfer_accept_share_id_specified(self):
        share_id = self._create_share()
        transfer = self.share_transfer_api.create(context.get_admin_context(),
                                                  share_id, 'test_transfer')
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock())
        self.mock_object(quota.QUOTAS, 'commit', mock.Mock())
        self.mock_object(share_api.API,
                         'check_is_share_size_within_per_share_quota_limit',
                         mock.Mock())
        self.mock_object(share_rpcapi.ShareAPI,
                         'transfer_accept',
                         mock.Mock())
        fake_share_type = {'id': 'fake_id',
                           'name': 'fake_name',
                           'is_public': True}
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_share_type))
        self.mock_object(db, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value={}))

        body = {"accept": {"auth_key": transfer['auth_key']}}
        path = '/v2/fake_project_id/share-transfers/%s/accept' % transfer['id']
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'POST'
        req.headers['Content-Type'] = 'application/json'
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.v2_controller.accept(req, transfer['id'], body)

    def test_transfer_accept_with_not_public_share_type(self):
        share_id = self._create_share()
        transfer = self.share_transfer_api.create(context.get_admin_context(),
                                                  share_id, 'test_transfer')
        fake_share_type = {'id': 'fake_id',
                           'name': 'fake_name',
                           'is_public': False,
                           'projects': ['project_id1', 'project_id2']}
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_share_type))

        body = {"accept": {"auth_key": transfer['auth_key']}}
        path = '/v2/fake_project_id/share-transfers/%s/accept' % transfer['id']
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'POST'
        req.headers['Content-Type'] = 'application/json'
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.v2_controller.accept, req,
                          transfer['id'], body)

    @ddt.data({},
              {"accept": {}},
              {"accept": {"auth_key": "fake_auth_key",
                          "clear_access_rules": "invalid_bool"}})
    def test_transfer_accept_with_invalid_body(self, body):
        path = '/v2/fake_project_id/share-transfers/fake_transfer_id/accept'
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'POST'
        req.headers['Content-Type'] = 'application/json'
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.v2_controller.accept, req,
                          'fake_transfer_id', body)

    def test_transfer_accept_with_invalid_auth_key(self):
        share_id = self._create_share(size=5)
        transfer = self._create_transfer(share_id)
        body = {"accept": {"auth_key": "invalid_auth_key"}}
        path = '/v2/fake_project_id/share-transfers/%s/accept' % transfer['id']
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'POST'
        req.headers['Content-Type'] = 'application/json'
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.v2_controller.accept, req,
                          transfer['id'], body)

    def test_transfer_accept_with_invalid_share_status(self):
        share_id = self._create_share(size=5)
        transfer = self._create_transfer(share_id)
        db.share_update(context.get_admin_context(),
                        share_id, {'status': 'error'})
        body = {"accept": {"auth_key": transfer['auth_key']}}
        path = '/v2/fake_project_id/share-transfers/%s/accept' % transfer['id']
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'POST'
        req.headers['Content-Type'] = 'application/json'
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.v2_controller.accept, req,
                          transfer['id'], body)

    @ddt.data({'overs': {'gigabytes': 'fake'}},
              {'overs': {'shares': 'fake'}},
              {'overs': {'snapshot_gigabytes': 'fake'}},
              {'overs': {'snapshots': 'fake'}})
    @ddt.unpack
    def test_accept_share_over_quota(self, overs):
        share_id = self._create_share()
        db_utils.create_snapshot(share_id=share_id, status='available')
        transfer = self.share_transfer_api.create(context.get_admin_context(),
                                                  share_id, 'test_transfer')

        usages = {'gigabytes': {'reserved': 5, 'in_use': 5},
                  'shares': {'reserved': 10, 'in_use': 10},
                  'snapshot_gigabytes': {'reserved': 5, 'in_use': 5},
                  'snapshots': {'reserved': 10, 'in_use': 10}}

        quotas = {'gigabytes': 5, 'shares': 10,
                  'snapshot_gigabytes': 5, 'snapshots': 10}
        exc = exception.OverQuota(overs=overs, usages=usages, quotas=quotas)
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(side_effect=exc))
        self.mock_object(quota.QUOTAS, 'commit', mock.Mock())
        self.mock_object(share_api.API,
                         'check_is_share_size_within_per_share_quota_limit',
                         mock.Mock())
        self.mock_object(share_rpcapi.ShareAPI,
                         'transfer_accept',
                         mock.Mock())
        fake_share_type = {'id': 'fake_id',
                           'name': 'fake_name',
                           'is_public': True}
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_share_type))

        body = {"accept": {"auth_key": transfer['auth_key']}}
        path = '/v2/fake_project_id/share-transfers/%s/accept' % transfer['id']
        req = fakes.HTTPRequest.blank(path, version=self.microversion)
        req.environ['manila.context'] = self.ctxt
        req.method = 'POST'
        req.headers['Content-Type'] = 'application/json'
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.assertRaises(webob.exc.HTTPRequestEntityTooLarge,
                          self.v2_controller.accept, req,
                          transfer['id'], body)
