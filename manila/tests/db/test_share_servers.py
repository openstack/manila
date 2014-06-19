# Copyright (c) 2014 NetApp, Inc.
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

"""Tests for the ShareServer and ShareServerBackendDetails tables."""

from manila import context
from manila import db
from manila import exception
from manila.openstack.common import uuidutils
from manila import test


class ShareServerTableTestCase(test.TestCase):

    def setUp(self):
        super(ShareServerTableTestCase, self).setUp()
        self.ctxt = context.RequestContext(user_id='user_id',
                                           project_id='project_id',
                                           is_admin=True)

    def _create_share_server(self, values=None):
        if not values:
            values = {
                'share_network_id': uuidutils.generate_uuid(),
                'host': 'host1',
                'status': 'ACTIVE'
            }
        return db.share_server_create(self.ctxt, values)

    def test_share_server_get(self):
        values = {
            'share_network_id': 'fake-share-net-id',
            'host': 'hostname',
            'status': 'ACTIVE'
        }
        expected = self._create_share_server(values)
        server = db.share_server_get(self.ctxt, expected['id'])
        self.assertEqual(expected['id'], server['id'])
        self.assertEqual(server.share_network_id, expected.share_network_id)
        self.assertEqual(server.host, expected.host)
        self.assertEqual(server.status, expected.status)

    def test_share_get_not_found(self):
        fake_id = 'FAKE_UUID'
        self.assertRaises(exception.ShareServerNotFound, db.share_server_get,
                          self.ctxt, fake_id)

    def test_share_server_create(self):
        values = {
            'share_network_id': 'fake-share-net-id',
            'host': 'hostname',
            'status': 'ACTIVE'
        }
        server = self._create_share_server(values)
        self.assertTrue(server['id'])
        self.assertEqual(server.share_network_id, values['share_network_id'])
        self.assertEqual(server.host, values['host'])
        self.assertEqual(server.status, values['status'])

    def test_share_server_delete(self):
        server = self._create_share_server()
        num_records = len(db.share_server_get_all(self.ctxt))
        db.share_server_delete(self.ctxt, server['id'])
        self.assertEqual(len(db.share_server_get_all(self.ctxt)),
                         num_records - 1)

    def test_share_server_delete_not_found(self):
        fake_id = 'FAKE_UUID'
        self.assertRaises(exception.ShareServerNotFound,
                          db.share_server_delete,
                          self.ctxt, fake_id)

    def test_share_server_update(self):
        update = {
            'share_network_id': 'update_net',
            'host': 'update_host',
            'status': 'updated_status'
        }
        server = self._create_share_server()
        updated_server = db.share_server_update(self.ctxt, server['id'],
                                                update)
        self.assertEqual(server['id'], updated_server['id'])
        self.assertEqual(updated_server.share_network_id,
                         update['share_network_id'])
        self.assertEqual(updated_server.host, update['host'])
        self.assertEqual(updated_server.status, update['status'])

    def test_share_server_update_not_found(self):
        fake_id = 'FAKE_UUID'
        self.assertRaises(exception.ShareServerNotFound,
                          db.share_server_update,
                          self.ctxt, fake_id, {})

    def test_share_server_get_by_host_and_share_net_valid(self):
        valid = {
            'share_network_id': '1',
            'host': 'host1',
            'status': 'ACTIVE'
        }
        invalid = {
            'share_network_id': '1',
            'host': 'host1',
            'status': 'ERROR'
        }
        other = {
            'share_network_id': '2',
            'host': 'host2',
            'status': 'ACTIVE'
        }
        valid = self._create_share_server(valid)
        self._create_share_server(invalid)
        self._create_share_server(other)

        servers = db.share_server_get_by_host_and_share_net_valid(
            self.ctxt,
            host='host1',
            share_net_id='1')
        self.assertEqual(servers['id'], valid['id'])

    def test_share_server_get_by_host_and_share_net_not_found(self):
        self.assertRaises(exception.ShareServerNotFound,
                          db.share_server_get_by_host_and_share_net_valid,
                          self.ctxt, host='fake', share_net_id='fake')

    def test_share_server_get_all(self):
        srv1 = {
            'share_network_id': '1',
            'host': 'host1',
            'status': 'ACTIVE'
        }
        srv2 = {
            'share_network_id': '1',
            'host': 'host1',
            'status': 'ERROR'
        }
        srv3 = {
            'share_network_id': '2',
            'host': 'host2',
            'status': 'ACTIVE'
        }
        servers = db.share_server_get_all(self.ctxt)
        self.assertEqual(len(servers), 0)

        to_delete = self._create_share_server(srv1)
        self._create_share_server(srv2)
        self._create_share_server(srv3)

        servers = db.share_server_get_all(self.ctxt)
        self.assertEqual(len(servers), 3)

        db.share_server_delete(self.ctxt, to_delete['id'])
        servers = db.share_server_get_all(self.ctxt)
        self.assertEqual(len(servers), 2)

    def test_share_server_backend_details_set(self):
        details = {
            'value1': '1',
            'value2': '2',
        }
        server = self._create_share_server()
        db.share_server_backend_details_set(self.ctxt, server['id'], details)

        self.assertDictMatch(
            details,
            db.share_server_backend_details_get(self.ctxt, server['id'])
        )

    def test_share_server_backend_details_set_not_found(self):
        fake_id = 'FAKE_UUID'
        self.assertRaises(exception.ShareServerNotFound,
                          db.share_server_backend_details_set,
                          self.ctxt, fake_id, {})

    def test_share_server_get_with_details(self):
        values = {
            'share_network_id': 'fake-share-net-id',
            'host': 'hostname',
            'status': 'ACTIVE'
        }
        details = {
            'value1': '1',
            'value2': '2',
        }
        srv_id = self._create_share_server(values)['id']
        db.share_server_backend_details_set(self.ctxt, srv_id, details)
        server = db.share_server_get(self.ctxt, srv_id)
        self.assertEqual(srv_id, server['id'])
        self.assertEqual(server.share_network_id, values['share_network_id'])
        self.assertEqual(server.host, values['host'])
        self.assertEqual(server.status, values['status'])
        self.assertDictMatch(details, server['backend_details'])

    def test_share_server_delete_with_details(self):
        server = self._create_share_server()
        details = {
            'value1': '1',
            'value2': '2',
        }
        db.share_server_backend_details_set(self.ctxt, server['id'], details)
        num_records = len(db.share_server_get_all(self.ctxt))
        db.share_server_delete(self.ctxt, server['id'])
        self.assertEqual(len(db.share_server_get_all(self.ctxt)),
                         num_records - 1)
        self.assertFalse(
            db.share_server_backend_details_get(self.ctxt, server['id']))
